package app

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
	"github.com/teamseatwatch/teamseatwatch/internal/runtime"
)

type DiagnosticError struct {
	code string
}

func (e *DiagnosticError) Error() string { return e.code }

func ErrorCode(err error) string {
	var diagnostic *DiagnosticError
	if errors.As(err, &diagnostic) {
		return diagnostic.code
	}
	return "runtime_failure"
}

func diagnostic(code string) error {
	return &DiagnosticError{code: code}
}

const (
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 5 * time.Second
	requestTimeout    = 5 * time.Second
	connectionTimeout = 3 * time.Second
	idleTimeout       = 30 * time.Second
	privateClientName = "gateway"
)

func Run(ctx context.Context, role string, getenv func(string) string, logger *slog.Logger) error {
	switch role {
	case "control":
		return runControl(ctx, getenv, logger)
	case "gateway":
		return runGateway(ctx, getenv, logger)
	case "migrate":
		return runMigrate(ctx, getenv)
	default:
		return diagnostic("invalid_command")
	}
}

func runControl(ctx context.Context, getenv func(string) string, logger *slog.Logger) error {
	egressConfig, err := egress.ConfigFromEnv(getenv)
	if err != nil {
		return diagnostic(egress.ErrorCode(err))
	}
	router, err := egress.New(egressConfig)
	if err != nil {
		return diagnostic(egress.ErrorCode(err))
	}
	// Admission happens before platform adapters exist. A required deployment with no
	// usable candidate keeps an empty candidate set and reports the failure privately;
	// local health remains available, while every platform-client request stays blocked.
	admission, admissionErr := router.Admit(ctx)
	if admissionErr != nil && ctx.Err() != nil {
		router.CloseIdleConnections()
		return ctx.Err()
	}
	defer router.CloseIdleConnections()
	dsn, err := required(getenv, databaseURLEnv)
	if err != nil {
		return err
	}
	publicAddress, err := required(getenv, controlListenEnv)
	if err != nil {
		return err
	}
	privateAddress, err := required(getenv, privateListenEnv)
	if err != nil {
		return err
	}
	if err := validatePrivateAddress(privateAddress); err != nil {
		return err
	}
	staticDir, err := required(getenv, ownerStaticDirEnv)
	if err != nil {
		return err
	}
	caFile, err := required(getenv, tlsCAFileEnv)
	if err != nil {
		return err
	}
	certFile, err := required(getenv, tlsCertFileEnv)
	if err != nil {
		return err
	}
	keyFile, err := required(getenv, tlsKeyFileEnv)
	if err != nil {
		return err
	}
	privateTLS, err := runtime.LoadServerTLS(runtime.ServerTLSConfig{
		CAFile: caFile, CertFile: certFile, KeyFile: keyFile,
		AllowedClientCommonNames: []string{privateClientName},
	})
	if err != nil {
		return fmt.Errorf("invalid private TLS configuration: %w", err)
	}
	handlers, err := runtime.NewControlHandlers(runtime.ControlConfig{
		DatabaseURL: dsn, StaticDir: staticDir, PlatformClients: router, EgressStatus: router.Status(admission),
	})
	if err != nil {
		return err
	}
	defer handlers.Close()
	public, err := net.Listen("tcp", publicAddress)
	if err != nil {
		return err
	}
	private, err := net.Listen("tcp", privateAddress)
	if err != nil {
		_ = public.Close()
		return err
	}
	return serve(ctx, logger, []listener{
		{socket: public, server: newServer(runtime.NewRequestMiddleware(logger)(handlers.Public))},
		{socket: tls.NewListener(private, privateTLS), server: newServer(runtime.NewRequestMiddleware(logger)(handlers.Private))},
	})
}

func runGateway(ctx context.Context, getenv func(string) string, logger *slog.Logger) error {
	for _, secret := range []string{databaseURLEnv, platformCredentialsEnv, proxyURLEnv, egressProxyEnv, egressModeEnv, egressEndpointsEnv, egressReachabilityEnv, egressIPEchoEnv, egressHMACKeyEnv, egressHMACVersionEnv} {
		if getenv(secret) != "" {
			return diagnostic("gateway_forbidden_secret")
		}
	}
	address, err := required(getenv, gatewayListenEnv)
	if err != nil {
		return err
	}
	endpoint, err := required(getenv, controlPrivateURLEnv)
	if err != nil {
		return err
	}
	staticDir, err := required(getenv, publicStaticDirEnv)
	if err != nil {
		return err
	}
	caFile, err := required(getenv, tlsCAFileEnv)
	if err != nil {
		return err
	}
	certFile, err := required(getenv, tlsCertFileEnv)
	if err != nil {
		return err
	}
	keyFile, err := required(getenv, tlsKeyFileEnv)
	if err != nil {
		return err
	}
	serverName, err := required(getenv, controlServerNameEnv)
	if err != nil {
		return err
	}
	clientTLS, err := runtime.LoadClientTLS(runtime.ClientTLSConfig{
		CAFile: caFile, CertFile: certFile, KeyFile: keyFile, ServerName: serverName,
	})
	if err != nil {
		return fmt.Errorf("invalid gateway TLS configuration: %w", err)
	}
	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       clientTLS,
			DialContext:           (&net.Dialer{Timeout: connectionTimeout}).DialContext,
			TLSHandshakeTimeout:   connectionTimeout,
			ResponseHeaderTimeout: requestTimeout,
			IdleConnTimeout:       idleTimeout,
		},
	}
	handler, closeHandler, err := runtime.NewGatewayHandler(runtime.GatewayConfig{
		ControlURL: endpoint, ProbeClient: client, StaticDir: staticDir,
	})
	if err != nil {
		return err
	}
	defer closeHandler()
	socket, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return serve(ctx, logger, []listener{{socket: socket, server: newServer(runtime.NewRequestMiddleware(logger)(handler))}})
}

func runMigrate(ctx context.Context, getenv func(string) string) error {
	dsn, err := required(getenv, databaseURLEnv)
	if err != nil {
		return err
	}
	connection, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.PingContext(ctx); err != nil {
		return err
	}
	return migrations.Apply(ctx, connection)
}

func required(getenv func(string) string, name string) (string, error) {
	value := getenv(name)
	if value == "" {
		return "", diagnostic("config_missing")
	}
	return value, nil
}

func validatePrivateAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("private listener requires an explicit host and port")
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !(ip.IsLoopback() || ip.IsPrivate()) {
		return errors.New("private listener must bind to a loopback or private IP")
	}
	return nil
}

type listener struct {
	socket net.Listener
	server *http.Server
}

func newServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: readHeaderTimeout, IdleTimeout: idleTimeout}
}

func serve(ctx context.Context, logger *slog.Logger, listeners []listener) error {
	results := make(chan error, len(listeners))
	for _, item := range listeners {
		go func(item listener) {
			err := item.server.Serve(item.socket)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			results <- err
		}(item)
	}
	var result error
	select {
	case <-ctx.Done():
		logger.Info("shutdown_requested")
	case result = <-results:
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, item := range listeners {
		if err := item.server.Shutdown(shutdownContext); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}
