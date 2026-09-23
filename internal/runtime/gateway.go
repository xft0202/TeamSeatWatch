package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type GatewayConfig struct {
	ControlURL   string
	ProbeClient  *http.Client
	ProbeTimeout time.Duration
	StaticDir    string
}

func configuredMTLSClient(client *http.Client) bool {
	if client == nil || client.Transport == nil {
		return false
	}
	transport, ok := client.Transport.(*http.Transport)
	return ok && transport.TLSClientConfig != nil && len(transport.TLSClientConfig.Certificates) > 0
}

func NewGatewayHandler(config GatewayConfig) (http.Handler, func(), error) {
	if config.ControlURL != "" {
		endpoint, err := url.Parse(config.ControlURL)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != privateHealthPath || !configuredMTLSClient(config.ProbeClient) {
			return nil, nil, errors.New("private control health requires an HTTPS endpoint and a configured mTLS transport")
		}
	}
	if config.ProbeTimeout <= 0 {
		config.ProbeTimeout = defaultProbeTimeout
	}
	client := config.ProbeClient

	handler := http.NewServeMux()
	handler.HandleFunc("GET "+livePath, func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, http.StatusOK, healthResponse{Status: "ok"})
	})
	handler.HandleFunc("GET "+readyPath, func(w http.ResponseWriter, r *http.Request) {
		if config.ControlURL == "" {
			writeHealth(w, http.StatusServiceUnavailable, healthResponse{Status: "not_ready", Dependency: "control_service"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), config.ProbeTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.ControlURL, nil)
		if err != nil {
			writeHealth(w, http.StatusServiceUnavailable, healthResponse{Status: "not_ready", Dependency: "control_service"})
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			writeHealth(w, http.StatusServiceUnavailable, healthResponse{Status: "not_ready", Dependency: "control_service"})
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			writeHealth(w, http.StatusServiceUnavailable, healthResponse{Status: "not_ready", Dependency: "control_service"})
			return
		}
		writeHealth(w, http.StatusOK, healthResponse{Status: "ok"})
	})

	proxy, err := newPublicProxy(config.ControlURL, client)
	if err != nil {
		return nil, nil, err
	}
	handler.Handle("/api/public/v1/", proxy)
	handler.HandleFunc("/api/public/v1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/public/v1/", http.StatusPermanentRedirect)
	})

	staticHandler, err := newStaticHandler(config.StaticDir, publicRoute)
	if err != nil {
		return nil, func() {}, err
	}
	handler.Handle("/", staticHandler)

	return handler, func() {}, nil
}

func newPublicProxy(controlURL string, client *http.Client) (http.Handler, error) {
	endpoint, err := url.Parse(controlURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || client == nil {
		return nil, errors.New("public proxy requires the private mTLS control client")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicPath := strings.TrimPrefix(r.URL.Path, "/api/public/v1")
		if !allowedPublicProxyPath(publicPath) {
			writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
			return
		}
		target := *endpoint
		target.Path = "/internal/v1/public" + publicPath
		target.RawQuery = r.URL.RawQuery
		request, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
		if err != nil {
			writePublicProblem(w, r, http.StatusServiceUnavailable, "public_unavailable", 0)
			return
		}
		for name, values := range r.Header {
			if strings.EqualFold(name, "X-TSW-Source-IP") || strings.EqualFold(name, "Host") {
				continue
			}
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		request.Header.Set("X-TSW-Source-IP", gatewaySourceIP(r))
		response, err := client.Do(request)
		if err != nil {
			writePublicProblem(w, r, http.StatusServiceUnavailable, "public_unavailable", 0)
			return
		}
		defer response.Body.Close()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}), nil
}

func gatewaySourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}
	return "unknown"
}

func allowedPublicProxyPath(path string) bool {
	switch path {
	case "/redeem/confirm", "/redeem/state", "/redeem/records", "/redeem/credential-status", "/redeem/download":
		return true
	default:
		return false
	}
}
