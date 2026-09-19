package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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

	staticHandler, err := newStaticHandler(config.StaticDir, publicRoute)
	if err != nil {
		return nil, func() {}, err
	}
	handler.Handle("/", staticHandler)

	return handler, func() {}, nil
}
