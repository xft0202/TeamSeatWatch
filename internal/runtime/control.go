package runtime

import (
	"errors"
	"net/http"
	"time"

	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/internalapi"
)

type ControlConfig struct {
	DatabaseURL         string
	DatabasePingTimeout time.Duration
	StaticDir           string
	PlatformClients     egress.PlatformClients
	EgressStatus        egress.Status
}

type ControlHandlers struct {
	Public          http.Handler
	Private         http.Handler
	PlatformClients egress.PlatformClients
	Close           func()
}

func NewControlHandlers(config ControlConfig) (ControlHandlers, error) {
	if config.PlatformClients == nil {
		return ControlHandlers{}, errors.New("platform client boundary is required")
	}
	metrics := NewMetrics(config.EgressStatus)
	health, closeHealth, err := NewControlHealthHandler(HealthConfig{
		DatabaseURL:         config.DatabaseURL,
		DatabasePingTimeout: config.DatabasePingTimeout,
		Metrics:             metrics,
	})
	if err != nil {
		return ControlHandlers{}, err
	}
	staticHandler, err := newStaticHandler(config.StaticDir, ownerRoute)
	if err != nil {
		closeHealth()
		return ControlHandlers{}, err
	}

	public := http.NewServeMux()
	public.Handle("/", staticHandler)
	private := http.NewServeMux()
	private.Handle(livePath, health)
	private.Handle(readyPath, health)
	private.Handle(metricsPath, metrics.Handler())
	internalapi.HandlerFromMux(privateHealthHandler{health: health}, private)
	return ControlHandlers{
		Public:          metrics.CountRequests(public),
		Private:         metrics.CountRequests(private),
		PlatformClients: config.PlatformClients,
		Close: func() {
			config.PlatformClients.CloseIdleConnections()
			closeHealth()
		},
	}, nil
}

type privateHealthHandler struct {
	health http.Handler
}

func (handler privateHealthHandler) GetPrivateHealth(w http.ResponseWriter, r *http.Request) {
	handler.health.ServeHTTP(w, r)
}
