package runtime

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/internalapi"
)

// ControlConfig contains immutable startup dependencies for the control role.
type ControlConfig struct {
	DatabaseURL         string
	DatabasePingTimeout time.Duration
	StaticDir           string
	PlatformClients     egress.PlatformClients
	EgressStatus        egress.Status
	TOTPKeyRingFile     string
	OwnerOrigins        auth.OriginPolicy
}

// ControlHandlers separates the public Owner surface from private health and metrics.
type ControlHandlers struct {
	Public          http.Handler
	Private         http.Handler
	PlatformClients egress.PlatformClients
	Close           func()
}

// NewControlHandlers loads security material before exposing the Owner API.
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
	// Keyring loading is fail-closed so encrypted TOTP material is never accepted without its deployment key.
	keyRing, err := auth.LoadKeyRingFile(config.TOTPKeyRingFile)
	if err != nil {
		closeHealth()
		return ControlHandlers{}, fmt.Errorf("invalid TOTP key ring: %w", err)
	}
	ownerAuth, closeOwnerAuth, err := NewOwnerAuthHandler(OwnerAuthConfig{DatabaseURL: config.DatabaseURL, KeyRing: keyRing, Origins: config.OwnerOrigins})
	if err != nil {
		closeHealth()
		return ControlHandlers{}, err
	}

	public := http.NewServeMux()
	public.Handle("/api/owner/", ownerAuth)
	public.Handle("/owner/", staticHandler)
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
			closeOwnerAuth()
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
