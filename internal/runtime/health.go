package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/store"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
)

type HealthConfig struct {
	DatabaseURL         string
	DatabasePingTimeout time.Duration
	Metrics             *Metrics
}

func NewControlHealthHandler(config HealthConfig) (http.Handler, func(), error) {
	if config.DatabaseURL == "" {
		return nil, func() {}, errors.New("database URL is required")
	}
	if config.DatabasePingTimeout <= 0 {
		config.DatabasePingTimeout = time.Second
	}

	pool, err := pgxpool.New(context.Background(), config.DatabaseURL)
	if err != nil {
		return nil, func() {}, err
	}

	handler := http.NewServeMux()
	handler.HandleFunc("GET "+livePath, func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, http.StatusOK, healthResponse{Status: "ok"})
	})
	readiness := func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), config.DatabasePingTimeout)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			if config.Metrics != nil {
				config.Metrics.SetReadiness(false)
			}
			writeHealth(w, http.StatusServiceUnavailable, healthResponse{
				Status:     "not_ready",
				Dependency: "database",
			})
			return
		}
		migrated, err := store.New(pool).IsSchemaVersionApplied(ctx, migrations.RequiredVersion)
		if err != nil || !migrated {
			if config.Metrics != nil {
				config.Metrics.SetReadiness(false)
			}
			writeHealth(w, http.StatusServiceUnavailable, healthResponse{Status: "not_ready", Dependency: "migration"})
			return
		}
		if config.Metrics != nil {
			config.Metrics.SetReadiness(true)
		}
		writeHealth(w, http.StatusOK, healthResponse{Status: "ok"})
	}
	handler.HandleFunc("GET "+readyPath, readiness)
	handler.HandleFunc("GET "+privateHealthPath, readiness)

	return handler, pool.Close, nil
}

type healthResponse struct {
	Status     string `json:"status"`
	Dependency string `json:"dependency,omitempty"`
}

func writeHealth(w http.ResponseWriter, status int, response healthResponse) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}
