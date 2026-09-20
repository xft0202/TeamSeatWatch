package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/internalapi"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
	"github.com/teamseatwatch/teamseatwatch/internal/task"
	"github.com/teamseatwatch/teamseatwatch/internal/workspace"
)

// ControlConfig contains immutable startup dependencies for the control role.
type ControlConfig struct {
	Context             context.Context
	DatabaseURL         string
	DatabasePingTimeout time.Duration
	StaticDir           string
	PlatformClients     egress.PlatformClients
	EgressLeases        *egress.LeaseManager
	EgressStatus        egress.Status
	PlatformBaseURL     string
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
	if config.Context == nil || config.PlatformClients == nil || config.EgressLeases == nil {
		return ControlHandlers{}, errors.New("platform client boundary is required")
	}
	platformConfig, err := platform.NewHTTPConfig(config.PlatformBaseURL)
	if err != nil {
		return ControlHandlers{}, err
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
	workerPool, err := pgxpool.New(config.Context, config.DatabaseURL)
	if err != nil {
		closeOwnerAuth()
		closeHealth()
		return ControlHandlers{}, err
	}
	workspaceWorker := &task.Worker{
		Store: task.NewStore(workerPool), Facts: workspace.NewService(workerPool, keyRing),
		Egress: config.EgressLeases, ID: "workspace-reader-1",
		Reader: func(client *http.Client, credentials platform.Credentials) (platform.Reader, error) {
			return platformConfig.Reader(client, credentials)
		},
	}
	workerContext, cancelWorker := context.WithCancel(config.Context)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		runWorkspaceWorker(workerContext, workerPool, workspaceWorker, metrics)
	}()
	var closeOnce sync.Once

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
			closeOnce.Do(func() {
				// Stop and join the worker before closing the pool it owns.
				cancelWorker()
				<-workerDone
				closeOwnerAuth()
				workerPool.Close()
				config.PlatformClients.CloseIdleConnections()
				closeHealth()
			})
		},
	}, nil
}

func runWorkspaceWorker(ctx context.Context, pool *pgxpool.Pool, worker *task.Worker, metrics *Metrics) {
	ticker := time.NewTicker(time.Second)
	cleanupTicker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer cleanupTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			queued, running := int64(0), int64(0)
			_ = pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status IN ('queued','retry_wait')), count(*) FILTER (WHERE status='running' AND lease_expires_at>now()) FROM tsw_tasks`).Scan(&queued, &running)
			metrics.SetTaskCounts(queued, running, int64(worker.Egress.ActiveCount()))
			didWork, err := worker.RunOnce(ctx)
			if err != nil {
				metrics.IncTaskResult(false)
			} else if didWork {
				metrics.IncTaskResult(true)
			}
		case now := <-cleanupTicker.C:
			if _, err := worker.Store.EnqueueExpiredCleanups(ctx, 100, now.UTC().Format("20060102T1504")); err != nil {
				metrics.IncRetentionScheduleFailure()
			}
		}
	}
}

type privateHealthHandler struct {
	health http.Handler
}

func (handler privateHealthHandler) GetPrivateHealth(w http.ResponseWriter, r *http.Request) {
	handler.health.ServeHTTP(w, r)
}
