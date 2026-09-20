package task

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
	"github.com/teamseatwatch/teamseatwatch/internal/workspace"
)

var ErrAttemptFailed = errors.New("workspace read attempt failed")

type ReaderFactory func(*http.Client, platform.Credentials) (platform.Reader, error)

type Worker struct {
	Store       *Store
	Facts       *workspace.Service
	Egress      *egress.LeaseManager
	Reader      ReaderFactory
	ID          string
	LeaseTime   time.Duration
	lastCleanup time.Time
}

// RunOnce performs only the Workspace read slice. The DB lease transaction ends
// before Reader is called, and every publication is fenced again in PostgreSQL.
func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	if settled, err := w.Store.SettleExhausted(ctx); err != nil || settled {
		return settled, err
	}
	if w.cleanupDue() {
		cleanup, err := w.Store.ClaimCleanup(ctx, w.ID, w.leaseDuration())
		w.lastCleanup = time.Now()
		if err == nil {
			err = w.Store.CompleteCleanup(ctx, cleanup, func(ctx context.Context, tx pgx.Tx, workspaceID string) error {
				return w.Facts.DeleteExpiredWorkspaceTx(ctx, tx, workspaceID)
			})
			if err != nil {
				_ = w.Store.RecordInterruption(ctx, cleanup, "cleanup_fenced", "retention_cleanup")
			}
			return true, err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
	}
	lease, err := w.Egress.Acquire(ctx)
	if err != nil {
		if errors.Is(err, egress.ErrLeaseExhausted) || errors.Is(err, egress.ErrEgressDrift) {
			resultCode := "proxy_capacity_exhausted"
			if errors.Is(err, egress.ErrEgressDrift) {
				resultCode = "proxy_egress_drift"
			}
			item, claimErr := w.Store.ClaimRejected(ctx, w.ID, w.leaseDuration())
			if errors.Is(claimErr, pgx.ErrNoRows) {
				return false, nil
			}
			if claimErr != nil {
				return false, claimErr
			}
			return true, w.fail(ctx, item, "task.rejected", resultCode, "egress_admission")
		}
		return false, err
	}
	defer lease.Release()
	route := AttemptRoute{Mode: string(lease.Mode())}
	if lease.Mode() == egress.ModeRequired {
		scheme, keyVersion, stage := lease.Scheme(), lease.KeyVersion(), "remeasured"
		verified := lease.VerifiedAt()
		fingerprint := lease.Fingerprint()
		route.Scheme = &scheme
		route.KeyVersion = &keyVersion
		route.Stage = &stage
		route.VerifiedAt = &verified
		route.Fingerprint = fingerprint[:]
	}
	item, err := w.Store.Claim(ctx, w.ID, w.leaseDuration(), route)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	target, err := w.Store.WorkspaceReadTarget(ctx, item.WorkspaceID)
	if err != nil {
		return true, w.fail(ctx, item, "task.rejected", "platform_credential_unavailable", "credential_resolution")
	}
	reader, err := w.Reader(lease.Client(), platform.Credentials{
		LoginIdentifier: target.LoginIdentifier,
		Password:        target.Password,
	})
	if err != nil {
		return true, w.fail(ctx, item, "task.rejected", "platform_configuration_invalid", "prepare")
	}
	reads := []func(context.Context, string) (platform.Result, error){
		reader.ReadExchange, reader.ReadSubscription, reader.ReadCapacity,
		reader.ReadJoin, reader.ReadMembers, reader.ReadPendingInvites,
	}
	results := make([]platform.Result, 0, len(reads))
	for index, read := range reads {
		if index > 0 {
			if err := lease.Remeasure(ctx); err != nil {
				return true, w.fail(ctx, item, "task.interrupted", "proxy_egress_drift", "remeasure")
			}
		}
		result, readErr := read(ctx, target.PlatformWorkspaceID)
		if readErr != nil {
			result.ObservedAt = time.Now().UTC()
			result.Outcome = platform.Classify(0, "", readErr)
		}
		results = append(results, result)
		if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
			_ = w.Store.RecordInterruption(ctx, item, "lease_lost", "renew")
			return true, err
		}
	}
	if err := w.Store.CompleteWorkspaceRead(ctx, item, func(ctx context.Context, tx pgx.Tx, workspaceID string) error {
		return w.Facts.PublishReadTx(ctx, tx, workspaceID, results)
	}); err != nil {
		_ = w.Store.RecordInterruption(ctx, item, "publication_fenced", "publish")
		return true, err
	}
	return true, nil
}

func (w *Worker) fail(ctx context.Context, item Task, eventType, result, stage string) error {
	if err := w.Store.Settle(ctx, item, "failed", eventType, "failed", result, stage); err != nil {
		return err
	}
	return ErrAttemptFailed
}

func (w *Worker) cleanupDue() bool {
	return w.lastCleanup.IsZero() || time.Since(w.lastCleanup) >= 5*time.Second
}

func (w *Worker) leaseDuration() time.Duration {
	if w.LeaseTime <= 0 {
		return 30 * time.Second
	}
	return w.LeaseTime
}
