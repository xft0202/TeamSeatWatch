package task

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
	targetdomain "github.com/teamseatwatch/teamseatwatch/internal/target"
	"github.com/teamseatwatch/teamseatwatch/internal/workspace"
)

var ErrAttemptFailed = errors.New("task attempt failed")

type ReaderFactory func(*http.Client, platform.Credentials) (platform.Reader, error)
type TargetProberFactory func(*http.Client, platform.Credentials) (*platform.HTTPReader, error)

type Worker struct {
	Store        *Store
	Facts        *workspace.Service
	Targets      *targetdomain.Service
	Egress       *egress.LeaseManager
	Reader       ReaderFactory
	TargetProber TargetProberFactory
	ID           string
	LeaseTime    time.Duration
	lastCleanup  time.Time
}

// RunOnce reuses the Ticket 04 durable queue, lease fence, egress lease and
// terminal audit boundary for both Workspace reads and target-account probes.
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

	taskType, err := w.Store.NextNetworkTaskType(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	lease, err := w.Egress.Acquire(ctx)
	if err != nil {
		return w.rejectForEgress(ctx, taskType, err)
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
	var item Task
	if taskType == "target_account_probe" {
		item, err = w.Store.ClaimTargetProbe(ctx, w.ID, w.leaseDuration(), route)
	} else {
		item, err = w.Store.Claim(ctx, w.ID, w.leaseDuration(), route)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if item.TaskType == "target_account_probe" {
		return true, w.runTargetProbe(ctx, item, lease)
	}
	return true, w.runWorkspaceRead(ctx, item, lease)
}

func (w *Worker) rejectForEgress(ctx context.Context, taskType string, acquireErr error) (bool, error) {
	if !errors.Is(acquireErr, egress.ErrLeaseExhausted) && !errors.Is(acquireErr, egress.ErrEgressDrift) {
		return false, acquireErr
	}
	resultCode := "proxy_capacity_exhausted"
	if errors.Is(acquireErr, egress.ErrEgressDrift) {
		resultCode = "proxy_egress_drift"
	}
	var item Task
	var err error
	if taskType == "target_account_probe" {
		item, err = w.Store.ClaimRejectedTargetProbe(ctx, w.ID, w.leaseDuration())
	} else {
		item, err = w.Store.ClaimRejected(ctx, w.ID, w.leaseDuration())
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if item.TaskType == "target_account_probe" {
		probe := platform.TargetProbeResult{
			Status: platform.TargetUnknown, Endpoint: "account_usage", Origin: "worker",
			ErrorCode: resultCode, ObservedAt: time.Now().UTC(),
		}
		err = w.Store.RejectTargetProbe(ctx, item, resultCode, "egress_admission", func(ctx context.Context, tx pgx.Tx, targetID string) error {
			return w.Targets.PublishProbeTx(ctx, tx, targetID, probe, item.CorrelationID, targetProbeAuditKey(item))
		})
		if err != nil {
			return true, err
		}
		return true, ErrAttemptFailed
	}
	return true, w.fail(ctx, item, "task.rejected", resultCode, "egress_admission")
}

func (w *Worker) runTargetProbe(ctx context.Context, item Task, lease *egress.Lease) error {
	target, err := w.Store.TargetProbeTarget(ctx, item.TargetAccountID)
	if err != nil {
		return w.rejectTargetProbe(ctx, item, "platform_credential_unavailable", "credential_resolution")
	}
	prober, err := w.TargetProber(lease.Client(), platform.Credentials{
		LoginIdentifier: target.LoginIdentifier,
		Password:        target.Password,
	})
	if err != nil {
		return w.rejectTargetProbe(ctx, item, "platform_configuration_invalid", "prepare")
	}
	result, probeErr := prober.ProbeTarget(ctx)
	var egressErr *egress.ConfigError
	if errors.As(probeErr, &egressErr) {
		result.Status = platform.TargetUnknown
		result.ErrorCode = egressErr.Code()
	}
	if result.Status == "" {
		result.Status = platform.TargetUnknown
	}
	if result.Endpoint == "" {
		result.Endpoint = "account_usage"
	}
	if result.Origin == "" {
		result.Origin = "worker"
	}
	if err := w.Store.CompleteTargetProbe(ctx, item, func(ctx context.Context, tx pgx.Tx, targetID string) error {
		return w.Targets.PublishProbeTx(ctx, tx, targetID, result, item.CorrelationID, targetProbeAuditKey(item))
	}); err != nil {
		_ = w.Store.RecordInterruption(ctx, item, "publication_fenced", "publish")
		return err
	}
	return nil
}

func (w *Worker) rejectTargetProbe(ctx context.Context, item Task, resultCode, stage string) error {
	probe := platform.TargetProbeResult{
		Status: platform.TargetUnknown, Endpoint: "account_usage", Origin: "worker",
		ErrorCode: resultCode, ObservedAt: time.Now().UTC(),
	}
	if err := w.Store.RejectTargetProbe(ctx, item, resultCode, stage, func(ctx context.Context, tx pgx.Tx, targetID string) error {
		return w.Targets.PublishProbeTx(ctx, tx, targetID, probe, item.CorrelationID, targetProbeAuditKey(item))
	}); err != nil {
		return err
	}
	return ErrAttemptFailed
}

func (w *Worker) runWorkspaceRead(ctx context.Context, item Task, lease *egress.Lease) error {
	target, err := w.Store.WorkspaceReadTarget(ctx, item.WorkspaceID)
	if err != nil {
		return w.fail(ctx, item, "task.rejected", "platform_credential_unavailable", "credential_resolution")
	}
	reader, err := w.Reader(lease.Client(), platform.Credentials{
		LoginIdentifier: target.LoginIdentifier,
		Password:        target.Password,
	})
	if err != nil {
		return w.fail(ctx, item, "task.rejected", "platform_configuration_invalid", "prepare")
	}
	reads := []func(context.Context, string) (platform.Result, error){
		reader.ReadExchange, reader.ReadSubscription, reader.ReadCapacity,
		reader.ReadJoin, reader.ReadMembers, reader.ReadPendingInvites,
	}
	results := make([]platform.Result, 0, len(reads))
	for index, read := range reads {
		if index > 0 {
			if err := lease.Remeasure(ctx); err != nil {
				return w.fail(ctx, item, "task.interrupted", "proxy_egress_drift", "remeasure")
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
			return err
		}
	}
	if err := w.Store.CompleteWorkspaceRead(ctx, item, func(ctx context.Context, tx pgx.Tx, workspaceID string) error {
		return w.Facts.PublishReadTx(ctx, tx, workspaceID, results)
	}); err != nil {
		_ = w.Store.RecordInterruption(ctx, item, "publication_fenced", "publish")
		return err
	}
	return nil
}

func targetProbeAuditKey(item Task) string {
	return item.ID + ":target-account.probed:" + strconv.Itoa(item.AttemptNo)
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
