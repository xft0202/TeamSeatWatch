package task

import (
	"context"
	"errors"
	"time"

	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

func (w *Worker) runDeliveryProbe(ctx context.Context, item Task, lease *egress.Lease) error {
	if w.DeliveryProbe == nil {
		return w.fail(ctx, item, "task.rejected", "oauth_probe_unavailable", "prepare")
	}
	target, err := w.Store.DeliveryProbeTarget(ctx, item)
	if err != nil {
		return w.fail(ctx, item, "task.rejected", "oauth_probe_target_unavailable", "credential_resolution")
	}
	attempt, err := w.Store.BeginDeliveryAttempt(ctx, item)
	if err != nil {
		return err
	}
	prober, err := w.DeliveryProbe(lease.Client())
	if err != nil {
		return w.finishDeliveryProbe(ctx, item, attempt, target, platform.DeliveryLiveness{Status: oauthdomain.ProbeUnknown, ErrorCode: "oauth_probe_configuration_invalid", Origin: "scheduled", ObservedAt: time.Now().UTC()})
	}
	probe, probeErr := prober.CheckDeliveryLiveness(ctx, target.AccessToken, target.PlatformWorkspace)
	if probe.ObservedAt.IsZero() {
		probe.ObservedAt = time.Now().UTC()
	}
	probe.Origin = "scheduled"
	if probeErr != nil && probe.ErrorCode == "" {
		probe.ErrorCode = "oauth_probe_failed"
	}
	if err := lease.Remeasure(ctx); err != nil {
		probe.Status = oauthdomain.ProbeTransientFailure
		probe.HTTPStatus = 0
		probe.ErrorCode = "proxy_egress_drift"
	}
	return w.finishDeliveryProbe(ctx, item, attempt, target, probe)
}

func (w *Worker) finishDeliveryProbe(ctx context.Context, item Task, attempt DeliveryAttempt, target DeliveryProbeTarget, probe platform.DeliveryLiveness) error {
	if err := w.Store.FinishDeliveryProbe(ctx, item, attempt, target, probe); err != nil {
		if errors.Is(err, ErrDeliveryAttemptSuperseded) {
			return ErrAttemptFailed
		}
		return err
	}
	if probe.Status != oauthdomain.ProbeOK {
		return ErrAttemptFailed
	}
	return nil
}
