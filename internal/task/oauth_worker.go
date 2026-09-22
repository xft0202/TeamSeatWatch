package task

import (
	"context"
	"errors"
	"time"

	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

func (w *Worker) runDeliveryGeneration(ctx context.Context, item Task, lease *egress.Lease) error {
	target, err := w.Store.DeliveryTarget(ctx, item)
	if err != nil {
		return err
	}
	attempt, err := w.Store.BeginDeliveryAttempt(ctx, item)
	if err != nil {
		return err
	}
	probeFailure := func(code string) platform.DeliveryLiveness {
		return platform.DeliveryLiveness{Status: oauthdomain.ProbeUnknown, ErrorCode: code, Origin: "generation", ObservedAt: time.Now().UTC()}
	}
	if w.DeliveryAdapter == nil {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, platform.DeliveryCredentialSet{}, probeFailure("oauth_generator_unavailable"))
	}
	generator, err := w.DeliveryAdapter(lease.Client(), platform.Credentials{LoginIdentifier: target.TargetIdentifier, Password: target.Password})
	if err != nil {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, platform.DeliveryCredentialSet{}, probeFailure("oauth_configuration_invalid"))
	}
	generated, err := generator.CreateDeliveryCredentials(ctx, platform.DeliveryCredentialRequest{
		Identifier: target.TargetIdentifier,
		Password:   target.Password,
		TOTPSecret: target.TOTPSecret,
		Recovery:   target.RecoverySecret,
		Workspace:  target.PlatformWorkspace,
	})
	if err != nil {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, platform.DeliveryCredentialSet{}, probeFailure("oauth_generation_failed"))
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishDeliveryAttempt(ctx, item, attempt, target, generated, probeFailure("proxy_egress_drift"))
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	probe, probeErr := generator.CheckDeliveryLiveness(ctx, generated.AccessToken, target.PlatformWorkspace)
	if probe.ObservedAt.IsZero() {
		probe.ObservedAt = time.Now().UTC()
	}
	if probe.Origin == "" {
		probe.Origin = "generation"
	}
	if probeErr != nil && probe.ErrorCode == "" {
		probe.ErrorCode = "oauth_probe_failed"
	}
	if err := lease.Remeasure(ctx); err != nil {
		probe.Status = oauthdomain.ProbeTransientFailure
		probe.HTTPStatus = 0
		probe.ErrorCode = "proxy_egress_drift"
	}
	return w.finishDeliveryAttempt(ctx, item, attempt, target, generated, probe)
}

func (w *Worker) finishDeliveryAttempt(ctx context.Context, item Task, attempt DeliveryAttempt, target DeliveryTarget, generated platform.DeliveryCredentialSet, probe platform.DeliveryLiveness) error {
	if err := w.Store.FinishDeliveryAttempt(ctx, item, attempt, target, generated, probe); err != nil {
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
