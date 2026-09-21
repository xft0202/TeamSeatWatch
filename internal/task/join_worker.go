package task

import (
	"context"
	"errors"

	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

func (w *Worker) runJoin(ctx context.Context, item Task, lease *egress.Lease) error {
	if w.Joiner == nil || w.TargetProber == nil {
		return w.finishJoinFailure(ctx, item, "platform_configuration_invalid", "prepare", "failed")
	}
	target, err := w.Store.JoinTarget(ctx, item)
	if err != nil {
		return w.finishJoinFailure(ctx, item, "platform_credential_unavailable", "credential_resolution", "failed")
	}
	if target.PlatformRequestMayHaveReached {
		return w.runJoinReconcile(ctx, item, lease)
	}
	credentials := platform.Credentials{LoginIdentifier: target.TargetIdentifier, Password: target.TargetPassword}
	prober, err := w.TargetProber(lease.Client(), credentials)
	if err != nil {
		return w.finishJoinFailure(ctx, item, "platform_configuration_invalid", "preflight_prepare", "failed")
	}
	preflight, probeErr := prober.ProbeTarget(ctx)
	if probeErr != nil && preflight.Status == "" {
		preflight.Status = platform.TargetTransientFailure
		preflight.ErrorCode = "preflight_transport_failure"
	}
	if preflight.Status == "" {
		preflight.Status = platform.TargetUnknown
	}
	if err := w.Store.RecordJoinPreflight(ctx, item, preflight); err != nil {
		return err
	}
	if preflight.Status != platform.TargetAvailable {
		status := "blocked"
		if preflight.Status == platform.TargetCredentialInvalid || preflight.Status == platform.TargetDefinitelyUnavailable {
			status = "failed"
		}
		return w.finishJoin(ctx, item, target, status, string(preflight.Status), preflight.ErrorCode, "preflight", nil)
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishJoin(ctx, item, target, "blocked", "proxy_egress_drift", "proxy_egress_drift", "before_join_request", nil)
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	joiner, err := w.Joiner(lease.Client(), credentials)
	if err != nil {
		return w.finishJoin(ctx, item, target, "failed", "platform_configuration_invalid", "platform_configuration_invalid", "join_prepare", nil)
	}
	// Fence the first POST in durable state before sending it. A worker crash
	// after this point must reconcile membership rather than replay the join.
	if err := w.Store.MarkJoinSideEffectStarted(ctx, item, "request_join"); err != nil {
		return err
	}
	request, requestErr := joiner.RequestJoin(ctx, target.PlatformWorkspace)
	if requestErr != nil {
		return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", "join_request_failed", "join_request", nil)
	}
	if !request.Success {
		code := request.ErrorCode
		if code == "" {
			code = "join_request_rejected"
		}
		if request.RequestMayHaveEffect {
			return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", code, "join_request", nil)
		}
		return w.finishJoin(ctx, item, target, "failed", code, code, "join_request", nil)
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", "proxy_egress_drift", "before_accept", nil)
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	// The second POST has its own durable stage boundary; the lease is checked
	// immediately before it and any later attempt is read-only reconciliation.
	if err := w.Store.MarkJoinSideEffectStarted(ctx, item, "accept_join"); err != nil {
		return err
	}
	accept, acceptErr := joiner.AcceptJoin(ctx, target.PlatformWorkspace)
	if acceptErr != nil || (!accept.Success && accept.RequestMayHaveEffect) {
		return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", "accept_uncertain", "join_accept", nil)
	}
	if !accept.Success {
		code := accept.ErrorCode
		if code == "" {
			code = "join_request_rejected"
		}
		return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", code, "join_accept", nil)
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", "proxy_egress_drift", "membership_verify", nil)
	}
	if err := w.Store.Renew(ctx, item.ID, item.LeaseToken, w.leaseDuration()); err != nil {
		return err
	}
	member, verifyErr := joiner.VerifyMembership(ctx, target.PlatformWorkspace, target.TargetIdentifier)
	if verifyErr != nil || !member.Complete {
		code := member.ErrorCode
		if code == "" {
			code = "membership_unknown"
		}
		return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", code, "membership_verify", nil)
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", "proxy_egress_drift", "after_membership_verify", nil)
	}
	if !member.Present {
		return w.finishJoin(ctx, item, target, "unknown", "platform_unknown", "member_not_confirmed", "membership_verify", &member)
	}
	return w.finishJoin(ctx, item, target, "succeeded", "member_confirmed", "", "membership_verify", &member)
}

func (w *Worker) runJoinReconcile(ctx context.Context, item Task, lease *egress.Lease) error {
	if w.Joiner == nil {
		return w.finishJoinReconcile(ctx, item, JoinTarget{}, platform.MembershipResult{ErrorCode: "platform_configuration_invalid"})
	}
	target, err := w.Store.JoinTarget(ctx, item)
	if err != nil {
		return err
	}
	joiner, err := w.Joiner(lease.Client(), platform.Credentials{LoginIdentifier: target.TargetIdentifier, Password: target.TargetPassword})
	if err != nil {
		return w.finishJoinReconcile(ctx, item, target, platform.MembershipResult{ErrorCode: "platform_configuration_invalid"})
	}
	if err := lease.Remeasure(ctx); err != nil {
		return w.finishJoinReconcile(ctx, item, target, platform.MembershipResult{ErrorCode: "proxy_egress_drift"})
	}
	member, verifyErr := joiner.VerifyMembership(ctx, target.PlatformWorkspace, target.TargetIdentifier)
	if verifyErr != nil || !member.Complete {
		member.ErrorCode = "membership_unknown"
	}
	if err := lease.Remeasure(ctx); err != nil {
		member.Complete = false
		member.ErrorCode = "proxy_egress_drift"
	}
	return w.finishJoinReconcile(ctx, item, target, member)
}

func (w *Worker) finishJoin(ctx context.Context, item Task, target JoinTarget, status, outcome, diagnostic, stage string, member *platform.MembershipResult) error {
	if err := w.Store.FinishJoin(ctx, item, target, status, outcome, diagnostic, stage, member); err != nil {
		return err
	}
	if status != "succeeded" {
		return ErrAttemptFailed
	}
	return nil
}

func (w *Worker) finishJoinFailure(ctx context.Context, item Task, diagnostic, stage, status string) error {
	target, err := w.Store.JoinTarget(ctx, item)
	if err != nil {
		return err
	}
	return w.finishJoin(ctx, item, target, status, diagnostic, diagnostic, stage, nil)
}

func (w *Worker) finishJoinReconcile(ctx context.Context, item Task, target JoinTarget, member platform.MembershipResult) error {
	if target.OperationID == "" {
		return errors.New("join reconciliation target is missing")
	}
	if err := w.Store.FinishJoinReconciliation(ctx, item, target, member); err != nil {
		return err
	}
	return nil
}
