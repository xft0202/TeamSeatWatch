package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

// rotationJoinStatus is intentionally a redacted projection. It contains only
// bounded state needed to choose the next explicit action; no account material,
// bearer, cookie, lease token, nonce, ciphertext or upstream response crosses
// this boundary.
func (h *OwnerAuthHandler) rotationJoinStatus(ctx context.Context, owner, preview, slot uuid.UUID) (ownerapi.RotationJoinStatus, error) {
	var out ownerapi.RotationJoinStatus
	var workspace uuid.UUID
	var candidate string
	var execution, membership, diagnostic string
	var componentCount int
	var review, complete, credentialAttempt, unknown, busy, allowed bool
	err := h.pool.QueryRow(ctx, `
SELECT s.workspace_id,COALESCE(i.candidate_identifier,target.identifier,''),COALESCE(e.state,''),
       COALESCE(m.result,''),COALESCE(m.diagnostic,''),COALESCE(c.component_count,0),
       COALESCE(c.review,false),COALESCE(c.complete,false),COALESCE(c.has_attempt,false),
       COALESCE(c.unknown,false),COALESCE(c.busy,false) OR COALESCE(e.lease_expires_at>clock_timestamp(),false),
       EXISTS(SELECT 1 FROM public.tsw_rotation_released_slots released WHERE released.id=s.id)
FROM public.tsw_rotation_removal_slots s
JOIN public.tsw_rotation_removals r ON r.preview_id=s.preview_id AND r.workspace_id=s.workspace_id
JOIN public.tsw_expiry_rotation_previews p ON p.id=r.preview_id AND p.owner_id=r.owner_id
JOIN public.tsw_target_accounts target ON target.id=s.candidate_account_id
LEFT JOIN public.tsw_rotation_candidate_join_intents i ON i.slot_id=s.id AND i.preview_id=s.preview_id
LEFT JOIN public.tsw_rotation_join_executions e ON e.slot_id=i.slot_id
LEFT JOIN LATERAL (
 SELECT ev.result,ev.diagnostic FROM public.tsw_rotation_join_membership_evidence ev
 WHERE ev.slot_id=s.id ORDER BY ev.reconciliation_attempt DESC LIMIT 1
) m ON true
LEFT JOIN LATERAL (
 SELECT count(DISTINCT cc.kind)::int AS component_count,
        bool_or(ce.event='review_required') AS review,
        count(DISTINCT ca.attempt_id)>0 AS has_attempt,
        bool_or(ce.event='started' AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_components saved WHERE saved.attempt_id=ca.attempt_id AND saved.kind=ce.stage)) AS unknown,
        bool_or(ca.lease_expires_at>clock_timestamp()) AS busy,
        EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_generations g
               JOIN public.tsw_rotation_join_credential_attempts ca USING(attempt_id)
               WHERE ca.slot_id=s.id) AS complete
 FROM public.tsw_rotation_join_credential_attempts ca
 LEFT JOIN public.tsw_rotation_join_credential_components cc ON cc.attempt_id=ca.attempt_id
 LEFT JOIN public.tsw_rotation_join_credential_events ce ON ce.attempt_id=ca.attempt_id
 WHERE ca.slot_id=s.id
) c ON true
WHERE s.id=$1 AND r.preview_id=$2 AND r.owner_id=$3`, slot, preview, owner).Scan(
		&workspace, &candidate, &execution, &membership, &diagnostic,
		&componentCount, &review, &complete, &credentialAttempt, &unknown, &busy, &allowed)
	if err != nil {
		return out, err
	}
	out.PreviewId, out.SlotId, out.WorkspaceId = preview, slot, workspace
	out.CandidateIdentifier = candidate
	out.Membership = membership
	if out.Membership == "" {
		out.Membership = "not_observed"
	}
	out.Credentials = "missing"
	if componentCount > 0 {
		out.Credentials = "partial"
	}
	if unknown {
		out.Credentials = "unknown"
	}
	if review {
		out.Credentials = "review_required"
	}
	if complete {
		out.Credentials = "complete"
	}
	switch {
	case execution == "":
		out.Phase, out.NextAction = "not_started", "run"
	case execution == "ready":
		out.Phase, out.NextAction = "intent_reserved", "run"
	case execution == "request_started":
		out.Phase, out.NextAction = "join_request_uncertain", "verify"
	case execution == "request_succeeded":
		out.Phase, out.NextAction = "join_request_sent", "verify"
	case execution == "accept_started":
		out.Phase, out.NextAction = "join_accept_uncertain", "verify"
	case execution == "reconcile_required":
		out.Phase = "reconcile_required"
		if membership == "confirmed" {
			if complete {
				out.NextAction = "none"
			} else if credentialAttempt {
				out.NextAction = "repair"
			} else {
				out.NextAction = "save"
			}
		} else {
			out.NextAction = "verify"
		}
	case execution == "blocked":
		out.Phase, out.NextAction = "blocked", "verify"
	default:
		out.Phase, out.NextAction = "unknown", "verify"
	}
	if complete {
		out.Phase, out.NextAction = "credentials_complete", "none"
	}
	out.Usage = "unobserved"
	var usageState, usageResult, usageScope string
	var usageFresh, usageBusy, usageAuthority bool
	if err = h.pool.QueryRow(ctx, `SELECT COALESCE(a.state,''),COALESCE(e.result,''),COALESCE(e.scope,''),COALESCE(e.expires_at>clock_timestamp(),false),COALESCE(a.lease_expires_at>clock_timestamp(),false),public.tsw_rotation_join_usage_ready($1),CASE WHEN $2 THEN public.tsw_rotation_join_usage_authority($1,p.authorized_session::uuid) ELSE false END FROM public.tsw_expiry_rotation_previews p LEFT JOIN LATERAL (SELECT * FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=$1 ORDER BY attempt_no DESC LIMIT 1) a ON true LEFT JOIN public.tsw_rotation_join_usage_evidence e ON e.attempt_id=a.id WHERE p.id=$3`, slot, complete, preview).Scan(&usageState, &usageResult, &usageScope, &usageFresh, &usageBusy, &out.DeliveryReady, &usageAuthority); err != nil {
		return out, err
	}
	if complete {
		out.NextAction = "observe"
		if usageState == "pending" {
			out.Usage = "pending"
		}
		if usageState == "complete" {
			out.Usage = usageResult
			out.NextAction = "recheck"
			if usageResult == "zero" && usageScope == "account" {
				out.Usage = "shared"
			}
			if !usageFresh {
				out.Usage = "stale"
			}
			if out.DeliveryReady {
				out.Phase = "usage_ready"
			} else {
				out.Phase = "usage_pending"
			}
		}
		if !usageAuthority {
			allowed = false
			out.DeliveryReady = false
		}
	}
	busy = busy || usageBusy
	if !allowed || busy {
		out.NextAction = "none"
	}
	if busy {
		out.Diagnostic = "action_in_progress"
	} else if !allowed {
		out.Diagnostic = "original_authority_unavailable"
	} else {
		out.Diagnostic = diagnostic
	}

	if out.Diagnostic == "" {
		out.Diagnostic = "none"
	}
	return out, nil
}

func (h *OwnerAuthHandler) GetRotationJoinStatus(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	status, err := h.rotationJoinStatus(r.Context(), uuid.MustParse(owner.OwnerID), preview, slot)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (h *OwnerAuthHandler) joinAction(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID, action string) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	if !decodeRotationJoinAction(w, r) {
		writeProblem(w, r, http.StatusUnprocessableEntity, "confirmation_required", "Confirmation Required", "Confirm this original slot action", 0)
		return
	}
	oid := uuid.MustParse(owner.OwnerID)
	status, statusErr := h.rotationJoinStatus(r.Context(), oid, preview, slot)
	if statusErr != nil {
		h.removalError(w, r, statusErr)
		return
	}
	// Duplicate run/save submissions observe their immutable obligation only.
	// They must not claim another reconcile lease or another credential attempt.
	if action == "run" && status.Phase != "not_started" && status.Phase != "intent_reserved" || action == "save" && status.Credentials != "missing" || status.Phase == "credentials_complete" {
		writeJSON(w, 200, status)
		return
	}
	worker := uuid.New()
	var err error
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	switch action {
	case "run":
		_, err = h.reserveRotationJoinIntent(ctx, owner, preview, slot)
		if err == nil {
			err = h.dispatchRotationCandidateJoin(ctx, owner, preview, slot, worker, 2*time.Minute)
		}
	case "verify":
		err = h.reconcileRotationJoinMembership(ctx, owner, preview, slot, worker, 2*time.Minute)
	case "save":
		err = h.saveRotationJoinCredentials(ctx, owner, preview, slot, worker, 2*time.Minute, false)
	case "repair":
		err = h.saveRotationJoinCredentials(ctx, owner, preview, slot, worker, 2*time.Minute, true)
	default:
		err = removalFailure("join_action_invalid")
	}
	// A durable uncertain/review state is the successful public result of an
	// ambiguous remote action. The status projection tells the caller what is
	// explicitly permitted next; it never turns a 2xx receipt into completion.
	if err != nil && !errors.Is(err, joinDispatchReconcileRequired) &&
		!errors.Is(err, joinCredentialsReview) {
		if errors.Is(err, joinCredentialsBusy) || errors.Is(err, joinExecutionBusy) {
			writeProblem(w, r, http.StatusConflict, string(joinCredentialsBusy), "Join Busy", "The original slot action is already running", 1)
			return
		}
		if errors.Is(err, joinCredentialsStale) || errors.Is(err, joinCredentialsRepair) {
			// Return the durable state when available; it carries the same intent.
			if status, statusErr := h.rotationJoinStatus(ctx, oid, preview, slot); statusErr == nil {
				writeJSON(w, http.StatusOK, status)
				return
			}
		}
		if errors.Is(err, platform.ErrRotationJoinUnavailable) || errors.Is(err, platform.ErrRotationCredentialsUnavailable) {
			writeProblem(w, r, http.StatusServiceUnavailable, "join_adapter_unavailable", "Join Temporarily Unavailable", "The original slot was not replaced; reload its status", 1)
			return
		}
		writeProblem(w, r, http.StatusConflict, "join_action_pending", "Original Join Pending", "Reload the same original slot; do not replay or replace it", 0)
		return
	}
	status, statusErr = h.rotationJoinStatus(ctx, oid, preview, slot)
	if statusErr != nil {
		h.removalError(w, r, statusErr)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// Exact singleton confirmation rejects case-folded duplicates and arbitrary
// replacement fields without changing shared legacy JSON decoding behavior.
func decodeRotationJoinAction(w http.ResponseWriter, r *http.Request) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := false
	for d.More() {
		key, err := d.Token()
		if err != nil || key != "confirmed" || seen {
			return false
		}
		seen = true
		var confirmed bool
		if d.Decode(&confirmed) != nil || !confirmed {
			return false
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || !seen {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}

func (h *OwnerAuthHandler) RunRotationJoin(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID, _ ownerapi.RunRotationJoinParams) {
	h.joinAction(w, r, preview, slot, "run")
}
func (h *OwnerAuthHandler) VerifyRotationJoin(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID, _ ownerapi.VerifyRotationJoinParams) {
	h.joinAction(w, r, preview, slot, "verify")
}
func (h *OwnerAuthHandler) SaveRotationJoinCredentials(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID, _ ownerapi.SaveRotationJoinCredentialsParams) {
	h.joinAction(w, r, preview, slot, "save")
}
func (h *OwnerAuthHandler) RepairRotationJoinCredentials(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID, _ ownerapi.RepairRotationJoinCredentialsParams) {
	h.joinAction(w, r, preview, slot, "repair")
}

func (h *OwnerAuthHandler) usageAction(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID, recheck bool) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	if !decodeRotationJoinAction(w, r) {
		writeProblem(w, r, 422, "confirmation_required", "Confirmation Required", "Confirm this original slot action", 0)
		return
	}
	oid := uuid.MustParse(owner.OwnerID)
	if _, err := h.rotationJoinStatus(r.Context(), oid, preview, slot); err != nil {
		h.removalError(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	err := h.observeRotationJoinUsage(ctx, owner, preview, slot, uuid.New(), 45*time.Second, recheck)
	if err != nil {
		if errors.Is(err, joinUsageBusy) {
			writeProblem(w, r, 409, "join_usage_busy", "Usage Busy", "The original slot read is already running", 1)
			return
		}
		writeProblem(w, r, 409, "join_usage_pending", "Original Usage Pending", "Reload the original slot status", 0)
		return
	}
	status, err := h.rotationJoinStatus(ctx, oid, preview, slot)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	writeJSON(w, 200, status)
}
func (h *OwnerAuthHandler) ObserveRotationJoinUsage(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID, _ ownerapi.ObserveRotationJoinUsageParams) {
	h.usageAction(w, r, preview, slot, false)
}
func (h *OwnerAuthHandler) RecheckRotationJoinUsage(w http.ResponseWriter, r *http.Request, preview, slot uuid.UUID, _ ownerapi.RecheckRotationJoinUsageParams) {
	h.usageAction(w, r, preview, slot, true)
}
