package runtime

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
	"github.com/teamseatwatch/teamseatwatch/internal/task"
)

func (h *OwnerAuthHandler) getBatchDeliveries(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	batchID := r.PathValue("batchId")
	batchUUID, err := uuid.Parse(batchID)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "invalid_batch", "Invalid Request", "The batch identifier is invalid", 0)
		return
	}
	rows, err := h.pool.Query(r.Context(), `SELECT membership.id,membership.target_account_id,asset.status,asset.current_generation,
		asset.liveness_status,asset.liveness_http_status,asset.liveness_error_code,asset.probed_at,
		card.status,card.display_suffix,card.redemption_deadline
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
		LEFT JOIN tsw_cards card ON card.membership_id=membership.id
		WHERE membership.batch_id=$1 ORDER BY membership.created_at,membership.id`, batchUUID)
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	defer rows.Close()
	response := ownerapi.DeliveryList{BatchId: batchUUID, Items: []ownerapi.Delivery{}}
	for rows.Next() {
		var membershipID, targetID, assetStatus string
		var generation int64
		var livenessStatus, livenessError *string
		var httpStatus *int
		var probedAt *time.Time
		var cardStatus, suffix *string
		var deadline *time.Time
		if err := rows.Scan(&membershipID, &targetID, &assetStatus, &generation, &livenessStatus, &httpStatus, &livenessError, &probedAt, &cardStatus, &suffix, &deadline); err != nil {
			h.deliveryFailure(w, r)
			return
		}
		membershipUUID, parseMembershipErr := uuid.Parse(membershipID)
		targetUUID, parseTargetErr := uuid.Parse(targetID)
		if parseMembershipErr != nil || parseTargetErr != nil {
			h.deliveryFailure(w, r)
			return
		}
		item := ownerapi.Delivery{MembershipId: membershipUUID, TargetAccountId: targetUUID, Generation: generation, Status: ownerapi.DeliveryStatus(assetStatus)}
		item.LivenessStatus, item.LivenessHttpStatus, item.LivenessErrorCode, item.ProbedAt = livenessStatus, httpStatus, livenessError, probedAt
		item.CardStatus, item.CardDisplaySuffix, item.RedemptionDeadline = cardStatusValue(cardStatus), suffix, deadline
		activated := cardStatus != nil
		item.CardActivated = &activated
		response.Items = append(response.Items, item)
	}
	if err := rows.Err(); err != nil {
		h.deliveryFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func cardStatusValue(value *string) *ownerapi.DeliveryCardStatus {
	if value == nil {
		return nil
	}
	converted := ownerapi.DeliveryCardStatus(*value)
	return &converted
}

func (h *OwnerAuthHandler) authorizeDeliveryReclaim(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	membershipID, err := uuid.Parse(r.PathValue("membershipId"))
	if err != nil {
		h.rejectOwnerMutation(w, r, owner, "delivery.reclaim_authorize", "invalid_request", http.StatusBadRequest, "invalid_membership", "Invalid Request", "The membership identifier is invalid")
		return
	}
	var request ownerapi.AuthorizeDeliveryReclaimJSONRequestBody
	if !decodeJSON(w, r, &request) || !validLength(request.IdempotencyKey, 8, 64) {
		h.rejectOwnerMutation(w, r, owner, "delivery.reclaim_authorize", "invalid_request", http.StatusUnprocessableEntity, "invalid_idempotency_key", "Invalid Request", "A stable idempotency key is required")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())
	reject := func(reason string, status int, code, title, detail string) {
		_ = tx.Rollback(r.Context())
		h.rejectOwnerMutation(w, r, owner, "delivery.reclaim_authorize", reason, status, code, title, detail)
	}

	var assetID, orderID, workspaceID, assetStatus, cardStatus string
	err = tx.QueryRow(r.Context(), `SELECT asset.id::text,ord.id::text,binding.workspace_id::text,asset.status,card.status
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
		JOIN tsw_orders ord ON ord.membership_id=membership.id AND ord.oauth_asset_id=asset.id
		JOIN tsw_cards card ON card.id=ord.card_id AND card.membership_id=membership.id
		WHERE membership.id=$1 AND membership.state='active' AND batch.status IN ('serving','removing')
		  AND ord.current_delivery_version_id=asset.current_delivery_version_id
		FOR UPDATE OF membership,asset,ord,card`, membershipID).Scan(&assetID, &orderID, &workspaceID, &assetStatus, &cardStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		reject("target_not_found", http.StatusNotFound, "delivery_not_found", "Not Found", "The customer delivery was not found")
		return
	}
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}

	suffix := ownerDeliveryReclaimSuffix(owner.OwnerID, request.IdempotencyKey)
	dedupeKey := "oauth-reclaim:" + assetID + ":" + suffix
	var existingTaskID string
	err = tx.QueryRow(r.Context(), `SELECT id::text FROM tsw_tasks WHERE task_type='oauth_reclaim' AND oauth_asset_id=$1 AND dedupe_key=$2`, assetID, dedupeKey).Scan(&existingTaskID)
	if err == nil {
		if err := tx.Commit(r.Context()); err != nil {
			h.deliveryFailure(w, r)
			return
		}
		h.writeDeliveryReclaimAccepted(w, membershipID)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		h.deliveryFailure(w, r)
		return
	}

	var latestStatus, latestResult string
	err = tx.QueryRow(r.Context(), `SELECT status,COALESCE(reclaim_result,'') FROM tsw_tasks
		WHERE task_type='oauth_reclaim' AND oauth_asset_id=$1 ORDER BY created_at DESC LIMIT 1`, assetID).Scan(&latestStatus, &latestResult)
	if !errors.Is(err, pgx.ErrNoRows) && err != nil {
		h.deliveryFailure(w, r)
		return
	}
	if cardStatus != "active" {
		reject("delivery_not_reclaimable", http.StatusConflict, "delivery_reclaim_not_available", "Conflict", "A new reclaim can only be authorized for an active card")
		return
	}
	if assetStatus != "unavailable" || !errors.Is(err, pgx.ErrNoRows) && (latestStatus != "failed" || latestResult != "unrecoverable") {
		reject("delivery_not_reclaimable", http.StatusConflict, "delivery_reclaim_not_available", "Conflict", "A new reclaim can only be authorized after an unrecoverable terminal result")
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		reject("delivery_not_reclaimable", http.StatusConflict, "delivery_reclaim_not_available", "Conflict", "A new reclaim can only be authorized after an unrecoverable terminal result")
		return
	}

	created, err := task.EnqueueOwnerDeliveryReclaimTx(r.Context(), tx, assetID, orderID, suffix, correlation(r))
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	if !created {
		var taskID string
		err = tx.QueryRow(r.Context(), `SELECT id::text FROM tsw_tasks WHERE task_type='oauth_reclaim' AND oauth_asset_id=$1 AND dedupe_key=$2`, assetID, dedupeKey).Scan(&taskID)
		if err == nil {
			if err := tx.Commit(r.Context()); err != nil {
				h.deliveryFailure(w, r)
				return
			}
			h.writeDeliveryReclaimAccepted(w, membershipID)
			return
		}
		reject("conflict", http.StatusConflict, "delivery_reclaim_in_progress", "Conflict", "A reclaim operation is already in progress")
		return
	}

	source := auth.SourceFingerprint(r.RemoteAddr, r.UserAgent())
	if _, err := audit.Write(r.Context(), tx, audit.Event{
		Type: audit.OwnerDeliveryReclaimAuthorized, Actor: audit.ActorOwner, OwnerID: owner.OwnerID,
		RetentionScopeID: workspaceID, EntityType: "oauth_asset", EntityID: assetID,
		Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), SourceFingerprint: source[:],
		Details:        audit.DeliveryReclaimAuthorizationDetails{Action: "owner_reauthorization", Result: "queued"},
		IdempotencyKey: dedupeKey,
	}); err != nil {
		h.deliveryFailure(w, r)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.deliveryFailure(w, r)
		return
	}
	h.writeDeliveryReclaimAccepted(w, membershipID)
}

func ownerDeliveryReclaimSuffix(ownerID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(ownerID + "\x00" + idempotencyKey))
	return hex.EncodeToString(sum[:])
}

func (h *OwnerAuthHandler) writeDeliveryReclaimAccepted(w http.ResponseWriter, membershipID uuid.UUID) {
	writeJSON(w, http.StatusAccepted, ownerapi.AuthorizeDeliveryReclaimResponse{MembershipId: membershipID, Result: "queued"})
}

func (h *OwnerAuthHandler) probeBatchDeliveries(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.ProbeBatchDeliveriesJSONRequestBody
	if !decodeJSON(w, r, &request) || strings.TrimSpace(request.IdempotencyKey) == "" {
		h.rejectOwnerMutation(w, r, owner, "delivery.probe", "invalid_request", http.StatusUnprocessableEntity, "invalid_idempotency_key", "Invalid Request", "A stable idempotency key is required")
		return
	}
	batchID := r.PathValue("batchId")
	if _, err := uuid.Parse(batchID); err != nil {
		h.rejectOwnerMutation(w, r, owner, "delivery.probe", "invalid_request", http.StatusBadRequest, "invalid_batch", "Invalid Request", "The batch identifier is invalid")
		return
	}
	queued, err := h.workspaceTasks.EnqueueDeliveryProbes(r.Context(), batchID, correlation(r), "owner:"+request.IdempotencyKey)
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	batchUUID, _ := uuid.Parse(batchID)
	writeJSON(w, http.StatusAccepted, ownerapi.ProbeDeliveryResponse{BatchId: batchUUID, Queued: int(queued)})
}

func (h *OwnerAuthHandler) activateMembershipCard(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.ActivateMembershipCardJSONRequestBody
	if !decodeJSON(w, r, &request) || strings.TrimSpace(request.IdempotencyKey) == "" {
		h.rejectOwnerMutation(w, r, owner, "card.activate", "invalid_request", http.StatusUnprocessableEntity, "invalid_card_activation", "Invalid Request", "Card activation fields are invalid")
		return
	}
	keyVersion, lookup, err := oauthdomain.LookupHMAC(h.keyRing, strings.TrimSpace(request.CardSecret))
	if err != nil {
		h.rejectOwnerMutation(w, r, owner, "card.activate", "invalid_request", http.StatusUnprocessableEntity, "invalid_card_secret", "Invalid Card", "The card secret is invalid")
		return
	}
	membershipID := r.PathValue("membershipId")
	membershipUUID, err := uuid.Parse(membershipID)
	if err != nil {
		h.rejectOwnerMutation(w, r, owner, "card.activate", "invalid_request", http.StatusBadRequest, "invalid_membership", "Invalid Request", "The membership identifier is invalid")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())
	var workspaceID, batchStatus, assetStatus string
	var deadline time.Time
	err = tx.QueryRow(r.Context(), `SELECT binding.workspace_id,batch.status,asset.status,batch.planned_at
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
		WHERE membership.id=$1 AND membership.state='active' FOR UPDATE OF membership,batch,asset`, membershipUUID).Scan(&workspaceID, &batchStatus, &assetStatus, &deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		h.rejectOwnerMutation(w, r, owner, "card.activate", "target_not_found", http.StatusNotFound, "membership_not_found", "Not Found", "The membership was not found")
		return
	}
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	if batchStatus != "serving" || assetStatus != "ready" || !deadline.After(time.Now()) {
		h.rejectOwnerMutation(w, r, owner, "card.activate", "conflict", http.StatusConflict, "delivery_not_ready", "Conflict", "The OAuth delivery is not ready for card activation")
		return
	}
	var existing ownerapi.CardActivation
	var existingVersion int16
	var existingHash []byte
	err = tx.QueryRow(r.Context(), `SELECT id,membership_id,status,display_suffix,redemption_deadline,hmac_key_version,lookup_hmac
		FROM tsw_cards WHERE membership_id=$1 FOR UPDATE`, membershipUUID).Scan(&existing.CardId, &existing.MembershipId, &existing.Status, &existing.DisplaySuffix, &existing.RedemptionDeadline, &existingVersion, &existingHash)
	if err == nil {
		if existingVersion != int16(keyVersion) || !hmacEqual(existingHash, lookup[:]) {
			h.rejectOwnerMutation(w, r, owner, "card.activate", "conflict", http.StatusConflict, "card_already_activated", "Conflict", "This membership already has a different card")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			h.deliveryFailure(w, r)
			return
		}
		writeJSON(w, http.StatusOK, existing)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		h.deliveryFailure(w, r)
		return
	}
	var cardID uuid.UUID
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_cards(membership_id,hmac_key_version,lookup_hmac,display_suffix,redemption_deadline,activation_idempotency_key)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, membershipUUID, keyVersion, lookup[:], oauthdomain.DisplaySuffix(request.CardSecret), deadline, request.IdempotencyKey).Scan(&cardID)
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.CardActivated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: workspaceID, EntityType: "card", EntityID: cardID.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.CardDetails{Result: "activated", KeyVersion: int(keyVersion), DisplaySuffix: oauthdomain.DisplaySuffix(request.CardSecret)}, IdempotencyKey: cardID.String() + ":activated"})
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.deliveryFailure(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, ownerapi.CardActivation{CardId: cardID, MembershipId: membershipUUID, Status: ownerapi.CardActivationStatusActive, DisplaySuffix: oauthdomain.DisplaySuffix(request.CardSecret), RedemptionDeadline: deadline})
}

func (h *OwnerAuthHandler) revokeDeliveryCard(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.RevokeDeliveryCardJSONRequestBody
	if !decodeJSON(w, r, &request) || request.Confirm != ownerapi.RevokeDeliveryCardRequestConfirmTrue {
		h.rejectOwnerMutation(w, r, owner, "delivery.card_revoke", "invalid_request", http.StatusUnprocessableEntity, "revocation_confirmation_required", "Confirmation Required", "Explicit confirmation is required")
		return
	}
	membershipID, err := uuid.Parse(r.PathValue("membershipId"))
	if err != nil {
		h.rejectOwnerMutation(w, r, owner, "delivery.card_revoke", "target_not_found", http.StatusBadRequest, "delivery_not_found", "Not Found", "The customer delivery was not found")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())

	var cardID, cardStatus string
	err = tx.QueryRow(r.Context(), `SELECT card.id::text,card.status
		FROM tsw_cards card
		JOIN tsw_batch_memberships membership ON membership.id=card.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		WHERE membership.id=$1
		FOR UPDATE OF card`, membershipID).Scan(&cardID, &cardStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		h.rejectOwnerMutation(w, r, owner, "delivery.card_revoke", "target_not_found", http.StatusNotFound, "delivery_not_found", "Not Found", "The customer delivery was not found")
		return
	}
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	cardUUID, err := uuid.Parse(cardID)
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	if cardStatus == "revoked" {
		var revokedTokenCount int
		err = tx.QueryRow(r.Context(), `SELECT COALESCE(
			(SELECT (details->>'revoked_token_count')::int
			 FROM tsw_audit_events
			 WHERE event_type=$1 AND entity_type='card' AND entity_id=$2
			 ORDER BY occurred_at DESC LIMIT 1),
			(SELECT count(*)::int FROM tsw_public_tokens WHERE card_id=$2 AND revocation_reason='card_revoked'),
			0)`, audit.OwnerCardRevoked, cardUUID).Scan(&revokedTokenCount)
		if err != nil {
			h.deliveryFailure(w, r)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			h.deliveryFailure(w, r)
			return
		}
		writeJSON(w, http.StatusOK, ownerapi.RevokeDeliveryCardResponse{
			MembershipId: membershipID, CardId: cardUUID, Status: ownerapi.RevokeDeliveryCardResponseStatusRevoked,
			RevokedTokenCount: revokedTokenCount,
		})
		return
	}
	if cardStatus != "active" {
		h.rejectOwnerMutation(w, r, owner, "delivery.card_revoke", "conflict", http.StatusConflict, "card_not_revocable", "Conflict", "The card cannot be revoked in its current state")
		return
	}
	result, err := tx.Exec(r.Context(), `UPDATE tsw_cards
		SET status='revoked',revoked_at=now(),revocation_reason='owner_request',updated_at=now(),version=version+1
		WHERE id=$1 AND status='active'`, cardUUID)
	if err != nil || result.RowsAffected() != 1 {
		h.deliveryFailure(w, r)
		return
	}
	tokens, err := tx.Exec(r.Context(), `UPDATE tsw_public_tokens
		SET revoked_at=now(),revocation_reason='card_revoked'
		WHERE card_id=$1 AND revoked_at IS NULL`, cardUUID)
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	source := auth.SourceFingerprint(r.RemoteAddr, r.UserAgent())
	if _, err := audit.Write(r.Context(), tx, audit.Event{
		Type: audit.OwnerCardRevoked, Actor: audit.ActorOwner, OwnerID: owner.OwnerID,
		RetentionScopeID: cardID, EntityType: "card", EntityID: cardID, Outcome: audit.OutcomeSucceeded,
		CorrelationID: correlation(r), SourceFingerprint: source[:],
		Details:        audit.CardRevocationDetails{Action: "owner_revoked", Result: "revoked", RevokedTokenCount: int(tokens.RowsAffected())},
		IdempotencyKey: cardID + ":revoked",
	}); err != nil {
		h.deliveryFailure(w, r)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.deliveryFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, ownerapi.RevokeDeliveryCardResponse{
		MembershipId: membershipID, CardId: cardUUID,
		Status: ownerapi.RevokeDeliveryCardResponseStatusRevoked, RevokedTokenCount: int(tokens.RowsAffected()),
	})
}

func hmacEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func (h *OwnerAuthHandler) deliveryFailure(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusInternalServerError, "delivery_unavailable", "Internal Server Error", "Delivery data is temporarily unavailable", 0)
}
