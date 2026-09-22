package runtime

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
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

func hmacEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func (h *OwnerAuthHandler) deliveryFailure(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusInternalServerError, "delivery_unavailable", "Internal Server Error", "Delivery data is temporarily unavailable", 0)
}
