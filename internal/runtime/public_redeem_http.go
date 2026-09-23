package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/internalapi"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
	"github.com/teamseatwatch/teamseatwatch/internal/publicaccess"
	"github.com/teamseatwatch/teamseatwatch/internal/task"
)

const (
	publicRateWindow      = 15 * time.Minute
	publicTokenRateWindow = time.Minute
	publicAccessTTL       = 24 * time.Hour
)

var errPublicAuthorization = errors.New("public authorization denied")

type PublicRedeemHandler struct {
	pool    *pgxpool.Pool
	keyRing auth.KeyRing
	tasks   *task.Store
	health  http.Handler
}

type redeemFacts struct {
	CardID          string
	MembershipID    string
	AssetID         string
	VersionID       string
	OrderID         string
	OrderVersionID  string
	CardSuffix      string
	CardStatus      string
	BatchStatus     string
	MembershipState string
	AssetStatus     string
	Liveness        string
	Deadline        time.Time
	PlannedAt       time.Time
}

func NewPublicRedeemHandler(pool *pgxpool.Pool, keyRing auth.KeyRing, health http.Handler) *PublicRedeemHandler {
	return &PublicRedeemHandler{pool: pool, keyRing: keyRing, tasks: task.NewStore(pool), health: health}
}

var _ internalapi.ServerInterface = (*PublicRedeemHandler)(nil)

func (h *PublicRedeemHandler) GetPrivateHealth(w http.ResponseWriter, r *http.Request) {
	if h.health == nil {
		writePublicProblem(w, r, http.StatusServiceUnavailable, "control_not_ready", 0)
		return
	}
	h.health.ServeHTTP(w, r)
}

func (h *PublicRedeemHandler) ConfirmPublicRedeem(w http.ResponseWriter, r *http.Request) {
	var request internalapi.ConfirmPublicRedeemJSONRequestBody
	if !decodeJSON(w, r, &request) || !validCardInput(request.CardSecret) {
		writePublicProblem(w, r, http.StatusBadRequest, "public_request_invalid", 0)
		return
	}
	if !h.allowCardRequest(r.Context(), r, request.CardSecret) {
		writePublicProblem(w, r, http.StatusTooManyRequests, "public_rate_limited", 60)
		return
	}
	keyVersion, lookup, err := oauthdomain.LookupHMAC(h.keyRing, request.CardSecret)
	if err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	defer tx.Rollback(r.Context())
	facts, err := loadRedeemFactsForUpdate(r.Context(), tx, keyVersion, lookup[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_ = tx.Commit(r.Context())
			writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
			return
		}
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	wasRestore := facts.hasOrder()
	if wasRestore && !facts.canAccess() {
		if err := writePublicAudit(r.Context(), tx, audit.PublicRestoreDenied, "card", facts.CardID, facts.CardID, r, audit.PublicAccessDetails{Action: "order_restore", Result: "denied", Reason: "delivery_unavailable"}); err != nil {
			writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
			return
		}
		_ = tx.Commit(r.Context())
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	if !wasRestore && !facts.canClaim(time.Now().UTC()) {
		if err := writePublicAudit(r.Context(), tx, audit.PublicClaimDenied, "card", facts.CardID, facts.CardID, r, audit.PublicAccessDetails{Action: "first_claim", Result: "denied", Reason: "claim_unavailable"}); err != nil {
			writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
			return
		}
		_ = tx.Commit(r.Context())
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	if !wasRestore {
		if err := createOrderTx(r.Context(), tx, facts); err != nil {
			writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
			return
		}
		facts.OrderID, err = findOrderIDTx(r.Context(), tx, facts.CardID)
		if err != nil {
			writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
			return
		}
	}
	plainToken, tokenHash, err := publicaccess.NewToken()
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	tokenID, err := insertTokenTx(r.Context(), tx, facts, tokenHash[:])
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	action := audit.PublicOrderCreated
	publicAction := "first_claim"
	if wasRestore {
		action = audit.PublicOrderRestored
		publicAction = "order_restore"
	}
	if err := writePublicAudit(r.Context(), tx, action, "order", facts.OrderID, facts.CardID, r, audit.PublicAccessDetails{Action: publicAction, Result: "accepted"}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := writePublicAudit(r.Context(), tx, audit.PublicTokenIssued, "public_token", tokenID, facts.CardID, r, audit.PublicAccessDetails{Action: "token_issued", Result: "accepted"}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	setPublicAccessCookie(w, plainToken, time.Now().UTC().Add(publicAccessTTL))
	confirmation := confirmationPayload(facts, false, true, "claimed")
	if wasRestore {
		confirmation.Action = "restored"
	}
	writeNoStoreJSON(w, http.StatusOK, confirmation)
}

func (h *PublicRedeemHandler) GetPublicRedeemState(w http.ResponseWriter, r *http.Request) {
	facts, _, tx, ok := h.authorizedReadOnlyTokenTransaction(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	if err := writePublicAudit(r.Context(), tx, audit.PublicStateRead, "order", facts.OrderID, facts.CardID, r, audit.PublicAccessDetails{Action: "state_read", Result: "accepted"}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	timeline, err := loadTimelineTx(r.Context(), tx, facts.CardID)
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	response := statePayload(facts, timeline)
	writeNoStoreJSON(w, http.StatusOK, response)
}

func (h *PublicRedeemHandler) ListPublicRedeemRecords(w http.ResponseWriter, r *http.Request) {
	facts, _, tx, ok := h.authorizedReadOnlyTokenTransaction(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	if err := writePublicAudit(r.Context(), tx, audit.PublicRecordsRead, "order", facts.OrderID, facts.CardID, r, audit.PublicAccessDetails{Action: "records_read", Result: "accepted"}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	timeline, err := loadTimelineTx(r.Context(), tx, facts.CardID)
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, internalapi.RedeemTimeline{Items: timeline})
}

func (h *PublicRedeemHandler) CheckPublicRedeemCredentialStatus(w http.ResponseWriter, r *http.Request) {
	var request internalapi.CheckPublicRedeemCredentialStatusJSONRequestBody
	if !decodeJSON(w, r, &request) || !validCardInput(request.CardSecret) {
		writePublicProblem(w, r, http.StatusBadRequest, "public_request_invalid", 0)
		return
	}
	if !h.allowCardRequest(r.Context(), r, request.CardSecret) {
		writePublicProblem(w, r, http.StatusTooManyRequests, "public_rate_limited", 60)
		return
	}
	keyVersion, lookup, err := oauthdomain.LookupHMAC(h.keyRing, request.CardSecret)
	if err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	defer tx.Rollback(r.Context())
	facts, err := loadRedeemFactsForUpdate(r.Context(), tx, keyVersion, lookup[:])
	if err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	queued := false
	if facts.canCredentialCheck() {
		queued, err = task.EnqueueCustomerDeliveryProbeTx(r.Context(), tx, facts.AssetID, newProbeSuffix(), correlation(r))
		if err != nil {
			writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
			return
		}
	}
	status := facts.publicLiveness()
	if err := writePublicAudit(r.Context(), tx, audit.PublicStatusChecked, "card", facts.CardID, facts.CardID, r, audit.PublicAccessDetails{Action: "status_check", Result: status, Status: status}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	var checkedAt *time.Time
	if !facts.Deadline.IsZero() {
		now := time.Now().UTC()
		checkedAt = &now
	}
	writeNoStoreJSON(w, http.StatusOK, internalapi.CredentialStatus{Status: status, CheckQueued: queued, CheckedAt: checkedAt})
}

func (h *PublicRedeemHandler) RequestPublicRedeemReclaim(w http.ResponseWriter, r *http.Request) {
	var request internalapi.RequestPublicRedeemReclaimJSONRequestBody
	if !decodeJSON(w, r, &request) || !validCardInput(request.CardSecret) {
		writePublicProblem(w, r, http.StatusBadRequest, "public_request_invalid", 0)
		return
	}
	if !h.allowReclaimRequest(r.Context(), r, request.CardSecret) {
		writePublicProblem(w, r, http.StatusTooManyRequests, "public_rate_limited", 60)
		return
	}
	keyVersion, lookup, err := oauthdomain.LookupHMAC(h.keyRing, request.CardSecret)
	if err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	defer tx.Rollback(r.Context())
	cardFacts, err := loadRedeemFactsForUpdate(r.Context(), tx, keyVersion, lookup[:])
	if err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	if !cardFacts.canReclaimRequest() {
		_ = writePublicAudit(r.Context(), tx, audit.PublicReclaimDenied, "card", cardFacts.CardID, cardFacts.CardID, r, audit.PublicAccessDetails{Action: "reclaim_request", Result: "denied", Reason: "reclaim_unavailable"})
		_ = tx.Commit(r.Context())
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	created, err := task.EnqueueCustomerDeliveryReclaimTx(r.Context(), tx, cardFacts.AssetID, cardFacts.OrderID, newProbeSuffix(), correlation(r))
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	result := "queued"
	if !created {
		result = "checking"
	}
	if err := writePublicAudit(r.Context(), tx, audit.PublicReclaimRequested, "card", cardFacts.CardID, cardFacts.CardID, r, audit.PublicAccessDetails{Action: "reclaim_request", Result: result}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	// A card-authenticated reclaim may be requested from a fresh browser. Issue
	// a normal customer-access cookie for the existing order so read-only status
	// polling can continue without putting the card secret in a URL.
	plainToken, tokenHash, err := publicaccess.NewToken()
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	tokenID, err := insertReclaimStatusTokenTx(r.Context(), tx, cardFacts, tokenHash[:])
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := writePublicAudit(r.Context(), tx, audit.PublicTokenIssued, "public_token", tokenID, cardFacts.CardID, r, audit.PublicAccessDetails{Action: "token_issued", Result: "accepted"}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	setPublicAccessCookie(w, plainToken, time.Now().UTC().Add(publicAccessTTL))
	status := internalapi.ReclaimStatus{Status: internalapi.ReclaimStatusStatusQueued, DeliveryStatus: internalapi.ReclaimStatusDeliveryStatusUnavailable, LivenessStatus: internalapi.ReclaimStatusLivenessStatus(cardFacts.publicLiveness()), Result: reclaimResultPointer(result)}
	if !created {
		status.Status = internalapi.ReclaimStatusStatusRunning
	}
	writeNoStoreJSON(w, http.StatusAccepted, status)
}

func (h *PublicRedeemHandler) GetPublicRedeemReclaimStatus(w http.ResponseWriter, r *http.Request) {
	facts, _, tx, ok := h.authorizedReclaimStatusTokenTransaction(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	status, err := loadReclaimStatusTx(r.Context(), tx, facts)
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := writePublicAudit(r.Context(), tx, audit.PublicStateRead, "order", facts.OrderID, facts.CardID, r, audit.PublicAccessDetails{Action: "reclaim_status", Result: publicReclaimPollResult(status)}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, status)
}

func (h *PublicRedeemHandler) DownloadPublicRedeemDelivery(w http.ResponseWriter, r *http.Request) {
	facts, tokenHash, tx, ok := h.authorizedTokenTransaction(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	var payload []byte
	if err := tx.QueryRow(r.Context(), `SELECT payload FROM tsw_delivery_versions WHERE id=$1::uuid AND oauth_asset_id=$2::uuid`, facts.VersionID, facts.AssetID).Scan(&payload); err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	if err := updateTokenUseTx(r.Context(), tx, tokenHash[:]); err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return
	}
	if err := writePublicAudit(r.Context(), tx, audit.PublicDownloadAuthorized, "public_token", tokenIDFromHash(tokenHash), facts.CardID, r, audit.PublicAccessDetails{Action: "download_authorized", Result: "accepted"}); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="teamseatwatch-delivery.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (h *PublicRedeemHandler) authorizedTokenTransaction(w http.ResponseWriter, r *http.Request) (redeemFacts, [32]byte, pgx.Tx, bool) {
	var empty [32]byte
	cookie, err := r.Cookie(publicaccess.CookieName)
	if err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	hash, err := publicaccess.HashToken(cookie.Value)
	if err != nil || !h.allowTokenRequest(r.Context(), r, cookie.Value) {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return redeemFacts{}, empty, nil, false
	}
	facts, err := loadRedeemFactsByToken(r.Context(), tx, hash[:])
	if err != nil || !facts.canAccess() {
		_ = tx.Rollback(r.Context())
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	return facts, hash, tx, true
}

func (h *PublicRedeemHandler) authorizedReadOnlyTokenTransaction(w http.ResponseWriter, r *http.Request) (redeemFacts, [32]byte, pgx.Tx, bool) {
	var empty [32]byte
	cookie, err := r.Cookie(publicaccess.CookieName)
	if err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	hash, err := publicaccess.HashToken(cookie.Value)
	if err != nil || !h.allowTokenRequest(r.Context(), r, cookie.Value) {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return redeemFacts{}, empty, nil, false
	}
	facts, err := loadRedeemFactsByTokenReadOnly(r.Context(), tx, hash[:])
	if err != nil || !facts.canReadStatus() {
		_ = tx.Rollback(r.Context())
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	return facts, hash, tx, true
}

func loadRedeemFactsByTokenReadOnly(ctx context.Context, tx pgx.Tx, hash []byte) (redeemFacts, error) {
	return loadRedeemFactsQuery(ctx, tx, `JOIN tsw_public_tokens token ON token.order_id=ord.id AND token.token_hash=$1 AND token.token_kind='customer_access' AND token.expires_at>now()
		WHERE card.id=token.card_id AND token.membership_id=membership.id AND token.oauth_asset_id=asset.id AND token.delivery_version_id=asset.current_delivery_version_id`, hash)
}

func loadReclaimStatusFactsByToken(ctx context.Context, tx pgx.Tx, hash []byte) (redeemFacts, error) {
	return loadRedeemFactsQuery(ctx, tx, `JOIN tsw_public_tokens token ON token.order_id=ord.id AND token.token_hash=$1 AND token.token_kind='reclaim_status' AND token.expires_at>now()
		WHERE card.id=token.card_id AND token.membership_id=membership.id AND token.oauth_asset_id=asset.id`, hash)
}

func (h *PublicRedeemHandler) allowReclaimRequest(ctx context.Context, r *http.Request, secret string) bool {
	now := time.Now().UTC()
	cardHash := publicaccess.SubjectFingerprint("card", secret)
	ipHash := publicaccess.SubjectFingerprint("ip", sourceIP(r))
	ok, err := publicaccess.Check(ctx, h.pool, []publicaccess.Limit{
		{Kind: "public_reclaim_card", Hash: cardHash, Window: publicRateWindow, Max: 10},
		{Kind: "public_reclaim_ip", Hash: ipHash, Window: publicRateWindow, Max: 30},
	}, now)
	return err == nil && ok
}

func reclaimResultPointer(value string) *internalapi.ReclaimStatusResult {
	result := internalapi.ReclaimStatusResult(value)
	return &result
}

func (h *PublicRedeemHandler) authorizedReclaimStatusTokenTransaction(w http.ResponseWriter, r *http.Request) (redeemFacts, [32]byte, pgx.Tx, bool) {
	var empty [32]byte
	cookie, err := r.Cookie(publicaccess.CookieName)
	if err != nil {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	hash, err := publicaccess.HashToken(cookie.Value)
	if err != nil || !h.allowTokenRequest(r.Context(), r, cookie.Value) {
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writePublicProblem(w, r, http.StatusInternalServerError, "public_unavailable", 0)
		return redeemFacts{}, empty, nil, false
	}
	facts, err := loadReclaimStatusFactsByToken(r.Context(), tx, hash[:])
	if err != nil || !facts.canReadStatus() {
		_ = tx.Rollback(r.Context())
		writePublicProblem(w, r, http.StatusNotFound, "public_request_denied", 0)
		return redeemFacts{}, empty, nil, false
	}
	return facts, hash, tx, true
}

func publicReclaimPollResult(status internalapi.ReclaimStatus) string {
	switch status.Status {
	case internalapi.ReclaimStatusStatusQueued:
		return "queued"
	case internalapi.ReclaimStatusStatusRunning, internalapi.ReclaimStatusStatusRetryWait:
		return "checking"
	case internalapi.ReclaimStatusStatusSucceeded:
		if status.Result != nil && *status.Result == internalapi.ReclaimStatusResultHealthy {
			return "healthy"
		}
		return "restored"
	case internalapi.ReclaimStatusStatusFailed:
		if status.Result != nil && *status.Result == internalapi.ReclaimStatusResultUnrecoverable {
			return "unrecoverable"
		}
		return "unknown"
	default:
		return "unknown"
	}
}

func loadReclaimStatusTx(ctx context.Context, tx pgx.Tx, facts redeemFacts) (internalapi.ReclaimStatus, error) {
	status := internalapi.ReclaimStatus{
		Status:         internalapi.ReclaimStatusStatusNotRequested,
		DeliveryStatus: internalapi.ReclaimStatusDeliveryStatusUnavailable,
		LivenessStatus: internalapi.ReclaimStatusLivenessStatus(facts.publicLiveness()),
	}
	if facts.AssetStatus == "ready" && facts.VersionID != "" {
		status.DeliveryStatus = internalapi.ReclaimStatusDeliveryStatusAvailable
	}
	var taskStatus string
	var reclaimStage, tier, result, probeStatus *string
	var probeHTTP *int
	err := tx.QueryRow(ctx, `SELECT task.status,task.reclaim_stage,task.reclaim_tier,task.reclaim_result,task.reclaim_probe_status,task.reclaim_http_status
		FROM tsw_tasks task WHERE task.oauth_asset_id=$1::uuid AND task.task_type='oauth_reclaim'
		ORDER BY task.created_at DESC LIMIT 1`, facts.AssetID).Scan(&taskStatus, &reclaimStage, &tier, &result, &probeStatus, &probeHTTP)
	if errors.Is(err, pgx.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	status.Status = internalapi.ReclaimStatusStatus(taskStatus)
	if taskStatus == "interrupted" {
		status.Status = internalapi.ReclaimStatusStatusFailed
	}
	if reclaimStage != nil && *reclaimStage != "" {
		value := internalapi.ReclaimStatusStage(*reclaimStage)
		status.Stage = &value
	}
	if tier != nil && *tier != "" {
		value := internalapi.ReclaimStatusTier(*tier)
		status.Tier = &value
	}
	switch taskStatus {
	case "queued":
		status.Result = reclaimResultPointer("queued")
	case "running", "retry_wait":
		status.Result = reclaimResultPointer("checking")
	case "succeeded":
		if result != nil && *result == "probe_ok" {
			status.Result = reclaimResultPointer("healthy")
		} else {
			status.Result = reclaimResultPointer("restored")
		}
	case "failed":
		if (result != nil && *result == "unrecoverable") || (tier != nil && *tier == "unrecoverable") {
			status.Result = reclaimResultPointer("unrecoverable")
		} else {
			status.Result = reclaimResultPointer("unknown")
		}
	case "interrupted":
		status.Result = reclaimResultPointer("unknown")
	}
	_ = probeStatus
	_ = probeHTTP
	return status, nil
}
func (h *PublicRedeemHandler) allowCardRequest(ctx context.Context, r *http.Request, secret string) bool {
	now := time.Now().UTC()
	cardHash := publicaccess.SubjectFingerprint("card", secret)
	ok, err := publicaccess.Check(ctx, h.pool, []publicaccess.Limit{
		{Kind: "public_card", Hash: cardHash, Window: publicRateWindow, Max: 10},
		{Kind: "public_ip", Hash: publicaccess.SubjectFingerprint("ip", sourceIP(r)), Window: publicRateWindow, Max: 30},
	}, now)
	return err == nil && ok
}

func (h *PublicRedeemHandler) allowTokenRequest(ctx context.Context, r *http.Request, token string) bool {
	now := time.Now().UTC()
	tokenHash := publicaccess.Fingerprint(token)
	ipHash := publicaccess.SubjectFingerprint("ip", sourceIP(r))
	ok, err := publicaccess.Check(ctx, h.pool, []publicaccess.Limit{
		{Kind: "public_token", Hash: tokenHash, Window: publicTokenRateWindow, Max: 60},
		{Kind: "public_token_ip", Hash: ipHash, Window: publicTokenRateWindow, Max: 120},
	}, now)
	return err == nil && ok
}

func loadRedeemFacts(ctx context.Context, tx pgx.Tx, keyVersion uint16, lookup []byte) (redeemFacts, error) {
	return loadRedeemFactsQuery(ctx, tx, `WHERE card.hmac_key_version=$1 AND card.lookup_hmac=$2`, keyVersion, lookup)
}

func loadRedeemFactsForUpdate(ctx context.Context, tx pgx.Tx, keyVersion uint16, lookup []byte) (redeemFacts, error) {
	facts, err := loadRedeemFacts(ctx, tx, keyVersion, lookup)
	if err != nil {
		return facts, err
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM tsw_cards WHERE id=$1::uuid FOR UPDATE`, facts.CardID); err != nil {
		return redeemFacts{}, err
	}
	return loadRedeemFacts(ctx, tx, keyVersion, lookup)
}

func loadRedeemFactsByToken(ctx context.Context, tx pgx.Tx, hash []byte) (redeemFacts, error) {
	return loadRedeemFactsQuery(ctx, tx, `JOIN tsw_public_tokens token ON token.order_id=ord.id AND token.token_hash=$1 AND token.token_kind='customer_access' AND token.revoked_at IS NULL AND token.expires_at>now()
		WHERE card.id=token.card_id AND token.delivery_version_id=asset.current_delivery_version_id AND token.oauth_asset_id=asset.id`, hash)
}

func loadRedeemFactsQuery(ctx context.Context, tx pgx.Tx, predicate string, args ...any) (redeemFacts, error) {
	var facts redeemFacts
	query := `SELECT card.id::text,membership.id::text,asset.id::text,COALESCE(asset.current_delivery_version_id::text,''),COALESCE(ord.id::text,''),COALESCE(ord.current_delivery_version_id::text,''),card.display_suffix,card.status,batch.status,membership.state,asset.status,COALESCE(asset.liveness_status,''),card.redemption_deadline,batch.planned_at
		FROM tsw_cards card
		JOIN tsw_batch_memberships membership ON membership.id=card.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
		LEFT JOIN tsw_orders ord ON ord.card_id=card.id AND ord.membership_id=membership.id
		` + predicate + ` LIMIT 1`
	if err := tx.QueryRow(ctx, query, args...).Scan(&facts.CardID, &facts.MembershipID, &facts.AssetID, &facts.VersionID, &facts.OrderID, &facts.OrderVersionID, &facts.CardSuffix, &facts.CardStatus, &facts.BatchStatus, &facts.MembershipState, &facts.AssetStatus, &facts.Liveness, &facts.Deadline, &facts.PlannedAt); err != nil {
		return redeemFacts{}, err
	}
	return facts, nil
}

func (f redeemFacts) hasOrder() bool { return f.OrderID != "" }
func (f redeemFacts) canClaim(now time.Time) bool {
	return !f.hasOrder() && f.CardStatus == "active" && f.MembershipState == "active" && f.BatchStatus == "serving" && now.Before(f.Deadline) && now.Before(f.PlannedAt) && f.AssetStatus == "ready" && f.VersionID != ""
}
func (f redeemFacts) canAccess() bool {
	return f.CardStatus == "active" && f.MembershipState == "active" && (f.BatchStatus == "serving" || f.BatchStatus == "removing") && f.AssetStatus == "ready" && f.VersionID != "" && f.hasOrder() && f.OrderVersionID == f.VersionID
}
func (f redeemFacts) canCredentialCheck() bool {
	return f.CardStatus == "active" && f.MembershipState == "active" && (f.BatchStatus == "serving" || f.BatchStatus == "removing") && f.AssetStatus != "" && f.VersionID != ""
}
func (f redeemFacts) canReadStatus() bool {
	return f.CardStatus == "active" && f.MembershipState == "active" && (f.BatchStatus == "serving" || f.BatchStatus == "removing") && f.hasOrder() && f.OrderVersionID == f.VersionID
}
func (f redeemFacts) canReclaimRequest() bool {
	return f.canReadStatus() && f.AssetID != "" && f.VersionID != "" && f.OrderVersionID != "" && f.OrderVersionID == f.VersionID && (f.AssetStatus == "ready" || f.AssetStatus == "unavailable" || f.AssetStatus == "reclaiming")
}
func (f redeemFacts) publicLiveness() string {
	switch f.Liveness {
	case "ok":
		return "healthy"
	case "auth_error":
		return "need_reclaim"
	case "deactivated_workspace":
		return "cannot_reclaim"
	default:
		return "unknown"
	}
}

func statePayload(f redeemFacts, timeline []internalapi.TimelineEntry) internalapi.RedeemState {
	preview := previewPayload(f, false, f.canAccess())
	return internalapi.RedeemState{CardSuffix: preview.CardSuffix, HasOrder: preview.HasOrder, CanClaim: preview.CanClaim, CanAccess: preview.CanAccess, RemainingSeconds: preview.RemainingSeconds, DeliveryStatus: preview.DeliveryStatus, LivenessStatus: preview.LivenessStatus, Timeline: timeline}
}

func confirmationPayload(f redeemFacts, canClaim, canAccess bool, action string) internalapi.RedeemConfirmation {
	preview := previewPayload(f, canClaim, canAccess)
	return internalapi.RedeemConfirmation{CardSuffix: preview.CardSuffix, HasOrder: preview.HasOrder, CanClaim: preview.CanClaim, CanAccess: preview.CanAccess, RemainingSeconds: preview.RemainingSeconds, DeliveryStatus: preview.DeliveryStatus, LivenessStatus: preview.LivenessStatus, Action: action}
}

func previewPayload(f redeemFacts, canClaim, canAccess bool) internalapi.RedeemPreview {
	remaining := int64(0)
	if seconds := time.Until(f.PlannedAt).Seconds(); seconds > 0 {
		remaining = int64(seconds)
	}
	return internalapi.RedeemPreview{CardSuffix: f.CardSuffix, HasOrder: f.hasOrder(), CanClaim: canClaim, CanAccess: canAccess, RemainingSeconds: remaining, DeliveryStatus: map[bool]string{true: "available", false: "unavailable"}[f.AssetStatus == "ready" && f.VersionID != ""], LivenessStatus: f.publicLiveness()}
}

func createOrderTx(ctx context.Context, tx pgx.Tx, f redeemFacts) error {
	_, err := tx.Exec(ctx, `INSERT INTO tsw_orders(membership_id,card_id,oauth_asset_id,current_delivery_version_id) VALUES ($1,$2,$3,$4) ON CONFLICT (card_id) DO NOTHING`, f.MembershipID, f.CardID, f.AssetID, f.VersionID)
	return err
}
func findOrderIDTx(ctx context.Context, tx pgx.Tx, cardID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM tsw_orders WHERE card_id=$1::uuid`, cardID).Scan(&id)
	return id, err
}
func insertTokenTx(ctx context.Context, tx pgx.Tx, f redeemFacts, hash []byte) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO tsw_public_tokens(membership_id,card_id,order_id,oauth_asset_id,delivery_version_id,token_kind,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,'customer_access',$6,now()+$7::interval) RETURNING id::text`, f.MembershipID, f.CardID, f.OrderID, f.AssetID, f.VersionID, hash, publicAccessTTL.String()).Scan(&id)
	return id, err
}
func insertReclaimStatusTokenTx(ctx context.Context, tx pgx.Tx, facts redeemFacts, hash []byte) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO tsw_public_tokens(membership_id,card_id,order_id,oauth_asset_id,delivery_version_id,token_kind,token_hash,expires_at)
		VALUES($1,$2,$3,$4,$5,'reclaim_status',$6,now()+$7::interval) RETURNING id::text`, facts.MembershipID, facts.CardID, facts.OrderID, facts.AssetID, facts.VersionID, hash, publicAccessTTL.String()).Scan(&id)
	return id, err
}

func updateTokenUseTx(ctx context.Context, tx pgx.Tx, hash []byte) error {
	result, err := tx.Exec(ctx, `UPDATE tsw_public_tokens SET last_used_at=now() WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now()`, hash)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errPublicAuthorization
	}
	return nil
}
func tokenIDFromHash(hash [32]byte) string { return uuid.NewSHA1(uuid.NameSpaceOID, hash[:]).String() }

func loadTimelineTx(ctx context.Context, tx pgx.Tx, cardID string) ([]internalapi.TimelineEntry, error) {
	rows, err := tx.Query(ctx, `SELECT occurred_at,event_type,outcome,details FROM tsw_audit_events WHERE retention_scope_type='card' AND retention_scope_id=$1::uuid AND event_type LIKE 'public.%' ORDER BY occurred_at ASC LIMIT 100`, cardID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]internalapi.TimelineEntry, 0, 16)
	for rows.Next() {
		var at time.Time
		var eventType, outcome string
		var raw []byte
		if err := rows.Scan(&at, &eventType, &outcome, &raw); err != nil {
			return nil, err
		}
		var detail audit.PublicAccessDetails
		_ = json.Unmarshal(raw, &detail)
		action := detail.Action
		if action == "" {
			action = strings.TrimPrefix(eventType, "public.")
		}
		result := detail.Status
		if result == "" {
			result = detail.Result
		}
		if result == "" {
			if outcome == string(audit.OutcomeSucceeded) {
				result = "accepted"
			} else {
				result = "denied"
			}
		}
		var reason *string
		if detail.Reason != "" {
			value := detail.Reason
			reason = &value
		}
		items = append(items, internalapi.TimelineEntry{OccurredAt: at, Action: action, Result: result, Reason: reason})
	}
	return items, rows.Err()
}

func writePublicAudit(ctx context.Context, tx pgx.Tx, event audit.EventType, entityType, entityID, scopeID string, r *http.Request, details audit.PublicAccessDetails) error {
	outcome := audit.OutcomeSucceeded
	if details.Result == "denied" {
		outcome = audit.OutcomeDenied
	}
	source := auth.SourceFingerprint(sourceIP(r), "public")
	returnAudit := audit.Event{Type: event, Actor: audit.ActorAnonymous, RetentionScopeID: scopeID, EntityType: entityType, EntityID: entityID, Outcome: outcome, CorrelationID: correlation(r), SourceFingerprint: source[:], Details: details, IdempotencyKey: string(event) + ":" + entityID + ":" + details.Action + ":" + time.Now().UTC().Format(time.RFC3339Nano)}
	_, err := audit.Write(ctx, tx, returnAudit)
	return err
}

func newProbeSuffix() string {
	return uuid.NewString()
}
func validCardInput(value string) bool { return oauthdomain.ValidateCardSecret(value) == nil }
func sourceIP(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-TSW-Source-IP")); value != "" {
		if net.ParseIP(value) != nil {
			return value
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func writeNoStoreJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, value)
}
func writePublicProblem(w http.ResponseWriter, r *http.Request, status int, code string, retry int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/problem+json")
	if retry > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(retry))
	}
	w.WriteHeader(status)
	detail := "The request cannot be completed"
	var retryValue *int
	if retry > 0 {
		retryValue = &retry
	}
	_ = json.NewEncoder(w).Encode(internalapi.Problem{Type: "urn:teamseatwatch:problem:" + code, Title: "Request unavailable", Status: status, Code: code, Detail: &detail, RetryAfterSeconds: retryValue})
}
func setPublicAccessCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: publicaccess.CookieName, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(time.Until(expires).Seconds())})
}
