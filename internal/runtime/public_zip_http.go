package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/internalapi"
	oauthdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/oauth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/publicaccess"
)

type publicZIPFacts struct {
	inventory, packageID, order uuid.UUID
	customer, suffix            string
	enabled                     bool
	revoked                     *time.Time
	claimExpiry, accessExpiry   time.Time
}

func (f publicZIPFacts) allowed() bool {
	return f.enabled && f.revoked == nil && time.Now().Before(f.accessExpiry)
}
func (f publicZIPFacts) recipient() BatchZIPRecipient {
	return BatchZIPRecipient{"public", f.customer, f.order.String()}
}
func (h *PublicRedeemHandler) zipService() *OwnerAuthHandler {
	return &OwnerAuthHandler{pool: h.pool, keyRing: h.keyRing}
}

// Card/token dispatch preserves authorized historical orders. It never maps a
// legacy account or channel name to a new Public inventory record.
func (h *PublicRedeemHandler) zipCardRequest(w http.ResponseWriter, r *http.Request, action string, legacy http.HandlerFunc) {
	var request internalapi.CardRequest
	if !decodeJSON(w, r, &request) || !validCardInput(request.CardSecret) {
		writePublicProblem(w, r, 400, "public_request_invalid", 0)
		return
	}
	body, _ := json.Marshal(request)
	r.Body = io.NopCloser(bytes.NewReader(body))
	id, err := h.findZIPCard(r.Context(), request.CardSecret)
	if errors.Is(err, pgx.ErrNoRows) {
		legacy(w, r)
		return
	}
	if err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	if !h.allowCardRequest(r.Context(), r, request.CardSecret) {
		writePublicProblem(w, r, 429, "public_rate_limited", 60)
		return
	}
	h.handleZIPCard(w, r, id, action)
}
func (h *PublicRedeemHandler) findZIPCard(ctx context.Context, secret string) (uuid.UUID, error) {
	rows, err := h.pool.Query(ctx, `SELECT DISTINCT hmac_key_version FROM public.tsw_public_zip_inventory`)
	if err != nil {
		return uuid.Nil, err
	}
	versions := []uint16{}
	for rows.Next() {
		var v uint16
		if err = rows.Scan(&v); err != nil {
			rows.Close()
			return uuid.Nil, err
		}
		versions = append(versions, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return uuid.Nil, err
	}
	for _, v := range versions {
		hash, e := oauthdomain.LookupHMACVersion(h.keyRing, v, secret)
		if e != nil {
			continue
		}
		var id uuid.UUID
		e = h.pool.QueryRow(ctx, `SELECT id FROM public.tsw_public_zip_inventory WHERE hmac_key_version=$1 AND lookup_hmac=$2`, v, hash[:]).Scan(&id)
		if e == nil {
			return id, nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return uuid.Nil, e
		}
	}
	return uuid.Nil, pgx.ErrNoRows
}
func (h *PublicRedeemHandler) ConfirmPublicRedeem(w http.ResponseWriter, r *http.Request) {
	h.zipCardRequest(w, r, "claim", h.legacyConfirmPublicRedeem)
}
func (h *PublicRedeemHandler) CheckPublicRedeemCredentialStatus(w http.ResponseWriter, r *http.Request) {
	h.zipCardRequest(w, r, "check", h.legacyCheckPublicRedeemCredentialStatus)
}
func (h *PublicRedeemHandler) RequestPublicRedeemReclaim(w http.ResponseWriter, r *http.Request) {
	h.zipCardRequest(w, r, "recover", h.legacyRequestPublicRedeemReclaim)
}
func (h *PublicRedeemHandler) GetPublicRedeemState(w http.ResponseWriter, r *http.Request) {
	h.zipTokenRequest(w, r, "state", h.legacyGetPublicRedeemState)
}
func (h *PublicRedeemHandler) ListPublicRedeemRecords(w http.ResponseWriter, r *http.Request) {
	h.zipTokenRequest(w, r, "records", h.legacyListPublicRedeemRecords)
}
func (h *PublicRedeemHandler) GetPublicRedeemReclaimStatus(w http.ResponseWriter, r *http.Request) {
	h.zipTokenRequest(w, r, "recovery", h.legacyGetPublicRedeemReclaimStatus)
}
func (h *PublicRedeemHandler) DownloadPublicRedeemDelivery(w http.ResponseWriter, r *http.Request) {
	h.zipTokenRequest(w, r, "download", h.legacyDownloadPublicRedeemDelivery)
}

func loadPublicZIPFacts(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock string) (publicZIPFacts, error) {
	var f publicZIPFacts
	// Waiting for an inventory lock must finish in its own statement: a LEFT
	// JOIN snapshot taken before the wait cannot see the preceding claimant's
	// newly committed order, because that insert did not update inventory.
	if lock != "" {
		var locked uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT i.id FROM public.tsw_public_zip_inventory i WHERE i.id=$1 `+lock, id).Scan(&locked); err != nil {
			return f, err
		}
	}
	err := tx.QueryRow(ctx, `SELECT i.id,i.package_id,COALESCE(o.id,'00000000-0000-0000-0000-000000000000'::uuid),COALESCE(o.customer_id,''),i.display_suffix,i.enabled,i.revoked_at,i.claim_expires_at,i.access_expires_at FROM public.tsw_public_zip_inventory i LEFT JOIN public.tsw_public_zip_orders o ON o.inventory_id=i.id WHERE i.id=$1 `, id).Scan(&f.inventory, &f.packageID, &f.order, &f.customer, &f.suffix, &f.enabled, &f.revoked, &f.claimExpiry, &f.accessExpiry)
	return f, err
}
func (h *PublicRedeemHandler) handleZIPCard(w http.ResponseWriter, r *http.Request, id uuid.UUID, action string) {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	defer tx.Rollback(r.Context())
	f, err := loadPublicZIPFacts(r.Context(), tx, id, "FOR UPDATE OF i")
	if err != nil || !f.allowed() {
		writePublicProblem(w, r, 404, "public_request_denied", 0)
		return
	}
	if action == "check" {
		// This is archive/authorization state, never a fabricated platform probe.
		writeNoStoreJSON(w, 200, internalapi.CredentialStatus{Status: "unknown", CheckQueued: false})
		return
	}
	restored := f.order != uuid.Nil
	if action == "recover" && !restored {
		writePublicProblem(w, r, 404, "public_request_denied", 0)
		return
	}
	if !restored {
		if !time.Now().Before(f.claimExpiry) {
			writePublicProblem(w, r, 404, "public_request_denied", 0)
			return
		}
		f.order = uuid.New()
		f.customer = "public:" + f.order.String()
		if err = h.zipService().reserveBatchZIPTx(r.Context(), tx, f.packageID, f.recipient()); err != nil {
			writePublicProblem(w, r, 404, "public_request_denied", 0)
			return
		}
		if _, err = tx.Exec(r.Context(), `INSERT INTO public.tsw_public_zip_orders(id,inventory_id,package_id,customer_id)VALUES($1,$2,$3,$4)`, f.order, f.inventory, f.packageID, f.customer); err != nil {
			writePublicProblem(w, r, 503, "public_unavailable", 0)
			return
		}
	}
	// Verify the exact encrypted original before exposing a download action. A
	// failure rolls back first claim; recovery never creates a replacement order.
	a, err := readPublicZIPArchive(r.Context(), tx, f)
	if err != nil {
		writePublicProblem(w, r, 404, "public_request_denied", 0)
		return
	}
	data, err := h.zipService().openBatchZIP(a)
	if err != nil {
		writePublicProblem(w, r, 409, "public_delivery_pending", 0)
		return
	}
	clear(data)
	plain, hash, err := publicaccess.NewToken()
	if err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	expires := time.Now().UTC().Add(publicAccessTTL)
	if f.accessExpiry.Before(expires) {
		expires = f.accessExpiry
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO public.tsw_public_zip_tokens(id,order_id,token_hash,expires_at)VALUES($1,$2,$3,$4)`, uuid.New(), f.order, hash[:], expires); err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	event, publicAction := audit.PublicOrderCreated, "first_claim"
	if restored {
		event, publicAction = audit.PublicOrderRestored, "order_restore"
	}
	if action == "recover" {
		event, publicAction = audit.PublicOrderRestored, "order_restore"
	}
	if err = writePublicAudit(r.Context(), tx, event, "order", f.order.String(), f.inventory.String(), r, audit.PublicAccessDetails{Action: publicAction, Result: "accepted"}); err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	setPublicAccessCookie(w, plain, expires)
	if action == "recover" {
		writeNoStoreJSON(w, 202, zipRecoveryStatus(true))
		return
	}
	response := zipConfirmation(f, a)
	if restored {
		response.Action = "restored"
	}
	writeNoStoreJSON(w, 200, response)
}
func readPublicZIPArchive(ctx context.Context, tx pgx.Tx, f publicZIPFacts) (batchZIPRecord, error) {
	var owner, preview uuid.UUID
	err := tx.QueryRow(ctx, `SELECT a.owner_id,a.preview_id FROM public.tsw_batch_zip_archives a JOIN public.tsw_batch_zip_receivers r ON r.package_id=a.id WHERE a.id=$1 AND r.channel='public' AND r.customer_id=$2 AND r.authorization_id=$3 AND a.account_count=(SELECT count(*) FROM public.tsw_batch_zip_protections p WHERE p.package_id=a.id AND p.customer_id=$2)`, f.packageID, f.customer, f.order.String()).Scan(&owner, &preview)
	if err != nil {
		return batchZIPRecord{}, err
	}
	return readBatchZIP(ctx, tx, owner, preview)
}
func zipConfirmation(f publicZIPFacts, a batchZIPRecord) internalapi.RedeemConfirmation {
	format := internalapi.RedeemConfirmationDeliveryFormatZip
	return internalapi.RedeemConfirmation{Action: "claimed", CardSuffix: f.suffix, HasOrder: true, CanAccess: true, CanClaim: false, RemainingSeconds: int64(max(0, time.Until(f.accessExpiry).Seconds())), DeliveryStatus: "available", LivenessStatus: "unknown", Filename: &a.filename, AccountCount: &a.count, DeliveryFormat: &format}
}
func zipRecoveryStatus(available bool) internalapi.ReclaimStatus {
	delivery := internalapi.ReclaimStatusDeliveryStatusUnavailable
	if available {
		delivery = internalapi.ReclaimStatusDeliveryStatusAvailable
	}
	result := internalapi.ReclaimStatusResultRestored
	return internalapi.ReclaimStatus{Status: internalapi.ReclaimStatusStatusSucceeded, DeliveryStatus: delivery, LivenessStatus: internalapi.ReclaimStatusLivenessStatusUnknown, Result: &result}
}
func (h *PublicRedeemHandler) zipTokenRequest(w http.ResponseWriter, r *http.Request, action string, legacy http.HandlerFunc) {
	cookie, err := r.Cookie(publicaccess.CookieName)
	if err != nil {
		legacy(w, r)
		return
	}
	hash, err := publicaccess.HashToken(cookie.Value)
	if err != nil {
		legacy(w, r)
		return
	}
	var id uuid.UUID
	err = h.pool.QueryRow(r.Context(), `SELECT o.inventory_id FROM public.tsw_public_zip_tokens t JOIN public.tsw_public_zip_orders o ON o.id=t.order_id WHERE t.token_hash=$1`, hash[:]).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		legacy(w, r)
		return
	}
	if err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	if !h.allowTokenRequest(r.Context(), r, cookie.Value) {
		writePublicProblem(w, r, 429, "public_rate_limited", 60)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	defer tx.Rollback(r.Context())
	// Revocation/permission writes wait for the entire authorized read/write.
	f, err := loadPublicZIPFacts(r.Context(), tx, id, "FOR SHARE OF i")
	var tokenOK bool
	if err == nil {
		err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM public.tsw_public_zip_tokens WHERE token_hash=$1 AND order_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp())`, hash[:], f.order).Scan(&tokenOK)
	}
	if err != nil || !tokenOK || !f.allowed() {
		writePublicProblem(w, r, 404, "public_request_denied", 0)
		return
	}
	a, err := readPublicZIPArchive(r.Context(), tx, f)
	if err != nil {
		writePublicProblem(w, r, 404, "public_request_denied", 0)
		return
	}
	timeline, err := loadTimelineTx(r.Context(), tx, f.inventory.String())
	if err != nil {
		writePublicProblem(w, r, 503, "public_unavailable", 0)
		return
	}
	if action == "records" {
		writeNoStoreJSON(w, 200, internalapi.RedeemTimeline{Items: timeline})
		return
	}
	data, err := h.zipService().openBatchZIP(a)
	if err != nil {
		writePublicProblem(w, r, 409, "public_delivery_pending", 0)
		return
	}
	defer clear(data)
	if action == "state" {
		c := zipConfirmation(f, a)
		format := internalapi.RedeemStateDeliveryFormatZip
		writeNoStoreJSON(w, 200, internalapi.RedeemState{CardSuffix: c.CardSuffix, HasOrder: true, CanClaim: false, CanAccess: true, RemainingSeconds: c.RemainingSeconds, DeliveryStatus: c.DeliveryStatus, LivenessStatus: c.LivenessStatus, Timeline: timeline, Filename: c.Filename, AccountCount: c.AccountCount, DeliveryFormat: &format})
		return
	}
	if action == "recovery" {
		writeNoStoreJSON(w, 200, zipRecoveryStatus(true))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+a.filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	n, writeErr := w.Write(data)
	// A local completed transfer is the Public receipt; interrupted writes leave
	// the same permanent reservation pending. No claim/status/read implies receipt.
	if writeErr == nil && n == len(data) {
		_, err = tx.Exec(r.Context(), `INSERT INTO public.tsw_batch_zip_delivered(package_id,receipt_id)VALUES($1,$2)ON CONFLICT(package_id)DO NOTHING`, f.packageID, "public-download:"+f.order.String())
		if err == nil {
			_ = tx.Commit(r.Context())
		}
	}
}
