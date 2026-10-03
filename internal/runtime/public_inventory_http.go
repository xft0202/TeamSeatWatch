package runtime

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	oauthdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/oauth"
)

func publicZIPInventory(ctx context.Context, db rotationRow, owner, packageID uuid.UUID) (ownerapi.PublicZIPInventory, error) {
	out := ownerapi.PublicZIPInventory{PackageId: packageID, Status: "not_activated"}
	var exists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_batch_zip_archives WHERE id=$1 AND owner_id=$2)`, packageID, owner).Scan(&exists); err != nil {
		return out, err
	}
	if !exists {
		return out, pgx.ErrNoRows
	}
	var enabled bool
	var revoked *time.Time
	err := db.QueryRow(ctx, `SELECT display_suffix,claim_expires_at,access_expires_at,enabled,revoked_at,EXISTS(SELECT 1 FROM public.tsw_public_zip_orders o WHERE o.inventory_id=i.id) FROM public.tsw_public_zip_inventory i WHERE package_id=$1 AND owner_id=$2`, packageID, owner).Scan(&out.CardSuffix, &out.ClaimExpiresAt, &out.AccessExpiresAt, &enabled, &revoked, &out.HasOrder)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Status = "active"
	if revoked != nil {
		out.Status = "revoked"
	} else if !enabled || out.AccessExpiresAt == nil || !out.AccessExpiresAt.After(time.Now()) {
		out.Status = "unavailable"
	}
	return out, nil
}
func (h *OwnerAuthHandler) GetPublicZIPInventory(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	out, err := publicZIPInventory(r.Context(), h.pool, uuid.MustParse(owner.OwnerID), id)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
func (h *OwnerAuthHandler) ActivatePublicZIPInventory(w http.ResponseWriter, r *http.Request, id uuid.UUID, _ ownerapi.ActivatePublicZIPInventoryParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.ActivatePublicZIPInventoryJSONRequestBody
	if !decodeJSON(w, r, &request) || request.Confirmed != ownerapi.ActivatePublicZIPInventoryRequestConfirmedTrue || !request.ClaimExpiresAt.After(time.Now()) || request.AccessExpiresAt.Before(request.ClaimExpiresAt) {
		writeProblem(w, r, 422, "invalid_public_inventory", "Invalid Authorization", "Confirm valid claim and access deadlines", 0)
		return
	}
	version, hash, err := oauthdomain.LookupHMAC(h.keyRing, request.CardSecret)
	if err != nil {
		writeProblem(w, r, 422, "invalid_public_inventory", "Invalid Authorization", "The card secret is invalid", 0)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	// Serialize activation with channel reservation, but activation itself never
	// reserves accounts or becomes a sale. Public's first claim does that.
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('tsw.batch.zip.receiver.'||$1::text,0))`, id); err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	var originalOwner, workspaceID uuid.UUID
	var reserved bool
	err = tx.QueryRow(r.Context(), `SELECT owner_id,workspace_id,EXISTS(SELECT 1 FROM public.tsw_batch_zip_receivers WHERE package_id=a.id) FROM public.tsw_batch_zip_archives a WHERE id=$1`, id).Scan(&originalOwner, &workspaceID, &reserved)
	if err != nil || originalOwner.String() != owner.OwnerID {
		h.removalError(w, r, pgx.ErrNoRows)
		return
	}
	changed := false
	var existingVersion uint16
	var existingHash []byte
	var claim, access time.Time
	err = tx.QueryRow(r.Context(), `SELECT hmac_key_version,lookup_hmac,claim_expires_at,access_expires_at FROM public.tsw_public_zip_inventory WHERE package_id=$1 FOR UPDATE`, id).Scan(&existingVersion, &existingHash, &claim, &access)
	if err == nil {
		if existingVersion != version || !hmacEqual(existingHash, hash[:]) || !claim.Equal(request.ClaimExpiresAt) || !access.Equal(request.AccessExpiresAt) {
			writeProblem(w, r, 409, "public_inventory_bound", "Original Authorization", "Keep the original card and deadlines", 0)
			return
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		changed = true
		if reserved {
			writeProblem(w, r, 409, "public_inventory_bound", "Original Authorization", "The original package already has a customer authorization", 0)
			return
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO public.tsw_public_zip_inventory(id,package_id,owner_id,hmac_key_version,lookup_hmac,display_suffix,claim_expires_at,access_expires_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), id, originalOwner, version, hash[:], oauthdomain.DisplaySuffix(request.CardSecret), request.ClaimExpiresAt, request.AccessExpiresAt)
		if err != nil {
			writeProblem(w, r, 409, "public_inventory_bound", "Original Authorization", "The card or original package is already bound", 0)
			return
		}
	} else {
		h.deliveryFailure(w, r, err)
		return
	}
	out, err := publicZIPInventory(r.Context(), tx, originalOwner, id)
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.CardActivated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: workspaceID.String(), EntityType: "card", EntityID: id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.CardDetails{Result: "activated", KeyVersion: int(version), DisplaySuffix: oauthdomain.DisplaySuffix(request.CardSecret)}, IdempotencyKey: "public-zip:" + id.String() + ":activated"})
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	var token string
	var idleExpiresAt time.Time
	if changed {
		token, idleExpiresAt, err = h.rotateSessionTx(r.Context(), tx, owner, "public_inventory_authorization", r)
		if err != nil {
			h.deliveryFailure(w, r, err)
			return
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	if changed {
		auth.SetSessionCookie(w, token, idleExpiresAt, h.secureCookies)
	}
	writeJSON(w, 200, out)
}
func (h *OwnerAuthHandler) RevokePublicZIPInventory(w http.ResponseWriter, r *http.Request, id uuid.UUID, _ ownerapi.RevokePublicZIPInventoryParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	if !decodeRotationJoinAction(w, r) {
		writeProblem(w, r, 422, "confirmation_required", "Confirmation Required", "Confirm revocation of the original Public authorization", 0)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var revokedAt *time.Time
	if err = tx.QueryRow(r.Context(), `SELECT revoked_at FROM public.tsw_public_zip_inventory WHERE package_id=$1 AND owner_id=$2 FOR UPDATE`, id, owner.OwnerID).Scan(&revokedAt); err != nil {
		h.removalError(w, r, err)
		return
	}
	if revokedAt != nil {
		out, e := publicZIPInventory(r.Context(), tx, uuid.MustParse(owner.OwnerID), id)
		if e != nil {
			h.deliveryFailure(w, r, e)
			return
		}
		if e = tx.Commit(r.Context()); e != nil {
			h.deliveryFailure(w, r, e)
			return
		}
		writeJSON(w, 200, out)
		return
	}
	tag, err := tx.Exec(r.Context(), `UPDATE public.tsw_public_zip_inventory SET revoked_at=COALESCE(revoked_at,clock_timestamp()),enabled=false WHERE package_id=$1 AND owner_id=$2`, id, owner.OwnerID)
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	if tag.RowsAffected() != 1 {
		h.removalError(w, r, pgx.ErrNoRows)
		return
	}
	tokens, err := tx.Exec(r.Context(), `UPDATE public.tsw_public_zip_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE order_id IN (SELECT id FROM public.tsw_public_zip_orders WHERE package_id=$1)`, id)
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	out, err := publicZIPInventory(r.Context(), tx, uuid.MustParse(owner.OwnerID), id)
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	var inventoryID uuid.UUID
	if err = tx.QueryRow(r.Context(), `SELECT id FROM public.tsw_public_zip_inventory WHERE package_id=$1`, id).Scan(&inventoryID); err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.OwnerCardRevoked, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: inventoryID.String(), EntityType: "card", EntityID: id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.CardRevocationDetails{Action: "owner_revoked", Result: "revoked", RevokedTokenCount: int(tokens.RowsAffected())}, IdempotencyKey: "public-zip:" + id.String() + ":revoked"})
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	token, idleExpiresAt, err := h.rotateSessionTx(r.Context(), tx, owner, "public_inventory_authorization", r)
	if err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		h.deliveryFailure(w, r, err)
		return
	}
	auth.SetSessionCookie(w, token, idleExpiresAt, h.secureCookies)
	writeJSON(w, 200, out)
}
