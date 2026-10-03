package runtime

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
)

func (h *OwnerAuthHandler) batchZIPStatus(r *http.Request, owner, preview uuid.UUID) (ownerapi.BatchZIPStatus, error) {
	s := ownerapi.BatchZIPStatus{PreviewId: preview, Phase: "pending", NextAction: "none"}
	if e := h.pool.QueryRow(r.Context(), `SELECT p.workspace_id,jsonb_array_length(p.assignments),COALESCE(bool_and(public.tsw_rotation_join_usage_ready(slot.id)),false) AND count(slot.id)=jsonb_array_length(p.assignments) AND count(slot.id)>0 FROM public.tsw_expiry_rotation_previews p JOIN public.tsw_rotation_removals rem ON rem.preview_id=p.id LEFT JOIN public.tsw_rotation_removal_slots slot ON slot.preview_id=p.id WHERE p.owner_id=$1 AND p.id=$2 GROUP BY p.id`, owner, preview).Scan(&s.WorkspaceId, &s.AccountCount, &s.CanGenerate); e != nil {
		return s, e
	}
	if s.CanGenerate {
		s.NextAction = "generate"
	}
	a, e := readBatchZIP(r.Context(), h.pool, owner, preview)
	if errors.Is(e, pgx.ErrNoRows) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	s.PackageId = &a.id
	s.Filename = &a.filename
	s.CreatedAt = &a.created
	s.AccountCount = a.count
	s.CanGenerate = false
	s.Phase = "prepared"
	s.NextAction = "download"
	var reserved, delivered bool
	if e = h.pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM public.tsw_batch_zip_receivers WHERE package_id=$1),EXISTS(SELECT 1 FROM public.tsw_batch_zip_delivered WHERE package_id=$1)`, a.id).Scan(&reserved, &delivered); e != nil {
		return s, e
	}
	if reserved {
		s.Phase = "reserved"
	}
	if delivered {
		s.Phase = "delivered"
	}
	return s, nil
}
func (h *OwnerAuthHandler) GetBatchZIPStatus(w http.ResponseWriter, r *http.Request, preview uuid.UUID) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	s, e := h.batchZIPStatus(r, uuid.MustParse(owner.OwnerID), preview)
	if e != nil {
		h.removalError(w, r, e)
		return
	}
	writeJSON(w, 200, s)
}
func (h *OwnerAuthHandler) GenerateBatchZIP(w http.ResponseWriter, r *http.Request, preview uuid.UUID, _ ownerapi.GenerateBatchZIPParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	if !decodeRotationJoinAction(w, r) {
		writeProblem(w, r, 422, "confirmation_required", "Confirmation Required", "Confirm the original batch", 0)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if _, e := h.prepareBatchZIP(ctx, owner, preview); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			h.removalError(w, r, e)
			return
		}
		writeProblem(w, r, 409, "batch_zip_pending", "Original Batch Pending", "Reload the same original batch result", 0)
		return
	}
	s, e := h.batchZIPStatus(r, uuid.MustParse(owner.OwnerID), preview)
	if e != nil {
		h.removalError(w, r, e)
		return
	}
	writeJSON(w, 200, s)
}
func (h *OwnerAuthHandler) DownloadBatchZIP(w http.ResponseWriter, r *http.Request, preview uuid.UUID) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	a, e := readBatchZIP(r.Context(), h.pool, uuid.MustParse(owner.OwnerID), preview)
	if e != nil {
		h.removalError(w, r, e)
		return
	}
	data, e := h.openBatchZIP(a)
	if e != nil {
		writeProblem(w, r, 409, "batch_zip_pending", "Original Batch Pending", "The original package is unavailable", 0)
		return
	}
	defer clear(data)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+a.filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Last-Modified", a.created.UTC().Format(time.RFC1123))
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
