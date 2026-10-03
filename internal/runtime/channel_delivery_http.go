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

func (h *OwnerAuthHandler) channelStatus(ctx context.Context, owner ownerContext, preview uuid.UUID) (ownerapi.ChannelDeliveryStatus, error) {
	s := ownerapi.ChannelDeliveryStatus{PreviewId: preview, Phase: "pending", NextAction: "none", Objects: []ownerapi.ChannelDeliveryObject{}}
	if e := h.pool.QueryRow(ctx, `SELECT p.workspace_id FROM public.tsw_expiry_rotation_previews p JOIN public.tsw_rotation_removals r ON r.preview_id=p.id WHERE p.id=$1 AND p.owner_id=$2`, preview, owner.OwnerID).Scan(&s.WorkspaceId); e != nil {
		return s, e
	}
	a, e := readBatchZIP(ctx, h.pool, uuid.MustParse(owner.OwnerID), preview)
	if errors.Is(e, pgx.ErrNoRows) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	s.PackageId = &a.id
	c, e := h.readChannel(ctx, h.pool, a)
	if errors.Is(e, pgx.ErrNoRows) {
		// Passive reads do not freeze, expose or create a remote channel order.
		c, e = h.originalChannel(ctx, h.pool, a)
		if errors.Is(e, pgx.ErrNoRows) {
			return s, nil
		}
		if e != nil {
			return s, e
		}
		s.DestinationName = &c.destination.Name
		if e = h.channelAuthority(ctx, h.pool, owner, c); errors.Is(e, errChannelPending) {
			return s, nil
		} else if e != nil {
			return s, e
		}
		rows, e := h.pool.Query(ctx, `SELECT target_account_id,slot_id FROM public.tsw_batch_zip_members WHERE package_id=$1 ORDER BY ordinal`, a.id)
		if e != nil {
			return s, e
		}
		objects := []ChannelObject{}
		for rows.Next() {
			var o ChannelObject
			if e = rows.Scan(&o.AccountID, &o.SlotID); e != nil {
				rows.Close()
				return s, e
			}
			objects = append(objects, o)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return s, e
		}
		if len(objects) != a.count {
			return s, nil
		}
		for _, o := range objects {
			if e = h.channelFresh(ctx, h.pool, c, o); e != nil {
				// Qualification failures retain the archive without offering an
				// exposure action. The guarded POST checks these same live facts.
				return s, nil
			}
		}
		s.Phase = "ready"
		s.NextAction = "receive"
		return s, nil
	}
	if e != nil {
		return s, e
	}
	s.DestinationName = &c.destination.Name
	s.Phase = "receiving"
	s.NextAction = "reconcile"
	rows, e := h.pool.Query(ctx, `SELECT m.target_account_id,m.slot_id,a.identifier,EXISTS(SELECT 1 FROM public.tsw_channel_attempts t WHERE t.package_id=m.package_id AND t.target_account_id=m.target_account_id),EXISTS(SELECT 1 FROM public.tsw_channel_receipts r WHERE r.package_id=m.package_id AND r.target_account_id=m.target_account_id AND r.stage='received'),EXISTS(SELECT 1 FROM public.tsw_channel_associations r WHERE r.package_id=m.package_id AND r.target_account_id=m.target_account_id AND r.stage='received'),EXISTS(SELECT 1 FROM public.tsw_channel_receipts r WHERE r.package_id=m.package_id AND r.target_account_id=m.target_account_id AND r.stage='delivered'),EXISTS(SELECT 1 FROM public.tsw_channel_associations r WHERE r.package_id=m.package_id AND r.target_account_id=m.target_account_id AND r.stage='delivered') FROM public.tsw_batch_zip_members m JOIN public.tsw_target_accounts a ON a.id=m.target_account_id WHERE m.package_id=$1 ORDER BY m.ordinal`, a.id)
	if e != nil {
		return s, e
	}
	defer rows.Close()
	pending := false
	for rows.Next() {
		v := ownerapi.ChannelDeliveryObject{Reception: "pending", Delivery: "pending"}
		var attempted, rawReceived, received, rawDelivered, delivered bool
		if e = rows.Scan(&v.AccountId, &v.SlotId, &v.Identifier, &attempted, &rawReceived, &received, &rawDelivered, &delivered); e != nil {
			return s, e
		}
		if attempted {
			v.Reception = "receipt_pending"
		}
		if rawReceived {
			v.Reception = "record_pending"
		}
		if received {
			v.Reception = "received"
			s.ReceivedCount++
		}
		if rawDelivered {
			v.Delivery = "record_pending"
		}
		if delivered {
			v.Delivery = "delivered"
			s.DeliveredCount++
		}
		if !attempted {
			pending = true
		}
		s.Objects = append(s.Objects, v)
	}
	if e = rows.Err(); e != nil {
		return s, e
	}
	active := h.channelAuthority(ctx, h.pool, owner, c) == nil
	if pending && active {
		s.NextAction = "receive"
	}
	if !active {
		s.Phase = "blocked"
	}
	if s.ReceivedCount > 0 && s.ReceivedCount < a.count {
		s.Phase = "partial"
	}
	if s.ReceivedCount == a.count {
		s.Phase = "received"
	}
	if s.DeliveredCount > 0 && s.DeliveredCount < a.count {
		s.Phase = "partial"
	}
	if s.DeliveredCount == a.count {
		s.Phase = "delivered"
		s.NextAction = "none"
	}
	return s, nil
}
func (h *OwnerAuthHandler) GetChannelDelivery(w http.ResponseWriter, r *http.Request, preview uuid.UUID) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	s, e := h.channelStatus(r.Context(), owner, preview)
	if e != nil {
		h.removalError(w, r, e)
		return
	}
	writeJSON(w, 200, s)
}
func (h *OwnerAuthHandler) ReceiveChannelDelivery(w http.ResponseWriter, r *http.Request, preview uuid.UUID, _ ownerapi.ReceiveChannelDeliveryParams) {
	h.channelAction(w, r, preview, true)
}
func (h *OwnerAuthHandler) ReconcileChannelDelivery(w http.ResponseWriter, r *http.Request, preview uuid.UUID, _ ownerapi.ReconcileChannelDeliveryParams) {
	h.channelAction(w, r, preview, false)
}
func (h *OwnerAuthHandler) channelAction(w http.ResponseWriter, r *http.Request, preview uuid.UUID, receive bool) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	if !decodeRotationJoinAction(w, r) {
		writeProblem(w, r, 422, "confirmation_required", "Confirmation Required", "Confirm the original channel obligation", 0)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if e := h.runChannel(ctx, owner, preview, receive); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			h.removalError(w, r, e)
			return
		}
		writeProblem(w, r, 409, "channel_delivery_pending", "Original Channel Pending", "Reload the original channel result", 0)
		return
	}
	s, e := h.channelStatus(r.Context(), owner, preview)
	if e != nil {
		h.removalError(w, r, e)
		return
	}
	writeJSON(w, 200, s)
}
