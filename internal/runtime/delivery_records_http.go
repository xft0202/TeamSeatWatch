package runtime

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
)

type deliveryRecordScan struct {
	MembershipID       string
	TargetAccountID    string
	WorkspaceID        string
	BatchID            string
	WorkspaceName      string
	AssetStatus        string
	Generation         int64
	LivenessStatus     *string
	LivenessOrigin     *string
	LivenessHTTPStatus *int
	LivenessErrorCode  *string
	ProbedAt           *time.Time
	CardStatus         *string
	CardSuffix         *string
	RedemptionDeadline *time.Time
	ReclaimStatus      *string
	ReclaimTier        *string
	ReclaimResult      *string
	CardID             *string
	AssetID            string
	MembershipState    string
	OrderID            *string
}

func (h *OwnerAuthHandler) ListDeliveryRecords(w http.ResponseWriter, r *http.Request, params ownerapi.ListDeliveryRecordsParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	if !validDeliveryRecordFilters(params) {
		writeProblem(w, r, http.StatusBadRequest, "invalid_delivery_filter", "Invalid Request", "A delivery filter is invalid", 0)
		return
	}
	page, pageSize := 1, 20
	if params.Page != nil && *params.Page > 0 {
		page = int(*params.Page)
	}
	if params.PageSize != nil && *params.PageSize > 0 && *params.PageSize <= 100 {
		pageSize = int(*params.PageSize)
	}
	args := deliveryRecordFilterArgs(params)
	countQuery := `SELECT count(*)
		FROM tsw_batch_memberships membership
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
		LEFT JOIN tsw_cards card ON card.membership_id=membership.id
		LEFT JOIN tsw_orders ord ON ord.membership_id=membership.id` + deliveryRecordFilterSQL
	var total int
	if err := h.pool.QueryRow(r.Context(), countQuery, args...).Scan(&total); err != nil {
		h.deliveryFailure(w, r)
		return
	}
	queryArgs := append(append([]any(nil), args...), pageSize, (page-1)*pageSize)
	rows, err := h.pool.Query(r.Context(), deliveryRecordQuery+deliveryRecordFilterSQL+` ORDER BY membership.created_at DESC,membership.id LIMIT $4 OFFSET $5`, queryArgs...)
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	defer rows.Close()
	items := make([]ownerapi.DeliveryRecord, 0, pageSize)
	for rows.Next() {
		var scan deliveryRecordScan
		if err := rows.Scan(
			&scan.MembershipID, &scan.TargetAccountID, &scan.WorkspaceID, &scan.BatchID, &scan.WorkspaceName,
			&scan.AssetID, &scan.AssetStatus, &scan.Generation, &scan.LivenessStatus, &scan.LivenessOrigin,
			&scan.LivenessHTTPStatus, &scan.LivenessErrorCode, &scan.ProbedAt, &scan.CardID, &scan.CardStatus,
			&scan.CardSuffix, &scan.RedemptionDeadline, &scan.ReclaimStatus, &scan.ReclaimTier, &scan.ReclaimResult,
			&scan.MembershipState, &scan.OrderID,
		); err != nil {
			h.deliveryFailure(w, r)
			return
		}
		item, err := deliveryRecordFromScan(scan)
		if err != nil {
			h.deliveryFailure(w, r)
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		h.deliveryFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, ownerapi.DeliveryRecordList{Page: page, PageSize: pageSize, Total: total, Items: items})
}

func (h *OwnerAuthHandler) GetDeliveryRecord(w http.ResponseWriter, r *http.Request, membershipID ownerapi.MembershipId) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	var scan deliveryRecordScan
	err := h.pool.QueryRow(r.Context(), deliveryRecordQuery+` WHERE membership.id=$1`, uuid.UUID(membershipID)).Scan(
		&scan.MembershipID, &scan.TargetAccountID, &scan.WorkspaceID, &scan.BatchID, &scan.WorkspaceName,
		&scan.AssetID, &scan.AssetStatus, &scan.Generation, &scan.LivenessStatus, &scan.LivenessOrigin,
		&scan.LivenessHTTPStatus, &scan.LivenessErrorCode, &scan.ProbedAt, &scan.CardID, &scan.CardStatus,
		&scan.CardSuffix, &scan.RedemptionDeadline, &scan.ReclaimStatus, &scan.ReclaimTier, &scan.ReclaimResult,
		&scan.MembershipState, &scan.OrderID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "delivery_not_found", "Not Found", "The delivery record was not found", 0)
		return
	}
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	item, err := deliveryRecordFromScan(scan)
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	events, err := h.deliveryRecordTimeline(r, scan)
	if err != nil {
		h.deliveryFailure(w, r)
		return
	}
	item.Timeline = &events
	writeJSON(w, http.StatusOK, item)
}

const deliveryRecordFilterSQL = ` WHERE ($1::text IS NULL OR (CASE WHEN membership.state='active' THEN 'active' ELSE 'ended' END)=$1::text)
	AND ($2::text IS NULL OR COALESCE(card.status,'unactivated')=$2::text)
	AND ($3::text IS NULL OR (CASE WHEN ord.id IS NULL THEN 'unclaimed' ELSE 'claimed' END)=$3::text)`

func validDeliveryRecordFilters(params ownerapi.ListDeliveryRecordsParams) bool {
	return (params.ServiceStatus == nil || params.ServiceStatus.Valid()) &&
		(params.CardStatus == nil || params.CardStatus.Valid()) &&
		(params.OrderStatus == nil || params.OrderStatus.Valid())
}

func deliveryRecordFilterArgs(params ownerapi.ListDeliveryRecordsParams) []any {
	var serviceStatus, cardStatus, orderStatus any
	if params.ServiceStatus != nil {
		serviceStatus = string(*params.ServiceStatus)
	}
	if params.CardStatus != nil {
		cardStatus = string(*params.CardStatus)
	}
	if params.OrderStatus != nil {
		orderStatus = string(*params.OrderStatus)
	}
	return []any{serviceStatus, cardStatus, orderStatus}
}

const deliveryRecordQuery = `SELECT membership.id::text,membership.target_account_id::text,workspace.id::text,batch.id::text,workspace.display_name,
	asset.id::text,asset.status,asset.current_generation,asset.liveness_status,asset.liveness_origin,asset.liveness_http_status,
	asset.liveness_error_code,asset.probed_at,card.id::text,card.status,card.display_suffix,card.redemption_deadline,
	reclaim.status,reclaim.reclaim_tier,reclaim.reclaim_result,membership.state,ord.id::text
	FROM tsw_batch_memberships membership
	JOIN tsw_batches batch ON batch.id=membership.batch_id
	JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
	JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
	JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
	LEFT JOIN tsw_cards card ON card.membership_id=membership.id
	LEFT JOIN tsw_orders ord ON ord.membership_id=membership.id
	LEFT JOIN LATERAL (
		SELECT task.status,task.reclaim_tier,task.reclaim_result
		FROM tsw_tasks task
		WHERE task.task_type='oauth_reclaim' AND task.oauth_asset_id=asset.id
		ORDER BY task.created_at DESC LIMIT 1
	) reclaim ON TRUE`

func deliveryRecordFromScan(scan deliveryRecordScan) (ownerapi.DeliveryRecord, error) {
	membershipID, err := uuid.Parse(scan.MembershipID)
	if err != nil {
		return ownerapi.DeliveryRecord{}, err
	}
	targetID, err := uuid.Parse(scan.TargetAccountID)
	if err != nil {
		return ownerapi.DeliveryRecord{}, err
	}
	workspaceID, err := uuid.Parse(scan.WorkspaceID)
	if err != nil {
		return ownerapi.DeliveryRecord{}, err
	}
	batchID, err := uuid.Parse(scan.BatchID)
	if err != nil {
		return ownerapi.DeliveryRecord{}, err
	}
	serviceStatus := ownerapi.DeliveryRecordServiceStatus("ended")
	if scan.MembershipState == "active" {
		serviceStatus = ownerapi.DeliveryRecordServiceStatus("active")
	}
	orderStatus := ownerapi.DeliveryRecordOrderStatus("unclaimed")
	if scan.OrderID != nil {
		orderStatus = ownerapi.DeliveryRecordOrderStatus("claimed")
	}
	cardStatus := "unactivated"
	if scan.CardStatus != nil {
		cardStatus = *scan.CardStatus
	}
	return ownerapi.DeliveryRecord{
		MembershipId: membershipID, TargetAccountId: targetID, WorkspaceId: workspaceID, BatchId: batchID,
		WorkspaceName: scan.WorkspaceName, AssetStatus: scan.AssetStatus, Generation: scan.Generation,
		LivenessStatus: scan.LivenessStatus, LivenessOrigin: scan.LivenessOrigin, LivenessHttpStatus: scan.LivenessHTTPStatus,
		LivenessErrorCode: scan.LivenessErrorCode, ProbedAt: scan.ProbedAt, CardStatus: &cardStatus,
		CardDisplaySuffix: scan.CardSuffix, RedemptionDeadline: scan.RedemptionDeadline, ReclaimStatus: scan.ReclaimStatus,
		ReclaimTier: scan.ReclaimTier, ReclaimResult: scan.ReclaimResult,
		ServiceStatus: &serviceStatus, OrderStatus: &orderStatus,
	}, nil
}

func (h *OwnerAuthHandler) deliveryRecordTimeline(r *http.Request, scan deliveryRecordScan) ([]ownerapi.DeliveryRecordEvent, error) {
	if scan.CardID == nil {
		return []ownerapi.DeliveryRecordEvent{}, nil
	}
	rows, err := h.pool.Query(r.Context(), `SELECT occurred_at,event_type,outcome,details
		FROM tsw_audit_events
		WHERE (retention_scope_type='card' AND retention_scope_id=$1::uuid)
		   OR (entity_type='oauth_asset' AND entity_id=$2)
		   OR (entity_type='oauth_attempt' AND entity_id IN (SELECT id::text FROM tsw_oauth_attempts WHERE oauth_asset_id=$2::uuid))
		ORDER BY occurred_at ASC LIMIT 100`, *scan.CardID, scan.AssetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]ownerapi.DeliveryRecordEvent, 0, 16)
	for rows.Next() {
		var occurredAt time.Time
		var eventType, outcome string
		var raw []byte
		if err := rows.Scan(&occurredAt, &eventType, &outcome, &raw); err != nil {
			return nil, err
		}
		var detail map[string]any
		_ = json.Unmarshal(raw, &detail)
		event := ownerapi.DeliveryRecordEvent{OccurredAt: occurredAt, Action: strings.TrimPrefix(eventType, "public."), Result: outcome}
		if value, ok := detail["action"].(string); ok && value != "" {
			event.Action = value
		}
		if value, ok := detail["result"].(string); ok && value != "" {
			event.Result = value
		}
		if value, ok := detail["reason"].(string); ok && value != "" {
			event.Reason = &value
		}
		if value, ok := detail["status"].(string); ok && value != "" {
			event.Status = &value
		}
		if value, ok := detail["http_status"].(float64); ok && value >= 100 && value <= 599 {
			httpStatus := int(value)
			event.HttpStatus = &httpStatus
		}
		if value, ok := detail["result"].(string); ok && (value == "probe_ok" || value == "token_refresh" || value == "full_relogin" || value == "unrecoverable") {
			event.Tier = &value
		}
		if strings.HasPrefix(eventType, "public.reclaim_requested") {
			origin := "customer"
			event.Origin = &origin
		} else if eventType == string(audit.OwnerDeliveryReclaimAuthorized) || eventType == string(audit.OwnerCardRevoked) {
			origin := "owner"
			event.Origin = &origin
		} else if value, ok := detail["reason"].(string); ok && value == "authoritative_401" {
			origin := "automatic"
			event.Origin = &origin
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
