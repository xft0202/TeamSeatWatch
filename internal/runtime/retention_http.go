package runtime

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
)

type auditFilter struct {
	From, To      *time.Time
	Actor         string
	EventType     string
	Outcome       string
	WorkspaceID   *uuid.UUID
	BatchID       *uuid.UUID
	MembershipID  *uuid.UUID
	OrderID       *uuid.UUID
	CorrelationID string
}

type auditRecord struct {
	OccurredAt  time.Time
	Actor       string
	EventType   string
	Outcome     string
	EntityType  string
	Correlation string
	Details     map[string]interface{}
}

func (h *OwnerAuthHandler) listAuditEvents(w http.ResponseWriter, r *http.Request, params ownerapi.ListAuditEventsParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	filter, ok := auditFilterFromList(params)
	if !ok {
		writeProblem(w, r, http.StatusBadRequest, "invalid_audit_filter", "Invalid Request", "An audit filter is invalid", 0)
		return
	}
	page, pageSize := auditPage(params.Page, params.PageSize)
	items, total, err := h.queryAuditRecords(r, filter, pageSize, (page-1)*pageSize)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "audit_records_unavailable", "Internal Server Error", "Audit records are temporarily unavailable", 0)
		return
	}
	writeJSON(w, http.StatusOK, ownerapi.AuditEventList{Items: items, Page: page, PageSize: pageSize, Total: total})
}

func (h *OwnerAuthHandler) exportAuditEvents(w http.ResponseWriter, r *http.Request, params ownerapi.ExportAuditEventsParams) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	filter, valid := auditFilterFromExport(params)
	if !valid || !params.Format.Valid() {
		writeProblem(w, r, http.StatusBadRequest, "invalid_audit_export", "Invalid Request", "The audit export request is invalid", 0)
		return
	}
	items, total, err := h.queryAuditRecords(r, filter, 5000, 0)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "audit_export_unavailable", "Internal Server Error", "Audit export is temporarily unavailable", 0)
		return
	}
	if err := h.recordAuditExport(r, owner.OwnerID, string(params.Format)); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to record audit export", 0)
		return
	}
	if params.Format == ownerapi.Json {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=teamseatwatch-audit.json")
		writeJSON(w, http.StatusOK, ownerapi.AuditEventList{Items: items, Page: 1, PageSize: len(items), Total: total})
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=teamseatwatch-audit.csv")
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"occurred_at", "actor", "event_type", "outcome", "entity_type", "correlation_id", "details_json"})
	for _, item := range items {
		details, _ := json.Marshal(item.Details)
		_ = writer.Write([]string{item.OccurredAt.UTC().Format(time.RFC3339Nano), string(item.Actor), item.EventType, string(item.Outcome), item.EntityType, item.CorrelationId, string(details)})
	}
	writer.Flush()
}

func (h *OwnerAuthHandler) recordAuditExport(r *http.Request, ownerID, format string) error {
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	if _, err := audit.Write(r.Context(), tx, audit.Event{Type: audit.OwnerAuditExported, Actor: audit.ActorOwner, OwnerID: ownerID, EntityType: "owner", EntityID: ownerID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.AuditExportDetails{Format: format, Result: "downloaded"}, IdempotencyKey: correlation(r) + ":audit-export:" + format}); err != nil {
		return err
	}
	return tx.Commit(r.Context())
}

func (h *OwnerAuthHandler) getDataProtectionStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	status, err := h.dataProtectionStatus(r)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "data_protection_unavailable", "Internal Server Error", "Data protection status is temporarily unavailable", 0)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (h *OwnerAuthHandler) openRecoveryGate(w http.ResponseWriter, r *http.Request, _ ownerapi.OpenRecoveryGateParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.OpenRecoveryGateJSONRequestBody
	if !decodeJSON(w, r, &request) || request.RestoredAt.IsZero() || request.RestoredAt.After(time.Now().UTC().Add(time.Minute)) {
		writeProblem(w, r, http.StatusBadRequest, "invalid_recovery_open", "Invalid Request", "The recovery timestamp is invalid", 0)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "recovery_gate_unavailable", "Internal Server Error", "Recovery gate is temporarily unavailable", 0)
		return
	}
	defer tx.Rollback(r.Context())
	var pending int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM tsw_batch_memberships WHERE state='removed' AND retention_due_at<=now()`).Scan(&pending); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "recovery_gate_unavailable", "Internal Server Error", "Recovery gate is temporarily unavailable", 0)
		return
	}
	if pending != 0 {
		writeProblem(w, r, http.StatusConflict, "recovery_cleanup_required", "Conflict", "Retention cleanup must complete before recovery opens", 0)
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE tsw_recovery_gate SET state='open',restored_at=$1,checked_at=now() WHERE id=true`, request.RestoredAt); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "recovery_gate_unavailable", "Internal Server Error", "Recovery gate is temporarily unavailable", 0)
		return
	}
	if _, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.RecoveryGateOpened, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, EntityType: "owner", EntityID: owner.OwnerID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.RecoveryGateDetails{RestoredAt: request.RestoredAt.UTC().Format(time.RFC3339Nano)}, IdempotencyKey: correlation(r) + ":recovery-gate-opened"}); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "audit_failed", "Internal Server Error", "Unable to record recovery gate change", 0)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "recovery_gate_unavailable", "Internal Server Error", "Recovery gate is temporarily unavailable", 0)
		return
	}
	status, err := h.dataProtectionStatus(r)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "data_protection_unavailable", "Internal Server Error", "Data protection status is temporarily unavailable", 0)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (h *OwnerAuthHandler) dataProtectionStatus(r *http.Request) (ownerapi.DataProtectionStatus, error) {
	var gate string
	var lastCleanupAt, restoredAt *time.Time
	var cycle *string
	var pending int
	err := h.pool.QueryRow(r.Context(), `SELECT state,last_cleanup_at,last_cleanup_cycle,restored_at FROM tsw_recovery_gate WHERE id=true`).Scan(&gate, &lastCleanupAt, &cycle, &restoredAt)
	if err != nil {
		return ownerapi.DataProtectionStatus{}, err
	}
	if err := h.pool.QueryRow(r.Context(), `SELECT count(*) FROM tsw_batch_memberships WHERE state='removed' AND retention_due_at<=now()`).Scan(&pending); err != nil {
		return ownerapi.DataProtectionStatus{}, err
	}
	result := ownerapi.DataProtectionStatus{RecoveryGate: ownerapi.DataProtectionStatusRecoveryGate(gate), RetentionReady: pending == 0 && gate == "open", PendingRelationships: pending, BackupRetentionDays: 7}
	if lastCleanupAt != nil {
		result.LastCleanupAt = lastCleanupAt
	}
	if cycle != nil {
		result.LastCleanupCycle = cycle
	}
	_ = restoredAt
	return result, nil
}

func auditPage(page *ownerapi.Page, pageSize *ownerapi.PageSize) (int, int) {
	p, size := 1, 20
	if page != nil && int(*page) > 0 {
		p = int(*page)
	}
	if pageSize != nil && int(*pageSize) > 0 && int(*pageSize) <= 100 {
		size = int(*pageSize)
	}
	return p, size
}

func auditFilterFromList(params ownerapi.ListAuditEventsParams) (auditFilter, bool) {
	filter := auditFilter{From: params.From, To: params.To, EventType: auditStringValue(params.EventType), CorrelationID: auditStringValue(params.CorrelationId)}
	if params.Actor != nil {
		filter.Actor = string(*params.Actor)
	}
	if params.Outcome != nil {
		filter.Outcome = string(*params.Outcome)
	}
	filter.WorkspaceID, filter.BatchID, filter.MembershipID, filter.OrderID = uuidParam(params.WorkspaceId), uuidParam(params.BatchId), uuidParam(params.MembershipId), uuidParam(params.OrderId)
	return filter, validAuditFilter(filter)
}

func auditFilterFromExport(params ownerapi.ExportAuditEventsParams) (auditFilter, bool) {
	filter := auditFilter{From: params.From, To: params.To, EventType: auditStringValue(params.EventType), CorrelationID: auditStringValue(params.CorrelationId)}
	if params.Actor != nil {
		filter.Actor = string(*params.Actor)
	}
	if params.Outcome != nil {
		filter.Outcome = string(*params.Outcome)
	}
	filter.WorkspaceID, filter.BatchID, filter.MembershipID, filter.OrderID = uuidParam(params.WorkspaceId), uuidParam(params.BatchId), uuidParam(params.MembershipId), uuidParam(params.OrderId)
	return filter, validAuditFilter(filter)
}

func validAuditFilter(filter auditFilter) bool {
	return (filter.From == nil || filter.To == nil || !filter.From.After(*filter.To)) &&
		(filter.Actor == "" || filter.Actor == "owner" || filter.Actor == "system" || filter.Actor == "anonymous") &&
		(filter.Outcome == "" || filter.Outcome == "succeeded" || filter.Outcome == "failed" || filter.Outcome == "denied") &&
		(filter.EventType == "" || audit.IsRegisteredEventType(filter.EventType)) && len(filter.CorrelationID) <= 128
}

func uuidParam(value *uuid.UUID) *uuid.UUID { return value }
func auditStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (h *OwnerAuthHandler) queryAuditRecords(r *http.Request, filter auditFilter, limit, offset int) ([]ownerapi.AuditEvent, int, error) {
	where := []string{"event.expires_at>now()"}
	args := make([]any, 0, 12)
	add := func(sql string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(sql, len(args)))
	}
	if filter.From != nil {
		add("event.occurred_at >= $%d", *filter.From)
	}
	if filter.To != nil {
		add("event.occurred_at < $%d", *filter.To)
	}
	if filter.Actor != "" {
		add("event.actor_type = $%d", filter.Actor)
	}
	if filter.EventType != "" {
		add("event.event_type = $%d", filter.EventType)
	}
	if filter.Outcome != "" {
		add("event.outcome = $%d", filter.Outcome)
	}
	if filter.CorrelationID != "" {
		add("event.correlation_id = $%d", filter.CorrelationID)
	}
	if filter.WorkspaceID != nil {
		idx := len(args) + 1
		args = append(args, *filter.WorkspaceID)
		where = append(where, fmt.Sprintf("(event.retention_scope_type='workspace' AND event.retention_scope_id=$%d::uuid OR event.entity_id IN (SELECT operation.id FROM tsw_operations operation WHERE operation.workspace_id=$%d::uuid UNION SELECT target.id FROM tsw_operation_targets target JOIN tsw_operations operation ON operation.id=target.operation_id WHERE operation.workspace_id=$%d::uuid))", idx, idx, idx))
	}
	if filter.BatchID != nil {
		idx := len(args) + 1
		args = append(args, *filter.BatchID)
		where = append(where, fmt.Sprintf("(event.entity_id=$%d::uuid OR event.entity_id IN (SELECT operation.id FROM tsw_operations operation WHERE operation.batch_id=$%d::uuid UNION SELECT target.id FROM tsw_operation_targets target JOIN tsw_operations operation ON operation.id=target.operation_id WHERE operation.batch_id=$%d::uuid UNION SELECT membership.id FROM tsw_batch_memberships membership WHERE membership.batch_id=$%d::uuid))", idx, idx, idx, idx))
	}
	if filter.MembershipID != nil {
		idx := len(args) + 1
		args = append(args, *filter.MembershipID)
		where = append(where, fmt.Sprintf("(event.entity_id=$%d::uuid OR event.retention_scope_id=$%d::uuid OR event.entity_id IN (SELECT asset.id FROM tsw_oauth_assets asset WHERE asset.membership_id=$%d::uuid UNION SELECT card.id FROM tsw_cards card WHERE card.membership_id=$%d::uuid UNION SELECT ord.id FROM tsw_orders ord WHERE ord.membership_id=$%d::uuid))", idx, idx, idx, idx, idx))
	}
	if filter.OrderID != nil {
		idx := len(args) + 1
		args = append(args, *filter.OrderID)
		where = append(where, fmt.Sprintf("(event.entity_id=$%d::uuid OR event.retention_scope_id=$%d::uuid OR event.entity_id IN (SELECT token.id FROM tsw_public_tokens token WHERE token.order_id=$%d::uuid))", idx, idx, idx))
	}
	base := ` FROM tsw_audit_events event WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := h.pool.QueryRow(r.Context(), `SELECT count(*)`+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := append(append([]any(nil), args...), limit, offset)
	rows, err := h.pool.Query(r.Context(), `SELECT event.occurred_at,event.actor_type,event.event_type,event.outcome,event.entity_type,event.correlation_id,event.details`+base+` ORDER BY event.occurred_at DESC,event.id DESC LIMIT $`+strconv.Itoa(len(args)+1)+` OFFSET $`+strconv.Itoa(len(args)+2), queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]ownerapi.AuditEvent, 0)
	for rows.Next() {
		var record auditRecord
		var raw []byte
		if err := rows.Scan(&record.OccurredAt, &record.Actor, &record.EventType, &record.Outcome, &record.EntityType, &record.Correlation, &raw); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal(raw, &record.Details); err != nil {
			return nil, 0, err
		}
		items = append(items, ownerapi.AuditEvent{OccurredAt: record.OccurredAt, Actor: ownerapi.AuditEventActor(record.Actor), EventType: record.EventType, Outcome: ownerapi.AuditEventOutcome(record.Outcome), EntityType: record.EntityType, CorrelationId: record.Correlation, Details: record.Details})
	}
	return items, total, rows.Err()
}
