package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
)

func (h *OwnerAuthHandler) getBatchJoinPreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	preview, err := h.joinPreview(r, r.PathValue("batchId"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "join_target_not_found", "Not Found", "The batch target was not found", 0)
		return
	}
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (h *OwnerAuthHandler) joinPreview(r *http.Request, batchID string) (ownerapi.JoinPreview, error) {
	batch, err := h.batchByID(r, batchID)
	if err != nil {
		return ownerapi.JoinPreview{}, err
	}
	preview := ownerapi.JoinPreview{Batch: batch, Blockers: []ownerapi.PreviewBlocker{}, SnapshotCompleteness: "unknown"}
	var evidenceExpiry *time.Time
	err = h.pool.QueryRow(r.Context(), `SELECT projection.operational_state,projection.seat_limit,projection.member_count,projection.pending_invite_count,
		projection.evidence_expires_at,conclusion.observed_at,conclusion.source_endpoint,
		snapshot.observed_at,snapshot.source_endpoint,COALESCE(snapshot.completeness,'unknown')
		FROM tsw_workspace_projections projection
		LEFT JOIN tsw_workspace_observations conclusion ON conclusion.id=projection.conclusion_observation_id
		LEFT JOIN tsw_workspace_member_snapshots snapshot ON snapshot.id=projection.latest_snapshot_id
		WHERE projection.workspace_id=$1`, batch.WorkspaceId).Scan(
		&preview.OperationalState, &preview.SeatLimit, &preview.MemberCount, &preview.PendingInviteCount,
		&evidenceExpiry, &preview.EvidenceObservedAt, &preview.EvidenceSource,
		&preview.SnapshotObservedAt, &preview.SnapshotSource, &preview.SnapshotCompleteness)
	if err != nil {
		return ownerapi.JoinPreview{}, err
	}
	if batch.Status != ownerapi.BatchStatusPlanned {
		addJoinBlocker(&preview, "batch_not_planned", "本批已冻结或正在处理")
	}
	if preview.OperationalState != "operational" {
		addJoinBlocker(&preview, "workspace_not_operational", "团队空间当前没有明确可运营证据")
	}
	if evidenceExpiry == nil || !evidenceExpiry.After(time.Now()) {
		addJoinBlocker(&preview, "workspace_evidence_stale", "团队空间当前证据缺失或已过期")
	}
	if preview.SnapshotCompleteness != "complete" || preview.SnapshotObservedAt == nil {
		addJoinBlocker(&preview, "member_snapshot_incomplete", "成员事实不完整；请先读取最新事实")
	}
	if preview.SeatLimit == nil || preview.MemberCount == nil || preview.PendingInviteCount == nil {
		addJoinBlocker(&preview, "capacity_unknown", "当前席位容量无法解释")
	} else {
		available := *preview.SeatLimit - *preview.MemberCount - *preview.PendingInviteCount
		if available < 0 {
			available = 0
		}
		preview.AvailableSeats = &available
		if available < 1 {
			addJoinBlocker(&preview, "capacity_exhausted", "当前没有可解释的可用席位")
		}
	}
	var targetCount int
	if err = h.pool.QueryRow(r.Context(), `SELECT count(*) FROM tsw_batch_targets WHERE batch_id=$1`, batchID).Scan(&targetCount); err != nil {
		return ownerapi.JoinPreview{}, err
	}
	if targetCount == 0 {
		addJoinBlocker(&preview, "target_probe_unavailable", "本批没有目标账号")
	}
	if preview.AvailableSeats != nil && *preview.AvailableSeats < targetCount {
		addJoinBlocker(&preview, "capacity_exhausted", "当前可解释的可用席位不足以容纳整批目标")
	}
	preview.CanProceed = len(preview.Blockers) == 0
	return preview, nil
}

func addJoinBlocker(preview *ownerapi.JoinPreview, code, message string) {
	preview.Blockers = append(preview.Blockers, ownerapi.PreviewBlocker{Code: code, Message: message})
}

func (h *OwnerAuthHandler) createJoinOperation(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateJoinOperationJSONRequestBody
	if !decodeJSON(w, r, &request) || !bool(request.Confirm) {
		h.rejectOwnerMutation(w, r, owner, "join.create", "join_confirmation_required", http.StatusUnprocessableEntity, "join_confirmation_required", "Confirmation Required", "Explicit Owner confirmation is required")
		return
	}
	batchID := r.PathValue("batchId")
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())

	var workspaceID, batchStatus, operationalState, snapshotCompleteness string
	var seatLimit, memberCount, pendingInviteCount *int
	var evidenceExpiry *time.Time
	var conclusionID, snapshotID *string
	err = tx.QueryRow(r.Context(), `SELECT binding.workspace_id,batch.status,projection.operational_state,projection.evidence_expires_at,
		projection.seat_limit,projection.member_count,projection.pending_invite_count,
		projection.conclusion_observation_id::text,projection.latest_snapshot_id::text,COALESCE(snapshot.completeness,'unknown')
		FROM tsw_batches batch
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id AND binding.ended_at IS NULL
		JOIN tsw_workspace_projections projection ON projection.workspace_id=binding.workspace_id
		LEFT JOIN tsw_workspace_member_snapshots snapshot ON snapshot.id=projection.latest_snapshot_id
		WHERE batch.id=$1 FOR UPDATE OF batch`, batchID).Scan(&workspaceID, &batchStatus, &operationalState, &evidenceExpiry, &seatLimit, &memberCount, &pendingInviteCount, &conclusionID, &snapshotID, &snapshotCompleteness)
	if errors.Is(err, pgx.ErrNoRows) {
		h.rejectOwnerMutation(w, r, owner, "join.create", "join_batch_not_found", http.StatusUnprocessableEntity, "join_batch_not_found", "Invalid Join Batch", "The batch was not found")
		return
	}
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}

	rows, err := tx.Query(r.Context(), `SELECT selected.target_account_id::text,COALESCE(credentials.latest_probe_status,'')
		FROM tsw_batch_targets selected
		JOIN tsw_target_accounts target ON target.id=selected.target_account_id AND target.status='active'
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		WHERE selected.batch_id=$1 ORDER BY selected.target_account_id FOR UPDATE OF selected,target,credentials`, batchID)
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	var targetIDs []string
	for rows.Next() {
		var targetID, probeStatus string
		if err = rows.Scan(&targetID, &probeStatus); err != nil {
			rows.Close()
			h.joinFailure(w, r, err)
			return
		}
		targetIDs = append(targetIDs, targetID)
		_ = probeStatus
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	sort.Strings(targetIDs)
	requestHash := sha256.Sum256([]byte("teamseatwatch:join:v2\x00" + batchID + "\x00" + strings.Join(targetIDs, "\x00")))

	var existingID string
	var existingHash []byte
	err = tx.QueryRow(r.Context(), `SELECT id,request_hash FROM tsw_operations WHERE owner_id=$1 AND operation_type='join' AND idempotency_key=$2 FOR UPDATE`, owner.OwnerID, request.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if !bytes.Equal(existingHash, requestHash[:]) {
			h.rejectOwnerMutation(w, r, owner, "join.create", "idempotency_conflict", http.StatusConflict, "idempotency_conflict", "Conflict", "The idempotency key belongs to a different frozen target")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			h.joinFailure(w, r, err)
			return
		}
		item, getErr := h.joinOperationByID(r, existingID)
		if getErr != nil {
			h.joinFailure(w, r, getErr)
			return
		}
		writeJSON(w, http.StatusAccepted, item)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		h.joinFailure(w, r, err)
		return
	}

	availableSeats := -1
	if seatLimit != nil && memberCount != nil && pendingInviteCount != nil {
		availableSeats = *seatLimit - *memberCount - *pendingInviteCount
	}
	if len(targetIDs) == 0 || batchStatus != "planned" || operationalState != "operational" || evidenceExpiry == nil || !evidenceExpiry.After(time.Now()) || snapshotCompleteness != "complete" || availableSeats < len(targetIDs) {
		_ = tx.Rollback(r.Context())
		if h.writeExistingJoin(w, r, owner, request.IdempotencyKey, requestHash[:]) {
			return
		}
		h.rejectOwnerMutation(w, r, owner, "join.create", "join_not_ready", http.StatusConflict, "join_not_ready", "Join Not Ready", "Current Workspace, member, capacity, or target evidence is not sufficient")
		return
	}
	targetIDsJSON, err := json.Marshal(targetIDs)
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	var operationID string
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_operations(owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id)
		VALUES ($1,$2,$3,'join',$4,$5,jsonb_build_object('workspace_id',$7::text,'batch_id',$8::text,'target_account_ids',$9::jsonb,'conclusion_observation_id',$10::text,'member_snapshot_id',$11::text),$6)
		RETURNING id`, owner.OwnerID, workspaceID, batchID, request.IdempotencyKey, requestHash[:], correlation(r), workspaceID, batchID, string(targetIDsJSON), conclusionID, snapshotID).Scan(&operationID)
	if err == nil {
		for ordinal, targetID := range targetIDs {
			var operationTargetID string
			err = tx.QueryRow(r.Context(), `INSERT INTO tsw_operation_targets(operation_id,target_account_id,ordinal) VALUES ($1,$2,$3) RETURNING id`, operationID, targetID, ordinal+1).Scan(&operationTargetID)
			if err != nil {
				break
			}
			_, err = tx.Exec(r.Context(), `INSERT INTO tsw_tasks(operation_target_id,workspace_id,target_account_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
				VALUES ($1,$2,$3,'join',$4,jsonb_build_object('operation_target_id',$6::text,'workspace_id',$7::text,'target_account_id',$8::text),$5,3)`, operationTargetID, workspaceID, targetID, "join:"+operationTargetID, correlation(r), operationTargetID, workspaceID, targetID)
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tsw_batches SET status='joining',blocking_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1`, batchID)
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.JoinOperationAuthorized, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: workspaceID, EntityType: "operation", EntityID: operationID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.OperationDetails{Operation: "join", Result: "authorized"}, IdempotencyKey: operationID + ":authorized"})
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			_ = tx.Rollback(r.Context())
			// A concurrent winner may report either the idempotency or active-
			// operation unique constraint. Always read the committed winner and
			// compare its request hash before deciding retry versus conflict.
			if h.writeExistingJoin(w, r, owner, request.IdempotencyKey, requestHash[:]) {
				return
			}
			h.rejectOwnerMutation(w, r, owner, "join.create", "conflict", http.StatusConflict, "join_conflict", "Conflict", "This Workspace already has an active member operation")
			return
		}
		h.joinFailure(w, r, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.joinFailure(w, r, err)
		return
	}
	item, err := h.joinOperationByID(r, operationID)
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (h *OwnerAuthHandler) writeExistingJoin(w http.ResponseWriter, r *http.Request, owner ownerContext, idempotencyKey string, requestHash []byte) bool {
	var operationID string
	var storedHash []byte
	err := h.pool.QueryRow(r.Context(), `SELECT id,request_hash FROM tsw_operations WHERE owner_id=$1 AND operation_type='join' AND idempotency_key=$2`, owner.OwnerID, idempotencyKey).Scan(&operationID, &storedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		h.joinFailure(w, r, err)
		return true
	}
	if !bytes.Equal(storedHash, requestHash) {
		h.rejectOwnerMutation(w, r, owner, "join.create", "idempotency_conflict", http.StatusConflict, "idempotency_conflict", "Conflict", "The idempotency key belongs to a different frozen target")
		return true
	}
	item, err := h.joinOperationByID(r, operationID)
	if err != nil {
		h.joinFailure(w, r, err)
		return true
	}
	writeJSON(w, http.StatusAccepted, item)
	return true
}

func (h *OwnerAuthHandler) createJoinReconciliation(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateJoinReconciliationJSONRequestBody
	if !decodeJSON(w, r, &request) || !validLength(request.IdempotencyKey, 8, 64) {
		h.rejectOwnerMutation(w, r, owner, "join.reconcile", "invalid_request", http.StatusUnprocessableEntity, "invalid_idempotency_key", "Invalid Request", "A stable idempotency key is required")
		return
	}
	_, _, err := h.workspaceTasks.EnqueueJoinReconciliation(r.Context(), r.PathValue("batchId"), request.IdempotencyKey, correlation(r))
	if errors.Is(err, pgx.ErrNoRows) {
		h.rejectOwnerMutation(w, r, owner, "join.reconcile", "conflict", http.StatusConflict, "join_reconciliation_not_available", "Conflict", "This Join operation does not currently require reconciliation")
		return
	}
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	item, err := h.joinOperationByBatch(r, r.PathValue("batchId"), 1, 100)
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (h *OwnerAuthHandler) getJoinOperation(w http.ResponseWriter, r *http.Request, params ownerapi.GetJoinOperationParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(params.TargetPage, params.TargetPageSize)
	if !ok {
		writeProblem(w, r, http.StatusBadRequest, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}

	item, err := h.joinOperationByBatch(r, r.PathValue("batchId"), page, size)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "join_operation_not_found", "Not Found", "The join operation was not found", 0)
		return
	}
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *OwnerAuthHandler) listJoinOperationsNeedingAttention(w http.ResponseWriter, r *http.Request, params ownerapi.ListJoinOperationsNeedingAttentionParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(params.Page, params.PageSize)
	if !ok {
		writeProblem(w, r, http.StatusBadRequest, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	rows, err := h.pool.Query(r.Context(), joinOperationSelect+`,count(*) OVER() FROM tsw_operations operation WHERE operation.operation_type=$1 AND (operation.status='blocked' OR EXISTS (SELECT 1 FROM tsw_operation_targets attention_target WHERE attention_target.operation_id=operation.id AND attention_target.status IN ('failed','blocked','unknown'))) ORDER BY operation.updated_at DESC LIMIT $4 OFFSET $5`, "join", 100, 0, size, (page-1)*size)
	if err != nil {
		h.joinFailure(w, r, err)
		return
	}
	defer rows.Close()
	response := ownerapi.JoinOperationList{Items: []ownerapi.JoinOperation{}, Page: page, PageSize: size}
	for rows.Next() {
		var total int64
		item, scanErr := scanJoinOperation(rowWithTotal{Rows: rows, total: &total}, 1, 100)
		if scanErr != nil {
			h.joinFailure(w, r, scanErr)
			return
		}
		response.Total = total
		response.Items = append(response.Items, item)
	}
	if err := rows.Err(); err != nil {
		h.joinFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

const joinOperationSelect = `SELECT operation.id,operation.batch_id,operation.workspace_id,operation.status,operation.authorized_at,operation.completed_at,operation.correlation_id,
	COALESCE((SELECT jsonb_agg(jsonb_build_object('id',page.id,'targetAccountId',COALESCE(page.target_account_id,page.membership_target_account_id),'status',page.status,'preflightStatus',page.preflight_status,'preflightAt',page.preflight_at,'outcomeCode',page.outcome_code,'diagnosticCode',page.diagnostic_code,'lastAttemptAt',page.last_attempt_at,'completedAt',page.completed_at) ORDER BY page.ordinal) FROM (SELECT target_result.*,membership.target_account_id AS membership_target_account_id FROM tsw_operation_targets target_result LEFT JOIN tsw_batch_memberships membership ON membership.id=target_result.membership_id WHERE target_result.operation_id=operation.id ORDER BY target_result.ordinal LIMIT $2 OFFSET $3) page),'[]'::jsonb),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id AND target_result.status='succeeded'),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id AND target_result.status='failed'),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id AND target_result.status IN ('blocked','unknown')),
	(SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id AND target_result.status NOT IN ('succeeded','failed','blocked','unknown'))`

func scanJoinOperation(scanner interface{ Scan(...any) error }, page, size int) (ownerapi.JoinOperation, error) {
	var item ownerapi.JoinOperation
	var targets []byte
	err := scanner.Scan(&item.Id, &item.BatchId, &item.WorkspaceId, &item.Status, &item.AuthorizedAt, &item.CompletedAt, &item.CorrelationId, &targets, &item.TargetTotal, &item.SucceededCount, &item.FailedCount, &item.BlockedCount, &item.PendingCount)
	if err != nil {
		return item, err
	}
	item.TargetPage, item.TargetPageSize = page, size
	return item, json.Unmarshal(targets, &item.Targets)
}

func (h *OwnerAuthHandler) joinOperationByID(r *http.Request, operationID string) (ownerapi.JoinOperation, error) {
	return scanJoinOperation(h.pool.QueryRow(r.Context(), joinOperationSelect+` FROM tsw_operations operation WHERE operation.id=$1`, operationID, 100, 0), 1, 100)
}

func (h *OwnerAuthHandler) joinOperationByBatch(r *http.Request, batchID string, page, size int) (ownerapi.JoinOperation, error) {
	return scanJoinOperation(h.pool.QueryRow(r.Context(), joinOperationSelect+` FROM tsw_operations operation WHERE operation.batch_id=$1 AND operation.operation_type='join' ORDER BY operation.created_at DESC LIMIT 1`, batchID, size, (page-1)*size), page, size)
}

// joinFailure 把底层错误记入服务端日志（带 request_id，可与 http_request 日志行对照），
// 对外只写固定的 5xx problem——不把数据库细节暴露给任何调用方。
func (h *OwnerAuthHandler) joinFailure(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("join_data_unavailable", "request_id", RequestIDFromContext(r.Context()), "error", err)
	writeProblem(w, r, http.StatusInternalServerError, "join_unavailable", "Internal Server Error", "Join data is temporarily unavailable", 0)
}
