package runtime

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

func (h *OwnerAuthHandler) getBatchJoinPreview(w http.ResponseWriter, r *http.Request, targetID string) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	preview, err := h.joinPreview(r, r.PathValue("batchId"), targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "join_target_not_found", "Not Found", "The batch target was not found", 0)
		return
	}
	if err != nil {
		h.joinFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (h *OwnerAuthHandler) joinPreview(r *http.Request, batchID, targetID string) (ownerapi.JoinPreview, error) {
	batch, err := h.batchByID(r, batchID)
	if err != nil {
		return ownerapi.JoinPreview{}, err
	}
	target, err := scanTargetAccount(h.pool.QueryRow(r.Context(), `SELECT `+targetProjectionSQL+`
		FROM tsw_batch_targets selected
		JOIN tsw_target_accounts target ON target.id=selected.target_account_id
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		WHERE selected.batch_id=$1 AND selected.target_account_id=$2`, batchID, targetID))
	if err != nil {
		return ownerapi.JoinPreview{}, err
	}
	preview := ownerapi.JoinPreview{Batch: batch, Target: target, Blockers: []ownerapi.PreviewBlocker{}, SnapshotCompleteness: "unknown"}
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
	if target.Status != ownerapi.TargetAccountStatusActive || target.LatestProbeStatus == nil || *target.LatestProbeStatus != ownerapi.TargetProbeClassificationAvailable {
		addJoinBlocker(&preview, "target_probe_unavailable", "目标账号最近探测不是可用；执行时仍会再次实时探测")
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
	batchID, targetID := r.PathValue("batchId"), request.TargetAccountId.String()
	requestHash := sha256.Sum256([]byte("teamseatwatch:join:v1\x00" + batchID + "\x00" + targetID))
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.joinFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())

	var existingID string
	var existingHash []byte
	err = tx.QueryRow(r.Context(), `SELECT id,request_hash FROM tsw_operations WHERE owner_id=$1 AND operation_type='join' AND idempotency_key=$2 FOR UPDATE`, owner.OwnerID, request.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if !bytes.Equal(existingHash, requestHash[:]) {
			h.rejectOwnerMutation(w, r, owner, "join.create", "idempotency_conflict", http.StatusConflict, "idempotency_conflict", "Conflict", "The idempotency key belongs to a different frozen target")
			return
		}
		if tx.Commit(r.Context()) != nil {
			h.joinFailure(w, r)
			return
		}
		item, getErr := h.joinOperationByID(r, existingID)
		if getErr != nil {
			h.joinFailure(w, r)
			return
		}
		writeJSON(w, http.StatusAccepted, item)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		h.joinFailure(w, r)
		return
	}

	var workspaceID, batchStatus, operationalState, snapshotCompleteness, probeStatus string
	var seatLimit, memberCount, pendingInviteCount *int
	var evidenceExpiry *time.Time
	var conclusionID, snapshotID *string
	err = tx.QueryRow(r.Context(), `SELECT binding.workspace_id,batch.status,projection.operational_state,projection.evidence_expires_at,
		projection.seat_limit,projection.member_count,projection.pending_invite_count,
		projection.conclusion_observation_id::text,projection.latest_snapshot_id::text,COALESCE(snapshot.completeness,'unknown'),COALESCE(credentials.latest_probe_status,'')
		FROM tsw_batches batch
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id AND binding.ended_at IS NULL
		JOIN tsw_workspace_projections projection ON projection.workspace_id=binding.workspace_id
		LEFT JOIN tsw_workspace_member_snapshots snapshot ON snapshot.id=projection.latest_snapshot_id
		JOIN tsw_batch_targets selected ON selected.batch_id=batch.id AND selected.target_account_id=$2
		JOIN tsw_target_accounts target ON target.id=selected.target_account_id AND target.status='active'
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		WHERE batch.id=$1 FOR UPDATE OF batch`, batchID, targetID).Scan(&workspaceID, &batchStatus, &operationalState, &evidenceExpiry, &seatLimit, &memberCount, &pendingInviteCount, &conclusionID, &snapshotID, &snapshotCompleteness, &probeStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		h.rejectOwnerMutation(w, r, owner, "join.create", "join_target_not_in_batch", http.StatusUnprocessableEntity, "join_target_not_in_batch", "Invalid Join Target", "The target is not part of this batch")
		return
	}
	if err != nil {
		h.joinFailure(w, r)
		return
	}
	availableSeats := -1
	if seatLimit != nil && memberCount != nil && pendingInviteCount != nil {
		availableSeats = *seatLimit - *memberCount - *pendingInviteCount
	}
	if batchStatus != "planned" || operationalState != "operational" || evidenceExpiry == nil || !evidenceExpiry.After(time.Now()) || snapshotCompleteness != "complete" || probeStatus != "available" || availableSeats < 1 {
		_ = tx.Rollback(r.Context())
		if h.writeExistingJoin(w, r, owner, request.IdempotencyKey, requestHash[:]) {
			return
		}
		h.rejectOwnerMutation(w, r, owner, "join.create", "join_not_ready", http.StatusConflict, "join_not_ready", "Join Not Ready", "Current Workspace, member, capacity, or target evidence is not sufficient")
		return
	}
	var operationID, operationTargetID string
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_operations(owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id)
		VALUES ($1,$2,$3,'join',$4,$5,jsonb_build_object('workspace_id',$10::text,'batch_id',$11::text,'target_account_id',$12::text,'conclusion_observation_id',$13::text,'member_snapshot_id',$14::text),$9)
		RETURNING id`, owner.OwnerID, workspaceID, batchID, request.IdempotencyKey, requestHash[:], targetID, conclusionID, snapshotID, correlation(r), workspaceID, batchID, targetID, conclusionID, snapshotID).Scan(&operationID)
	if err == nil {
		err = tx.QueryRow(r.Context(), `INSERT INTO tsw_operation_targets(operation_id,target_account_id,ordinal) VALUES ($1,$2,1) RETURNING id`, operationID, targetID).Scan(&operationTargetID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO tsw_tasks(operation_target_id,workspace_id,target_account_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
			VALUES ($1,$2,$3,'join',$4,jsonb_build_object('operation_target_id',$6::text,'workspace_id',$7::text,'target_account_id',$8::text),$5,3)`, operationTargetID, workspaceID, targetID, "join:"+operationID, correlation(r), operationTargetID, workspaceID, targetID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tsw_batches SET status='joining',blocking_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1`, batchID)
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.JoinOperationAuthorized, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: workspaceID, EntityType: "operation", EntityID: operationID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.OperationDetails{Operation: "join", Result: "authorized", TargetID: targetID}, IdempotencyKey: operationID + ":authorized"})
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
		h.joinFailure(w, r)
		return
	}
	if tx.Commit(r.Context()) != nil {
		h.joinFailure(w, r)
		return
	}
	item, err := h.joinOperationByID(r, operationID)
	if err != nil {
		h.joinFailure(w, r)
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
		h.joinFailure(w, r)
		return true
	}
	if !bytes.Equal(storedHash, requestHash) {
		h.rejectOwnerMutation(w, r, owner, "join.create", "idempotency_conflict", http.StatusConflict, "idempotency_conflict", "Conflict", "The idempotency key belongs to a different frozen target")
		return true
	}
	item, err := h.joinOperationByID(r, operationID)
	if err != nil {
		h.joinFailure(w, r)
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
		h.joinFailure(w, r)
		return
	}
	item, err := h.joinOperationByBatch(r, r.PathValue("batchId"))
	if err != nil {
		h.joinFailure(w, r)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (h *OwnerAuthHandler) getJoinOperation(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	item, err := h.joinOperationByBatch(r, r.PathValue("batchId"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "join_operation_not_found", "Not Found", "The join operation was not found", 0)
		return
	}
	if err != nil {
		h.joinFailure(w, r)
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
	rows, err := h.pool.Query(r.Context(), joinOperationSelect+`,count(*) OVER() FROM tsw_operations operation JOIN tsw_operation_targets target_result ON target_result.operation_id=operation.id LEFT JOIN tsw_batch_memberships membership ON membership.id=target_result.membership_id WHERE operation.operation_type='join' AND (operation.status='blocked' OR target_result.status IN ('failed','blocked','unknown')) ORDER BY operation.updated_at DESC LIMIT $1 OFFSET $2`, size, (page-1)*size)
	if err != nil {
		h.joinFailure(w, r)
		return
	}
	defer rows.Close()
	response := ownerapi.JoinOperationList{Items: []ownerapi.JoinOperation{}, Page: page, PageSize: size}
	for rows.Next() {
		var total int64
		item, scanErr := scanJoinOperation(rowWithTotal{Rows: rows, total: &total})
		if scanErr != nil {
			h.joinFailure(w, r)
			return
		}
		response.Total = total
		response.Items = append(response.Items, item)
	}
	if rows.Err() != nil {
		h.joinFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

const joinOperationSelect = `SELECT operation.id,operation.batch_id,operation.workspace_id,COALESCE(target_result.target_account_id,membership.target_account_id),operation.status,operation.authorized_at,operation.completed_at,operation.correlation_id,target_result.id,target_result.status,target_result.preflight_status,target_result.preflight_at,target_result.outcome_code,target_result.diagnostic_code,target_result.last_attempt_at,target_result.completed_at`

func scanJoinOperation(scanner interface{ Scan(...any) error }) (ownerapi.JoinOperation, error) {
	var item ownerapi.JoinOperation
	var outcomeCode, diagnosticCode *string
	err := scanner.Scan(&item.Id, &item.BatchId, &item.WorkspaceId, &item.TargetAccountId, &item.Status, &item.AuthorizedAt, &item.CompletedAt, &item.CorrelationId, &item.Target.Id, &item.Target.Status, &item.Target.PreflightStatus, &item.Target.PreflightAt, &outcomeCode, &diagnosticCode, &item.Target.LastAttemptAt, &item.Target.CompletedAt)
	if outcomeCode != nil {
		value := platform.NormalizeDiagnostic(*outcomeCode)
		item.Target.OutcomeCode = &value
	}
	if diagnosticCode != nil {
		value := platform.NormalizeDiagnostic(*diagnosticCode)
		item.Target.DiagnosticCode = &value
	}
	item.Target.TargetAccountId = item.TargetAccountId
	return item, err
}

func (h *OwnerAuthHandler) joinOperationByID(r *http.Request, operationID string) (ownerapi.JoinOperation, error) {
	return scanJoinOperation(h.pool.QueryRow(r.Context(), joinOperationSelect+` FROM tsw_operations operation JOIN tsw_operation_targets target_result ON target_result.operation_id=operation.id LEFT JOIN tsw_batch_memberships membership ON membership.id=target_result.membership_id WHERE operation.id=$1`, operationID))
}

func (h *OwnerAuthHandler) joinOperationByBatch(r *http.Request, batchID string) (ownerapi.JoinOperation, error) {
	return scanJoinOperation(h.pool.QueryRow(r.Context(), joinOperationSelect+` FROM tsw_operations operation JOIN tsw_operation_targets target_result ON target_result.operation_id=operation.id LEFT JOIN tsw_batch_memberships membership ON membership.id=target_result.membership_id WHERE operation.batch_id=$1 AND operation.operation_type='join' ORDER BY operation.created_at DESC LIMIT 1`, batchID))
}

func (h *OwnerAuthHandler) joinFailure(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, http.StatusInternalServerError, "join_unavailable", "Internal Server Error", "Join data is temporarily unavailable", 0)
}
