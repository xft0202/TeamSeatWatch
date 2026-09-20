package runtime

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
)

var errInvalidBatchTargets = errors.New("batch targets are invalid")

const batchProjectionSQL = `batch.id,batch.binding_id,binding.workspace_id,workspace.display_name,
	account.display_name,batch.sequence_no,batch.status,batch.planned_at,
	batch.service_started_at,batch.service_ended_at,batch.blocking_reason,
	(SELECT count(*)::int FROM tsw_batch_targets target WHERE target.batch_id=batch.id),
	batch.version,batch.created_at,batch.updated_at`

func scanBatch(scanner interface{ Scan(...any) error }) (ownerapi.Batch, error) {
	var item ownerapi.Batch
	err := scanner.Scan(
		&item.Id, &item.BindingId, &item.WorkspaceId, &item.WorkspaceName,
		&item.MotherAccountName, &item.SequenceNo, &item.Status, &item.PlannedAt,
		&item.ServiceStartedAt, &item.ServiceEndedAt, &item.BlockingReason,
		&item.TargetCount, &item.Version, &item.CreatedAt, &item.UpdatedAt,
	)
	return item, err
}

func (h *OwnerAuthHandler) listBatches(w http.ResponseWriter, r *http.Request, params ownerapi.ListBatchesParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(params.Page, params.PageSize)
	if !ok {
		writeProblem(w, r, 400, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	rows, err := h.pool.Query(r.Context(), `SELECT `+batchProjectionSQL+`,count(*) OVER()
		FROM tsw_batches batch JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		JOIN tsw_mother_accounts account ON account.id=binding.mother_account_id
		WHERE batch.binding_id=$3 AND binding.ended_at IS NULL
		ORDER BY batch.planned_at DESC,batch.sequence_no DESC LIMIT $1 OFFSET $2`, size, (page-1)*size, params.BindingId)
	if err != nil {
		h.batchFailure(w, r)
		return
	}
	defer rows.Close()
	response := ownerapi.BatchList{Items: []ownerapi.Batch{}, Page: page, PageSize: size}
	for rows.Next() {
		var total int64
		item, err := scanBatch(rowWithTotal{Rows: rows, total: &total})
		if err != nil {
			h.batchFailure(w, r)
			return
		}
		response.Total = total
		response.Items = append(response.Items, item)
	}
	if rows.Err() != nil {
		h.batchFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *OwnerAuthHandler) createBatch(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateBatchJSONRequestBody
	if !decodeJSON(w, r, &request) || request.PlannedAt.IsZero() || !validUUIDList(request.TargetAccountIds, 1000) {
		h.rejectOwnerMutation(w, r, owner, "batch.create", "invalid_request", 422, "invalid_batch", "Invalid Batch", "Batch fields are invalid")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.batchFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())
	var workspaceID string
	if err = tx.QueryRow(r.Context(), `SELECT workspace_id FROM tsw_mother_workspace_bindings WHERE id=$1 AND status='active' AND ended_at IS NULL FOR UPDATE`, request.BindingId).Scan(&workspaceID); errors.Is(err, pgx.ErrNoRows) {
		h.rejectOwnerMutation(w, r, owner, "batch.create", "invalid_request", 422, "invalid_binding", "Invalid Relationship", "A current administrator account relationship is required")
		return
	} else if err != nil {
		h.batchFailure(w, r)
		return
	}
	var batchID string
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_batches (binding_id,sequence_no,status,planned_at)
		SELECT $1,COALESCE(max(sequence_no),0)+1,'planned',$2 FROM tsw_batches WHERE binding_id=$1
		RETURNING id`, request.BindingId, request.PlannedAt).Scan(&batchID)
	if err == nil {
		err = insertBatchTargets(r, tx, batchID, request.TargetAccountIds)
	}
	var item ownerapi.Batch
	if err == nil {
		item, err = batchByIDTx(r, tx, batchID)
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.BatchCreated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: workspaceID, EntityType: "batch", EntityID: batchID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.BatchDetails{Result: "created"}, IdempotencyKey: batchID + ":created"})
	}
	if err != nil {
		h.batchConflict(w, r, owner, "batch.create", err)
		return
	}
	if tx.Commit(r.Context()) != nil {
		h.batchFailure(w, r)
		return
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusCreated, item)
}

func validUUIDList(values []uuid.UUID, maximum int) bool {
	if len(values) == 0 || len(values) > maximum {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, value := range values {
		if value == uuid.Nil {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func insertBatchTargets(r *http.Request, tx pgx.Tx, batchID string, targetIDs []uuid.UUID) error {
	result, err := tx.Exec(r.Context(), `INSERT INTO tsw_batch_targets (batch_id,target_account_id,ordinal)
		SELECT $1,target.id,selected.ordinality::int FROM unnest($2::uuid[]) WITH ORDINALITY selected(id,ordinality)
		JOIN tsw_target_accounts target ON target.id=selected.id AND target.status='active'`, batchID, targetIDs)
	if err != nil {
		return err
	}
	if result.RowsAffected() != int64(len(targetIDs)) {
		return errInvalidBatchTargets
	}
	return nil
}

func batchByIDTx(r *http.Request, tx pgx.Tx, id string) (ownerapi.Batch, error) {
	return scanBatch(tx.QueryRow(r.Context(), `SELECT `+batchProjectionSQL+`
		FROM tsw_batches batch JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		JOIN tsw_mother_accounts account ON account.id=binding.mother_account_id WHERE batch.id=$1`, id))
}

func (h *OwnerAuthHandler) batchByID(r *http.Request, id string) (ownerapi.Batch, error) {
	return scanBatch(h.pool.QueryRow(r.Context(), `SELECT `+batchProjectionSQL+`
		FROM tsw_batches batch JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		JOIN tsw_mother_accounts account ON account.id=binding.mother_account_id WHERE batch.id=$1`, id))
}

func (h *OwnerAuthHandler) getBatch(w http.ResponseWriter, r *http.Request, params ownerapi.GetBatchParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	detail, err := h.batchDetail(r, r.PathValue("batchId"), params.TargetPage, params.TargetPageSize)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "batch_not_found", "Not Found", "Batch was not found", 0)
		return
	}
	if err != nil {
		h.batchFailure(w, r)
		return
	}
	setETag(w, detail.Batch.Version)
	writeJSON(w, http.StatusOK, detail)
}

func (h *OwnerAuthHandler) batchDetail(r *http.Request, batchID string, pageParam *ownerapi.TargetPage, sizeParam *ownerapi.TargetPageSize) (ownerapi.BatchDetail, error) {
	page, size := 1, 20
	if pageParam != nil {
		page = int(*pageParam)
	}
	if sizeParam != nil {
		size = int(*sizeParam)
	}
	if page < 1 || size < 1 || size > 100 {
		return ownerapi.BatchDetail{}, errors.New("invalid pagination")
	}
	batch, err := h.batchByID(r, batchID)
	if err != nil {
		return ownerapi.BatchDetail{}, err
	}
	detail := ownerapi.BatchDetail{Batch: batch, Targets: []ownerapi.TargetAccount{}, TargetPage: page, TargetPageSize: size, TargetTotal: int64(batch.TargetCount)}
	rows, err := h.pool.Query(r.Context(), `SELECT `+targetProjectionSQL+`
		FROM tsw_batch_targets selected JOIN tsw_target_accounts target ON target.id=selected.target_account_id
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		WHERE selected.batch_id=$1 ORDER BY selected.ordinal LIMIT $2 OFFSET $3`, batchID, size, (page-1)*size)
	if err != nil {
		return ownerapi.BatchDetail{}, err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanTargetAccount(rows)
		if err != nil {
			return ownerapi.BatchDetail{}, err
		}
		detail.Targets = append(detail.Targets, item)
	}
	return detail, rows.Err()
}

func (h *OwnerAuthHandler) updateBatch(w http.ResponseWriter, r *http.Request, params ownerapi.UpdateBatchParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	version, ok := ifMatch(params.IfMatch)
	if !ok {
		h.rejectOwnerMutation(w, r, owner, "batch.update", "invalid_request", 428, "if_match_required", "Precondition Required", "If-Match is required")
		return
	}
	var request ownerapi.UpdateBatchJSONRequestBody
	if !decodeJSON(w, r, &request) || request.PlannedAt.IsZero() || !validUUIDList(request.TargetAccountIds, 1000) {
		h.rejectOwnerMutation(w, r, owner, "batch.update", "invalid_request", 422, "invalid_batch", "Invalid Batch", "Batch fields are invalid")
		return
	}
	batchID := r.PathValue("batchId")
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.batchFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())
	var currentVersion int64
	var status, workspaceID string
	err = tx.QueryRow(r.Context(), `SELECT batch.version,batch.status,binding.workspace_id FROM tsw_batches batch JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id WHERE batch.id=$1 FOR UPDATE`, batchID).Scan(&currentVersion, &status, &workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		h.rejectOwnerMutation(w, r, owner, "batch.update", "batch_not_found", 404, "batch_not_found", "Not Found", "Batch was not found")
		return
	}
	if err != nil {
		h.batchFailure(w, r)
		return
	}
	if currentVersion != version {
		h.rejectOwnerMutation(w, r, owner, "batch.update", "version_mismatch", 412, "version_mismatch", "Precondition Failed", "The batch changed")
		return
	}
	if status != "draft" && status != "planned" {
		h.rejectOwnerMutation(w, r, owner, "batch.update", "conflict", 409, "batch_frozen", "Conflict", "The batch target list is already frozen")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE tsw_batches SET planned_at=$2,updated_at=now(),version=version+1 WHERE id=$1`, batchID, request.PlannedAt)
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM tsw_batch_targets WHERE batch_id=$1`, batchID)
	}
	if err == nil {
		err = insertBatchTargets(r, tx, batchID, request.TargetAccountIds)
	}
	var item ownerapi.Batch
	if err == nil {
		item, err = batchByIDTx(r, tx, batchID)
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.BatchUpdated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: workspaceID, EntityType: "batch", EntityID: batchID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.BatchDetails{Result: "updated"}, IdempotencyKey: batchID + ":updated:" + strconv.FormatInt(item.Version, 10)})
	}
	if err != nil {
		h.batchConflict(w, r, owner, "batch.update", err)
		return
	}
	if tx.Commit(r.Context()) != nil {
		h.batchFailure(w, r)
		return
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusOK, item)
}

func (h *OwnerAuthHandler) getBatchPreview(w http.ResponseWriter, r *http.Request, params ownerapi.GetBatchPreviewParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	detail, err := h.batchDetail(r, r.PathValue("batchId"), params.TargetPage, params.TargetPageSize)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "batch_not_found", "Not Found", "Batch was not found", 0)
		return
	}
	if err != nil {
		h.batchFailure(w, r)
		return
	}
	preview := ownerapi.BatchPreview{Batch: detail.Batch, Targets: detail.Targets, TargetPage: detail.TargetPage, TargetPageSize: detail.TargetPageSize, TargetTotal: detail.TargetTotal, Blockers: []ownerapi.PreviewBlocker{}, SnapshotCompleteness: "unknown"}
	var evidenceExpiry, evidenceObserved, snapshotObserved *time.Time
	var evidenceSource, snapshotSource *string
	err = h.pool.QueryRow(r.Context(), `SELECT projection.operational_state,projection.seat_limit,projection.member_count,projection.pending_invite_count,
		projection.evidence_expires_at,conclusion.observed_at,conclusion.source_endpoint,
		snapshot.observed_at,snapshot.source_endpoint,COALESCE(snapshot.completeness,'unknown')
		FROM tsw_workspace_projections projection
		LEFT JOIN tsw_workspace_observations conclusion ON conclusion.id=projection.conclusion_observation_id
		LEFT JOIN tsw_workspace_member_snapshots snapshot ON snapshot.id=projection.latest_snapshot_id
		WHERE projection.workspace_id=$1`, detail.Batch.WorkspaceId).Scan(&preview.OperationalState, &preview.SeatLimit, &preview.MemberCount, &preview.PendingInviteCount, &evidenceExpiry, &evidenceObserved, &evidenceSource, &snapshotObserved, &snapshotSource, &preview.SnapshotCompleteness)
	if err != nil {
		h.batchFailure(w, r)
		return
	}
	preview.EvidenceObservedAt, preview.EvidenceSource = evidenceObserved, evidenceSource
	preview.SnapshotObservedAt, preview.SnapshotSource = snapshotObserved, snapshotSource
	if preview.OperationalState != "operational" {
		addBlocker(&preview, "workspace_not_operational", "团队空间当前没有明确可运营证据")
	}
	if evidenceExpiry == nil || !evidenceExpiry.After(time.Now()) {
		addBlocker(&preview, "workspace_evidence_stale", "团队空间当前证据缺失或已过期")
	}
	if preview.SnapshotCompleteness != "complete" || snapshotObserved == nil {
		addBlocker(&preview, "member_snapshot_incomplete", "成员与待邀请快照不完整")
	}
	if preview.SeatLimit == nil || preview.MemberCount == nil || preview.PendingInviteCount == nil {
		addBlocker(&preview, "capacity_unknown", "席位、成员或待邀请容量无法解释")
	} else {
		available := *preview.SeatLimit - *preview.MemberCount - *preview.PendingInviteCount
		if available < 0 {
			available = 0
		}
		preview.AvailableSeats = &available
		if detail.Batch.TargetCount > available {
			addBlocker(&preview, "capacity_exceeded", "计划目标数超过当前可解释容量")
		}
	}
	var unavailable int
	if err := h.pool.QueryRow(r.Context(), `SELECT count(*) FROM tsw_batch_targets selected JOIN tsw_target_accounts target ON target.id=selected.target_account_id JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id WHERE selected.batch_id=$1 AND (target.status<>'active' OR credentials.latest_probe_status IS DISTINCT FROM 'available')`, detail.Batch.Id).Scan(&unavailable); err != nil {
		h.batchFailure(w, r)
		return
	}
	if unavailable > 0 {
		addBlocker(&preview, "target_probe_unavailable", "部分目标账号没有当前可用探测结论")
	}
	var activeOther bool
	if err := h.pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tsw_batches WHERE binding_id=$1 AND id<>$2 AND status IN ('joining','serving','removing'))`, detail.Batch.BindingId, detail.Batch.Id).Scan(&activeOther); err != nil {
		h.batchFailure(w, r)
		return
	}
	if activeOther {
		addBlocker(&preview, "binding_has_active_batch", "当前管理员账号—团队空间关系已有服务中的批次")
	}
	preview.CanProceed = len(preview.Blockers) == 0
	writeJSON(w, http.StatusOK, preview)
}

func addBlocker(preview *ownerapi.BatchPreview, code, message string) {
	preview.Blockers = append(preview.Blockers, ownerapi.PreviewBlocker{Code: code, Message: message})
}

func (h *OwnerAuthHandler) batchConflict(w http.ResponseWriter, r *http.Request, owner ownerContext, operation string, err error) {
	if errors.Is(err, errInvalidBatchTargets) {
		h.rejectOwnerMutation(w, r, owner, operation, "invalid_request", 422, "invalid_batch_targets", "Invalid Batch", "Every target must exist and be active")
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			h.rejectOwnerMutation(w, r, owner, operation, "conflict", 409, "batch_conflict", "Conflict", "The batch conflicts with an existing plan")
			return
		case "23503", "23514":
			h.rejectOwnerMutation(w, r, owner, operation, "invalid_request", 422, "invalid_batch", "Invalid Batch", "Batch fields are invalid")
			return
		}
	}
	h.batchFailure(w, r)
}

func (h *OwnerAuthHandler) batchFailure(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, 500, "batch_planning_unavailable", "Internal Server Error", "Batch planning data is temporarily unavailable", 0)
}
