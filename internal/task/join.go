package task

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

type JoinTarget struct {
	OperationID                   string
	BatchID                       string
	WorkspaceID                   string
	TargetID                      string
	TargetIdentifier              string
	TargetPassword                string
	PlatformWorkspace             string
	PlatformRequestMayHaveReached bool
	PlatformRequestStage          string
	PlatformRequestStartedAt      *time.Time
}

func (s *Store) ClaimJoin(ctx context.Context, worker string, duration time.Duration, route AttemptRoute) (Task, error) {
	return s.claim(ctx, worker, duration, "join", route)
}

func (s *Store) ClaimJoinReconcile(ctx context.Context, worker string, duration time.Duration, route AttemptRoute) (Task, error) {
	return s.claim(ctx, worker, duration, "join_reconcile", route)
}

// RecoverExpiredJoin converts a possibly delivered expired Join into a new
// read-only reconciliation task before the generic claim path can replay it.
func (s *Store) RecoverExpiredJoin(ctx context.Context) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var item Task
	var operationID, batchID string
	err = tx.QueryRow(ctx, `SELECT task.id,task.workspace_id,task.target_account_id,task.operation_target_id,task.correlation_id,task.attempt_count,target_result.operation_id,operation.batch_id
		FROM tsw_tasks task
		JOIN tsw_operation_targets target_result ON target_result.id=task.operation_target_id
		JOIN tsw_operations operation ON operation.id=target_result.operation_id
		WHERE task.task_type='join' AND task.status='running' AND task.lease_expires_at<=now()
		ORDER BY task.lease_expires_at,task.created_at FOR UPDATE OF task,target_result SKIP LOCKED LIMIT 1`).Scan(
		&item.ID, &item.WorkspaceID, &item.TargetAccountID, &item.OperationTargetID, &item.CorrelationID, &item.AttemptNo, &operationID, &batchID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_tasks SET status='interrupted',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.ID); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status='unknown',outcome_code='platform_unknown',diagnostic_code='lease_lost',completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_operations SET workspace_mutation_lease_owner=NULL,workspace_mutation_lease_token=NULL,workspace_mutation_lease_expires_at=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND workspace_mutation_lease_owner=$2`, operationID, item.ID); err != nil {
		return false, err
	}
	if err = settleJoinAggregate(ctx, tx, operationID, batchID); err != nil {
		return false, err
	}
	var reconciliationID string
	err = tx.QueryRow(ctx, `INSERT INTO tsw_tasks(operation_target_id,workspace_id,target_account_id,parent_task_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		VALUES ($1,$2,$3,$4,'join_reconcile',$5,jsonb_build_object('operation_target_id',$7::text,'workspace_id',$8::text,'target_account_id',$9::text),$6,3)
		ON CONFLICT (task_type,dedupe_key) DO UPDATE SET updated_at=now() RETURNING id`, item.OperationTargetID, item.WorkspaceID, item.TargetAccountID, item.ID, "join-reconcile-recovery:"+item.ID, item.CorrelationID, item.OperationTargetID, item.WorkspaceID, item.TargetAccountID).Scan(&reconciliationID)
	if err != nil {
		return false, err
	}
	_, err = audit.Write(ctx, tx, audit.Event{Type: audit.JoinTargetUnknown, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "operation_target", EntityID: item.OperationTargetID, Outcome: audit.OutcomeFailed, CorrelationID: item.CorrelationID, Details: audit.JoinTargetDetails{Status: "unknown", Result: "platform_unknown", Stage: "crash_recovery", DiagnosticCode: "lease_lost"}, IdempotencyKey: item.ID + ":join.recovered"})
	if err != nil {
		return false, err
	}
	_, err = audit.Write(ctx, tx, audit.Event{Type: audit.JoinReconciliationQueued, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "task", EntityID: reconciliationID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.TaskDetails{AttemptNo: 1, Result: "queued", Stage: "crash_recovery"}, IdempotencyKey: reconciliationID + ":reconciliation.queued"})
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *Store) EnqueueJoinReconciliation(ctx context.Context, batchID, idempotencyKey, correlationID string) (Task, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Task{}, false, err
	}
	defer tx.Rollback(ctx)
	var operationTargetID, workspaceID, targetID string
	err = tx.QueryRow(ctx, `SELECT target_result.id,operation.workspace_id,COALESCE(target_result.target_account_id,membership.target_account_id)
		FROM tsw_operations operation
		JOIN tsw_operation_targets target_result ON target_result.operation_id=operation.id
		LEFT JOIN tsw_batch_memberships membership ON membership.id=target_result.membership_id
		WHERE operation.batch_id=$1 AND operation.operation_type='join' AND operation.status='blocked' AND target_result.status IN ('blocked','unknown')
		ORDER BY operation.created_at DESC LIMIT 1 FOR UPDATE OF operation,target_result`, batchID).Scan(&operationTargetID, &workspaceID, &targetID)
	if err != nil {
		return Task{}, false, err
	}
	dedupeKey := "join-reconcile:" + operationTargetID + ":" + idempotencyKey
	var item Task
	created := true
	err = tx.QueryRow(ctx, `INSERT INTO tsw_tasks(operation_target_id,workspace_id,target_account_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		VALUES ($1,$2,$3,'join_reconcile',$4,jsonb_build_object('operation_target_id',$6::text,'workspace_id',$7::text,'target_account_id',$8::text),$5,3)
		ON CONFLICT (task_type,dedupe_key) DO NOTHING
		RETURNING id,task_type,workspace_id,target_account_id,operation_target_id,dedupe_key,status,correlation_id,created_at,finished_at`, operationTargetID, workspaceID, targetID, dedupeKey, correlationID, operationTargetID, workspaceID, targetID).Scan(
		&item.ID, &item.TaskType, &item.WorkspaceID, &item.TargetAccountID, &item.OperationTargetID, &item.DedupeKey, &item.Status, &item.CorrelationID, &item.CreatedAt, &item.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		created = false
		err = tx.QueryRow(ctx, `SELECT id,task_type,workspace_id,target_account_id,operation_target_id,dedupe_key,status,correlation_id,created_at,finished_at FROM tsw_tasks WHERE task_type='join_reconcile' AND dedupe_key=$1`, dedupeKey).Scan(
			&item.ID, &item.TaskType, &item.WorkspaceID, &item.TargetAccountID, &item.OperationTargetID, &item.DedupeKey, &item.Status, &item.CorrelationID, &item.CreatedAt, &item.FinishedAt)
	}
	if err != nil {
		return Task{}, false, err
	}
	_, err = audit.Write(ctx, tx, audit.Event{Type: audit.JoinReconciliationQueued, Actor: audit.ActorSystem, RetentionScopeID: workspaceID, EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.TaskDetails{AttemptNo: 1, Result: "queued", Stage: "owner_refresh"}, IdempotencyKey: item.ID + ":owner-refresh"})
	if err != nil {
		return Task{}, false, err
	}
	return item, created, tx.Commit(ctx)
}

func (s *Store) JoinTarget(ctx context.Context, item Task) (JoinTarget, error) {
	var target JoinTarget
	var password []byte
	err := s.pool.QueryRow(ctx, `
		SELECT operation.id,batch.id,operation.workspace_id,task.target_account_id,
			target.identifier,credentials.password_secret,workspace.platform_workspace_id,
			operation_target.platform_request_may_have_reached,operation_target.platform_request_stage,operation_target.platform_request_started_at
		FROM tsw_tasks task
		JOIN tsw_operation_targets operation_target ON operation_target.id=task.operation_target_id
		JOIN tsw_operations operation ON operation.id=operation_target.operation_id
		JOIN tsw_batches batch ON batch.id=operation.batch_id
		JOIN tsw_target_accounts target ON target.id=task.target_account_id AND target.status='active'
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		JOIN tsw_workspaces workspace ON workspace.id=operation.workspace_id
		WHERE task.id=$1 AND task.task_type IN ('join','join_reconcile')`, item.ID).Scan(
		&target.OperationID, &target.BatchID, &target.WorkspaceID, &target.TargetID,
		&target.TargetIdentifier, &password, &target.PlatformWorkspace,
		&target.PlatformRequestMayHaveReached, &target.PlatformRequestStage, &target.PlatformRequestStartedAt)
	target.TargetPassword = string(password)
	clear(password)
	return target, err
}

func (s *Store) MarkJoinSideEffectStarted(ctx context.Context, item Task, stage string) error {
	if stage != "request_join" && stage != "accept_join" {
		return errors.New("invalid join side-effect stage")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockJoinTask(ctx, tx, item); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `UPDATE tsw_operations SET workspace_mutation_lease_owner=$2,workspace_mutation_lease_token=$3,workspace_mutation_lease_expires_at=now()+interval '10 minutes',updated_at=now(),version=version+1
		WHERE id=(SELECT operation_target.operation_id FROM tsw_operation_targets operation_target WHERE operation_target.id=$1)
		AND (workspace_mutation_lease_token IS NULL OR workspace_mutation_lease_expires_at<=now() OR workspace_mutation_lease_token=$3)`, item.OperationTargetID, item.ID, item.LeaseToken)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	result, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET platform_request_may_have_reached=true,platform_request_stage=$2,platform_request_started_at=COALESCE(platform_request_started_at,now()),status='running',last_attempt_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, stage)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return tx.Commit(ctx)
}

func (s *Store) RecordJoinPreflight(ctx context.Context, item Task, result platform.TargetProbeResult) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockJoinTask(ctx, tx, item); err != nil {
		return err
	}
	status := string(result.Status)
	if status == "" {
		status = string(platform.TargetUnknown)
	}
	diagnostic := platform.NormalizeDiagnostic(result.ErrorCode)
	_, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status='running',preflight_status=$2,preflight_http_status=NULLIF($3,0),preflight_error_code=NULLIF($4,''),preflight_origin='worker',preflight_at=$5,updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, status, result.HTTPStatus, diagnostic, result.ObservedAt)
	if err != nil {
		return err
	}
	auditOutcome := audit.OutcomeSucceeded
	if status != string(platform.TargetAvailable) {
		auditOutcome = audit.OutcomeFailed
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: audit.JoinTargetPreflight, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID,
		EntityType: "operation_target", EntityID: item.OperationTargetID, Outcome: auditOutcome,
		CorrelationID:  item.CorrelationID,
		Details:        audit.JoinTargetDetails{Status: status, Result: status, Stage: "preflight", DiagnosticCode: diagnostic},
		IdempotencyKey: item.ID + ":join.preflight:" + result.ObservedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishJoin(ctx context.Context, item Task, target JoinTarget, status, outcomeCode, diagnosticCode, stage string, member *platform.MembershipResult) error {
	if status != "succeeded" && status != "failed" && status != "blocked" && status != "unknown" {
		return errors.New("invalid join target status")
	}
	outcomeCode = platform.NormalizeDiagnostic(outcomeCode)
	diagnosticCode = platform.NormalizeDiagnostic(diagnosticCode)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockJoinTask(ctx, tx, item); err != nil {
		return err
	}
	var membershipID string
	if status == "succeeded" {
		memberID := ""
		if member != nil {
			memberID = member.PlatformMemberID
		}
		err = tx.QueryRow(ctx, `INSERT INTO tsw_batch_memberships(batch_id,target_account_id,join_operation_target_id,platform_member_id,joined_at) VALUES ($1,$2,$3,NULLIF($4,''),now()) ON CONFLICT (batch_id,target_account_id) DO UPDATE SET updated_at=now() RETURNING id`, target.BatchID, target.TargetID, item.OperationTargetID, memberID).Scan(&membershipID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2,status='succeeded',outcome_code=$3,diagnostic_code=NULLIF($4,''),last_attempt_at=now(),completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, membershipID, outcomeCode, diagnosticCode)
	} else {
		_, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status=$2,outcome_code=$3,diagnostic_code=NULLIF($4,''),last_attempt_at=now(),completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, status, outcomeCode, diagnosticCode)
	}
	if err != nil {
		return err
	}
	batchReason := diagnosticCode
	if status == "succeeded" {
		batchReason = ""
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_operations SET status=CASE WHEN NOT EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status NOT IN ('succeeded','failed','blocked','unknown')) THEN CASE WHEN EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status IN ('blocked','unknown')) THEN 'blocked' WHEN EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status='failed') THEN 'failed' ELSE 'succeeded' END ELSE 'running' END,
		completed_at=CASE WHEN NOT EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status NOT IN ('succeeded','failed','blocked','unknown')) THEN now() ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1`, target.OperationID)
	if err != nil {
		return err
	}
	if status == "succeeded" {
		_, err = tx.Exec(ctx, `UPDATE tsw_batches SET status='serving',service_started_at=COALESCE(service_started_at,now()),blocking_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM tsw_operation_targets other JOIN tsw_operations operation ON operation.id=other.operation_id WHERE operation.id=$2 AND other.status NOT IN ('succeeded'))`, target.BatchID, target.OperationID)
	} else {
		_, err = tx.Exec(ctx, `UPDATE tsw_batches SET status='joining',blocking_reason=NULLIF($2,''),updated_at=now(),version=version+1 WHERE id=$1`, target.BatchID, batchReason)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE tsw_operations SET workspace_mutation_lease_owner=NULL,workspace_mutation_lease_token=NULL,workspace_mutation_lease_expires_at=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND workspace_mutation_lease_token=$2`, target.OperationID, item.LeaseToken)
	}
	if err != nil {
		return err
	}
	joinEvent := audit.JoinTargetFailed
	joinOutcome := audit.OutcomeFailed
	if status == "succeeded" {
		joinEvent, joinOutcome = audit.JoinTargetSucceeded, audit.OutcomeSucceeded
	}
	if status == "blocked" || status == "unknown" {
		joinEvent = audit.JoinTargetUnknown
	}
	_, err = audit.Write(ctx, tx, audit.Event{Type: joinEvent, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "operation_target", EntityID: item.OperationTargetID, Outcome: joinOutcome, CorrelationID: item.CorrelationID, Details: audit.JoinTargetDetails{Status: status, Result: outcomeCode, Stage: stage, DiagnosticCode: diagnosticCode}, IdempotencyKey: item.ID + ":join.ended:" + status})
	if err != nil {
		return err
	}
	if (status == "blocked" || status == "unknown") && stage != "egress_admission" && stage != "before_join_request" {
		var reconciliationID string
		err = tx.QueryRow(ctx, `INSERT INTO tsw_tasks(operation_target_id,workspace_id,target_account_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts) VALUES ($1,$2,$3,'join_reconcile',$4,jsonb_build_object('operation_target_id',$6::text,'workspace_id',$7::text,'target_account_id',$8::text),$5,3) ON CONFLICT (task_type,dedupe_key) DO UPDATE SET updated_at=now() RETURNING id`, item.OperationTargetID, target.WorkspaceID, target.TargetID, "join-reconcile:"+item.OperationTargetID, item.CorrelationID, item.OperationTargetID, target.WorkspaceID, target.TargetID).Scan(&reconciliationID)
		if err != nil {
			return err
		}
		_, err = audit.Write(ctx, tx, audit.Event{Type: audit.JoinReconciliationQueued, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "task", EntityID: reconciliationID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.TaskDetails{AttemptNo: 1, Result: "queued", Stage: "join_unknown"}, IdempotencyKey: reconciliationID + ":reconciliation.queued"})
		if err != nil {
			return err
		}
	}
	settled, err := tx.Exec(ctx, `UPDATE tsw_tasks SET status='succeeded',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=now(),updated_at=now(),version=version+1 WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken)
	if err != nil {
		return err
	}
	if settled.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishJoinReconciliation(ctx context.Context, item Task, target JoinTarget, member platform.MembershipResult) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockJoinTask(ctx, tx, item); err != nil {
		return err
	}
	var maxAttempts int
	if err := tx.QueryRow(ctx, `SELECT max_attempts FROM tsw_tasks WHERE id=$1`, item.ID).Scan(&maxAttempts); err != nil {
		return err
	}
	diagnostic := platform.NormalizeDiagnostic(member.ErrorCode)
	if !member.Complete {
		resultCode, taskStatus := "membership_unknown", "retry_wait"
		if diagnostic == "" {
			diagnostic = "membership_unknown"
		}
		if item.AttemptNo >= maxAttempts {
			resultCode, taskStatus, diagnostic = "reconciliation_attempts_exhausted", "failed", "reconciliation_attempts_exhausted"
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status='unknown',outcome_code='platform_unknown',diagnostic_code=$2,completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, diagnostic); err != nil {
			return err
		}
		if err = settleJoinAggregate(ctx, tx, target.OperationID, target.BatchID); err != nil {
			return err
		}
		settled, settleErr := tx.Exec(ctx, `UPDATE tsw_tasks SET status=$3,available_at=CASE WHEN $3='retry_wait' THEN now()+interval '5 seconds' ELSE available_at END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=CASE WHEN $3='failed' THEN now() ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken, taskStatus)
		if settleErr != nil {
			return settleErr
		}
		if settled.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		_, err = audit.Write(ctx, tx, audit.Event{Type: audit.JoinReconciliationDone, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeFailed, CorrelationID: item.CorrelationID, Details: audit.TaskDetails{AttemptNo: item.AttemptNo, Result: resultCode, Stage: "membership_reconcile"}, IdempotencyKey: item.ID + ":reconciliation.done:" + strconv.Itoa(item.AttemptNo)})
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	resultCode := "member_confirmed"
	if member.Present {
		var membershipID string
		err = tx.QueryRow(ctx, `INSERT INTO tsw_batch_memberships(batch_id,target_account_id,join_operation_target_id,platform_member_id,joined_at) VALUES ($1,$2,$3,NULLIF($4,''),now()) ON CONFLICT (batch_id,target_account_id) DO UPDATE SET updated_at=now() RETURNING id`, target.BatchID, target.TargetID, item.OperationTargetID, member.PlatformMemberID).Scan(&membershipID)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2,status='succeeded',outcome_code='member_confirmed',diagnostic_code=NULL,completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, membershipID); err != nil {
			return err
		}
		if err = settleJoinAggregate(ctx, tx, target.OperationID, target.BatchID); err != nil {
			return err
		}
	} else {
		// A complete absence fact is not permission to replay a side effect. The
		// owner can explicitly authorize a new operation after reviewing it, but
		// this operation remains explainably unresolved/failed in this worker run.
		resultCode = "member_not_confirmed"
		if _, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status='unknown',outcome_code='platform_unknown',diagnostic_code=$2,completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, resultCode); err != nil {
			return err
		}
		if err = settleJoinAggregate(ctx, tx, target.OperationID, target.BatchID); err != nil {
			return err
		}
	}
	settled, err := tx.Exec(ctx, `UPDATE tsw_tasks SET status='succeeded',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=now(),updated_at=now(),version=version+1 WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken)
	if err != nil {
		return err
	}
	if settled.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	outcome := audit.OutcomeSucceeded
	if resultCode == "reconciliation_attempts_exhausted" {
		outcome = audit.OutcomeFailed
	}
	_, err = audit.Write(ctx, tx, audit.Event{Type: audit.JoinReconciliationDone, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "task", EntityID: item.ID, Outcome: outcome, CorrelationID: item.CorrelationID, Details: audit.TaskDetails{AttemptNo: item.AttemptNo, Result: resultCode, Stage: "membership_reconcile"}, IdempotencyKey: item.ID + ":reconciliation.done:" + strconv.Itoa(item.AttemptNo)})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func settleJoinAggregate(ctx context.Context, tx pgx.Tx, operationID, batchID string) error {
	_, err := tx.Exec(ctx, `UPDATE tsw_operations SET status=CASE WHEN NOT EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status NOT IN ('succeeded','failed','blocked','unknown')) THEN CASE WHEN EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status IN ('blocked','unknown')) THEN 'blocked' WHEN EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status='failed') THEN 'failed' ELSE 'succeeded' END ELSE 'running' END,completed_at=CASE WHEN NOT EXISTS (SELECT 1 FROM tsw_operation_targets WHERE operation_id=$1 AND status NOT IN ('succeeded','failed','blocked','unknown')) THEN now() ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1`, operationID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_batches SET status=CASE WHEN (SELECT status FROM tsw_operations WHERE id=$2)='succeeded' THEN 'serving' ELSE 'joining' END,service_started_at=CASE WHEN (SELECT status FROM tsw_operations WHERE id=$2)='succeeded' THEN COALESCE(service_started_at,now()) ELSE service_started_at END,blocking_reason=CASE WHEN (SELECT status FROM tsw_operations WHERE id=$2)='blocked' THEN 'join_target_unresolved' ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1`, batchID, operationID)
	return err
}

func lockJoinTask(ctx context.Context, tx pgx.Tx, item Task) error {
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM tsw_tasks WHERE id=$1 AND task_type IN ('join','join_reconcile') AND status='running' AND lease_token=$2 AND lease_expires_at>now() FOR UPDATE`, item.ID, item.LeaseToken).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	return err
}
