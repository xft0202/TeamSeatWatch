package task

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
)

var (
	ErrLeaseLost           = errors.New("task lease lost")
	ErrIdempotencyConflict = errors.New("task idempotency conflict")
)

type WorkspaceReadTarget struct {
	PlatformWorkspaceID string
	LoginIdentifier     string
	Password            string
}

type TargetProbeTarget struct {
	LoginIdentifier string
	Password        string
}

type Task struct {
	ID                string
	TaskType          string
	WorkspaceID       string
	TargetAccountID   string
	OperationTargetID string
	MembershipID      string
	DedupeKey         string
	Status            string
	LeaseToken        uuid.UUID
	AttemptNo         int
	CorrelationID     string
	CreatedAt         time.Time
	FinishedAt        *time.Time
}

type AttemptRoute struct {
	Mode        string
	Scheme      *string
	KeyVersion  *string
	Fingerprint []byte
	VerifiedAt  *time.Time
	Stage       *string
}

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// CreateWorkspaceRead is the only queue-creation path. Status/list reads never
// call it, making page loads and polling side-effect free by construction.
func (s *Store) CreateWorkspaceRead(ctx context.Context, workspaceID, dedupeKey, correlationID string) (Task, bool, error) {
	var result Task
	created := true
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tsw_tasks (workspace_id, task_type, dedupe_key, input_snapshot, correlation_id)
		VALUES ($1::uuid, 'workspace_read', $2, jsonb_build_object('workspace_id', $1::uuid::text), $3)
		ON CONFLICT (task_type, dedupe_key) DO NOTHING
		RETURNING id, workspace_id, dedupe_key, status, correlation_id, created_at, finished_at`, workspaceID, dedupeKey, correlationID).Scan(
		&result.ID, &result.WorkspaceID, &result.DedupeKey, &result.Status, &result.CorrelationID,
		&result.CreatedAt, &result.FinishedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		created = false
		err = s.pool.QueryRow(ctx, `SELECT id, workspace_id, dedupe_key, status, correlation_id, created_at, finished_at FROM tsw_tasks WHERE task_type = 'workspace_read' AND dedupe_key = $1`, dedupeKey).Scan(
			&result.ID, &result.WorkspaceID, &result.DedupeKey, &result.Status, &result.CorrelationID,
			&result.CreatedAt, &result.FinishedAt,
		)
		if err == nil && result.WorkspaceID != workspaceID {
			return Task{}, false, ErrIdempotencyConflict
		}
	}
	return result, created, err
}

func (s *Store) CreateTargetProbe(ctx context.Context, targetID, dedupeKey, correlationID string) (Task, bool, error) {
	var result Task
	created := true
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tsw_tasks (target_account_id, task_type, dedupe_key, input_snapshot, correlation_id)
		VALUES ($1::uuid, 'target_account_probe', $2, jsonb_build_object('target_account_id', $1::uuid::text), $3)
		ON CONFLICT (task_type, dedupe_key) DO NOTHING
		RETURNING id, task_type, target_account_id, dedupe_key, status, correlation_id, created_at, finished_at`, targetID, dedupeKey, correlationID).Scan(
		&result.ID, &result.TaskType, &result.TargetAccountID, &result.DedupeKey, &result.Status, &result.CorrelationID,
		&result.CreatedAt, &result.FinishedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		created = false
		err = s.pool.QueryRow(ctx, `SELECT id, task_type, target_account_id, dedupe_key, status, correlation_id, created_at, finished_at FROM tsw_tasks WHERE task_type = 'target_account_probe' AND dedupe_key = $1`, dedupeKey).Scan(
			&result.ID, &result.TaskType, &result.TargetAccountID, &result.DedupeKey, &result.Status, &result.CorrelationID,
			&result.CreatedAt, &result.FinishedAt,
		)
		if err == nil && result.TargetAccountID != targetID {
			return Task{}, false, ErrIdempotencyConflict
		}
	}
	return result, created, err
}

func (s *Store) WorkspaceReadTarget(ctx context.Context, workspaceID string) (WorkspaceReadTarget, error) {
	var target WorkspaceReadTarget
	var password []byte
	err := s.pool.QueryRow(ctx, `
		SELECT workspace.platform_workspace_id, credential.login_identifier, credential.password_secret
		FROM tsw_workspaces workspace
		JOIN tsw_mother_workspace_bindings binding
		  ON binding.workspace_id=workspace.id AND binding.ended_at IS NULL
		JOIN tsw_mother_accounts account
		  ON account.id=binding.mother_account_id AND account.status='active'
		JOIN tsw_mother_account_credentials credential
		  ON credential.mother_account_id=account.id
		WHERE workspace.id=$1`, workspaceID).Scan(
		&target.PlatformWorkspaceID, &target.LoginIdentifier, &password,
	)
	target.Password = string(password)
	clear(password)
	return target, err
}

func (s *Store) TargetProbeTarget(ctx context.Context, targetID string) (TargetProbeTarget, error) {
	var target TargetProbeTarget
	var password []byte
	err := s.pool.QueryRow(ctx, `
		SELECT target.identifier, credentials.password_secret
		FROM tsw_target_accounts target
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		WHERE target.id=$1 AND target.status='active'`, targetID).Scan(&target.LoginIdentifier, &password)
	target.Password = string(password)
	clear(password)
	return target, err
}

func (s *Store) Get(ctx context.Context, id string) (Task, error) {
	var result Task
	err := s.pool.QueryRow(ctx, `SELECT id, task_type, COALESCE(workspace_id::text,''), COALESCE(target_account_id::text,''), COALESCE(operation_target_id::text,''), COALESCE(membership_id::text,''), dedupe_key, status, correlation_id, created_at, finished_at FROM tsw_tasks WHERE id = $1`, id).Scan(
		&result.ID, &result.TaskType, &result.WorkspaceID, &result.TargetAccountID, &result.OperationTargetID, &result.MembershipID, &result.DedupeKey, &result.Status, &result.CorrelationID,
		&result.CreatedAt, &result.FinishedAt,
	)
	return result, err
}

// SettleExhausted interrupts one expired task that cannot create another attempt.
// The task transition and terminal audit remain one atomic recovery fact.
func (s *Store) SettleExhausted(ctx context.Context) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var item Task
	err = tx.QueryRow(ctx, `
		SELECT id,task_type,COALESCE(workspace_id::text,''),COALESCE(target_account_id::text,''),COALESCE(operation_target_id::text,''),correlation_id,attempt_count
		FROM tsw_tasks
		WHERE status='running' AND lease_expires_at<=now() AND attempt_count>=max_attempts
		ORDER BY lease_expires_at,created_at
		FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(
		&item.ID, &item.TaskType, &item.WorkspaceID, &item.TargetAccountID, &item.OperationTargetID, &item.CorrelationID, &item.AttemptNo,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE tsw_tasks SET status='interrupted',lease_owner=NULL,lease_token=NULL,
			lease_expires_at=NULL,finished_at=now(),updated_at=now(),version=version+1
		WHERE id=$1 AND status='running' AND lease_expires_at<=now()`, item.ID)
	if err != nil {
		return false, err
	}
	if result.RowsAffected() != 1 {
		return false, ErrLeaseLost
	}
	if item.TaskType == "join" || item.TaskType == "join_reconcile" {
		diagnostic := "attempts_exhausted"
		if item.TaskType == "join_reconcile" {
			diagnostic = "reconciliation_attempts_exhausted"
		}
		_, err = tx.Exec(ctx, `UPDATE tsw_operation_targets SET status='unknown',outcome_code='platform_unknown',diagnostic_code=$2,completed_at=now(),updated_at=now(),version=version+1 WHERE id=$1`, item.OperationTargetID, diagnostic)
		if err != nil {
			return false, err
		}
		_, err = tx.Exec(ctx, `UPDATE tsw_operations SET status='blocked',completed_at=now(),updated_at=now(),version=version+1 WHERE id=(SELECT operation_id FROM tsw_operation_targets WHERE id=$1)`, item.OperationTargetID)
		if err != nil {
			return false, err
		}
	}
	if item.TaskType == "target_account_probe" {
		observedAt := time.Now().UTC()
		updated, err := tx.Exec(ctx, `
			UPDATE tsw_target_credentials SET latest_probe_status='unknown',
				latest_probe_http_status=NULL,latest_probe_error_code='attempts_exhausted',
				latest_probe_endpoint_key='account_usage',latest_probe_origin='worker',
				latest_probed_at=$2,version=version+1
			WHERE target_account_id=$1`, item.TargetAccountID, observedAt)
		if err != nil {
			return false, err
		}
		if updated.RowsAffected() != 1 {
			return false, errors.New("target credential projection was not found")
		}
		_, err = audit.Write(ctx, tx, audit.Event{
			Type: audit.TargetAccountProbed, Actor: audit.ActorSystem, RetentionScopeID: item.TargetAccountID,
			EntityType: "target_account", EntityID: item.TargetAccountID, Outcome: audit.OutcomeFailed,
			CorrelationID: item.CorrelationID,
			Details: audit.TargetProbeDetails{
				Status: "unknown", Endpoint: "account_usage", Origin: "worker",
				ErrorCode: "attempts_exhausted", ObservedAt: observedAt.Format(time.RFC3339Nano),
			},
			IdempotencyKey: item.ID + ":target-account.probed:attempts-exhausted",
		})
		if err != nil {
			return false, err
		}
	}
	event, scope := audit.TaskInterrupted, item.WorkspaceID
	if item.TaskType == "target_account_probe" {
		event, scope = audit.TargetProbeInterrupted, item.TargetAccountID
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: event, Actor: audit.ActorSystem, RetentionScopeID: scope,
		EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeFailed,
		CorrelationID:  item.CorrelationID,
		Details:        audit.TaskDetails{AttemptNo: item.AttemptNo, Result: "attempts_exhausted", Stage: "crash_recovery"},
		IdempotencyKey: item.ID + ":task.interrupted:attempts-exhausted",
	})
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// ClaimRejected leases one task without creating an attempt start fact. It is used
// only when egress admission failed before any platform request could be made.
func (s *Store) ClaimRejected(ctx context.Context, worker string, duration time.Duration) (Task, error) {
	return s.claimRejected(ctx, worker, duration, "workspace_read")
}

func (s *Store) ClaimRejectedTargetProbe(ctx context.Context, worker string, duration time.Duration) (Task, error) {
	return s.claimRejected(ctx, worker, duration, "target_account_probe")
}

func (s *Store) claimRejected(ctx context.Context, worker string, duration time.Duration, taskType string) (Task, error) {
	var result Task
	err := s.pool.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id FROM tsw_tasks
			WHERE task_type=$3
			  AND ((status IN ('queued','retry_wait') AND available_at<=now()) OR
				(status='running' AND lease_expires_at<=now()))
			  AND NOT (task_type='join' AND status='running' AND lease_expires_at<=now())
			  AND attempt_count<max_attempts
			ORDER BY priority DESC,available_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE tsw_tasks task SET status='running',lease_owner=$1,lease_token=gen_random_uuid(),
			lease_expires_at=now()+$2::interval,attempt_count=attempt_count+1,updated_at=now(),version=version+1
		FROM candidate WHERE task.id=candidate.id
		RETURNING task.id,task.task_type,COALESCE(task.workspace_id::text,''),COALESCE(task.target_account_id::text,''),COALESCE(task.operation_target_id::text,''),COALESCE(task.membership_id::text,''),task.dedupe_key,task.status,task.lease_token,task.attempt_count,task.correlation_id`, worker, duration.String(), taskType).Scan(
		&result.ID, &result.TaskType, &result.WorkspaceID, &result.TargetAccountID, &result.OperationTargetID, &result.MembershipID, &result.DedupeKey, &result.Status, &result.LeaseToken, &result.AttemptNo, &result.CorrelationID)
	return result, err
}

func (s *Store) EnqueueExpiredCleanups(ctx context.Context, limit int, period string) (int64, error) {
	if limit <= 0 || limit > 1000 || period == "" || len(period) > 32 {
		return 0, errors.New("cleanup scheduling input is invalid")
	}
	result, err := s.pool.Exec(ctx, `
		INSERT INTO tsw_tasks (workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		SELECT expired.workspace_id,'workspace_fact_cleanup',
			'workspace-cleanup:'||expired.workspace_id::text||':'||$2,
			jsonb_build_object('workspace_id',expired.workspace_id::text,'period',$2),
			'workspace-cleanup:'||$2,5
		FROM (
			SELECT workspace_id FROM tsw_workspace_observations WHERE expires_at<=now()
			UNION SELECT workspace_id FROM tsw_workspace_member_snapshots WHERE expires_at<=now()
			UNION SELECT workspace_id FROM tsw_tasks WHERE workspace_id IS NOT NULL AND status IN ('succeeded','failed','interrupted') AND finished_at<=now()-interval '7 days'
			UNION SELECT retention_scope_id FROM tsw_audit_events WHERE retention_scope_type='workspace' AND expires_at<=now()
			ORDER BY workspace_id LIMIT $1
		) expired
		ON CONFLICT DO NOTHING`, limit, period)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// Claim holds the row lock only until lease publication; external work happens
// after this transaction commits. Expired running tasks are eligible for takeover.
func (s *Store) Claim(ctx context.Context, worker string, duration time.Duration, route AttemptRoute) (Task, error) {
	return s.claim(ctx, worker, duration, "workspace_read", route)
}

func (s *Store) ClaimCleanup(ctx context.Context, worker string, duration time.Duration) (Task, error) {
	return s.claim(ctx, worker, duration, "workspace_fact_cleanup", AttemptRoute{Mode: "direct"})
}

func (s *Store) ClaimTargetProbe(ctx context.Context, worker string, duration time.Duration, route AttemptRoute) (Task, error) {
	return s.claim(ctx, worker, duration, "target_account_probe", route)
}

func (s *Store) ClaimRejectedNetwork(ctx context.Context, worker string, duration time.Duration, taskType string) (Task, error) {
	return s.claimRejected(ctx, worker, duration, taskType)
}

func (s *Store) NextNetworkTaskType(ctx context.Context) (string, error) {
	var taskType string
	err := s.pool.QueryRow(ctx, `
		SELECT task_type FROM tsw_tasks
		WHERE task_type IN ('workspace_read','target_account_probe','join','join_reconcile')
		  AND ((status IN ('queued','retry_wait') AND available_at<=now()) OR
			(status='running' AND lease_expires_at<=now() AND task_type<>'join'))
		  AND attempt_count<max_attempts
		ORDER BY priority DESC,available_at,created_at LIMIT 1`).Scan(&taskType)
	return taskType, err
}

func (s *Store) claim(ctx context.Context, worker string, duration time.Duration, taskType string, route AttemptRoute) (Task, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Task{}, err
	}
	defer tx.Rollback(ctx)
	var result Task
	err = tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id FROM tsw_tasks
			WHERE task_type=$3
			  AND ((status IN ('queued','retry_wait') AND available_at <= now()) OR (status = 'running' AND lease_expires_at <= now()))
			  AND NOT (task_type='join' AND status='running' AND lease_expires_at<=now())
			  AND attempt_count < max_attempts
			ORDER BY priority DESC, available_at, created_at
			FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE tsw_tasks AS task
		SET status = 'running', lease_owner = $1, lease_token = gen_random_uuid(),
			lease_expires_at = now() + $2::interval, attempt_count = attempt_count + 1,
			updated_at = now(), version = version + 1
		FROM candidate WHERE task.id = candidate.id
		RETURNING task.id, task.task_type, COALESCE(task.workspace_id::text,''), COALESCE(task.target_account_id::text,''), COALESCE(task.operation_target_id::text,''), COALESCE(task.membership_id::text,''), task.dedupe_key, task.status,
			task.lease_token, task.attempt_count, task.correlation_id`, worker, duration.String(), taskType).Scan(
		&result.ID, &result.TaskType, &result.WorkspaceID, &result.TargetAccountID, &result.OperationTargetID, &result.MembershipID, &result.DedupeKey, &result.Status,
		&result.LeaseToken, &result.AttemptNo, &result.CorrelationID,
	)
	if err != nil {
		return Task{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO tsw_task_attempts (task_id, attempt_no, lease_token, route_mode, proxy_scheme, egress_key_version, egress_fingerprint, proxy_verified_at, proxy_stage)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, result.ID, result.AttemptNo, result.LeaseToken, route.Mode, route.Scheme, route.KeyVersion, nullableBytes(route.Fingerprint), route.VerifiedAt, route.Stage)
	if err != nil {
		return Task{}, err
	}
	startStage := "before_platform_request"
	event, scope := audit.TaskStarted, result.WorkspaceID
	if taskType == "workspace_fact_cleanup" {
		startStage = "before_retention_cleanup"
	} else if taskType == "target_account_probe" {
		event, scope = audit.TargetProbeStarted, result.TargetAccountID
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: event, Actor: audit.ActorSystem, RetentionScopeID: scope,
		EntityType: "task", EntityID: result.ID, Outcome: audit.OutcomeSucceeded,
		CorrelationID: result.CorrelationID,
		Details: audit.TaskDetails{
			AttemptNo: result.AttemptNo, Result: "started", Stage: startStage,
			RouteMode: route.Mode, ProxyScheme: stringValue(route.Scheme), EgressKeyVersion: stringValue(route.KeyVersion),
			ProxyVerifiedAt: timeValue(route.VerifiedAt),
		},
		IdempotencyKey: result.ID + ":task.started:" + strconv.Itoa(result.AttemptNo),
	})
	if err != nil {
		return Task{}, err
	}
	return result, tx.Commit(ctx)
}

func (s *Store) Renew(ctx context.Context, taskID string, lease uuid.UUID, duration time.Duration) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE tsw_tasks SET lease_expires_at = now() + $3::interval, updated_at = now(), version = version + 1
		WHERE id = $1 AND status = 'running' AND lease_token = $2 AND lease_expires_at > now()`, taskID, lease, duration.String())
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}

// CompleteWorkspaceRead owns the atomic publication boundary: the lease fence,
// fact/projection writes, task terminal state, and audit fact commit together.
func (s *Store) CompleteWorkspaceRead(ctx context.Context, item Task, publish func(context.Context, pgx.Tx, string) error) error {
	return s.complete(ctx, item, "workspace_read_complete", "publish", publish)
}

func (s *Store) CompleteCleanup(ctx context.Context, item Task, cleanup func(context.Context, pgx.Tx, string) error) error {
	return s.complete(ctx, item, "workspace_fact_cleanup_complete", "retention_cleanup", cleanup)
}

func (s *Store) CompleteTargetProbe(ctx context.Context, item Task, publish func(context.Context, pgx.Tx, string) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var targetID string
	err = tx.QueryRow(ctx, `SELECT target_account_id FROM tsw_tasks WHERE id=$1 AND task_type='target_account_probe' AND lease_token=$2 AND status='running' AND lease_expires_at>now() FOR UPDATE`, item.ID, item.LeaseToken).Scan(&targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if err := publish(ctx, tx, targetID); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE tsw_tasks SET status='succeeded',lease_owner=NULL,lease_token=NULL,
			lease_expires_at=NULL,finished_at=now(),updated_at=now(),version=version+1
		WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: audit.TargetProbeEnded, Actor: audit.ActorSystem, RetentionScopeID: targetID,
		EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeSucceeded,
		CorrelationID:  item.CorrelationID,
		Details:        audit.TaskDetails{AttemptNo: item.AttemptNo, Result: "target_probe_complete", Stage: "publish"},
		IdempotencyKey: item.ID + ":target-probe.ended:" + strconv.Itoa(item.AttemptNo),
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RejectTargetProbe(ctx context.Context, item Task, resultCode, stage string, publish func(context.Context, pgx.Tx, string) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `
		UPDATE tsw_tasks SET status='failed',lease_owner=NULL,lease_token=NULL,
			lease_expires_at=NULL,finished_at=now(),updated_at=now(),version=version+1
		WHERE id=$1 AND task_type='target_account_probe' AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	if err := publish(ctx, tx, item.TargetAccountID); err != nil {
		return err
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: audit.TargetProbeRejected, Actor: audit.ActorSystem, RetentionScopeID: item.TargetAccountID,
		EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeFailed,
		CorrelationID:  item.CorrelationID,
		Details:        audit.TaskDetails{AttemptNo: item.AttemptNo, Result: resultCode, Stage: stage},
		IdempotencyKey: item.ID + ":target-probe.rejected:" + strconv.Itoa(item.AttemptNo),
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) complete(ctx context.Context, item Task, resultCode, stage string, publish func(context.Context, pgx.Tx, string) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var workspaceID string
	err = tx.QueryRow(ctx, `SELECT workspace_id FROM tsw_tasks WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now() FOR UPDATE`, item.ID, item.LeaseToken).Scan(&workspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if err := publish(ctx, tx, workspaceID); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE tsw_tasks SET status='succeeded',lease_owner=NULL,lease_token=NULL,
			lease_expires_at=NULL,finished_at=now(),updated_at=now(),version=version+1
		WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: audit.TaskEnded, Actor: audit.ActorSystem, RetentionScopeID: workspaceID,
		EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeSucceeded,
		CorrelationID:  item.CorrelationID,
		Details:        audit.TaskDetails{AttemptNo: item.AttemptNo, Result: resultCode, Stage: stage},
		IdempotencyKey: item.ID + ":task.ended:" + strconv.Itoa(item.AttemptNo),
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Settle applies the publication fence and typed audit insert in one transaction;
// either both persist or neither does. The details payload is assembled from typed
// scalar parameters rather than caller-owned JSON.
func (s *Store) Settle(ctx context.Context, item Task, status, eventType, outcome, resultCode, stage string) error {
	if status != "succeeded" && status != "failed" && status != "interrupted" {
		return errors.New("invalid terminal task status")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `
		UPDATE tsw_tasks SET status=$3, lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL,
			finished_at=now(), updated_at=now(), version=version+1
		WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at > now()`, item.ID, item.LeaseToken, status)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	event, scope := audit.TaskEnded, item.WorkspaceID
	if item.TaskType == "target_account_probe" {
		event, scope = audit.TargetProbeEnded, item.TargetAccountID
	}
	switch eventType {
	case "task.rejected":
		if item.TaskType == "target_account_probe" {
			event = audit.TargetProbeRejected
		} else {
			event = audit.TaskRejected
		}
	case "task.interrupted":
		if item.TaskType == "target_account_probe" {
			event = audit.TargetProbeInterrupted
		} else {
			event = audit.TaskInterrupted
		}
	}
	auditOutcome := audit.OutcomeSucceeded
	switch outcome {
	case "failed":
		auditOutcome = audit.OutcomeFailed
	case "denied":
		auditOutcome = audit.OutcomeDenied
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: event, Actor: audit.ActorSystem, RetentionScopeID: scope,
		EntityType: "task", EntityID: item.ID, Outcome: auditOutcome,
		CorrelationID:  item.CorrelationID,
		Details:        audit.TaskDetails{AttemptNo: item.AttemptNo, Result: resultCode, Stage: stage},
		IdempotencyKey: item.ID + ":" + eventType + ":" + strconv.Itoa(item.AttemptNo),
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecordInterruption preserves a start-before-request failure fact without
// settling a task whose database lease is already owned by another worker.
func (s *Store) RecordInterruption(ctx context.Context, item Task, resultCode, stage string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	event, scope := audit.TaskInterrupted, item.WorkspaceID
	if item.TaskType == "target_account_probe" {
		event, scope = audit.TargetProbeInterrupted, item.TargetAccountID
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: event, Actor: audit.ActorSystem, RetentionScopeID: scope,
		EntityType: "task", EntityID: item.ID, Outcome: audit.OutcomeFailed,
		CorrelationID:  item.CorrelationID,
		Details:        audit.TaskDetails{AttemptNo: item.AttemptNo, Result: resultCode, Stage: stage},
		IdempotencyKey: item.ID + ":task.interrupted:" + strconv.Itoa(item.AttemptNo) + ":" + stage,
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func timeValue(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func nullableBytes(value []byte) interface{} {
	if len(value) == 0 {
		return nil
	}
	return value
}
