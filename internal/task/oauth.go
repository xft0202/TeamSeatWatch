package task

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

var ErrDeliveryAttemptSuperseded = errors.New("oauth generation superseded")

type DeliveryTarget struct {
	AssetID           string
	MembershipID      string
	WorkspaceID       string
	PlatformWorkspace string
	TargetAccountID   string
	TargetIdentifier  string
	Password          string
	TOTPSecret        string
	RecoverySecret    string
	PlatformSubjectID string
}

type DeliveryProbeTarget struct {
	AssetID           string
	MembershipID      string
	WorkspaceID       string
	PlatformWorkspace string
	AccessToken       string
}

type DeliveryAttempt struct {
	ID         string
	Generation int64
	AttemptNo  int
}

// QueueDeliveryGenerationTx creates the relationship-scoped asset and durable
// task in the same transaction that confirms platform membership.
func QueueDeliveryGenerationTx(ctx context.Context, tx pgx.Tx, workspaceID, membershipID, correlationID string) error {
	var assetID string
	if err := tx.QueryRow(ctx, `INSERT INTO tsw_oauth_assets(membership_id)
		VALUES ($1) ON CONFLICT (membership_id) DO UPDATE SET updated_at=now() RETURNING id`, membershipID).Scan(&assetID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO tsw_tasks(membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		VALUES ($1,$2,$3,'oauth_generate',$4,jsonb_build_object('membership_id',$1::text,'oauth_asset_id',$2::text,'workspace_id',$3::text),$5,3)
		ON CONFLICT (task_type,dedupe_key) DO NOTHING`, membershipID, assetID, workspaceID, "oauth-generate:"+assetID, correlationID)
	return err
}

func (s *Store) DeliveryTarget(ctx context.Context, item Task) (DeliveryTarget, error) {
	var target DeliveryTarget
	var password, totp, recovery []byte
	var batchID string
	err := s.pool.QueryRow(ctx, `SELECT asset.id,asset.membership_id,batch.id,binding.workspace_id,
		workspace.platform_workspace_id,membership.target_account_id,target.identifier,
		credentials.password_secret,credentials.totp_secret,credentials.recovery_secret,credentials.platform_subject_id
		FROM tsw_tasks task
		JOIN tsw_oauth_assets asset ON asset.id=task.oauth_asset_id
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		JOIN tsw_target_accounts target ON target.id=membership.target_account_id AND target.status='active'
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		WHERE task.id=$1 AND task.task_type IN ('oauth_generate','oauth_probe')`, item.ID).Scan(
		&target.AssetID, &target.MembershipID, &batchID, &target.WorkspaceID,
		&target.PlatformWorkspace, &target.TargetAccountID, &target.TargetIdentifier,
		&password, &totp, &recovery, &target.PlatformSubjectID)
	if err != nil {
		return DeliveryTarget{}, err
	}
	target.Password, target.TOTPSecret, target.RecoverySecret = string(password), string(totp), string(recovery)
	clear(password)
	clear(totp)
	clear(recovery)
	return target, nil
}

func (s *Store) DeliveryProbeTarget(ctx context.Context, item Task) (DeliveryProbeTarget, error) {
	var target DeliveryProbeTarget
	err := s.pool.QueryRow(ctx, `SELECT asset.id,asset.membership_id,binding.workspace_id,
		workspace.platform_workspace_id,version.payload->>'access_token'
		FROM tsw_tasks task
		JOIN tsw_oauth_assets asset ON asset.id=task.oauth_asset_id AND asset.status IN ('ready','unavailable')
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		JOIN tsw_delivery_versions version ON version.id=asset.current_delivery_version_id AND version.oauth_asset_id=asset.id
		WHERE task.id=$1 AND task.task_type='oauth_probe'`, item.ID).Scan(
		&target.AssetID, &target.MembershipID, &target.WorkspaceID, &target.PlatformWorkspace, &target.AccessToken)
	return target, err
}

// EnqueueCustomerDeliveryProbe creates one explicit customer status-check task.
// The suffix is request-scoped so each check is a new read-only observation,
// while the task remains bound to the original asset and membership.
func (s *Store) EnqueueCustomerDeliveryProbe(ctx context.Context, assetID, suffix, correlationID string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	created, err := EnqueueCustomerDeliveryProbeTx(ctx, tx, assetID, suffix, correlationID)
	if err != nil {
		return false, err
	}
	return created, tx.Commit(ctx)
}

// EnqueueCustomerDeliveryProbeTx keeps the explicit check and its customer
// audit fact in one caller-owned transaction.
func EnqueueCustomerDeliveryProbeTx(ctx context.Context, tx pgx.Tx, assetID, suffix, correlationID string) (bool, error) {
	if strings.TrimSpace(assetID) == "" || strings.TrimSpace(suffix) == "" || len(suffix) > 64 {
		return false, errors.New("customer probe input is invalid")
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO tsw_tasks(membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		SELECT asset.membership_id,asset.id,binding.workspace_id,'oauth_probe',
			'oauth-probe:'||asset.id::text||':customer:'||$2,
			jsonb_build_object('membership_id',asset.membership_id::text,'oauth_asset_id',asset.id::text,'workspace_id',binding.workspace_id::text,'origin','customer'),$3,3
		FROM tsw_oauth_assets asset
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		WHERE asset.id=$1::uuid AND membership.state='active'
		  AND batch.status IN ('serving','removing')
		  AND asset.current_delivery_version_id IS NOT NULL
		ON CONFLICT (task_type,dedupe_key) DO NOTHING`, assetID, suffix, correlationID)
	return result.RowsAffected() == 1, err
}

// EnqueueDeliveryProbes schedules one read-only probe per current asset. The
// suffix makes scheduler rounds idempotent while allowing a later round to run.
func (s *Store) EnqueueDeliveryProbes(ctx context.Context, batchID, correlationID, suffix string) (int64, error) {
	if strings.TrimSpace(suffix) == "" {
		return 0, errors.New("oauth probe suffix is required")
	}
	result, err := s.pool.Exec(ctx, `INSERT INTO tsw_tasks(membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		SELECT asset.membership_id,asset.id,binding.workspace_id,'oauth_probe',
			'oauth-probe:'||asset.id::text||':'||$2,
			jsonb_build_object('membership_id',asset.membership_id::text,'oauth_asset_id',asset.id::text,'workspace_id',binding.workspace_id::text),$3,3
		FROM tsw_oauth_assets asset
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_delivery_versions version ON version.id=asset.current_delivery_version_id AND version.oauth_asset_id=asset.id
		WHERE ($1 = '' OR batch.id=NULLIF($1,'')::uuid) AND membership.state='active' AND asset.status IN ('ready','unavailable')
		  AND NOT EXISTS (SELECT 1 FROM tsw_oauth_attempts active WHERE active.oauth_asset_id=asset.id AND active.state='running')
		ON CONFLICT (task_type,dedupe_key) DO NOTHING`, batchID, suffix, correlationID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

func (s *Store) recordDeliveryLeaseLost(ctx context.Context, tx pgx.Tx, item Task, attempt DeliveryAttempt, stage string) error {
	result, err := tx.Exec(ctx, `UPDATE tsw_oauth_attempts SET state='superseded',outcome_code='lease_lost',finished_at=now() WHERE id=$1 AND state='running'`, attempt.ID)
	if err != nil || result.RowsAffected() == 0 {
		return err
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: audit.DeliveryAttemptSettled, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID,
		EntityType: "oauth_attempt", EntityID: attempt.ID, Outcome: audit.OutcomeFailed, CorrelationID: item.CorrelationID,
		Details:        audit.DeliveryAttemptDetails{Generation: attempt.Generation, AttemptNo: attempt.AttemptNo, Result: "lease_lost", Stage: stage, Status: "unknown"},
		IdempotencyKey: attempt.ID + ":lease_lost:" + stage,
	})
	return err
}
func (s *Store) FinishDeliveryProbe(ctx context.Context, item Task, attempt DeliveryAttempt, target DeliveryProbeTarget, probe platform.DeliveryLiveness) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentAttempt string
	var currentGeneration int64
	if err = tx.QueryRow(ctx, `SELECT asset.current_attempt_id::text,asset.current_generation
		FROM tsw_oauth_assets asset JOIN tsw_tasks task ON task.oauth_asset_id=asset.id
		WHERE task.id=$1 AND task.lease_token=$2 AND task.status='running' AND task.lease_expires_at>now() AND asset.id=$3 FOR UPDATE OF task,asset`, item.ID, item.LeaseToken, item.OAuthAssetID).Scan(&currentAttempt, &currentGeneration); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_ = s.recordDeliveryLeaseLost(ctx, tx, item, attempt, "probe")
			_ = tx.Commit(ctx)
			return ErrLeaseLost
		}
		return err
	}
	if currentGeneration != attempt.Generation || currentAttempt != attempt.ID {
		_, _ = tx.Exec(ctx, `UPDATE tsw_oauth_attempts SET state='superseded',outcome_code='generation_superseded',finished_at=now() WHERE id=$1 AND state='running'`, attempt.ID)
		return ErrDeliveryAttemptSuperseded
	}
	success := probe.Status == "ok" && probe.HTTPStatus >= 200 && probe.HTTPStatus < 300
	assetStatus := "ready"
	if probe.Status == "auth_error" || probe.Status == "deactivated_workspace" {
		assetStatus = "unavailable"
	}
	resultCode := probe.ErrorCode
	if resultCode == "" {
		resultCode = string(probe.Status)
	}
	attemptState := "published"
	if !success && (probe.Status == "unknown" || probe.Status == "transient_failure" || probe.Status == "rate_limited") {
		attemptState = "failed"
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_attempts SET state=$2,outcome_code=$3,finished_at=now() WHERE id=$1 AND state='running'`, attempt.ID, attemptState, resultCode); err != nil {
		return err
	}
	probeOrigin := probe.Origin
	if probeOrigin != "customer" {
		probeOrigin = "scheduled"
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET status=$2,liveness_status=$3,liveness_http_status=NULLIF($4,0),liveness_error_code=NULLIF($5,''),liveness_origin=$6,probed_at=$7,unavailable_reason=CASE WHEN $2='unavailable' THEN NULLIF($5,'') ELSE unavailable_reason END,updated_at=now(),version=version+1 WHERE id=$1`, item.OAuthAssetID, assetStatus, probe.Status, probe.HTTPStatus, resultCode, probeOrigin, probe.ObservedAt); err != nil {
		return err
	}
	taskStatus := "succeeded"
	if attemptState == "failed" {
		taskStatus = "retry_wait"
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_tasks SET status=$3,available_at=CASE WHEN $3='retry_wait' THEN now()+interval '5 seconds' ELSE available_at END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=CASE WHEN $3='retry_wait' THEN NULL ELSE now() END,updated_at=now(),version=version+1 WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken, taskStatus); err != nil {
		return err
	}
	outcome := audit.OutcomeSucceeded
	if !success {
		outcome = audit.OutcomeFailed
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.DeliveryAttemptSettled, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "oauth_attempt", EntityID: attempt.ID, Outcome: outcome, CorrelationID: item.CorrelationID, Details: audit.DeliveryAttemptDetails{Generation: attempt.Generation, AttemptNo: attempt.AttemptNo, Result: resultCode, Stage: "probe", Status: string(probe.Status), HTTPStatus: probe.HTTPStatus, ErrorCode: probe.ErrorCode}, IdempotencyKey: attempt.ID + ":probe-settled"}); err != nil {
		return err
	}
	if probeOrigin == "customer" {
		var cardID string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM tsw_cards WHERE membership_id=$1::uuid`, target.MembershipID).Scan(&cardID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if cardID != "" {
			statusResult := customerProbePublicResult(probe.Status)
			statusOutcome := audit.OutcomeSucceeded
			if !success {
				statusOutcome = audit.OutcomeFailed
			}
			if _, err = audit.Write(ctx, tx, audit.Event{
				Type: audit.PublicStatusChanged, Actor: audit.ActorSystem, RetentionScopeID: cardID,
				EntityType: "card", EntityID: cardID, Outcome: statusOutcome, CorrelationID: item.CorrelationID,
				Details:        audit.PublicAccessDetails{Action: "status_check", Result: statusResult, Status: statusResult, Reason: resultCode},
				IdempotencyKey: attempt.ID + ":customer-status",
			}); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func customerProbePublicResult(status oauthdomain.ProbeStatus) string {
	switch status {
	case oauthdomain.ProbeOK:
		return "healthy"
	case oauthdomain.ProbeAuthError:
		return "need_reclaim"
	case oauthdomain.ProbeDeactivatedWorkspace:
		return "cannot_reclaim"
	default:
		return "unknown"
	}
}

// BeginDeliveryAttempt advances the generation only after the task lease is held.
func (s *Store) BeginDeliveryAttempt(ctx context.Context, item Task) (DeliveryAttempt, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DeliveryAttempt{}, err
	}
	defer tx.Rollback(ctx)
	var currentGeneration int64
	var attempt DeliveryAttempt
	if err = tx.QueryRow(ctx, `SELECT current_generation FROM tsw_oauth_assets asset
		JOIN tsw_tasks task ON task.oauth_asset_id=asset.id
		WHERE task.id=$1 AND task.lease_token=$2 AND task.status='running' AND task.lease_expires_at>now()
		AND asset.id=$3 FOR UPDATE OF task,asset`, item.ID, item.LeaseToken, item.OAuthAssetID).Scan(&currentGeneration); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DeliveryAttempt{}, ErrLeaseLost
		}
		return DeliveryAttempt{}, err
	}
	kind := "generate"
	generation := currentGeneration + 1
	if item.TaskType == "oauth_probe" {
		kind = "probe"
		generation = currentGeneration
	}
	var attemptNo int
	if err = tx.QueryRow(ctx, `SELECT COALESCE(max(attempt_no),0)+1 FROM tsw_oauth_attempts WHERE oauth_asset_id=$1 AND generation=$2`, item.OAuthAssetID, generation).Scan(&attemptNo); err != nil {
		return DeliveryAttempt{}, err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO tsw_oauth_attempts(oauth_asset_id,task_id,generation,attempt_no,attempt_kind)
		VALUES ($1,$2,$3,$4,$5) RETURNING id,generation,attempt_no`, item.OAuthAssetID, item.ID, generation, attemptNo, kind).Scan(&attempt.ID, &attempt.Generation, &attempt.AttemptNo); err != nil {
		return DeliveryAttempt{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET current_generation=$2,current_attempt_id=$3,status='generating',unavailable_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.OAuthAssetID, generation, attempt.ID); err != nil {
		return DeliveryAttempt{}, err
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.DeliveryAttemptStarted, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "oauth_attempt", EntityID: attempt.ID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.DeliveryAttemptDetails{Generation: generation, AttemptNo: item.AttemptNo, Result: "started", Stage: "generate", Status: "pending"}, IdempotencyKey: attempt.ID + ":started"}); err != nil {
		return DeliveryAttempt{}, err
	}
	return attempt, tx.Commit(ctx)
}

func (s *Store) FinishDeliveryAttempt(ctx context.Context, item Task, attempt DeliveryAttempt, target DeliveryTarget, generated platform.DeliveryCredentialSet, probe platform.DeliveryLiveness) error {
	payload := map[string]any{
		"refresh_token":       generated.RefreshToken,
		"access_token":        generated.AccessToken,
		"id_token":            generated.IDToken,
		"expires_in":          generated.ExpiresIn,
		"scope":               generated.Scope,
		"workspace_id":        generated.WorkspaceID,
		"platform_subject_id": generated.PlatformSubjectID,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(encoded)
	subjectMatches := strings.TrimSpace(target.PlatformSubjectID) == "" || strings.TrimSpace(generated.PlatformSubjectID) == strings.TrimSpace(target.PlatformSubjectID)
	success := strings.TrimSpace(generated.RefreshToken) != "" && strings.TrimSpace(generated.AccessToken) != "" && strings.TrimSpace(generated.IDToken) != "" &&
		subjectMatches && strings.TrimSpace(generated.WorkspaceID) == strings.TrimSpace(target.PlatformWorkspace) && strings.TrimSpace(probe.WorkspaceID) == strings.TrimSpace(target.PlatformWorkspace) &&
		strings.TrimSpace(generated.PlatformSubjectID) != "" && strings.TrimSpace(probe.PlatformSubjectID) == strings.TrimSpace(generated.PlatformSubjectID) &&
		probe.Status == "ok" && probe.HTTPStatus >= 200 && probe.HTTPStatus < 300
	resultCode := "oauth_published"
	status := "ok"
	if !success {
		status = string(probe.Status)
		if status == "" {
			status = "unknown"
		}
		resultCode = strings.TrimSpace(probe.ErrorCode)
		if resultCode == "" {
			resultCode = "oauth_publish_blocked"
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentAttempt string
	var currentGeneration int64
	if err = tx.QueryRow(ctx, `SELECT asset.current_attempt_id::text,asset.current_generation
		FROM tsw_oauth_assets asset JOIN tsw_tasks task ON task.oauth_asset_id=asset.id
		WHERE task.id=$1 AND task.lease_token=$2 AND task.status='running' AND task.lease_expires_at>now() AND asset.id=$3
		FOR UPDATE OF task,asset`, item.ID, item.LeaseToken, item.OAuthAssetID).Scan(&currentAttempt, &currentGeneration); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_ = s.recordDeliveryLeaseLost(ctx, tx, item, attempt, "publish")
			_ = tx.Commit(ctx)
			return ErrLeaseLost
		}
		return err
	}
	if currentGeneration != attempt.Generation || currentAttempt != attempt.ID {
		_, _ = tx.Exec(ctx, `UPDATE tsw_oauth_attempts SET state='superseded',outcome_code='generation_superseded',finished_at=now() WHERE id=$1 AND state='running'`, attempt.ID)
		return ErrDeliveryAttemptSuperseded
	}
	if success {
		var versionID string
		if err = tx.QueryRow(ctx, `INSERT INTO tsw_delivery_versions(oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id)
			VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, item.OAuthAssetID, attempt.Generation, encoded, hash[:], generated.PlatformSubjectID, target.WorkspaceID).Scan(&versionID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_attempts SET state='published',outcome_code=$2,published_version_id=$3,finished_at=now() WHERE id=$1 AND state='running'`, attempt.ID, resultCode, versionID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET status='ready',current_delivery_version_id=$2,liveness_status='ok',liveness_http_status=$3,liveness_error_code=NULL,liveness_origin='generation',probed_at=$4,platform_subject_id=$5,unavailable_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.OAuthAssetID, versionID, probe.HTTPStatus, probe.ObservedAt, generated.PlatformSubjectID); err != nil {
			return err
		}
	} else {
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_attempts SET state='failed',outcome_code=$2,finished_at=now() WHERE id=$1 AND state='running'`, attempt.ID, resultCode); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET status='unavailable',liveness_status=$2,liveness_http_status=NULLIF($3,0),liveness_error_code=NULLIF($4,''),liveness_origin='generation',probed_at=$5,unavailable_reason=$4,updated_at=now(),version=version+1 WHERE id=$1`, item.OAuthAssetID, status, probe.HTTPStatus, resultCode, probe.ObservedAt); err != nil {
			return err
		}
	}
	taskStatus := "failed"
	if !success && (probe.Status == "unknown" || probe.Status == "transient_failure" || probe.Status == "rate_limited") {
		taskStatus = "retry_wait"
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_tasks SET status=$3,available_at=CASE WHEN $3='retry_wait' THEN now()+interval '5 seconds' ELSE available_at END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=CASE WHEN $3='retry_wait' THEN NULL ELSE now() END,updated_at=now(),version=version+1 WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_expires_at>now()`, item.ID, item.LeaseToken, taskStatus); err != nil {
		return err
	}
	outcome := audit.OutcomeSucceeded
	if !success {
		outcome = audit.OutcomeFailed
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.DeliveryAttemptSettled, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "oauth_attempt", EntityID: attempt.ID, Outcome: outcome, CorrelationID: item.CorrelationID, Details: audit.DeliveryAttemptDetails{Generation: attempt.Generation, AttemptNo: attempt.AttemptNo, Result: resultCode, Stage: "publish", Status: status, HTTPStatus: probe.HTTPStatus, ErrorCode: probe.ErrorCode}, IdempotencyKey: attempt.ID + ":settled"}); err != nil {
		return err
	}
	if success {
		if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.DeliveryPublished, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "oauth_asset", EntityID: item.OAuthAssetID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.DeliveryAttemptDetails{Generation: attempt.Generation, AttemptNo: attempt.AttemptNo, Result: "published", Stage: "publish", Status: "ok", HTTPStatus: probe.HTTPStatus}, IdempotencyKey: item.OAuthAssetID + ":published:" + fmt.Sprint(attempt.Generation)}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
