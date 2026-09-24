package task

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

type DeliveryReclaimTarget struct {
	DeliveryTarget
	OrderID          string
	CurrentVersionID string
	AccessToken      string
	RefreshToken     string
	CardID           string
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
		WHERE task.id=$1 AND task.task_type IN ('oauth_generate','oauth_probe')
		AND membership.state='active' AND batch.status<>'ended'`, item.ID).Scan(
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

func (s *Store) DeliveryReclaimTarget(ctx context.Context, item Task) (DeliveryReclaimTarget, error) {
	var target DeliveryReclaimTarget
	var password, totp, recovery []byte
	err := s.pool.QueryRow(ctx, `SELECT asset.id,asset.membership_id,binding.workspace_id,
		workspace.platform_workspace_id,membership.target_account_id,target.identifier,
		credentials.password_secret,credentials.totp_secret,credentials.recovery_secret,credentials.platform_subject_id,
		ord.id,ord.current_delivery_version_id,version.payload->>'access_token',version.payload->>'refresh_token',card.id
		FROM tsw_tasks task
		JOIN tsw_oauth_assets asset ON asset.id=task.oauth_asset_id
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		JOIN tsw_target_accounts target ON target.id=membership.target_account_id AND target.status='active'
		JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		JOIN tsw_orders ord ON ord.membership_id=membership.id AND ord.oauth_asset_id=asset.id
		JOIN tsw_delivery_versions version ON version.id=ord.current_delivery_version_id AND version.oauth_asset_id=asset.id
		JOIN tsw_cards card ON card.id=ord.card_id AND card.membership_id=membership.id
		WHERE task.id=$1 AND task.task_type='oauth_reclaim'
		AND membership.state='active' AND batch.status<>'ended'`, item.ID).Scan(
		&target.AssetID, &target.MembershipID, &target.WorkspaceID, &target.PlatformWorkspace,
		&target.TargetAccountID, &target.TargetIdentifier, &password, &totp, &recovery,
		&target.PlatformSubjectID, &target.OrderID, &target.CurrentVersionID, &target.AccessToken,
		&target.RefreshToken, &target.CardID)
	if err != nil {
		return DeliveryReclaimTarget{}, err
	}
	target.Password, target.TOTPSecret, target.RecoverySecret = string(password), string(totp), string(recovery)
	clear(password)
	clear(totp)
	clear(recovery)
	return target, nil
}

// EnqueueCustomerDeliveryReclaimTx creates one idempotent customer reclaim task.
// The caller owns the transaction and audit fact.
func EnqueueCustomerDeliveryReclaimTx(ctx context.Context, tx pgx.Tx, assetID, orderID, suffix, correlationID string) (bool, error) {
	return enqueueDeliveryReclaimTx(ctx, tx, assetID, orderID, suffix, correlationID, "customer")
}

// EnqueueOwnerDeliveryReclaimTx creates one idempotent Owner-authorized reclaim task.
func EnqueueOwnerDeliveryReclaimTx(ctx context.Context, tx pgx.Tx, assetID, orderID, suffix, correlationID string) (bool, error) {
	return enqueueDeliveryReclaimTx(ctx, tx, assetID, orderID, suffix, correlationID, "owner")
}

func enqueueDeliveryReclaimTx(ctx context.Context, tx pgx.Tx, assetID, orderID, suffix, correlationID, origin string) (bool, error) {
	if origin != "customer" && origin != "owner" {
		return false, errors.New("delivery reclaim origin is invalid")
	}
	if strings.TrimSpace(assetID) == "" || strings.TrimSpace(orderID) == "" || strings.TrimSpace(suffix) == "" || len(suffix) > 64 {
		return false, errors.New("customer reclaim input is invalid")
	}
	var boundCardID string
	if err := tx.QueryRow(ctx, `SELECT card.id::text
		FROM tsw_cards card
		JOIN tsw_batch_memberships membership ON membership.id=card.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id AND asset.id=$1::uuid
		JOIN tsw_orders ord ON ord.card_id=card.id AND ord.membership_id=membership.id AND ord.oauth_asset_id=asset.id AND ord.id=$2::uuid
		WHERE membership.state='active' AND batch.status IN ('serving','removing')
		FOR UPDATE OF card,asset,ord`, assetID, orderID).Scan(&boundCardID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	_ = boundCardID
	result, err := tx.Exec(ctx, `
		INSERT INTO tsw_tasks(membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
		SELECT asset.membership_id,asset.id,binding.workspace_id,'oauth_reclaim',
			'oauth-reclaim:'||asset.id::text||':'||$3,
			jsonb_build_object('membership_id',asset.membership_id::text,'oauth_asset_id',asset.id::text,'workspace_id',binding.workspace_id::text,'order_id',$2,'origin',$5::text),$4,3
		FROM tsw_oauth_assets asset
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_orders ord ON ord.oauth_asset_id=asset.id AND ord.id=$2::uuid AND ord.membership_id=membership.id
		WHERE asset.id=$1::uuid AND membership.state='active'
		  AND batch.status IN ('serving','removing')
		  AND asset.current_delivery_version_id=ord.current_delivery_version_id
		ON CONFLICT DO NOTHING`, assetID, orderID, suffix, correlationID, origin)
	if err != nil {
		return false, err
	}
	created := result.RowsAffected() == 1
	if created {
		_, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET status='reclaiming',unavailable_reason='reclaim_in_progress',liveness_origin='reclaim',updated_at=now(),version=version+1 WHERE id=$1::uuid AND status IN ('ready','unavailable')`, assetID)
		if err != nil {
			return false, err
		}
	}
	return created, nil
}

func EnqueueCustomerDeliveryReclaim(ctx context.Context, pool *pgxpool.Pool, assetID, orderID, suffix, correlationID string) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	created, err := EnqueueCustomerDeliveryReclaimTx(ctx, tx, assetID, orderID, suffix, correlationID)
	if err != nil {
		return false, err
	}
	return created, tx.Commit(ctx)
}

func (s *Store) DeliveryProbeTarget(ctx context.Context, item Task) (DeliveryProbeTarget, error) {
	var target DeliveryProbeTarget
	err := s.pool.QueryRow(ctx, `SELECT asset.id,asset.membership_id,binding.workspace_id,
		workspace.platform_workspace_id,version.payload->>'access_token'
		FROM tsw_tasks task
		JOIN tsw_oauth_assets asset ON asset.id=task.oauth_asset_id AND asset.status IN ('ready','unavailable','reclaiming')
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		JOIN tsw_delivery_versions version ON version.id=asset.current_delivery_version_id AND version.oauth_asset_id=asset.id
		WHERE task.id=$1 AND task.task_type='oauth_probe'
		AND membership.state='active' AND batch.status<>'ended'`, item.ID).Scan(
		&target.AssetID, &target.MembershipID, &target.WorkspaceID, &target.PlatformWorkspace, &target.AccessToken)
	return target, err
}

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
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		WHERE task.id=$1 AND task.lease_token=$2 AND task.status='running' AND task.lease_expires_at>now() AND asset.id=$3
		AND membership.state='active' AND batch.status<>'ended' FOR UPDATE OF task,asset,membership,batch`, item.ID, item.LeaseToken, item.OAuthAssetID).Scan(&currentAttempt, &currentGeneration); err != nil {
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
	if probeOrigin != "customer" && probe.Status == oauthdomain.ProbeAuthError && probe.HTTPStatus == 401 {
		var cardID, orderID string
		err = tx.QueryRow(ctx, `SELECT card.id::text,ord.id::text
			FROM tsw_orders ord
			JOIN tsw_cards card ON card.id=ord.card_id AND card.status='active'
			JOIN tsw_oauth_assets asset ON asset.id=ord.oauth_asset_id
			WHERE ord.oauth_asset_id=$1::uuid AND ord.current_delivery_version_id=asset.current_delivery_version_id
			FOR UPDATE OF card,ord`, item.OAuthAssetID).Scan(&cardID, &orderID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			queued, queueErr := tx.Exec(ctx, `
				INSERT INTO tsw_tasks(membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts)
				SELECT asset.membership_id,asset.id,binding.workspace_id,'oauth_reclaim',
					'oauth-reclaim:'||asset.id::text||':auto:'||$3,
					jsonb_build_object('membership_id',asset.membership_id::text,'oauth_asset_id',asset.id::text,'workspace_id',binding.workspace_id::text,'order_id',$2,'origin','automatic_401'),$4,3
				FROM tsw_oauth_assets asset
				JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
				JOIN tsw_batches batch ON batch.id=membership.batch_id
				JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
				JOIN tsw_orders ord ON ord.id=$2::uuid AND ord.oauth_asset_id=asset.id AND ord.membership_id=membership.id
				JOIN tsw_cards card ON card.id=ord.card_id AND card.status='active'
				WHERE asset.id=$1::uuid AND membership.state='active'
				  AND batch.status IN ('serving','removing')
				  AND asset.current_delivery_version_id=ord.current_delivery_version_id
				ON CONFLICT DO NOTHING`, item.OAuthAssetID, orderID, fmt.Sprint(currentGeneration), item.CorrelationID)
			if queueErr != nil {
				return queueErr
			}
			if queued.RowsAffected() == 1 {
				if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET status='reclaiming',unavailable_reason='reclaim_in_progress',liveness_origin='reclaim',updated_at=now(),version=version+1 WHERE id=$1`, item.OAuthAssetID); err != nil {
					return err
				}
				if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.PublicReclaimUpdated, Actor: audit.ActorSystem, RetentionScopeID: cardID, EntityType: "card", EntityID: cardID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.PublicAccessDetails{Action: "reclaim_request", Result: "queued", Reason: "authoritative_401"}, IdempotencyKey: item.ID + ":automatic-reclaim"}); err != nil {
					return err
				}
			}
		}
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
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		WHERE task.id=$1 AND task.lease_token=$2 AND task.status='running' AND task.lease_expires_at>now()
		AND asset.id=$3 AND membership.state='active' AND batch.status<>'ended'
		FOR UPDATE OF task,asset,membership,batch`, item.ID, item.LeaseToken, item.OAuthAssetID).Scan(&currentGeneration); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DeliveryAttempt{}, ErrLeaseLost
		}
		return DeliveryAttempt{}, err
	}
	kind := "generate"
	generation := currentGeneration + 1
	assetStatus := "generating"
	if item.TaskType == "oauth_probe" {
		kind = "probe"
		generation = currentGeneration
	} else if item.TaskType == "oauth_reclaim" {
		kind = "reclaim"
		generation = currentGeneration + 1
		assetStatus = "reclaiming"
	}
	var attemptNo int
	if err = tx.QueryRow(ctx, `SELECT COALESCE(max(attempt_no),0)+1 FROM tsw_oauth_attempts WHERE oauth_asset_id=$1 AND generation=$2`, item.OAuthAssetID, generation).Scan(&attemptNo); err != nil {
		return DeliveryAttempt{}, err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO tsw_oauth_attempts(oauth_asset_id,task_id,generation,attempt_no,attempt_kind)
		VALUES ($1,$2,$3,$4,$5) RETURNING id,generation,attempt_no`, item.OAuthAssetID, item.ID, generation, attemptNo, kind).Scan(&attempt.ID, &attempt.Generation, &attempt.AttemptNo); err != nil {
		return DeliveryAttempt{}, err
	}
	if kind == "reclaim" {
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_attempts attempt SET requested_order_id=NULLIF(task.input_snapshot->>'order_id','')::uuid FROM tsw_tasks task WHERE attempt.id=$1 AND task.id=attempt.task_id`, attempt.ID); err != nil {
			return DeliveryAttempt{}, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET current_generation=$2,current_attempt_id=$3,status=$4,unavailable_reason=CASE WHEN $4='reclaiming' THEN 'reclaim_in_progress' ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1`, item.OAuthAssetID, generation, attempt.ID, assetStatus); err != nil {
		return DeliveryAttempt{}, err
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.DeliveryAttemptStarted, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "oauth_attempt", EntityID: attempt.ID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.DeliveryAttemptDetails{Generation: generation, AttemptNo: item.AttemptNo, Result: "started", Stage: kind, Status: "pending"}, IdempotencyKey: attempt.ID + ":started"}); err != nil {
		return DeliveryAttempt{}, err
	}
	return attempt, tx.Commit(ctx)
}

func (s *Store) RecordDeliveryReclaimStage(ctx context.Context, item Task, attempt DeliveryAttempt, stage string, tier string) error {
	if stage != "probe" && stage != "refresh" && stage != "relogin" && stage != "publish" {
		return errors.New("invalid reclaim stage")
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
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		WHERE task.id=$1 AND task.lease_token=$2 AND task.status='running' AND task.lease_expires_at>now()
		AND asset.id=$3 AND membership.state='active' AND batch.status<>'ended'
		FOR UPDATE OF task,asset,membership,batch`, item.ID, item.LeaseToken, item.OAuthAssetID).Scan(&currentAttempt, &currentGeneration); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLeaseLost
		}
		return err
	}
	if currentGeneration != attempt.Generation || currentAttempt != attempt.ID {
		return ErrDeliveryAttemptSuperseded
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_tasks SET reclaim_stage=$3,reclaim_tier=NULLIF($4,''),updated_at=now(),version=version+1 WHERE id=$1 AND lease_token=$2 AND status='running'`, item.ID, item.LeaseToken, stage, tier); err != nil {
		return err
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.DeliveryAttemptSettled, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "oauth_attempt", EntityID: attempt.ID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.DeliveryAttemptDetails{Generation: attempt.Generation, AttemptNo: attempt.AttemptNo, Result: stage, Stage: "reclaim", Status: "pending"}, IdempotencyKey: attempt.ID + ":stage:" + stage}); err != nil {
		return err
	}
	var cardID string
	if err = tx.QueryRow(ctx, `SELECT card.id::text FROM tsw_cards card JOIN tsw_orders ord ON ord.card_id=card.id WHERE ord.oauth_asset_id=$1::uuid`, item.OAuthAssetID).Scan(&cardID); err != nil {
		return err
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.PublicReclaimUpdated, Actor: audit.ActorSystem, RetentionScopeID: cardID, EntityType: "card", EntityID: cardID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.PublicAccessDetails{Action: "reclaim_status", Result: "checking", Status: stage}, IdempotencyKey: attempt.ID + ":public-stage:" + stage}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishDeliveryReclaim(ctx context.Context, item Task, attempt DeliveryAttempt, target DeliveryReclaimTarget, generated platform.DeliveryCredentialSet, probe platform.DeliveryLiveness, tier string, noAction, unavailable bool) error {
	if tier == "" {
		tier = "unrecoverable"
	}
	payload := map[string]any{
		"refresh_token": generated.RefreshToken, "access_token": generated.AccessToken,
		"id_token": generated.IDToken, "expires_in": generated.ExpiresIn,
		"scope": generated.Scope, "workspace_id": generated.WorkspaceID,
		"platform_subject_id": generated.PlatformSubjectID,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(encoded)
	success := !noAction && strings.TrimSpace(generated.RefreshToken) != "" && strings.TrimSpace(generated.AccessToken) != "" && strings.TrimSpace(generated.IDToken) != "" && strings.TrimSpace(target.PlatformSubjectID) != "" && strings.EqualFold(strings.TrimSpace(generated.PlatformSubjectID), strings.TrimSpace(target.PlatformSubjectID)) && probe.Status == oauthdomain.ProbeOK && probe.HTTPStatus >= 200 && probe.HTTPStatus < 300 && strings.EqualFold(strings.TrimSpace(probe.WorkspaceID), strings.TrimSpace(target.PlatformWorkspace)) && strings.EqualFold(strings.TrimSpace(probe.PlatformSubjectID), strings.TrimSpace(target.PlatformSubjectID))
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentAttempt string
	var currentGeneration int64
	if err = tx.QueryRow(ctx, `SELECT asset.current_attempt_id::text,asset.current_generation
		FROM tsw_oauth_assets asset JOIN tsw_tasks task ON task.oauth_asset_id=asset.id
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		WHERE task.id=$1 AND task.lease_token=$2 AND task.status='running' AND task.lease_expires_at>now() AND asset.id=$3
		AND membership.state='active' AND batch.status<>'ended'
		FOR UPDATE OF task,asset,membership,batch`, item.ID, item.LeaseToken, item.OAuthAssetID).Scan(&currentAttempt, &currentGeneration); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLeaseLost
		}
		return err
	}
	if currentGeneration != attempt.Generation || currentAttempt != attempt.ID {
		return ErrDeliveryAttemptSuperseded
	}
	assetStatus := "unavailable"
	taskStatus := "failed"
	resultCode := tier
	if noAction {
		assetStatus = "ready"
		taskStatus = "succeeded"
		resultCode = "probe_ok"
	} else if success {
		resultCode = tier
		taskStatus = "succeeded"
		var versionID string
		if err = tx.QueryRow(ctx, `INSERT INTO tsw_delivery_versions(oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, item.OAuthAssetID, attempt.Generation, encoded, hash[:], probe.PlatformSubjectID, target.WorkspaceID).Scan(&versionID); err != nil {
			return err
		}
		updated, updateErr := tx.Exec(ctx, `UPDATE tsw_orders SET current_delivery_version_id=$2,updated_at=now(),version=version+1 WHERE id=$1 AND oauth_asset_id=$3 AND current_delivery_version_id=$4`, target.OrderID, versionID, item.OAuthAssetID, target.CurrentVersionID)
		if updateErr != nil {
			return updateErr
		}
		if updated.RowsAffected() != 1 {
			return ErrDeliveryAttemptSuperseded
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_public_tokens SET revoked_at=now(),revocation_reason='reclaim_published' WHERE order_id=$1 AND revoked_at IS NULL`, target.OrderID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_attempts SET published_version_id=$2 WHERE id=$1`, attempt.ID, versionID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET current_delivery_version_id=$2,status='ready',platform_subject_id=$3,liveness_status='ok',liveness_http_status=$4,liveness_error_code=NULL,liveness_origin='reclaim',probed_at=$5,unavailable_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1 AND current_delivery_version_id=$6`, item.OAuthAssetID, versionID, target.PlatformSubjectID, probe.HTTPStatus, probe.ObservedAt, target.CurrentVersionID); err != nil {
			return err
		}
	}
	if unavailable && !success {
		resultCode = "unrecoverable"
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_attempts SET state=CASE WHEN $2='succeeded' THEN 'published' ELSE 'failed' END,outcome_code=$3,finished_at=now() WHERE id=$1 AND state='running'`, attempt.ID, taskStatus, resultCode); err != nil {
		return err
	}
	if !success {
		retryable := probe.Status == oauthdomain.ProbeUnknown || probe.Status == oauthdomain.ProbeTransientFailure || probe.Status == oauthdomain.ProbeRateLimited || probe.HTTPStatus == 0
		if retryable && item.AttemptNo < 3 {
			taskStatus = "retry_wait"
			assetStatus = "reclaiming"
		}
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET status=$2,liveness_status=NULLIF($3,''),liveness_http_status=NULLIF($4,0),liveness_error_code=NULLIF($5,''),liveness_origin='reclaim',probed_at=$6,unavailable_reason=CASE WHEN $2='unavailable' THEN NULLIF($5,'') WHEN $2='reclaiming' THEN 'reclaim_in_progress' ELSE NULL END,updated_at=now(),version=version+1 WHERE id=$1`, item.OAuthAssetID, assetStatus, string(probe.Status), probe.HTTPStatus, probe.ErrorCode, probe.ObservedAt); err != nil {
			return err
		}
	} else if noAction {
		if _, err = tx.Exec(ctx, `UPDATE tsw_oauth_assets SET status='ready',liveness_status='ok',liveness_http_status=$2,liveness_error_code=NULL,liveness_origin='reclaim',probed_at=$3,unavailable_reason=NULL,updated_at=now(),version=version+1 WHERE id=$1`, item.OAuthAssetID, probe.HTTPStatus, probe.ObservedAt); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE tsw_tasks SET status=$3,reclaim_tier=$4,reclaim_result=$5,reclaim_probe_status=NULLIF($6,''),reclaim_http_status=NULLIF($7,0),reclaim_stage='publish',available_at=CASE WHEN $3='retry_wait' THEN now()+interval '5 seconds' ELSE available_at END,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=CASE WHEN $3='retry_wait' THEN NULL ELSE now() END,updated_at=now(),version=version+1 WHERE id=$1 AND lease_token=$2 AND status='running'`, item.ID, item.LeaseToken, taskStatus, tier, resultCode, string(probe.Status), probe.HTTPStatus); err != nil {
		return err
	}
	outcome := audit.OutcomeFailed
	if taskStatus == "succeeded" {
		outcome = audit.OutcomeSucceeded
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.DeliveryAttemptSettled, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "oauth_attempt", EntityID: attempt.ID, Outcome: outcome, CorrelationID: item.CorrelationID, Details: audit.DeliveryAttemptDetails{Generation: attempt.Generation, AttemptNo: attempt.AttemptNo, Result: resultCode, Stage: "reclaim", Status: string(probe.Status), HTTPStatus: probe.HTTPStatus, ErrorCode: probe.ErrorCode}, IdempotencyKey: attempt.ID + ":reclaim-settled"}); err != nil {
		return err
	}
	if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.PublicReclaimUpdated, Actor: audit.ActorSystem, RetentionScopeID: target.CardID, EntityType: "card", EntityID: target.CardID, Outcome: outcome, CorrelationID: item.CorrelationID, Details: audit.PublicAccessDetails{Action: "reclaim_status", Result: reclaimAuditResult(tier, resultCode, taskStatus, noAction), Reason: resultCode}, IdempotencyKey: attempt.ID + ":public-reclaim-updated"}); err != nil {
		return err
	}
	if taskStatus == "succeeded" {
		if _, err = audit.Write(ctx, tx, audit.Event{Type: audit.DeliveryPublished, Actor: audit.ActorSystem, RetentionScopeID: item.WorkspaceID, EntityType: "oauth_asset", EntityID: item.OAuthAssetID, Outcome: audit.OutcomeSucceeded, CorrelationID: item.CorrelationID, Details: audit.DeliveryAttemptDetails{Generation: attempt.Generation, AttemptNo: attempt.AttemptNo, Result: resultCode, Stage: "reclaim", Status: "ok", HTTPStatus: probe.HTTPStatus}, IdempotencyKey: item.OAuthAssetID + ":reclaim:" + fmt.Sprint(attempt.Generation)}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func reclaimAuditResult(tier, resultCode, taskStatus string, noAction bool) string {
	if noAction || tier == "probe_ok" {
		return "healthy"
	}
	if resultCode == "unrecoverable" || tier == "unrecoverable" {
		return "unrecoverable"
	}
	if taskStatus == "succeeded" && (tier == "token_refresh" || tier == "full_relogin") {
		return "restored"
	}
	return "unknown"
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
		JOIN tsw_batch_memberships membership ON membership.id=asset.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		WHERE task.id=$1 AND task.lease_token=$2 AND task.status='running' AND task.lease_expires_at>now() AND asset.id=$3
		AND membership.state='active' AND batch.status<>'ended'
		FOR UPDATE OF task,asset,membership,batch`, item.ID, item.LeaseToken, item.OAuthAssetID).Scan(&currentAttempt, &currentGeneration); err != nil {
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
