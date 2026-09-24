package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/identity"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

type Service struct {
	pool    *pgxpool.Pool
	keyRing auth.KeyRing
}

func NewService(pool *pgxpool.Pool, keyRing auth.KeyRing) *Service {
	return &Service{pool: pool, keyRing: keyRing}
}

// PublishReadTx appends endpoint facts and recomputes their projection inside
// the task-owned completion transaction. The caller must lock and fence the task.
func (s *Service) PublishReadTx(ctx context.Context, tx pgx.Tx, workspaceID string, results []platform.Result) error {
	for _, result := range results {
		if result.ObservedAt.IsZero() {
			return errors.New("platform observation time is required")
		}
		if result.Endpoint == platform.EndpointMembers {
			outcome := validatedOutcome(result)
			if outcome == platform.OutcomeOperational || outcome == platform.OutcomeDeactivated || outcome == platform.OutcomeNotFound {
				if err := insertObservation(ctx, tx, workspaceID, result); err != nil {
					return err
				}
			} else if err := insertMemberReadError(ctx, tx, workspaceID, result); err != nil {
				return err
			}
			if membersSnapshotAllowed(result) {
				if err := s.insertSnapshot(ctx, tx, workspaceID, result); err != nil {
					return err
				}
			}
			continue
		}
		if err := insertObservation(ctx, tx, workspaceID, result); err != nil {
			return err
		}
	}
	return recomputeTx(ctx, tx, workspaceID)
}

type ManualVerification struct {
	WorkspaceID string
	OwnerID     string
	Source      string
	Conclusion  string
	ObservedAt  time.Time
	ActiveUntil *time.Time
}

// RecordManualVerificationTx appends Owner evidence and derives the projection
// from all unexpired facts; an older manual timestamp cannot overwrite newer evidence.
func (s *Service) RecordManualVerificationTx(ctx context.Context, tx pgx.Tx, verification ManualVerification) (string, error) {
	now := time.Now().UTC()
	validConclusion := verification.Conclusion == "deactivated" || verification.Conclusion == "recovered"
	validExpiration := verification.Conclusion == "expiration_corrected" && verification.ActiveUntil != nil
	if verification.WorkspaceID == "" || verification.OwnerID == "" ||
		(verification.Source != "platform_ui" && verification.Source != "platform_subscription_page") ||
		(!validConclusion && !validExpiration) || (validConclusion && verification.ActiveUntil != nil) ||
		verification.ObservedAt.IsZero() || verification.ObservedAt.After(now) ||
		verification.ObservedAt.Before(now.Add(-7*24*time.Hour)) {
		return "", errors.New("manual verification is invalid")
	}
	outcome := "manual_" + verification.Conclusion
	var observationID string
	err := tx.QueryRow(ctx, `
		INSERT INTO tsw_workspace_observations (
			workspace_id,observation_type,source_kind,owner_id,source_endpoint,
			observed_at,expires_at,outcome_code,active_until
		) VALUES ($1,'manual_verification','owner',$2,$3,$4::timestamptz,$4::timestamptz+interval '7 days',$5,$6)
		RETURNING id`, verification.WorkspaceID, verification.OwnerID, verification.Source,
		verification.ObservedAt, outcome, verification.ActiveUntil).Scan(&observationID)
	if err != nil {
		return "", err
	}
	if err := recomputeTx(ctx, tx, verification.WorkspaceID); err != nil {
		return "", err
	}
	return observationID, nil
}

// RunRetentionTx executes one idempotent retention cycle inside the task
// completion transaction. The cycle key is the durable scheduler fence.
func (s *Service) RunRetentionTx(ctx context.Context, tx pgx.Tx, cycleKey string, limit int) error {
	if cycleKey == "" || limit <= 0 || limit > 1000 {
		return errors.New("retention cycle is invalid")
	}
	var runID, status string
	if err := tx.QueryRow(ctx, `
		INSERT INTO tsw_retention_runs(cycle_key,status)
		VALUES ($1,'running') ON CONFLICT (cycle_key) DO NOTHING
		RETURNING id::text,status`, cycleKey).Scan(&runID, &status); errors.Is(err, pgx.ErrNoRows) {
		if err := tx.QueryRow(ctx, `SELECT id::text,status FROM tsw_retention_runs WHERE cycle_key=$1 FOR UPDATE`, cycleKey).Scan(&runID, &status); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if status == "succeeded" {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT binding.workspace_id::text
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		WHERE membership.retention_due_at<=now()
		ORDER BY 1 LIMIT $1`, limit)
	if err != nil {
		return err
	}
	workspaceIDs := make([]string, 0, limit)
	for rows.Next() {
		var workspaceID string
		if err := rows.Scan(&workspaceID); err != nil {
			rows.Close()
			return err
		}
		workspaceIDs = append(workspaceIDs, workspaceID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, workspaceID := range workspaceIDs {
		if err := s.DeleteExpiredWorkspaceTx(ctx, tx, workspaceID); err != nil {
			return err
		}
	}
	if len(workspaceIDs) == 0 {
		if err := s.deleteGlobalExpiredTx(ctx, tx); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_retention_runs SET status='succeeded',finished_at=now(),deleted_workspaces=$2 WHERE id=$1`, runID, len(workspaceIDs))
	return err
}

func (s *Service) deleteGlobalExpiredTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SET LOCAL tsw.retention_cleanup='on'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_audit_events WHERE expires_at<=now()`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_rate_limit_buckets WHERE expires_at<=now()`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_owner_recovery_codes WHERE used_at IS NOT NULL AND used_at<=now()-interval '7 days'`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM tsw_owner_sessions WHERE absolute_expires_at<=now() OR revoked_at<=now()-interval '7 days'`)
	return err
}

// DeleteExpired recomputes each affected projection before deleting expired
// supporting facts, so retained projections never reference deleted evidence.
func (s *Service) DeleteExpired(ctx context.Context, limit int) (int, error) {
	if limit <= 0 || limit > 1000 {
		return 0, errors.New("cleanup limit is invalid")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT workspace_id FROM (
			SELECT workspace_id FROM tsw_workspace_observations WHERE expires_at<=now()
			UNION SELECT workspace_id FROM tsw_workspace_member_snapshots WHERE expires_at<=now()
		) expired ORDER BY workspace_id LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	var workspaceIDs []string
	for rows.Next() {
		var workspaceID string
		if err := rows.Scan(&workspaceID); err != nil {
			rows.Close()
			return 0, err
		}
		workspaceIDs = append(workspaceIDs, workspaceID)
	}
	rows.Close()
	if rows.Err() != nil {
		return 0, rows.Err()
	}
	for _, workspaceID := range workspaceIDs {
		if err := s.DeleteExpiredWorkspaceTx(ctx, tx, workspaceID); err != nil {
			return 0, err
		}
	}
	return len(workspaceIDs), tx.Commit(ctx)
}

func (s *Service) DeleteExpiredWorkspaceTx(ctx context.Context, tx pgx.Tx, workspaceID string) error {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM tsw_workspace_projections WHERE workspace_id=$1 FOR UPDATE`, workspaceID); err != nil {
		return err
	}
	if err := recomputeTx(ctx, tx, workspaceID); err != nil {
		return err
	}
	if err := s.deleteExpiredRelationshipsTx(ctx, tx, workspaceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_workspace_member_snapshots WHERE workspace_id=$1 AND expires_at<=now()`, workspaceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_workspace_observations WHERE workspace_id=$1 AND expires_at<=now()`, workspaceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_audit_events WHERE retention_scope_type='workspace' AND retention_scope_id=$1 AND expires_at<=now()`, workspaceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_rate_limit_buckets WHERE expires_at<=now()`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_owner_recovery_codes WHERE used_at IS NOT NULL AND used_at<=now()-interval '7 days'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_owner_sessions WHERE (absolute_expires_at<=now() OR revoked_at<=now()-interval '7 days')`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_task_attempts attempt USING tsw_tasks task WHERE attempt.task_id=task.id AND task.workspace_id=$1 AND task.status IN ('succeeded','failed','interrupted') AND task.finished_at<=now()-interval '7 days'`, workspaceID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM tsw_tasks task WHERE task.workspace_id=$1 AND task.status IN ('succeeded','failed','interrupted') AND task.finished_at<=now()-interval '7 days' AND NOT EXISTS (SELECT 1 FROM tsw_tasks child WHERE child.parent_task_id=task.id)`, workspaceID)
	return err
}

func (s *Service) deleteExpiredRelationshipsTx(ctx context.Context, tx pgx.Tx, workspaceID string) error {
	if _, err := tx.Exec(ctx, `SET LOCAL tsw.retention_cleanup='on'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DROP TABLE IF EXISTS tsw_retention_candidates`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE tsw_retention_candidates ON COMMIT DROP AS
		SELECT membership.id AS membership_id, membership.batch_id, membership.target_account_id
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		WHERE binding.workspace_id=$1 AND membership.state='removed' AND membership.retention_due_at<=now()
		AND NOT EXISTS (
			SELECT 1 FROM tsw_tasks task
			WHERE (task.membership_id=membership.id OR task.oauth_asset_id IN (SELECT asset.id FROM tsw_oauth_assets asset WHERE asset.membership_id=membership.id)
				OR task.operation_target_id IN (SELECT target.id FROM tsw_operation_targets target WHERE target.membership_id=membership.id))
				AND task.status IN ('queued','retry_wait','running')
		)`, workspaceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_audit_events event
		WHERE (event.retention_scope_type='membership' AND event.retention_scope_id IN (SELECT membership_id FROM tsw_retention_candidates))
		OR (event.retention_scope_type='card' AND event.retention_scope_id IN (SELECT card.id FROM tsw_cards card JOIN tsw_retention_candidates candidate ON candidate.membership_id=card.membership_id))`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_tasks task
		WHERE task.membership_id IN (SELECT membership_id FROM tsw_retention_candidates)
		   OR task.oauth_asset_id IN (SELECT asset.id FROM tsw_oauth_assets asset JOIN tsw_retention_candidates candidate ON candidate.membership_id=asset.membership_id)
		   OR task.operation_target_id IN (SELECT target.id FROM tsw_operation_targets target JOIN tsw_retention_candidates candidate ON candidate.membership_id=target.membership_id)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_operation_targets target
		WHERE target.membership_id IN (SELECT membership_id FROM tsw_retention_candidates)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_operation_targets target
		USING tsw_batch_memberships membership, tsw_retention_candidates candidate
		WHERE membership.id=candidate.membership_id AND target.id=membership.join_operation_target_id`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_operations operation
		WHERE operation.batch_id IN (SELECT batch_id FROM tsw_retention_candidates)
		  AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships membership WHERE membership.batch_id=operation.batch_id)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_batches batch
		USING tsw_mother_workspace_bindings binding
		WHERE batch.binding_id=binding.id AND binding.workspace_id=$1 AND batch.status='ended'
		  AND batch.service_ended_at<=now()-interval '7 days'
		  AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships membership WHERE membership.batch_id=batch.id)
		  AND NOT EXISTS (SELECT 1 FROM tsw_operations operation WHERE operation.batch_id=batch.id)`, workspaceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_target_credentials credentials
		WHERE credentials.target_account_id IN (SELECT target_account_id FROM tsw_retention_candidates)
		  AND NOT EXISTS (SELECT 1 FROM tsw_batch_targets batch_target WHERE batch_target.target_account_id=credentials.target_account_id)
		  AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships membership WHERE membership.target_account_id=credentials.target_account_id)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tsw_target_accounts target
		WHERE target.id IN (SELECT target_account_id FROM tsw_retention_candidates)
		  AND NOT EXISTS (SELECT 1 FROM tsw_batch_targets batch_target WHERE batch_target.target_account_id=target.id)
		  AND NOT EXISTS (SELECT 1 FROM tsw_batch_memberships membership WHERE membership.target_account_id=target.id)`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE tsw_recovery_gate SET last_cleanup_at=now(),last_cleanup_cycle=to_char(now(),'YYYY-MM-DD') WHERE id=true`)
	return err
}

func insertObservation(ctx context.Context, tx pgx.Tx, workspaceID string, result platform.Result) error {
	kind := "exchange"
	switch result.Endpoint {
	case platform.EndpointExchange:
		kind = "exchange"
	case platform.EndpointSubscription:
		kind = "subscription"
	case platform.EndpointCapacity:
		kind = "capacity"
	case platform.EndpointJoin:
		kind = "join"
	case platform.EndpointMembers:
		kind = "members"
	case platform.EndpointPendingInvite:
		kind = "pending_invites"
	default:
		return errors.New("unsupported observation endpoint")
	}
	outcome := validatedOutcome(result)
	var activeUntil *time.Time
	var seatLimit, memberCount, pendingInviteCount *int
	if outcome == platform.OutcomeOperational {
		switch result.Endpoint {
		case platform.EndpointSubscription:
			activeUntil = result.ActiveUntil
		case platform.EndpointCapacity:
			seatLimit, memberCount = result.SeatLimit, result.MemberCount
		case platform.EndpointPendingInvite:
			pendingInviteCount = result.PendingInviteCount
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO tsw_workspace_observations (workspace_id,observation_type,source_kind,source_endpoint,observed_at,expires_at,outcome_code,active_until,seat_limit,member_count,pending_invite_count,payload_hash) VALUES ($1,$2,'platform',$3,$4::timestamptz,$4::timestamptz+interval '7 days',$5,$6,$7,$8,$9,$10)`, workspaceID, kind, result.Endpoint, result.ObservedAt, outcome, activeUntil, seatLimit, memberCount, pendingInviteCount, resultHash(result))
	return err
}

func membersSnapshotAllowed(result platform.Result) bool {
	return result.Outcome != platform.OutcomeDeactivated && result.Outcome != platform.OutcomeNotFound &&
		(result.Outcome == platform.OutcomeOperational || len(result.Members) > 0 || result.Completeness != platform.Unknown)
}

func insertMemberReadError(ctx context.Context, tx pgx.Tx, workspaceID string, result platform.Result) error {
	outcome := result.Outcome
	if outcome == platform.OutcomeDeactivated || outcome == platform.OutcomeNotFound {
		outcome = platform.OutcomeIncomplete
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO tsw_workspace_observations (
			workspace_id,observation_type,source_kind,source_endpoint,observed_at,
			expires_at,outcome_code,payload_hash
		) VALUES ($1,'read_error','platform','workspace_members',$2::timestamptz,$2::timestamptz+interval '7 days',$3,$4)`,
		workspaceID, result.ObservedAt, outcome, resultHash(result))
	return err
}

func (s *Service) insertSnapshot(ctx context.Context, tx pgx.Tx, workspaceID string, result platform.Result) error {
	completeness := result.Completeness
	if completeness == "" {
		completeness = platform.Unknown
	}
	var snapshotID string
	err := tx.QueryRow(ctx, `INSERT INTO tsw_workspace_member_snapshots (workspace_id,source_endpoint,observed_at,completeness,declared_member_count,pending_invite_count,payload_hash,expires_at) VALUES ($1,'workspace_members',$2::timestamptz,$3,$4,$5,$6,$2::timestamptz+interval '7 days') RETURNING id`, workspaceID, result.ObservedAt, completeness, result.MemberCount, result.PendingInviteCount, resultHash(result)).Scan(&snapshotID)
	if err != nil {
		return err
	}
	for _, member := range result.Members {
		normalized, keyVersion, fingerprint, err := identity.Fingerprint(s.keyRing, identity.WorkspaceEntry, member.Identifier)
		if err != nil {
			return err
		}
		var platformID interface{} = member.PlatformMemberID
		if member.PlatformMemberID == "" {
			platformID = nil
		}
		var role interface{} = member.Role
		if member.Role == "" {
			role = nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO tsw_workspace_member_snapshot_entries (snapshot_id,entry_kind,platform_member_id,member_identifier,identifier_hmac,identifier_key_version,platform_status,platform_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, snapshotID, member.Kind, platformID, normalized, fingerprint[:], keyVersion, member.Status, role)
		if err != nil {
			return err
		}
	}
	return nil
}

func recomputeTx(ctx context.Context, tx pgx.Tx, workspaceID string) error {
	rows, err := tx.Query(ctx, `SELECT id,source_endpoint,source_kind,outcome_code,observed_at,expires_at FROM tsw_workspace_observations WHERE workspace_id=$1 AND expires_at>now() ORDER BY observed_at DESC`, workspaceID)
	if err != nil {
		return err
	}
	observations := []Observation{}
	for rows.Next() {
		var item Observation
		if err := rows.Scan(&item.ID, &item.Endpoint, &item.Source, &item.Outcome, &item.ObservedAt, &item.ExpiresAt); err != nil {
			rows.Close()
			return err
		}
		observations = append(observations, item)
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	projection := Recompute(time.Now(), observations)
	var conclusion interface{}
	var expiry interface{}
	if projection.ConclusionObservationID != "" {
		conclusion = projection.ConclusionObservationID
		expiry = projection.EvidenceExpiresAt
	}
	_, err = tx.Exec(ctx, `UPDATE tsw_workspace_projections projection SET operational_state=$2,conclusion_observation_id=$3,evidence_expires_at=$4,active_until=COALESCE((SELECT active_until FROM tsw_workspace_observations WHERE workspace_id=$1 AND outcome_code='manual_expiration_corrected' AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),(SELECT active_until FROM tsw_workspace_observations WHERE workspace_id=$1 AND observation_type='subscription' AND outcome_code='operational' AND expires_at>now() ORDER BY observed_at DESC LIMIT 1)),capacity_observation_id=(SELECT id FROM tsw_workspace_observations WHERE workspace_id=$1 AND observation_type='capacity' AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),seat_limit=(SELECT seat_limit FROM tsw_workspace_observations WHERE workspace_id=$1 AND observation_type='capacity' AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),member_count=(SELECT member_count FROM tsw_workspace_observations WHERE workspace_id=$1 AND observation_type='capacity' AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),pending_invite_count=COALESCE((SELECT pending_invite_count FROM tsw_workspace_observations WHERE workspace_id=$1 AND observation_type='pending_invites' AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),(SELECT pending_invite_count FROM tsw_workspace_member_snapshots WHERE workspace_id=$1 AND expires_at>now() ORDER BY observed_at DESC LIMIT 1)),latest_snapshot_id=(SELECT id FROM tsw_workspace_member_snapshots WHERE workspace_id=$1 AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),updated_at=now(),version=projection.version+1 WHERE projection.workspace_id=$1`, workspaceID, projection.State, conclusion, expiry)
	return err
}

func validatedOutcome(result platform.Result) platform.Outcome {
	if (result.Outcome == platform.OutcomeDeactivated && result.HTTPStatus != 402) ||
		(result.Outcome == platform.OutcomeNotFound && result.HTTPStatus != 404) {
		return platform.OutcomeIncomplete
	}
	return result.Outcome
}

func resultHash(result platform.Result) []byte {
	// Member identifiers have their own versioned HMAC columns. The fact digest
	// covers every non-secret projected value without creating a dictionary oracle.
	payload, _ := json.Marshal(struct {
		Endpoint           platform.Endpoint
		Outcome            platform.Outcome
		HTTPStatus         int
		ObservedAt         string
		ActiveUntil        *time.Time
		SeatLimit          *int
		MemberCount        *int
		PendingInviteCount *int
		Completeness       platform.Completeness
		Entries            int
	}{
		Endpoint: result.Endpoint, Outcome: result.Outcome, HTTPStatus: result.HTTPStatus,
		ObservedAt: result.ObservedAt.UTC().Format(time.RFC3339Nano), ActiveUntil: result.ActiveUntil,
		SeatLimit: result.SeatLimit, MemberCount: result.MemberCount,
		PendingInviteCount: result.PendingInviteCount, Completeness: result.Completeness,
		Entries: len(result.Members),
	})
	sum := sha256.Sum256(payload)
	return sum[:]
}
