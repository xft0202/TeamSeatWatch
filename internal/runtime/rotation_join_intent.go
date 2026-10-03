package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

// rotationJoinIntent is an immutable original obligation, never permission to
// execute, joined membership, credentials, or deliverability. Recovery reads
// deliberately retain it after source/authorization/proof drift.
type rotationJoinIntent struct {
	slotID, previewID, workspaceID, ownerID, candidateAccountID                  uuid.UUID
	originalPlatformMemberID, candidateIdentifier, seatType, authorizationDigest string
	authorizedSession, releasedVerificationID                                    uuid.UUID
	epochs                                                                       map[string]int64
	createdAt                                                                    time.Time
}

func rotationJoinOwnerLegal(ctx context.Context, db rotationRow, owner ownerContext) error {
	var legal bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_owner_sessions s JOIN public.tsw_owners o ON o.id=s.owner_id WHERE s.id=$1 AND s.owner_id=$2 AND s.auth_version=o.auth_version AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())`, owner.SessionID, owner.OwnerID).Scan(&legal)
	if err != nil {
		return err
	}
	if !legal {
		return removalFailure("owner_session_inactive")
	}
	return nil
}

func readRotationJoinIntent(ctx context.Context, db rotationRow, owner ownerContext, previewID, slotID uuid.UUID) (rotationJoinIntent, error) {
	var out rotationJoinIntent
	var epochs []byte
	err := db.QueryRow(ctx, `SELECT slot_id,preview_id,workspace_id,owner_id,candidate_account_id,original_platform_member_id,candidate_identifier,seat_type,authorization_digest,authorized_session,epoch_versions,released_verification_id,created_at FROM public.tsw_rotation_candidate_join_intents WHERE slot_id=$1 AND preview_id=$2 AND owner_id=$3 AND EXISTS(SELECT 1 FROM public.tsw_owner_sessions s JOIN public.tsw_owners o ON o.id=s.owner_id WHERE s.id=$4 AND s.owner_id=$3 AND s.auth_version=o.auth_version AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())`, slotID, previewID, owner.OwnerID, owner.SessionID).Scan(&out.slotID, &out.previewID, &out.workspaceID, &out.ownerID, &out.candidateAccountID, &out.originalPlatformMemberID, &out.candidateIdentifier, &out.seatType, &out.authorizationDigest, &out.authorizedSession, &epochs, &out.releasedVerificationID, &out.createdAt)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(epochs, &out.epochs); err != nil {
		return rotationJoinIntent{}, err
	}
	return out, nil
}

// loadRotationJoinIntent is observation-only. Only the current Owner session is
// checked; stale original authority must not erase a recovery obligation.
func (h *OwnerAuthHandler) loadRotationJoinIntent(ctx context.Context, owner ownerContext, previewID, slotID uuid.UUID) (rotationJoinIntent, error) {
	oid, err := uuid.Parse(owner.OwnerID)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	gate := &removalGate{conn: conn}
	defer gate.close()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock_shared(hashtextextended('tsw.rotation.action.owner/'||$1::text,0))`, oid.String()); err != nil {
		return rotationJoinIntent{}, err
	}
	if err = rotationJoinOwnerLegal(ctx, conn, owner); err != nil {
		return rotationJoinIntent{}, err
	}
	return readRotationJoinIntent(ctx, conn, owner, previewID, slotID)
}

func (h *OwnerAuthHandler) reserveRotationJoinIntent(ctx context.Context, owner ownerContext, previewID, slotID uuid.UUID) (rotationJoinIntent, error) {
	original, err := h.loadRotationJoinIntent(ctx, owner, previewID, slotID)
	if err == nil {
		return original, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return rotationJoinIntent{}, err
	}
	oid, err := uuid.Parse(owner.OwnerID)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	a, err := loadRemovalAuthorization(ctx, h.pool, oid, previewID)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	keys := rotationAuthorizationKeys(oid, a.preview)
	gate, err := h.lockRemovalGate(ctx, a.preview.WorkspaceId, keys)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	defer gate.close()
	tx, versions, err := writerfence.BeginLockedOnConn(ctx, gate.conn, keys)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	defer tx.Rollback(ctx)
	if err = rotationJoinOwnerLegal(ctx, tx, owner); err != nil {
		return rotationJoinIntent{}, err
	}
	// A racing identical reservation is still observation-only, not reauthorized.
	original, err = readRotationJoinIntent(ctx, tx, owner, previewID, slotID)
	if err == nil {
		return original, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return rotationJoinIntent{}, err
	}
	access, personal, b, _, err := h.removalLocalFacts(ctx, tx, a, owner, versions)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	// Keep the checked credential bindings and DB deadlines; source gates prevent
	// rebinding, but clocks can still invalidate them without an epoch change.
	var personalDBExpiry, workspaceDBExpiry time.Time
	err = tx.QueryRow(ctx, `SELECT ms.expires_at,wt.expires_at FROM public.tsw_mother_personal_sessions ms JOIN public.tsw_selected_workspace_tokens wt ON wt.mother_account_id=ms.mother_account_id AND wt.session_generation=ms.generation AND wt.secret_revision=ms.secret_revision WHERE ms.mother_account_id=$1 AND ms.secret_revision=$2 AND ms.generation=$3 AND wt.workspace_id=$4 AND wt.discovery_run_id=$5 AND wt.exchange_id=$6 AND wt.attempt=$7 AND wt.status='ready'`, b.motherID, b.revision, b.generation, b.workspaceID, b.run, b.exchangeID, b.attempt).Scan(&personalDBExpiry, &workspaceDBExpiry)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	var candidate, originalAccount, evidence uuid.UUID
	var member, identifier, seat string
	err = tx.QueryRow(ctx, `SELECT s.candidate_account_id,s.original_account_id,s.platform_member_id,s.identifier,s.seat_type,s.verification_id FROM public.tsw_rotation_released_slots s JOIN public.tsw_rotation_removal_evidence e ON e.id=s.verification_id WHERE s.id=$1 AND s.preview_id=$2 AND s.workspace_id=$3 AND e.slot_id=s.id AND e.lease_epoch=s.lease_epoch AND e.authorization_digest=$4 AND e.observed_at<=clock_timestamp()`, slotID, previewID, a.preview.WorkspaceId, a.digest).Scan(&candidate, &originalAccount, &member, &identifier, &seat, &evidence)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	matchedSlot, matchedAssignment, matchedCandidate := false, false, false
	for _, s := range a.preview.Slots {
		if s.PlatformMemberId == member && s.AccountId == originalAccount && s.Identifier == identifier && s.SeatType == seat && s.Decision == "replaceable" {
			matchedSlot = true
		}
	}
	for _, assignment := range a.assignments {
		if assignment.PlatformMemberId == member && assignment.AccountId == candidate {
			matchedAssignment = true
		}
	}
	var candidateIdentifier string
	for _, c := range a.preview.Candidates {
		if c.AccountId == candidate && c.Decision == "eligible" && c.SeatType == seat && seat == "prolite" && !c.EverUsed && c.ProtectionStatus == "none" && c.DeliveryStatus == "join_candidate_pending_first_probe" {
			matchedCandidate = true
			candidateIdentifier = c.Identifier
		}
	}
	if !matchedSlot || !matchedAssignment || !matchedCandidate {
		return rotationJoinIntent{}, removalFailure("original_candidate_scope_changed")
	}
	var eligible bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_target_accounts a JOIN public.tsw_target_credentials c ON c.target_account_id=a.id WHERE a.id=$1 AND a.identifier=$2 AND a.status='active' AND a.version=$3 AND c.version=$4 AND c.material_status='complete' AND c.materials_sealed AND (SELECT count(*) FROM public.tsw_target_accounts same WHERE same.identifier=a.identifier)=1
 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_usage_ledger u WHERE u.target_account_id=a.id AND (u.ever_used OR u.usage_state<>'never_used'))
 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_effective_protections protection WHERE protection.target_account_id=a.id AND protection.status<>'none')
 AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_memberships m JOIN public.tsw_oauth_assets asset ON asset.membership_id=m.id JOIN public.tsw_delivery_versions delivered ON delivered.oauth_asset_id=asset.id WHERE m.target_account_id=a.id))`, candidate, candidateIdentifier, a.preview.SourceRevisions["account:"+candidate.String()], a.preview.SourceRevisions["credential:"+candidate.String()]).Scan(&eligible)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	if !eligible {
		return rotationJoinIntent{}, removalFailure("candidate_local_facts_changed")
	}
	previouslyUsed, err := rotationPreviouslyUsed(ctx, tx, candidate, a.preview.WorkspaceId)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	if previouslyUsed {
		return rotationJoinIntent{}, removalFailure("candidate_usage_history_changed")
	}
	epochs, err := json.Marshal(a.epochs)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	// Preserve the helpers' decoded validity windows and exact DB bindings at
	// the write, not merely at preflight; never refresh original authority.
	tag, err := tx.Exec(ctx, `INSERT INTO public.tsw_rotation_candidate_join_intents(slot_id,preview_id,workspace_id,owner_id,candidate_account_id,original_platform_member_id,candidate_identifier,seat_type,authorization_digest,authorized_session,epoch_versions,released_verification_id)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 WHERE EXISTS(SELECT 1 FROM public.tsw_owner_sessions s JOIN public.tsw_owners o ON o.id=s.owner_id WHERE s.id=$13 AND s.owner_id=$4 AND s.auth_version=o.auth_version AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())
 AND $14::timestamptz > clock_timestamp()+interval '1 minute'
 AND $15::timestamptz > clock_timestamp()+interval '30 seconds'
 AND EXISTS(SELECT 1 FROM public.tsw_mother_personal_sessions ms WHERE ms.mother_account_id=$16 AND ms.secret_revision=$17 AND ms.generation=$18 AND ms.expires_at=$26 AND ms.expires_at>clock_timestamp())
 AND EXISTS(SELECT 1 FROM public.tsw_selected_workspace_tokens wt WHERE wt.mother_account_id=$19 AND wt.workspace_id=$20 AND wt.discovery_run_id=$21 AND wt.session_generation=$22 AND wt.secret_revision=$23 AND wt.exchange_id=$24 AND wt.attempt=$25 AND wt.status='ready' AND wt.expires_at=$27 AND wt.expires_at>clock_timestamp()+interval '30 seconds')`, slotID, previewID, a.preview.WorkspaceId, oid, candidate, member, candidateIdentifier, seat, a.digest, a.session, epochs, evidence, owner.SessionID, personal.ExpiresAt, access.ExpiresAt, b.motherID, b.revision, b.generation, b.motherID, b.workspaceID, b.run, b.generation, b.revision, b.exchangeID, b.attempt, personalDBExpiry, workspaceDBExpiry)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	if tag.RowsAffected() != 1 {
		return rotationJoinIntent{}, removalFailure("reservation_authority_expired")
	}
	original, err = readRotationJoinIntent(ctx, tx, owner, previewID, slotID)
	if err != nil {
		return rotationJoinIntent{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return rotationJoinIntent{}, err
	}
	return original, nil
}
