package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

type officialRotationSnapshot struct {
	ObservedAt     time.Time
	ActiveUntil    time.Time
	PaidDefault    int
	SeatTypeCounts map[string]int
	Members        []platform.Member
}

func compareOfficialRotationSnapshots(a, b platform.SelectedWorkspaceFacts) (officialRotationSnapshot, bool) {
	now := time.Now().UTC()
	normalize := func(f platform.SelectedWorkspaceFacts) (officialRotationSnapshot, bool) {
		result := f.Result
		if (f.Permission != "read" && f.Permission != "manage") || result.Outcome != platform.OutcomeOperational || result.Completeness != platform.Complete ||
			result.ObservedAt.IsZero() || result.ObservedAt.After(now) || result.ObservedAt.Before(now.Add(-5*time.Minute)) || result.ActiveUntil == nil || result.ActiveUntil.IsZero() ||
			result.SeatLimit == nil || *result.SeatLimit < 0 || result.MemberCount == nil || *result.MemberCount < 0 || result.PendingInviteCount == nil || *result.PendingInviteCount < 0 ||
			!validSelectedSeatTypeCounts(result.SeatTypeCounts) || len(result.SeatTypeCounts) != 4 {
			return officialRotationSnapshot{}, false
		}
		members, invites, occupied := 0, 0, 0
		items := append([]platform.Member(nil), result.Members...)
		seen := map[string]bool{}
		for _, item := range items {
			item.Identifier = strings.ToLower(strings.TrimSpace(item.Identifier))
			key := item.Kind + ":" + item.PlatformMemberID + ":" + item.Identifier
			if seen[key] || item.Identifier == "" || item.SeatType == "" {
				return officialRotationSnapshot{}, false
			}
			seen[key] = true
			switch item.Kind {
			case "member":
				if item.PlatformMemberID == "" {
					return officialRotationSnapshot{}, false
				}
				members++
				occupied++
			case "pending_invite":
				if item.PlatformMemberID != "" || item.Status != "pending" {
					return officialRotationSnapshot{}, false
				}
				invites++
			default:
				return officialRotationSnapshot{}, false
			}
		}
		if members != *result.MemberCount || invites != *result.PendingInviteCount {
			return officialRotationSnapshot{}, false
		}
		total := 0
		for _, count := range result.SeatTypeCounts {
			total += count
		}
		if total != occupied {
			return officialRotationSnapshot{}, false
		}
		sort.Slice(items, func(i, j int) bool {
			left, _ := json.Marshal(items[i])
			right, _ := json.Marshal(items[j])
			return string(left) < string(right)
		})
		return officialRotationSnapshot{ObservedAt: result.ObservedAt.UTC(), ActiveUntil: result.ActiveUntil.UTC(), PaidDefault: *result.SeatLimit, SeatTypeCounts: result.SeatTypeCounts, Members: items}, true
	}
	left, ok := normalize(a)
	if !ok {
		return officialRotationSnapshot{}, false
	}
	right, ok := normalize(b)
	if !ok {
		return officialRotationSnapshot{}, false
	}
	leftCompare, rightCompare := left, right
	leftCompare.ObservedAt, rightCompare.ObservedAt = time.Time{}, time.Time{}
	if rotationHash(leftCompare) != rotationHash(rightCompare) {
		return officialRotationSnapshot{}, false
	}
	if right.ObservedAt.After(left.ObservedAt) {
		left.ObservedAt = right.ObservedAt
	}
	return left, true
}

// officialRotationCapability mirrors the reference campaign's two independent
// read snapshots. It never mutates the platform and only emits evidence when
// the saved Personal discovery says owner and both snapshots agree exactly.
type officialRotationCapability struct{ handler *OwnerAuthHandler }

func (c officialRotationCapability) Evidence(ctx context.Context, owner uuid.UUID) (rotationEvidence, error) {
	if c.handler == nil || c.handler.selectedWorkspaceReader == nil {
		return rotationEvidence{}, errors.New("rotation evidence reader unavailable")
	}
	return c.handler.officialRotationEvidence(ctx, owner)
}

func (h *OwnerAuthHandler) officialRotationEvidence(ctx context.Context, owner uuid.UUID) (rotationEvidence, error) {
	var evidence rotationEvidence
	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return evidence, err
	}
	defer tx.Rollback(ctx)
	var workspaceID, motherID, run, generation uuid.UUID
	var verificationID, revision int64
	if err = tx.QueryRow(ctx, `SELECT workspace_id,mother_account_id,verification_id,visibility_run_id,session_generation,mother_revision
		FROM public.tsw_operation_selection_drafts WHERE owner_id=$1 AND step='complete'`, owner).Scan(&workspaceID, &motherID, &verificationID, &run, &generation, &revision); err != nil {
		return evidence, err
	}
	var platformID, role string
	if err = tx.QueryRow(ctx, `SELECT workspace.platform_workspace_id,visibility.workspace_role
		FROM public.tsw_mother_workspace_visibility visibility
		JOIN public.tsw_workspaces workspace ON workspace.id=visibility.workspace_id
		WHERE visibility.mother_account_id=$1 AND visibility.workspace_id=$2 AND visibility.run_id=$3 AND visibility.access_status='readable'`, motherID, workspaceID, run).Scan(&platformID, &role); err != nil {
		return evidence, err
	}
	if role != "owner" {
		return evidence, errors.New("current Workspace owner role is not proven")
	}
	binding := workspaceAccessBinding{motherID: motherID, workspaceID: workspaceID, run: run, generation: generation, revision: revision}
	access, binding, err := h.currentWorkspaceAccessTx(ctx, tx, binding, platformID, false)
	if err != nil {
		return evidence, err
	}
	if err = tx.Commit(ctx); err != nil {
		return evidence, err
	}
	first, err := h.selectedWorkspaceReader.VerifySelectedWorkspace(ctx, access, motherID.String(), platformID)
	if err != nil {
		return evidence, err
	}
	second, err := h.selectedWorkspaceReader.VerifySelectedWorkspace(ctx, access, motherID.String(), platformID)
	if err != nil {
		return evidence, err
	}
	snapshot, ok := compareOfficialRotationSnapshots(first, second)
	if !ok {
		return evidence, errors.New("independent Workspace evidence drifted or is incomplete")
	}
	return h.rotationEvidenceFromSnapshot(ctx, owner, workspaceID, motherID, generation, verificationID, binding, snapshot)
}

func (h *OwnerAuthHandler) rotationEvidenceFromSnapshot(ctx context.Context, owner, workspaceID, motherID, generation uuid.UUID, verificationID int64, binding workspaceAccessBinding, snapshot officialRotationSnapshot) (rotationEvidence, error) {
	evidence := rotationEvidence{WorkspaceID: workspaceID, MotherID: motherID, VerificationID: verificationID, ActiveUntil: snapshot.ActiveUntil, SeatTypeCounts: snapshot.SeatTypeCounts, Slots: map[string]rotationVerdict{}, Candidates: map[uuid.UUID]rotationVerdict{}, Invitations: map[string]rotationInvitationProof{}}
	expires := snapshot.ObservedAt.Add(5 * time.Minute)
	semantic := snapshot
	semantic.ObservedAt = time.Time{}
	snapshotID := rotationHash(struct {
		Domain        string
		WorkspaceID   uuid.UUID
		MotherID      uuid.UUID
		RunID         uuid.UUID
		Generation    uuid.UUID
		Revision      int64
		TokenAttempt  int64
		TokenExchange uuid.UUID
		Snapshot      officialRotationSnapshot
	}{"tsw.official_rotation_ab.v1", workspaceID, motherID, binding.run, binding.generation, binding.revision, binding.attempt, binding.exchangeID, semantic})
	evidence.Permission = rotationProof{Source: "official_owner_ab", EvidenceID: snapshotID, ObservedAt: snapshot.ObservedAt, ExpiresAt: expires}
	evidence.PermissionDecision = "manage"
	evidence.Counts = rotationProof{Source: "official_seat_type_counts_ab", EvidenceID: snapshotID, ObservedAt: snapshot.ObservedAt, ExpiresAt: expires}
	evidence.PaidDefault = rotationProof{Source: "official_paid_default_ab", EvidenceID: snapshotID, ObservedAt: snapshot.ObservedAt, ExpiresAt: expires}
	evidence.PaidDefaultEntitlement = snapshot.PaidDefault

	memberByIdentifier := map[string]platform.Member{}
	inviteByIdentifier := map[string]platform.Member{}
	for _, item := range snapshot.Members {
		identifier := strings.ToLower(strings.TrimSpace(item.Identifier))
		if item.Kind == "member" {
			memberByIdentifier[identifier] = item
		} else {
			inviteByIdentifier[identifier] = item
			evidence.Invitations[identifier] = rotationInvitationProof{rotationProof: rotationProof{Source: "official_invitation_ab", EvidenceID: rotationHash(struct{ Snapshot, Identifier, SeatType string }{snapshotID, identifier, item.SeatType}), ObservedAt: snapshot.ObservedAt, ExpiresAt: expires}, WorkspaceID: workspaceID, VerificationID: verificationID, Identifier: identifier, Status: "pending", SeatType: item.SeatType}
		}
	}
	for identifier, member := range memberByIdentifier {
		var accountID uuid.UUID
		var count int
		if err := h.pool.QueryRow(ctx, `SELECT count(*),COALESCE((array_agg(id ORDER BY id))[1],'00000000-0000-0000-0000-000000000000'::uuid) FROM public.tsw_target_accounts WHERE identifier=$1`, identifier).Scan(&count, &accountID); err != nil {
			return evidence, err
		}
		if count != 1 {
			continue
		}
		usage, protection, err := h.persistedRotationEvidence(ctx, accountID, workspaceID, snapshot.ObservedAt, expires)
		if err != nil {
			return evidence, err
		}
		decision, reason := "needs_verification", "usage_unknown"
		if protection.Status == "delivered" || protection.Status == "canceled_retired" {
			decision, reason = "retained", "global_delivery_protected"
		} else if blockingRotationProtection(protection.Status) {
			reason = "protection_blocks_rotation"
		} else if usage.State == "used" && usage.EverUsed {
			decision, reason = "replaceable", "persisted_used_unprotected"
		} else if usage.State == "never_used" && !usage.EverUsed {
			decision, reason = "retained", "never_used_retained"
		}
		evidence.Slots[member.PlatformMemberID] = rotationVerdict{rotationProof: rotationProof{Source: "official_member_ab", EvidenceID: rotationHash(struct{ Snapshot, Member string }{snapshotID, member.PlatformMemberID}), ObservedAt: snapshot.ObservedAt, ExpiresAt: expires}, AccountID: accountID, SeatType: member.SeatType, Usage: usage, Protection: protection, Decision: decision, Reason: reason}
	}

	var childrenJSON []byte
	var batchID uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT children,batch_id FROM public.tsw_operation_selection_drafts WHERE owner_id=$1 AND step='complete' AND workspace_id=$2 AND mother_account_id=$3 AND verification_id=$4`, owner, workspaceID, motherID, verificationID).Scan(&childrenJSON, &batchID); err != nil {
		return evidence, err
	}
	var children []ownerapi.OperationDraftChild
	if err := json.Unmarshal(childrenJSON, &children); err != nil {
		return evidence, err
	}
	for _, child := range children {
		var identifier string
		var accountVersion, credentialVersion int64
		var complete, delivered bool
		var identityCount int
		if err := h.pool.QueryRow(ctx, `SELECT account.identifier,account.version,credential.version,
			(account.status='active' AND credential.material_status='complete' AND credential.materials_sealed),
			(SELECT count(*) FROM public.tsw_target_accounts same WHERE same.identifier=account.identifier),
			EXISTS(SELECT 1 FROM public.tsw_batch_memberships m JOIN public.tsw_oauth_assets asset ON asset.membership_id=m.id JOIN public.tsw_delivery_versions delivery ON delivery.oauth_asset_id=asset.id WHERE m.target_account_id=account.id)
			FROM public.tsw_standby_child_memberships membership JOIN public.tsw_target_accounts account ON account.id=membership.target_account_id JOIN public.tsw_target_credentials credential ON credential.target_account_id=account.id WHERE membership.target_account_id=$1 AND membership.version=$2 AND membership.batch_id=$3`, child.AccountId, child.MembershipVersion, batchID).Scan(&identifier, &accountVersion, &credentialVersion, &complete, &identityCount, &delivered); err != nil {
			return evidence, err
		}
		usage, protection, err := h.persistedRotationEvidence(ctx, child.AccountId, workspaceID, snapshot.ObservedAt, expires)
		if err != nil {
			return evidence, err
		}
		absent, clear, err := rotationCandidateLedgerLookup(ctx, h.pool, child.AccountId, workspaceID)
		if err != nil {
			return evidence, err
		}
		invite := inviteByIdentifier[strings.ToLower(identifier)]
		_, alreadyMember := memberByIdentifier[strings.ToLower(identifier)]
		decision, reason := "excluded", "usage_evidence_missing"
		if clear && (absent || usage.State == "never_used" && !usage.EverUsed) && protection.Status == "none" && complete && !delivered && identityCount == 1 && !alreadyMember && invite.SeatType == "prolite" {
			if absent {
				// No observed first-use fact is not an observed zero. Only this
				// candidate-specific complete lookup can produce pre-join absence.
				usage.State = "unobserved_prejoin"
			}
			decision, reason = "eligible", "join_candidate_pending_first_probe"
			scope := rotationUsageAbsenceProof{rotationProof: rotationProof{Source: "persisted_usage_ledger_lookup", ObservedAt: usage.ObservedAt, ExpiresAt: usage.ExpiresAt}, WorkspaceID: workspaceID, AccountID: child.AccountId, MotherID: motherID, SessionGeneration: generation, VerificationID: verificationID, Identifier: identifier, AccountVersion: accountVersion, CredentialVersion: credentialVersion, MembershipVersion: child.MembershipVersion, LookupComplete: true, FirstUseRecordStatus: "absent"}
			scope.EvidenceID = rotationAbsenceEvidenceID(scope)
			usage.Absence = &scope
		}
		seatType := invite.SeatType
		if seatType == "" {
			decision, reason = "excluded", "invitation_seat_type_unverified"
		}
		evidence.Candidates[child.AccountId] = rotationVerdict{rotationProof: rotationProof{Source: "persisted_candidate_evidence", EvidenceID: rotationHash(struct {
			Snapshot string
			Account  uuid.UUID
			Usage    string
		}{snapshotID, child.AccountId, usage.EvidenceID}), ObservedAt: snapshot.ObservedAt, ExpiresAt: expires}, AccountID: child.AccountId, SeatType: seatType, Usage: usage, Protection: protection, Decision: decision, Reason: reason}
	}
	return evidence, nil
}

func (h *OwnerAuthHandler) persistedRotationEvidence(ctx context.Context, accountID, workspaceID uuid.UUID, observedAt, defaultExpiry time.Time) (rotationUsageProof, rotationProtectionProof, error) {
	usage := rotationUsageProof{rotationProof: rotationProof{Source: "persisted_workspace_usage", ObservedAt: observedAt, ExpiresAt: defaultExpiry}, WorkspaceID: workspaceID, AccountID: accountID, State: "unknown"}
	err := h.pool.QueryRow(ctx, `SELECT usage_state,ever_used,evidence_id,observed_at,expires_at FROM public.tsw_rotation_usage_ledger WHERE target_account_id=$1 AND workspace_id=$2`, accountID, workspaceID).Scan(&usage.State, &usage.EverUsed, &usage.EvidenceID, &usage.ObservedAt, &usage.ExpiresAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return usage, rotationProtectionProof{}, err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		usage.EvidenceID = rotationHash(struct {
			Domain             string
			Account, Workspace uuid.UUID
		}{"tsw.missing_usage.v1", accountID, workspaceID})
	}
	positive, historyErr := readJoinedWorkspacePositiveUsage(ctx, h.pool, accountID, workspaceID)
	if historyErr != nil && !errors.Is(historyErr, pgx.ErrNoRows) {
		return usage, rotationProtectionProof{}, historyErr
	}
	if historyErr == nil {
		usage = positive
	}
	protection := rotationProtectionProof{rotationProof: rotationProof{Source: "persisted_global_protection", ObservedAt: observedAt, ExpiresAt: defaultExpiry}, AccountID: accountID, Status: "none"}
	err = h.pool.QueryRow(ctx, `SELECT status,evidence_id,observed_at FROM public.tsw_rotation_effective_protections WHERE target_account_id=$1`, accountID).Scan(&protection.Status, &protection.EvidenceID, &protection.ObservedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return usage, protection, err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		protection.EvidenceID = rotationHash(struct {
			Domain  string
			Account uuid.UUID
		}{"tsw.no_global_protection.v1", accountID})
	}
	return usage, protection, nil
}

// Shared by preview production and transaction revalidation. Account history
// remains a global exclusion fact and cannot certify Workspace use or removal.
func readJoinedWorkspacePositiveUsage(ctx context.Context, db rotationRow, account, workspace uuid.UUID) (rotationUsageProof, error) {
	proof := rotationUsageProof{WorkspaceID: workspace, AccountID: account, Scope: "workspace", State: "used", EverUsed: true}
	proof.Source = "persisted_join_workspace_usage"
	err := db.QueryRow(ctx, `SELECT evidence_digest,observed_at,expires_at FROM public.tsw_rotation_join_usage_evidence WHERE target_account_id=$1 AND result='positive' AND scope='workspace' AND workspace_id=$2 ORDER BY observed_at DESC,attempt_id DESC LIMIT 1`, account, workspace).Scan(&proof.EvidenceID, &proof.ObservedAt, &proof.ExpiresAt)
	return proof, err
}
