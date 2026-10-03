package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

// rotationCapability performs the reference-compatible A/B read attestation.
// It never performs a platform mutation; confirmation separately rechecks local
// facts under the durable writer fence.
type rotationCapability interface {
	Evidence(context.Context, uuid.UUID) (rotationEvidence, error)
}
type rotationProof struct {
	Source     string    `json:"source"`
	EvidenceID string    `json:"evidenceId"`
	ObservedAt time.Time `json:"observedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}
type rotationUsageProof struct {
	rotationProof
	WorkspaceID uuid.UUID                  `json:"workspaceId"`
	AccountID   uuid.UUID                  `json:"accountId"`
	State       string                     `json:"state"`
	EverUsed    bool                       `json:"everUsed"`
	Scope       string                     `json:"scope,omitempty"`
	Absence     *rotationUsageAbsenceProof `json:"absence,omitempty"`
}

// Only a complete negative ledger lookup may distinguish no first-use record
// from a failed/partial probe. Production uses the durable usage ledger; the
// content-addressed mock variant is restricted to disposable integration tests.
type rotationUsageAbsenceProof struct {
	rotationProof
	WorkspaceID          uuid.UUID `json:"workspaceId"`
	AccountID            uuid.UUID `json:"accountId"`
	MotherID             uuid.UUID `json:"motherId"`
	SessionGeneration    uuid.UUID `json:"sessionGeneration"`
	VerificationID       int64     `json:"verificationId"`
	Identifier           string    `json:"identifier"`
	AccountVersion       int64     `json:"accountVersion"`
	CredentialVersion    int64     `json:"credentialVersion"`
	MembershipVersion    int64     `json:"membershipVersion"`
	LookupComplete       bool      `json:"lookupComplete"`
	FirstUseRecordStatus string    `json:"firstUseRecordStatus"`
}
type rotationCandidateScope struct {
	WorkspaceID       uuid.UUID
	AccountID         uuid.UUID
	MotherID          uuid.UUID
	SessionGeneration uuid.UUID
	VerificationID    int64
	Identifier        string
	AccountVersion    int64
	CredentialVersion int64
	MembershipVersion int64
}
type rotationProtectionProof struct {
	rotationProof
	AccountID uuid.UUID `json:"accountId"`
	Status    string    `json:"status"`
}
type rotationInvitationProof struct {
	rotationProof
	WorkspaceID    uuid.UUID `json:"workspaceId"`
	VerificationID int64     `json:"verificationId"`
	Identifier     string    `json:"identifier"`
	Status         string    `json:"status"`
	SeatType       string    `json:"seatType"`
}
type rotationVerdict struct {
	rotationProof
	AccountID  uuid.UUID               `json:"accountId"`
	SeatType   string                  `json:"seatType"`
	Usage      rotationUsageProof      `json:"usage"`
	Protection rotationProtectionProof `json:"protection"`
	Decision   string                  `json:"decision"`
	Reason     string                  `json:"reason"`
}

const rotationPreviewPolicyVersion = 2

type rotationEvidence struct {
	WorkspaceID            uuid.UUID                          `json:"workspaceId"`
	MotherID               uuid.UUID                          `json:"motherId"`
	VerificationID         int64                              `json:"verificationId"`
	ActiveUntil            time.Time                          `json:"activeUntil"`
	Permission             rotationProof                      `json:"permission"`
	PermissionDecision     string                             `json:"permissionDecision"`
	Counts                 rotationProof                      `json:"counts"`
	PaidDefault            rotationProof                      `json:"paidDefault"`
	PaidDefaultEntitlement int                                `json:"paidDefaultEntitlement"`
	SeatTypeCounts         map[string]int                     `json:"seatTypeCounts"`
	Slots                  map[string]rotationVerdict         `json:"slots"`       // exact platform member IDs
	Candidates             map[uuid.UUID]rotationVerdict      `json:"candidates"`  // exact selected account IDs
	Invitations            map[string]rotationInvitationProof `json:"invitations"` // exact normalized outbound invite identifiers
}

func rotationExpired(activeUntil, now time.Time) bool { return !activeUntil.After(now) }
func validRotationUsage(u rotationUsageProof, workspaceID, accountID uuid.UUID, now time.Time) bool {
	scopeMatches := u.WorkspaceID == workspaceID && u.Scope != "account"
	if !validRotationProof(u.rotationProof, now, "mock_workspace_usage", "persisted_workspace_usage", "persisted_join_workspace_usage") || !scopeMatches || u.AccountID != accountID {
		return false
	}
	return u.Absence == nil && (u.State == "used" && u.EverUsed || u.State == "never_used" && !u.EverUsed || u.State == "unknown")
}
func validRotationCandidateUsage(u rotationUsageProof, scope rotationCandidateScope, now time.Time) bool {
	if u.State != "unobserved_prejoin" && u.State != "never_used" {
		return validRotationUsage(u, scope.WorkspaceID, scope.AccountID, now)
	}
	a := u.Absence
	return !u.EverUsed && validRotationProof(u.rotationProof, now, "mock_workspace_usage", "persisted_workspace_usage") && u.WorkspaceID == scope.WorkspaceID && u.AccountID == scope.AccountID && a != nil &&
		validRotationProof(a.rotationProof, now, "mock_usage_ledger_lookup", "persisted_usage_ledger_lookup") && a.EvidenceID != u.EvidenceID && a.EvidenceID == rotationAbsenceEvidenceID(*a) &&
		a.WorkspaceID == scope.WorkspaceID && a.AccountID == scope.AccountID && a.MotherID == scope.MotherID &&
		a.SessionGeneration == scope.SessionGeneration && a.VerificationID == scope.VerificationID &&
		a.Identifier == scope.Identifier && a.AccountVersion == scope.AccountVersion && a.CredentialVersion == scope.CredentialVersion && a.MembershipVersion == scope.MembershipVersion &&
		a.AccountVersion > 0 && a.CredentialVersion > 0 && a.MembershipVersion > 0 && a.LookupComplete && a.FirstUseRecordStatus == "absent"
}
func validRotationProtection(p rotationProtectionProof, accountID uuid.UUID, now time.Time) bool {
	if !validRotationProof(p.rotationProof, now, "mock_global_protection", "persisted_global_protection") || p.AccountID != accountID {
		return false
	}
	switch p.Status {
	case "none", "delivered", "canceled_retired", "sale_reserved", "delivery_pending", "suspected_sold", "unknown":
		return true
	}
	return false
}
func blockingRotationProtection(status string) bool {
	return status == "sale_reserved" || status == "delivery_pending" || status == "suspected_sold" || status == "unknown"
}

func validRotationProof(p rotationProof, now time.Time, sources ...string) bool {
	sourceOK := false
	for _, source := range sources {
		if p.Source == source {
			sourceOK = true
			break
		}
	}
	return sourceOK && p.EvidenceID != "" && !p.ObservedAt.After(now) && !p.ObservedAt.Before(now.Add(-5*time.Minute)) && p.ExpiresAt.After(now) && p.ExpiresAt.After(p.ObservedAt) && !p.ExpiresAt.After(p.ObservedAt.Add(5*time.Minute))
}
func rotationHash(value any) string {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Content-address the complete lookup so an ID cannot be reused for a different
// scope, result or observation time. Production additionally rechecks the
// durable row under target-account epochs; this digest alone is not authentication.
func rotationAbsenceEvidenceID(a rotationUsageAbsenceProof) string {
	a.EvidenceID = ""
	a.ObservedAt = a.ObservedAt.UTC()
	a.ExpiresAt = a.ExpiresAt.UTC()
	return rotationHash(struct {
		Domain string                    `json:"domain"`
		Proof  rotationUsageAbsenceProof `json:"proof"`
	}{Domain: "tsw.rotation_usage_ledger_absence.v1", Proof: a})
}
func rotationDigest(p ownerapi.ExpiryRotationPreview) string {
	p.Id = uuid.Nil
	p.Digest = ""
	p.Authorized = false
	p.AuthorizedAt = nil
	p.AuthorizedBy = nil
	p.RevokedAt = nil
	p.Assignments = []ownerapi.ExpiryRotationAssignment{}
	p.AuthorizationDigest = nil
	return rotationHash(p)
}

type rotationRow interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// A retained mock everUsed observation in any Workspace cannot be downgraded
// by a later preview of the same account. This fixture-only history check is
// not a durable production usage ledger or remote usage observation.
func rotationPreviouslyUsed(ctx context.Context, db rotationRow, accountID, workspaceID uuid.UUID) (bool, error) {
	var used bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_expiry_rotation_previews prior, LATERAL jsonb_array_elements(COALESCE(prior.facts->'slots','[]'::jsonb) || COALESCE(prior.facts->'candidates','[]'::jsonb)) item WHERE prior.facts->>'source'='mock_capability' AND item->>'accountId'=$1 AND item->>'everUsed'='true') OR EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_evidence e WHERE e.target_account_id=$1::uuid AND e.result='positive' AND (e.scope='account' OR e.workspace_id=$2))`, accountID.String(), workspaceID).Scan(&used)
	return used, err
}

// Read every retained account-ledger row before asserting complete absence in
// the selected Workspace. Unknown/conflicting or ever-used history blocks a
// candidate globally; membership in another Workspace is not a blocking fact.
// Scan and terminal query errors never become a negative lookup result.
func rotationCandidateLedgerLookup(ctx context.Context, db rotationRow, accountID, workspaceID uuid.UUID) (absent, clear bool, err error) {
	rows, err := db.Query(ctx, `SELECT workspace_id,usage_state,ever_used,evidence_id,observed_at,expires_at FROM public.tsw_rotation_usage_ledger WHERE target_account_id=$1`, accountID)
	if err != nil {
		return false, false, err
	}
	defer rows.Close()
	absent, clear = true, true
	for rows.Next() {
		var row rotationUsageProof
		if err = rows.Scan(&row.WorkspaceID, &row.State, &row.EverUsed, &row.EvidenceID, &row.ObservedAt, &row.ExpiresAt); err != nil {
			return false, false, err
		}
		if row.WorkspaceID == workspaceID {
			absent = false
		}
		if row.State != "never_used" || row.EverUsed {
			clear = false
		}
	}
	if err = rows.Err(); err != nil {
		return false, false, err
	}
	var blocked bool
	if err = db.QueryRow(ctx, `SELECT public.tsw_rotation_join_usage_blocks_candidate($1,$2) OR EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections WHERE target_account_id=$1) OR EXISTS(SELECT 1 FROM public.tsw_channel_objects WHERE target_account_id=$1)`, accountID, workspaceID).Scan(&blocked); err != nil {
		return false, false, err
	}
	return absent, clear && !blocked, nil
}

func rotationPersistedVerdictMatches(ctx context.Context, db rotationRow, workspaceID uuid.UUID, verdict rotationVerdict) (bool, error) {
	joined := verdict.Usage.Source == "persisted_join_workspace_usage"
	if !joined && verdict.Usage.Source != "persisted_workspace_usage" || verdict.Protection.Source != "persisted_global_protection" {
		return true, nil
	}
	var state, evidenceID string
	var everUsed bool
	var observedAt, expiresAt time.Time
	var err error
	if joined {
		var proof rotationUsageProof
		proof, err = readJoinedWorkspacePositiveUsage(ctx, db, verdict.AccountID, workspaceID)
		state, everUsed = proof.State, proof.EverUsed
		evidenceID, observedAt, expiresAt = proof.EvidenceID, proof.ObservedAt, proof.ExpiresAt
		if err == nil && (proof.Scope != verdict.Usage.Scope || proof.WorkspaceID != verdict.Usage.WorkspaceID) {
			return false, nil
		}
	} else {
		err = db.QueryRow(ctx, `SELECT usage_state,ever_used,evidence_id,observed_at,expires_at FROM public.tsw_rotation_usage_ledger WHERE target_account_id=$1 AND workspace_id=$2`, verdict.AccountID, workspaceID).Scan(&state, &everUsed, &evidenceID, &observedAt, &expiresAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		if verdict.Usage.State != "unknown" && verdict.Usage.State != "unobserved_prejoin" {
			return false, nil
		}
	} else if err != nil {
		return false, err
	} else if state != verdict.Usage.State || everUsed != verdict.Usage.EverUsed || evidenceID != verdict.Usage.EvidenceID || !observedAt.Equal(verdict.Usage.ObservedAt) || !expiresAt.Equal(verdict.Usage.ExpiresAt) {
		return false, nil
	}
	if verdict.Usage.State == "unobserved_prejoin" || verdict.Usage.Absence != nil {
		a := verdict.Usage.Absence
		if a == nil || a.Source != "persisted_usage_ledger_lookup" {
			return false, nil
		}
		absent, clear, lookupErr := rotationCandidateLedgerLookup(ctx, db, verdict.AccountID, workspaceID)
		if lookupErr != nil {
			return false, lookupErr
		}
		if !clear || absent != (verdict.Usage.State == "unobserved_prejoin") {
			return false, nil
		}
	}
	// Missing usage must not skip revalidation of global protection under the fence.
	var status, protectionID string
	var protectionObserved time.Time
	err = db.QueryRow(ctx, `SELECT status,evidence_id,observed_at FROM public.tsw_rotation_effective_protections WHERE target_account_id=$1`, verdict.AccountID).Scan(&status, &protectionID, &protectionObserved)
	if errors.Is(err, pgx.ErrNoRows) {
		return verdict.Protection.Status == "none", nil
	}
	if err != nil {
		return false, err
	}
	return status == verdict.Protection.Status && protectionID == verdict.Protection.EvidenceID && protectionObserved.Equal(verdict.Protection.ObservedAt), nil
}

func (h *OwnerAuthHandler) rotationFacts(ctx context.Context, db rotationRow, owner uuid.UUID, supplied *rotationEvidence) (ownerapi.ExpiryRotationPreview, error) {
	version := rotationPreviewPolicyVersion
	p := ownerapi.ExpiryRotationPreview{PolicyVersion: &version, Status: "facts_incomplete", ManagementPermission: "unknown", Assignments: []ownerapi.ExpiryRotationAssignment{}, Slots: []ownerapi.ExpiryRotationSlot{}, Candidates: []ownerapi.ExpiryRotationCandidate{}, Members: []string{}, Invitations: []string{}, SeatTypeCounts: map[string]int{}, SourceRevisions: map[string]int64{}, Source: "selected_workspace_read"}
	var children []byte
	var run, generation uuid.UUID
	var revision int64
	err := db.QueryRow(ctx, `SELECT id,version,mother_account_id,mother_revision,workspace_id,verification_id,batch_id,batch_version,children,destination_id,destination_revision,visibility_run_id,session_generation
 FROM tsw_operation_selection_drafts WHERE owner_id=$1 AND step='complete'`, owner).Scan(&p.DraftId, &p.DraftVersion, &p.MotherAccountId, &revision, &p.WorkspaceId, &p.VerificationId, &p.BatchId, &p.BatchVersion, &children, &p.DestinationId, &p.DestinationRevision, &run, &generation)
	if err != nil {
		return p, err
	}
	p.SourceRevisions["mother"] = revision
	// Each connection is scoped to the selected canonical Workspace and current
	// Personal and Workspace token generations. Latest failed reads supersede success.
	var memberCount, inviteCount, seatLimit int
	var permission string
	err = db.QueryRow(ctx, `SELECT f.active_until,f.observed_at,f.expires_at,f.member_count,f.pending_invite_count,f.seat_limit,f.permission
 FROM tsw_mother_accounts a
 JOIN tsw_mother_account_credentials c ON c.mother_account_id=a.id AND c.secret_revision=$6
 JOIN tsw_mother_discoveries discovery ON discovery.mother_account_id=a.id AND discovery.run_id=$3 AND discovery.status='discovered' AND discovery.secret_revision=c.secret_revision AND discovery.session_generation=$4 AND discovery.observed_at>now()-interval '7 days'
 JOIN tsw_mother_personal_sessions s ON s.mother_account_id=a.id AND s.generation=$4 AND s.secret_revision=c.secret_revision AND s.expires_at>now()
 JOIN tsw_mother_workspace_visibility v ON v.mother_account_id=a.id AND v.workspace_id=$2 AND v.run_id=$3 AND v.access_status='readable'
 JOIN tsw_selected_workspace_tokens t ON t.workspace_id=$2 AND t.mother_account_id=a.id AND t.discovery_run_id=$3 AND t.session_generation=$4 AND t.secret_revision=c.secret_revision AND t.status='ready' AND t.expires_at>now()+interval '30 seconds'
 JOIN tsw_workspace_verifications f ON f.id=$5 AND f.workspace_id=$2 AND f.mother_account_id=a.id AND f.discovery_run_id=$3 AND f.session_generation=$4 AND f.secret_revision=c.secret_revision AND f.token_attempt=t.attempt AND f.token_exchange_id=t.exchange_id AND f.outcome='verified' AND f.completeness='complete' AND f.expires_at>now() AND f.observed_at<=now() AND f.observed_at>now()-interval '5 minutes'
 WHERE a.id=$1 AND a.status='active' AND f.id=(SELECT max(id) FROM tsw_workspace_verifications WHERE workspace_id=$2 AND mother_account_id=a.id AND discovery_run_id=$3 AND session_generation=$4 AND token_attempt=t.attempt AND token_exchange_id=t.exchange_id)`, p.MotherAccountId, p.WorkspaceId, run, generation, p.VerificationId, revision).Scan(&p.ActiveUntil, &p.ObservedAt, &p.ExpiresAt, &memberCount, &inviteCount, &seatLimit, &permission)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if !rotationExpired(p.ActiveUntil, time.Now()) {
		p.Status = "not_expired"
	}
	var batchCurrent, destinationCurrent bool
	err = db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_standby_child_batches WHERE id=$1 AND version=$2),EXISTS(SELECT 1 FROM tsw_delivery_destinations WHERE id=$3 AND revision=$4 AND enabled AND test_connection='connected' AND test_target='connected' AND test_revision=revision)`, p.BatchId, p.BatchVersion, p.DestinationId, p.DestinationRevision).Scan(&batchCurrent, &destinationCurrent)
	if err != nil {
		return p, err
	}
	if !batchCurrent || !destinationCurrent {
		return p, nil
	}
	rows, err := db.Query(ctx, `SELECT kind,identifier,status,COALESCE(role,''),COALESCE(platform_member_id,'') FROM tsw_workspace_verification_entries WHERE verification_id=$1 ORDER BY kind,identifier`, p.VerificationId)
	if err != nil {
		return p, err
	}
	type entry struct{ identifier, status, role, id string }
	var members []entry
	invitations := map[string]bool{}
	memberIdentifiers := map[string]bool{}
	memberIDs := map[string]bool{}
	ambiguousMember := false
	for rows.Next() {
		var kind string
		var e entry
		if err = rows.Scan(&kind, &e.identifier, &e.status, &e.role, &e.id); err != nil {
			break
		}
		if kind == "member" {
			if e.id == "" || memberIDs[e.id] {
				ambiguousMember = true
				break
			}
			memberIDs[e.id] = true
			memberIdentifiers[strings.ToLower(e.identifier)] = true
			members = append(members, e)
			p.Members = append(p.Members, e.identifier+" · "+e.id+" · "+e.status+" · "+e.role)
		} else {
			invitations[strings.ToLower(e.identifier)] = e.status == "pending"
			p.Invitations = append(p.Invitations, e.identifier+" · "+e.status)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return p, err
	}
	if ambiguousMember || len(members) != memberCount || len(p.Invitations) != inviteCount || len(invitations) != inviteCount || seatLimit < 0 || memberCount < 0 {
		return p, nil
	}
	var selected []ownerapi.OperationDraftChild
	if err = json.Unmarshal(children, &selected); err != nil {
		return p, err
	}
	if len(selected) == 0 {
		return p, nil
	}
	// No batch count is an eligibility signal. Re-read each exact selected account,
	// its membership version, credential version and global delivery history.
	type child struct {
		id                                uuid.UUID
		identifier                        string
		accountVersion, credentialVersion int64
		complete, delivered               bool
	}
	found := make([]child, 0, len(selected))
	seen := make(map[uuid.UUID]bool, len(selected))
	for _, chosen := range selected {
		if seen[chosen.AccountId] || chosen.AccountId == uuid.Nil || chosen.MembershipVersion < 1 {
			return p, nil
		}
		seen[chosen.AccountId] = true
		var c child
		c.id = chosen.AccountId
		err = db.QueryRow(ctx, `SELECT a.identifier,a.version,creds.version,(a.status='active' AND creds.material_status='complete' AND creds.materials_sealed),
   EXISTS(SELECT 1 FROM tsw_batch_memberships m JOIN tsw_oauth_assets asset ON asset.membership_id=m.id JOIN tsw_delivery_versions delivered ON delivered.oauth_asset_id=asset.id WHERE m.target_account_id=a.id)
   FROM tsw_standby_child_memberships membership JOIN tsw_target_accounts a ON a.id=membership.target_account_id JOIN tsw_target_credentials creds ON creds.target_account_id=a.id
   WHERE membership.target_account_id=$1 AND membership.batch_id=$2 AND membership.version=$3`, c.id, p.BatchId, chosen.MembershipVersion).Scan(&c.identifier, &c.accountVersion, &c.credentialVersion, &c.complete, &c.delivered)
		if errors.Is(err, pgx.ErrNoRows) {
			return p, nil
		}
		if err != nil {
			return p, err
		}
		var identityCount int
		if err = db.QueryRow(ctx, `SELECT count(*) FROM tsw_target_accounts WHERE identifier=$1`, c.identifier).Scan(&identityCount); err != nil {
			return p, err
		}
		if identityCount != 1 {
			return p, nil
		}
		p.SourceRevisions["account:"+c.id.String()] = c.accountVersion
		p.SourceRevisions["credential:"+c.id.String()] = c.credentialVersion
		p.SourceRevisions["membership:"+c.id.String()] = chosen.MembershipVersion
		found = append(found, c)
	}
	pending := func() {
		for _, e := range members {
			p.Slots = append(p.Slots, ownerapi.ExpiryRotationSlot{Identifier: e.identifier, PlatformMemberId: e.id, UsageState: "unknown", ProtectionStatus: "unknown", Decision: "needs_verification", Reason: "protection_proof_missing"})
		}
		for _, c := range found {
			reason := "eligibility_proof_missing"
			if !invitations[strings.ToLower(c.identifier)] {
				reason = "invitation_required"
			}
			p.Candidates = append(p.Candidates, ownerapi.ExpiryRotationCandidate{AccountId: c.id, Identifier: c.identifier, UsageState: "unknown", ProtectionStatus: "unknown", Decision: "excluded", DeliveryStatus: "blocked", Reason: reason})
		}
	}
	if supplied == nil {
		pending()
		if p.Status != "not_expired" {
			p.Status = "pending_permission"
		}
		return p, nil
	}
	ev := *supplied
	now := time.Now()
	if ev.WorkspaceID != p.WorkspaceId || ev.MotherID != p.MotherAccountId || ev.VerificationID != p.VerificationId ||
		(ev.Permission.Source == "official_owner_ab" && !ev.ActiveUntil.Equal(p.ActiveUntil)) ||
		!validRotationProof(ev.Permission, now, "mock_write_permission", "official_owner_ab") || ev.PermissionDecision != "manage" {
		pending()
		if p.Status != "not_expired" {
			p.Status = "pending_permission"
		}
		return p, nil
	}
	if ev.Permission.Source == "official_owner_ab" {
		var currentRole string
		if err = db.QueryRow(ctx, `SELECT workspace_role FROM public.tsw_mother_workspace_visibility WHERE mother_account_id=$1 AND workspace_id=$2 AND run_id=$3`, p.MotherAccountId, p.WorkspaceId, run).Scan(&currentRole); err != nil {
			return p, err
		}
		if currentRole != "owner" {
			pending()
			if p.Status != "not_expired" {
				p.Status = "pending_permission"
			}
			return p, nil
		}
	}
	if !validRotationProof(ev.Counts, now, "mock_seat_type_counts", "official_seat_type_counts_ab") || !validRotationProof(ev.PaidDefault, now, "mock_paid_default_entitlement", "official_paid_default_ab") || ev.PaidDefaultEntitlement != seatLimit || len(ev.SeatTypeCounts) == 0 {
		pending()
		return p, nil
	}
	total := 0
	for kind, count := range ev.SeatTypeCounts {
		if kind == "" || count < 0 || count > memberCount-total {
			pending()
			return p, nil
		}
		total += count
	}
	if total != memberCount {
		pending()
		return p, nil
	}
	if len(ev.Slots) != memberCount || len(ev.Candidates) != len(found) || len(ev.Invitations) != inviteCount {
		pending()
		if p.Status != "not_expired" {
			p.Status = "needs_verification"
		}
		return p, nil
	}
	p.SeatTypeCounts = ev.SeatTypeCounts
	p.PaidDefaultEntitlement = &ev.PaidDefaultEntitlement
	p.ManagementPermission = "manage"
	p.Source = "mock_capability"
	p.EvidenceFingerprint = rotationHash(ev)
	if ev.Permission.Source == "official_owner_ab" {
		p.Source = "official_owner_ab"
		// Official A/B evidence IDs exclude volatile observation timestamps while
		// binding token generation and all typed facts.
		p.EvidenceFingerprint = ev.Permission.EvidenceID
	}
	ready := true
	replaceable, eligible := 0, 0
	observedSeatTypes := make(map[string]int)
	// No read or arbitrary fixture verdict is an eligibility grant. Independently
	// sourced usage, seat typing and global protection must agree with each verdict.
	for _, e := range members {
		verdict, ok := ev.Slots[e.id]
		slot := ownerapi.ExpiryRotationSlot{Identifier: e.identifier, PlatformMemberId: e.id, AccountId: verdict.AccountID, UsageState: "unknown", ProtectionStatus: "unknown", Decision: "needs_verification", Reason: "protection_proof_missing"}
		var identityCount int
		persistedOK := true
		if ok && verdict.AccountID != uuid.Nil {
			err = db.QueryRow(ctx, `SELECT count(*) FROM tsw_target_accounts WHERE id=$1 AND identifier=$2`, verdict.AccountID, e.identifier).Scan(&identityCount)
			if err != nil {
				return p, err
			}
			persistedOK, err = rotationPersistedVerdictMatches(ctx, db, p.WorkspaceId, verdict)
			if err != nil {
				return p, err
			}
		}
		if ok && persistedOK && identityCount == 1 && verdict.SeatType == "prolite" && validRotationProof(verdict.rotationProof, now, "mock_member_protection", "official_member_ab") && validRotationUsage(verdict.Usage, p.WorkspaceId, verdict.AccountID, now) && validRotationProtection(verdict.Protection, verdict.AccountID, now) {
			slot.SeatType = "prolite"
			slot.UsageState = ownerapi.ExpiryRotationSlotUsageState(verdict.Usage.State)
			slot.EverUsed = verdict.Usage.EverUsed
			slot.ProtectionStatus = ownerapi.ExpiryRotationSlotProtectionStatus(verdict.Protection.Status)
			switch {
			case blockingRotationProtection(verdict.Protection.Status):
				slot.Reason = "protection_blocks_rotation"
				ready = false
			case verdict.Protection.Status == "delivered" || verdict.Protection.Status == "canceled_retired":
				slot.Decision = "retained"
				slot.Reason = "global_delivery_protected"
			case verdict.Usage.State == "used" && verdict.Usage.EverUsed:
				slot.Decision = "replaceable"
				slot.Reason = "fixture_used_unprotected"
			case verdict.Usage.State == "never_used" && !verdict.Usage.EverUsed:
				slot.Decision = "retained"
				slot.Reason = "never_used_retained"
			default:
				slot.Reason = "usage_unknown"
				ready = false
			}
			var previouslyUsed bool
			if !verdict.Usage.EverUsed {
				previouslyUsed, err = rotationPreviouslyUsed(ctx, db, verdict.AccountID, p.WorkspaceId)
				if err != nil {
					return p, err
				}
			}
			if previouslyUsed {
				slot.Decision = "needs_verification"
				slot.Reason = "sticky_usage_conflict"
				ready = false
			}
			if verdict.Decision != string(slot.Decision) {
				slot.Decision = "needs_verification"
				slot.Reason = "verdict_conflicts_with_evidence"
				ready = false
			}
		} else {
			ready = false
		}
		var delivered bool
		err = db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_batch_memberships membership JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id JOIN tsw_delivery_versions delivery ON delivery.oauth_asset_id=asset.id WHERE membership.target_account_id=$1)`, verdict.AccountID).Scan(&delivered)
		if err != nil {
			return p, err
		}
		if delivered {
			if verdict.Protection.Status == "none" {
				ready = false
			}
			slot.Decision = "retained"
			slot.Reason = "global_delivery_protected"
			if slot.SeatType == "" {
				ready = false
			}
		}
		if slot.Decision == "needs_verification" {
			ready = false
		}
		if slot.Decision == "replaceable" {
			replaceable++
		}
		if slot.SeatType != "" {
			observedSeatTypes[slot.SeatType]++
		}
		p.Slots = append(p.Slots, slot)
	}
	for _, c := range found {
		verdict, ok := ev.Candidates[c.id]
		candidate := ownerapi.ExpiryRotationCandidate{AccountId: c.id, Identifier: c.identifier, UsageState: "unknown", ProtectionStatus: "unknown", Decision: "excluded", DeliveryStatus: "blocked", Reason: "eligibility_proof_missing"}
		scope := rotationCandidateScope{WorkspaceID: p.WorkspaceId, AccountID: c.id, MotherID: p.MotherAccountId, SessionGeneration: generation, VerificationID: p.VerificationId, Identifier: c.identifier, AccountVersion: c.accountVersion, CredentialVersion: c.credentialVersion, MembershipVersion: p.SourceRevisions["membership:"+c.id.String()]}
		persistedOK := true
		if ok {
			persistedOK, err = rotationPersistedVerdictMatches(ctx, db, p.WorkspaceId, verdict)
			if err != nil {
				return p, err
			}
		}
		if ok && persistedOK && verdict.AccountID == c.id && verdict.SeatType == "prolite" && validRotationProof(verdict.rotationProof, now, "mock_candidate_protection", "persisted_candidate_evidence") && validRotationCandidateUsage(verdict.Usage, scope, now) && validRotationProtection(verdict.Protection, c.id, now) {
			candidate.SeatType = "prolite"
			candidate.UsageState = ownerapi.ExpiryRotationCandidateUsageState(verdict.Usage.State)
			candidate.EverUsed = verdict.Usage.EverUsed
			candidate.ProtectionStatus = ownerapi.ExpiryRotationCandidateProtectionStatus(verdict.Protection.Status)
			switch {
			case blockingRotationProtection(verdict.Protection.Status):
				candidate.Reason = "protection_blocks_rotation"
				ready = false
			case verdict.Protection.Status == "delivered" || verdict.Protection.Status == "canceled_retired":
				candidate.Reason = "global_delivery_protected"
			case (verdict.Usage.State == "unobserved_prejoin" || verdict.Usage.State == "never_used") && !verdict.Usage.EverUsed && verdict.Protection.Status == "none":
				candidate.Decision = "eligible"
				candidate.Reason = "join_candidate_pending_first_probe"
			case verdict.Usage.State == "used" || verdict.Usage.EverUsed:
				candidate.Reason = "sticky_usage_protected"
			default:
				candidate.Reason = "usage_unknown"
				ready = false
			}
			var previouslyUsed bool
			if !verdict.Usage.EverUsed {
				previouslyUsed, err = rotationPreviouslyUsed(ctx, db, c.id, p.WorkspaceId)
				if err != nil {
					return p, err
				}
			}
			if previouslyUsed {
				candidate.Decision = "excluded"
				candidate.Reason = "sticky_usage_conflict"
				ready = false
			}
		} else {
			// A correctly scoped everUsed assertion remains sticky even when its
			// incompatible absence claim makes the candidate ineligible.
			if verdict.AccountID == c.id && validRotationProof(verdict.Usage.rotationProof, now, "mock_workspace_usage", "persisted_workspace_usage") && verdict.Usage.WorkspaceID == p.WorkspaceId && verdict.Usage.AccountID == c.id && verdict.Usage.EverUsed {
				candidate.EverUsed = true
				candidate.Reason = "sticky_usage_protected"
			} else if verdict.Usage.State == "unobserved_prejoin" || verdict.Usage.State == "never_used" {
				candidate.Reason = "usage_absence_unverified"
			}
			ready = false
		}
		if !c.complete {
			candidate.Decision = "excluded"
			candidate.Reason = "material_changed"
			ready = false
		}
		if c.delivered {
			candidate.Decision = "excluded"
			candidate.Reason = "global_delivery_protected"
		}
		inviteIdentifier := strings.ToLower(c.identifier)
		if !invitations[inviteIdentifier] {
			candidate.Decision = "excluded"
			candidate.Reason = "invitation_required"
		} else {
			invite, hasProof := ev.Invitations[inviteIdentifier]
			if !hasProof || !validRotationProof(invite.rotationProof, now, "mock_invite_seat_type", "official_invitation_ab") || invite.WorkspaceID != p.WorkspaceId || invite.VerificationID != p.VerificationId || invite.Identifier != inviteIdentifier || invite.Status != "pending" || invite.SeatType != "prolite" || invite.SeatType != candidate.SeatType {
				candidate.Decision = "excluded"
				candidate.Reason = "invitation_seat_type_unverified"
				ready = false
			}
		}
		if memberIdentifiers[strings.ToLower(c.identifier)] {
			candidate.Decision = "excluded"
			candidate.Reason = "already_member"
		}
		if verdict.Decision != string(candidate.Decision) {
			candidate.Decision = "excluded"
			if candidate.Reason == "eligibility_proof_missing" || candidate.Reason == "join_candidate_pending_first_probe" {
				candidate.Reason = "verdict_conflicts_with_evidence"
			}
			ready = false
		}
		if candidate.Decision == "eligible" {
			eligible++
			// The preview has no joined identity or persisted post-join zero
			// observation. Join eligibility can never certify delivery here.
			candidate.DeliveryStatus = "join_candidate_pending_first_probe"
		}
		p.Candidates = append(p.Candidates, candidate)
	}
	for seatType, occupied := range observedSeatTypes {
		if p.SeatTypeCounts[seatType] < occupied {
			ready = false
		}
	}
	if p.Status == "not_expired" {
		return p, nil
	}
	if ready && replaceable > 0 && eligible == replaceable {
		p.Status = "ready"
	} else {
		p.Status = "needs_verification"
	}
	if ev.Permission.ExpiresAt.Before(p.ExpiresAt) {
		p.ExpiresAt = ev.Permission.ExpiresAt
	}
	if ev.Counts.ExpiresAt.Before(p.ExpiresAt) {
		p.ExpiresAt = ev.Counts.ExpiresAt
	}
	if ev.PaidDefault.ExpiresAt.Before(p.ExpiresAt) {
		p.ExpiresAt = ev.PaidDefault.ExpiresAt
	}
	for _, v := range ev.Slots {
		for _, expiry := range []time.Time{v.ExpiresAt, v.Usage.ExpiresAt, v.Protection.ExpiresAt} {
			if expiry.Before(p.ExpiresAt) {
				p.ExpiresAt = expiry
			}
		}
	}
	for _, v := range ev.Candidates {
		for _, expiry := range []time.Time{v.ExpiresAt, v.Usage.ExpiresAt, v.Protection.ExpiresAt} {
			if expiry.Before(p.ExpiresAt) {
				p.ExpiresAt = expiry
			}
		}
		if v.Usage.Absence != nil && v.Usage.Absence.ExpiresAt.Before(p.ExpiresAt) {
			p.ExpiresAt = v.Usage.Absence.ExpiresAt
		}
	}
	for _, invite := range ev.Invitations {
		if invite.ExpiresAt.Before(p.ExpiresAt) {
			p.ExpiresAt = invite.ExpiresAt
		}
	}
	// Scope the preview lifetime independently of Ticket07's seven-day read TTL.
	if limit := now.Add(5 * time.Minute); p.ExpiresAt.After(limit) {
		p.ExpiresAt = limit
	}
	return p, nil
}

func (h *OwnerAuthHandler) PreviewExpiryRotation(w http.ResponseWriter, r *http.Request, _ ownerapi.PreviewExpiryRotationParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	oid := uuid.MustParse(owner.OwnerID)
	var supplied *rotationEvidence
	evidenceFailed := false
	if h.rotationCapability != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		evidence, evidenceErr := h.rotationCapability.Evidence(ctx, oid)
		cancel()
		if evidenceErr == nil {
			supplied = &evidence
		} else {
			evidenceFailed = true
		}
	}
	tx, err := h.pool.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	p, err := h.rotationFacts(r.Context(), tx, oid, supplied)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 409, "draft_incomplete", "Incomplete", "Complete the selection wizard first", 0)
		return
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	if p.DraftId == uuid.Nil {
		writeProblem(w, r, 409, "draft_incomplete", "Incomplete", "Complete the selection wizard first", 0)
		return
	}
	if evidenceFailed && p.Status != "not_expired" {
		p.Status = "facts_incomplete"
	}
	if err = rotationAttachEpochVersions(r.Context(), tx, oid, &p); err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	// A pending preview is visible but cannot be confirmed. Never default missing facts to zero.
	if p.ExpiresAt.IsZero() {
		p.ExpiresAt = time.Now().Add(time.Minute)
	}
	p.Digest = rotationDigest(p)
	facts, _ := json.Marshal(p)
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_expiry_rotation_previews(owner_id,draft_id,draft_version,workspace_id,verification_id,facts,digest,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, owner.OwnerID, p.DraftId, p.DraftVersion, p.WorkspaceId, p.VerificationId, facts, p.Digest, p.Status, p.ExpiresAt).Scan(&p.Id)
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	writeJSON(w, 200, p)
}

// Old policy facts cannot prove the complete-negative lookup, even when they
// already say join_candidate_pending_first_probe. Normalize only the response;
// frozen facts, digest and database status remain unchanged.
func rotationNormalizeHistoricalPreview(p ownerapi.ExpiryRotationPreview, status string) (ownerapi.ExpiryRotationPreview, string) {
	legacy := p.PolicyVersion == nil || *p.PolicyVersion != rotationPreviewPolicyVersion
	for _, c := range p.Candidates {
		if (c.DeliveryStatus != "blocked" && c.DeliveryStatus != "join_candidate_pending_first_probe") ||
			(c.Decision == "eligible" && c.DeliveryStatus != "join_candidate_pending_first_probe") ||
			(c.Decision != "eligible" && c.DeliveryStatus == "join_candidate_pending_first_probe") {
			legacy = true
			break
		}
	}
	if legacy {
		p.Candidates = append([]ownerapi.ExpiryRotationCandidate{}, p.Candidates...)
		for i := range p.Candidates {
			c := &p.Candidates[i]
			c.DeliveryStatus = "blocked"
			if c.Decision == "eligible" {
				c.Decision = "excluded"
				c.Reason = "legacy_preview_requires_repreview"
			}
		}
		status = "needs_verification"
	}
	p.Status = ownerapi.ExpiryRotationPreviewStatus(status)
	return p, status
}
func rotationStored(ctx context.Context, tx pgx.Tx, owner uuid.UUID, id uuid.UUID) (ownerapi.ExpiryRotationPreview, uuid.UUID, string, error) {
	var p ownerapi.ExpiryRotationPreview
	var raw []byte
	var key *uuid.UUID
	var status string
	var assignments []byte
	err := tx.QueryRow(ctx, `SELECT facts,status,idempotency_key,authorized_by,authorized_at,revoked_at,assignments,authorization_digest FROM tsw_expiry_rotation_previews WHERE id=$1 AND owner_id=$2 FOR UPDATE`, id, owner).Scan(&raw, &status, &key, &p.AuthorizedBy, &p.AuthorizedAt, &p.RevokedAt, &assignments, &p.AuthorizationDigest)
	if err != nil {
		return p, uuid.Nil, "", err
	}
	authorizedBy, authorizedAt, revokedAt, authorizedDigest := p.AuthorizedBy, p.AuthorizedAt, p.RevokedAt, p.AuthorizationDigest
	if err = json.Unmarshal(raw, &p); err != nil {
		return p, uuid.Nil, "", err
	}
	p.Id = id
	p.Status = ownerapi.ExpiryRotationPreviewStatus(status)
	p.AuthorizedBy = authorizedBy
	p.AuthorizedAt = authorizedAt
	p.RevokedAt = revokedAt
	p.AuthorizationDigest = authorizedDigest
	if err = json.Unmarshal(assignments, &p.Assignments); err != nil {
		return p, uuid.Nil, "", err
	}
	p.Authorized = authorizedAt != nil && revokedAt == nil
	p, status = rotationNormalizeHistoricalPreview(p, status)
	if key != nil {
		return p, *key, status, nil
	}
	return p, uuid.Nil, status, nil
}
func (h *OwnerAuthHandler) GetLatestExpiryRotationPreview(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	var id uuid.UUID
	err := h.pool.QueryRow(r.Context(), `SELECT id FROM tsw_expiry_rotation_previews WHERE owner_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, owner.OwnerID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "preview_not_found", "Not Found", "No preview exists", 0)
		return
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	h.GetExpiryRotationPreview(w, r, id)
}

func (h *OwnerAuthHandler) GetExpiryRotationPreview(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	p, _, _, err := rotationStored(r.Context(), tx, uuid.MustParse(owner.OwnerID), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "preview_not_found", "Not Found", "Preview not found", 0)
		return
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	writeJSON(w, 200, p)
}

// An assignment is not inferred from roster order. Every replaceable original
// slot must have one different explicitly chosen eligible candidate of the same
// independently evidenced seat type; excess candidates require a new draft.
func rotationAssignments(preview ownerapi.ExpiryRotationPreview, requested []ownerapi.ExpiryRotationAssignment) ([]ownerapi.ExpiryRotationAssignment, bool) {
	slots := map[string]string{}
	candidates := map[uuid.UUID]string{}
	for _, s := range preview.Slots {
		if s.Decision == "replaceable" {
			slots[s.PlatformMemberId] = s.SeatType
		}
	}
	for _, c := range preview.Candidates {
		if c.Decision == "eligible" {
			if c.DeliveryStatus != "join_candidate_pending_first_probe" {
				return nil, false
			}
			candidates[c.AccountId] = c.SeatType
		}
	}
	if len(slots) == 0 || len(requested) != len(slots) || len(candidates) != len(slots) {
		return nil, false
	}
	used := map[uuid.UUID]bool{}
	assigned := map[string]bool{}
	for _, a := range requested {
		seat, exists := slots[a.PlatformMemberId]
		typeOfCandidate, eligible := candidates[a.AccountId]
		if !exists || !eligible || seat != typeOfCandidate || used[a.AccountId] || assigned[a.PlatformMemberId] {
			return nil, false
		}
		used[a.AccountId] = true
		assigned[a.PlatformMemberId] = true
	}
	assignments := append([]ownerapi.ExpiryRotationAssignment{}, requested...)
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].PlatformMemberId < assignments[j].PlatformMemberId })
	return assignments, true
}

func rotationComparableDigest(p ownerapi.ExpiryRotationPreview) string {
	p.ObservedAt = time.Time{}
	p.ExpiresAt = time.Time{}
	return rotationDigest(p)
}

func rotationAuthorizationKeys(owner uuid.UUID, p ownerapi.ExpiryRotationPreview) []writerfence.Key {
	keys := map[writerfence.Key]bool{
		{Kind: writerfence.Owner, ID: owner}:                                       true,
		{Kind: writerfence.Workspace, ID: p.WorkspaceId}:                           true,
		{Kind: writerfence.Mother, ID: p.MotherAccountId}:                          true,
		{Kind: writerfence.StandbyBatch, ID: p.BatchId}:                            true,
		{Kind: writerfence.Destination, ID: p.DestinationId}:                       true,
		{Kind: writerfence.TargetIdentity, ID: writerfence.TargetIdentityID}:       true,
		{Kind: writerfence.StandbyMembership, ID: writerfence.StandbyMembershipID}: true,
	}
	for _, slot := range p.Slots {
		if slot.AccountId != uuid.Nil {
			keys[writerfence.Key{Kind: writerfence.TargetAccount, ID: slot.AccountId}] = true
		}
	}
	for _, candidate := range p.Candidates {
		if candidate.AccountId != uuid.Nil {
			keys[writerfence.Key{Kind: writerfence.TargetAccount, ID: candidate.AccountId}] = true
		}
	}
	out := make([]writerfence.Key, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	return out
}

func rotationEpochVersions(versions []writerfence.Version) map[string]int64 {
	out := make(map[string]int64, len(versions))
	for _, version := range versions {
		out[string(version.Key.Kind)+"/"+version.Key.ID.String()] = version.Version
	}
	return out
}

func rotationAttachKnownEpochVersions(p *ownerapi.ExpiryRotationPreview, versions []writerfence.Version) {
	if p.SourceRevisions == nil {
		p.SourceRevisions = map[string]int64{}
	}
	for key, version := range rotationEpochVersions(versions) {
		p.SourceRevisions["epoch:"+key] = version
	}
}

func rotationAttachEpochVersions(ctx context.Context, db rotationRow, owner uuid.UUID, p *ownerapi.ExpiryRotationPreview) error {
	keys := rotationAuthorizationKeys(owner, *p)
	versions := make([]writerfence.Version, 0, len(keys))
	for _, key := range keys {
		var version int64
		if err := db.QueryRow(ctx, `SELECT version FROM public.tsw_rotation_epochs WHERE kind=$1 AND id=$2`, key.Kind, key.ID).Scan(&version); err != nil {
			return err
		}
		versions = append(versions, writerfence.Version{Key: key, Version: version})
	}
	rotationAttachKnownEpochVersions(p, versions)
	return nil
}

func (h *OwnerAuthHandler) ConfirmExpiryRotation(w http.ResponseWriter, r *http.Request, id uuid.UUID, _ ownerapi.ConfirmExpiryRotationParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var input ownerapi.ExpiryRotationConfirmation
	if !decodeJSON(w, r, &input) || !input.Confirmed || input.IdempotencyKey == uuid.Nil || len(input.Digest) != 64 || len(input.Assignments) == 0 || len(input.Assignments) > 1000 {
		writeProblem(w, r, 422, "confirmation_required", "Confirmation Required", "Confirm the exact preview with a unique key", 0)
		return
	}
	oid := uuid.MustParse(owner.OwnerID)
	initialTx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	p, replayKey, status, err := rotationStored(r.Context(), initialTx, oid, id)
	_ = initialTx.Rollback(r.Context())
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "preview_not_found", "Not Found", "Preview not found", 0)
		return
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	if status == "authorized" {
		assignments, valid := rotationAssignments(p, input.Assignments)
		if replayKey == input.IdempotencyKey && p.Digest == input.Digest && valid && rotationHash(assignments) == rotationHash(p.Assignments) {
			writeJSON(w, http.StatusOK, p)
			return
		}
		writeProblem(w, r, 409, "idempotency_conflict", "Conflict", "The authorization already exists with different confirmation facts", 0)
		return
	}
	if status != "ready" {
		writeProblem(w, r, 409, string(p.Status), "Not Authorizable", "No executable authorization was created", 0)
		return
	}
	assignments, valid := rotationAssignments(p, input.Assignments)
	if !valid {
		writeProblem(w, r, 409, "assignment_incomplete", "Incomplete Mapping", "Choose one distinct eligible candidate per replaceable slot; revise the draft for excess or mismatched candidates", 0)
		return
	}
	if p.Digest != input.Digest || !time.Now().Before(p.ExpiresAt) {
		writeProblem(w, r, 409, "preview_stale", "Stale Preview", "Re-preview changed or expired facts", 0)
		return
	}
	if h.rotationCapability == nil {
		writeProblem(w, r, 409, "pending_permission", "Permission Pending", "No production rotation evidence adapter is configured", 0)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	evidence, evidenceErr := h.rotationCapability.Evidence(ctx, oid)
	cancel()
	if evidenceErr != nil {
		writeProblem(w, r, 409, "facts_incomplete", "Evidence Incomplete", "Current management, seat, usage or protection evidence could not be reverified", 0)
		return
	}
	tx, versions, err := writerfence.BeginLocked(r.Context(), h.pool, rotationAuthorizationKeys(oid, p))
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	current, currentKey, currentStatus, err := rotationStored(r.Context(), tx, oid, id)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	if currentStatus == "authorized" {
		if currentKey == input.IdempotencyKey && current.Digest == input.Digest && rotationHash(current.Assignments) == rotationHash(assignments) {
			writeJSON(w, http.StatusOK, current)
			return
		}
		writeProblem(w, r, 409, "idempotency_conflict", "Conflict", "The authorization was committed by another request", 0)
		return
	}
	if currentStatus != "ready" || current.Digest != input.Digest || !time.Now().Before(current.ExpiresAt) {
		writeProblem(w, r, 409, "preview_stale", "Stale Preview", "Re-preview changed or expired facts", 0)
		return
	}
	fresh, err := h.rotationFacts(r.Context(), tx, oid, &evidence)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	rotationAttachKnownEpochVersions(&fresh, versions)
	freshAssignments, valid := rotationAssignments(fresh, assignments)
	if fresh.Status != "ready" || !valid || rotationHash(freshAssignments) != rotationHash(assignments) || rotationComparableDigest(fresh) != rotationComparableDigest(current) {
		writeProblem(w, r, 409, "preview_stale", "Stale Preview", "Current facts no longer match the confirmed preview", 0)
		return
	}
	epochs := rotationEpochVersions(versions)
	epochJSON, err := json.Marshal(epochs)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	authorizationDigest := rotationHash(struct {
		PreviewDigest string                              `json:"previewDigest"`
		FactDigest    string                              `json:"factDigest"`
		Assignments   []ownerapi.ExpiryRotationAssignment `json:"assignments"`
		Epochs        map[string]int64                    `json:"epochs"`
	}{current.Digest, rotationComparableDigest(fresh), assignments, epochs})
	assignmentsJSON, _ := json.Marshal(assignments)
	var authorizedAt time.Time
	err = tx.QueryRow(r.Context(), `UPDATE public.tsw_expiry_rotation_previews SET status='authorized',assignments=$2,authorization_digest=$3,idempotency_key=$4,authorized_by=$5,authorized_session=$6,authorized_at=now(),epoch_versions=$7 WHERE id=$1 AND status='ready' RETURNING authorized_at`, id, assignmentsJSON, authorizationDigest, input.IdempotencyKey, oid, owner.SessionID, epochJSON).Scan(&authorizedAt)
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.ExpiryRotationAuthorized, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: current.WorkspaceId.String(), EntityType: "expiry_rotation_preview", EntityID: id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.ExpiryRotationDetails{Digest: authorizationDigest, Action: "authorized"}, IdempotencyKey: id.String() + ":" + input.IdempotencyKey.String()})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		var conflict *pgconn.PgError
		if errors.As(err, &conflict) && conflict.Code == "23505" {
			writeProblem(w, r, 409, "idempotency_conflict", "Conflict", "The idempotency key already belongs to another authorization", 0)
			return
		}
		h.workspaceFailure(w, r, err)
		return
	}
	current.Status = "authorized"
	current.Authorized = true
	current.Assignments = assignments
	current.AuthorizationDigest = &authorizationDigest
	current.AuthorizedBy = &oid
	current.AuthorizedAt = &authorizedAt
	writeJSON(w, http.StatusOK, current)
}
func (h *OwnerAuthHandler) RevokeExpiryRotation(w http.ResponseWriter, r *http.Request, id uuid.UUID, _ ownerapi.RevokeExpiryRotationParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	// Serialize with Ticket 11 dispatch. Revocation does not claim that an
	// already issued remote request was undone.
	gate, err := h.rotationWorkspaceGate(r.Context(), uuid.MustParse(owner.OwnerID), id)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	defer gate.close()
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	oid := uuid.MustParse(owner.OwnerID)
	p, _, status, err := rotationStored(r.Context(), tx, oid, id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "preview_not_found", "Not Found", "Preview not found", 0)
		return
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	if status == "revoked" {
		writeJSON(w, 200, p)
		return
	}
	if status != "authorized" {
		writeProblem(w, r, 409, "not_authorized", "Not Authorized", "Only an authorization may be revoked", 0)
		return
	}
	err = tx.QueryRow(r.Context(), `UPDATE tsw_expiry_rotation_previews SET status='revoked',revoked_by=$2,revoked_at=now() WHERE id=$1 RETURNING revoked_at`, id, oid).Scan(&p.RevokedAt)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1 AND stopped_at IS NULL`, id)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE public.tsw_rotation_removal_slots SET state='stopped',lease_epoch=lease_epoch+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error_code='authorization_revoked',last_error='Authorization revoked; sent request obligations retained' WHERE preview_id=$1 AND state<>'stopped'`, id)
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.ExpiryRotationRevoked, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: p.WorkspaceId.String(), EntityType: "expiry_rotation_preview", EntityID: id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.ExpiryRotationDetails{Digest: *p.AuthorizationDigest, Action: "revoked"}, IdempotencyKey: id.String() + ":revoked"})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	p.Status = "revoked"
	p.Authorized = false
	writeJSON(w, 200, p)
}
