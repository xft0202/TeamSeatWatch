package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

type removalFailure string

func (e removalFailure) Error() string { return string(e) }

type removalAuthorization struct {
	preview       ownerapi.ExpiryRotationPreview
	assignments   []ownerapi.ExpiryRotationAssignment
	epochs        map[string]int64
	digest        string
	session       uuid.UUID
	active        bool
	reconcileOnly bool // observations only; cannot dispatch or release a slot
}

// Parse the immutable Ticket 10 facts separately from the response projection:
// its original ready status, not the current authorized status, is hashed.
func loadRemovalAuthorization(ctx context.Context, db rotationRow, owner, id uuid.UUID) (removalAuthorization, error) {
	var a removalAuthorization
	var facts, assignments, epochRaw []byte
	var digest string
	err := db.QueryRow(ctx, `SELECT facts,digest,assignments,epoch_versions,COALESCE(authorization_digest,''),COALESCE(authorized_session,'00000000-0000-0000-0000-000000000000')::uuid,status='authorized' AND revoked_at IS NULL AND expires_at>clock_timestamp() FROM public.tsw_expiry_rotation_previews WHERE id=$1 AND owner_id=$2`, id, owner).Scan(&facts, &digest, &assignments, &epochRaw, &a.digest, &a.session, &a.active)
	if err != nil {
		return a, err
	}
	if json.Unmarshal(facts, &a.preview) != nil || json.Unmarshal(assignments, &a.assignments) != nil || json.Unmarshal(epochRaw, &a.epochs) != nil {
		return a, removalFailure("authorization_corrupt")
	}
	p := a.preview
	if p.PolicyVersion == nil || *p.PolicyVersion != rotationPreviewPolicyVersion || p.Source != "official_owner_ab" || p.Status != "ready" || digest != p.Digest || rotationDigest(p) != digest || a.session == uuid.Nil {
		return a, removalFailure("authorization_corrupt")
	}
	exact, valid := rotationAssignments(p, a.assignments)
	if !valid || rotationHash(exact) != rotationHash(a.assignments) || len(a.epochs) != len(rotationAuthorizationKeys(owner, p)) {
		return a, removalFailure("authorization_corrupt")
	}
	for _, key := range rotationAuthorizationKeys(owner, p) {
		scope := string(key.Kind) + "/" + key.ID.String()
		if a.epochs[scope] < 1 || p.SourceRevisions["epoch:"+scope] != a.epochs[scope] {
			return a, removalFailure("authorization_corrupt")
		}
	}
	expected := rotationHash(struct {
		PreviewDigest string                              `json:"previewDigest"`
		FactDigest    string                              `json:"factDigest"`
		Assignments   []ownerapi.ExpiryRotationAssignment `json:"assignments"`
		Epochs        map[string]int64                    `json:"epochs"`
	}{p.Digest, rotationComparableDigest(p), a.assignments, a.epochs})
	if expected != a.digest {
		return a, removalFailure("authorization_digest_changed")
	}
	a.preview.Id = id
	return a, nil
}

// These session locks are NOT epoch transactions. Migration 29 makes covered
// writers take the corresponding exclusive xact lock, so their source facts
// cannot commit between the short locked preflight and bounded HTTP dispatch.
// Source locks precede the workspace gate to avoid lock inversion.
// The workspace gate covers claims, dispatch and commits, not remote reads:
// stop/revoke can fence a preflight or verification still in flight.
type removalGate struct {
	conn            *pgxpool.Conn
	keys            []writerfence.Key
	workspace       uuid.UUID
	workspaceLocked bool
}

func (h *OwnerAuthHandler) lockRemovalGate(ctx context.Context, workspace uuid.UUID, keys []writerfence.Key) (*removalGate, error) {
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	gate := &removalGate{conn: conn, workspace: workspace}
	ordered := append([]writerfence.Key(nil), keys...)
	sort.Slice(ordered, func(i, j int) bool {
		return string(ordered[i].Kind)+ordered[i].ID.String() < string(ordered[j].Kind)+ordered[j].ID.String()
	})
	for _, key := range ordered {
		if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock_shared(hashtextextended('tsw.rotation.action.'||$1,0))`, string(key.Kind)+"/"+key.ID.String()); err != nil {
			gate.close()
			return nil, err
		}
		gate.keys = append(gate.keys, key)
	}
	if err = gate.lockWorkspace(ctx); err != nil {
		gate.close()
		return nil, err
	}
	return gate, nil
}
func (g *removalGate) lockWorkspace(ctx context.Context) error {
	if g.workspaceLocked {
		return nil
	}
	_, err := g.conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended('tsw.rotation.workspace.'||$1::text,0))`, g.workspace.String())
	if err == nil {
		g.workspaceLocked = true
	}
	return err
}
func (g *removalGate) unlockWorkspace(ctx context.Context) error {
	if !g.workspaceLocked {
		return nil
	}
	var unlocked bool
	err := g.conn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended('tsw.rotation.workspace.'||$1::text,0))`, g.workspace.String()).Scan(&unlocked)
	if err == nil && !unlocked {
		err = removalFailure("dispatch_gate_lost")
	}
	if err == nil {
		g.workspaceLocked = false
	}
	return err
}
func (g *removalGate) close() {
	if g == nil || g.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// A failed cleanup must discard the physical session, not return locked state
	// to the pool. This connection owns no unrelated advisory locks.
	_, err := g.conn.Exec(ctx, `SELECT pg_advisory_unlock_all()`)
	if err != nil {
		_ = g.conn.Conn().Close(ctx)
	}
	g.conn.Release()
	g.conn = nil
}
func (h *OwnerAuthHandler) rotationWorkspaceGate(ctx context.Context, owner, preview uuid.UUID) (*removalGate, error) {
	var workspace uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT workspace_id FROM public.tsw_expiry_rotation_previews WHERE id=$1 AND owner_id=$2`, preview, owner).Scan(&workspace); err != nil {
		return nil, err
	}
	return h.lockRemovalGate(ctx, workspace, nil)
}

func (h *OwnerAuthHandler) removalLocalFacts(ctx context.Context, tx pgx.Tx, a removalAuthorization, owner ownerContext, versions []writerfence.Version) (platform.WorkspaceAccess, platform.PersonalSession, workspaceAccessBinding, string, error) {
	var access platform.WorkspaceAccess
	var personal platform.PersonalSession
	var b workspaceAccessBinding
	var platformID string
	fail := func(code string) (platform.WorkspaceAccess, platform.PersonalSession, workspaceAccessBinding, string, error) {
		return access, personal, b, platformID, removalFailure(code)
	}
	current, err := loadRemovalAuthorization(ctx, tx, uuid.MustParse(owner.OwnerID), a.preview.Id)
	if err != nil {
		return access, personal, b, platformID, err
	}
	if current.digest != a.digest {
		return fail("authorization_corrupt")
	}
	if a.reconcileOnly {
		return h.removalReadOnlyFacts(ctx, tx, a, owner)
	}
	if !current.active {
		return fail("authorization_inactive")
	}
	if current.digest != a.digest || rotationHash(current.epochs) != rotationHash(a.epochs) || rotationHash(rotationEpochVersions(versions)) != rotationHash(a.epochs) {
		return fail("writer_epoch_changed")
	}
	var sessionsOK bool
	err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM public.tsw_owner_sessions s JOIN public.tsw_owners o ON o.id=s.owner_id WHERE s.id=ANY($1::uuid[]) AND s.owner_id=$2 AND s.auth_version=o.auth_version AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())=$3`, []uuid.UUID{a.session, uuid.MustParse(owner.SessionID)}, owner.OwnerID, func() int {
		if a.session.String() == owner.SessionID {
			return 1
		}
		return 2
	}()).Scan(&sessionsOK)
	if err != nil {
		return access, personal, b, platformID, err
	}
	if !sessionsOK {
		return fail("owner_session_inactive")
	}
	var keyVersion int16
	var nonce, sealed []byte
	var role string
	p := a.preview
	err = tx.QueryRow(ctx, `SELECT w.platform_workspace_id,d.visibility_run_id,d.session_generation,d.mother_revision,v.workspace_role,s.key_version,s.nonce,s.sealed_session FROM public.tsw_operation_selection_drafts d JOIN public.tsw_workspaces w ON w.id=d.workspace_id JOIN public.tsw_mother_accounts m ON m.id=d.mother_account_id AND m.status='active' JOIN public.tsw_mother_account_credentials c ON c.mother_account_id=m.id AND c.secret_revision=d.mother_revision JOIN public.tsw_mother_personal_sessions s ON s.mother_account_id=m.id AND s.generation=d.session_generation AND s.secret_revision=c.secret_revision AND s.expires_at>clock_timestamp() JOIN public.tsw_mother_workspace_visibility v ON v.workspace_id=w.id AND v.mother_account_id=m.id AND v.run_id=d.visibility_run_id AND v.access_status='readable' JOIN public.tsw_mother_discoveries discovery ON discovery.mother_account_id=m.id AND discovery.run_id=d.visibility_run_id AND discovery.status='discovered' AND discovery.session_generation=s.generation AND discovery.secret_revision=c.secret_revision WHERE d.id=$1 AND d.owner_id=$2 AND d.version=$3 AND d.step='complete' AND d.workspace_id=$4 AND d.mother_account_id=$5 AND d.verification_id=$6`, p.DraftId, owner.OwnerID, p.DraftVersion, p.WorkspaceId, p.MotherAccountId, p.VerificationId).Scan(&platformID, &b.run, &b.generation, &b.revision, &role, &keyVersion, &nonce, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return fail("source_binding_changed")
	}
	if err != nil {
		return access, personal, b, platformID, err
	}
	if role != "owner" {
		return fail("workspace_owner_required")
	}
	b.motherID = p.MotherAccountId
	b.workspaceID = p.WorkspaceId
	access, b, err = h.currentWorkspaceAccessTx(ctx, tx, b, platformID, false)
	if err != nil {
		return fail("workspace_token_invalid")
	}
	personal, err = openPersonalSession(h.keyRing, p.MotherAccountId, b.revision, uint16(keyVersion), nonce, sealed)
	if err != nil || !platform.ValidatePersonalRefresh(platform.PersonalRefreshResult{Status: "ready", Session: personal}, time.Now()) {
		return fail("personal_session_invalid")
	}
	for _, slot := range p.Slots {
		if slot.Decision != "replaceable" {
			continue
		}
		var identifier, state, protection string
		var used bool
		var expires time.Time
		err = tx.QueryRow(ctx, `SELECT t.identifier,u.usage_state,u.ever_used,u.expires_at,COALESCE(protection.status,'none') FROM public.tsw_target_accounts t JOIN LATERAL (SELECT usage_state,ever_used,expires_at,observed_at FROM public.tsw_rotation_usage_ledger WHERE target_account_id=t.id AND workspace_id=$2 UNION ALL SELECT 'used',true,expires_at,observed_at FROM public.tsw_rotation_join_usage_evidence WHERE target_account_id=t.id AND result='positive' AND scope='workspace' AND workspace_id=$2 ORDER BY observed_at DESC LIMIT 1) u ON true LEFT JOIN public.tsw_rotation_effective_protections protection ON protection.target_account_id=t.id WHERE t.id=$1`, slot.AccountId, p.WorkspaceId).Scan(&identifier, &state, &used, &expires, &protection)
		if errors.Is(err, pgx.ErrNoRows) {
			return fail("usage_evidence_required")
		}
		if err != nil {
			return access, personal, b, platformID, err
		}
		if identifier != slot.Identifier {
			return fail("original_identity_changed")
		}
		if state != "used" || !used || !expires.After(time.Now()) {
			return fail("usage_evidence_changed")
		}
		if protection != "none" {
			return fail("global_protection_changed")
		}
	}
	return access, personal, b, platformID, nil
}

// Inactive authorizations can observe an already-sent obligation using current
// credentials. These observations never reauthorize drift or release a slot.
func (h *OwnerAuthHandler) removalReadOnlyFacts(ctx context.Context, tx pgx.Tx, a removalAuthorization, owner ownerContext) (platform.WorkspaceAccess, platform.PersonalSession, workspaceAccessBinding, string, error) {
	var access platform.WorkspaceAccess
	var personal platform.PersonalSession
	var b workspaceAccessBinding
	var platformID, role string
	var keyVersion int16
	var nonce, sealed []byte
	var currentSession bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_owner_sessions s JOIN public.tsw_owners o ON o.id=s.owner_id WHERE s.id=$1 AND s.owner_id=$2 AND s.auth_version=o.auth_version AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp())`, owner.SessionID, owner.OwnerID).Scan(&currentSession)
	if err != nil || !currentSession {
		return access, personal, b, platformID, removalFailure("owner_session_inactive")
	}
	err = tx.QueryRow(ctx, `SELECT w.platform_workspace_id,d.run_id,d.session_generation,d.secret_revision,v.workspace_role,s.key_version,s.nonce,s.sealed_session FROM public.tsw_workspaces w JOIN public.tsw_mother_accounts m ON m.id=$2 AND m.status='active' JOIN public.tsw_mother_account_credentials c ON c.mother_account_id=m.id JOIN public.tsw_mother_personal_sessions s ON s.mother_account_id=m.id AND s.secret_revision=c.secret_revision AND s.expires_at>clock_timestamp() JOIN public.tsw_mother_discoveries d ON d.mother_account_id=m.id AND d.session_generation=s.generation AND d.secret_revision=c.secret_revision AND d.status='discovered' JOIN public.tsw_mother_workspace_visibility v ON v.workspace_id=w.id AND v.mother_account_id=m.id AND v.run_id=d.run_id AND v.access_status='readable' WHERE w.id=$1`, a.preview.WorkspaceId, a.preview.MotherAccountId).Scan(&platformID, &b.run, &b.generation, &b.revision, &role, &keyVersion, &nonce, &sealed)
	if err != nil || role != "owner" {
		return access, personal, b, platformID, removalFailure("workspace_owner_required")
	}
	b.motherID = a.preview.MotherAccountId
	b.workspaceID = a.preview.WorkspaceId
	access, b, err = h.currentWorkspaceAccessTx(ctx, tx, b, platformID, false)
	if err != nil {
		return access, personal, b, platformID, removalFailure("workspace_token_invalid")
	}
	personal, err = openPersonalSession(h.keyRing, b.motherID, b.revision, uint16(keyVersion), nonce, sealed)
	if err != nil || !platform.ValidatePersonalRefresh(platform.PersonalRefreshResult{Status: "ready", Session: personal}, time.Now()) {
		return access, personal, b, platformID, removalFailure("personal_session_invalid")
	}
	return access, personal, b, platformID, nil
}

func (h *OwnerAuthHandler) removalError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "removal_not_found", "Not Found", "Authorization or slot not found", 0)
		return
	}
	var f removalFailure
	if errors.As(err, &f) {
		writeProblem(w, r, 409, string(f), "Removal Blocked", "Recheck the original authorization and slot", 0)
		return
	}
	var conflict *pgconn.PgError
	if errors.As(err, &conflict) && conflict.Code == "23505" {
		writeProblem(w, r, 409, "idempotency_conflict", "Conflict", "This removal scope or key already exists", 0)
		return
	}
	h.workspaceFailure(w, r, err)
}

func (h *OwnerAuthHandler) StartRotationRemoval(w http.ResponseWriter, r *http.Request, id uuid.UUID, _ ownerapi.StartRotationRemovalParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var input ownerapi.RotationRemovalStart
	if !decodeJSON(w, r, &input) || !input.Confirmed || input.IdempotencyKey == uuid.Nil || len(input.AuthorizationDigest) != 64 {
		writeProblem(w, r, 422, "confirmation_required", "Confirmation Required", "Confirm the frozen authorization", 0)
		return
	}
	oid := uuid.MustParse(owner.OwnerID)
	a, err := loadRemovalAuthorization(r.Context(), h.pool, oid, id)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	if a.digest != input.AuthorizationDigest {
		h.removalError(w, r, removalFailure("authorization_digest_changed"))
		return
	}
	gate, err := h.lockRemovalGate(r.Context(), a.preview.WorkspaceId, rotationAuthorizationKeys(oid, a.preview))
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	defer gate.close()
	var key uuid.UUID
	err = h.pool.QueryRow(r.Context(), `SELECT idempotency_key FROM public.tsw_rotation_removals WHERE preview_id=$1`, id).Scan(&key)
	if err == nil {
		if key != input.IdempotencyKey {
			h.removalError(w, r, removalFailure("idempotency_conflict"))
			return
		}
		h.writeRemoval(w, r, oid, id)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		h.removalError(w, r, err)
		return
	}
	tx, versions, err := writerfence.BeginLocked(r.Context(), h.pool, rotationAuthorizationKeys(oid, a.preview))
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	if _, _, _, _, err = h.removalLocalFacts(r.Context(), tx, a, owner, versions); err != nil {
		h.removalError(w, r, err)
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO public.tsw_rotation_removals(preview_id,workspace_id,owner_id,authorization_digest,idempotency_key,started_session) VALUES($1,$2,$3,$4,$5,$6)`, id, a.preview.WorkspaceId, oid, a.digest, input.IdempotencyKey, owner.SessionID)
	for _, assignment := range a.assignments {
		if err != nil {
			break
		}
		var original ownerapi.ExpiryRotationSlot
		for _, slot := range a.preview.Slots {
			if slot.PlatformMemberId == assignment.PlatformMemberId {
				original = slot
				break
			}
		}
		var outstanding bool
		err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_removal_slots WHERE workspace_id=$1 AND platform_member_id=$2 AND (uncertain_obligation OR state IN ('pending','lease_acquired','remove_requested','absent_verification_pending')))`, a.preview.WorkspaceId, assignment.PlatformMemberId).Scan(&outstanding)
		if err == nil && outstanding {
			err = removalFailure("original_slot_obligation_exists")
		}
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO public.tsw_rotation_removal_slots(preview_id,workspace_id,platform_member_id,original_account_id,candidate_account_id,identifier,seat_type) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, a.preview.WorkspaceId, assignment.PlatformMemberId, original.AccountId, assignment.AccountId, original.Identifier, original.SeatType)
		}
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.RotationRemovalStarted, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: a.preview.WorkspaceId.String(), EntityType: "rotation_removal", EntityID: id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), IdempotencyKey: id.String() + ":removal-start", Details: audit.RotationRemovalDetails{Digest: a.digest}})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	h.writeRemoval(w, r, oid, id)
}

func (h *OwnerAuthHandler) removalProgress(ctx context.Context, owner, id uuid.UUID) (ownerapi.RotationRemoval, error) {
	var out ownerapi.RotationRemoval
	out.Slots = []ownerapi.RotationRemovalSlot{}
	err := h.pool.QueryRow(ctx, `SELECT r.preview_id,r.workspace_id,r.authorization_digest,r.stopped_at IS NOT NULL,w.display_name,r.created_at,r.stopped_at IS NULL AND p.status='authorized' AND p.revoked_at IS NULL AND p.expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM public.tsw_owner_sessions s JOIN public.tsw_owners o ON o.id=s.owner_id WHERE s.id=p.authorized_session::uuid AND s.owner_id=r.owner_id AND s.auth_version=o.auth_version AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()) AND NOT EXISTS(SELECT 1 FROM jsonb_each_text(p.epoch_versions) v LEFT JOIN public.tsw_rotation_epochs e ON v.key=e.kind||'/'||e.id::text WHERE e.version IS NULL OR e.version::text<>v.value) FROM public.tsw_rotation_removals r JOIN public.tsw_expiry_rotation_previews p ON p.id=r.preview_id JOIN public.tsw_workspaces w ON w.id=r.workspace_id WHERE r.preview_id=$1 AND r.owner_id=$2`, id, owner).Scan(&out.PreviewId, &out.WorkspaceId, &out.AuthorizationDigest, &out.Stopped, &out.WorkspaceName, &out.CreatedAt, &out.WriteAllowed)
	if err != nil {
		return out, err
	}
	rows, err := h.pool.Query(ctx, `SELECT s.id,s.platform_member_id,s.original_account_id,s.candidate_account_id,s.identifier,s.seat_type,s.state,s.attempt_count,s.lease_epoch,s.lease_expires_at,s.remote_request_id,s.verification_id,s.uncertain_obligation,s.last_error_code,s.updated_at,EXISTS(SELECT 1 FROM public.tsw_rotation_released_slots released WHERE released.id=s.id) FROM public.tsw_rotation_removal_slots s WHERE s.preview_id=$1 ORDER BY s.created_at,s.id`, id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var s ownerapi.RotationRemovalSlot
		err = rows.Scan(&s.Id, &s.PlatformMemberId, &s.OriginalAccountId, &s.CandidateAccountId, &s.Identifier, &s.SeatType, &s.State, &s.AttemptCount, &s.LeaseEpoch, &s.LeaseExpiresAt, &s.RemoteRequestId, &s.VerificationId, &s.UncertainObligation, &s.LastErrorCode, &s.UpdatedAt, &s.CandidateReady)
		if err != nil {
			return out, err
		}
		out.Slots = append(out.Slots, s)
	}
	return out, rows.Err()
}
func (h *OwnerAuthHandler) writeRemoval(w http.ResponseWriter, r *http.Request, owner, id uuid.UUID) {
	out, err := h.removalProgress(r.Context(), owner, id)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}
func (h *OwnerAuthHandler) GetRotationRemoval(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	h.writeRemoval(w, r, uuid.MustParse(owner.OwnerID), id)
}

func (h *OwnerAuthHandler) ListRotationRemovals(w http.ResponseWriter, r *http.Request, params ownerapi.ListRotationRemovalsParams) {
	owner, ok := h.authenticated(w, r, false)
	if !ok {
		return
	}
	page := 1
	if params.Page != nil {
		page = *params.Page
	}
	if page < 1 || page > 1000000 {
		writeProblem(w, r, 422, "invalid_page", "Invalid Page", "Choose an available history page", 0)
		return
	}
	out := ownerapi.RotationRemovalHistory{Items: []ownerapi.RotationRemovalHistoryItem{}, Page: page}
	if err := h.pool.QueryRow(r.Context(), `SELECT count(*) FROM public.tsw_rotation_removals WHERE owner_id=$1`, owner.OwnerID).Scan(&out.Total); err != nil {
		h.removalError(w, r, err)
		return
	}
	rows, err := h.pool.Query(r.Context(), `SELECT r.preview_id,w.display_name,r.created_at,r.stopped_at IS NOT NULL FROM public.tsw_rotation_removals r JOIN public.tsw_workspaces w ON w.id=r.workspace_id WHERE r.owner_id=$1 ORDER BY r.created_at DESC,r.preview_id DESC LIMIT 20 OFFSET $2`, owner.OwnerID, (page-1)*20)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var item ownerapi.RotationRemovalHistoryItem
		if err = rows.Scan(&item.PreviewId, &item.WorkspaceName, &item.CreatedAt, &item.Stopped); err != nil {
			h.removalError(w, r, err)
			return
		}
		out.Items = append(out.Items, item)
	}
	if err = rows.Err(); err != nil {
		h.removalError(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}

func (h *OwnerAuthHandler) StopRotationRemoval(w http.ResponseWriter, r *http.Request, id uuid.UUID, _ ownerapi.StopRotationRemovalParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var input ownerapi.RotationRemovalAction
	if !decodeJSON(w, r, &input) || !input.Confirmed {
		writeProblem(w, r, 422, "confirmation_required", "Confirmation Required", "Confirm stop", 0)
		return
	}
	oid := uuid.MustParse(owner.OwnerID)
	gate, err := h.rotationWorkspaceGate(r.Context(), oid, id)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	defer gate.close()
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var stopped bool
	var digest string
	err = tx.QueryRow(r.Context(), `SELECT stopped_at IS NOT NULL,authorization_digest FROM public.tsw_rotation_removals WHERE preview_id=$1 AND owner_id=$2 FOR UPDATE`, id, oid).Scan(&stopped, &digest)
	if err == nil && !stopped {
		_, err = tx.Exec(r.Context(), `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, id)
	}
	if err == nil && !stopped {
		_, err = tx.Exec(r.Context(), `UPDATE public.tsw_rotation_removal_slots SET state='stopped',lease_epoch=lease_epoch+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error_code='owner_stopped',last_error='Stopped; any sent request remains an obligation' WHERE preview_id=$1 AND state<>'stopped'`, id)
	}
	if err == nil && !stopped {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.RotationRemovalStopped, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: gate.workspace.String(), EntityType: "rotation_removal", EntityID: id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), IdempotencyKey: id.String() + ":removal-stop", Details: audit.RotationRemovalDetails{Digest: digest}})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	h.writeRemoval(w, r, oid, id)
}

type removalLease struct {
	id, token, owner         uuid.UUID
	epoch                    int64
	expires                  time.Time
	requested                bool
	member, identifier, seat string
	requestID                *uuid.UUID
	readOnly                 bool
}

func (h *OwnerAuthHandler) claimRemoval(ctx context.Context, a removalAuthorization, owner ownerContext, slot uuid.UUID, verifyOnly bool) (removalLease, platform.WorkspaceAccess, platform.PersonalSession, workspaceAccessBinding, string, error) {
	var l removalLease
	l.id = slot
	l.token = uuid.New()
	l.owner = uuid.New()
	l.readOnly = a.reconcileOnly
	tx, versions, err := writerfence.BeginLocked(ctx, h.pool, rotationAuthorizationKeys(uuid.MustParse(owner.OwnerID), a.preview))
	if err != nil {
		return l, platform.WorkspaceAccess{}, platform.PersonalSession{}, workspaceAccessBinding{}, "", err
	}
	defer tx.Rollback(ctx)
	access, personal, b, platformID, err := h.removalLocalFacts(ctx, tx, a, owner, versions)
	if err != nil {
		return l, access, personal, b, platformID, err
	}
	var state string
	var leaseValid, stopped bool
	var original, candidate uuid.UUID
	err = tx.QueryRow(ctx, `SELECT s.state,s.remote_request_id,s.platform_member_id,s.identifier,s.seat_type,s.original_account_id,s.candidate_account_id,COALESCE(s.lease_expires_at>clock_timestamp(),false),r.stopped_at IS NOT NULL FROM public.tsw_rotation_removal_slots s JOIN public.tsw_rotation_removals r ON r.preview_id=s.preview_id WHERE s.id=$1 AND s.preview_id=$2 AND r.authorization_digest=$3 FOR UPDATE OF s,r`, slot, a.preview.Id, a.digest).Scan(&state, &l.requestID, &l.member, &l.identifier, &l.seat, &original, &candidate, &leaseValid, &stopped)
	if err != nil {
		return l, access, personal, b, platformID, err
	}
	matched := false
	for _, assignment := range a.assignments {
		if assignment.PlatformMemberId == l.member && assignment.AccountId == candidate {
			for _, s := range a.preview.Slots {
				if s.PlatformMemberId == l.member && s.AccountId == original && s.Identifier == l.identifier && s.SeatType == l.seat {
					matched = true
				}
			}
		}
	}
	if !matched {
		return l, access, personal, b, platformID, removalFailure("slot_not_authorized")
	}
	if (stopped || state == "stopped") && !a.reconcileOnly {
		return l, access, personal, b, platformID, removalFailure("removal_stopped")
	}
	if state == "absent_verified" && !verifyOnly {
		return l, access, personal, b, platformID, removalFailure("slot_already_verified")
	}
	if leaseValid {
		return l, access, personal, b, platformID, removalFailure("slot_lease_busy")
	}
	var workspaceBusy bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_removal_slots WHERE workspace_id=$1 AND id<>$2 AND lease_expires_at>clock_timestamp())`, a.preview.WorkspaceId, slot).Scan(&workspaceBusy)
	if err != nil {
		return l, access, personal, b, platformID, err
	}
	if workspaceBusy {
		return l, access, personal, b, platformID, removalFailure("workspace_removal_busy")
	}
	l.requested = l.requestID != nil
	if (verifyOnly || a.reconcileOnly) && !l.requested {
		return l, access, personal, b, platformID, removalFailure("slot_not_requested")
	}
	deadline := a.preview.ExpiresAt
	if a.reconcileOnly {
		deadline = time.Now().Add(60 * time.Second)
	}
	// Clock expiry does not advance an epoch. Bound the dispatch context by both
	// the original authorizer and current requester session, not just the token.
	sessionsForLease := []uuid.UUID{uuid.MustParse(owner.SessionID)}
	if !a.reconcileOnly && a.session.String() != owner.SessionID {
		sessionsForLease = append(sessionsForLease, a.session)
	}
	err = tx.QueryRow(ctx, `UPDATE public.tsw_rotation_removal_slots SET state=CASE WHEN $5 THEN 'stopped' WHEN remote_request_id IS NULL THEN 'lease_acquired' ELSE 'absent_verification_pending' END,uncertain_obligation=remote_request_id IS NOT NULL,absent_verified_at=NULL,lease_owner=$2,lease_token=$3,lease_epoch=lease_epoch+1,lease_expires_at=LEAST(clock_timestamp()+interval '60 seconds',$4,$6,(SELECT min(LEAST(idle_expires_at,absolute_expires_at)) FROM public.tsw_owner_sessions WHERE id=ANY($7::uuid[]))),attempt_count=attempt_count+1,last_error_code='',last_error='' WHERE id=$1 RETURNING lease_epoch,lease_expires_at`, slot, l.owner, l.token, deadline, a.reconcileOnly, access.ExpiresAt, sessionsForLease).Scan(&l.epoch, &l.expires)
	if err == nil {
		err = tx.Commit(ctx)
	}
	return l, access, personal, b, platformID, err
}

func (h *OwnerAuthHandler) currentRemovalRole(ctx context.Context, personal platform.PersonalSession, platformID string) (string, error) {
	if h.discovery == nil {
		return "", removalFailure("workspace_owner_required")
	}
	result, err := h.discovery.Discover(ctx, personal)
	if err != nil || !platform.ValidateDiscovery(result) || result.Status != "discovered" {
		return "", removalFailure("workspace_owner_required")
	}
	for _, w := range result.Workspaces {
		if w.PlatformID == platformID && w.Access == "readable" && w.Role == "owner" {
			return rotationHash(result), nil
		}
	}
	return "", removalFailure("workspace_owner_required")
}

// The complete live roster must be the frozen roster minus ONLY committed
// released original slots. Both remote IDs and canonical account identities are
// checked; new aliases, roles, seats and unrelated members fail closed.
func (h *OwnerAuthHandler) checkRemovalSnapshot(ctx context.Context, a removalAuthorization, l removalLease, snapshot platform.ExactMemberSnapshot, allowAbsent bool) (bool, error) {
	fact := snapshot.Fact
	if fact.Outcome != platform.OutcomeOperational || fact.Completeness != platform.Complete || fact.MemberCount == nil || *fact.MemberCount != len(fact.Members) || snapshot.DeclaredMemberCount != len(fact.Members) || fact.ObservedAt.IsZero() || fact.ObservedAt.After(time.Now().Add(time.Second)) || fact.ObservedAt.Before(time.Now().Add(-30*time.Second)) {
		return false, removalFailure("membership_snapshot_incomplete")
	}
	if a.reconcileOnly {
		aliases := map[string]string{}
		identities := map[string]bool{}
		present := false
		for _, member := range fact.Members {
			identifier := strings.ToLower(strings.TrimSpace(member.Identifier))
			if member.PlatformMemberID == "" || identifier == "" || identities[identifier] {
				return false, removalFailure("identity_conflict")
			}
			identities[identifier] = true
			for _, id := range []string{member.PlatformMemberID, member.PlatformAccountUserID} {
				if id == "" {
					continue
				}
				if previous, exists := aliases[id]; exists && previous != identifier {
					return false, removalFailure("identity_conflict")
				}
				aliases[id] = identifier
				if id == l.member {
					if identifier != l.identifier {
						return false, removalFailure("identity_conflict")
					}
					present = true
				}
			}
			if identifier == l.identifier {
				present = true
			}
		}
		return !present, nil
	}
	type frozen struct{ id, identifier, role, seat string }
	expected := map[string]frozen{}
	rows, err := h.pool.Query(ctx, `SELECT e.platform_member_id,e.identifier,COALESCE(e.role,''),COALESCE(e.seat_type,'') FROM public.tsw_workspace_verification_entries e WHERE e.verification_id=$1 AND e.kind='member' AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_removal_slots s WHERE s.preview_id=$2 AND s.platform_member_id=e.platform_member_id AND s.state='absent_verified' AND s.verification_id IS NOT NULL)`, a.preview.VerificationId, a.preview.Id)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var f frozen
		if err = rows.Scan(&f.id, &f.identifier, &f.role, &f.seat); err != nil {
			rows.Close()
			return false, err
		}
		if f.id == "" || expected[f.id].id != "" {
			rows.Close()
			return false, removalFailure("member_identity_conflict")
		}
		expected[f.id] = f
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	seenIDs, seenIdentifiers := map[string]bool{}, map[string]bool{}
	present := false
	for _, m := range fact.Members {
		identifier := strings.ToLower(strings.TrimSpace(m.Identifier))
		id := m.PlatformMemberID
		if m.Kind != "member" || id == "" || identifier == "" || seenIdentifiers[identifier] || seenIDs[id] || m.PlatformAccountUserID != "" && seenIDs[m.PlatformAccountUserID] {
			return false, removalFailure("member_identity_conflict")
		}
		seenIdentifiers[identifier] = true
		seenIDs[id] = true
		if m.PlatformAccountUserID != "" {
			seenIDs[m.PlatformAccountUserID] = true
		}
		f, exists := expected[id]
		if !exists || identifier != f.identifier || m.SeatType != f.seat || m.Role != f.role {
			return false, removalFailure("member_identity_or_seat_changed")
		}
		if id == l.member || m.PlatformAccountUserID == l.member || identifier == l.identifier {
			if id != l.member || identifier != l.identifier || m.SeatType != l.seat || m.Role == "owner" || m.Role == "admin" {
				return false, removalFailure("member_identity_conflict")
			}
			present = true
		}
		delete(expected, id)
	}
	if allowAbsent && !present {
		delete(expected, l.member)
	}
	if len(expected) != 0 || !allowAbsent && !present {
		return false, removalFailure("frozen_roster_changed")
	}
	return !present, nil
}

func (h *OwnerAuthHandler) removalLeaseTx(ctx context.Context, a removalAuthorization, owner ownerContext, l removalLease) (pgx.Tx, workspaceAccessBinding, error) {
	tx, versions, err := writerfence.BeginLocked(ctx, h.pool, rotationAuthorizationKeys(uuid.MustParse(owner.OwnerID), a.preview))
	if err != nil {
		return nil, workspaceAccessBinding{}, err
	}
	_, _, b, _, err := h.removalLocalFacts(ctx, tx, a, owner, versions)
	if err == nil {
		var valid bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_removal_slots s JOIN public.tsw_rotation_removals r ON r.preview_id=s.preview_id WHERE s.id=$1 AND s.preview_id=$2 AND s.lease_owner=$3 AND s.lease_token=$4 AND s.lease_epoch=$5 AND s.lease_expires_at>clock_timestamp() AND s.state<>'absent_verified' AND ($6 OR s.state<>'stopped' AND r.stopped_at IS NULL))`, l.id, a.preview.Id, l.owner, l.token, l.epoch, a.reconcileOnly).Scan(&valid)
		if err == nil && !valid {
			err = removalFailure("slot_lease_stale")
		}
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, b, err
	}
	return tx, b, nil
}
func (h *OwnerAuthHandler) reserveRemovalRequest(ctx context.Context, a removalAuthorization, owner ownerContext, l *removalLease) error {
	tx, _, err := h.removalLeaseTx(ctx, a, owner, *l)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	requestID := uuid.New()
	result, err := tx.Exec(ctx, `UPDATE public.tsw_rotation_removal_slots SET state='remove_requested',remote_request_id=$2,requested_at=clock_timestamp(),uncertain_obligation=true WHERE id=$1 AND remote_request_id IS NULL`, l.id, requestID)
	if err == nil && result.RowsAffected() != 1 {
		err = removalFailure("request_already_reserved")
	}
	if err == nil {
		_, err = audit.Write(ctx, tx, audit.Event{Type: audit.RotationRemovalRequested, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: a.preview.WorkspaceId.String(), EntityType: "rotation_slot", EntityID: l.id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: requestID.String(), IdempotencyKey: requestID.String(), Details: audit.RotationRemovalDetails{Digest: a.digest, LeaseEpoch: l.epoch}})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err == nil {
		l.requestID = &requestID
		l.requested = true
	}
	return err
}
func (h *OwnerAuthHandler) removalReceipt(ctx context.Context, a removalAuthorization, owner ownerContext, l removalLease, status int, code string) error {
	tx, _, err := h.removalLeaseTx(ctx, a, owner, l)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	state := "absent_verification_pending"
	if code != "" {
		state = "remote_result_uncertain"
	}
	_, err = tx.Exec(ctx, `UPDATE public.tsw_rotation_removal_slots SET state=$2,remote_http_status=NULLIF($3,0),last_error_code=$4,last_error=$4 WHERE id=$1`, l.id, state, status, code)
	if err == nil {
		err = tx.Commit(ctx)
	}
	return err
}
func (h *OwnerAuthHandler) finishRemovalFailure(ctx context.Context, l removalLease, code string) error {
	// Failure never releases a slot or erases the may-have-reached marker. CAS
	// includes DB-time expiry even if nobody has reclaimed the lease yet.
	result, err := h.pool.Exec(ctx, `UPDATE public.tsw_rotation_removal_slots SET state=CASE WHEN $6 THEN state WHEN remote_request_id IS NULL THEN 'blocked' ELSE 'remote_result_uncertain' END,last_error_code=$5,last_error=$5,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=$1 AND lease_owner=$2 AND lease_token=$3 AND lease_epoch=$4 AND lease_expires_at>clock_timestamp() AND state<>'absent_verified' AND ($6 OR state<>'stopped' AND EXISTS(SELECT 1 FROM public.tsw_rotation_removals r WHERE r.preview_id=tsw_rotation_removal_slots.preview_id AND r.stopped_at IS NULL))`, l.id, l.owner, l.token, l.epoch, code, l.readOnly)
	if err == nil && result.RowsAffected() != 1 {
		return removalFailure("slot_lease_stale")
	}
	return err
}
func (h *OwnerAuthHandler) commitRemovalEvidence(ctx context.Context, a removalAuthorization, owner ownerContext, l removalLease, b workspaceAccessBinding, snapshot platform.ExactMemberSnapshot, ownerEvidence string, absent bool) error {
	tx, current, err := h.removalLeaseTx(ctx, a, owner, l)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if current != b {
		return removalFailure("workspace_token_changed")
	}
	raw, err := json.Marshal(append([]platform.Member{}, snapshot.Fact.Members...))
	if err != nil {
		return err
	}
	id := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO public.tsw_rotation_removal_evidence(id,slot_id,lease_epoch,authorization_digest,token_exchange_id,owner_evidence_id,observed_at,members,target_absent,complete) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,true)`, id, l.id, l.epoch, a.digest, b.exchangeID, ownerEvidence, snapshot.Fact.ObservedAt, raw, absent)
	if err == nil {
		state, code := "remote_result_uncertain", "member_still_present"
		if absent {
			state, code = "absent_verified", ""
		}
		if a.reconcileOnly {
			state, code = "stopped", "authorization_inactive"
		}
		_, err = tx.Exec(ctx, `UPDATE public.tsw_rotation_removal_slots SET state=$2,verification_id=$3,absent_verified_at=CASE WHEN $4 THEN clock_timestamp() ELSE NULL END,uncertain_obligation=NOT $4,last_error_code=$5,last_error=$5,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=$1`, l.id, state, id, absent && !a.reconcileOnly, code)
	}
	if err == nil {
		_, err = audit.Write(ctx, tx, audit.Event{Type: audit.RotationRemovalVerified, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: a.preview.WorkspaceId.String(), EntityType: "rotation_slot", EntityID: l.id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: id.String(), IdempotencyKey: id.String(), Details: audit.RotationRemovalDetails{Digest: a.digest, LeaseEpoch: l.epoch, Absent: absent}})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	return err
}

func (h *OwnerAuthHandler) RunRotationRemovalSlot(w http.ResponseWriter, r *http.Request, id, slot uuid.UUID, _ ownerapi.RunRotationRemovalSlotParams) {
	h.runRotationRemovalSlot(w, r, id, slot, false)
}
func (h *OwnerAuthHandler) VerifyRotationRemovalSlot(w http.ResponseWriter, r *http.Request, id, slot uuid.UUID, _ ownerapi.VerifyRotationRemovalSlotParams) {
	h.runRotationRemovalSlot(w, r, id, slot, true)
}
func (h *OwnerAuthHandler) runRotationRemovalSlot(w http.ResponseWriter, r *http.Request, id, slot uuid.UUID, verifyOnly bool) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var input ownerapi.RotationRemovalAction
	if !decodeJSON(w, r, &input) || !input.Confirmed {
		writeProblem(w, r, 422, "confirmation_required", "Confirmation Required", "Confirm this original slot action", 0)
		return
	}
	oid := uuid.MustParse(owner.OwnerID)
	a, err := loadRemovalAuthorization(r.Context(), h.pool, oid, id)
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	if h.workspaceMemberRemover == nil {
		h.removalError(w, r, removalFailure("removal_adapter_unavailable"))
		return
	}
	gate, err := h.lockRemovalGate(r.Context(), a.preview.WorkspaceId, rotationAuthorizationKeys(oid, a.preview))
	if err != nil {
		h.removalError(w, r, err)
		return
	}
	defer gate.close()
	if verifyOnly {
		var observationOnly bool
		err = h.pool.QueryRow(r.Context(), `SELECT r.stopped_at IS NOT NULL OR NOT (p.status='authorized' AND p.revoked_at IS NULL AND p.expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM jsonb_each_text(p.epoch_versions) v LEFT JOIN public.tsw_rotation_epochs e ON v.key=e.kind||'/'||e.id::text WHERE e.version IS NULL OR e.version::text<>v.value) FROM public.tsw_rotation_removals r JOIN public.tsw_expiry_rotation_previews p ON p.id=r.preview_id WHERE r.preview_id=$1`, id).Scan(&observationOnly)
		if err != nil {
			h.removalError(w, r, err)
			return
		}
		a.reconcileOnly = observationOnly
	}
	l, access, personal, b, platformID, err := h.claimRemoval(r.Context(), a, owner, slot, verifyOnly)
	if err != nil {
		if err == removalFailure("slot_already_verified") {
			h.writeRemoval(w, r, oid, id)
		} else {
			h.removalError(w, r, err)
		}
		return
	}
	if err = gate.unlockWorkspace(r.Context()); err != nil {
		h.removalError(w, r, err)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), l.expires.Add(-time.Second))
	defer cancel()
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer finishCancel()
	fail := func(code string) {
		if failureErr := h.finishRemovalFailure(finishCtx, l, code); failureErr != nil {
			h.removalError(w, r, failureErr)
			return
		}
		h.writeRemoval(w, r, oid, id)
	}
	ownerEvidence, err := h.currentRemovalRole(ctx, personal, platformID)
	if err != nil {
		fail("workspace_owner_required")
		return
	}
	before, err := h.workspaceMemberRemover.SnapshotWorkspaceMembers(ctx, access, platformID)
	if err != nil {
		fail("membership_snapshot_incomplete")
		return
	}
	absent, err := h.checkRemovalSnapshot(ctx, a, l, before, l.requested)
	if err != nil {
		var f removalFailure
		if errors.As(err, &f) {
			fail(string(f))
		} else {
			fail("membership_verification_failed")
		}
		return
	}
	if l.requested {
		// Crash/reentry always reconciles the original request. Presence does not
		// authorize a second DELETE, even under another key or renewed lease.
		if err = gate.lockWorkspace(finishCtx); err != nil {
			h.removalError(w, r, err)
			return
		}
		if err = h.commitRemovalEvidence(finishCtx, a, owner, l, b, before, ownerEvidence, absent); err != nil {
			h.removalError(w, r, err)
			return
		}
		h.writeRemoval(w, r, oid, id)
		return
	}
	if err = gate.lockWorkspace(ctx); err != nil {
		h.removalError(w, r, err)
		return
	}
	if err = h.reserveRemovalRequest(ctx, a, owner, &l); err != nil {
		h.removalError(w, r, err)
		return
	}
	// Probe the physical action-lock session immediately before dispatch. A lost
	// gate cannot manufacture another DELETE because intent is already durable.
	if _, err = gate.conn.Exec(ctx, `SELECT 1`); err != nil {
		fail("dispatch_gate_lost")
		return
	}
	result, remoteErr := h.workspaceMemberRemover.RemoveWorkspaceMember(ctx, access, platformID, l.member, l.requestID.String())
	code := ""
	if remoteErr != nil || !result.Accepted {
		code = "remote_result_uncertain"
	}
	if err = h.removalReceipt(finishCtx, a, owner, l, result.HTTPStatus, code); err != nil {
		h.removalError(w, r, err)
		return
	}
	if code != "" {
		fail(code)
		return
	}
	if err = gate.unlockWorkspace(finishCtx); err != nil {
		h.removalError(w, r, err)
		return
	}
	// A 2xx receipt is still an obligation. Owner role and complete membership are
	// independently re-read AFTER the write, and persisted together with release.
	ownerEvidence, err = h.currentRemovalRole(ctx, personal, platformID)
	if err != nil {
		fail("workspace_owner_required")
		return
	}
	after, err := h.workspaceMemberRemover.SnapshotWorkspaceMembers(ctx, access, platformID)
	if err != nil {
		fail("membership_snapshot_incomplete")
		return
	}
	absent, err = h.checkRemovalSnapshot(ctx, a, l, after, true)
	if err != nil {
		fail("membership_verification_failed")
		return
	}
	if err = gate.lockWorkspace(finishCtx); err != nil {
		h.removalError(w, r, err)
		return
	}
	if err = h.commitRemovalEvidence(finishCtx, a, owner, l, b, after, ownerEvidence, absent); err != nil {
		h.removalError(w, r, err)
		return
	}
	h.writeRemoval(w, r, oid, id)
}
