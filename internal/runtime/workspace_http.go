package runtime

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
	"github.com/teamseatwatch/teamseatwatch/internal/identity"
	"github.com/teamseatwatch/teamseatwatch/internal/task"
	"github.com/teamseatwatch/teamseatwatch/internal/workspace"
)

type motherAccountDTO = ownerapi.MotherAccount

type workspaceDTO = ownerapi.Workspace

type workspaceReadDTO = ownerapi.WorkspaceReadStatus

func (h *OwnerAuthHandler) authenticated(w http.ResponseWriter, r *http.Request, mutation bool) (ownerContext, bool) {
	if mutation && !h.requireMutation(w, r) {
		return ownerContext{}, false
	}
	owner, err := h.session(r, false)
	if err != nil {
		writeProblem(w, r, http.StatusUnauthorized, "session_expired", "Session Expired", "Authentication is required", 0)
		return ownerContext{}, false
	}
	return owner, true
}

func pagination(pageParam, sizeParam *int) (int, int, bool) {
	page, size := 1, 20
	if pageParam != nil {
		page = *pageParam
	}
	if sizeParam != nil {
		size = *sizeParam
	}
	return page, size, page >= 1 && size >= 1 && size <= 100
}

func validLength(value string, minimum, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func optionalLength(value *string, maximum int) bool {
	return value == nil || utf8.RuneCountInString(*value) <= maximum
}

func setETag(w http.ResponseWriter, version int64) {
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", version))
}

func ifMatch(raw string) (int64, bool) {
	raw = strings.Trim(raw, "\"")
	version, err := strconv.ParseInt(raw, 10, 64)
	return version, err == nil && version > 0
}

func (h *OwnerAuthHandler) listMotherAccounts(w http.ResponseWriter, r *http.Request, params ownerapi.ListMotherAccountsParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(params.Page, params.PageSize)
	if !ok {
		writeProblem(w, r, 400, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	order := "created_at DESC"
	sortValue := ""
	if params.Sort != nil {
		sortValue = string(*params.Sort)
	}
	switch sortValue {
	case "", "created_desc":
	case "name_asc":
		order = "display_name ASC, created_at DESC"
	default:
		writeProblem(w, r, 400, "invalid_sort", "Invalid Request", "Sort is not allowed", 0)
		return
	}
	rows, err := h.pool.Query(r.Context(), `SELECT id, display_name, platform_account_ref, status, version, updated_at, count(*) OVER() FROM tsw_mother_accounts ORDER BY `+order+` LIMIT $1 OFFSET $2`, size, (page-1)*size)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer rows.Close()
	response := ownerapi.MotherAccountList{Items: []ownerapi.MotherAccount{}, Page: page, PageSize: size}
	for rows.Next() {
		var item motherAccountDTO
		if err := rows.Scan(&item.Id, &item.DisplayName, &item.PlatformAccountRef, &item.Status, &item.Version, &item.UpdatedAt, &response.Total); err != nil {
			h.workspaceFailure(w, r, err)
			return
		}
		response.Items = append(response.Items, item)
	}
	if err := rows.Err(); err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *OwnerAuthHandler) createMotherAccount(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateMotherAccountJSONRequestBody
	if !decodeJSON(w, r, &request) {
		h.rejectOwnerMutation(w, r, owner, "mother_account.create", "invalid_request", http.StatusUnprocessableEntity, "invalid_account", "Invalid Account", "Account fields are invalid")
		return
	}
	displayName, loginIdentifier := strings.TrimSpace(request.DisplayName), strings.TrimSpace(request.LoginIdentifier)
	if !validLength(displayName, 1, 120) || !validLength(loginIdentifier, 1, 254) ||
		!validLength(request.Password, 1, 1024) || !optionalLength(request.PlatformAccountRef, 255) ||
		!optionalLength(request.TotpSecret, 1024) {
		h.rejectOwnerMutation(w, r, owner, "mother_account.create", "invalid_request", http.StatusUnprocessableEntity, "invalid_account", "Invalid Account", "Account fields are invalid")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var item motherAccountDTO
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_mother_accounts (display_name, platform_account_ref) VALUES ($1,NULLIF($2,'')) RETURNING id,display_name,platform_account_ref,status,version,updated_at`, displayName, strings.TrimSpace(stringValue(request.PlatformAccountRef))).Scan(&item.Id, &item.DisplayName, &item.PlatformAccountRef, &item.Status, &item.Version, &item.UpdatedAt)
	if err == nil {
		identifier, keyVersion, fingerprint, fingerprintErr := identity.Fingerprint(h.keyRing, identity.MotherLogin, loginIdentifier)
		if fingerprintErr != nil {
			err = fingerprintErr
		} else {
			_, err = tx.Exec(r.Context(), `INSERT INTO tsw_mother_account_credentials (mother_account_id,login_identifier,identifier_hmac,identifier_key_version,password_secret,totp_secret) VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::bytea)`, item.Id, identifier, fingerprint[:], keyVersion, []byte(request.Password), []byte(stringValue(request.TotpSecret)))
		}
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.MotherAccountCreated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, EntityType: "mother_account", EntityID: item.Id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.WorkspaceDetails{Result: "created"}, IdempotencyKey: item.Id.String() + ":mother-account"})
	}
	if err != nil {
		h.workspaceConflict(w, r, owner, "mother_account.create", err)
		return
	}
	// Credential creation is sensitive; replace the caller token in the same transaction.
	token, idle, err := h.rotateSessionTx(r.Context(), tx, owner, "session_revocation", r)
	if err != nil || tx.Commit(r.Context()) != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	auth.SetSessionCookie(w, token, idle)
	setETag(w, item.Version)
	writeJSON(w, http.StatusCreated, item)
}

func (h *OwnerAuthHandler) updateMotherAccount(w http.ResponseWriter, r *http.Request, params ownerapi.UpdateMotherAccountParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	version, ok := ifMatch(params.IfMatch)
	if !ok {
		h.rejectOwnerMutation(w, r, owner, "mother_account.update", "invalid_request", http.StatusPreconditionRequired, "if_match_required", "Precondition Required", "If-Match is required")
		return
	}
	var request ownerapi.UpdateMotherAccountJSONRequestBody
	if !decodeJSON(w, r, &request) {
		h.rejectOwnerMutation(w, r, owner, "mother_account.update", "invalid_request", http.StatusUnprocessableEntity, "invalid_account", "Invalid Account", "Account fields are invalid")
		return
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if !validLength(displayName, 1, 120) ||
		(string(request.Status) != "active" && string(request.Status) != "disabled") {
		h.rejectOwnerMutation(w, r, owner, "mother_account.update", "invalid_request", http.StatusUnprocessableEntity, "invalid_account", "Invalid Account", "Account fields are invalid")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var item motherAccountDTO
	err = tx.QueryRow(r.Context(), `UPDATE tsw_mother_accounts SET display_name=$3,status=$4,updated_at=now(),version=version+1 WHERE id=$1 AND version=$2 RETURNING id,display_name,platform_account_ref,status,version,updated_at`, r.PathValue("accountId"), version, displayName, string(request.Status)).Scan(&item.Id, &item.DisplayName, &item.PlatformAccountRef, &item.Status, &item.Version, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		h.rejectOwnerMutation(w, r, owner, "mother_account.update", "version_mismatch", http.StatusPreconditionFailed, "version_mismatch", "Precondition Failed", "The account changed")
		return
	}
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{
			Type: audit.MotherAccountUpdated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID,
			EntityType: "mother_account", EntityID: item.Id.String(), Outcome: audit.OutcomeSucceeded,
			CorrelationID: correlation(r), Details: audit.WorkspaceDetails{Result: "updated"},
			IdempotencyKey: item.Id.String() + ":updated:" + strconv.FormatInt(item.Version, 10),
		})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusOK, item)
}

func (h *OwnerAuthHandler) createWorkspace(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateWorkspaceJSONRequestBody
	if !decodeJSON(w, r, &request) {
		h.rejectOwnerMutation(w, r, owner, "workspace.create", "invalid_request", http.StatusUnprocessableEntity, "invalid_workspace", "Invalid Workspace", "Workspace fields are invalid")
		return
	}
	displayName, platformID := strings.TrimSpace(request.DisplayName), strings.TrimSpace(request.PlatformWorkspaceId)
	if !validLength(displayName, 1, 120) || !validLength(platformID, 1, 255) {
		h.rejectOwnerMutation(w, r, owner, "workspace.create", "invalid_request", http.StatusUnprocessableEntity, "invalid_workspace", "Invalid Workspace", "Workspace fields are invalid")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var item workspaceDTO
	err = tx.QueryRow(r.Context(), `WITH workspace AS (INSERT INTO tsw_workspaces (display_name,platform_workspace_id) VALUES ($1,$2) RETURNING *) INSERT INTO tsw_workspace_projections (workspace_id) SELECT id FROM workspace RETURNING workspace_id,'unknown',NULL::timestamptz,NULL::int,NULL::int,NULL::int,NULL::timestamptz,1,now()`, displayName, platformID).Scan(&item.Id, &item.OperationalState, &item.ActiveUntil, &item.SeatLimit, &item.MemberCount, &item.PendingInviteCount, &item.EvidenceExpiresAt, &item.Version, &item.UpdatedAt)
	item.DisplayName = displayName
	item.PlatformWorkspaceId = platformID
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.WorkspaceCreated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: item.Id.String(), EntityType: "workspace", EntityID: item.Id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.WorkspaceDetails{Result: "created"}, IdempotencyKey: item.Id.String() + ":created"})
	}
	if err != nil {
		h.workspaceConflict(w, r, owner, "workspace.create", err)
		return
	}
	if tx.Commit(r.Context()) != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	setETag(w, item.Version)
	writeJSON(w, 201, item)
}

func (h *OwnerAuthHandler) listWorkspaces(w http.ResponseWriter, r *http.Request, params ownerapi.ListWorkspacesParams) {
	sortValue, stateValue := "", ""
	if params.Sort != nil {
		sortValue = string(*params.Sort)
	}
	if params.OperationalState != nil {
		stateValue = string(*params.OperationalState)
	}
	h.workspaceList(w, r, false, params.Page, params.PageSize, sortValue, stateValue)
}
func (h *OwnerAuthHandler) listNeedsAttention(w http.ResponseWriter, r *http.Request, params ownerapi.ListWorkspacesNeedingAttentionParams) {
	h.workspaceList(w, r, true, params.Page, params.PageSize, "", "")
}

func (h *OwnerAuthHandler) workspaceList(w http.ResponseWriter, r *http.Request, attention bool, pageParam, sizeParam *int, sortValue, stateValue string) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(pageParam, sizeParam)
	if !ok {
		writeProblem(w, r, 400, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	if stateValue != "" && stateValue != "unknown" && stateValue != "operational" && stateValue != "deactivated" && stateValue != "not_found" {
		writeProblem(w, r, 400, "invalid_filter", "Invalid Request", "Filter is not allowed", 0)
		return
	}
	order := "projection.updated_at DESC"
	switch sortValue {
	case "", "updated_desc":
	case "name_asc":
		order = "workspace.display_name ASC"
	case "active_until_asc":
		order = "projection.active_until ASC NULLS LAST"
	default:
		writeProblem(w, r, 400, "invalid_sort", "Invalid Request", "Sort is not allowed", 0)
		return
	}
	where := "TRUE"
	if attention {
		where = `(projection.operational_state='unknown'
			OR projection.active_until <= now() + interval '7 days'
			OR projection.evidence_expires_at <= now() + interval '24 hours'
			OR EXISTS (
				SELECT 1 FROM tsw_workspace_observations observation
				WHERE observation.workspace_id=workspace.id
				  AND observation.source_kind='owner' AND observation.expires_at>now()
			))`
	}
	rows, err := h.pool.Query(r.Context(), `SELECT workspace.id,workspace.display_name,workspace.platform_workspace_id,projection.operational_state,projection.active_until,projection.seat_limit,projection.member_count,projection.pending_invite_count,projection.evidence_expires_at,workspace.version,projection.updated_at,count(*) OVER() FROM tsw_workspaces workspace JOIN tsw_workspace_projections projection ON projection.workspace_id=workspace.id WHERE (`+where+`) AND ($3::text='' OR projection.operational_state=$3) ORDER BY `+order+` LIMIT $1 OFFSET $2`, size, (page-1)*size, stateValue)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer rows.Close()
	response := ownerapi.WorkspaceList{Items: []ownerapi.Workspace{}, Page: page, PageSize: size}
	for rows.Next() {
		var item workspaceDTO
		if err := rows.Scan(&item.Id, &item.DisplayName, &item.PlatformWorkspaceId, &item.OperationalState, &item.ActiveUntil, &item.SeatLimit, &item.MemberCount, &item.PendingInviteCount, &item.EvidenceExpiresAt, &item.Version, &item.UpdatedAt, &response.Total); err != nil {
			h.workspaceFailure(w, r, err)
			return
		}
		response.Items = append(response.Items, item)
	}
	if err := rows.Err(); err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	writeJSON(w, 200, response)
}

func (h *OwnerAuthHandler) getWorkspace(w http.ResponseWriter, r *http.Request, params ownerapi.GetWorkspaceParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	observationPage, observationSize, memberPage, memberSize := 1, 20, 1, 20
	if params.ObservationPage != nil {
		observationPage = int(*params.ObservationPage)
	}
	if params.ObservationPageSize != nil {
		observationSize = int(*params.ObservationPageSize)
	}
	if params.MemberPage != nil {
		memberPage = int(*params.MemberPage)
	}
	if params.MemberPageSize != nil {
		memberSize = int(*params.MemberPageSize)
	}
	if observationPage < 1 || observationSize < 1 || observationSize > 100 || memberPage < 1 || memberSize < 1 || memberSize > 100 {
		writeProblem(w, r, 400, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	item, err := h.workspaceByID(r, r.PathValue("workspaceId"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "workspace_not_found", "Not Found", "Workspace was not found", 0)
		return
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	detail := ownerapi.WorkspaceDetail{
		Workspace: item, Observations: []ownerapi.WorkspaceObservation{}, ObservationPage: observationPage, ObservationPageSize: observationSize,
		Members: []ownerapi.WorkspaceMember{}, MemberPage: memberPage, MemberPageSize: memberSize, SnapshotCompleteness: "unknown",
	}
	if err := h.pool.QueryRow(r.Context(), `SELECT
		(SELECT active_until FROM tsw_workspace_observations WHERE workspace_id=$1 AND observation_type='subscription' AND outcome_code='operational' AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),
		(SELECT active_until FROM tsw_workspace_observations WHERE workspace_id=$1 AND outcome_code='manual_expiration_corrected' AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),
		(SELECT outcome_code FROM tsw_workspace_observations WHERE workspace_id=$1 AND outcome_code IN ('manual_deactivated','manual_recovered') AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),
		(SELECT source_endpoint FROM tsw_workspace_observations WHERE workspace_id=$1 AND outcome_code IN ('manual_deactivated','manual_recovered') AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),
		(SELECT observed_at FROM tsw_workspace_observations WHERE workspace_id=$1 AND outcome_code IN ('manual_deactivated','manual_recovered') AND expires_at>now() ORDER BY observed_at DESC LIMIT 1),
		(SELECT expires_at FROM tsw_workspace_observations WHERE workspace_id=$1 AND outcome_code IN ('manual_deactivated','manual_recovered') AND expires_at>now() ORDER BY observed_at DESC LIMIT 1)`, r.PathValue("workspaceId")).Scan(&detail.PlatformActiveUntil, &detail.ManualActiveUntil, &detail.ManualConclusion, &detail.ManualSource, &detail.ManualObservedAt, &detail.ManualExpiresAt); err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	var binding ownerapi.WorkspaceBinding
	err = h.pool.QueryRow(r.Context(), `
		SELECT binding.id,binding.mother_account_id,account.display_name,binding.started_at
		FROM tsw_mother_workspace_bindings binding
		JOIN tsw_mother_accounts account ON account.id=binding.mother_account_id
		WHERE binding.workspace_id=$1 AND binding.ended_at IS NULL`, r.PathValue("workspaceId")).Scan(
		&binding.Id, &binding.MotherAccountId, &binding.MotherAccountName, &binding.StartedAt,
	)
	if err == nil {
		detail.Binding = &binding
	} else if !errors.Is(err, pgx.ErrNoRows) {
		h.workspaceFailure(w, r, err)
		return
	}
	if err := h.pool.QueryRow(r.Context(), `SELECT count(*) FROM tsw_workspace_observations WHERE workspace_id=$1 AND expires_at>now()`, r.PathValue("workspaceId")).Scan(&detail.ObservationTotal); err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	rows, err := h.pool.Query(r.Context(), `SELECT observation_type,source_kind,source_endpoint,outcome_code,active_until,observed_at,expires_at FROM tsw_workspace_observations WHERE workspace_id=$1 AND expires_at>now() ORDER BY observed_at DESC LIMIT $2 OFFSET $3`, r.PathValue("workspaceId"), observationSize, (observationPage-1)*observationSize)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	for rows.Next() {
		var typ, source, endpoint, outcome string
		var activeUntil *time.Time
		var observed, expires time.Time
		if err := rows.Scan(&typ, &source, &endpoint, &outcome, &activeUntil, &observed, &expires); err != nil {
			rows.Close()
			h.workspaceFailure(w, r, err)
			return
		}
		detail.Observations = append(detail.Observations, ownerapi.WorkspaceObservation{
			Type: typ, SourceKind: source, SourceEndpoint: endpoint,
			OutcomeCode: outcome, ActiveUntil: activeUntil, ObservedAt: observed, ExpiresAt: expires,
		})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	var snapshotID, snapshotSourceEndpoint string
	var snapshotObservedAt, snapshotExpiresAt time.Time
	err = h.pool.QueryRow(r.Context(), `SELECT id,source_endpoint,completeness,observed_at,expires_at FROM tsw_workspace_member_snapshots WHERE workspace_id=$1 AND expires_at>now() ORDER BY observed_at DESC LIMIT 1`, r.PathValue("workspaceId")).Scan(
		&snapshotID, &snapshotSourceEndpoint, &detail.SnapshotCompleteness, &snapshotObservedAt, &snapshotExpiresAt,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		h.workspaceFailure(w, r, err)
		return
	}
	if err == nil {
		sourceKind := string(workspace.SourcePlatform)
		detail.SnapshotSourceKind = &sourceKind
		detail.SnapshotSourceEndpoint = &snapshotSourceEndpoint
		detail.SnapshotObservedAt = &snapshotObservedAt
		detail.SnapshotExpiresAt = &snapshotExpiresAt
		if err := h.pool.QueryRow(r.Context(), `SELECT count(*) FROM tsw_workspace_member_snapshot_entries WHERE snapshot_id=$1`, snapshotID).Scan(&detail.MemberTotal); err != nil {
			h.workspaceFailure(w, r, err)
			return
		}
		rows, err = h.pool.Query(r.Context(), `SELECT entry_kind,member_identifier,platform_status,platform_role FROM tsw_workspace_member_snapshot_entries WHERE snapshot_id=$1 ORDER BY entry_kind,member_identifier LIMIT $2 OFFSET $3`, snapshotID, memberSize, (memberPage-1)*memberSize)
		if err != nil {
			h.workspaceFailure(w, r, err)
			return
		}
		for rows.Next() {
			var member ownerapi.WorkspaceMember
			if err := rows.Scan(&member.Kind, &member.Identifier, &member.Status, &member.Role); err != nil {
				rows.Close()
				h.workspaceFailure(w, r, err)
				return
			}
			detail.Members = append(detail.Members, member)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			h.workspaceFailure(w, r, err)
			return
		}
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusOK, detail)
}

func (h *OwnerAuthHandler) workspaceByID(r *http.Request, id string) (workspaceDTO, error) {
	var item workspaceDTO
	err := h.pool.QueryRow(r.Context(), `SELECT workspace.id,workspace.display_name,workspace.platform_workspace_id,projection.operational_state,projection.active_until,projection.seat_limit,projection.member_count,projection.pending_invite_count,projection.evidence_expires_at,workspace.version,projection.updated_at FROM tsw_workspaces workspace JOIN tsw_workspace_projections projection ON projection.workspace_id=workspace.id WHERE workspace.id=$1`, id).Scan(&item.Id, &item.DisplayName, &item.PlatformWorkspaceId, &item.OperationalState, &item.ActiveUntil, &item.SeatLimit, &item.MemberCount, &item.PendingInviteCount, &item.EvidenceExpiresAt, &item.Version, &item.UpdatedAt)
	return item, err
}

func (h *OwnerAuthHandler) updateWorkspace(w http.ResponseWriter, r *http.Request, params ownerapi.UpdateWorkspaceParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	version, ok := ifMatch(params.IfMatch)
	if !ok {
		h.rejectOwnerMutation(w, r, owner, "workspace.update", "invalid_request", http.StatusPreconditionRequired, "if_match_required", "Precondition Required", "If-Match is required")
		return
	}
	var request ownerapi.UpdateWorkspaceJSONRequestBody
	if !decodeJSON(w, r, &request) {
		h.rejectOwnerMutation(w, r, owner, "workspace.update", "invalid_request", http.StatusUnprocessableEntity, "invalid_workspace", "Invalid Workspace", "Display name is invalid")
		return
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if !validLength(displayName, 1, 120) {
		h.rejectOwnerMutation(w, r, owner, "workspace.update", "invalid_request", http.StatusUnprocessableEntity, "invalid_workspace", "Invalid Workspace", "Display name is invalid")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE tsw_workspaces SET display_name=$3,updated_at=now(),version=version+1 WHERE id=$1 AND version=$2`, r.PathValue("workspaceId"), version, displayName)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	if result.RowsAffected() != 1 {
		h.rejectOwnerMutation(w, r, owner, "workspace.update", "version_mismatch", http.StatusPreconditionFailed, "version_mismatch", "Precondition Failed", "The Workspace changed")
		return
	}
	var nextVersion int64
	if err = tx.QueryRow(r.Context(), `SELECT version FROM tsw_workspaces WHERE id=$1`, r.PathValue("workspaceId")).Scan(&nextVersion); err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{
			Type: audit.WorkspaceUpdated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID,
			RetentionScopeID: r.PathValue("workspaceId"), EntityType: "workspace", EntityID: r.PathValue("workspaceId"),
			Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r),
			Details:        audit.WorkspaceDetails{Result: "updated"},
			IdempotencyKey: r.PathValue("workspaceId") + ":updated:" + strconv.FormatInt(nextVersion, 10),
		})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	item, err := h.workspaceByID(r, r.PathValue("workspaceId"))
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusOK, item)
}

func (h *OwnerAuthHandler) createBinding(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateMotherWorkspaceBindingJSONRequestBody
	if !decodeJSON(w, r, &request) {
		h.rejectOwnerMutation(w, r, owner, "binding.create", "invalid_request", http.StatusUnprocessableEntity, "invalid_binding", "Invalid Relationship", "Both resources are required")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var response ownerapi.Binding
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_mother_workspace_bindings (mother_account_id,workspace_id) VALUES ($1,$2) RETURNING id,mother_account_id,workspace_id,status,started_at,version`, request.MotherAccountId, request.WorkspaceId).Scan(&response.Id, &response.MotherAccountId, &response.WorkspaceId, &response.Status, &response.StartedAt, &response.Version)
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.BindingCreated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: request.WorkspaceId.String(), EntityType: "workspace_binding", EntityID: response.Id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.WorkspaceDetails{Result: "bound"}, IdempotencyKey: response.Id.String() + ":bound"})
	}
	if err != nil {
		h.workspaceConflict(w, r, owner, "binding.create", err)
		return
	}
	if tx.Commit(r.Context()) != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	setETag(w, response.Version)
	writeJSON(w, http.StatusCreated, response)
}

func (h *OwnerAuthHandler) refreshWorkspace(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.RefreshWorkspaceFactsJSONRequestBody
	if !decodeJSON(w, r, &request) || !validLength(request.IdempotencyKey, 8, 128) {
		h.rejectOwnerMutation(w, r, owner, "workspace_read.create", "invalid_request", http.StatusUnprocessableEntity, "invalid_idempotency_key", "Invalid Request", "A stable idempotency key is required")
		return
	}
	item, _, err := h.workspaceTasks.CreateWorkspaceRead(r.Context(), r.PathValue("workspaceId"), request.IdempotencyKey, correlation(r))
	if errors.Is(err, task.ErrIdempotencyConflict) {
		h.rejectOwnerMutation(w, r, owner, "workspace_read.create", "idempotency_conflict", http.StatusConflict, "idempotency_conflict", "Conflict", "The key belongs to a different Workspace")
		return
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			h.rejectOwnerMutation(w, r, owner, "workspace_read.create", "workspace_not_found", http.StatusNotFound, "workspace_not_found", "Not Found", "Workspace was not found")
			return
		}
		h.workspaceFailure(w, r, err)
		return
	}
	response, err := workspaceReadResponse(item)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	if response.Status == "queued" || response.Status == "running" || response.Status == "retry_wait" {
		retry := 2
		response.RetryAfterSeconds = &retry
		w.Header().Set("Retry-After", "2")
	}
	writeJSON(w, http.StatusAccepted, response)
}

func (h *OwnerAuthHandler) getWorkspaceRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	item, err := h.workspaceTasks.Get(r.Context(), r.PathValue("readId"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, http.StatusNotFound, "workspace_read_not_found", "Not Found", "Read status was not found", 0)
		return
	}
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	response, err := workspaceReadResponse(item)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	if response.Status == "queued" || response.Status == "running" || response.Status == "retry_wait" {
		retry := 2
		response.RetryAfterSeconds = &retry
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *OwnerAuthHandler) manualVerifyWorkspace(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateWorkspaceManualVerificationJSONRequestBody
	if !decodeJSON(w, r, &request) {
		h.rejectOwnerMutation(w, r, owner, "manual_verification.create", "invalid_request", http.StatusUnprocessableEntity, "invalid_manual_verification", "Invalid Verification", "Conclusion, source, and time are required")
		return
	}
	now := time.Now().UTC()
	conclusion := string(request.Conclusion)
	validConclusion := (conclusion == "deactivated" || conclusion == "recovered") && request.ActiveUntil == nil
	validExpiration := conclusion == "expiration_corrected" && request.ActiveUntil != nil
	if (!validConclusion && !validExpiration) ||
		(request.Source != "platform_ui" && request.Source != "platform_subscription_page") ||
		request.ObservedAt.IsZero() || request.ObservedAt.After(now) || request.ObservedAt.Before(now.Add(-7*24*time.Hour)) {
		h.rejectOwnerMutation(w, r, owner, "manual_verification.create", "invalid_request", http.StatusUnprocessableEntity, "invalid_manual_verification", "Invalid Verification", "Conclusion, source, and time are required")
		return
	}
	activeUntil := ""
	if request.ActiveUntil != nil {
		activeUntil = request.ActiveUntil.UTC().Format(time.RFC3339)
	}
	workspaceID := r.PathValue("workspaceId")
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	observationID, err := h.workspaceFacts.RecordManualVerificationTx(r.Context(), tx, workspace.ManualVerification{
		WorkspaceID: workspaceID, OwnerID: owner.OwnerID,
		Source: string(request.Source), Conclusion: conclusion, ObservedAt: request.ObservedAt, ActiveUntil: request.ActiveUntil,
	})
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{
			Type: audit.ManualVerified, Actor: audit.ActorOwner, OwnerID: owner.OwnerID,
			RetentionScopeID: workspaceID, EntityType: "workspace", EntityID: workspaceID,
			Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r),
			Details: audit.ManualVerificationDetails{
				Conclusion: conclusion, Source: string(request.Source),
				ObservedAt: request.ObservedAt.UTC().Format(time.RFC3339), ActiveUntil: activeUntil,
			},
			IdempotencyKey: observationID + ":manual",
		})
	}
	var token string
	var idle time.Time
	if err == nil {
		token, idle, err = h.rotateSessionTx(r.Context(), tx, owner, "workspace_manual_verification", r)
	}
	if err != nil {
		h.workspaceConflict(w, r, owner, "manual_verification.create", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	auth.SetSessionCookie(w, token, idle)
	item, err := h.workspaceByID(r, workspaceID)
	if err != nil {
		h.workspaceFailure(w, r, err)
		return
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusOK, item)
}

func workspaceReadResponse(item task.Task) (workspaceReadDTO, error) {
	id, err := uuid.Parse(item.ID)
	if err != nil {
		return workspaceReadDTO{}, err
	}
	workspaceID, err := uuid.Parse(item.WorkspaceID)
	if err != nil {
		return workspaceReadDTO{}, err
	}
	return workspaceReadDTO{
		Id: id, WorkspaceId: workspaceID,
		Status:    ownerapi.WorkspaceReadStatusStatus(item.Status),
		CreatedAt: item.CreatedAt, FinishedAt: item.FinishedAt,
	}, nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (h *OwnerAuthHandler) rejectOwnerMutation(w http.ResponseWriter, r *http.Request, owner ownerContext, operation, reason string, status int, code, title, detail string) {
	tx, err := h.pool.Begin(r.Context())
	if err == nil {
		fingerprint := auth.SourceFingerprint(r.RemoteAddr, r.UserAgent())
		_, err = audit.Write(r.Context(), tx, audit.Event{
			Type: audit.OwnerMutationRejected, Actor: audit.ActorOwner, OwnerID: owner.OwnerID,
			EntityType: "owner", EntityID: owner.OwnerID, Outcome: audit.OutcomeDenied,
			CorrelationID: correlation(r), SourceFingerprint: fingerprint[:],
			Details:        audit.OwnerMutationRejectionDetails{Operation: operation, Reason: reason},
			IdempotencyKey: uuid.NewString(),
		})
	}
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(r.Context())
		}
		h.workspaceFailure(w, r, err)
		return
	}
	if commitErr := tx.Commit(r.Context()); commitErr != nil {
		_ = tx.Rollback(r.Context())
		h.workspaceFailure(w, r, commitErr)
		return
	}
	writeProblem(w, r, status, code, title, detail, 0)
}

func (h *OwnerAuthHandler) workspaceConflict(w http.ResponseWriter, r *http.Request, owner ownerContext, operation string, err error) {
	code := "workspace_conflict"
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			h.rejectOwnerMutation(w, r, owner, operation, "conflict", http.StatusConflict, code, "Conflict", "The resource already exists or is currently bound")
			return
		case "23503", "23514":
			h.rejectOwnerMutation(w, r, owner, operation, "invalid_request", http.StatusUnprocessableEntity, "invalid_workspace_resource", "Invalid Resource", "The referenced resource or fields are invalid")
			return
		}
	}
	h.workspaceFailure(w, r, err)
}

// workspaceFailure 把底层错误记入服务端日志（带 request_id），对外只写固定 5xx problem。
func (h *OwnerAuthHandler) workspaceFailure(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("workspace_data_unavailable", "request_id", RequestIDFromContext(r.Context()), "error", err)
	writeProblem(w, r, 500, "workspace_unavailable", "Internal Server Error", "Workspace data is temporarily unavailable", 0)
}
