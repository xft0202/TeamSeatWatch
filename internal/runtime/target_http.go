package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
	"github.com/teamseatwatch/teamseatwatch/internal/identity"
	targetdomain "github.com/teamseatwatch/teamseatwatch/internal/target"
	"github.com/teamseatwatch/teamseatwatch/internal/task"
)

func scanTargetAccount(scanner interface{ Scan(...any) error }) (ownerapi.TargetAccount, error) {
	var item ownerapi.TargetAccount
	var probeStatus *string
	err := scanner.Scan(
		&item.Id, &item.Identifier, &item.DisplayLabel, &item.Status,
		&item.HasPassword, &item.HasTotp, &item.HasRecovery, &item.SecretRevision,
		&probeStatus, &item.LatestProbeHttpStatus, &item.LatestProbeErrorCode,
		&item.LatestProbeEndpoint, &item.LatestProbeOrigin, &item.LatestProbedAt,
		&item.LastVerifiedAt, &item.Version, &item.UpdatedAt,
	)
	if err == nil && probeStatus != nil {
		status := ownerapi.TargetProbeClassification(*probeStatus)
		item.LatestProbeStatus = &status
	}
	return item, err
}

const targetProjectionSQL = `target.id,target.identifier,target.display_label,target.status,
	octet_length(credentials.password_secret)>0,credentials.totp_secret IS NOT NULL,
	credentials.recovery_secret IS NOT NULL,credentials.secret_revision,
	credentials.latest_probe_status,credentials.latest_probe_http_status,
	credentials.latest_probe_error_code,credentials.latest_probe_endpoint_key,
	credentials.latest_probe_origin,credentials.latest_probed_at,
	credentials.last_verified_at,target.version,target.updated_at`

func (h *OwnerAuthHandler) listTargetAccounts(w http.ResponseWriter, r *http.Request, params ownerapi.ListTargetAccountsParams) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	page, size, ok := pagination(params.Page, params.PageSize)
	if !ok {
		writeProblem(w, r, 400, "invalid_pagination", "Invalid Request", "Pagination is invalid", 0)
		return
	}
	sortValue, statusValue, probeValue, searchValue := "", "", "", ""
	if params.Sort != nil {
		sortValue = string(*params.Sort)
	}
	if params.Status != nil {
		statusValue = string(*params.Status)
	}
	if params.ProbeStatus != nil {
		probeValue = string(*params.ProbeStatus)
	}
	if params.Search != nil {
		searchValue = strings.ToLower(strings.TrimSpace(*params.Search))
	}
	order := "target.created_at DESC"
	switch sortValue {
	case "", "created_desc":
	case "identifier_asc":
		order = "target.identifier ASC"
	case "probed_desc":
		order = "credentials.latest_probed_at DESC NULLS LAST,target.created_at DESC"
	default:
		writeProblem(w, r, 400, "invalid_sort", "Invalid Request", "Sort is not allowed", 0)
		return
	}
	if statusValue != "" && statusValue != "active" && statusValue != "disabled" ||
		!validTargetProbeFilter(probeValue) || utf8.RuneCountInString(searchValue) > 254 {
		writeProblem(w, r, 400, "invalid_filter", "Invalid Request", "Filter is not allowed", 0)
		return
	}
	rows, err := h.pool.Query(r.Context(), `SELECT `+targetProjectionSQL+`,count(*) OVER()
		FROM tsw_target_accounts target JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		WHERE ($3='' OR target.status=$3)
		  AND ($4='' OR ($4='unprobed' AND credentials.latest_probe_status IS NULL) OR credentials.latest_probe_status=$4)
		  AND ($5='' OR target.identifier ILIKE '%'||$5||'%' OR target.display_label ILIKE '%'||$5||'%')
		ORDER BY `+order+` LIMIT $1 OFFSET $2`, size, (page-1)*size, statusValue, probeValue, searchValue)
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	defer rows.Close()
	response := ownerapi.TargetAccountList{Items: []ownerapi.TargetAccount{}, Page: page, PageSize: size}
	for rows.Next() {
		var total int64
		item, err := scanTargetAccount(rowWithTotal{Rows: rows, total: &total})
		if err != nil {
			h.targetFailure(w, r)
			return
		}
		response.Total = total
		response.Items = append(response.Items, item)
	}
	if rows.Err() != nil {
		h.targetFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type rowWithTotal struct {
	pgx.Rows
	total *int64
}

func (row rowWithTotal) Scan(values ...any) error {
	return row.Rows.Scan(append(values, row.total)...)
}

func validTargetProbeFilter(value string) bool {
	switch value {
	case "", "available", "credential_invalid", "definitely_unavailable", "transient_failure", "unknown", "unprobed":
		return true
	default:
		return false
	}
}

func (h *OwnerAuthHandler) createTargetAccount(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateTargetAccountJSONRequestBody
	if !decodeJSON(w, r, &request) {
		h.rejectOwnerMutation(w, r, owner, "target_account.create", "invalid_request", 422, "invalid_target_account", "Invalid Target Account", "Target account fields are invalid")
		return
	}
	identifier, display := strings.ToLower(strings.TrimSpace(request.Identifier)), strings.TrimSpace(stringValue(request.DisplayLabel))
	if display == "" {
		display = identifier
	}
	if !validTargetInput(identifier, display, request.Password, stringValue(request.TotpSecret), stringValue(request.RecoverySecret), stringValue(request.PlatformSubjectId)) {
		h.rejectOwnerMutation(w, r, owner, "target_account.create", "invalid_request", 422, "invalid_target_account", "Invalid Target Account", "Target account fields are invalid")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())
	item, err := h.insertTargetAccountTx(r, tx, identifier, display, request.Password, stringValue(request.TotpSecret), stringValue(request.RecoverySecret), stringValue(request.PlatformSubjectId))
	if err == nil {
		_, err = audit.Write(r.Context(), tx, audit.Event{
			Type: audit.TargetAccountCreated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID,
			RetentionScopeID: item.Id.String(), EntityType: "target_account", EntityID: item.Id.String(),
			Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r),
			Details: audit.WorkspaceDetails{Result: "created"}, IdempotencyKey: item.Id.String() + ":created",
		})
	}
	if err != nil {
		h.targetConflict(w, r, owner, "target_account.create", err)
		return
	}
	if tx.Commit(r.Context()) != nil {
		h.targetFailure(w, r)
		return
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusCreated, item)
}

func validTargetInput(identifier, display, password, totp, recovery, subject string) bool {
	return validLength(identifier, 1, 254) && validLength(display, 1, 120) &&
		validLength(password, 1, 1024) && utf8.RuneCountInString(totp) <= 1024 &&
		utf8.RuneCountInString(recovery) <= 4096 && utf8.RuneCountInString(subject) <= 255
}

func (h *OwnerAuthHandler) insertTargetAccountTx(r *http.Request, tx pgx.Tx, identifier, display, password, totp, recovery, subject string) (ownerapi.TargetAccount, error) {
	normalized, keyVersion, fingerprint, err := identity.Fingerprint(h.keyRing, identity.TargetLogin, identifier)
	if err != nil {
		return ownerapi.TargetAccount{}, err
	}
	var id string
	err = tx.QueryRow(r.Context(), `INSERT INTO tsw_target_accounts (identifier,identifier_hmac,identifier_key_version,display_label) VALUES ($1,$2,$3,$4) RETURNING id`, normalized, fingerprint[:], keyVersion, display).Scan(&id)
	if err != nil {
		return ownerapi.TargetAccount{}, err
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO tsw_target_credentials (target_account_id,password_secret,totp_secret,recovery_secret,platform_subject_id) VALUES ($1,$2,NULLIF($3,'')::bytea,NULLIF($4,'')::bytea,NULLIF($5,''))`, id, []byte(password), []byte(totp), []byte(recovery), strings.TrimSpace(subject))
	if err != nil {
		return ownerapi.TargetAccount{}, err
	}
	return targetByIDTx(r, tx, id)
}

func targetByIDTx(r *http.Request, tx pgx.Tx, id string) (ownerapi.TargetAccount, error) {
	return scanTargetAccount(tx.QueryRow(r.Context(), `SELECT `+targetProjectionSQL+` FROM tsw_target_accounts target JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id WHERE target.id=$1`, id))
}

func (h *OwnerAuthHandler) targetByID(r *http.Request, id string) (ownerapi.TargetAccount, error) {
	return scanTargetAccount(h.pool.QueryRow(r.Context(), `SELECT `+targetProjectionSQL+` FROM tsw_target_accounts target JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id WHERE target.id=$1`, id))
}

func (h *OwnerAuthHandler) getTargetAccount(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	item, err := h.targetByID(r, r.PathValue("targetAccountId"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, r, 404, "target_not_found", "Not Found", "Target account was not found", 0)
		return
	}
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	detail := ownerapi.TargetAccountDetail{TargetAccount: item, WorkspacePlans: []ownerapi.TargetWorkspacePlan{}}
	rows, err := h.pool.Query(r.Context(), `SELECT workspace.id,workspace.display_name,batch.id,batch.sequence_no,batch.status,batch.planned_at
		FROM tsw_batch_targets selected JOIN tsw_batches batch ON batch.id=selected.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_workspaces workspace ON workspace.id=binding.workspace_id
		WHERE selected.target_account_id=$1 ORDER BY batch.planned_at DESC`, item.Id)
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var plan ownerapi.TargetWorkspacePlan
		if err := rows.Scan(&plan.WorkspaceId, &plan.WorkspaceName, &plan.BatchId, &plan.SequenceNo, &plan.BatchStatus, &plan.PlannedAt); err != nil {
			h.targetFailure(w, r)
			return
		}
		detail.WorkspacePlans = append(detail.WorkspacePlans, plan)
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusOK, detail)
}

func (h *OwnerAuthHandler) updateTargetAccount(w http.ResponseWriter, r *http.Request, params ownerapi.UpdateTargetAccountParams) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	version, ok := ifMatch(params.IfMatch)
	if !ok {
		h.rejectOwnerMutation(w, r, owner, "target_account.update", "invalid_request", http.StatusPreconditionRequired, "if_match_required", "Precondition Required", "If-Match is required")
		return
	}
	var request ownerapi.UpdateTargetAccountJSONRequestBody
	if !decodeJSON(w, r, &request) || !validLength(strings.TrimSpace(request.DisplayLabel), 1, 120) {
		h.rejectOwnerMutation(w, r, owner, "target_account.update", "invalid_request", 422, "invalid_target_account", "Invalid Target Account", "Target account fields are invalid")
		return
	}
	targetID := r.PathValue("targetAccountId")
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE tsw_target_accounts SET display_label=$3,status=$4,updated_at=now(),version=version+1 WHERE id=$1 AND version=$2`, targetID, version, strings.TrimSpace(request.DisplayLabel), request.Status)
	if err == nil && result.RowsAffected() != 1 {
		h.rejectOwnerMutation(w, r, owner, "target_account.update", "version_mismatch", 412, "version_mismatch", "Precondition Failed", "The target account changed")
		return
	}
	secretRotation := request.Password != nil || request.TotpSecret != nil || request.RecoverySecret != nil
	if (request.Password != nil && stringValue(request.Password) == "") ||
		(request.TotpSecret != nil && stringValue(request.TotpSecret) == "") ||
		(request.RecoverySecret != nil && stringValue(request.RecoverySecret) == "") {
		h.rejectOwnerMutation(w, r, owner, "target_account.update", "invalid_request", 422, "invalid_target_account", "Invalid Target Account", "Secret material cannot be empty")
		return
	}
	credentialChanged := secretRotation || request.PlatformSubjectId != nil
	if err == nil && credentialChanged {
		secretRevision := "secret_revision"
		if secretRotation {
			secretRevision = "secret_revision+1"
		}
		_, err = tx.Exec(r.Context(), `UPDATE tsw_target_credentials SET
			password_secret=CASE WHEN $2 <> '' THEN $2 ELSE password_secret END,
			totp_secret=CASE WHEN $3 <> '' THEN $3 ELSE totp_secret END,
			recovery_secret=CASE WHEN $4 <> '' THEN $4 ELSE recovery_secret END,
			platform_subject_id=CASE WHEN $5 <> '' THEN $5 ELSE platform_subject_id END,
			secret_revision=`+secretRevision+`,version=version+1 WHERE target_account_id=$1`, targetID,
			[]byte(stringValue(request.Password)), []byte(stringValue(request.TotpSecret)), []byte(stringValue(request.RecoverySecret)), strings.TrimSpace(stringValue(request.PlatformSubjectId)))
	}
	item, itemErr := targetByIDTx(r, tx, targetID)
	if err == nil {
		err = itemErr
	}
	if err == nil {
		event, outcome := audit.TargetAccountUpdated, "updated"
		if credentialChanged {
			event, outcome = audit.TargetCredentialsUpdated, "credentials_updated"
		}
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: event, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: targetID, EntityType: "target_account", EntityID: targetID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.WorkspaceDetails{Result: outcome}, IdempotencyKey: targetID + ":updated:" + strconv.FormatInt(item.Version, 10)})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		h.targetFailure(w, r)
		return
	}
	setETag(w, item.Version)
	writeJSON(w, http.StatusOK, item)
}

func (h *OwnerAuthHandler) previewTargetImport(w http.ResponseWriter, r *http.Request, save bool) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.TargetAccountImportRequest
	if !decodeJSON(w, r, &request) {
		h.rejectOwnerMutation(w, r, owner, "target_account.import", "invalid_request", 422, "invalid_import", "Invalid Import", "Import content is invalid")
		return
	}
	rows, err := targetdomain.ParseImport(request.Content)
	if err != nil {
		h.rejectOwnerMutation(w, r, owner, "target_account.import", "invalid_request", 422, "invalid_import", "Invalid Import", err.Error())
		return
	}
	for i := range rows {
		_, keyVersion, fingerprint, fingerprintErr := identity.Fingerprint(h.keyRing, identity.TargetLogin, rows[i].Identifier)
		if fingerprintErr != nil {
			h.targetFailure(w, r)
			return
		}
		err = h.pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tsw_target_accounts WHERE identifier_key_version=$1 AND identifier_hmac=$2)`, keyVersion, fingerprint[:]).Scan(&rows[i].Existing)
		if err != nil {
			h.targetFailure(w, r)
			return
		}
	}
	if !save {
		preview := ownerapi.TargetAccountImportPreview{Items: []ownerapi.TargetAccountImportRow{}, Total: len(rows)}
		for _, row := range rows {
			preview.Items = append(preview.Items, ownerapi.TargetAccountImportRow{Line: row.Line, Identifier: row.Identifier, DisplayLabel: row.DisplayLabel, HasPassword: row.Password != "", HasTotp: row.TOTPSecret != "", HasRecovery: row.RecoverySecret != "", Existing: row.Existing})
			if row.Existing {
				preview.ExistingCount++
			} else {
				preview.NewCount++
			}
		}
		writeJSON(w, http.StatusOK, preview)
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())
	result := ownerapi.TargetAccountImportResult{}
	for _, row := range rows {
		if row.Existing {
			_, keyVersion, fingerprint, fingerprintErr := identity.Fingerprint(h.keyRing, identity.TargetLogin, row.Identifier)
			if fingerprintErr != nil {
				h.targetFailure(w, r)
				return
			}
			var targetID string
			if err = tx.QueryRow(r.Context(), `SELECT id FROM tsw_target_accounts WHERE identifier_key_version=$1 AND identifier_hmac=$2 FOR UPDATE`, keyVersion, fingerprint[:]).Scan(&targetID); err != nil {
				h.targetConflict(w, r, owner, "target_account.import", err)
				return
			}
			_, err = tx.Exec(r.Context(), `UPDATE tsw_target_accounts SET display_label=$2,updated_at=now(),version=version+1 WHERE id=$1`, targetID, row.DisplayLabel)
			if err == nil {
				_, err = tx.Exec(r.Context(), `UPDATE tsw_target_credentials SET
					password_secret=$2,
					totp_secret=CASE WHEN octet_length($3::bytea) > 0 THEN $3::bytea ELSE totp_secret END,
					recovery_secret=CASE WHEN octet_length($4::bytea) > 0 THEN $4::bytea ELSE recovery_secret END,
					platform_subject_id=CASE WHEN $5 <> '' THEN $5 ELSE platform_subject_id END,
					secret_revision=CASE WHEN password_secret IS DISTINCT FROM $2 OR totp_secret IS DISTINCT FROM CASE WHEN octet_length($3::bytea) > 0 THEN $3::bytea ELSE totp_secret END OR recovery_secret IS DISTINCT FROM CASE WHEN octet_length($4::bytea) > 0 THEN $4::bytea ELSE recovery_secret END THEN secret_revision+1 ELSE secret_revision END,
					version=version+1 WHERE target_account_id=$1`, targetID, []byte(row.Password), []byte(row.TOTPSecret), []byte(row.RecoverySecret), row.PlatformSubjectID)
			}
			if err == nil {
				_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.TargetCredentialsUpdated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: targetID, EntityType: "target_account", EntityID: targetID, Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.WorkspaceDetails{Result: "credentials_updated"}, IdempotencyKey: targetImportAuditKey(targetID, correlation(r), row.Line)})
			}
			if err != nil {
				h.targetConflict(w, r, owner, "target_account.import", err)
				return
			}
			result.Existing++
			continue
		}
		item, insertErr := h.insertTargetAccountTx(r, tx, row.Identifier, row.DisplayLabel, row.Password, row.TOTPSecret, row.RecoverySecret, row.PlatformSubjectID)
		if insertErr != nil {
			h.targetConflict(w, r, owner, "target_account.import", insertErr)
			return
		}
		_, err = audit.Write(r.Context(), tx, audit.Event{Type: audit.TargetAccountCreated, Actor: audit.ActorOwner, OwnerID: owner.OwnerID, RetentionScopeID: item.Id.String(), EntityType: "target_account", EntityID: item.Id.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: correlation(r), Details: audit.WorkspaceDetails{Result: "created"}, IdempotencyKey: item.Id.String() + ":imported"})
		if err != nil {
			h.targetFailure(w, r)
			return
		}
		result.Created++
	}
	if tx.Commit(r.Context()) != nil {
		h.targetFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *OwnerAuthHandler) createTargetProbes(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.authenticated(w, r, true)
	if !ok {
		return
	}
	var request ownerapi.CreateTargetAccountProbesJSONRequestBody
	if !decodeJSON(w, r, &request) || !validLength(request.IdempotencyKey, 8, 128) || !validTargetProbeFilter(stringValueEnum(request.ProbeStatus)) {
		h.rejectOwnerMutation(w, r, owner, "target_probe.create", "invalid_request", 422, "invalid_target_probe", "Invalid Probe", "Probe scope is invalid")
		return
	}
	ids := make([]uuid.UUID, 0)
	if request.TargetAccountIds != nil {
		ids = append(ids, (*request.TargetAccountIds)...)
	}
	rows, err := h.pool.Query(r.Context(), `SELECT target.id FROM tsw_target_accounts target JOIN tsw_target_credentials credentials ON credentials.target_account_id=target.id
		WHERE (cardinality($1::uuid[])=0 OR target.id=ANY($1::uuid[])) AND ($2='' OR target.status=$2)
		AND ($3='' OR ($3='unprobed' AND credentials.latest_probe_status IS NULL) OR credentials.latest_probe_status=$3)
		AND ($4='' OR target.identifier ILIKE '%'||$4||'%' OR target.display_label ILIKE '%'||$4||'%') ORDER BY target.id LIMIT 10000`, ids, stringValueEnum(request.Status), stringValueEnum(request.ProbeStatus), strings.TrimSpace(stringValue(request.Search)))
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	defer rows.Close()
	response := ownerapi.TargetProbeBatch{Items: []ownerapi.TargetProbeStatus{}}
	for rows.Next() {
		var targetID string
		if rows.Scan(&targetID) != nil {
			h.targetFailure(w, r)
			return
		}
		item, _, err := h.workspaceTasks.CreateTargetProbe(r.Context(), targetID, targetProbeDedupeKey(request.IdempotencyKey, targetID), correlation(r))
		if err != nil {
			h.targetConflict(w, r, owner, "target_probe.create", err)
			return
		}
		status, err := targetProbeResponse(item)
		if err != nil {
			h.targetFailure(w, r)
			return
		}
		response.Items = append(response.Items, status)
	}
	response.Total = len(response.Items)
	writeJSON(w, http.StatusAccepted, response)
}

func (h *OwnerAuthHandler) getTargetProbe(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	item, err := h.workspaceTasks.Get(r.Context(), r.PathValue("probeId"))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && item.TaskType != "target_account_probe" {
		writeProblem(w, r, 404, "target_probe_not_found", "Not Found", "Probe status was not found", 0)
		return
	}
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	response, err := targetProbeResponse(item)
	if err != nil {
		h.targetFailure(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func targetProbeDedupeKey(idempotencyKey, targetID string) string {
	digest := sha256.Sum256([]byte(idempotencyKey + ":" + targetID))
	return "target-probe:" + hex.EncodeToString(digest[:])
}

func targetImportAuditKey(targetID, correlationID string, line int) string {
	digest := sha256.Sum256([]byte(targetID + ":" + correlationID + ":" + strconv.Itoa(line)))
	return "target-import:" + hex.EncodeToString(digest[:])
}

func targetProbeResponse(item task.Task) (ownerapi.TargetProbeStatus, error) {
	id, err := uuid.Parse(item.ID)
	if err != nil {
		return ownerapi.TargetProbeStatus{}, err
	}
	targetID, err := uuid.Parse(item.TargetAccountID)
	if err != nil {
		return ownerapi.TargetProbeStatus{}, err
	}
	result := ownerapi.TargetProbeStatus{Id: id, TargetAccountId: targetID, Status: ownerapi.TargetProbeStatusStatus(item.Status), CreatedAt: item.CreatedAt, FinishedAt: item.FinishedAt}
	if item.Status == "queued" || item.Status == "running" || item.Status == "retry_wait" {
		retry := 2
		result.RetryAfterSeconds = &retry
	}
	return result, nil
}

func stringValueEnum[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func (h *OwnerAuthHandler) targetConflict(w http.ResponseWriter, r *http.Request, owner ownerContext, operation string, err error) {
	if errors.Is(err, task.ErrIdempotencyConflict) {
		h.rejectOwnerMutation(w, r, owner, operation, "idempotency_conflict", 409, "idempotency_conflict", "Conflict", "The key belongs to a different target")
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			h.rejectOwnerMutation(w, r, owner, operation, "conflict", 409, "target_conflict", "Conflict", "The target account already exists")
			return
		case "23503", "23514":
			h.rejectOwnerMutation(w, r, owner, operation, "invalid_request", 422, "invalid_target_account", "Invalid Target Account", "Target account fields are invalid")
			return
		}
	}
	h.targetFailure(w, r)
}

func (h *OwnerAuthHandler) targetFailure(w http.ResponseWriter, r *http.Request) {
	writeProblem(w, r, 500, "target_accounts_unavailable", "Internal Server Error", "Target account data is temporarily unavailable", 0)
}
