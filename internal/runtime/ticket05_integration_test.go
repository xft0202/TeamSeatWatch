package runtime

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
)

func TestTicket05ReadBoundariesWithPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("TSW_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}

	token, tokenHash, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	var ownerID string
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_owners (username,password_hash,totp_ciphertext,totp_nonce,totp_key_version)
		VALUES ('owner','x',decode(repeat('01',16),'hex'),decode(repeat('02',12),'hex'),1) RETURNING id`).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_owner_sessions (owner_id,token_hash,auth_version,idle_expires_at,absolute_expires_at)
		VALUES ($1,$2,1,now()+interval '1 hour',now()+interval '2 hours')`, ownerID, tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	var workspaceID, bindingID, targetID, batchID string
	if err := db.QueryRowContext(ctx, `WITH account AS (
		INSERT INTO tsw_mother_accounts (display_name) VALUES ('Mother') RETURNING id
	), workspace AS (
		INSERT INTO tsw_workspaces (platform_workspace_id,display_name) VALUES ('workspace-1','Workspace') RETURNING id
	), binding AS (
		INSERT INTO tsw_mother_workspace_bindings (mother_account_id,workspace_id)
		SELECT account.id,workspace.id FROM account,workspace RETURNING id,workspace_id
	)
	SELECT workspace_id,id FROM binding`).Scan(&workspaceID, &bindingID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_target_accounts (identifier,identifier_hmac,identifier_key_version,display_label)
		VALUES ('target@example.com',decode(repeat('03',32),'hex'),1,'Target') RETURNING id`).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_target_credentials (
		target_account_id,password_secret,latest_probe_status,latest_probe_http_status,
		latest_probe_endpoint_key,latest_probe_origin,latest_probed_at,last_verified_at)
		VALUES ($1,decode(repeat('aa',8),'hex'),'available',200,'account_usage','worker',now(),now())`, targetID); err != nil {
		t.Fatal(err)
	}
	var conclusionID, capacityID, snapshotID string
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_workspace_observations (
		workspace_id,observation_type,source_kind,source_endpoint,observed_at,expires_at,outcome_code,active_until)
		VALUES ($1,'subscription','platform','workspace_subscription',now(),now()+interval '1 day','operational',now()+interval '30 days') RETURNING id`, workspaceID).Scan(&conclusionID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_workspace_observations (
		workspace_id,observation_type,source_kind,source_endpoint,observed_at,expires_at,outcome_code,seat_limit,member_count)
		VALUES ($1,'capacity','platform','seat_counter',now(),now()+interval '1 day','operational',10,2) RETURNING id`, workspaceID).Scan(&capacityID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_workspace_member_snapshots (
		workspace_id,source_endpoint,observed_at,completeness,declared_member_count,pending_invite_count,payload_hash,expires_at)
		VALUES ($1,'workspace_members',now(),'complete',2,1,decode(repeat('04',32),'hex'),now()+interval '1 day') RETURNING id`, workspaceID).Scan(&snapshotID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_workspace_projections (
		workspace_id,operational_state,conclusion_observation_id,capacity_observation_id,latest_snapshot_id,
		active_until,seat_limit,member_count,pending_invite_count,evidence_expires_at)
		VALUES ($1,'operational',$2,$3,$4,now()+interval '30 days',10,2,1,now()+interval '1 day')`, workspaceID, conclusionID, capacityID, snapshotID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_batches (binding_id,sequence_no,planned_at) VALUES ($1,1,now()+interval '1 day') RETURNING id`, bindingID).Scan(&batchID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_batch_targets (batch_id,target_account_id,ordinal) VALUES ($1,$2,1)`, batchID, targetID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	origins, err := auth.ParseOriginPolicy("https://owner.example")
	if err != nil {
		t.Fatal(err)
	}
	handler := &OwnerAuthHandler{pool: pool, origins: origins}
	before := taskCount(t, ctx, pool)

	previewRequest := authenticatedRequest(http.MethodGet, "/api/owner/v1/batches/"+batchID+"/preview", token)
	previewRequest.SetPathValue("batchId", batchID)
	previewRecorder := httptest.NewRecorder()
	handler.getBatchPreview(previewRecorder, previewRequest, ownerapi.GetBatchPreviewParams{})
	if previewRecorder.Code != http.StatusOK {
		t.Fatalf("preview status %d: %s", previewRecorder.Code, previewRecorder.Body.String())
	}
	var preview ownerapi.BatchPreview
	if err := json.Unmarshal(previewRecorder.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if !preview.CanProceed || len(preview.Blockers) != 0 || preview.AvailableSeats == nil || *preview.AvailableSeats != 7 {
		t.Fatalf("unexpected ready preview: %#v", preview)
	}

	if _, err := pool.Exec(ctx, `UPDATE tsw_workspace_projections SET operational_state='unknown',conclusion_observation_id=NULL,evidence_expires_at=NULL,version=version+1 WHERE workspace_id=$1`, workspaceID); err != nil {
		t.Fatal(err)
	}
	blockedRequest := authenticatedRequest(http.MethodGet, "/api/owner/v1/batches/"+batchID+"/preview", token)
	blockedRequest.SetPathValue("batchId", batchID)
	blockedRecorder := httptest.NewRecorder()
	handler.getBatchPreview(blockedRecorder, blockedRequest, ownerapi.GetBatchPreviewParams{})
	var blocked ownerapi.BatchPreview
	if blockedRecorder.Code != http.StatusOK || json.Unmarshal(blockedRecorder.Body.Bytes(), &blocked) != nil || blocked.CanProceed || len(blocked.Blockers) == 0 {
		t.Fatalf("preview did not block unknown evidence: %d %s", blockedRecorder.Code, blockedRecorder.Body.String())
	}

	targetRequest := authenticatedRequest(http.MethodGet, "/api/owner/v1/target-accounts/"+targetID, token)
	targetRequest.SetPathValue("targetAccountId", targetID)
	targetRecorder := httptest.NewRecorder()
	handler.getTargetAccount(targetRecorder, targetRequest)
	if targetRecorder.Code != http.StatusOK || containsSecretField(targetRecorder.Body.String()) {
		t.Fatalf("target response leaked secret fields or failed: %d %s", targetRecorder.Code, targetRecorder.Body.String())
	}
	wrongVersion := authenticatedMutationRequest(http.MethodPatch, "/api/owner/v1/target-accounts/"+targetID, token, `{"displayLabel":"Changed","status":"active"}`)
	wrongVersion.SetPathValue("targetAccountId", targetID)
	wrongRecorder := httptest.NewRecorder()
	handler.updateTargetAccount(wrongRecorder, wrongVersion, ownerapi.UpdateTargetAccountParams{IfMatch: `"999"`})
	if wrongRecorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale target update was accepted: %d %s", wrongRecorder.Code, wrongRecorder.Body.String())
	}
	matchingVersion := authenticatedMutationRequest(http.MethodPatch, "/api/owner/v1/target-accounts/"+targetID, token, `{"displayLabel":"Changed","status":"active"}`)
	matchingVersion.SetPathValue("targetAccountId", targetID)
	matchingRecorder := httptest.NewRecorder()
	handler.updateTargetAccount(matchingRecorder, matchingVersion, ownerapi.UpdateTargetAccountParams{IfMatch: `"1"`})
	if matchingRecorder.Code != http.StatusOK || containsSecretField(matchingRecorder.Body.String()) {
		t.Fatalf("matching target update failed or leaked secret fields: %d %s", matchingRecorder.Code, matchingRecorder.Body.String())
	}
	if after := taskCount(t, ctx, pool); after != before {
		t.Fatalf("read-only handlers created tasks: before=%d after=%d", before, after)
	}
}

func authenticatedRequest(method, target, token string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	return request
}

func containsSecretField(body string) bool {
	return strings.Contains(body, "password_secret") || strings.Contains(body, "totp_secret") || strings.Contains(body, "recovery_secret")
}

func authenticatedMutationRequest(method, target, token, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	csrf := make([]byte, 32)
	_, _ = rand.Read(csrf)
	csrfToken := base64.RawURLEncoding.EncodeToString(csrf)
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfToken})
	request.Header.Set(auth.CSRFHeaderName, csrfToken)
	request.Header.Set("Origin", "https://owner.example")
	request.Header.Set("Content-Type", "application/json")
	return request
}

func taskCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_tasks`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
