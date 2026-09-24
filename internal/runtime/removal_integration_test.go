//go:build integration

package runtime

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
)

func TestOwnerRemovalAuthorizationFreezesOnlyCurrentBatchMemberships(t *testing.T) {
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ids, sessionToken, csrfToken := seedCardActivationGraph(t, ctx, pool)
	var batchID, motherID, targetID string
	if err := pool.QueryRow(ctx, `SELECT batch.id::text,binding.mother_account_id::text,membership.target_account_id::text
		FROM tsw_batch_memberships membership JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id WHERE membership.id=$1`, ids.membership).Scan(&batchID, &motherID, &targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_mother_account_credentials(mother_account_id,login_identifier,identifier_hmac,identifier_key_version,password_secret) VALUES ($1,'owner@example.com',decode(repeat('81',32),'hex'),1,'password')`, motherID); err != nil {
		t.Fatal(err)
	}
	var observationID, snapshotID string
	if err := pool.QueryRow(ctx, `INSERT INTO tsw_workspace_observations(workspace_id,observation_type,source_kind,source_endpoint,observed_at,expires_at,outcome_code,payload_hash) VALUES ($1,'members','platform','workspace_members',now(),now()+interval '7 days','operational',decode(repeat('82',32),'hex')) RETURNING id`, ids.workspace).Scan(&observationID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO tsw_workspace_member_snapshots(workspace_id,source_endpoint,observed_at,completeness,declared_member_count,payload_hash,expires_at) VALUES ($1,'workspace_members',now(),'complete',3,decode(repeat('83',32),'hex'),now()+interval '7 days') RETURNING id`, ids.workspace).Scan(&snapshotID); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ identifier, role, hash string }{
		{"owner@example.com", "owner", "84"},
		{"target@example.com", "member", "85"},
		{"unknown@example.com", "member", "86"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO tsw_workspace_member_snapshot_entries(snapshot_id,entry_kind,platform_member_id,member_identifier,identifier_hmac,identifier_key_version,platform_status,platform_role) VALUES ($1,'member',$2,$3,decode(repeat($4,32),'hex'),1,'active',$5)`, snapshotID, "live-"+entry.hash, entry.identifier, entry.hash, entry.role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_workspace_projections(workspace_id,operational_state,conclusion_observation_id,latest_snapshot_id,evidence_expires_at) VALUES ($1,'operational',$2,$3,now()+interval '7 days')`, ids.workspace, observationID, snapshotID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_batches SET planned_at=now()-interval '1 hour',service_started_at=now() WHERE id=$1`, batchID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_operations SET status='succeeded',completed_at=now() WHERE batch_id=$1 AND operation_type='join'`, batchID); err != nil {
		t.Fatal(err)
	}
	origins, err := auth.ParseOriginPolicy("https://owner.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := &OwnerAuthHandler{pool: pool, keyRing: cardIntegrationKeyRing{}, origins: origins}
	previewRequest := httptest.NewRequest(http.MethodGet, "/api/owner/v1/batches/"+batchID+"/remove-preview", nil)
	batch, err := handler.batchByID(previewRequest, batchID)
	if err != nil {
		t.Fatalf("load removal batch: %v", err)
	}
	preview, err := removalPreview(ctx, pool, batch)
	if err != nil {
		t.Fatalf("load removal preview: %v", err)
	}
	if !preview.CanProceed {
		t.Fatalf("removal preview blocked: %+v", preview.Blockers)
	}
	differenceReasons := map[string]bool{}
	for _, difference := range preview.Differences {
		differenceReasons[string(difference.Reason)] = true
	}
	if !differenceReasons["workspace_owner"] || !differenceReasons["unknown_member"] {
		t.Fatalf("removal preview differences=%+v", preview.Differences)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_workspace_projections SET evidence_expires_at=now()-interval '1 second' WHERE workspace_id=$1`, ids.workspace); err != nil {
		t.Fatal(err)
	}
	expiredPreview, err := removalPreview(ctx, pool, batch)
	if err != nil {
		t.Fatalf("load expired removal preview: %v", err)
	}
	expiredBlocked := false
	for _, blocker := range expiredPreview.Blockers {
		if blocker.Code == "member_snapshot_incomplete" {
			expiredBlocked = true
		}
	}
	if expiredPreview.CanProceed || !expiredBlocked {
		t.Fatalf("expired removal preview canProceed=%v blockers=%+v", expiredPreview.CanProceed, expiredPreview.Blockers)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_workspace_projections SET evidence_expires_at=now()+interval '7 days' WHERE workspace_id=$1`, ids.workspace); err != nil {
		t.Fatal(err)
	}
	requestRemoval := func(idempotencyKey string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"idempotencyKey": idempotencyKey, "confirm": true})
		request := httptest.NewRequest(http.MethodPost, "/api/owner/v1/batches/"+batchID+"/remove", bytes.NewReader(body))
		request.SetPathValue("batchId", batchID)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://owner.test")
		request.Header.Set(auth.CSRFHeaderName, csrfToken)
		request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
		request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfToken})
		response := httptest.NewRecorder()
		handler.createRemovalOperation(response, request)
		return response
	}
	first := requestRemoval("precise-remove-1")
	if first.Code != http.StatusAccepted {
		t.Fatalf("first authorization status=%d body=%s", first.Code, first.Body.String())
	}
	second := requestRemoval("precise-remove-1")
	if second.Code != http.StatusAccepted {
		t.Fatalf("idempotent authorization status=%d body=%s", second.Code, second.Body.String())
	}
	conflict := requestRemoval("precise-remove-2")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("same-Workspace second operation status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	var operationCount, targetCount, taskCount int
	var batchStatus string
	var frozenMembershipIDs []string
	if err := pool.QueryRow(ctx, `SELECT count(*),
		COALESCE(sum((SELECT count(*) FROM tsw_operation_targets target_result WHERE target_result.operation_id=operation.id)),0),
		COALESCE(sum((SELECT count(*) FROM tsw_tasks task JOIN tsw_operation_targets target_result ON target_result.id=task.operation_target_id WHERE target_result.operation_id=operation.id AND task.task_type='remove')),0)
		FROM tsw_operations operation WHERE operation.batch_id=$1 AND operation.operation_type='remove'`, batchID).Scan(&operationCount, &targetCount, &taskCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM tsw_batches WHERE id=$1`, batchID).Scan(&batchStatus); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `SELECT target_result.membership_id::text FROM tsw_operation_targets target_result JOIN tsw_operations operation ON operation.id=target_result.operation_id WHERE operation.batch_id=$1 AND operation.operation_type='remove' ORDER BY target_result.ordinal`, batchID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var membershipID string
		if err := rows.Scan(&membershipID); err != nil {
			t.Fatal(err)
		}
		frozenMembershipIDs = append(frozenMembershipIDs, membershipID)
	}
	rows.Close()
	if operationCount != 1 || targetCount != 1 || taskCount != 1 || batchStatus != "removing" || len(frozenMembershipIDs) != 1 || frozenMembershipIDs[0] != ids.membership {
		t.Fatalf("operations=%d targets=%d tasks=%d batch=%s manifest=%v target=%s", operationCount, targetCount, taskCount, batchStatus, frozenMembershipIDs, targetID)
	}
	var unknownTargeted bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tsw_operation_targets target_result JOIN tsw_operations operation ON operation.id=target_result.operation_id JOIN tsw_batch_memberships membership ON membership.id=target_result.membership_id JOIN tsw_target_accounts target ON target.id=membership.target_account_id WHERE operation.batch_id=$1 AND operation.operation_type='remove' AND lower(target.identifier)='unknown@example.com')`, batchID).Scan(&unknownTargeted); err != nil {
		t.Fatal(err)
	}
	if unknownTargeted {
		t.Fatal("unknown Workspace member entered the frozen removal manifest")
	}
}
