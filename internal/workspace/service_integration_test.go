//go:build integration

package workspace

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
)

func TestRetentionCycleDeletesOnlyExpiredRelationship(t *testing.T) {
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
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
	defer pool.Close()

	owner, mother, workspaceID, binding, batch, target, operation, operationTarget, membership := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	queries := []struct {
		query string
		args  []any
		dest  *string
	}{
		{`INSERT INTO tsw_owners(id,username,password_hash,totp_ciphertext,totp_nonce,totp_key_version) VALUES ($1,'retention-owner','hash',decode(repeat('11',16),'hex'),decode(repeat('22',12),'hex'),1) RETURNING id::text`, []any{owner}, &owner},
		{`INSERT INTO tsw_mother_accounts(id,display_name) VALUES ($1,'retention-mother') RETURNING id::text`, []any{mother}, &mother},
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES ($1,'retention-workspace','Retention Workspace') RETURNING id::text`, []any{workspaceID}, &workspaceID},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id) VALUES ($1,$2,$3) RETURNING id::text`, []any{binding, mother, workspaceID}, &binding},
		{`INSERT INTO tsw_workspace_projections(workspace_id,operational_state) VALUES ($1,'unknown')`, []any{workspaceID}, nil},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,status,planned_at,service_started_at,service_ended_at,created_at,updated_at) VALUES ($1,$2,1,'ended',now()-interval '9 days',now()-interval '9 days',now()-interval '8 days',now()-interval '9 days',now()-interval '8 days') RETURNING id::text`, []any{batch, binding}, &batch},
		{`INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES ($1,'expired@example.com',decode(repeat('33',32),'hex'),1,'expired') RETURNING id::text`, []any{target}, &target},
		{`INSERT INTO tsw_target_credentials(target_account_id,password_secret) VALUES ($1,'secret')`, []any{target}, nil},
		{`INSERT INTO tsw_batch_targets(batch_id,target_account_id,ordinal) VALUES ($1,$2,1)`, []any{batch, target}, nil},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,status,completed_at,correlation_id) VALUES ($1,$2,$3,$4,'join','retention-op',decode(repeat('44',32),'hex'),'{}','succeeded',now()-interval '8 days','retention') RETURNING id::text`, []any{operation, owner, workspaceID, batch}, &operation},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal,status,completed_at) VALUES ($1,$2,$3,1,'succeeded',now()-interval '8 days') RETURNING id::text`, []any{operationTarget, operation, target}, &operationTarget},
		{`INSERT INTO tsw_batch_memberships(batch_id,target_account_id,join_operation_target_id,state,joined_at,removed_at,service_ended_at,retention_due_at) VALUES ($1,$2,$3,'removed',now()-interval '9 days',now()-interval '8 days',now()-interval '8 days',now()-interval '1 hour') RETURNING id::text`, []any{batch, target, operationTarget}, &membership},
	}
	for _, item := range queries {
		if item.dest != nil {
			if err := pool.QueryRow(ctx, item.query, item.args...).Scan(item.dest); err != nil {
				t.Fatalf("seed query %s: %v", item.query, err)
			}
		} else if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	service := NewService(pool, nil)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RunRetentionTx(ctx, tx, "retention-test-cycle", 100); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_batch_memberships WHERE id=$1`, membership).Scan(&count); err != nil || count != 0 {
		t.Fatalf("membership count=%d err=%v", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_target_accounts WHERE id=$1`, target).Scan(&count); err != nil || count != 0 {
		t.Fatalf("target count=%d err=%v", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_retention_runs WHERE cycle_key='retention-test-cycle' AND status='succeeded'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retention run count=%d err=%v", count, err)
	}
}
