package migrations

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestTicket05PostgreSQLConstraints(t *testing.T) {
	databaseURL := os.Getenv("TSW_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, db); err != nil {
		t.Fatal(err)
	}

	var bindingID, targetID, secondTargetID, firstBatchID, secondBatchID string
	if err := db.QueryRowContext(ctx, `WITH account AS (
		INSERT INTO tsw_mother_accounts (display_name) VALUES ('Mother') RETURNING id
	), workspace AS (
		INSERT INTO tsw_workspaces (platform_workspace_id,display_name) VALUES ('workspace-1','Workspace') RETURNING id
	)
	INSERT INTO tsw_mother_workspace_bindings (mother_account_id,workspace_id)
	SELECT account.id,workspace.id FROM account,workspace RETURNING id`).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_target_accounts (identifier,identifier_hmac,identifier_key_version,display_label)
		VALUES ('first@example.com',decode(repeat('01',32),'hex'),1,'First') RETURNING id`).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_target_accounts (identifier,identifier_hmac,identifier_key_version,display_label)
		VALUES ('second@example.com',decode(repeat('02',32),'hex'),1,'Second') RETURNING id`).Scan(&secondTargetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_target_credentials (target_account_id,password_secret) VALUES ($1,$2)`, targetID, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_target_credentials (target_account_id,password_secret) VALUES ($1,$2)`, secondTargetID, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE tsw_target_credentials SET latest_probe_status='unknown',latest_probe_error_code='proxy_capacity_exhausted',latest_probe_endpoint_key='account_usage',latest_probe_origin='worker',latest_probed_at=now(),version=version+1 WHERE target_account_id=$1`, targetID); err != nil {
		t.Fatalf("probe-only version step failed: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tsw_target_credentials SET password_secret=$2,secret_revision=secret_revision+1,version=version+1 WHERE target_account_id=$1`, targetID, []byte{4, 5, 6}); err != nil {
		t.Fatalf("secret rotation failed: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tsw_target_credentials SET latest_probe_status='available',latest_probe_endpoint_key='account_usage',latest_probe_origin='worker',latest_probed_at=now(),last_verified_at=now(),secret_revision=secret_revision+1,version=version+1 WHERE target_account_id=$1`, targetID); postgresCode(err) != "P0001" {
		t.Fatalf("probe changed secret revision: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tsw_target_credentials SET latest_probe_status='transient_failure',latest_probe_error_code='transport_failure',latest_probe_endpoint_key='account_usage',latest_probe_origin='worker',latest_probed_at=now(),version=version+1 WHERE target_account_id=$1`, targetID); err != nil {
		t.Fatalf("transient probe discarded last verified evidence: %v", err)
	}

	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_batches (binding_id,sequence_no,planned_at) VALUES ($1,1,now()) RETURNING id`, bindingID).Scan(&firstBatchID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO tsw_batches (binding_id,sequence_no,planned_at) VALUES ($1,2,now()) RETURNING id`, bindingID).Scan(&secondBatchID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_batch_targets (batch_id,target_account_id,ordinal) VALUES ($1,$2,1)`, firstBatchID, targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_batch_targets (batch_id,target_account_id,ordinal) VALUES ($1,$2,2)`, firstBatchID, targetID); postgresCode(err) != "23505" {
		t.Fatalf("duplicate target was accepted: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_batch_targets (batch_id,target_account_id,ordinal) VALUES ($1,$2,1)`, secondBatchID, targetID); err != nil {
		t.Fatalf("same target in another batch was rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tsw_batches SET status='serving' WHERE id=$1`, firstBatchID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tsw_batches SET status='joining' WHERE id=$1`, secondBatchID); postgresCode(err) != "23505" {
		t.Fatalf("overlapping active batch was accepted: %v", err)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_tasks (target_account_id,task_type,dedupe_key,input_snapshot,correlation_id) VALUES ($1,'target_account_probe','probe-1','{}','correlation')`, targetID); err != nil {
		t.Fatalf("target probe subject was rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tsw_tasks (task_type,dedupe_key,input_snapshot,correlation_id) VALUES ('target_account_probe','probe-invalid','{}','correlation')`); postgresCode(err) != "23514" {
		t.Fatalf("subjectless target probe was accepted: %v", err)
	}
}

func postgresCode(err error) string {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		return postgresError.Code
	}
	return ""
}
