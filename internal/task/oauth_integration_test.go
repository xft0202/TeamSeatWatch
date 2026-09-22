//go:build integration

package task

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

func TestOAuthStoreFenceIntegration(t *testing.T) {
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
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
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

	ids := seedOAuthFenceGraph(t, ctx, pool)
	store := NewStore(pool)
	oldLease := uuid.New()
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET lease_token=$2 WHERE id=$1`, ids.oldTask, oldLease); err != nil {
		t.Fatal(err)
	}
	oldTask := Task{ID: ids.oldTask, TaskType: "oauth_generate", WorkspaceID: ids.workspace, MembershipID: ids.membership, OAuthAssetID: ids.asset, LeaseToken: oldLease, AttemptNo: 1, CorrelationID: "integration-fence"}
	oldAttempt, err := store.BeginDeliveryAttempt(ctx, oldTask)
	if err != nil {
		t.Fatal(err)
	}
	if oldAttempt.Generation != 1 {
		t.Fatalf("old generation=%d want 1", oldAttempt.Generation)
	}

	if _, err := pool.Exec(ctx, `UPDATE tsw_oauth_attempts SET state='superseded',outcome_code='test_superseded',finished_at=now() WHERE id=$1`, oldAttempt.ID); err != nil {
		t.Fatal(err)
	}
	newAttemptID := uuid.New().String()
	newTaskID := uuid.New().String()
	newLease := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,lease_owner,lease_token,lease_expires_at,attempt_count,max_attempts)
		VALUES ($1,$2,$3,$4,'oauth_generate',$5,'{}',$6,'running','integration',$7,now()+interval '10 minutes',1,3)`, newTaskID, ids.membership, ids.asset, ids.workspace, "integration-new-task", "integration-new", newLease); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_oauth_attempts(id,oauth_asset_id,task_id,generation,attempt_no,attempt_kind,state)
		VALUES ($1,$2,$3,2,1,'generate','running')`, newAttemptID, ids.asset, newTaskID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_oauth_assets SET current_generation=2,current_attempt_id=$2,status='generating' WHERE id=$1`, ids.asset, newAttemptID); err != nil {
		t.Fatal(err)
	}

	err = store.FinishDeliveryAttempt(ctx, oldTask, oldAttempt, DeliveryTarget{PlatformWorkspace: "workspace-platform"}, platform.DeliveryCredentialSet{
		RefreshToken: "refresh", AccessToken: "access", IDToken: "id", PlatformSubjectID: "subject", WorkspaceID: "workspace-platform",
	}, platform.DeliveryLiveness{Status: "ok", HTTPStatus: 200, WorkspaceID: "workspace-platform", PlatformSubjectID: "subject", ObservedAt: time.Now().UTC()})
	if !errors.Is(err, ErrDeliveryAttemptSuperseded) {
		t.Fatalf("stale attempt err=%v want ErrDeliveryAttemptSuperseded", err)
	}
	var currentAttempt string
	var currentGeneration int64
	if err := pool.QueryRow(ctx, `SELECT current_attempt_id::text,current_generation FROM tsw_oauth_assets WHERE id=$1`, ids.asset).Scan(&currentAttempt, &currentGeneration); err != nil {
		t.Fatal(err)
	}
	if currentAttempt != newAttemptID || currentGeneration != 2 {
		t.Fatalf("asset fence changed: attempt=%s generation=%d", currentAttempt, currentGeneration)
	}

	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, ids.oldTask); err != nil {
		t.Fatal(err)
	}
	err = store.FinishDeliveryAttempt(ctx, oldTask, oldAttempt, DeliveryTarget{}, platform.DeliveryCredentialSet{}, platform.DeliveryLiveness{})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired task lease err=%v want ErrLeaseLost", err)
	}

	versionID := uuid.New().String()
	payload := []byte(`{"access_token":"a"}`)
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_delivery_versions(id,oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id)
		VALUES ($1,$2,3,$3,decode(repeat('00',32),'hex'),'subject',$4)`, versionID, ids.asset, payload, ids.workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_delivery_versions SET payload='{}' WHERE id=$1`, versionID); err == nil {
		t.Fatal("immutable delivery version accepted an update")
	}
}

func TestClaimDeliveryPreservesOAuthTaskTypeAndLease(t *testing.T) {
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
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
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
	ids := seedOAuthFenceGraph(t, ctx, pool)
	queuedTaskID := uuid.New().String()
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,attempt_count,max_attempts)
		VALUES ($1,$2,$3,$4,'oauth_generate','integration-claim-delivery','{}','integration-claim','queued',0,3)`, queuedTaskID, ids.membership, ids.asset, ids.workspace); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	claimed, err := store.ClaimDelivery(ctx, "integration-worker", time.Minute, "oauth_generate", AttemptRoute{Mode: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != queuedTaskID || claimed.TaskType != "oauth_generate" || claimed.OAuthAssetID != ids.asset || claimed.LeaseToken == uuid.Nil || claimed.Status != "running" {
		t.Fatalf("claimed task=%+v", claimed)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, queuedTaskID); err != nil {
		t.Fatal(err)
	}
	takeover, err := store.ClaimDelivery(ctx, "integration-takeover", time.Minute, "oauth_generate", AttemptRoute{Mode: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	if takeover.ID != queuedTaskID || takeover.TaskType != "oauth_generate" || takeover.OAuthAssetID != ids.asset || takeover.AttemptNo != 2 || takeover.LeaseToken == uuid.Nil || takeover.LeaseToken == claimed.LeaseToken {
		t.Fatalf("takeover task=%+v previousLease=%s", takeover, claimed.LeaseToken)
	}
}
func TestOAuthCrashBeforePublishLeavesNoDeliveryVersion(t *testing.T) {
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
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
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
	ids := seedOAuthFenceGraph(t, ctx, pool)
	leaseToken := uuid.New()
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET lease_token=$2 WHERE id=$1`, ids.oldTask, leaseToken); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	item := Task{ID: ids.oldTask, TaskType: "oauth_generate", WorkspaceID: ids.workspace, MembershipID: ids.membership, OAuthAssetID: ids.asset, LeaseToken: leaseToken, AttemptNo: 1, CorrelationID: "integration-crash-before-publish"}
	attempt, err := store.BeginDeliveryAttempt(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	var status string
	var generation int64
	var versionCount int
	if err := pool.QueryRow(ctx, `SELECT status,current_generation FROM tsw_oauth_assets WHERE id=$1`, ids.asset).Scan(&status, &generation); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_delivery_versions WHERE oauth_asset_id=$1`, ids.asset).Scan(&versionCount); err != nil {
		t.Fatal(err)
	}
	if attempt.Generation != 1 || status != "generating" || generation != 1 || versionCount != 0 {
		t.Fatalf("crash-before-publish state attempt=%+v status=%s generation=%d versions=%d", attempt, status, generation, versionCount)
	}
}

func TestOAuthPublishRetryAfterCommitIsFenced(t *testing.T) {
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
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
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
	ids := seedOAuthFenceGraph(t, ctx, pool)
	leaseToken := uuid.New()
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET lease_token=$2 WHERE id=$1`, ids.oldTask, leaseToken); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	item := Task{ID: ids.oldTask, TaskType: "oauth_generate", WorkspaceID: ids.workspace, MembershipID: ids.membership, OAuthAssetID: ids.asset, LeaseToken: leaseToken, AttemptNo: 1, CorrelationID: "integration-publish-retry"}
	attempt, err := store.BeginDeliveryAttempt(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	target := DeliveryTarget{WorkspaceID: ids.workspace, PlatformWorkspace: "workspace-platform"}
	generated := platform.DeliveryCredentialSet{RefreshToken: "refresh", AccessToken: "access", IDToken: "id", PlatformSubjectID: "subject", WorkspaceID: "workspace-platform"}
	probe := platform.DeliveryLiveness{Status: "ok", HTTPStatus: 200, PlatformSubjectID: "subject", WorkspaceID: "workspace-platform", ObservedAt: time.Now().UTC()}
	if err := store.FinishDeliveryAttempt(ctx, item, attempt, target, generated, probe); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishDeliveryAttempt(ctx, item, attempt, target, generated, probe); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("retry after committed publish err=%v want ErrLeaseLost", err)
	}
	var versions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_delivery_versions WHERE oauth_asset_id=$1`, ids.asset).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 1 {
		t.Fatalf("delivery version count=%d want 1", versions)
	}
}

type fenceGraphIDs struct {
	owner, mother, workspace, binding, batch, target, operation, operationTarget, membership, asset, oldTask string
}

func seedOAuthFenceGraph(t *testing.T, ctx context.Context, pool *pgxpool.Pool) fenceGraphIDs {
	t.Helper()
	id := func() string { return uuid.New().String() }
	ids := fenceGraphIDs{owner: id(), mother: id(), workspace: id(), binding: id(), batch: id(), target: id(), operation: id(), operationTarget: id(), membership: id(), asset: id(), oldTask: id()}
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_owners(id,username,password_hash,totp_ciphertext,totp_nonce,totp_key_version) VALUES ($1,'integration','hash',decode(repeat('11',16),'hex'),decode(repeat('22',12),'hex'),1)`, []any{ids.owner}},
		{`INSERT INTO tsw_mother_accounts(id,display_name) VALUES ($1,'integration mother')`, []any{ids.mother}},
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES ($1,'workspace-platform','integration workspace')`, []any{ids.workspace}},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id) VALUES ($1,$2,$3)`, []any{ids.binding, ids.mother, ids.workspace}},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,planned_at) VALUES ($1,$2,1,now()+interval '1 day')`, []any{ids.batch, ids.binding}},
		{`INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES ($1,'target@example.com',decode(repeat('33',32),'hex'),1,'target')`, []any{ids.target}},
		{`INSERT INTO tsw_target_credentials(target_account_id,password_secret) VALUES ($1,'password')`, []any{ids.target}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id) VALUES ($1,$2,$3,$4,'join','integration-op',decode(repeat('44',32),'hex'),'{}','integration')`, []any{ids.operation, ids.owner, ids.workspace, ids.batch}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal) VALUES ($1,$2,$3,1)`, []any{ids.operationTarget, ids.operation, ids.target}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at) VALUES ($1,$2,$3,$4,now())`, []any{ids.membership, ids.batch, ids.target, ids.operationTarget}},
		{`UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2,status='succeeded',completed_at=now() WHERE id=$1`, []any{ids.operationTarget, ids.membership}},
		{`INSERT INTO tsw_oauth_assets(id,membership_id) VALUES ($1,$2)`, []any{ids.asset, ids.membership}},
		{`INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,lease_owner,lease_token,lease_expires_at,attempt_count,max_attempts)
			VALUES ($1,$2,$3,$4,'oauth_generate','integration-old-task','{}','integration-old','running','integration',$5,now()+interval '10 minutes',1,3)`, []any{ids.oldTask, ids.membership, ids.asset, ids.workspace, uuid.New()}},
	}
	for _, item := range queries {
		if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatalf("seed failed: %v", err)
		}
	}
	return ids
}
