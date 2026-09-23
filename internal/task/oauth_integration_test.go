//go:build integration

package task

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
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

type reclaimScenarioAdapter struct {
	probes      []platform.DeliveryLiveness
	probeCalls  int
	generated   platform.DeliveryCredentialSet
	createErr   error
	createCalls int
}

func (a *reclaimScenarioAdapter) CheckDeliveryLiveness(context.Context, string, string) (platform.DeliveryLiveness, error) {
	index := a.probeCalls
	a.probeCalls++
	if index >= len(a.probes) {
		index = len(a.probes) - 1
	}
	return a.probes[index], nil
}

func (a *reclaimScenarioAdapter) CreateDeliveryCredentials(context.Context, platform.DeliveryCredentialRequest) (platform.DeliveryCredentialSet, error) {
	a.createCalls++
	return a.generated, a.createErr
}

func TestOAuthReclaimWorkerResultMatrixIntegration(t *testing.T) {
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
	cardID, orderID, versionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `UPDATE tsw_batches SET status='serving' WHERE id=$1`, ids.batch); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_delivery_versions(id,oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id)
		VALUES ($1,$2,1,'{"access_token":"old-access","refresh_token":"old-refresh"}',decode(repeat('11',32),'hex'),'subject',$3)`, versionID, ids.asset, ids.workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_oauth_assets SET status='ready',current_generation=1,current_delivery_version_id=$2,platform_subject_id='subject' WHERE id=$1`, ids.asset, versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_cards(id,membership_id,hmac_key_version,lookup_hmac,display_suffix,redemption_deadline)
		VALUES ($1,$2,1,decode(repeat('22',32),'hex'),'22AAAAAA',now()+interval '1 day')`, cardID, ids.membership); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_orders(id,membership_id,card_id,oauth_asset_id,current_delivery_version_id) VALUES ($1,$2,$3,$4,$5)`, orderID, ids.membership, cardID, ids.asset, versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET task_type='oauth_reclaim',input_snapshot=jsonb_build_object('order_id',$2::text),correlation_id='reclaim-healthy' WHERE id=$1`, ids.oldTask, orderID); err != nil {
		t.Fatal(err)
	}

	router, err := egress.New(egress.Config{Mode: egress.ModeDirect})
	if err != nil {
		t.Fatal(err)
	}
	defer router.CloseIdleConnections()
	leaseManager, err := egress.NewLeaseManager(router, egress.Admission{})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	worker := &Worker{Store: store, Egress: leaseManager, ID: "reclaim-integration", LeaseTime: time.Minute}
	worker.DeliveryRefresh = func(context.Context, *http.Client, string) (platform.DeliveryCredentialSet, error) {
		t.Fatalf("refresh was called before a confirmed 401")
		return platform.DeliveryCredentialSet{}, errors.New("unexpected refresh")
	}

	workspaces := oauthdomain.ProbeOK
	authError := oauthdomain.ProbeAuthError
	terminal := oauthdomain.ProbeDeactivatedWorkspace
	probe := func(status oauthdomain.ProbeStatus, httpStatus int) platform.DeliveryLiveness {
		return platform.DeliveryLiveness{Status: status, HTTPStatus: httpStatus, WorkspaceID: "workspace-platform", PlatformSubjectID: "subject", ObservedAt: time.Now().UTC()}
	}
	newCredentials := platform.DeliveryCredentialSet{
		RefreshToken: "fresh-refresh", AccessToken: reclaimIntegrationToken(), IDToken: reclaimIntegrationToken(),
		PlatformSubjectID: "subject", WorkspaceID: "workspace-platform", ExpiresIn: 3600, Scope: "openid",
	}
	cases := []struct {
		name          string
		probes        []platform.DeliveryLiveness
		refreshErr    error
		refreshResult platform.DeliveryCredentialSet
		createErr     error
		wantTier      string
		wantResult    string
		wantTask      string
		wantErr       error
		wantCreates   int
	}{
		{name: "healthy_no_action", probes: []platform.DeliveryLiveness{probe(workspaces, 200)}, wantTier: "probe_ok", wantResult: "probe_ok", wantTask: "succeeded"},
		{name: "refresh_recovered", probes: []platform.DeliveryLiveness{probe(authError, 401), probe(workspaces, 200)}, refreshResult: newCredentials, wantTier: "token_refresh", wantResult: "token_refresh", wantTask: "succeeded"},
		{name: "full_relogin_recovered", probes: []platform.DeliveryLiveness{probe(authError, 401), probe(workspaces, 200)}, refreshErr: errors.New("refresh rejected"), wantTier: "full_relogin", wantResult: "full_relogin", wantTask: "succeeded", wantCreates: 1},
		{name: "unrecoverable", probes: []platform.DeliveryLiveness{probe(terminal, 402)}, wantTier: "unrecoverable", wantResult: "unrecoverable", wantTask: "failed", wantErr: ErrAttemptFailed},
	}
	firstLease := uuid.New()
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET lease_token=$2 WHERE id=$1`, ids.oldTask, firstLease); err != nil {
		t.Fatal(err)
	}
	for index, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			taskID, leaseToken, correlationID := ids.oldTask, firstLease, "reclaim-"+scenario.name
			if index > 0 {
				taskID, leaseToken = uuid.NewString(), uuid.New()
				if _, err := pool.Exec(ctx, `INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,lease_owner,lease_token,lease_expires_at,attempt_count,max_attempts)
						VALUES ($1,$2,$3,$4,'oauth_reclaim',$5,jsonb_build_object('order_id',$6::text),$7,'running','reclaim-integration',$8,now()+interval '5 minutes',1,3)`, taskID, ids.membership, ids.asset, ids.workspace, scenario.name, orderID, correlationID, leaseToken); err != nil {
					t.Fatal(err)
				}
			} else if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET input_snapshot=jsonb_build_object('order_id',$2::text),correlation_id=$3 WHERE id=$1`, taskID, orderID, correlationID); err != nil {
				t.Fatal(err)
			}

			adapter := &reclaimScenarioAdapter{probes: scenario.probes, generated: newCredentials, createErr: scenario.createErr}
			worker.DeliveryAdapter = func(*http.Client, platform.Credentials) (platform.DeliveryAdapter, error) { return adapter, nil }
			refreshCalls := 0
			worker.DeliveryRefresh = func(context.Context, *http.Client, string) (platform.DeliveryCredentialSet, error) {
				refreshCalls++
				return scenario.refreshResult, scenario.refreshErr
			}
			lease, err := leaseManager.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			item := Task{ID: taskID, TaskType: "oauth_reclaim", WorkspaceID: ids.workspace, MembershipID: ids.membership, OAuthAssetID: ids.asset, LeaseToken: leaseToken, AttemptNo: 1, CorrelationID: correlationID}
			err = worker.runDeliveryReclaim(ctx, item, lease)
			lease.Release()
			if !errors.Is(err, scenario.wantErr) {
				t.Fatalf("worker error=%v want %v", err, scenario.wantErr)
			}
			var gotTier, gotResult, gotTaskStatus string
			if err := pool.QueryRow(ctx, `SELECT reclaim_tier,reclaim_result,status FROM tsw_tasks WHERE id=$1`, taskID).Scan(&gotTier, &gotResult, &gotTaskStatus); err != nil {
				t.Fatal(err)
			}
			if gotTier != scenario.wantTier || gotResult != scenario.wantResult || gotTaskStatus != scenario.wantTask {
				t.Fatalf("tier=%s result=%s task=%s", gotTier, gotResult, gotTaskStatus)
			}
			if adapter.createCalls != scenario.wantCreates {
				t.Fatalf("full relogin calls=%d want %d", adapter.createCalls, scenario.wantCreates)
			}
			if scenario.name == "healthy_no_action" && (refreshCalls != 0 || adapter.createCalls != 0) {
				t.Fatalf("healthy probe performed recovery: refresh=%d relogin=%d", refreshCalls, adapter.createCalls)
			}
		})
	}

	staleTaskID, newerTaskID := uuid.NewString(), uuid.NewString()
	staleLease, newerLease := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,lease_owner,lease_token,lease_expires_at,attempt_count,max_attempts)
		VALUES ($1,$2,$3,$4,'oauth_reclaim','stale-reclaim',jsonb_build_object('order_id',$5::text),'stale-reclaim','running','stale-reclaim',$6,now()+interval '5 minutes',1,3)`, staleTaskID, ids.membership, ids.asset, ids.workspace, orderID, staleLease); err != nil {
		t.Fatal(err)
	}
	staleItem := Task{ID: staleTaskID, TaskType: "oauth_reclaim", WorkspaceID: ids.workspace, MembershipID: ids.membership, OAuthAssetID: ids.asset, LeaseToken: staleLease, AttemptNo: 1, CorrelationID: "stale-reclaim"}
	staleAttempt, err := store.BeginDeliveryAttempt(ctx, staleItem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET task_type='oauth_generate' WHERE id=$1`, staleTaskID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_oauth_attempts SET state='superseded',outcome_code='newer_generation',finished_at=now() WHERE id=$1`, staleAttempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,lease_owner,lease_token,lease_expires_at,attempt_count,max_attempts)
		VALUES ($1,$2,$3,$4,'oauth_generate','newer-generation','{}','newer-generation','running','newer-generation',$5,now()+interval '5 minutes',1,3)`, newerTaskID, ids.membership, ids.asset, ids.workspace, newerLease); err != nil {
		t.Fatal(err)
	}
	newerItem := Task{ID: newerTaskID, TaskType: "oauth_generate", WorkspaceID: ids.workspace, MembershipID: ids.membership, OAuthAssetID: ids.asset, LeaseToken: newerLease, AttemptNo: 1, CorrelationID: "newer-generation"}
	newerAttempt, err := store.BeginDeliveryAttempt(ctx, newerItem)
	if err != nil {
		t.Fatal(err)
	}
	staleTarget := DeliveryReclaimTarget{DeliveryTarget: DeliveryTarget{PlatformWorkspace: "workspace-platform", PlatformSubjectID: "subject"}, OrderID: orderID, CurrentVersionID: versionID, CardID: cardID}
	if err := store.FinishDeliveryReclaim(ctx, staleItem, staleAttempt, staleTarget, newCredentials, probe(workspaces, 200), "full_relogin", false, false); !errors.Is(err, ErrDeliveryAttemptSuperseded) {
		t.Fatalf("late reclaim publish err=%v want ErrDeliveryAttemptSuperseded", err)
	}
	var staleTaskStatus, latestAssetStatus, latestOrderVersion string
	if err := pool.QueryRow(ctx, `SELECT stale.status,asset.status,ord.current_delivery_version_id::text
		FROM tsw_tasks stale JOIN tsw_oauth_assets asset ON asset.id=stale.oauth_asset_id JOIN tsw_orders ord ON ord.oauth_asset_id=asset.id
		WHERE stale.id=$1 AND asset.current_attempt_id=$2`, staleTaskID, newerAttempt.ID).Scan(&staleTaskStatus, &latestAssetStatus, &latestOrderVersion); err != nil {
		t.Fatal(err)
	}
	var versions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_delivery_versions WHERE oauth_asset_id=$1`, ids.asset).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if staleTaskStatus != "running" || latestAssetStatus != "generating" || latestOrderVersion == versionID || versions != 3 {
		t.Fatalf("stale reclaim changed state: task=%s asset=%s orderVersion=%s versions=%d", staleTaskStatus, latestAssetStatus, latestOrderVersion, versions)
	}
}

func reclaimIntegrationToken() string {
	payload := `{"https://api.openai.com/auth":{"chatgpt_account_id":"workspace-platform","chatgpt_user_id":"subject"},"sub":"subject"}`
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func TestOAuthReclaimPublishesCurrentVersionAndRevokesOldAccess(t *testing.T) {
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
	cardID, orderID, versionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `UPDATE tsw_batches SET status='serving' WHERE id=(SELECT batch_id FROM tsw_batch_memberships WHERE id=$1)`, ids.membership); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_delivery_versions(id,oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id)
		VALUES($1,$2,1,'{"access_token":"old-access","refresh_token":"old-refresh"}',decode(repeat('11',32),'hex'),'subject',$3)`, versionID, ids.asset, ids.workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_oauth_assets SET status='ready',current_generation=1,current_delivery_version_id=$2,liveness_status='auth_error',liveness_http_status=401 WHERE id=$1`, ids.asset, versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_cards(id,membership_id,hmac_key_version,lookup_hmac,display_suffix,redemption_deadline)
		VALUES($1,$2,1,decode(repeat('22',32),'hex'),'22AAAAAA',now()+interval '1 day')`, cardID, ids.membership); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_orders(id,membership_id,card_id,oauth_asset_id,current_delivery_version_id) VALUES($1,$2,$3,$4,$5)`, orderID, ids.membership, cardID, ids.asset, versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_public_tokens(membership_id,card_id,order_id,oauth_asset_id,delivery_version_id,token_kind,token_hash,expires_at)
		VALUES($1,$2,$3,$4,$5,'customer_access',decode(repeat('33',32),'hex'),now()+interval '1 day')`, ids.membership, cardID, orderID, ids.asset, versionID); err != nil {
		t.Fatal(err)
	}
	leaseToken := uuid.New()
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET task_type='oauth_reclaim',input_snapshot=jsonb_build_object('order_id',$2::text),status='running',lease_owner='integration',lease_token=$3,lease_expires_at=now()+interval '10 minutes',attempt_count=1 WHERE id=$1`, ids.oldTask, orderID, leaseToken); err != nil {
		t.Fatal(err)
	}
	otherWorkspaceID, otherBindingID, otherBatchID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	otherOperationID, otherOperationTargetID, otherMembershipID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	otherAssetID, otherVersionID, otherCardID, otherOrderID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	otherTaskID := uuid.NewString()
	otherLeaseToken := uuid.New()
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES ($1,'other-workspace-platform','other workspace')`, []any{otherWorkspaceID}},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id) VALUES ($1,$2,$3)`, []any{otherBindingID, ids.mother, otherWorkspaceID}},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,status,planned_at) VALUES ($1,$2,2,'serving',now()+interval '1 day')`, []any{otherBatchID, otherBindingID}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id) VALUES ($1,$2,$3,$4,'join','other-workspace-op',decode(repeat('66',32),'hex'),'{}','other-workspace')`, []any{otherOperationID, ids.owner, otherWorkspaceID, otherBatchID}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal) VALUES ($1,$2,$3,1)`, []any{otherOperationTargetID, otherOperationID, ids.target}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at) VALUES ($1,$2,$3,$4,now())`, []any{otherMembershipID, otherBatchID, ids.target, otherOperationTargetID}},
		{`UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2,status='succeeded',completed_at=now() WHERE id=$1`, []any{otherOperationTargetID, otherMembershipID}},
		{`INSERT INTO tsw_oauth_assets(id,membership_id,status,current_generation,platform_subject_id) VALUES ($1,$2,'ready',7,'other-subject')`, []any{otherAssetID, otherMembershipID}},
		{`INSERT INTO tsw_delivery_versions(id,oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id) VALUES ($1,$2,7,'{"access_token":"other-access","refresh_token":"other-refresh"}',decode(repeat('77',32),'hex'),'other-subject',$3)`, []any{otherVersionID, otherAssetID, otherWorkspaceID}},
		{`UPDATE tsw_oauth_assets SET current_delivery_version_id=$2 WHERE id=$1`, []any{otherAssetID, otherVersionID}},
		{`INSERT INTO tsw_cards(id,membership_id,hmac_key_version,lookup_hmac,display_suffix,redemption_deadline) VALUES ($1,$2,1,decode(repeat('88',32),'hex'),'88BBBBBB',now()+interval '1 day')`, []any{otherCardID, otherMembershipID}},
		{`INSERT INTO tsw_orders(id,membership_id,card_id,oauth_asset_id,current_delivery_version_id) VALUES ($1,$2,$3,$4,$5)`, []any{otherOrderID, otherMembershipID, otherCardID, otherAssetID, otherVersionID}},
		{`INSERT INTO tsw_public_tokens(membership_id,card_id,order_id,oauth_asset_id,delivery_version_id,token_kind,token_hash,expires_at) VALUES ($1,$2,$3,$4,$5,'customer_access',decode(repeat('99',32),'hex'),now()+interval '1 day')`, []any{otherMembershipID, otherCardID, otherOrderID, otherAssetID, otherVersionID}},
		{`INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,lease_owner,lease_token,lease_expires_at,attempt_count,max_attempts) VALUES ($1,$2,$3,$4,'oauth_reclaim','other-workspace-task',jsonb_build_object('order_id',$5::text),'other-workspace','running','integration',$6,now()+interval '10 minutes',1,3)`, []any{otherTaskID, otherMembershipID, otherAssetID, otherWorkspaceID, otherOrderID, otherLeaseToken}},
	}
	for _, query := range queries {
		if _, err := pool.Exec(ctx, query.query, query.args...); err != nil {
			t.Fatalf("seed other workspace: %v", err)
		}
	}

	item := Task{ID: ids.oldTask, TaskType: "oauth_reclaim", WorkspaceID: ids.workspace, MembershipID: ids.membership, OAuthAssetID: ids.asset, LeaseToken: leaseToken, AttemptNo: 1, CorrelationID: "integration-reclaim"}
	store := NewStore(pool)
	attempt, err := store.BeginDeliveryAttempt(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Generation != 2 {
		t.Fatalf("reclaim generation=%d want 2", attempt.Generation)
	}
	if err := store.RecordDeliveryReclaimStage(ctx, item, attempt, "refresh", "token_refresh"); err != nil {
		t.Fatal(err)
	}
	var recordedStage, recordedTier string
	if err := pool.QueryRow(ctx, `SELECT reclaim_stage,reclaim_tier FROM tsw_tasks WHERE id=$1`, item.ID).Scan(&recordedStage, &recordedTier); err != nil {
		t.Fatal(err)
	}
	if recordedStage != "refresh" || recordedTier != "token_refresh" {
		t.Fatalf("reclaim progress stage=%s tier=%s", recordedStage, recordedTier)
	}
	target := DeliveryReclaimTarget{
		DeliveryTarget: DeliveryTarget{AssetID: ids.asset, WorkspaceID: ids.workspace, PlatformWorkspace: "workspace-platform", PlatformSubjectID: "subject"},
		OrderID:        orderID, CurrentVersionID: versionID, CardID: cardID,
	}
	generated := platform.DeliveryCredentialSet{RefreshToken: "new-refresh", AccessToken: "new-access", IDToken: "new-id", PlatformSubjectID: "subject", WorkspaceID: "workspace-platform"}
	probe := platform.DeliveryLiveness{Status: "ok", HTTPStatus: 200, PlatformSubjectID: "subject", WorkspaceID: "workspace-platform", ObservedAt: time.Now().UTC()}
	if err := store.FinishDeliveryReclaim(ctx, item, attempt, target, generated, probe, "token_refresh", false, false); err != nil {
		t.Fatal(err)
	}
	var assetStatus, orderVersion, assetVersion, taskStatus string
	var oldTokenRevoked bool
	if err := pool.QueryRow(ctx, `SELECT asset.status,ord.current_delivery_version_id::text,asset.current_delivery_version_id::text,token.revoked_at IS NOT NULL,task.status
		FROM tsw_oauth_assets asset JOIN tsw_orders ord ON ord.oauth_asset_id=asset.id
		JOIN tsw_public_tokens token ON token.order_id=ord.id JOIN tsw_tasks task ON task.id=$2 WHERE asset.id=$1`, ids.asset, ids.oldTask).Scan(
		&assetStatus, &orderVersion, &assetVersion, &oldTokenRevoked, &taskStatus); err != nil {
		t.Fatal(err)
	}
	if assetStatus != "ready" || orderVersion != assetVersion || orderVersion == versionID || !oldTokenRevoked || taskStatus != "succeeded" {
		t.Fatalf("reclaim settlement asset=%s orderVersion=%s assetVersion=%s oldTokenRevoked=%t task=%s", assetStatus, orderVersion, assetVersion, oldTokenRevoked, taskStatus)
	}
	var otherAssetStatus, otherAssetVersion, otherOrderVersion, otherTaskStatus string
	var otherGeneration int64
	var otherTokenRevoked bool
	if err := pool.QueryRow(ctx, `SELECT asset.status,asset.current_generation,asset.current_delivery_version_id::text,ord.current_delivery_version_id::text,task.status,token.revoked_at IS NOT NULL
		FROM tsw_oauth_assets asset JOIN tsw_orders ord ON ord.oauth_asset_id=asset.id JOIN tsw_tasks task ON task.id=$2
		JOIN tsw_public_tokens token ON token.order_id=ord.id WHERE asset.id=$1`, otherAssetID, otherTaskID).Scan(&otherAssetStatus, &otherGeneration, &otherAssetVersion, &otherOrderVersion, &otherTaskStatus, &otherTokenRevoked); err != nil {
		t.Fatal(err)
	}
	if otherAssetStatus != "ready" || otherGeneration != 7 || otherAssetVersion != otherVersionID || otherOrderVersion != otherVersionID || otherTaskStatus != "running" || otherTokenRevoked {
		t.Fatalf("other workspace changed: asset=%s generation=%d assetVersion=%s orderVersion=%s task=%s tokenRevoked=%t", otherAssetStatus, otherGeneration, otherAssetVersion, otherOrderVersion, otherTaskStatus, otherTokenRevoked)
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
		{`INSERT INTO tsw_target_credentials(target_account_id,password_secret,platform_subject_id) VALUES ($1,'password','subject')`, []any{ids.target}},
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
