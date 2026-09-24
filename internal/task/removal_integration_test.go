//go:build integration

package task

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
	"github.com/teamseatwatch/teamseatwatch/internal/workspace"
)

type removalIntegrationKeyRing struct{}

func (removalIntegrationKeyRing) Current() (uint16, [32]byte) { return 1, [32]byte{1} }
func (removalIntegrationKeyRing) Lookup(version uint16) ([32]byte, bool) {
	return [32]byte{1}, version == 1
}

var _ auth.KeyRing = removalIntegrationKeyRing{}

type removalScenarioAdapter struct {
	snapshots []platform.ExactMemberSnapshot
	removals  []platform.RemoveMemberResult
	removeErr []error
	deleted   []string
}

func (a *removalScenarioAdapter) SnapshotMembers(context.Context, string) (platform.ExactMemberSnapshot, error) {
	if len(a.snapshots) == 0 {
		return platform.ExactMemberSnapshot{}, errors.New("unexpected snapshot")
	}
	result := a.snapshots[0]
	a.snapshots = a.snapshots[1:]
	return result, nil
}

func (a *removalScenarioAdapter) RemoveMember(_ context.Context, _ string, memberID string) (platform.RemoveMemberResult, error) {
	a.deleted = append(a.deleted, memberID)
	if len(a.removals) == 0 {
		return platform.RemoveMemberResult{}, errors.New("unexpected removal")
	}
	result := a.removals[0]
	a.removals = a.removals[1:]
	var err error
	if len(a.removeErr) > 0 {
		err = a.removeErr[0]
		a.removeErr = a.removeErr[1:]
	}
	return result, err
}

type removalGraph struct {
	owner, workspace, batch, targetOne, targetTwo, membershipOne, membershipTwo, operation string
}

func newRemovalIntegrationPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
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
	t.Cleanup(pool.Close)
	return pool, ctx
}

func seedRemovalGraph(t *testing.T, ctx context.Context, pool *pgxpool.Pool) removalGraph {
	t.Helper()
	id := func() string { return uuid.NewString() }
	graph := removalGraph{owner: id(), workspace: id(), batch: id(), targetOne: id(), targetTwo: id(), membershipOne: id(), membershipTwo: id(), operation: id()}
	mother, binding, joinOperation, joinTargetOne, joinTargetTwo := id(), id(), id(), id(), id()
	removeTargetOne, removeTargetTwo := id(), id()
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_owners(id,username,password_hash,totp_ciphertext,totp_nonce,totp_key_version) VALUES ($1,'owner','hash',decode(repeat('11',16),'hex'),decode(repeat('22',12),'hex'),1)`, []any{graph.owner}},
		{`INSERT INTO tsw_mother_accounts(id,display_name) VALUES ($1,'mother')`, []any{mother}},
		{`INSERT INTO tsw_mother_account_credentials(mother_account_id,login_identifier,identifier_hmac,identifier_key_version,password_secret) VALUES ($1,'owner@example.com',decode(repeat('10',32),'hex'),1,'password')`, []any{mother}},
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES ($1,'workspace-platform','workspace')`, []any{graph.workspace}},
		{`INSERT INTO tsw_workspace_projections(workspace_id,operational_state) VALUES ($1,'unknown')`, []any{graph.workspace}},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id) VALUES ($1,$2,$3)`, []any{binding, mother, graph.workspace}},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,status,planned_at,service_started_at) VALUES ($1,$2,1,'removing',now()-interval '1 hour',now())`, []any{graph.batch, binding}},
		{`INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES ($1,'one@example.com',decode(repeat('31',32),'hex'),1,'one'),($2,'two@example.com',decode(repeat('32',32),'hex'),1,'two')`, []any{graph.targetOne, graph.targetTwo}},
		{`INSERT INTO tsw_target_credentials(target_account_id,password_secret) VALUES ($1,'one-password'),($2,'two-password')`, []any{graph.targetOne, graph.targetTwo}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,status,completed_at,correlation_id) VALUES ($1,$2,$3,$4,'join','join-operation',decode(repeat('40',32),'hex'),'{}','succeeded',now(),'join')`, []any{joinOperation, graph.owner, graph.workspace, graph.batch}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal,status,preflight_status,preflight_origin,preflight_at,completed_at) VALUES ($1,$3,$4,1,'succeeded','available','worker',now(),now()),($2,$3,$5,2,'succeeded','available','worker',now(),now())`, []any{joinTargetOne, joinTargetTwo, joinOperation, graph.targetOne, graph.targetTwo}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,platform_member_id,joined_at,removal_requested_at) VALUES ($1,$3,$4,$5,'stored-one',now()-interval '1 day',now()),($2,$3,$6,$7,'stored-two',now()-interval '1 day',now())`, []any{graph.membershipOne, graph.membershipTwo, graph.batch, graph.targetOne, joinTargetOne, graph.targetTwo, joinTargetTwo}},
		{`UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=CASE id WHEN $1::uuid THEN $3::uuid ELSE $4::uuid END WHERE id IN ($1::uuid,$2::uuid)`, []any{joinTargetOne, joinTargetTwo, graph.membershipOne, graph.membershipTwo}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id) VALUES ($1,$2,$3,$4,'remove','remove-operation',decode(repeat('50',32),'hex'),'{}','remove')`, []any{graph.operation, graph.owner, graph.workspace, graph.batch}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,membership_id,ordinal) VALUES ($1,$3,$4,1),($2,$3,$5,2)`, []any{removeTargetOne, removeTargetTwo, graph.operation, graph.membershipOne, graph.membershipTwo}},
		{`INSERT INTO tsw_tasks(operation_target_id,membership_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,max_attempts) VALUES ($1,$3,$5,'remove',$6,'{}','remove',6),($2,$4,$5,'remove',$7,'{}','remove',6)`, []any{removeTargetOne, removeTargetTwo, graph.membershipOne, graph.membershipTwo, graph.workspace, "remove:" + removeTargetOne, "remove:" + removeTargetTwo}},
	}
	for _, item := range queries {
		if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatalf("seed removal graph: %v\n%s", err, item.query)
		}
	}
	return graph
}

func exactRemovalSnapshot(members ...platform.Member) platform.ExactMemberSnapshot {
	count := len(members)
	return platform.ExactMemberSnapshot{DeclaredMemberCount: count, Fact: platform.Result{
		Endpoint: platform.EndpointMembers, Outcome: platform.OutcomeOperational, HTTPStatus: http.StatusOK,
		ObservedAt: time.Now().UTC(), Completeness: platform.Complete, MemberCount: &count, Members: members,
	}}
}

func newRemovalWorker(t *testing.T, pool *pgxpool.Pool, adapter *removalScenarioAdapter) *Worker {
	t.Helper()
	router, err := egress.New(egress.Config{Mode: egress.ModeDirect})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.CloseIdleConnections)
	leases, err := egress.NewLeaseManager(router, egress.Admission{})
	if err != nil {
		t.Fatal(err)
	}
	return &Worker{
		Store: NewStore(pool), Facts: workspace.NewService(pool, removalIntegrationKeyRing{}), Egress: leases,
		ID: "remove-integration", LeaseTime: time.Minute,
		Remover: func(*http.Client, platform.Credentials) (platform.Remover, error) { return adapter, nil },
	}
}

func removalTestMembers() (platform.Member, platform.Member, platform.Member) {
	return platform.Member{Kind: "member", PlatformMemberID: "owner-live", Identifier: "owner@example.com", Status: "active", Role: "owner"},
		platform.Member{Kind: "member", PlatformMemberID: "live-one", Identifier: "one@example.com", Status: "active", Role: "member"},
		platform.Member{Kind: "member", PlatformMemberID: "live-two", Identifier: "two@example.com", Status: "active", Role: "member"}
}

func TestRemovalIntegrationRequiredEgressAdmissionBlocksMutation(t *testing.T) {
	pool, ctx := newRemovalIntegrationPool(t)
	graph := seedRemovalGraph(t, ctx, pool)
	adapter := &removalScenarioAdapter{}
	router, err := egress.New(egress.Config{
		Mode:            egress.ModeRequired,
		Endpoints:       []egress.Endpoint{{ID: "proxy-1", URL: "https://proxy.invalid:443"}},
		ReachabilityURL: "https://reachability.invalid",
		IPEchoURL:       "https://ip-echo.invalid",
		HMACKey:         []byte("removal-test-key"),
		HMACKeyVersion:  "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.CloseIdleConnections)
	leases, err := egress.NewLeaseManager(router, egress.Admission{})
	if err != nil {
		t.Fatal(err)
	}
	worker := &Worker{
		Store: NewStore(pool), Facts: workspace.NewService(pool, removalIntegrationKeyRing{}), Egress: leases,
		ID: "remove-required-egress", LeaseTime: time.Minute,
		Remover: func(*http.Client, platform.Credentials) (platform.Remover, error) { return adapter, nil },
	}
	if worked, err := worker.RunOnce(ctx); !worked || !errors.Is(err, ErrAttemptFailed) {
		t.Fatalf("required egress admission worked=%v err=%v", worked, err)
	}
	if len(adapter.deleted) != 0 {
		t.Fatalf("required egress failure issued DELETE: %v", adapter.deleted)
	}
	var targetStatus, diagnostic string
	if err := pool.QueryRow(ctx, `SELECT status,diagnostic_code FROM tsw_operation_targets WHERE operation_id=$1 AND ordinal=1`, graph.operation).Scan(&targetStatus, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if targetStatus != "unknown" || diagnostic != "proxy_capacity_exhausted" {
		t.Fatalf("required egress target status=%s diagnostic=%s", targetStatus, diagnostic)
	}
}

func TestRemovalIntegrationDoesNotEndBatchAfterPartialOutcome(t *testing.T) {
	pool, ctx := newRemovalIntegrationPool(t)
	graph := seedRemovalGraph(t, ctx, pool)
	owner, one, two := removalTestMembers()
	adapter := &removalScenarioAdapter{
		snapshots: []platform.ExactMemberSnapshot{exactRemovalSnapshot(owner, one, two), exactRemovalSnapshot(owner, two), exactRemovalSnapshot(owner, two), exactRemovalSnapshot(owner, two)},
		removals:  []platform.RemoveMemberResult{{HTTPStatus: 200, Accepted: true, RequestMayHaveEffect: true}, {HTTPStatus: 429, ErrorCode: "rate_limit", Retryable: true, RequestMayHaveEffect: true}},
	}
	worker := newRemovalWorker(t, pool, adapter)
	if worked, err := worker.RunOnce(ctx); !worked || err != nil {
		t.Fatalf("canary worked=%v err=%v", worked, err)
	}
	if worked, err := worker.RunOnce(ctx); !worked || !errors.Is(err, ErrAttemptFailed) {
		t.Fatalf("partial worked=%v err=%v", worked, err)
	}
	var batchStatus, firstState, secondState string
	var endedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT batch.status,batch.service_ended_at,first.state,second.state FROM tsw_batches batch JOIN tsw_batch_memberships first ON first.id=$2 JOIN tsw_batch_memberships second ON second.id=$3 WHERE batch.id=$1`, graph.batch, graph.membershipOne, graph.membershipTwo).Scan(&batchStatus, &endedAt, &firstState, &secondState); err != nil {
		t.Fatal(err)
	}
	if batchStatus != "removing" || endedAt != nil || firstState != "removed" || secondState != "active" {
		t.Fatalf("batch=%s ended=%v memberships=%s/%s", batchStatus, endedAt, firstState, secondState)
	}
	if len(adapter.deleted) != 2 || adapter.deleted[0] != "live-one" || adapter.deleted[1] != "live-two" {
		t.Fatalf("DELETE targets=%v", adapter.deleted)
	}
}

func TestRemovalIntegrationReconcilesUnknownBeforeRetry(t *testing.T) {
	pool, ctx := newRemovalIntegrationPool(t)
	graph := seedRemovalGraph(t, ctx, pool)
	owner, one, two := removalTestMembers()
	adapter := &removalScenarioAdapter{
		snapshots: []platform.ExactMemberSnapshot{exactRemovalSnapshot(owner, one, two)},
		removals:  []platform.RemoveMemberResult{{RequestMayHaveEffect: true, Retryable: true}},
		removeErr: []error{errors.New("response lost")},
	}
	worker := newRemovalWorker(t, pool, adapter)
	if worked, err := worker.RunOnce(ctx); !worked || !errors.Is(err, ErrAttemptFailed) {
		t.Fatalf("unknown worked=%v err=%v", worked, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET available_at=now() WHERE task_type='remove' AND operation_target_id=(SELECT id FROM tsw_operation_targets WHERE operation_id=$1 AND ordinal=1)`, graph.operation); err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.RunOnce(ctx); !worked || !errors.Is(err, ErrAttemptFailed) {
		t.Fatalf("incomplete reconciliation worked=%v err=%v", worked, err)
	}
	var targetStatus, taskStatus string
	var mayHaveReached bool
	if err := pool.QueryRow(ctx, `SELECT target_result.status,target_result.platform_request_may_have_reached,task.status
		FROM tsw_operation_targets target_result JOIN tsw_tasks task ON task.operation_target_id=target_result.id
		WHERE target_result.operation_id=$1 AND target_result.ordinal=1 AND task.task_type='remove'`, graph.operation).Scan(&targetStatus, &mayHaveReached, &taskStatus); err != nil {
		t.Fatal(err)
	}
	if targetStatus != "unknown" || !mayHaveReached || taskStatus != "retry_wait" || len(adapter.deleted) != 1 {
		t.Fatalf("incomplete reconciliation target=%s mayHaveReached=%v task=%s deletes=%v", targetStatus, mayHaveReached, taskStatus, adapter.deleted)
	}
	adapter.snapshots = append(adapter.snapshots, exactRemovalSnapshot(owner, one, two))
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET available_at=now() WHERE task_type='remove' AND operation_target_id=(SELECT id FROM tsw_operation_targets WHERE operation_id=$1 AND ordinal=1)`, graph.operation); err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.RunOnce(ctx); !worked || !errors.Is(err, ErrAttemptFailed) {
		t.Fatalf("reconcile worked=%v err=%v", worked, err)
	}
	if len(adapter.deleted) != 1 {
		t.Fatalf("unknown result replayed DELETE: %v", adapter.deleted)
	}
	if err := pool.QueryRow(ctx, `SELECT target_result.status,target_result.platform_request_may_have_reached,task.status
		FROM tsw_operation_targets target_result JOIN tsw_tasks task ON task.operation_target_id=target_result.id
		WHERE target_result.operation_id=$1 AND target_result.ordinal=1 AND task.task_type='remove'`, graph.operation).Scan(&targetStatus, &mayHaveReached, &taskStatus); err != nil {
		t.Fatal(err)
	}
	if targetStatus != "queued" || mayHaveReached || taskStatus != "retry_wait" {
		t.Fatalf("reconciled target=%s mayHaveReached=%v task=%s", targetStatus, mayHaveReached, taskStatus)
	}
}

func TestRemovalIntegrationBoundsMutationRetries(t *testing.T) {
	pool, ctx := newRemovalIntegrationPool(t)
	graph := seedRemovalGraph(t, ctx, pool)
	owner, one, two := removalTestMembers()
	adapter := &removalScenarioAdapter{
		snapshots: []platform.ExactMemberSnapshot{
			exactRemovalSnapshot(owner, one, two), exactRemovalSnapshot(owner, one, two),
			exactRemovalSnapshot(owner, one, two), exactRemovalSnapshot(owner, one, two),
			exactRemovalSnapshot(owner, one, two), exactRemovalSnapshot(owner, one, two),
			exactRemovalSnapshot(owner, one, two),
		},
		removals: []platform.RemoveMemberResult{
			{HTTPStatus: 429, ErrorCode: "rate_limit", Retryable: true, RequestMayHaveEffect: true},
			{HTTPStatus: 429, ErrorCode: "rate_limit", Retryable: true, RequestMayHaveEffect: true},
			{HTTPStatus: 429, ErrorCode: "rate_limit", Retryable: true, RequestMayHaveEffect: true},
		},
	}
	worker := newRemovalWorker(t, pool, adapter)
	for attempt := 1; attempt <= 4; attempt++ {
		if attempt > 1 {
			if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET available_at=now() WHERE task_type='remove' AND operation_target_id=(SELECT id FROM tsw_operation_targets WHERE operation_id=$1 AND ordinal=1)`, graph.operation); err != nil {
				t.Fatal(err)
			}
		}
		if worked, err := worker.RunOnce(ctx); !worked || !errors.Is(err, ErrAttemptFailed) {
			t.Fatalf("attempt %d worked=%v err=%v", attempt, worked, err)
		}
	}
	if len(adapter.deleted) != maximumRemovalSideEffects {
		t.Fatalf("DELETE attempts=%d want %d", len(adapter.deleted), maximumRemovalSideEffects)
	}
	var status string
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT status,remove_attempt_count FROM tsw_operation_targets WHERE operation_id=$1 AND ordinal=1`, graph.operation).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "blocked" || attempts != maximumRemovalSideEffects {
		t.Fatalf("target status=%s attempts=%d", status, attempts)
	}
}

func TestRemovalIntegrationRecoversCrashWithFactsFirst(t *testing.T) {
	pool, ctx := newRemovalIntegrationPool(t)
	graph := seedRemovalGraph(t, ctx, pool)
	var taskID, operationTargetID string
	lease := uuid.New()
	if err := pool.QueryRow(ctx, `SELECT task.id::text,task.operation_target_id::text FROM tsw_tasks task
		JOIN tsw_operation_targets target_result ON target_result.id=task.operation_target_id
		WHERE target_result.operation_id=$1 AND target_result.ordinal=1`, graph.operation).Scan(&taskID, &operationTargetID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_tasks SET status='running',lease_owner='crashed',lease_token=$2,lease_expires_at=now()-interval '1 second',attempt_count=1 WHERE id=$1`, taskID, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_operation_targets SET status='running',platform_request_may_have_reached=true,platform_request_stage='remove_member',platform_request_started_at=now(),remove_attempt_count=1 WHERE id=$1`, operationTargetID); err != nil {
		t.Fatal(err)
	}
	owner, _, two := removalTestMembers()
	adapter := &removalScenarioAdapter{snapshots: []platform.ExactMemberSnapshot{exactRemovalSnapshot(owner, two)}}
	worker := newRemovalWorker(t, pool, adapter)
	if worked, err := worker.RunOnce(ctx); !worked || err != nil {
		t.Fatalf("recover worked=%v err=%v", worked, err)
	}
	if worked, err := worker.RunOnce(ctx); !worked || err != nil {
		t.Fatalf("reconcile absence worked=%v err=%v", worked, err)
	}
	if len(adapter.deleted) != 0 {
		t.Fatalf("crash recovery issued DELETE: %v", adapter.deleted)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM tsw_batch_memberships WHERE id=$1`, graph.membershipOne).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "removed" {
		t.Fatalf("reconciled membership state=%s", state)
	}
}

func TestRemovalIntegrationProtectsOwnerUnknownAndOtherWorkspace(t *testing.T) {
	pool, ctx := newRemovalIntegrationPool(t)
	graph := seedRemovalGraph(t, ctx, pool)
	owner, one, two := removalTestMembers()
	otherWorkspace, otherBinding, otherBatch, otherMembership, otherJoin, otherJoinTarget := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	var mother string
	if err := pool.QueryRow(ctx, `SELECT mother_account_id::text FROM tsw_mother_workspace_bindings WHERE workspace_id=$1`, graph.workspace).Scan(&mother); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES ($1,'workspace-other','other')`, []any{otherWorkspace}},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id) VALUES ($1,$2,$3)`, []any{otherBinding, mother, otherWorkspace}},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,status,planned_at,service_started_at) VALUES ($1,$2,1,'serving',now(),now())`, []any{otherBatch, otherBinding}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,status,completed_at,correlation_id) VALUES ($1,$2,$3,$4,'join',$5,decode(repeat('66',32),'hex'),'{}','succeeded',now(),'other')`, []any{otherJoin, graph.owner, otherWorkspace, otherBatch, "other-" + otherJoin}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal,status,preflight_status,preflight_origin,preflight_at,completed_at) VALUES ($1,$2,$3,1,'succeeded','available','worker',now(),now())`, []any{otherJoinTarget, otherJoin, graph.targetOne}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at) VALUES ($1,$2,$3,$4,now())`, []any{otherMembership, otherBatch, graph.targetOne, otherJoinTarget}},
		{`UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2 WHERE id=$1`, []any{otherJoinTarget, otherMembership}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	one.Role = "owner"
	unknown := platform.Member{Kind: "member", PlatformMemberID: "unknown-live", Identifier: "unknown@example.com", Status: "active", Role: "member"}
	adapter := &removalScenarioAdapter{snapshots: []platform.ExactMemberSnapshot{exactRemovalSnapshot(owner, one, two, unknown)}}
	worker := newRemovalWorker(t, pool, adapter)
	if worked, err := worker.RunOnce(ctx); !worked || !errors.Is(err, ErrAttemptFailed) {
		t.Fatalf("owner protection worked=%v err=%v", worked, err)
	}
	if len(adapter.deleted) != 0 {
		t.Fatalf("protected snapshot issued DELETE: %v", adapter.deleted)
	}
	var otherState, currentState string
	if err := pool.QueryRow(ctx, `SELECT current.state,other_membership.state FROM tsw_batch_memberships current JOIN tsw_batch_memberships other_membership ON other_membership.id=$2 WHERE current.id=$1`, graph.membershipOne, otherMembership).Scan(&currentState, &otherState); err != nil {
		t.Fatal(err)
	}
	if currentState != "active" || otherState != "active" {
		t.Fatalf("cross-Workspace state changed current=%s other=%s", currentState, otherState)
	}
}

func TestRemovalIntegrationEndsOnlyAfterEveryExactTargetIsAbsent(t *testing.T) {
	pool, ctx := newRemovalIntegrationPool(t)
	graph := seedRemovalGraph(t, ctx, pool)
	assetID, versionID, cardID, orderID, tokenID, reclaimTaskID, reclaimAttemptID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	reclaimLease := uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_oauth_assets(id,membership_id,status,current_generation,platform_subject_id) VALUES ($1,$2,'ready',1,'subject-two')`, []any{assetID, graph.membershipTwo}},
		{`INSERT INTO tsw_delivery_versions(id,oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id) VALUES ($1,$2,1,'{"access_token":"old","refresh_token":"old-refresh"}',decode(repeat('71',32),'hex'),'subject-two',$3)`, []any{versionID, assetID, graph.workspace}},
		{`UPDATE tsw_oauth_assets SET current_delivery_version_id=$2 WHERE id=$1`, []any{assetID, versionID}},
		{`INSERT INTO tsw_cards(id,membership_id,hmac_key_version,lookup_hmac,display_suffix,redemption_deadline) VALUES ($1,$2,1,decode(repeat('72',32),'hex'),'72AAAAAA',now()+interval '1 day')`, []any{cardID, graph.membershipTwo}},
		{`INSERT INTO tsw_orders(id,membership_id,card_id,oauth_asset_id,current_delivery_version_id) VALUES ($1,$2,$3,$4,$5)`, []any{orderID, graph.membershipTwo, cardID, assetID, versionID}},
		{`INSERT INTO tsw_public_tokens(id,membership_id,card_id,order_id,oauth_asset_id,delivery_version_id,token_kind,token_hash,expires_at) VALUES ($1,$2,$3,$4,$5,$6,'customer_access',decode(repeat('73',32),'hex'),now()+interval '1 hour')`, []any{tokenID, graph.membershipTwo, cardID, orderID, assetID, versionID}},
		{`INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,lease_owner,lease_token,lease_expires_at,attempt_count,max_attempts) VALUES ($1,$2,$3,$4,'oauth_reclaim','late-reclaim',jsonb_build_object('order_id',$5::text),'late-reclaim','running','late-reclaim',$6,now()+interval '10 minutes',1,3)`, []any{reclaimTaskID, graph.membershipTwo, assetID, graph.workspace, orderID, reclaimLease}},
		{`INSERT INTO tsw_oauth_attempts(id,oauth_asset_id,task_id,generation,attempt_no,attempt_kind,state,requested_order_id) VALUES ($1,$2,$3,2,1,'reclaim','running',$4)`, []any{reclaimAttemptID, assetID, reclaimTaskID, orderID}},
		{`UPDATE tsw_oauth_assets SET current_generation=2,current_attempt_id=$2,status='reclaiming' WHERE id=$1`, []any{assetID, reclaimAttemptID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed retained delivery: %v", err)
		}
	}
	owner, one, two := removalTestMembers()
	adapter := &removalScenarioAdapter{
		snapshots: []platform.ExactMemberSnapshot{exactRemovalSnapshot(owner, one, two), exactRemovalSnapshot(owner, two), exactRemovalSnapshot(owner, two), exactRemovalSnapshot(owner)},
		removals:  []platform.RemoveMemberResult{{HTTPStatus: 200, Accepted: true, RequestMayHaveEffect: true}, {HTTPStatus: 200, Accepted: true, RequestMayHaveEffect: true}},
	}
	worker := newRemovalWorker(t, pool, adapter)
	if worked, err := worker.RunOnce(ctx); !worked || err != nil {
		t.Fatalf("canary worked=%v err=%v", worked, err)
	}
	var statusAfterCanary string
	if err := pool.QueryRow(ctx, `SELECT status FROM tsw_batches WHERE id=$1`, graph.batch).Scan(&statusAfterCanary); err != nil {
		t.Fatal(err)
	}
	if statusAfterCanary != "removing" {
		t.Fatalf("batch advanced after canary: %s", statusAfterCanary)
	}
	if worked, err := worker.RunOnce(ctx); !worked || err != nil {
		t.Fatalf("final target worked=%v err=%v", worked, err)
	}
	var batchStatus, firstState, secondState string
	var endedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT batch.status,batch.service_ended_at,first.state,second.state FROM tsw_batches batch JOIN tsw_batch_memberships first ON first.id=$2 JOIN tsw_batch_memberships second ON second.id=$3 WHERE batch.id=$1`, graph.batch, graph.membershipOne, graph.membershipTwo).Scan(&batchStatus, &endedAt, &firstState, &secondState); err != nil {
		t.Fatal(err)
	}
	if batchStatus != "ended" || endedAt == nil || firstState != "removed" || secondState != "removed" {
		t.Fatalf("batch=%s ended=%v memberships=%s/%s", batchStatus, endedAt, firstState, secondState)
	}
	store := NewStore(pool)
	lateItem := Task{ID: reclaimTaskID, TaskType: "oauth_reclaim", WorkspaceID: graph.workspace, MembershipID: graph.membershipTwo, OAuthAssetID: assetID, LeaseToken: reclaimLease, AttemptNo: 1, CorrelationID: "late-reclaim"}
	lateAttempt := DeliveryAttempt{ID: reclaimAttemptID, Generation: 2, AttemptNo: 1}
	lateTarget := DeliveryReclaimTarget{DeliveryTarget: DeliveryTarget{WorkspaceID: graph.workspace, PlatformWorkspace: "workspace-platform", PlatformSubjectID: "subject-two"}, OrderID: orderID, CurrentVersionID: versionID, CardID: cardID}
	generated := platform.DeliveryCredentialSet{RefreshToken: "new-refresh", AccessToken: "new-access", IDToken: "new-id", PlatformSubjectID: "subject-two", WorkspaceID: "workspace-platform"}
	probe := platform.DeliveryLiveness{Status: "ok", HTTPStatus: 200, WorkspaceID: "workspace-platform", PlatformSubjectID: "subject-two", ObservedAt: time.Now().UTC()}
	if err := store.FinishDeliveryReclaim(ctx, lateItem, lateAttempt, lateTarget, generated, probe, "full_relogin", false, false); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("late reclaim publish err=%v want ErrLeaseLost", err)
	}
	var cardStatus, currentVersion string
	var orderCount, tokenCount int
	if err := pool.QueryRow(ctx, `SELECT card.status,asset.current_delivery_version_id::text,
		(SELECT count(*) FROM tsw_orders WHERE membership_id=$1),
		(SELECT count(*) FROM tsw_public_tokens WHERE membership_id=$1 AND revoked_at IS NULL)
		FROM tsw_cards card JOIN tsw_oauth_assets asset ON asset.membership_id=card.membership_id
		WHERE card.membership_id=$1`, graph.membershipTwo).Scan(&cardStatus, &currentVersion, &orderCount, &tokenCount); err != nil {
		t.Fatal(err)
	}
	if cardStatus != "active" || currentVersion != versionID || orderCount != 1 || tokenCount != 1 {
		t.Fatalf("service end changed retained delivery card=%s version=%s orders=%d tokens=%d", cardStatus, currentVersion, orderCount, tokenCount)
	}
}
