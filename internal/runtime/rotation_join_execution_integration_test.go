//go:build integration

package runtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
)

func executionFixture(t *testing.T) (*removalFixture, ownerContext, uuid.UUID) {
	t.Helper()
	f := newJoinFixture(t, 1)
	slot := joinReleased(t, f)
	owner := joinOwner(t, f)
	if _, err := f.h.reserveRotationJoinIntent(context.Background(), owner, f.preview.Id, slot); err != nil {
		t.Fatal(err)
	}
	return f, owner, slot
}

// Only legacy journal assertions intentionally creating unbound request markers
// use schema 32. Dispatch, membership, and SQL enforcement tests stay at 33.
func legacyExecutionSchema32Fixture(t *testing.T) (*removalFixture, ownerContext, uuid.UUID) {
	t.Helper()
	f, o, slot := executionFixture(t)
	membershipSchemaVersion(t, 32)
	return f, o, slot
}
func membershipSchemaVersion(t *testing.T, version int64) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("pgx", os.Getenv("TSW_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("../migrations/sql"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := provider.GetDBVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current > version {
		_, err = provider.DownTo(ctx, version)
	} else if current < version {
		_, err = provider.UpTo(ctx, version)
	}
	if err != nil {
		t.Fatal(err)
	}
	actual, err := provider.GetDBVersion(ctx)
	if err != nil || actual != version {
		t.Fatalf("schema=%d want=%d err=%v", actual, version, err)
	}
}
func executionClaim(t *testing.T, f *removalFixture, owner ownerContext, slot uuid.UUID, d time.Duration) rotationJoinExecutionLease {
	t.Helper()
	l, err := f.h.claimRotationJoinExecution(context.Background(), owner, f.preview.Id, slot, uuid.New(), d)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func executionError(t *testing.T, err error, want rotationJoinExecutionFailure) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
}
func executionExpire(t *testing.T, f *removalFixture, l rotationJoinExecutionLease) {
	t.Helper()
	f.exec(t, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.01)`, l.expires)
}

// Include credentials, protections, usage, epochs and all sources. Ordinary
// execution/dispatch assertions also detect any accidental schema34 writes.
func executionSources(t *testing.T, f *removalFixture) string {
	t.Helper()
	return executionSourceSnapshot(t, f, false)
}

// Migration31/32/33 down/up removes later derived tables as well. Only those
// migration assertions exclude the disappearing schema34/35 inventory.
func executionMigrationSources(t *testing.T, f *removalFixture) string {
	t.Helper()
	return executionSourceSnapshot(t, f, true)
}

func executionSourceSnapshot(t *testing.T, f *removalFixture, downgradeSchema34 bool) string {
	t.Helper()
	ctx := context.Background()
	rows, err := f.pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'tsw_%' AND tablename NOT IN ('tsw_rotation_join_executions','tsw_rotation_join_execution_attempts','tsw_rotation_join_membership_evidence','tsw_rotation_join_personal_bindings') AND (NOT $1::boolean OR tablename NOT IN ('tsw_rotation_join_credential_attempts','tsw_rotation_join_credential_events','tsw_rotation_join_credential_components','tsw_rotation_join_credential_generations','tsw_rotation_join_usage_attempts','tsw_rotation_join_usage_evidence','tsw_batch_zip_archives','tsw_batch_zip_members','tsw_batch_zip_receivers','tsw_batch_zip_protections','tsw_batch_zip_delivered')) ORDER BY tablename`, downgradeSchema34)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err = rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	var result strings.Builder
	for _, table := range tables {
		var raw string
		if err = f.pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM `+pgx.Identifier{"public", table}.Sanitize()+` t`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		result.WriteString(table + raw)
	}
	return result.String()
}
func executionState(t *testing.T, f *removalFixture, slot uuid.UUID) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(context.Background(), `SELECT state FROM tsw_rotation_join_executions WHERE slot_id=$1`, slot).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}
func executionEvents(t *testing.T, f *removalFixture, slot uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_rotation_join_execution_attempts WHERE slot_id=$1`, slot).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRotationJoinExecutionClaim(t *testing.T) {
	f, owner, slot := executionFixture(t)
	before := executionSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	l := executionClaim(t, f, owner, slot, time.Minute)
	if l.epoch != 1 || l.reconcileOnly || !l.expires.After(time.Now()) || l.workerID == uuid.Nil || l.token == uuid.Nil {
		t.Fatalf("invalid first claim: %+v", l)
	}
	var exact bool
	if err := f.pool.QueryRow(context.Background(), `SELECT ROW(e.slot_id,e.preview_id,e.workspace_id,e.owner_id,e.candidate_account_id,e.original_platform_member_id,e.candidate_identifier,e.seat_type,e.authorization_digest,e.authorized_session,e.epoch_versions,e.created_at) IS NOT DISTINCT FROM ROW(i.slot_id,i.preview_id,i.workspace_id,i.owner_id,i.candidate_account_id,i.original_platform_member_id,i.candidate_identifier,i.seat_type,i.authorization_digest,i.authorized_session,i.epoch_versions,i.created_at) FROM tsw_rotation_join_executions e JOIN tsw_rotation_candidate_join_intents i USING(slot_id) WHERE slot_id=$1`, slot).Scan(&exact); err != nil || !exact {
		t.Fatalf("binding exact=%v err=%v", exact, err)
	}
	for _, worker := range []uuid.UUID{l.workerID, uuid.New()} {
		_, err := f.h.claimRotationJoinExecution(context.Background(), owner, f.preview.Id, slot, worker, time.Minute)
		executionError(t, err, joinExecutionBusy)
	}
	for _, mutate := range []func(*rotationJoinExecutionLease){func(l *rotationJoinExecutionLease) { l.workerID = uuid.New() }, func(l *rotationJoinExecutionLease) { l.token = uuid.New() }, func(l *rotationJoinExecutionLease) { l.epoch++ }} {
		bad := l
		mutate(&bad)
		executionError(t, f.h.markRotationJoinStageStarted(context.Background(), bad, "request_join"), joinExecutionStale)
		executionError(t, f.h.finishRotationJoinStage(context.Background(), bad, "request_join", "succeeded", true), joinExecutionStale)
	}
	if executionEvents(t, f, slot) != 0 || before != executionSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("claim/stale rejection produced an event, wrote sources or called HTTP")
	}
}

func TestRotationJoinExecutionConcurrentClaim(t *testing.T) {
	for _, single := range []bool{false, true} {
		t.Run(fmt.Sprint("single_connection=", single), func(t *testing.T) {
			f, owner, slot := executionFixture(t)
			if single {
				config, err := pgxpool.ParseConfig(os.Getenv("TSW_TEST_DATABASE_URL"))
				if err != nil {
					t.Fatal(err)
				}
				config.MaxConns = 1
				pool, err := pgxpool.NewWithConfig(context.Background(), config)
				if err != nil {
					t.Fatal(err)
				}
				defer pool.Close()
				f.h.pool = pool
			}
			before := executionSources(t, f)
			reads, calls := f.http.reads, f.http.calls
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			errs := make(chan error, 8)
			leases := make(chan rotationJoinExecutionLease, 8)
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					l, err := f.h.claimRotationJoinExecution(ctx, owner, f.preview.Id, slot, uuid.New(), time.Minute)
					errs <- err
					leases <- l
				}()
			}
			wg.Wait()
			close(errs)
			close(leases)
			won := 0
			for err := range errs {
				if err == nil {
					won++
				} else {
					executionError(t, err, joinExecutionBusy)
				}
			}
			var count int
			var epoch int64
			if err := f.pool.QueryRow(ctx, `SELECT count(*),max(lease_epoch) FROM tsw_rotation_join_executions WHERE slot_id=$1`, slot).Scan(&count, &epoch); err != nil {
				t.Fatal(err)
			}
			if won != 1 || count != 1 || epoch != 1 || before != executionSources(t, f) || reads != f.http.reads || calls != f.http.calls {
				t.Fatalf("concurrent claim won=%d count=%d epoch=%d or side effects", won, count, epoch)
			}
		})
	}
}

func TestRotationJoinExecutionStageOrderAndAppendOnlyPairing(t *testing.T) {
	f, owner, slot := legacyExecutionSchema32Fixture(t)
	before := executionSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	l := executionClaim(t, f, owner, slot, time.Minute)
	ctx := context.Background()
	for _, stage := range []string{"accept_join", "reconcile", "unknown"} {
		executionError(t, f.h.markRotationJoinStageStarted(ctx, l, stage), joinExecutionTransition)
	}
	executionError(t, f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true), joinExecutionTransition)
	for _, stage := range []string{"request_join", "accept_join"} {
		if err := f.h.markRotationJoinStageStarted(ctx, l, stage); err != nil {
			t.Fatal(err)
		}
		executionError(t, f.h.markRotationJoinStageStarted(ctx, l, stage), joinExecutionTransition)
		var startBefore, startAfter string
		if err := f.pool.QueryRow(ctx, `SELECT to_jsonb(a)::text FROM tsw_rotation_join_execution_attempts a WHERE slot_id=$1 AND stage=$2 AND event_kind='started'`, slot, stage).Scan(&startBefore); err != nil {
			t.Fatal(err)
		}
		executionError(t, f.h.finishRotationJoinStage(ctx, l, stage, "upstream raw secret", true), joinExecutionTransition)
		if err := f.h.finishRotationJoinStage(ctx, l, stage, "succeeded", true); err != nil {
			t.Fatal(err)
		}
		if err := f.pool.QueryRow(ctx, `SELECT to_jsonb(a)::text FROM tsw_rotation_join_execution_attempts a WHERE slot_id=$1 AND stage=$2 AND event_kind='started'`, slot, stage).Scan(&startAfter); err != nil {
			t.Fatal(err)
		}
		if startBefore != startAfter {
			t.Fatal("finish rewrote original start")
		}
	}
	var paired int
	var requests, accepts int
	var requestMarker, acceptMarker bool
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM tsw_rotation_join_execution_attempts a JOIN tsw_rotation_join_execution_attempts f ON f.start_event_id=a.id WHERE a.slot_id=$1 AND a.attempt_no=f.attempt_no AND a.lease_epoch=f.lease_epoch AND a.started_at=f.started_at AND a.stage=f.stage AND f.finished_at>=a.started_at`, slot).Scan(&paired); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT request_attempt_count,accept_attempt_count,request_may_have_reached,accept_may_have_reached FROM tsw_rotation_join_executions WHERE slot_id=$1`, slot).Scan(&requests, &accepts, &requestMarker, &acceptMarker); err != nil {
		t.Fatal(err)
	}
	if paired != 2 || executionEvents(t, f, slot) != 4 || requests != 1 || accepts != 1 || !requestMarker || !acceptMarker || executionState(t, f, slot) != "reconcile_required" {
		t.Fatal("events/counts or conservative markers incorrect")
	}
	executionError(t, f.h.finishRotationJoinStage(ctx, l, "accept_join", "succeeded", true), joinExecutionStale)
	r := executionClaim(t, f, owner, slot, time.Minute)
	if !r.reconcileOnly {
		t.Fatal("accept success granted POST permission")
	}
	executionError(t, f.h.markRotationJoinStageStarted(ctx, r, "request_join"), joinExecutionTransition)
	executionError(t, f.h.markRotationJoinStageStarted(ctx, r, "accept_join"), joinExecutionTransition)
	if err := f.h.finishRotationJoinStage(ctx, r, "reconcile", "succeeded", false); err != nil {
		t.Fatal(err)
	}
	if executionState(t, f, slot) != "reconcile_required" || executionEvents(t, f, slot) != 6 || before != executionSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("success became completed/membership/credentials or external/source effects")
	}
}

func TestRotationJoinExecutionExpiryAndCrashRecovery(t *testing.T) {
	for _, stage := range []string{"none", "request_join", "request_succeeded", "accept_join"} {
		t.Run(stage, func(t *testing.T) {
			f, owner, slot := legacyExecutionSchema32Fixture(t)
			ctx := context.Background()
			before := executionSources(t, f)
			l := executionClaim(t, f, owner, slot, 300*time.Millisecond)
			if stage != "none" {
				if err := f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "request_succeeded" || stage == "accept_join" {
				if err := f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "accept_join" {
				if err := f.h.markRotationJoinStageStarted(ctx, l, "accept_join"); err != nil {
					t.Fatal(err)
				}
			}
			eventsBefore := executionEvents(t, f, slot)
			executionExpire(t, f, l)
			executionError(t, f.h.markRotationJoinStageStarted(ctx, l, "request_join"), joinExecutionStale)
			executionError(t, f.h.finishRotationJoinStage(ctx, l, "request_join", "uncertain", true), joinExecutionStale)
			r := executionClaim(t, f, owner, slot, time.Minute)
			if r.epoch != 2 || r.token == l.token || r.reconcileOnly != (stage != "none") {
				t.Fatalf("unsafe recovery %+v", r)
			}
			executionError(t, f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true), joinExecutionStale)
			if stage == "none" {
				if err := f.h.markRotationJoinStageStarted(ctx, r, "request_join"); err != nil {
					t.Fatal(err)
				}
			} else {
				executionError(t, f.h.markRotationJoinStageStarted(ctx, r, "request_join"), joinExecutionTransition)
				executionError(t, f.h.markRotationJoinStageStarted(ctx, r, "accept_join"), joinExecutionTransition)
				if executionState(t, f, slot) != "reconcile_required" {
					t.Fatal("expired marker not reconciled")
				}
			}
			if executionEvents(t, f, slot) != eventsBefore+1 || before != executionSources(t, f) {
				t.Fatal("reclaim fabricated receipt or changed original/source facts")
			}
		})
	}
}

func TestRotationJoinExecutionFailureAndUncertainty(t *testing.T) {
	for _, stage := range []string{"request_join", "accept_join"} {
		for _, outcome := range []string{"failed", "uncertain"} {
			for _, reached := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/reached=%v", stage, outcome, reached), func(t *testing.T) {
					f, owner, slot := legacyExecutionSchema32Fixture(t)
					ctx := context.Background()
					before := executionSources(t, f)
					l := executionClaim(t, f, owner, slot, time.Minute)
					if err := f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err != nil {
						t.Fatal(err)
					}
					if stage == "accept_join" {
						if err := f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true); err != nil {
							t.Fatal(err)
						}
						if err := f.h.markRotationJoinStageStarted(ctx, l, stage); err != nil {
							t.Fatal(err)
						}
					}
					if err := f.h.finishRotationJoinStage(ctx, l, stage, outcome, reached); err != nil {
						t.Fatal(err)
					}
					var recorded string
					var marker, terminalReached bool
					if err := f.pool.QueryRow(ctx, `SELECT a.outcome,a.may_have_reached,e.request_may_have_reached FROM tsw_rotation_join_execution_attempts a JOIN tsw_rotation_join_executions e USING(slot_id) WHERE a.slot_id=$1 AND a.stage=$2 AND a.event_kind='finished'`, slot, stage).Scan(&recorded, &terminalReached, &marker); err != nil {
						t.Fatal(err)
					}
					if recorded != outcome || terminalReached != reached || !marker || executionState(t, f, slot) != "reconcile_required" || before != executionSources(t, f) {
						t.Fatal("failure erased durable uncertainty or source")
					}
					if !executionClaim(t, f, owner, slot, time.Minute).reconcileOnly {
						t.Fatal("failure replayed POST")
					}
				})
			}
		}
	}
}

func TestRotationJoinExecutionInjectedFailuresRollback(t *testing.T) {
	f, owner, slot := legacyExecutionSchema32Fixture(t)
	ctx := context.Background()
	before := executionSources(t, f)
	f.exec(t, `CREATE FUNCTION join_execution_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected execution insert failure'; END; $$; CREATE TRIGGER join_execution_test_fail AFTER INSERT ON tsw_rotation_join_executions FOR EACH ROW EXECUTE FUNCTION join_execution_test_fail()`)
	if _, err := f.h.claimRotationJoinExecution(ctx, owner, f.preview.Id, slot, uuid.New(), time.Minute); err == nil {
		t.Fatal("injected claim succeeded")
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM tsw_rotation_join_executions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("half claim count=%d err=%v", count, err)
	}
	f.exec(t, `DROP TRIGGER join_execution_test_fail ON tsw_rotation_join_executions; DROP FUNCTION join_execution_test_fail()`)
	l := executionClaim(t, f, owner, slot, time.Minute)
	f.exec(t, `CREATE FUNCTION join_execution_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected event failure'; END; $$; CREATE TRIGGER join_execution_test_fail AFTER INSERT ON tsw_rotation_join_execution_attempts FOR EACH ROW EXECUTE FUNCTION join_execution_test_fail()`)
	if err := f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err == nil {
		t.Fatal("injected start succeeded")
	}
	if executionState(t, f, slot) != "ready" || executionEvents(t, f, slot) != 0 {
		t.Fatal("half stage marker committed")
	}
	f.exec(t, `DROP TRIGGER join_execution_test_fail ON tsw_rotation_join_execution_attempts`)
	if err := f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `CREATE TRIGGER join_execution_test_fail AFTER INSERT ON tsw_rotation_join_execution_attempts FOR EACH ROW EXECUTE FUNCTION join_execution_test_fail()`)
	if err := f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true); err == nil {
		t.Fatal("injected terminal succeeded")
	}
	if executionState(t, f, slot) != "request_started" || executionEvents(t, f, slot) != 1 {
		t.Fatal("failed receipt lost durable start")
	}
	f.exec(t, `DROP TRIGGER join_execution_test_fail ON tsw_rotation_join_execution_attempts; DROP FUNCTION join_execution_test_fail()`)
	if err := f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true); err != nil {
		t.Fatal(err)
	}
	if before != executionSources(t, f) {
		t.Fatal("rollback changed sources")
	}
}

func TestRotationJoinExecutionCurrentOwnerAndImmutableRecovery(t *testing.T) {
	f, owner, slot := legacyExecutionSchema32Fixture(t)
	ctx := context.Background()
	original, err := f.h.loadRotationJoinIntent(ctx, owner, f.preview.Id, slot)
	if err != nil {
		t.Fatal(err)
	}
	// Change the released proof while its source authority is still legal; then
	// invalidate that authority without ever rebasing the frozen intent.
	staleProof := uuid.New()
	f.exec(t, `INSERT INTO tsw_rotation_removal_evidence(id,slot_id,lease_epoch,authorization_digest,token_exchange_id,owner_evidence_id,observed_at,members,target_absent,complete) SELECT $1,slot_id,lease_epoch,authorization_digest,token_exchange_id,owner_evidence_id,clock_timestamp()-interval '31 seconds',members,target_absent,complete FROM tsw_rotation_removal_evidence WHERE id=$2`, staleProof, original.releasedVerificationID)
	f.exec(t, `UPDATE tsw_rotation_removal_slots SET verification_id=$2 WHERE id=$1`, slot, staleProof)
	current := ownerContext{OwnerID: f.owner, SessionID: uuid.NewString()}
	f.exec(t, `INSERT INTO tsw_owner_sessions(id,owner_id,token_hash,auth_version,idle_expires_at,absolute_expires_at) SELECT $1,owner_id,decode(repeat('e8',32),'hex'),auth_version,now()+interval '1 hour',now()+interval '2 hours' FROM tsw_owner_sessions WHERE id=$2`, current.SessionID, owner.SessionID)
	f.exec(t, `UPDATE tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE id=$1`, owner.SessionID)
	if _, err = f.h.claimRotationJoinExecution(ctx, owner, f.preview.Id, slot, uuid.New(), time.Minute); err == nil {
		t.Fatal("revoked session claimed")
	}
	for _, bad := range []struct {
		o    ownerContext
		p, s uuid.UUID
	}{{current, uuid.New(), slot}, {current, f.preview.Id, uuid.New()}, {ownerContext{OwnerID: uuid.NewString(), SessionID: current.SessionID}, f.preview.Id, slot}} {
		if _, err = f.h.claimRotationJoinExecution(ctx, bad.o, bad.p, bad.s, uuid.New(), time.Minute); err == nil {
			t.Fatal("wrong scope claimed")
		}
	}
	l := executionClaim(t, f, current, slot, 250*time.Millisecond)
	if err = f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err != nil {
		t.Fatal(err)
	}
	executionExpire(t, f, l)
	// Drift must not rewrite the original binding or require selecting a new account.
	f.exec(t, `UPDATE tsw_target_accounts SET status='disabled',version=version+1 WHERE id=$1`, original.candidateAccountID)
	f.exec(t, `UPDATE tsw_expiry_rotation_previews SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1`, f.preview.Id, f.owner)
	f.exec(t, `UPDATE tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
	before := executionSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	r := executionClaim(t, f, current, slot, time.Minute)
	v, err := f.h.loadRotationJoinIntent(ctx, current, f.preview.Id, slot)
	if err != nil || !reflect.DeepEqual(v, original) || !r.reconcileOnly || before != executionSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("source drift lost/remapped intent or execution, or called HTTP")
	}
	f.exec(t, `UPDATE tsw_owner_sessions SET last_seen_at=created_at,idle_expires_at=created_at+interval '1 microsecond' WHERE id=$1`, current.SessionID)
	if _, err = f.h.claimRotationJoinExecution(ctx, current, f.preview.Id, slot, uuid.New(), time.Minute); err == nil {
		t.Fatal("expired session claimed")
	}
	if err = f.h.finishRotationJoinStage(ctx, r, "reconcile", "uncertain", false); err == nil {
		t.Fatal("expired session wrote journal")
	}
}

const executionColumns = `slot_id,preview_id,workspace_id,owner_id,candidate_account_id,original_platform_member_id,candidate_identifier,seat_type,authorization_digest,authorized_session,epoch_versions,created_at`

func TestRotationJoinExecutionDirectSQLCannotUnlockAccept(t *testing.T) {
	f, owner, slot := executionFixture(t)
	ctx := context.Background()
	l := executionClaim(t, f, owner, slot, time.Minute)
	before := executionSources(t, f)
	_, err := f.pool.Exec(ctx, `UPDATE tsw_rotation_join_executions SET state='request_succeeded',request_attempt_count=1,request_may_have_reached=true WHERE slot_id=$1`, slot)
	if err == nil {
		acceptErr := f.h.markRotationJoinStageStarted(ctx, l, "accept_join")
		var requests int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM tsw_rotation_join_execution_attempts WHERE slot_id=$1 AND stage='request_join'`, slot).Scan(&requests); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("direct SQL forged request success: accept error=%v, request events=%d", acceptErr, requests)
	}
	executionError(t, f.h.markRotationJoinStageStarted(ctx, l, "accept_join"), joinExecutionTransition)
	if executionState(t, f, slot) != "ready" || executionEvents(t, f, slot) != 0 || before != executionSources(t, f) {
		t.Fatal("rejected forgery changed execution, journal or sources")
	}
}

func TestRotationJoinExecutionDirectSQLTransitions(t *testing.T) {
	f, owner, slot := legacyExecutionSchema32Fixture(t)
	ctx := context.Background()
	before := executionSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	l := executionClaim(t, f, owner, slot, time.Minute)
	checkRejected := func(name, assignments string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			var beforeRow, afterRow string
			query := `SELECT to_jsonb(e)::text FROM tsw_rotation_join_executions e WHERE slot_id=$1`
			if err := f.pool.QueryRow(ctx, query, slot).Scan(&beforeRow); err != nil {
				t.Fatal(err)
			}
			events := executionEvents(t, f, slot)
			if _, err := f.pool.Exec(ctx, `UPDATE tsw_rotation_join_executions SET `+assignments+` WHERE slot_id=$1`, slot); err == nil {
				t.Fatal("forged execution transition accepted")
			}
			if err := f.pool.QueryRow(ctx, query, slot).Scan(&afterRow); err != nil {
				t.Fatal(err)
			}
			if beforeRow != afterRow || events != executionEvents(t, f, slot) {
				t.Fatal("rejected transition changed row or events")
			}
		})
	}
	for _, tc := range []struct{ name, assignments string }{
		{"ready/request_success", `state='request_succeeded',request_attempt_count=1,request_may_have_reached=true,last_stage='request_join',last_outcome='succeeded'`},
		{"ready/request_start_without_event", `state='request_started',request_attempt_count=1,request_may_have_reached=true,last_stage='request_join',last_outcome='started'`},
		{"ready/accept_start", `state='accept_started',request_attempt_count=1,accept_attempt_count=1,request_may_have_reached=true,accept_may_have_reached=true,last_stage='accept_join',last_outcome='started'`},
		{"ready/reconcile", `state='reconcile_required',last_stage='reconcile',last_outcome='started'`},
		{"ready/blocked", `state='blocked'`},
		{"ready/count_without_marker", `request_attempt_count=1`},
		{"ready/marker_without_count", `request_may_have_reached=true`},
		{"ready/count_and_marker_without_start", `request_attempt_count=1,request_may_have_reached=true`},
		{"ready/skipped_attempt", `state='request_started',request_attempt_count=2,request_may_have_reached=true,last_stage='request_join',last_outcome='started'`},
		{"ready/outcome_without_event", `last_stage='request_join',last_outcome='succeeded'`},
		{"ready/replace_live_lease", `lease_epoch=lease_epoch+1,lease_owner=gen_random_uuid(),lease_token=gen_random_uuid()`},
		{"ready/extend_deadline", `lease_expires_at=lease_expires_at+interval '1 hour'`},
		{"ready/release_lease", `lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL`},
	} {
		checkRejected(tc.name, tc.assignments)
	}
	// The event may follow its marker only within the same transaction. Both
	// commit and explicit immediate checking must reject an unpaired marker.
	for _, immediate := range []bool{false, true} {
		t.Run(fmt.Sprint("unpaired_transaction/immediate=", immediate), func(t *testing.T) {
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, `UPDATE tsw_rotation_join_executions SET state='request_started',request_attempt_count=1,request_may_have_reached=true,last_stage='request_join',last_outcome='started' WHERE slot_id=$1`, slot); err != nil {
				t.Fatalf("legal marker before event rejected too early: %v", err)
			}
			if immediate {
				_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
			} else {
				err = tx.Commit(ctx)
			}
			if err == nil {
				t.Fatal("unpaired marker passed transaction constraint")
			}
		})
	}
	if executionState(t, f, slot) != "ready" || executionEvents(t, f, slot) != 0 {
		t.Fatal("unpaired transaction left marker or event")
	}
	if err := f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, assignments string }{
		{"request_started/success_without_terminal", `state='request_succeeded',last_outcome='succeeded'`},
		{"request_started/reconcile_without_terminal", `state='reconcile_required',last_outcome='uncertain',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL`},
		{"request_started/accept_start", `state='accept_started',accept_attempt_count=1,accept_may_have_reached=true,last_stage='accept_join'`},
		{"request_started/reset_ready", `state='ready'`},
	} {
		checkRejected(tc.name, tc.assignments)
	}
	if err := f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true); err != nil {
		t.Fatal(err)
	}
	checkRejected("request_succeeded/accept_without_event", `state='accept_started',accept_attempt_count=1,accept_may_have_reached=true,last_stage='accept_join',last_outcome='started'`)
	checkRejected("request_succeeded/reconcile_without_terminal", `state='reconcile_required',last_stage='reconcile',last_outcome='started'`)
	if err := f.h.markRotationJoinStageStarted(ctx, l, "accept_join"); err != nil {
		t.Fatal(err)
	}
	checkRejected("accept_started/reuse_request_success", `state='request_succeeded',last_stage='request_join',last_outcome='succeeded'`)
	if err := f.h.finishRotationJoinStage(ctx, l, "accept_join", "succeeded", true); err != nil {
		t.Fatal(err)
	}
	checkRejected("reconcile_required/reuse_success_to_accept", `state='accept_started',last_stage='accept_join',last_outcome='started'`)
	checkRejected("reconcile_required/claim_without_start", `lease_epoch=lease_epoch+1,lease_owner=gen_random_uuid(),lease_token=gen_random_uuid(),lease_expires_at=clock_timestamp()+interval '1 minute',last_stage='reconcile',last_outcome='started'`)
	r := executionClaim(t, f, owner, slot, time.Minute)
	checkRejected("reconcile_started/finish_without_terminal", `last_outcome='succeeded',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL`)
	if err := f.h.finishRotationJoinStage(ctx, r, "reconcile", "succeeded", false); err != nil {
		t.Fatal(err)
	}
	if executionEvents(t, f, slot) != 6 || before != executionSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("transition guards changed journal pairing or produced external/source effects")
	}
}

func TestRotationJoinExecutionDirectSQLGuards(t *testing.T) {
	f, owner, slot := legacyExecutionSchema32Fixture(t)
	ctx := context.Background()
	columns := strings.Split(executionColumns, ",")
	for i, column := range columns {
		t.Run("insert/"+column, func(t *testing.T) {
			values := append([]string(nil), columns...)
			switch column {
			case "original_platform_member_id", "candidate_identifier", "seat_type", "authorization_digest":
				values[i] = "'forged'"
			case "epoch_versions":
				values[i] = "'{}'::jsonb"
			case "created_at":
				values[i] = "created_at-interval '1 second'"
			default:
				values[i] = "gen_random_uuid()"
			}
			if _, err := f.pool.Exec(ctx, `INSERT INTO tsw_rotation_join_executions(`+executionColumns+`) SELECT `+strings.Join(values, ",")+` FROM tsw_rotation_candidate_join_intents WHERE slot_id=$1`, slot); err == nil {
				t.Fatal("forged binding insert accepted")
			}
		})
	}
	l := executionClaim(t, f, owner, slot, time.Minute)
	for _, column := range columns {
		value := "gen_random_uuid()"
		switch column {
		case "original_platform_member_id", "candidate_identifier", "seat_type", "authorization_digest":
			value = "'forged'"
		case "epoch_versions":
			value = "'{}'::jsonb"
		case "created_at":
			value = "created_at-interval '1 second'"
		}
		if _, err := f.pool.Exec(ctx, `UPDATE tsw_rotation_join_executions SET `+column+`=`+value+` WHERE slot_id=$1`, slot); err == nil {
			t.Fatalf("binding %s mutated", column)
		}
	}
	for _, q := range []string{`DELETE FROM tsw_rotation_join_executions WHERE slot_id=$1`, `UPDATE tsw_rotation_join_executions SET state='completed' WHERE slot_id=$1`, `UPDATE tsw_rotation_join_executions SET lease_token=NULL WHERE slot_id=$1`} {
		if _, err := f.pool.Exec(ctx, q, slot); err == nil {
			t.Fatal("invalid execution update/delete accepted")
		}
	}
	if err := f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE tsw_rotation_join_execution_attempts SET outcome=outcome WHERE slot_id=$1`, `DELETE FROM tsw_rotation_join_execution_attempts WHERE slot_id=$1`, `UPDATE tsw_rotation_join_executions SET request_may_have_reached=false WHERE slot_id=$1`, `UPDATE tsw_rotation_join_executions SET lease_epoch=0 WHERE slot_id=$1`, `UPDATE tsw_rotation_join_executions SET request_attempt_count=0 WHERE slot_id=$1`} {
		if _, err := f.pool.Exec(ctx, q, slot); err == nil {
			t.Fatal("immutable event/marker changed")
		}
	}
	terminalColumns := `slot_id,lease_epoch,stage,attempt_no,event_kind,start_event_id,may_have_reached,outcome,started_at,finished_at`
	expressions := []string{"slot_id", "lease_epoch", "stage", "attempt_no", "'finished'", "id", "true", "'succeeded'", "started_at", "clock_timestamp()"}
	for _, tc := range []struct {
		name  string
		index int
		value string
	}{{"orphan", 5, "gen_random_uuid()"}, {"epoch", 1, "lease_epoch+1"}, {"stage", 2, "'accept_join'"}, {"attempt", 3, "attempt_no+1"}, {"time", 8, "started_at-interval '1 second'"}, {"finish_time", 9, "started_at-interval '1 second'"}, {"outcome", 7, "'secret upstream text'"}} {
		t.Run("terminal/"+tc.name, func(t *testing.T) {
			values := append([]string(nil), expressions...)
			values[tc.index] = tc.value
			if _, err := f.pool.Exec(ctx, `INSERT INTO tsw_rotation_join_execution_attempts(`+terminalColumns+`) SELECT `+strings.Join(values, ",")+` FROM tsw_rotation_join_execution_attempts WHERE slot_id=$1 AND event_kind='started'`, slot); err == nil {
				t.Fatal("bad terminal event accepted")
			}
		})
	}
	if err := f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO tsw_rotation_join_execution_attempts(`+terminalColumns+`) SELECT `+strings.Join(expressions, ",")+` FROM tsw_rotation_join_execution_attempts WHERE slot_id=$1 AND event_kind='started'`, slot); err == nil {
		t.Fatal("duplicate terminal event accepted")
	}
	var publicPrivilege bool
	if err := f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE c.oid IN ('tsw_rotation_join_executions'::regclass,'tsw_rotation_join_execution_attempts'::regclass) AND a.grantee=0)`).Scan(&publicPrivilege); err != nil || publicPrivilege {
		t.Fatalf("public privilege=%v err=%v", publicPrivilege, err)
	}
}

// Pause the real CAS write without production hooks. DB time, not transaction
// now() or an unreclaimed token, must fence a worker crossing its deadline.
type executionWriteBarrier struct {
	reached, release chan struct{}
	once             sync.Once
}

func (b *executionWriteBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "UPDATE public.tsw_rotation_join_executions SET state=") {
		b.once.Do(func() { close(b.reached) })
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*executionWriteBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestRotationJoinExecutionFinalWriteClock(t *testing.T) {
	for _, finish := range []bool{false, true} {
		t.Run(fmt.Sprint("finish=", finish), func(t *testing.T) {
			f, owner, slot := legacyExecutionSchema32Fixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			l := executionClaim(t, f, owner, slot, 400*time.Millisecond)
			if finish {
				if err := f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err != nil {
					t.Fatal(err)
				}
			}
			before := executionEvents(t, f, slot)
			barrier := &executionWriteBarrier{reached: make(chan struct{}), release: make(chan struct{})}
			config, err := pgxpool.ParseConfig(os.Getenv("TSW_TEST_DATABASE_URL"))
			if err != nil {
				t.Fatal(err)
			}
			config.ConnConfig.Tracer = barrier
			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); pool.Close() }()
			f.h.pool = pool
			result := make(chan error, 1)
			go func() {
				if finish {
					result <- f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true)
				} else {
					result <- f.h.markRotationJoinStageStarted(ctx, l, "request_join")
				}
			}()
			select {
			case <-barrier.reached:
			case err := <-result:
				t.Fatalf("did not reach final write: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			executionExpire(t, f, l)
			close(barrier.release)
			executionError(t, <-result, joinExecutionStale)
			want := "ready"
			if finish {
				want = "request_started"
			}
			if executionEvents(t, f, slot) != before || executionState(t, f, slot) != want {
				t.Fatal("clock crossing left half marker/receipt")
			}
			r := executionClaim(t, f, owner, slot, time.Minute)
			if r.reconcileOnly != finish {
				t.Fatal("clock rollback lost prior obligation")
			}
		})
	}
}

func TestRotationJoinExecutionMigrationDownUp(t *testing.T) {
	f, owner, slot, _ := membershipDispatched(t)
	ctx := context.Background()
	before := executionMigrationSources(t, f)
	db, err := sql.Open("pgx", os.Getenv("TSW_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("../migrations/sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.DownTo(ctx, 30); err != nil {
		t.Fatal(err)
	}
	version, err := provider.GetDBVersion(ctx)
	if err != nil || version != 30 {
		t.Fatalf("down version=%d err=%v", version, err)
	}
	var absent bool
	if err = f.pool.QueryRow(ctx, `SELECT to_regclass('public.tsw_rotation_join_executions') IS NULL AND to_regclass('public.tsw_rotation_join_execution_attempts') IS NULL AND to_regprocedure('public.tsw_rotation_join_execution_guard()') IS NULL AND to_regprocedure('public.tsw_rotation_join_attempt_guard()') IS NULL AND to_regprocedure('public.tsw_rotation_join_execution_start_guard()') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatalf("own down cleanup absent=%v err=%v", absent, err)
	}
	if before != executionMigrationSources(t, f) {
		t.Fatal("migration down changed previous sources or intent")
	}
	for i := 0; i < 2; i++ {
		if err = migrations.Apply(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	version, err = provider.GetDBVersion(ctx)
	if err != nil || version != migrations.RequiredVersion {
		t.Fatalf("up version=%d required=%d err=%v", version, migrations.RequiredVersion, err)
	}
	if before != executionMigrationSources(t, f) {
		t.Fatal("migration up changed previous sources or intent")
	}
	if executionClaim(t, f, owner, slot, time.Minute).epoch != 1 {
		t.Fatal("reapplied schema did not accept original binding")
	}
}
