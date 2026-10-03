//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRotationJoinIntentSchema(t *testing.T) {
	f := newJoinFixture(t, 1)
	var exists bool
	if err := f.pool.QueryRow(context.Background(), `SELECT to_regclass('public.tsw_rotation_candidate_join_intents') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("immutable original-slot intent table missing")
	}
}

func joinOwner(t *testing.T, f *removalFixture) ownerContext {
	t.Helper()
	var id string
	if err := f.pool.QueryRow(context.Background(), `SELECT authorized_session FROM tsw_expiry_rotation_previews WHERE id=$1`, f.preview.Id).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return ownerContext{OwnerID: f.owner, SessionID: id}
}

func joinReleased(t *testing.T, f *removalFixture) uuid.UUID {
	t.Helper()
	p := f.start(t)
	f.action(t, p.Slots[0].Id, "run")
	return p.Slots[0].Id
}

// Snapshot every source/output table except this new derived output. This also
// detects fabricated usage, token/protection writes and accidental epoch updates.
func joinSources(t *testing.T, f *removalFixture) string {
	t.Helper()
	ctx := context.Background()
	rows, err := f.pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'tsw_%' AND tablename<>'tsw_rotation_candidate_join_intents' ORDER BY tablename`)
	if err != nil {
		t.Fatal(err)
	}
	tables := []string{}
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

func joinReject(t *testing.T, f *removalFixture, owner ownerContext, preview, slot uuid.UUID) {
	t.Helper()
	before := joinSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	if _, err := f.h.reserveRotationJoinIntent(context.Background(), owner, preview, slot); err == nil {
		t.Fatal("unsafe reservation accepted")
	}
	var count int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_rotation_candidate_join_intents`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 || before != joinSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("rejection wrote facts/intent or made HTTP")
	}
}

func TestRotationJoinIntentOriginalConcurrentRecovery(t *testing.T) {
	f := newJoinFixture(t, 1)
	slot := joinReleased(t, f)
	owner := joinOwner(t, f)
	before := joinSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	ctx := context.Background()
	const n = 8
	results := make(chan rotationJoinIntent, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := f.h.reserveRotationJoinIntent(ctx, owner, f.preview.Id, slot)
			results <- v
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first rotationJoinIntent
	for v := range results {
		if first.slotID == uuid.Nil {
			first = v
		}
		if !reflect.DeepEqual(first, v) {
			t.Fatal("concurrent reservation remapped original")
		}
	}
	a, err := loadRemovalAuthorization(ctx, f.pool, uuid.MustParse(f.owner), f.preview.Id)
	if err != nil {
		t.Fatal(err)
	}
	c := f.preview.Candidates[0]
	if first.slotID != slot || first.previewID != f.preview.Id || first.workspaceID != f.space || first.ownerID.String() != f.owner || first.candidateAccountID != c.AccountId || first.candidateIdentifier != c.Identifier || first.originalPlatformMemberID != a.assignments[0].PlatformMemberId || first.seatType != "prolite" || first.authorizationDigest != a.digest || first.authorizedSession != a.session || !reflect.DeepEqual(first.epochs, a.epochs) {
		t.Fatalf("not original intent: %+v", first)
	}
	var count int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM tsw_rotation_candidate_join_intents`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if before != joinSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("reservation wrote source facts or called HTTP")
	}
	// Proof expiry also preserves the exact original record without renewal.
	stale := uuid.New()
	f.exec(t, `INSERT INTO tsw_rotation_removal_evidence(id,slot_id,lease_epoch,authorization_digest,token_exchange_id,owner_evidence_id,observed_at,members,target_absent,complete) SELECT $1,slot_id,lease_epoch,authorization_digest,token_exchange_id,owner_evidence_id,clock_timestamp()-interval '31 seconds',members,target_absent,complete FROM tsw_rotation_removal_evidence WHERE id=$2`, stale, first.releasedVerificationID)
	f.exec(t, `UPDATE tsw_rotation_removal_slots SET verification_id=$2 WHERE id=$1`, slot, stale)
	before = joinSources(t, f)
	v, e := f.h.reserveRotationJoinIntent(ctx, owner, f.preview.Id, slot)
	if e != nil || !reflect.DeepEqual(first, v) || before != joinSources(t, f) {
		t.Fatal("stale proof remapped or refreshed original intent")
	}
	// Both authorization and local source drift must preserve observation only.
	f.exec(t, `UPDATE tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
	f.exec(t, `UPDATE tsw_target_accounts SET status='disabled',version=version+1 WHERE id=$1`, c.AccountId)
	rotationResult(t, rotationRequest(f.h, f.session, f.csrf, "POST", "/api/owner/v1/expiry-rotation/previews/"+f.preview.Id.String()+"/revoke", nil), 200)
	before = joinSources(t, f)
	for _, load := range []func(context.Context, ownerContext, uuid.UUID, uuid.UUID) (rotationJoinIntent, error){f.h.reserveRotationJoinIntent, f.h.loadRotationJoinIntent} {
		v, e := load(ctx, owner, f.preview.Id, slot)
		if e != nil || !reflect.DeepEqual(first, v) {
			t.Fatalf("recovery lost original: %+v %v", v, e)
		}
	}
	if before != joinSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("recovery refreshed authority or proof")
	}
	for _, bad := range []struct {
		o    ownerContext
		p, s uuid.UUID
	}{{owner, uuid.New(), slot}, {owner, f.preview.Id, uuid.New()}, {ownerContext{OwnerID: uuid.NewString(), SessionID: owner.SessionID}, f.preview.Id, slot}} {
		for _, load := range []func(context.Context, ownerContext, uuid.UUID, uuid.UUID) (rotationJoinIntent, error){f.h.reserveRotationJoinIntent, f.h.loadRotationJoinIntent} {
			if _, e := load(ctx, bad.o, bad.p, bad.s); e == nil {
				t.Fatal("wrong scope revealed intent")
			}
		}
	}
	f.exec(t, `UPDATE tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE id=$1`, owner.SessionID)
	if _, err = f.h.loadRotationJoinIntent(ctx, owner, f.preview.Id, slot); err == nil {
		t.Fatal("revoked current session read intent")
	}
	if _, err = f.h.reserveRotationJoinIntent(ctx, owner, f.preview.Id, slot); err == nil {
		t.Fatal("revoked current session replayed intent")
	}
}

func TestRotationJoinIntentRejectsUnsafeSources(t *testing.T) {
	cases := []struct {
		name     string
		released bool
		change   func(*testing.T, *removalFixture, uuid.UUID)
	}{
		{"no_proof", false, func(*testing.T, *removalFixture, uuid.UUID) {}},
		{"stale_proof", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			id := uuid.New()
			f.exec(t, `INSERT INTO tsw_rotation_removal_evidence(id,slot_id,lease_epoch,authorization_digest,token_exchange_id,owner_evidence_id,observed_at,members,target_absent,complete) SELECT $1,slot_id,lease_epoch,authorization_digest,token_exchange_id,owner_evidence_id,clock_timestamp()-interval '31 seconds',members,target_absent,complete FROM tsw_rotation_removal_evidence WHERE id=(SELECT verification_id FROM tsw_rotation_removal_slots WHERE id=$2)`, id, s)
			f.exec(t, `UPDATE tsw_rotation_removal_slots SET verification_id=$2 WHERE id=$1`, s, id)
		}},
		{"uncertain", false, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			f.http.remove = false
			f.http.fail = errors.New("timeout")
			f.action(t, s, "run")
		}},
		{"stopped", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			f.exec(t, `UPDATE tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
		}},
		{"revoked", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			rotationResult(t, rotationRequest(f.h, f.session, f.csrf, "POST", "/api/owner/v1/expiry-rotation/previews/"+f.preview.Id.String()+"/revoke", nil), 200)
		}},
		{"session_expired", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			f.exec(t, `UPDATE tsw_owner_sessions SET last_seen_at=created_at,idle_expires_at=created_at+interval '1 microsecond' WHERE owner_id=$1`, f.owner)
		}},
		{"session_revoked", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			f.exec(t, `UPDATE tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE owner_id=$1`, f.owner)
		}},
		{"identity_drift", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			f.exec(t, `UPDATE tsw_target_accounts SET identifier='changed@fixture.test',version=version+1 WHERE id=$1`, f.preview.Candidates[0].AccountId)
		}},
		{"material_drift", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			f.exec(t, `UPDATE tsw_target_credentials SET material_status='needs_totp',version=version+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId)
		}},
		{"protection", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			f.exec(t, `INSERT INTO tsw_rotation_global_protections(target_account_id,status,evidence_source,evidence_id,observed_at) VALUES($1,'delivered','fixture',repeat('c',64),now())`, f.preview.Candidates[0].AccountId)
		}},
		{"historical_usage_other_workspace", true, func(t *testing.T, f *removalFixture, s uuid.UUID) {
			w := uuid.New()
			f.exec(t, `INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES($1::uuid,$1::uuid::text,'other')`, w)
			f.exec(t, `INSERT INTO tsw_rotation_usage_ledger(target_account_id,workspace_id,usage_state,ever_used,evidence_source,evidence_id,observed_at,expires_at) VALUES($1,$2,'used',true,'fixture',repeat('d',64),now()-interval '1 day',now()-interval '1 day'+interval '1 minute')`, f.preview.Candidates[0].AccountId, w)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newJoinFixture(t, 1)
			owner := joinOwner(t, f)
			var slot uuid.UUID
			if tc.released {
				slot = joinReleased(t, f)
			} else {
				slot = f.start(t).Slots[0].Id
			}
			tc.change(t, f, slot)
			joinReject(t, f, owner, f.preview.Id, slot)
		})
	}
}

func TestRotationJoinIntentEveryFrozenEpoch(t *testing.T) {
	// Each fresh fixture gets one forward drift. Never restore or adopt a frozen epoch.
	f := newJoinFixture(t, 1)
	a, err := loadRemovalAuthorization(context.Background(), f.pool, uuid.MustParse(f.owner), f.preview.Id)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(a.epochs))
	for key := range a.epochs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			f := newJoinFixture(t, 1)
			slot := joinReleased(t, f)
			owner := joinOwner(t, f)
			kind := strings.Split(key, "/")[0]
			var scope string
			if kind == "target_account" {
				id := f.preview.Slots[0].AccountId
				if key == "target_account/"+a.preview.Candidates[0].AccountId.String() {
					id = f.preview.Candidates[0].AccountId
				}
				scope = kind + "/" + id.String()
			} else if err := f.pool.QueryRow(context.Background(), `SELECT key FROM jsonb_each_text((SELECT epoch_versions FROM tsw_expiry_rotation_previews WHERE id=$1)) WHERE key LIKE $2 ORDER BY key LIMIT 1`, f.preview.Id, kind+"/%").Scan(&scope); err != nil {
				t.Fatal(err)
			}
			f.exec(t, `UPDATE tsw_rotation_epochs SET version=version+1 WHERE kind||'/'||id::text=$1`, scope)
			joinReject(t, f, owner, f.preview.Id, slot)
		})
	}
}

func TestRotationJoinIntentMissingUsageDoesNotWriteZero(t *testing.T) {
	f := newJoinFixture(t, 1)
	oldPreview := f.preview
	var oldFrozen string
	if err := f.pool.QueryRow(context.Background(), `SELECT to_jsonb(p)::text FROM tsw_expiry_rotation_previews p WHERE id=$1`, oldPreview.Id).Scan(&oldFrozen); err != nil {
		t.Fatal(err)
	}
	c := oldPreview.Candidates[0].AccountId
	// Omission happens before originating the new immutable preview and confirmation.
	f.exec(t, `DELETE FROM tsw_rotation_usage_ledger WHERE target_account_id=$1`, c)
	path := "/api/owner/v1/expiry-rotation/previews"
	fresh := rotationResult(t, rotationRequest(f.h, f.session, f.csrf, "POST", path, nil), 200)
	if fresh.Status != "ready" || fresh.Source != "official_owner_ab" || fresh.Candidates[0].UsageState != "unobserved_prejoin" || fresh.Id == oldPreview.Id {
		t.Fatalf("new scoped absence preview not ready: %+v", fresh)
	}
	f.preview = rotationResult(t, rotationRequest(f.h, f.session, f.csrf, "POST", path+"/"+fresh.Id.String()+"/confirm", map[string]any{"confirmed": true, "digest": fresh.Digest, "idempotencyKey": uuid.New(), "assignments": oldPreview.Assignments}), 200)
	slot := joinReleased(t, f)
	owner := joinOwner(t, f)
	before := joinSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	if _, err := f.h.reserveRotationJoinIntent(context.Background(), owner, f.preview.Id, slot); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_rotation_usage_ledger WHERE target_account_id=$1`, c).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 || before != joinSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("missing usage fabricated zero/evidence, wrote source facts or called HTTP")
	}
	// The old authorization was never rewritten or rebased.
	old, err := loadRemovalAuthorization(context.Background(), f.pool, uuid.MustParse(f.owner), oldPreview.Id)
	if err != nil {
		t.Fatal(err)
	}
	var oldAfter string
	if err = f.pool.QueryRow(context.Background(), `SELECT to_jsonb(p)::text FROM tsw_expiry_rotation_previews p WHERE id=$1`, oldPreview.Id).Scan(&oldAfter); err != nil {
		t.Fatal(err)
	}
	if old.digest != *oldPreview.AuthorizationDigest || old.preview.Digest != oldPreview.Digest || oldAfter != oldFrozen {
		t.Fatal("old preview, authorization or frozen epochs changed")
	}
}

const joinDirectColumns = `slot_id,preview_id,workspace_id,owner_id,candidate_account_id,original_platform_member_id,candidate_identifier,seat_type,authorization_digest,authorized_session,epoch_versions,released_verification_id`

func TestRotationJoinIntentDirectScopeAndImmutability(t *testing.T) {
	f := newJoinFixture(t, 1)
	slot := joinReleased(t, f)
	expressions := []string{"s.id", "s.preview_id", "s.workspace_id", "p.owner_id", "s.candidate_account_id", "s.platform_member_id", "c->>'identifier'", "s.seat_type", "p.authorization_digest", "p.authorized_session::uuid", "p.epoch_versions", "s.verification_id"}
	for _, tc := range []struct {
		name  string
		index int
		value string
	}{
		{"slot", 0, "gen_random_uuid()"}, {"preview", 1, "gen_random_uuid()"}, {"workspace", 2, "gen_random_uuid()"}, {"owner", 3, "gen_random_uuid()"}, {"candidate", 4, "s.original_account_id"}, {"member", 5, "'forged'"}, {"identifier", 6, "'forged@test.invalid'"}, {"seat", 7, "'default'"}, {"digest", 8, "repeat('f',64)"}, {"session", 9, "gen_random_uuid()"}, {"epochs", 10, "'{}'::jsonb"}, {"proof", 11, "gen_random_uuid()"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := append([]string(nil), expressions...)
			values[tc.index] = tc.value
			if _, err := f.pool.Exec(context.Background(), `INSERT INTO tsw_rotation_candidate_join_intents(`+joinDirectColumns+`) SELECT `+strings.Join(values, ",")+` FROM tsw_rotation_removal_slots s JOIN tsw_expiry_rotation_previews p ON p.id=s.preview_id CROSS JOIN LATERAL jsonb_array_elements(p.facts->'candidates') c WHERE s.id=$1`, slot); err == nil {
				t.Fatal("forged direct insert accepted")
			}
		})
	}
	original, err := f.h.reserveRotationJoinIntent(context.Background(), joinOwner(t, f), f.preview.Id, slot)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE tsw_rotation_candidate_join_intents SET candidate_identifier='forged@test.invalid' WHERE slot_id=$1`, `UPDATE tsw_rotation_candidate_join_intents SET created_at=created_at WHERE slot_id=$1`, `DELETE FROM tsw_rotation_candidate_join_intents WHERE slot_id=$1`} {
		if _, err = f.pool.Exec(context.Background(), q, slot); err == nil {
			t.Fatal("immutable intent changed")
		}
	}
	v, err := f.h.loadRotationJoinIntent(context.Background(), joinOwner(t, f), f.preview.Id, slot)
	if err != nil || !reflect.DeepEqual(v, original) {
		t.Fatal("failed tampering lost original")
	}
	var publicPrivilege bool
	if err = f.pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE c.oid='tsw_rotation_candidate_join_intents'::regclass AND a.grantee=0)`).Scan(&publicPrivilege); err != nil || publicPrivilege {
		t.Fatalf("public privilege=%v err=%v", publicPrivilege, err)
	}
}

func TestRotationJoinIntentInsertFailureAtomicAndCancellation(t *testing.T) {
	f := newJoinFixture(t, 1)
	slot := joinReleased(t, f)
	owner := joinOwner(t, f)
	f.exec(t, `CREATE FUNCTION join_intent_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected intent insert failure'; END; $$; CREATE TRIGGER join_intent_test_fail AFTER INSERT ON tsw_rotation_candidate_join_intents FOR EACH ROW EXECUTE FUNCTION join_intent_test_fail()`)
	joinReject(t, f, owner, f.preview.Id, slot)
	f.exec(t, `DROP TRIGGER join_intent_test_fail ON tsw_rotation_candidate_join_intents; DROP FUNCTION join_intent_test_fail()`)
	conn, err := f.pool.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(context.Background(), `SELECT pg_advisory_lock(hashtextextended('tsw.rotation.workspace.'||$1::text,0))`, f.space.String()); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = f.h.reserveRotationJoinIntent(ctx, owner, f.preview.Id, slot)
	cancel()
	if _, unlockErr := conn.Exec(context.Background(), `SELECT pg_advisory_unlock_all()`); unlockErr != nil {
		t.Fatal(unlockErr)
	}
	conn.Release()
	if err == nil {
		t.Fatal("cancelled gate wait accepted")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = f.h.reserveRotationJoinIntent(ctx, owner, f.preview.Id, slot); err != nil {
		t.Fatalf("failure/cancellation leaked gate/transaction: %v", err)
	}
}

func TestRotationJoinIntentSingleConnectionConcurrent(t *testing.T) {
	f := newJoinFixture(t, 1)
	slot := joinReleased(t, f)
	owner := joinOwner(t, f)
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
	before := joinSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errs := make(chan error, 8)
	values := make(chan rotationJoinIntent, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := f.h.reserveRotationJoinIntent(ctx, owner, f.preview.Id, slot)
			errs <- e
			values <- v
		}()
	}
	wg.Wait()
	close(errs)
	close(values)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first rotationJoinIntent
	for v := range values {
		if first.slotID == uuid.Nil {
			first = v
		}
		if !reflect.DeepEqual(first, v) {
			t.Fatal("single pool conn remapped original")
		}
	}
	var count int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM tsw_rotation_candidate_join_intents`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d %v", count, err)
	}
	if before != joinSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("single conn wrote sources or called HTTP")
	}
}

func newJoinFixture(t *testing.T, n int, noFirstUse ...bool) *removalFixture {
	t.Helper()
	const privateURL = "postgres://postgres@127.0.0.1:55311/tsw_ticket11?sslmode=disable"
	if os.Getenv("TSW_TEST_DATABASE_URL") == "" {
		t.Skip("private TSW_TEST_DATABASE_URL required")
	}
	if os.Getenv("TSW_TEST_DATABASE_URL") != "postgres://postgres@127.0.0.1:55411/tsw_ticket16_worker?sslmode=disable" && os.Getenv("TSW_TEST_DATABASE_URL") != "postgres://postgres@127.0.0.1:55411/tsw_ticket15_worker?sslmode=disable" && os.Getenv("TSW_TEST_DATABASE_URL") != privateURL && os.Getenv("TSW_TEST_DATABASE_URL") != "postgres://postgres@127.0.0.1:55411/tsw_ticket13_worker?sslmode=disable" && os.Getenv("TSW_TEST_DATABASE_URL") != "postgres://postgres@127.0.0.1:55411/tsw_ticket14_worker?sslmode=disable" {
		t.Fatal("S1 tests require the designated disposable private PostgreSQL URL")
	}
	if len(noFirstUse) > 0 && noFirstUse[0] {
		return newRemovalFixtureWithUsage(t, n, true)
	}
	return newRemovalFixture(t, n)
}

func TestRotationJoinIntentOriginalSessionExpiryWithLegalCurrentSession(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint("existing=", existing), func(t *testing.T) {
			f := newJoinFixture(t, 1)
			slot := joinReleased(t, f)
			originalOwner := joinOwner(t, f)
			var original rotationJoinIntent
			var err error
			if existing {
				original, err = f.h.reserveRotationJoinIntent(context.Background(), originalOwner, f.preview.Id, slot)
				if err != nil {
					t.Fatal(err)
				}
			}
			current := ownerContext{OwnerID: f.owner, SessionID: uuid.NewString()}
			f.exec(t, `INSERT INTO tsw_owner_sessions(id,owner_id,token_hash,auth_version,idle_expires_at,absolute_expires_at) SELECT $1,owner_id,decode(repeat('e7',32),'hex'),auth_version,now()+interval '1 hour',now()+interval '2 hours' FROM tsw_owner_sessions WHERE id=$2`, current.SessionID, originalOwner.SessionID)
			f.exec(t, `UPDATE tsw_owner_sessions SET last_seen_at=created_at,idle_expires_at=created_at+interval '1 microsecond' WHERE id=$1`, originalOwner.SessionID)
			if !existing {
				joinReject(t, f, current, f.preview.Id, slot)
				return
			}
			before := joinSources(t, f)
			reads, calls := f.http.reads, f.http.calls
			v, err := f.h.reserveRotationJoinIntent(context.Background(), current, f.preview.Id, slot)
			if err != nil || !reflect.DeepEqual(original, v) || before != joinSources(t, f) || reads != f.http.reads || calls != f.http.calls {
				t.Fatal("legal current session could not observe expired original obligation, or replay had side effects")
			}
		})
	}
}

// Shorten only the NEW originating permission proof lifetime, preserving all
// actual AB identities/permission/invitation facts. No frozen record is edited.
type joinShortAuthority struct{ h *OwnerAuthHandler }

func (c joinShortAuthority) Evidence(ctx context.Context, owner uuid.UUID) (rotationEvidence, error) {
	e, err := (officialRotationCapability{handler: c.h}).Evidence(ctx, owner)
	if err == nil {
		e.Permission.ExpiresAt = time.Now().Add(2 * time.Second)
	}
	return e, err
}
func TestRotationJoinIntentAuthorizationExpiresWithoutRebase(t *testing.T) {
	f := newJoinFixture(t, 1)
	prior := f.preview
	f.h.rotationCapability = joinShortAuthority{h: f.h}
	path := "/api/owner/v1/expiry-rotation/previews"
	fresh := rotationResult(t, rotationRequest(f.h, f.session, f.csrf, "POST", path, nil), 200)
	if fresh.Status != "ready" {
		t.Fatalf("short originating preview not ready: %+v", fresh)
	}
	f.preview = rotationResult(t, rotationRequest(f.h, f.session, f.csrf, "POST", path+"/"+fresh.Id.String()+"/confirm", map[string]any{"confirmed": true, "digest": fresh.Digest, "idempotencyKey": uuid.New(), "assignments": prior.Assignments}), 200)
	slot := joinReleased(t, f)
	owner := joinOwner(t, f)
	time.Sleep(time.Until(f.preview.ExpiresAt) + 10*time.Millisecond)
	joinReject(t, f, owner, f.preview.Id, slot)
}

// Query tracing pauses at the real final write without a production test hook.
type joinWriteBarrier struct{ reached, release chan struct{} }

func (b *joinWriteBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "INSERT INTO public.tsw_rotation_candidate_join_intents(") {
		close(b.reached)
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*joinWriteBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func joinNewAuthorization(t *testing.T, f *removalFixture) {
	t.Helper()
	prior := f.preview
	path := "/api/owner/v1/expiry-rotation/previews"
	fresh := rotationResult(t, rotationRequest(f.h, f.session, f.csrf, "POST", path, nil), 200)
	if fresh.Status != "ready" {
		t.Fatalf("new originating preview not ready: %+v", fresh)
	}
	f.preview = rotationResult(t, rotationRequest(f.h, f.session, f.csrf, "POST", path+"/"+fresh.Id.String()+"/confirm", map[string]any{"confirmed": true, "digest": fresh.Digest, "idempotencyKey": uuid.New(), "assignments": prior.Assignments}), 200)
}

func TestRotationJoinIntentWriteTimeCredentialClocks(t *testing.T) {
	for _, clock := range []string{"personal_db", "personal_decoded_window", "workspace_db_window", "workspace_decoded_window"} {
		t.Run(clock, func(t *testing.T) {
			f := newJoinFixture(t, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			// All source setup precedes the NEW originating immutable authorization.
			deadline := time.Now().Add(4 * time.Second)
			switch clock {
			case "personal_db":
				f.exec(t, `UPDATE tsw_mother_personal_sessions SET expires_at=$2 WHERE mother_account_id=$1`, f.mother, deadline)
			case "personal_decoded_window":
				var kv int16
				var nonce, sealed []byte
				var revision int64
				if err := f.pool.QueryRow(ctx, `SELECT secret_revision,key_version,nonce,sealed_session FROM tsw_mother_personal_sessions WHERE mother_account_id=$1`, f.mother).Scan(&revision, &kv, &nonce, &sealed); err != nil {
					t.Fatal(err)
				}
				personal, err := openPersonalSession(f.h.keyRing, f.mother, revision, uint16(kv), nonce, sealed)
				if err != nil {
					t.Fatal(err)
				}
				personal.ExpiresAt = deadline.Add(time.Minute)
				v, n, c, err := sealPersonalSession(f.h.keyRing, f.mother, revision, personal)
				if err != nil {
					t.Fatal(err)
				}
				f.exec(t, `UPDATE tsw_mother_personal_sessions SET key_version=$2,nonce=$3,sealed_session=$4 WHERE mother_account_id=$1`, f.mother, int16(v), n, c)
			default:
				var b workspaceAccessBinding
				b.motherID = f.mother
				b.workspaceID = f.space
				var kv int16
				var nonce, sealed []byte
				if err := f.pool.QueryRow(ctx, `SELECT discovery_run_id,session_generation,secret_revision,attempt,exchange_id,key_version,nonce,sealed_access FROM tsw_selected_workspace_tokens WHERE mother_account_id=$1 AND workspace_id=$2`, f.mother, f.space).Scan(&b.run, &b.generation, &b.revision, &b.attempt, &b.exchangeID, &kv, &nonce, &sealed); err != nil {
					t.Fatal(err)
				}
				access, err := openWorkspaceAccess(f.h.keyRing, b, uint16(kv), nonce, sealed)
				if err != nil {
					t.Fatal(err)
				}
				access.ExpiresAt = deadline.Add(30 * time.Second)
				v, n, c, err := sealWorkspaceAccess(f.h.keyRing, b, access)
				if err != nil {
					t.Fatal(err)
				}
				dbExpiry := access.ExpiresAt.Add(time.Hour)
				if clock == "workspace_db_window" {
					dbExpiry = access.ExpiresAt
				}
				f.exec(t, `UPDATE tsw_selected_workspace_tokens SET key_version=$3,nonce=$4,sealed_access=$5,expires_at=$6 WHERE mother_account_id=$1 AND workspace_id=$2`, f.mother, f.space, int16(v), n, c, dbExpiry)
			}
			joinNewAuthorization(t, f)
			slot := joinReleased(t, f)
			owner := joinOwner(t, f)
			before := joinSources(t, f)
			reads, calls := f.http.reads, f.http.calls
			barrier := &joinWriteBarrier{reached: make(chan struct{}), release: make(chan struct{})}
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
			go func() { _, err := f.h.reserveRotationJoinIntent(ctx, owner, f.preview.Id, slot); result <- err }()
			select {
			case <-barrier.reached:
			case err := <-result:
				t.Fatalf("did not reach final write: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// Wait against the real DB clock, not transaction now() or a falsified source.
			_, err = f.pool.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.02)`, deadline)
			close(barrier.release)
			if err != nil {
				t.Fatal(err)
			}
			if err = <-result; err == nil {
				t.Fatal("credential clock crossed at final write but reservation accepted")
			}
			var count int
			if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM tsw_rotation_candidate_join_intents`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 || before != joinSources(t, f) || reads != f.http.reads || calls != f.http.calls {
				t.Fatal("clock rejection wrote intent/source facts or made HTTP")
			}
		})
	}
}

func TestRotationJoinIntentRecoveryAfterMotherCredentialExpiry(t *testing.T) {
	f := newJoinFixture(t, 1)
	slot := joinReleased(t, f)
	owner := joinOwner(t, f)
	original, err := f.h.reserveRotationJoinIntent(context.Background(), owner, f.preview.Id, slot)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE tsw_mother_personal_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE mother_account_id=$1`, f.mother)
	before := joinSources(t, f)
	reads, calls := f.http.reads, f.http.calls
	for _, load := range []func(context.Context, ownerContext, uuid.UUID, uuid.UUID) (rotationJoinIntent, error){f.h.reserveRotationJoinIntent, f.h.loadRotationJoinIntent} {
		v, err := load(context.Background(), owner, f.preview.Id, slot)
		if err != nil || !reflect.DeepEqual(original, v) {
			t.Fatalf("expired mother erased original observation: %v", err)
		}
	}
	if before != joinSources(t, f) || reads != f.http.reads || calls != f.http.calls {
		t.Fatal("observation refreshed sources or called HTTP")
	}
}
