//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

type usageMock struct {
	mu            sync.Mutex
	calls         int
	scope, result string
	resetDelay    time.Duration
	hook          func()
	f             *removalFixture
}

func (m *usageMock) ReadRotationUsage(_ context.Context, c platform.DeliveryCredentialSet, subject string) (platform.RotationUsageEvidence, error) {
	m.mu.Lock()
	m.calls++
	hook, scope, result, resetDelay := m.hook, m.scope, m.result, m.resetDelay
	m.mu.Unlock()
	if c.WorkspaceID != m.f.space.String() || subject != "candidate-user" {
		return platform.RotationUsageEvidence{}, errors.New("wrong candidate")
	}
	if hook != nil {
		hook()
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if resetDelay == 0 {
		resetDelay = time.Hour
	}
	e := platform.RotationUsageEvidence{Scope: scope, WorkspaceID: c.WorkspaceID, Result: result, ObservedAt: now, Windows: []platform.RotationUsageWindow{{Seconds: 18000, ResetsAt: now.Add(resetDelay)}, {Seconds: 604800, ResetsAt: now.Add(resetDelay)}}}
	if result == "positive" {
		e.Windows[0].UsedPercent = 2
	}
	if result == "unknown" {
		e.Windows = nil
	}
	if scope == "account" {
		e.WorkspaceID = ""
	}
	return e, nil
}
func usageFixture(t *testing.T) (*removalFixture, ownerContext, uuid.UUID, *dispatchTransport, *usageMock) {
	t.Helper()
	f, o, slot, d, _ := credentialFixture(t)
	if err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false); err != nil {
		t.Fatal(err)
	}
	m := &usageMock{f: f, scope: "workspace", result: "zero"}
	f.h.rotationUsageAdapters = func(platform.DiscoveryClient) platform.RotationUsageReader { return m }
	return f, o, slot, d, m
}
func usageObserve(t *testing.T, f *removalFixture, o ownerContext, slot uuid.UUID, recheck bool) {
	t.Helper()
	if err := f.h.observeRotationJoinUsage(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, recheck); err != nil {
		t.Fatal(err)
	}
}
func usageReady(t *testing.T, f *removalFixture, slot uuid.UUID) bool {
	t.Helper()
	var ready bool
	if err := f.pool.QueryRow(context.Background(), `SELECT public.tsw_rotation_join_usage_ready($1)`, slot).Scan(&ready); err != nil {
		t.Fatal(err)
	}
	return ready
}
func usageCounts(t *testing.T, f *removalFixture, slot uuid.UUID) (int, int) {
	t.Helper()
	var a, e int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*),count(e.attempt_id) FROM public.tsw_rotation_join_usage_attempts a LEFT JOIN public.tsw_rotation_join_usage_evidence e ON e.attempt_id=a.id WHERE a.slot_id=$1`, slot).Scan(&a, &e); err != nil {
		t.Fatal(err)
	}
	return a, e
}
func usageOriginalDigest(t *testing.T, f *removalFixture) string {
	t.Helper()
	var v string
	err := f.pool.QueryRow(context.Background(), `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(t)) FROM public.tsw_rotation_candidate_join_intents t),(SELECT jsonb_agg(to_jsonb(t)) FROM public.tsw_rotation_join_executions t),(SELECT jsonb_agg(to_jsonb(t)) FROM public.tsw_rotation_join_credential_generations t),(SELECT jsonb_agg(to_jsonb(t)) FROM public.tsw_rotation_usage_ledger t),(SELECT jsonb_agg(to_jsonb(t)) FROM public.tsw_rotation_released_slots t),(SELECT jsonb_agg(to_jsonb(t)) FROM public.tsw_rotation_epochs t))::text`).Scan(&v)
	if err != nil {
		t.Fatal(err)
	}
	return rotationHash(v)
}
func TestRotationJoinUsageRequiresOriginalMembershipAndCompleteCredentials(t *testing.T) {
	for _, mode := range []string{"no_join", "no_credentials", "partial_credentials", "membership_unknown", "revoked_authorization"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, d, m := credentialFixture(t)
			reads := 0
			f.h.rotationUsageAdapters = func(platform.DiscoveryClient) platform.RotationUsageReader {
				return &usageMock{f: f, hook: func() { reads++ }, scope: "workspace", result: "zero"}
			}
			switch mode {
			case "no_join":
				slot = uuid.New()
			case "no_credentials":
			case "partial_credentials":
				m.fail = "oauth"
				_ = f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false)
			case "membership_unknown":
				if err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false); err != nil {
					t.Fatal(err)
				}
				d.membershipStatus = 500
				_ = f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute)
			case "revoked_authorization":
				if err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false); err != nil {
					t.Fatal(err)
				}
				// Revoke the original authorization without rewriting its facts.
				f.exec(t, `UPDATE public.tsw_expiry_rotation_previews SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1`, f.preview.Id, f.owner)
			}
			before := usageOriginalDigest(t, f)
			posts := len(d.paths)
			err := f.h.observeRotationJoinUsage(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false)
			if err == nil || reads != 0 || posts != len(d.paths) || before != usageOriginalDigest(t, f) {
				t.Fatalf("read without prerequisite: %v reads=%d", err, reads)
			}
		})
	}
}
func TestRotationJoinUsageZeroIsAtomicOriginalAndIdempotent(t *testing.T) {
	f, o, slot, d, m := usageFixture(t)
	before := usageOriginalDigest(t, f)
	posts := len(d.paths)
	usageObserve(t, f, o, slot, false)
	usageObserve(t, f, o, slot, false)
	a, e := usageCounts(t, f, slot)
	if a != 1 || e != 1 || m.calls != 1 || !usageReady(t, f, slot) || before != usageOriginalDigest(t, f) || posts != len(d.paths) {
		t.Fatalf("a=%d e=%d calls=%d ready=%v", a, e, m.calls, usageReady(t, f, slot))
	}
	s, err := f.h.rotationJoinStatus(context.Background(), uuid.MustParse(f.owner), f.preview.Id, slot)
	if err != nil || !s.DeliveryReady || s.Usage != "zero" || s.NextAction != "recheck" {
		t.Fatalf("%+v %v", s, err)
	}
}
func TestRotationJoinUsageUnknownDoesNotRefreshPreviousZero(t *testing.T) {
	f, o, slot, _, m := usageFixture(t)
	usageObserve(t, f, o, slot, false)
	var digest string
	var observed, expiry time.Time
	if err := f.pool.QueryRow(context.Background(), `SELECT evidence_digest,observed_at,expires_at FROM public.tsw_rotation_join_usage_evidence WHERE result='zero'`).Scan(&digest, &observed, &expiry); err != nil {
		t.Fatal(err)
	}
	m.result = "unknown"
	usageObserve(t, f, o, slot, true)
	if usageReady(t, f, slot) {
		t.Fatal("unknown reused historical zero")
	}
	var same bool
	if err := f.pool.QueryRow(context.Background(), `SELECT evidence_digest=$1 AND observed_at=$2 AND expires_at=$3 FROM public.tsw_rotation_join_usage_evidence WHERE result='zero'`, digest, observed, expiry).Scan(&same); err != nil || !same {
		t.Fatal("historical zero refreshed", err)
	}
	_, clear, err := rotationCandidateLedgerLookup(context.Background(), f.pool, f.preview.Candidates[0].AccountId, f.space)
	if err != nil || clear {
		t.Fatal("old candidate gate ignored unknown", err)
	}
}
func TestRotationJoinUsagePositiveHistoryIsMonotonicAndScoped(t *testing.T) {
	for _, scope := range []string{"workspace", "account"} {
		t.Run(scope, func(t *testing.T) {
			f, o, slot, _, m := usageFixture(t)
			other := uuid.New()
			f.exec(t, `INSERT INTO public.tsw_workspaces(id,platform_workspace_id,display_name)VALUES($1,$2,'other')`, other, other.String())
			// The new Workspace itself changes no pinned source epochs for this round.
			m.scope = scope
			m.result = "positive"
			usageObserve(t, f, o, slot, false)
			m.scope = "workspace"
			m.result = "zero"
			usageObserve(t, f, o, slot, true)
			if usageReady(t, f, slot) {
				t.Fatal("zero erased positive history")
			}
			for _, tc := range []struct {
				space uuid.UUID
				clear bool
			}{{f.space, false}, {other, scope == "workspace"}} {
				_, clear, err := rotationCandidateLedgerLookup(context.Background(), f.pool, f.preview.Candidates[0].AccountId, tc.space)
				if err != nil || clear != tc.clear {
					t.Fatalf("scope=%s workspace=%s clear=%v err=%v", scope, tc.space, clear, err)
				}
			}
			proof, protection, err := f.h.persistedRotationEvidence(context.Background(), f.preview.Candidates[0].AccountId, f.space, time.Now(), time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if scope == "workspace" {
				if !proof.EverUsed || proof.State != "used" || proof.Scope != scope {
					t.Fatal("preview lost Workspace positive history", proof)
				}
				verdict := rotationVerdict{AccountID: f.preview.Candidates[0].AccountId, Usage: proof, Protection: protection}
				if match, err := rotationPersistedVerdictMatches(context.Background(), f.pool, f.space, verdict); err != nil || !match {
					t.Fatal("history not revalidated", match, err)
				}
				if !validRotationUsage(proof, f.space, f.preview.Candidates[0].AccountId, time.Now()) {
					t.Fatal("Workspace history projection rejected")
				}
			} else if proof.EverUsed || proof.State == "used" {
				t.Fatal("account history became Workspace usage", proof)
			}
			var positives int
			if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.tsw_rotation_join_usage_evidence WHERE result='positive' AND scope=$1`, scope).Scan(&positives); err != nil || positives != 1 {
				t.Fatal(positives, err)
			}
		})
	}
}
func TestRotationJoinUsageWriteFailurePendingAndRestartRecovery(t *testing.T) {
	for _, stage := range []string{"claim", "evidence", "completion"} {
		t.Run(stage, func(t *testing.T) {
			f, o, slot, d, m := usageFixture(t)
			before := usageOriginalDigest(t, f)
			posts := len(d.paths)
			table, event, predicate := "tsw_rotation_join_usage_attempts", "UPDATE", "NEW.lease_epoch>OLD.lease_epoch"
			if stage == "evidence" {
				table, event, predicate = "tsw_rotation_join_usage_evidence", "INSERT", "true"
			}
			if stage == "completion" {
				predicate = "NEW.state='complete'"
			}
			f.exec(t, `CREATE FUNCTION public.fail_usage_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF `+predicate+` THEN RAISE EXCEPTION 'injected usage write failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_usage_write BEFORE `+event+` ON public.`+table+` FOR EACH ROW EXECUTE FUNCTION public.fail_usage_write()`)
			err := f.h.observeRotationJoinUsage(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false)
			if err == nil || usageReady(t, f, slot) {
				t.Fatal("failed persistence certified readiness")
			}
			a, e := usageCounts(t, f, slot)
			if e != 0 || stage == "claim" && (a != 1 || m.calls != 0) || stage != "claim" && (a != 1 || m.calls != 1) {
				t.Fatalf("a=%d e=%d calls=%d", a, e, m.calls)
			}
			f.exec(t, `DROP TRIGGER fail_usage_write ON public.`+table+`;DROP FUNCTION public.fail_usage_write()`)
			// A new handler object simulates loss of all worker in-memory state.
			restarted := *f.h
			f.h = &restarted
			usageObserve(t, f, o, slot, false)
			a, e = usageCounts(t, f, slot)
			if a != 1 || e != 1 || !usageReady(t, f, slot) || before != usageOriginalDigest(t, f) || posts != len(d.paths) {
				t.Fatal("recovery replaced original obligation")
			}
		})
	}
}
func TestRotationJoinUsageConcurrentReadAndFencing(t *testing.T) {
	f, o, slot, _, m := usageFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	m.hook = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() {
		done <- f.h.observeRotationJoinUsage(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false)
	}()
	<-entered
	// Use the regular pool rather than the one-connection network fixture pool.
	second := *f.h
	second.pool = f.pool
	if err := second.observeRotationJoinUsage(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false); !errors.Is(err, joinUsageBusy) {
		t.Fatal("concurrent original read", err)
	}
	if usageReady(t, f, slot) {
		t.Fatal("pending attempt ready")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	a, e := usageCounts(t, f, slot)
	if a != 1 || e != 1 || m.calls != 1 {
		t.Fatal(a, e, m.calls)
	}
}
func TestRotationJoinUsageStopExpiryRevokeAndSourceFences(t *testing.T) {
	for _, mode := range []string{"stop", "owner_revoke", "source_revision", "lease_expiry"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, d, m := usageFixture(t)
			beforePosts := len(d.paths)
			var sourceDone chan error
			m.hook = func() {
				switch mode {
				case "stop":
					f.exec(t, `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
				case "owner_revoke":
					_, err := d.gateConn.Exec(context.Background(), `UPDATE public.tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE id=$1`, o.SessionID)
					if err != nil {
						t.Fatal(err)
					}
				case "source_revision":
					sourceDone = make(chan error, 1)
					go func() {
						_, err := f.pool.Exec(context.Background(), `UPDATE public.tsw_target_accounts SET version=version+1 WHERE id=$1`, f.preview.Candidates[0].AccountId)
						sourceDone <- err
					}()
					select {
					case err := <-sourceDone:
						t.Fatalf("source writer bypassed read fence: %v", err)
					case <-time.After(25 * time.Millisecond):
					}

				case "lease_expiry":
					time.Sleep(900 * time.Millisecond)
				}
			}
			duration := time.Minute
			if mode == "lease_expiry" {
				duration = 750 * time.Millisecond
			}
			err := f.h.observeRotationJoinUsage(context.Background(), o, f.preview.Id, slot, uuid.New(), duration, false)
			if mode == "source_revision" {
				if err != nil {
					t.Fatal("read was fenced before source writer could commit", err)
				}
				select {
				case err = <-sourceDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("source writer remained blocked after read released gate")
				}
			} else if err == nil {
				t.Fatal("fence bypass")
			}
			if usageReady(t, f, slot) {
				t.Fatal("source or authority fence retained readiness")
			}
			a, e := usageCounts(t, f, slot)
			expectedEvidence := 0
			if mode == "source_revision" {
				expectedEvidence = 1
			}
			if a != 1 || e != expectedEvidence || len(d.paths) != beforePosts || executionState(t, f, slot) != "reconcile_required" {
				t.Fatal("fence released original", a, e)
			}
		})
	}
}
func TestRotationJoinUsageProtectionAndFreshnessGate(t *testing.T) {
	for _, mode := range []string{"suspected_sold", "sale_reserved", "delivery_pending", "delivered", "canceled_retired", "stale"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, _, m := usageFixture(t)
			if mode == "stale" {
				m.hook = func() {}
				m.resetDelay = 2 * time.Second
				usageObserve(t, f, o, slot, false)
				if !usageReady(t, f, slot) {
					t.Fatal("fresh zero not ready")
				}
				time.Sleep(2100 * time.Millisecond)
				if usageReady(t, f, slot) {
					t.Fatal("expired window stayed ready")
				}
				return
			}
			usageObserve(t, f, o, slot, false)
			f.exec(t, `INSERT INTO public.tsw_rotation_global_protections(target_account_id,status,evidence_source,evidence_id,observed_at)VALUES($1,$2,'fixture',repeat('a',64),clock_timestamp())`, f.preview.Candidates[0].AccountId, mode)
			if usageReady(t, f, slot) {
				t.Fatal("protection ignored")
			}
			if err := f.h.observeRotationJoinUsage(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, true); err == nil {
				t.Fatal("protection allowed new read")
			}
		})
	}
}
func TestRotationJoinUsageHTTPRegisteredStrictAndRedacted(t *testing.T) {
	f, _, slot, _, m := usageFixture(t)
	before := m.calls
	for _, body := range []string{`{}`, `{"confirmed":false}`, `{"confirmed":true,"confirmed":true}`, `{"Confirmed":true}`, `{"confirmed":true,"replacement":"other"}`, `{"confirmed":true}{}`} {
		w := joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "usage", body)
		if w.Code != 422 || m.calls != before {
			t.Fatalf("body %s status %d", body, w.Code)
		}
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.test") }} {
		if w := joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "usage", `{"confirmed":true}`, change); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	for _, action := range []string{"usage", "usage"} {
		w := joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", action, `{"confirmed":true}`)
		s := joinHTTPStatus(t, w)
		if !s.DeliveryReady || s.Usage != "zero" {
			t.Fatal(s)
		}
		for _, secret := range []string{"original-refresh", "secret-cookie", "leaseToken", "nonce", "sealed", "oauthDigest"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("secret leaked", secret)
			}
		}
	}
	if m.calls != 1 {
		t.Fatal("duplicate HTTP read replay", m.calls)
	}
	m.result = "unknown"
	s := joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "usage/recheck", `{"confirmed":true}`))
	if s.DeliveryReady || s.Usage != "unknown" || s.NextAction != "recheck" {
		t.Fatal(s)
	}
	s = joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "GET", "", ""))
	if s.DeliveryReady {
		t.Fatal("passive status reused old zero")
	}
}

type usageHTTPTransport struct {
	next  http.RoundTripper
	calls int
	body  string
}

func (u *usageHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/backend-api/wham/usage" {
		u.calls++
		if r.Method != "GET" {
			return nil, errors.New("mutation forbidden")
		}
		response := removalHTTPResponse(200, u.body)
		response.Header.Set("Content-Type", "application/json")
		return response, nil
	}
	return u.next.RoundTrip(r)
}
func TestRotationJoinUsageOfficialAdapterRetainsAccountScope(t *testing.T) {
	f, o, slot, d, _ := usageFixture(t)
	now := time.Now().UTC()
	u := &usageHTTPTransport{next: d, body: fmt.Sprintf(`{"account_id":%q,"user_id":"candidate-user","rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":0,"limit_window_seconds":18000,"reset_at":%d},"secondary_window":{"used_percent":0,"limit_window_seconds":604800,"reset_at":%d}}}`, f.space.String(), now.Add(time.Hour).Unix(), now.Add(time.Hour).Unix())}
	d.route.client.Transport = u
	f.h.rotationUsageAdapters = func(c platform.DiscoveryClient) platform.RotationUsageReader {
		return platform.OfficialRotationUsageReader{Client: c}
	}
	usageObserve(t, f, o, slot, false)
	if u.calls != 1 || usageReady(t, f, slot) {
		t.Fatal("official account scope became Workspace zero", u.calls)
	}
	s, err := f.h.rotationJoinStatus(context.Background(), uuid.MustParse(f.owner), f.preview.Id, slot)
	if err != nil || s.Usage != "shared" || s.DeliveryReady {
		t.Fatal(s, err)
	}
}
func TestRotationJoinUsageMigration35DownUpAndImmutableJournal(t *testing.T) {
	f, o, slot, _, _ := usageFixture(t)
	usageObserve(t, f, o, slot, false)
	for _, sql := range []string{`DELETE FROM public.tsw_rotation_join_usage_attempts`, `DELETE FROM public.tsw_rotation_join_usage_evidence`, `UPDATE public.tsw_rotation_join_usage_evidence SET result='unknown'`, `UPDATE public.tsw_rotation_join_usage_attempts SET credential_attempt_id=gen_random_uuid()`} {
		if _, err := f.pool.Exec(context.Background(), sql); err == nil {
			t.Fatal("journal rewritten", sql)
		}
	}
	before := usageOriginalDigest(t, f)
	membershipSchemaVersion(t, 34)
	var absent bool
	if err := f.pool.QueryRow(context.Background(), `SELECT to_regclass('public.tsw_rotation_join_usage_attempts') IS NULL AND to_regprocedure('public.tsw_rotation_join_usage_ready(uuid)') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal(absent, err)
	}
	membershipSchemaVersion(t, migrations.RequiredVersion)
	membershipSchemaVersion(t, migrations.RequiredVersion)
	if before != usageOriginalDigest(t, f) {
		t.Fatal("migration mutated original sources")
	}
	usageObserve(t, f, o, slot, false)
	if !usageReady(t, f, slot) {
		t.Fatal("up migration lost capability")
	}
}

func TestRotationJoinUsageRecheckClaimFailureCannotReviveOldZero(t *testing.T) {
	f, o, slot, d, m := usageFixture(t)
	usageObserve(t, f, o, slot, false)
	if !usageReady(t, f, slot) {
		t.Fatal("initial zero not ready")
	}
	var digest string
	var observed, expires time.Time
	if err := f.pool.QueryRow(context.Background(), `SELECT evidence_digest,observed_at,expires_at FROM public.tsw_rotation_join_usage_evidence`).Scan(&digest, &observed, &expires); err != nil {
		t.Fatal(err)
	}
	before := usageOriginalDigest(t, f)
	posts := len(d.paths)
	f.exec(t, `CREATE FUNCTION public.fail_recheck_claim() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.lease_epoch>OLD.lease_epoch THEN RAISE EXCEPTION 'injected recheck claim failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_recheck_claim BEFORE UPDATE ON public.tsw_rotation_join_usage_attempts FOR EACH ROW EXECUTE FUNCTION public.fail_recheck_claim()`)
	if err := f.h.observeRotationJoinUsage(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, true); err == nil {
		t.Fatal("claim write unexpectedly succeeded")
	}
	a, e := usageCounts(t, f, slot)
	if a != 2 || e != 1 || m.calls != 1 || usageReady(t, f, slot) {
		t.Fatal("claim failure revived prior zero", a, e, m.calls)
	}
	restarted := *f.h
	f.h = &restarted
	status, err := f.h.rotationJoinStatus(context.Background(), uuid.MustParse(f.owner), f.preview.Id, slot)
	if err != nil || status.DeliveryReady || status.Usage != "pending" {
		t.Fatal("restart lost pending read obligation", status, err)
	}
	f.exec(t, `DROP TRIGGER fail_recheck_claim ON public.tsw_rotation_join_usage_attempts;DROP FUNCTION public.fail_recheck_claim()`)
	usageObserve(t, f, o, slot, false)
	a, e = usageCounts(t, f, slot)
	var same bool
	if err := f.pool.QueryRow(context.Background(), `SELECT evidence_digest=$1 AND observed_at=$2 AND expires_at=$3 FROM public.tsw_rotation_join_usage_evidence WHERE evidence_digest=$1`, digest, observed, expires).Scan(&same); err != nil || !same {
		t.Fatal("retry refreshed original zero", err)
	}
	if a != 2 || e != 2 || !usageReady(t, f, slot) || before != usageOriginalDigest(t, f) || posts != len(d.paths) {
		t.Fatal("recovery changed original or created replacement attempt", a, e)
	}
}

func TestRotationJoinUsageAccountHistoryDoesNotAuthorizeOtherWorkspaceRemoval(t *testing.T) {
	f, o, slot, _, m := usageFixture(t)
	m.scope = "account"
	m.result = "positive"
	usageObserve(t, f, o, slot, false)
	account := f.preview.Candidates[0].AccountId
	identifier := f.preview.Candidates[0].Identifier
	other := uuid.New()
	ctx := context.Background()
	f.exec(t, `INSERT INTO public.tsw_workspaces(id,platform_workspace_id,display_name)VALUES($1,$2,'Workspace B')`, other, other.String())
	proof, _, err := f.h.persistedRotationEvidence(ctx, account, other, time.Now(), time.Now().Add(time.Minute))
	if err != nil || proof.State != "unknown" || proof.EverUsed {
		t.Fatal("A account history became B usage", proof, err)
	}
	if _, clear, err := rotationCandidateLedgerLookup(ctx, f.pool, account, other); err != nil || clear {
		t.Fatal("global account history failed to block new join", clear, err)
	}
	forged := rotationUsageProof{rotationProof: rotationProof{Source: "persisted_join_account_usage", EvidenceID: strings.Repeat("a", 64), ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, AccountID: account, Scope: "account", State: "used", EverUsed: true}
	if validRotationUsage(forged, other, account, time.Now()) {
		t.Fatal("account history accepted as B member usage")
	}
	// Prepare B's legitimate selection facts without a B usage observation. A's
	// immutable journal remains in place. The member is the same account, but its
	// unknown B evidence must prevent a replaceable preview and removal start.
	var b workspaceAccessBinding
	b.motherID = f.mother
	b.workspaceID = other
	b.attempt = 1
	b.exchangeID = uuid.New()
	if err = f.pool.QueryRow(ctx, `SELECT mother_revision,visibility_run_id,session_generation FROM public.tsw_operation_selection_drafts WHERE owner_id=$1`, f.owner).Scan(&b.revision, &b.run, &b.generation); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO public.tsw_mother_workspace_visibility(mother_account_id,workspace_id,run_id,access_status,workspace_role)VALUES($1,$2,$3,'readable','owner')`, f.mother, other, b.run)
	access := fixtureWorkspaceAccess(other.String())
	key, nonce, sealed, err := sealWorkspaceAccess(f.h.keyRing, b, access)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO public.tsw_selected_workspace_tokens(mother_account_id,workspace_id,discovery_run_id,session_generation,secret_revision,attempt,exchange_id,status,key_version,nonce,sealed_access,expires_at)VALUES($1,$2,$3,$4,$5,1,$6,'ready',$7,$8,$9,$10)`, f.mother, other, b.run, b.generation, b.revision, b.exchangeID, key, nonce, sealed, access.ExpiresAt)
	var verification int64
	active := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	if err = f.pool.QueryRow(ctx, `INSERT INTO public.tsw_workspace_verifications(workspace_id,mother_account_id,discovery_run_id,session_generation,secret_revision,token_attempt,token_exchange_id,source,outcome,permission,completeness,observed_at,expires_at,active_until,seat_limit,member_count,pending_invite_count,seat_type_counts)VALUES($1,$2,$3,$4,$5,1,$6,'injected_platform_reader','verified','read','complete',clock_timestamp(),clock_timestamp()+interval '4 minutes',$7,2,1,0,'{"default":0,"usage_based":0,"automation":0,"prolite":1}') RETURNING id`, other, f.mother, b.run, b.generation, b.revision, b.exchangeID, active).Scan(&verification); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO public.tsw_workspace_verification_entries(verification_id,kind,identifier,identifier_hmac,identifier_key_version,status,platform_member_id,role,seat_type) SELECT $1,'member',identifier,identifier_hmac,identifier_key_version,'active','b-member','member','prolite' FROM public.tsw_target_accounts WHERE id=$2`, verification, account)
	f.exec(t, `INSERT INTO public.tsw_rotation_global_protections(target_account_id,status,evidence_source,evidence_id,observed_at)VALUES($1,'none','fixture',repeat('d',64),clock_timestamp())`, account)
	f.exec(t, `UPDATE public.tsw_operation_selection_drafts SET workspace_id=$2,verification_id=$3,version=version+1 WHERE owner_id=$1`, f.owner, other, verification)
	paid, count, invites := 2, 1, 0
	f.h.pool = f.pool
	f.http.workspace = other.String()
	f.http.members = []platform.Member{{Kind: "member", PlatformMemberID: "b-member", Identifier: identifier, Status: "listed", Role: "member", SeatType: "prolite"}}
	f.h.selectedWorkspaceReader = fixedSelectedWorkspaceReader{facts: platform.SelectedWorkspaceFacts{Permission: "read", Result: platform.Result{Outcome: platform.OutcomeOperational, Completeness: platform.Complete, ActiveUntil: &active, SeatLimit: &paid, MemberCount: &count, PendingInviteCount: &invites, SeatTypeCounts: map[string]int{"default": 0, "usage_based": 0, "automation": 0, "prolite": 1}, Members: []platform.Member{{Kind: "member", PlatformMemberID: "b-member", Identifier: identifier, Status: "listed", Role: "member", SeatType: "prolite"}}}}}
	p := productionAbsencePreview(t, f)
	if p.Source != "official_owner_ab" || len(p.Slots) != 1 || p.Slots[0].AccountId != account || p.Slots[0].Decision == "replaceable" || p.Slots[0].UsageState != "unknown" || p.Slots[0].EverUsed || p.Status == "ready" {
		t.Fatal("B gained removal qualification from A account history", p)
	}
	beforeDeletes := f.http.calls
	w := removalRequest(f.h, f.session, f.csrf, "POST", p.Id, uuid.Nil, "start", map[string]any{"confirmed": true, "authorizationDigest": p.Digest, "idempotencyKey": uuid.New()})
	if w.Code != http.StatusConflict || f.http.calls != beforeDeletes {
		t.Fatal("pending B preview authorized DELETE", w.Code, w.Body.String())
	}
	if usageReady(t, f, slot) {
		t.Fatal("account usage or changed selection certified delivery")
	}
}
