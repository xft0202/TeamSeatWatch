//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

func TestRotationJoinMembershipRejectsDispatchGenerationChange(t *testing.T) {
	for _, mode := range []string{"generation", "revision", "attempt", "sealed_bytes", "db_expiry", "decoded_expiry"} {
		t.Run(mode, func(t *testing.T) {
			f, owner, slot, transport := membershipDispatched(t)
			candidate := f.preview.Candidates[0]
			transport.membershipBody = fmt.Sprintf(`{"complete":true,"members":[{"kind":"member","platform_member_id":"remote-member-1","identifier":%q,"status":"active","seat_type":"prolite"}]}`, candidate.Identifier)
			switch mode {
			case "generation":
				f.exec(t, `UPDATE public.tsw_target_personal_sessions SET generation=$2 WHERE target_account_id=$1`, candidate.AccountId, uuid.New())
			case "revision":
				f.exec(t, `UPDATE public.tsw_target_personal_sessions SET secret_revision=secret_revision+1 WHERE target_account_id=$1`, candidate.AccountId)
			case "attempt":
				f.exec(t, `UPDATE public.tsw_target_personal_access SET attempt=attempt+1 WHERE target_account_id=$1`, candidate.AccountId)
			case "sealed_bytes":
				f.exec(t, `UPDATE public.tsw_target_personal_sessions SET sealed_session=decode(repeat('ee',32),'hex') WHERE target_account_id=$1`, candidate.AccountId)
			case "db_expiry":
				f.exec(t, `UPDATE public.tsw_target_personal_sessions SET expires_at=expires_at-interval '1 second' WHERE target_account_id=$1`, candidate.AccountId)
			case "decoded_expiry":
				changed := transport.session
				changed.ExpiresAt = changed.ExpiresAt.Add(-time.Second)
				v, n, c, err := sealSessionFor("target", f.h.keyRing, candidate.AccountId, 1, changed)
				if err != nil {
					t.Fatal(err)
				}
				f.exec(t, `UPDATE public.tsw_target_personal_sessions SET key_version=$2,nonce=$3,sealed_session=$4 WHERE target_account_id=$1`, candidate.AccountId, int16(v), n, c)
			}
			before := executionSources(t, f)
			posts := len(transport.paths)
			_ = f.h.reconcileRotationJoinMembership(context.Background(), owner, f.preview.Id, slot, uuid.New(), time.Minute)
			if membershipResult(t, f, slot) != "unknown" {
				t.Fatalf("changed dispatch %s accepted", mode)
			}
			if posts != len(transport.paths) || before != executionSources(t, f) || executionState(t, f, slot) != "reconcile_required" {
				t.Fatal("generation rejection changed sources, replayed POST, or discharged obligation")
			}
		})
	}
}

func TestRotationJoinMembershipReconcileConfirmedWithoutPOST(t *testing.T) {
	f, owner, slot, transport := dispatchFixture(t)
	candidate := f.preview.Candidates[0]
	transport.membershipBody = fmt.Sprintf(`{"complete":true,"members":[{"kind":"member","platform_member_id":"remote-member-1","identifier":%q,"status":"active","seat_type":"prolite"}]}`, candidate.Identifier)
	if err := f.h.dispatchRotationCandidateJoin(context.Background(), owner, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatalf("dispatch err=%v", err)
	}
	before := executionSources(t, f)
	posts := len(transport.paths)
	err := f.h.reconcileRotationJoinMembership(context.Background(), owner, f.preview.Id, slot, uuid.New(), time.Minute)
	if !errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatalf("reconcile err=%v", err)
	}
	if len(transport.paths) != posts || before != executionSources(t, f) {
		t.Fatalf("membership reconciliation sent POST or wrote sources: before=%d after=%d", posts, len(transport.paths))
	}
	var result, memberID, diagnostic string
	if err := f.pool.QueryRow(context.Background(), `SELECT result,COALESCE(platform_member_id,''),diagnostic FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&result, &memberID, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if result != "confirmed" || memberID != "remote-member-1" || diagnostic != "member_confirmed" || executionState(t, f, slot) != "reconcile_required" {
		t.Fatalf("evidence result=%s member=%s diagnostic=%s state=%s", result, memberID, diagnostic, executionState(t, f, slot))
	}
}

func membershipDispatched(t *testing.T) (*removalFixture, ownerContext, uuid.UUID, *dispatchTransport) {
	t.Helper()
	f, o, slot, d := dispatchFixture(t)
	if err := f.h.dispatchRotationCandidateJoin(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatal(err)
	}
	return f, o, slot, d
}
func membershipResult(t *testing.T, f *removalFixture, slot uuid.UUID) string {
	t.Helper()
	var result string
	if err := f.pool.QueryRow(context.Background(), `SELECT result FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1 ORDER BY reconciliation_attempt DESC LIMIT 1`, slot).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestRotationJoinMembershipOutcomesPreserveSources(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"absent", `{"complete":true,"members":[]}`, "absent", 200},
		{"incomplete", `{"complete":false,"members":[]}`, "unknown", 200},
		{"unauthorized", `{"error_code":"auth_error"}`, "unknown", 401},
		{"wrong_workspace", `{"workspace_id":"other-workspace","complete":true,"members":[]}`, "unknown", 200},
		{"wrong_identifier", `{"complete":true,"members":[{"kind":"member","platform_member_id":"other","identifier":"other@example.test","status":"active","seat_type":"prolite"}]}`, "absent", 200},
		{"wrong_seat", `{"complete":true,"members":[{"kind":"member","platform_member_id":"member","identifier":%q,"status":"active","seat_type":"default"}]}`, "invalid", 200},
		{"pending", `{"complete":true,"members":[{"kind":"pending_invite","identifier":%q,"status":"pending","seat_type":"prolite"}]}`, "invalid", 200},
		{"duplicate", `{"complete":true,"members":[{"kind":"member","platform_member_id":"one","identifier":%q,"status":"active","seat_type":"prolite"},{"kind":"member","platform_member_id":"two","identifier":%q,"status":"active","seat_type":"prolite"}]}`, "unknown", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, o, slot, d := membershipDispatched(t)
			d.membershipBody = tc.body
			if strings.Contains(tc.body, "%q") {
				if tc.name == "duplicate" {
					d.membershipBody = fmt.Sprintf(tc.body, f.preview.Candidates[0].Identifier, f.preview.Candidates[0].Identifier)
				} else {
					d.membershipBody = fmt.Sprintf(tc.body, f.preview.Candidates[0].Identifier)
				}
			}
			d.membershipStatus = tc.status
			before := executionSources(t, f)
			posts := len(d.paths)
			err := f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute)
			if !errors.Is(err, joinDispatchReconcileRequired) || membershipResult(t, f, slot) != tc.want {
				t.Fatalf("result=%s err=%v", membershipResult(t, f, slot), err)
			}
			if before != executionSources(t, f) || posts != len(d.paths) || executionState(t, f, slot) != "reconcile_required" {
				t.Fatal("source write, POST replay or discharged obligation")
			}
		})
	}
}
func TestRotationJoinMembershipAppendOnlyGuards(t *testing.T) {
	f, o, slot, d := membershipDispatched(t)
	before := executionSources(t, f)
	d.membershipBody = fmt.Sprintf(`{"complete":true,"members":[{"kind":"member","platform_member_id":"member","identifier":%q,"status":"accepted","seat_type":"prolite"}]}`, f.preview.Candidates[0].Identifier)
	if err := f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE public.tsw_rotation_join_membership_evidence SET result='unknown',platform_member_id=NULL WHERE slot_id=$1`,
		`DELETE FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`,
		`UPDATE public.tsw_rotation_join_personal_bindings SET generation=gen_random_uuid() WHERE slot_id=$1`,
		`DELETE FROM public.tsw_rotation_join_personal_bindings WHERE slot_id=$1`,
		`INSERT INTO public.tsw_rotation_join_membership_evidence SELECT slot_id,reconciliation_attempt+1,observed_at,source,result,platform_member_id,candidate_identifier,seat_type,workspace_id,lease_epoch,lease_owner,lease_token,owner_session,diagnostic,repeat('f',64),created_at FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`,
	} {
		if _, err := f.pool.Exec(context.Background(), query, slot); err == nil {
			t.Fatalf("unguarded SQL: %s", query)
		}
	}
	d.membershipBody = `{"complete":true,"members":[]}`
	if err := f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatal(err)
	}
	var n, confirmed int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*),count(*) FILTER(WHERE result='confirmed') FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&n, &confirmed); err != nil || n != 2 || confirmed != 1 {
		t.Fatalf("prior confirmed overwritten count=%d confirmed=%d err=%v", n, confirmed, err)
	}
	if before != executionSources(t, f) {
		t.Fatal("sources changed")
	}
}
func TestRotationJoinMembershipMissingOriginalBinding(t *testing.T) {
	f, o, slot := legacyExecutionSchema32Fixture(t)
	l := executionClaim(t, f, o, slot, time.Minute)
	if err := f.h.markRotationJoinStageStarted(context.Background(), l, "request_join"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.finishRotationJoinStage(context.Background(), l, "request_join", "uncertain", true); err != nil {
		t.Fatal(err)
	}
	membershipSchemaVersion(t, migrations.RequiredVersion)
	before := executionSources(t, f)
	// Missing access is also fail-closed for a historical marker without a binding.
	f.h.rotationJoinEgress = func(context.Context) (rotationJoinEgress, error) {
		return &dispatchRoute{client: &http.Client{Timeout: time.Second, Transport: rotationNoHTTP{t: t}}}, nil
	}
	f.h.rotationJoinAdapters = officialRotationJoinAdapters
	if err := f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatal(err)
	}
	if membershipResult(t, f, slot) != "unknown" || before != executionSources(t, f) {
		t.Fatal("historical marker was rebound")
	}
}

type rotationNoHTTP struct{ t *testing.T }

func (n rotationNoHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	n.t.Fatal("historical marker performed HTTP")
	return nil, errors.New("no HTTP")
}
func TestRotationJoinMembershipWriteFailureRollback(t *testing.T) {
	f, o, slot, d := membershipDispatched(t)
	before := executionSources(t, f)
	posts := len(d.paths)
	f.exec(t, `CREATE FUNCTION public.fail_membership_write() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected'; END$$; CREATE TRIGGER fail_membership_write BEFORE INSERT ON public.tsw_rotation_join_membership_evidence FOR EACH ROW EXECUTE FUNCTION public.fail_membership_write()`)
	if err := f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); err == nil || errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatal("injected write unexpectedly succeeded")
	}
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&n); err != nil || n != 0 {
		t.Fatalf("half evidence n=%d err=%v", n, err)
	}
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.tsw_rotation_join_execution_attempts WHERE slot_id=$1 AND stage='reconcile' AND event_kind='finished'`, slot).Scan(&n); err != nil || n != 0 {
		t.Fatalf("half terminal n=%d err=%v", n, err)
	}
	if before != executionSources(t, f) || posts != len(d.paths) || executionState(t, f, slot) != "reconcile_required" {
		t.Fatal("write failure changed original obligation")
	}
}

func TestRotationJoinMembershipConcurrentOneDurableResult(t *testing.T) {
	f, o, slot, d := membershipDispatched(t)
	f.h.pool = f.pool
	before := executionSources(t, f)
	posts := len(d.paths)
	entered, release := make(chan struct{}), make(chan struct{})
	d.membershipHook = func() { close(entered); <-release }
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	winner := make(chan error, 1)
	go func() {
		winner <- f.h.reconcileRotationJoinMembership(ctx, o, f.preview.Id, slot, uuid.New(), time.Minute)
	}()
	select {
	case <-entered:
	case err := <-winner:
		t.Fatalf("did not enter GET: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	errs := make(chan error, 7)
	for n := 0; n < 7; n++ {
		go func() {
			errs <- f.h.reconcileRotationJoinMembership(ctx, o, f.preview.Id, slot, uuid.New(), time.Minute)
		}()
	}
	for n := 0; n < 7; n++ {
		select {
		case err := <-errs:
			if !errors.Is(err, joinExecutionBusy) {
				t.Errorf("loser=%v", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(release)
	if err := <-winner; !errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatal(err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if before != executionSources(t, f) || posts != len(d.paths) {
		t.Fatal("concurrent reconcile changed sources or sent POST")
	}
}
func TestRotationJoinMembershipLeaseAndOwnerFencing(t *testing.T) {
	for _, mode := range []string{"expired_lease", "revoked_owner", "source_drift", "expired_personal"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, d := membershipDispatched(t)
			posts := len(d.paths)
			duration := time.Minute
			if mode == "expired_lease" {
				duration = time.Second
			}
			var afterMutation string
			d.membershipHook = func() {
				switch mode {
				case "expired_lease":
					time.Sleep(1100 * time.Millisecond)
				case "revoked_owner":
					if _, err := d.gateConn.Exec(context.Background(), `UPDATE public.tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE id=$1`, o.SessionID); err != nil {
						t.Fatal(err)
					}
				case "source_drift":
					if _, err := d.gateConn.Exec(context.Background(), `UPDATE public.tsw_standby_child_batches SET version=version+1 WHERE id=$1`, f.preview.BatchId); err != nil {
						t.Fatal(err)
					}
				case "expired_personal":
					if _, err := d.gateConn.Exec(context.Background(), `UPDATE public.tsw_target_personal_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId); err != nil {
						t.Fatal(err)
					}
				}
				if mode != "expired_lease" {
					afterMutation = executionSources(t, f)
				}
			}
			before := executionSources(t, f)
			err := f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), duration)
			if mode == "source_drift" || mode == "expired_personal" {
				if !errors.Is(err, joinDispatchReconcileRequired) || membershipResult(t, f, slot) != "unknown" {
					t.Fatalf("drift err=%v", err)
				}
			} else {
				var n int
				if dbErr := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&n); dbErr != nil || n != 0 || err == nil {
					t.Fatalf("stale writer evidence=%d err=%v dbErr=%v", n, err, dbErr)
				}
			}
			if mode == "expired_lease" {
				afterMutation = before
			}
			if afterMutation != executionSources(t, f) || posts != len(d.paths) || executionState(t, f, slot) != "reconcile_required" {
				t.Fatal("fenced worker changed sources, POST replay or obligation")
			}
		})
	}
}
func TestRotationJoinMembershipDispatchBindingRollback(t *testing.T) {
	f, o, slot, d := dispatchFixture(t)
	before := executionSources(t, f)
	f.exec(t, `CREATE FUNCTION public.fail_personal_binding() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected'; END$$; CREATE TRIGGER fail_personal_binding BEFORE INSERT ON public.tsw_rotation_join_personal_bindings FOR EACH ROW EXECUTE FUNCTION public.fail_personal_binding()`)
	if err := f.h.dispatchRotationCandidateJoin(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); err == nil {
		t.Fatal("binding failure unexpectedly succeeded")
	}
	var bindings, events int
	if err := f.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM public.tsw_rotation_join_personal_bindings WHERE slot_id=$1),(SELECT count(*) FROM public.tsw_rotation_join_execution_attempts WHERE slot_id=$1)`, slot).Scan(&bindings, &events); err != nil || bindings != 0 || events != 0 {
		t.Fatalf("half binding=%d event=%d err=%v", bindings, events, err)
	}
	if len(d.paths) != 0 || before != executionSources(t, f) || executionState(t, f, slot) != "ready" {
		t.Fatal("failed admission performed POST or wrote sources")
	}
}
func TestRotationJoinMembershipDigestIdempotencyAndStaleToken(t *testing.T) {
	f, o, slot, d := membershipDispatched(t)
	posts := len(d.paths)
	before := executionSources(t, f)
	i, err := f.h.loadRotationJoinIntent(context.Background(), o, f.preview.Id, slot)
	if err != nil {
		t.Fatal(err)
	}
	l := executionClaim(t, f, o, slot, time.Minute)
	a, err := loadRemovalAuthorization(context.Background(), f.pool, i.ownerID, i.previewID)
	if err != nil {
		t.Fatal(err)
	}
	keys := rotationAuthorizationKeys(i.ownerID, a.preview)
	gate, err := f.h.lockRemovalGate(context.Background(), i.workspaceID, keys)
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	observation := rotationMembershipObservation{result: "unknown", diagnostic: "membership_unknown"}
	bad := l
	bad.token = uuid.New()
	if err := f.h.persistRotationJoinMembershipEvidence(context.Background(), gate.conn, keys, bad, i, observation, observed, nil); !errors.Is(err, joinExecutionStale) {
		t.Fatalf("stale token=%v", err)
	}
	for n := 0; n < 2; n++ {
		if err := f.h.persistRotationJoinMembershipEvidence(context.Background(), gate.conn, keys, l, i, observation, observed, nil); !errors.Is(err, joinDispatchReconcileRequired) {
			t.Fatalf("duplicate attempt=%v", err)
		}
	}
	changed := observation
	changed.result = "absent"
	changed.diagnostic = "reconcile_absent"
	if err := f.h.persistRotationJoinMembershipEvidence(context.Background(), gate.conn, keys, l, i, changed, observed, nil); !errors.Is(err, joinExecutionTransition) {
		t.Fatalf("conflicting evidence=%v", err)
	}
	gate.close()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1 AND evidence_digest=public.tsw_rotation_join_membership_digest(slot_id,reconciliation_attempt,observed_at,source,result,platform_member_id,candidate_identifier,seat_type,workspace_id,lease_epoch,diagnostic)`, slot).Scan(&n); err != nil || n != 1 {
		t.Fatalf("digest count=%d err=%v", n, err)
	}
	if before != executionSources(t, f) || posts != len(d.paths) {
		t.Fatal("idempotency changed source or POST")
	}
}

func membershipSQLAdmission(t *testing.T, f *removalFixture, owner ownerContext, slot uuid.UUID) (rotationJoinIntent, joinAdmission) {
	t.Helper()
	ctx := context.Background()
	i, err := f.h.loadRotationJoinIntent(ctx, owner, f.preview.Id, slot)
	if err != nil {
		t.Fatal(err)
	}
	a, err := loadRemovalAuthorization(ctx, f.pool, i.ownerID, i.previewID)
	if err != nil {
		t.Fatal(err)
	}
	tx, versions, err := writerfence.BeginLocked(ctx, f.pool, rotationAuthorizationKeys(i.ownerID, a.preview))
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.h.joinAdmissionLocal(ctx, tx, a, i, owner, versions)
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return i, p
}
func TestRotationJoinMembershipRequestBindingTransaction(t *testing.T) {
	for _, mode := range []string{"atomic", "unbound_commit", "unbound_immediate", "paired_immediate", "rollback", "historical_current", "historical_changed"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, _ := dispatchFixture(t)
			ctx := context.Background()
			historical := strings.HasPrefix(mode, "historical_")
			if historical {
				membershipSchemaVersion(t, 32)
			}
			l := executionClaim(t, f, o, slot, time.Minute)
			if historical {
				if err := f.h.markRotationJoinStageStarted(ctx, l, "request_join"); err != nil {
					t.Fatal(err)
				}
				membershipSchemaVersion(t, 33)
				// Keep the historical request created under schema32, then run
				// current Go admission against the current required schema. The
				// schema33 historical-binding guard still rejects a new binding.
				membershipSchemaVersion(t, migrations.RequiredVersion)
				if mode == "historical_changed" {
					f.exec(t, `UPDATE public.tsw_target_personal_sessions SET generation=$2 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId, uuid.New())
				}
			}
			before := executionSources(t, f)
			i, p := membershipSQLAdmission(t, f, o, slot)
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if !historical {
				if err = markRotationJoinStageInTx(ctx, tx, l, "ready", "request_join", "", nil); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unbound_commit" || mode == "unbound_immediate" {
				if mode == "unbound_immediate" {
					_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
				} else {
					err = tx.Commit(ctx)
				}
				if err == nil {
					t.Fatal("new request committed without Personal binding")
				}
			} else {
				err = appendJoinPersonalBinding(ctx, tx, l, i, p, platform.PersonalIdentity{Identifier: i.candidateIdentifier, SubjectID: "candidate-user", ObservedAt: time.Now().UTC()})
				if historical {
					if err == nil {
						err = tx.Commit(ctx)
					}
					if err == nil {
						t.Fatal("historical request acquired replacement binding")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if mode == "paired_immediate" {
						if _, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
							t.Fatal(err)
						}
					}
					if mode == "rollback" {
						err = tx.Rollback(ctx)
					} else {
						err = tx.Commit(ctx)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			_ = tx.Rollback(ctx)
			var bindings int
			if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM public.tsw_rotation_join_personal_bindings WHERE slot_id=$1`, slot).Scan(&bindings); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "atomic" || mode == "paired_immediate" {
				want = 1
			}
			if bindings != want || before != executionSources(t, f) {
				t.Fatalf("bindings=%d want=%d or changed sources", bindings, want)
			}
			if want == 0 && !historical && (executionEvents(t, f, slot) != 0 || executionState(t, f, slot) != "ready") {
				t.Fatal("request/binding failure left half marker")
			}
		})
	}
}

func TestRotationJoinMembershipEvidenceTerminalPairing(t *testing.T) {
	for _, mode := range []string{"orphan_commit", "orphan_immediate", "other_attempt", "wrong_outcome", "wrong_start", "valid_pair", "paired_immediate", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, _ := membershipDispatched(t)
			ctx := context.Background()
			if mode == "other_attempt" {
				if err := f.h.reconcileRotationJoinMembership(ctx, o, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
					t.Fatal(err)
				}
			}
			l := executionClaim(t, f, o, slot, time.Minute)
			before := executionSources(t, f)
			var initialRows int
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&initialRows); err != nil {
				t.Fatal(err)
			}
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			observed := time.Now().UTC()
			_, err = tx.Exec(ctx, `INSERT INTO public.tsw_rotation_join_membership_evidence(slot_id,reconciliation_attempt,observed_at,source,result,candidate_identifier,seat_type,workspace_id,lease_epoch,lease_owner,lease_token,owner_session,diagnostic,evidence_digest,reconcile_start_event_id) SELECT e.slot_id,j.attempt_no,$5,'personal_session_members','unknown',e.candidate_identifier,e.seat_type,e.workspace_id,e.lease_epoch,$2,$3,$4,'membership_unknown',public.tsw_rotation_join_membership_digest(e.slot_id,j.attempt_no,$5,'personal_session_members','unknown',NULL,e.candidate_identifier,e.seat_type,e.workspace_id,e.lease_epoch,'membership_unknown'),CASE WHEN $6::boolean THEN gen_random_uuid() ELSE j.id END FROM public.tsw_rotation_join_executions e JOIN public.tsw_rotation_join_execution_attempts j ON j.slot_id=e.slot_id AND j.lease_epoch=e.lease_epoch AND j.stage='reconcile' AND j.event_kind='started' WHERE e.slot_id=$1`, slot, l.workerID, l.token, o.SessionID, observed, mode == "wrong_start")
			if mode == "wrong_start" {
				if err == nil {
					t.Fatal("evidence accepted wrong start identity")
				}
				_ = tx.Rollback(ctx)
				var count int
				if dbErr := f.pool.QueryRow(ctx, `SELECT count(*) FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&count); dbErr != nil || count != initialRows || before != executionSources(t, f) {
					t.Fatal("wrong start left half row or changed sources")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			paired := mode == "wrong_outcome" || mode == "valid_pair" || mode == "paired_immediate" || mode == "rollback"
			if paired {
				outcome := "uncertain"
				if mode == "wrong_outcome" {
					outcome = "succeeded"
				}
				_, err = tx.Exec(ctx, `INSERT INTO public.tsw_rotation_join_execution_attempts(slot_id,lease_epoch,stage,attempt_no,event_kind,start_event_id,may_have_reached,outcome,started_at,finished_at) SELECT slot_id,lease_epoch,stage,attempt_no,'finished',id,false,$3,started_at,clock_timestamp() FROM public.tsw_rotation_join_execution_attempts WHERE slot_id=$1 AND lease_epoch=$2 AND stage='reconcile' AND event_kind='started'`, slot, l.epoch, outcome)
				if err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(ctx, `UPDATE public.tsw_rotation_join_executions SET last_outcome=$2,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE slot_id=$1`, slot, outcome)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "orphan_immediate" || mode == "paired_immediate" {
				_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
			}
			if mode == "rollback" {
				err = tx.Rollback(ctx)
			} else if err == nil {
				err = tx.Commit(ctx)
			}
			valid := mode == "valid_pair" || mode == "paired_immediate" || mode == "rollback"
			if valid && err != nil {
				t.Fatal(err)
			}
			if !valid && err == nil {
				t.Fatal("orphan/mismatched evidence committed")
			}
			_ = tx.Rollback(ctx)
			var rows int
			if dbErr := f.pool.QueryRow(ctx, `SELECT count(*) FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&rows); dbErr != nil {
				t.Fatal(dbErr)
			}
			want := initialRows
			if mode == "valid_pair" || mode == "paired_immediate" {
				want++
			}
			if rows != want || before != executionSources(t, f) || executionState(t, f, slot) != "reconcile_required" {
				t.Fatalf("half evidence rows=%d want=%d or source/obligation changed", rows, want)
			}
		})
	}
}

func TestRotationJoinMembershipStopDuringReadOnlyGET(t *testing.T) {
	for _, phase := range []string{"identity", "members"} {
		t.Run(phase, func(t *testing.T) {
			f, o, slot, d := membershipDispatched(t)
			d.membershipBody = fmt.Sprintf(`{"complete":true,"members":[{"kind":"member","platform_member_id":"member","identifier":%q,"status":"active","seat_type":"prolite"}]}`, f.preview.Candidates[0].Identifier)
			posts := len(d.paths)
			entered, release := make(chan struct{}), make(chan struct{})
			hook := func() { close(entered); <-release }
			if phase == "identity" {
				d.identityHook = hook
			} else {
				d.membershipHook = hook
			}
			run := make(chan error, 1)
			go func() {
				run <- f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute)
			}()
			select {
			case <-entered:
			case err := <-run:
				t.Fatalf("did not reach GET: %v", err)
			case <-time.After(8 * time.Second):
				t.Fatal("GET did not start")
			}
			controlHandler := *f.h
			controlHandler.pool = f.pool
			stop := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				stop <- removalRequest(&controlHandler, f.session, f.csrf, "POST", f.preview.Id, uuid.Nil, "stop", map[string]any{"confirmed": true})
			}()
			var response *httptest.ResponseRecorder
			select {
			case response = <-stop:
			case <-time.After(2 * time.Second):
				close(release)
				<-run
				<-stop
				t.Fatal("read-only GET blocked StopRotationRemoval")
			}
			if response.Code != 200 {
				close(release)
				<-run
				t.Fatalf("stop=%d %s", response.Code, response.Body.String())
			}
			afterStop := executionSources(t, f)
			close(release)
			if err := <-run; !errors.Is(err, joinDispatchReconcileRequired) {
				t.Fatal(err)
			}
			if membershipResult(t, f, slot) != "unknown" || posts != len(d.paths) || afterStop != executionSources(t, f) || executionState(t, f, slot) != "reconcile_required" {
				t.Fatal("stopped GET became confirmed, replayed POST or changed original source/obligation")
			}
		})
	}
}

func TestRotationJoinMembershipSchema33JournalGuards(t *testing.T) {
	f, o, slot, d := dispatchFixture(t)
	ctx := context.Background()
	before := executionSources(t, f)
	i, p := membershipSQLAdmission(t, f, o, slot)
	l := executionClaim(t, f, o, slot, time.Minute)
	reject := func(assignments string) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `UPDATE public.tsw_rotation_join_executions SET `+assignments+` WHERE slot_id=$1`, slot); err == nil {
			t.Fatalf("schema33 accepted forged transition: %s", assignments)
		}
	}
	reject(`state='request_succeeded',request_attempt_count=1,request_may_have_reached=true,last_stage='request_join',last_outcome='succeeded'`)
	reject(`state='accept_started',request_attempt_count=1,accept_attempt_count=1,request_may_have_reached=true,accept_may_have_reached=true,last_stage='accept_join',last_outcome='started'`)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = markRotationJoinStageInTx(ctx, tx, l, "ready", "request_join", "", nil); err != nil {
		t.Fatal(err)
	}
	if err = appendJoinPersonalBinding(ctx, tx, l, i, p, platform.PersonalIdentity{Identifier: i.candidateIdentifier, SubjectID: "candidate-user", ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	reject(`state='request_succeeded',last_outcome='succeeded'`)
	reject(`state='accept_started',accept_attempt_count=1,accept_may_have_reached=true,last_stage='accept_join',last_outcome='started'`)
	if err = f.h.finishRotationJoinStage(ctx, l, "request_join", "succeeded", true); err != nil {
		t.Fatal(err)
	}
	reject(`state='accept_started',accept_attempt_count=1,accept_may_have_reached=true,last_stage='accept_join',last_outcome='started'`)
	if err = f.h.markRotationJoinStageStarted(ctx, l, "accept_join"); err != nil {
		t.Fatal(err)
	}
	reject(`state='request_succeeded',last_stage='request_join',last_outcome='succeeded'`)
	if err = f.h.finishRotationJoinStage(ctx, l, "accept_join", "uncertain", true); err != nil {
		t.Fatal(err)
	}
	if before != executionSources(t, f) || len(d.paths) != 0 || executionState(t, f, slot) != "reconcile_required" {
		t.Fatal("schema33 guard exercise wrote source, sent HTTP, or changed obligation")
	}
}

func TestRotationJoinMembershipRosterIdentityCollisions(t *testing.T) {
	for _, field := range []string{"platform_member_id", "platform_account_user_id"} {
		for _, present := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/present=%v", field, present), func(t *testing.T) {
				f, o, slot, d := membershipDispatched(t)
				identifier := f.preview.Candidates[0].Identifier
				if !present {
					identifier = "other@example.test"
				}
				first := platform.Member{Kind: "member", PlatformMemberID: "one", PlatformAccountUserID: "user-one", Identifier: identifier, Status: "active", SeatType: "prolite"}
				second := platform.Member{Kind: "member", PlatformMemberID: "two", PlatformAccountUserID: "user-two", Identifier: "second@example.test", Status: "active", SeatType: "prolite"}
				if field == "platform_member_id" {
					second.PlatformMemberID = first.PlatformMemberID
				} else {
					second.PlatformAccountUserID = first.PlatformAccountUserID
				}
				body, err := json.Marshal(map[string]any{"complete": true, "members": []platform.Member{first, second}})
				if err != nil {
					t.Fatal(err)
				}
				d.membershipBody = string(body)
				before := executionSources(t, f)
				posts := len(d.paths)
				if err = f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
					t.Fatal(err)
				}
				var diagnostic string
				if err = f.pool.QueryRow(context.Background(), `SELECT diagnostic FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=$1`, slot).Scan(&diagnostic); err != nil || diagnostic != "membership_duplicate_identity" {
					t.Fatalf("diagnostic=%s err=%v", diagnostic, err)
				}
				if membershipResult(t, f, slot) != "unknown" || posts != len(d.paths) || before != executionSources(t, f) {
					t.Fatal("colliding roster confirmed/absent, replayed POST or changed sources")
				}
			})
		}
	}
}
