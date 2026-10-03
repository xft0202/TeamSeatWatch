//go:build integration

package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

type dispatchTransport struct {
	t                           *testing.T
	f                           *removalFixture
	slot                        uuid.UUID
	session                     platform.PersonalSession
	paths                       []string
	hook                        func(string)
	identity                    string
	identityToken               string
	role, remoteWorkspace, seat string
	incomplete                  bool
	responseBody                string
	membershipBody              string
	membershipStatus            int
	membershipHook              func()
	identityHook                func()
	remoteError                 error
	gateConn                    *pgx.Conn
	route                       *dispatchRoute
}

type dispatchTracer struct {
	d      *dispatchTransport
	before func(*pgx.Conn, string)
}

func (tr dispatchTracer) TraceQueryStart(ctx context.Context, c *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT version FROM public.tsw_rotation_epochs") {
		tr.d.gateConn = c
	}
	if tr.before != nil {
		tr.before(c, data.SQL)
	}
	return ctx
}
func (dispatchTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (d *dispatchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	d.t.Helper()
	if d.gateConn != nil && d.gateConn.PgConn().TxStatus() != 'I' {
		d.t.Fatal("network inside source transaction")
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/backend-api/accounts/check/") {
		return removalHTTPResponse(200, `{"accounts":{"selected":{"account":{"account_id":"`+d.remoteWorkspace+`","name":"fixture","plan_type":"team","structure":"workspace","workspace_role":"`+d.role+`"}}}}`), nil
	}
	if r.Method == "GET" && r.URL.Path == "/backend-api/subscriptions" {
		if r.URL.Query().Get("account_id") != d.f.space.String() {
			d.t.Fatal("wrong Workspace subscription scope")
		}
		return removalHTTPResponse(200, `{"active_until":"2026-01-01T00:00:00Z","seats_in_use":0,"seats_entitled":2,"seat_capacity":[{"type":"default","paid":2}]}`), nil
	}
	if r.Method == "GET" && r.URL.Path == "/backend-api/accounts/"+d.f.space.String()+"/users/seat_type_counts" {
		return removalHTTPResponse(200, `{"seat_type_counts":{"default":0,"usage_based":0,"automation":0,"prolite":0}}`), nil
	}
	if r.Method == "GET" && r.URL.Path == "/backend-api/accounts/"+d.f.space.String()+"/users" {
		body := `{"items":[],"total":0,"offset":0,"limit":100}`
		if d.incomplete {
			body = `{"items":[],"total":1,"offset":0,"limit":100}`
		}
		return removalHTTPResponse(200, body), nil
	}
	if r.Method == "GET" && r.URL.Path == "/backend-api/accounts/"+d.f.space.String()+"/invites" {
		return removalHTTPResponse(200, `{"items":[{"email_address":"`+d.f.preview.Candidates[0].Identifier+`","status":"pending","seat_type":"`+d.seat+`"}],"total":1,"offset":0,"limit":100}`), nil
	}
	if r.Method == "GET" && r.URL.Path == "/api/auth/session" {
		if d.identityHook != nil {
			d.identityHook()
		}
		identifier := d.f.preview.Candidates[0].Identifier
		if d.identity != "" {
			identifier = d.identity
		}
		token := d.session.AccessToken
		if d.identityToken != "" {
			token = d.identityToken
		}
		raw, _ := json.Marshal(map[string]any{"accessToken": token, "expires": d.session.ExpiresAt.Format(time.RFC3339Nano), "user": map[string]string{"email": identifier}})
		return removalHTTPResponse(200, string(raw)), nil
	}
	if r.Method == "GET" && r.URL.Path == "/workspaces/"+d.f.space.String()+"/members" {
		body := d.membershipBody
		if body == "" {
			body = `{"complete":true,"members":[]}`
		}
		if d.membershipHook != nil {
			d.membershipHook()
		}
		status := d.membershipStatus
		if status == 0 {
			status = 200
		}
		return removalHTTPResponse(status, body), nil
	}
	if r.Method != "POST" || !strings.HasPrefix(r.URL.Path, "/backend-api/accounts/"+d.f.space.String()+"/invites/") {
		d.t.Fatalf("unexpected request %s %s", r.Method, r.URL)
	}
	stage := "request_join"
	if strings.HasSuffix(r.URL.Path, "/accept") {
		stage = "accept_join"
	}
	var marked bool
	if err := d.f.pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tsw_rotation_join_execution_attempts WHERE slot_id=$1 AND stage=$2 AND event_kind='started' AND may_have_reached)`, d.slot, stage).Scan(&marked); err != nil || !marked {
		d.t.Fatalf("POST preceded durable marker: %v %v", marked, err)
	}
	d.paths = append(d.paths, stage)
	if d.hook != nil {
		d.hook(stage)
	}
	if d.remoteError != nil {
		return nil, d.remoteError
	}
	body := d.responseBody
	if body == "" {
		body = `{"success":true}`
	}
	return removalHTTPResponse(200, body), nil
}

type dispatchRoute struct {
	client  *http.Client
	measure func() error
}

func (r *dispatchRoute) Client() *http.Client { return r.client }
func (r *dispatchRoute) Remeasure(context.Context) error {
	if r.measure != nil {
		return r.measure()
	}
	return nil
}
func (*dispatchRoute) Release() {}

func dispatchFixture(t *testing.T, noFirstUse ...bool) (*removalFixture, ownerContext, uuid.UUID, *dispatchTransport) {
	t.Helper()
	f := newJoinFixture(t, 1, noFirstUse...)
	slot := joinReleased(t, f)
	owner := joinOwner(t, f)
	if _, err := f.h.reserveRotationJoinIntent(context.Background(), owner, f.preview.Id, slot); err != nil {
		t.Fatal(err)
	}
	id := f.preview.Candidates[0].AccountId
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	claims := map[string]any{"exp": expiry.Unix(), "sub": "auth0|candidate", "email": f.preview.Candidates[0].Identifier, "amr": []string{"urn:openai:amr:otp_totp"}, "https://api.openai.com/mfa": map[string]any{"required": true}, "https://api.openai.com/auth": map[string]any{"client_id": "app_X8zY6vW2pQ9tR3dE7nK1jL5gH", "chatgpt_account_id": "personal-account", "chatgpt_user_id": "candidate-user", "chatgpt_plan_type": "free", "scope": "openid email profile offline_access model.request model.read organization.read organization.write"}}
	raw, _ := json.Marshal(claims)
	session := platform.PersonalSession{AccessToken: "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".fixture", ExpiresAt: expiry, DeviceID: "fixture-device", Cookies: []platform.SessionCookie{{Name: "__Secure-next-auth.session-token", Value: "secret-cookie"}}}
	version, nonce, sealed, err := sealSessionFor("target", f.h.keyRing, id, 1, session)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO tsw_target_personal_access(target_account_id,secret_revision,status) VALUES($1,1,'ready')`, id)
	f.exec(t, `INSERT INTO tsw_target_personal_sessions(target_account_id,secret_revision,attempt,generation,key_version,nonce,sealed_session,expires_at) VALUES($1,1,1,$2,$3,$4,$5,$6)`, id, uuid.New(), version, nonce, sealed, expiry)
	d := &dispatchTransport{t: t, f: f, slot: slot, session: session, role: "owner", remoteWorkspace: f.space.String(), seat: "prolite"}
	route := &dispatchRoute{client: &http.Client{Timeout: time.Second, Transport: d}}
	f.h.rotationJoinEgress = func(context.Context) (rotationJoinEgress, error) { return route, nil }
	d.route = route
	f.h.rotationJoinAdapters = officialRotationJoinAdapters
	config, err := pgxpool.ParseConfig(os.Getenv("TSW_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	config.ConnConfig.Tracer = dispatchTracer{d: d}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.h.pool = pool
	return f, owner, slot, d
}
func TestRotationJoinDispatchRejectsPinnedGenerationChange(t *testing.T) {
	f, owner, slot, d := dispatchFixture(t)
	d.route.measure = func() error {
		_, err := d.gateConn.Exec(context.Background(), `UPDATE public.tsw_target_personal_sessions SET generation=$2 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId, uuid.New())
		return err
	}
	err := f.h.dispatchRotationCandidateJoin(context.Background(), owner, f.preview.Id, slot, uuid.New(), time.Minute)
	if err == nil || len(d.paths) != 0 || executionEvents(t, f, slot) != 0 {
		t.Fatalf("generation substituted: paths=%v err=%v", d.paths, err)
	}
}

func TestRotationJoinDispatchPreflightBlocks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *removalFixture, ownerContext, uuid.UUID, *dispatchTransport)
	}{
		{"wrong_workspace", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			d.remoteWorkspace = uuid.NewString()
		}},
		{"not_owner", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			d.role = "member"
		}},
		{"wrong_identifier", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			d.identity = "wrong@example.test"
		}},
		{"changed_authenticated_token", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			d.identityToken = "different-token"
		}},
		{"incomplete_roster", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			d.incomplete = true
		}},
		{"wrong_seat", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			d.seat = "default"
		}},
		{"db_decoded_expiry", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			f.exec(t, `UPDATE tsw_target_personal_sessions SET expires_at=expires_at-interval '1 second' WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId)
		}},
		{"attempt_mismatch", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			f.exec(t, `UPDATE tsw_target_personal_access SET attempt=attempt+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId)
		}},
		{"wrong_subject", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			f.exec(t, `UPDATE tsw_target_credentials SET platform_subject_id='another-user',version=version+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId)
		}},
		{"protection", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			f.exec(t, `INSERT INTO tsw_rotation_global_protections(target_account_id,status,evidence_source,evidence_id,observed_at) VALUES($1,'delivered','fixture',repeat('f',64),clock_timestamp())`, f.preview.Candidates[0].AccountId)
		}},
		{"usage_history", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			f.exec(t, `UPDATE tsw_rotation_usage_ledger SET ever_used=true,usage_state='used',version=version+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId)
		}},
		{"stop", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			f.exec(t, `UPDATE tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
		}},
		{"missing_adapters", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			f.h.rotationJoinAdapters = nil
		}},
		{"missing_egress", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			f.h.rotationJoinEgress = nil
		}},
		{"egress_drift", func(t *testing.T, f *removalFixture, o ownerContext, s uuid.UUID, d *dispatchTransport) {
			d.route.measure = func() error { return errors.New("secret proxy URL") }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, o, s, d := dispatchFixture(t)
			tc.change(t, f, o, s, d)
			before := executionSources(t, f)
			err := f.h.dispatchRotationCandidateJoin(context.Background(), o, f.preview.Id, s, uuid.New(), time.Minute)
			if err == nil || len(d.paths) != 0 || executionEvents(t, f, s) != 0 || before != executionSources(t, f) {
				t.Fatalf("unsafe preflight paths=%v err=%v", d.paths, err)
			}
		})
	}
}

func TestRotationJoinDispatchBetweenStageDrift(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
		args func(*removalFixture, ownerContext) []any
	}{
		{"generation", `UPDATE tsw_target_personal_sessions SET generation=$2 WHERE target_account_id=$1`, func(f *removalFixture, o ownerContext) []any {
			return []any{f.preview.Candidates[0].AccountId, uuid.New()}
		}},
		{"attempt", `UPDATE tsw_target_personal_access SET attempt=attempt+1 WHERE target_account_id=$1`, func(f *removalFixture, o ownerContext) []any { return []any{f.preview.Candidates[0].AccountId} }},
		{"revision", `UPDATE tsw_target_personal_sessions SET secret_revision=secret_revision+1 WHERE target_account_id=$1`, func(f *removalFixture, o ownerContext) []any { return []any{f.preview.Candidates[0].AccountId} }},
		{"owner_revoked", `UPDATE tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE id=$1`, func(f *removalFixture, o ownerContext) []any { return []any{o.SessionID} }},
		{"owner_clock", `UPDATE tsw_owner_sessions SET idle_expires_at=clock_timestamp() WHERE id=$1`, func(f *removalFixture, o ownerContext) []any { return []any{o.SessionID} }},
		{"stopped", `UPDATE tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, func(f *removalFixture, o ownerContext) []any { return []any{f.preview.Id} }},
		{"authorization_revoked", `UPDATE tsw_expiry_rotation_previews SET status='revoked',revoked_at=clock_timestamp(),revoked_by=owner_id WHERE id=$1`, func(f *removalFixture, o ownerContext) []any { return []any{f.preview.Id} }},
		{"source_epoch", `UPDATE tsw_target_accounts SET version=version+1 WHERE id=$1`, func(f *removalFixture, o ownerContext) []any { return []any{f.preview.Candidates[0].AccountId} }},
		{"gate_lost", `SELECT pg_advisory_unlock_all()`, func(f *removalFixture, o ownerContext) []any { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, o, s, d := dispatchFixture(t)
			d.hook = func(stage string) {
				if stage == "request_join" {
					if _, err := d.gateConn.Exec(context.Background(), tc.sql, tc.args(f, o)...); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := f.h.dispatchRotationCandidateJoin(context.Background(), o, f.preview.Id, s, uuid.New(), time.Minute)
			if err == nil || strings.Join(d.paths, ",") != "request_join" {
				t.Fatalf("drift sent accept paths=%v err=%v", d.paths, err)
			}
			var retained bool
			if err = f.pool.QueryRow(context.Background(), `SELECT request_may_have_reached AND NOT accept_may_have_reached FROM tsw_rotation_join_executions WHERE slot_id=$1`, s).Scan(&retained); err != nil || !retained {
				t.Fatal("lost original sent obligation", err)
			}
		})
	}
}

func TestRotationJoinDispatchSecondAdmission(t *testing.T) {
	for _, mode := range []string{"identity", "invite_seat", "owner_role", "incomplete_read", "egress_drift", "identity_deadline"} {
		t.Run(mode, func(t *testing.T) {
			f, o, s, d := dispatchFixture(t)
			d.hook = func(stage string) {
				if stage != "request_join" {
					return
				}
				switch mode {
				case "identity":
					d.identity = "wrong@example.test"
				case "invite_seat":
					d.seat = "default"
				case "owner_role":
					d.role = "member"
				case "incomplete_read":
					d.incomplete = true
				case "egress_drift":
					d.route.measure = func() error { return errors.New("egress drift") }
				case "identity_deadline":
					d.session.ExpiresAt = d.session.ExpiresAt.Add(-time.Minute)
				}
			}
			before := executionSources(t, f)
			err := f.h.dispatchRotationCandidateJoin(context.Background(), o, f.preview.Id, s, uuid.New(), time.Minute)
			if err == nil || strings.Join(d.paths, ",") != "request_join" || before != executionSources(t, f) {
				t.Fatalf("second admission bypassed %v %v", d.paths, err)
			}
			if executionState(t, f, s) != "request_succeeded" || executionEvents(t, f, s) != 2 {
				t.Fatal("second admission failure changed request obligation")
			}
		})
	}
}

func TestRotationJoinDispatchReceiptUncertaintyAndTakeover(t *testing.T) {
	for _, mode := range []string{"ambiguous", "semantic_failure", "cancel", "write_failure", "lease_expiry"} {
		t.Run(mode, func(t *testing.T) {
			f, o, s, d := dispatchFixture(t)
			duration := 500 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "ambiguous":
				d.responseBody = `{}`
			case "semantic_failure":
				d.responseBody = `{"success":false}`
			case "cancel":
				d.hook = func(string) { cancel() }
				d.remoteError = context.Canceled
			case "lease_expiry":
				duration = 500 * time.Millisecond
				d.hook = func(string) { time.Sleep(550 * time.Millisecond) }
			case "write_failure":
				f.exec(t, `CREATE FUNCTION public.dispatch_test_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_kind='finished' THEN RAISE EXCEPTION 'fixture receipt write failure'; END IF; RETURN NEW; END$$`)
				f.exec(t, `CREATE TRIGGER dispatch_test_receipt_failure BEFORE INSERT ON public.tsw_rotation_join_execution_attempts FOR EACH ROW EXECUTE FUNCTION public.dispatch_test_receipt_failure()`)
			}
			before := executionSources(t, f)
			err := f.h.dispatchRotationCandidateJoin(ctx, o, f.preview.Id, s, uuid.New(), duration)
			if err == nil || strings.Join(d.paths, ",") != "request_join" || before != executionSources(t, f) {
				t.Fatalf("unsafe receipt paths=%v err=%v", d.paths, err)
			}
			if mode == "write_failure" {
				f.exec(t, `DROP TRIGGER dispatch_test_receipt_failure ON public.tsw_rotation_join_execution_attempts`)
				f.exec(t, `DROP FUNCTION public.dispatch_test_receipt_failure()`)
			}
			f.exec(t, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM (lease_expires_at-clock_timestamp())))+0.01) FROM public.tsw_rotation_join_executions WHERE slot_id=$1`, s)
			d.paths = nil
			d.hook = nil
			d.remoteError = nil
			if err = f.h.dispatchRotationCandidateJoin(context.Background(), o, f.preview.Id, s, uuid.New(), time.Minute); err != joinDispatchReconcileRequired || len(d.paths) != 0 {
				t.Fatalf("takeover replayed unknown obligation %v %v", d.paths, err)
			}
		})
	}
}

func TestRotationJoinDispatchNoFirstUseSynthesis(t *testing.T) {
	f, o, s, d := dispatchFixture(t, true)
	before := executionSources(t, f)
	err := f.h.dispatchRotationCandidateJoin(context.Background(), o, f.preview.Id, s, uuid.New(), time.Minute)
	var count int
	if queryErr := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_rotation_usage_ledger WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId).Scan(&count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if err != joinDispatchReconcileRequired || len(d.paths) != 2 || count != 0 || before != executionSources(t, f) {
		t.Fatalf("first-use absence was blocked or synthesized paths=%v count=%d err=%v", d.paths, count, err)
	}
}

func TestRotationJoinDispatchLostGate(t *testing.T) {
	f, o, s, d := dispatchFixture(t)
	// The epoch writer is deliberately run on the preflight's own gate session
	// to simulate drift; normal external writers are blocked by action gates.
	d.route.measure = func() error {
		_, err := d.gateConn.Exec(context.Background(), `SELECT pg_advisory_unlock_all()`)
		return err
	}
	before := executionSources(t, f)
	err := f.h.dispatchRotationCandidateJoin(context.Background(), o, f.preview.Id, s, uuid.New(), time.Minute)
	if err == nil || len(d.paths) != 0 || before != executionSources(t, f) {
		t.Fatal("lost gates dispatched or synthesized facts")
	}
}

func TestRotationJoinDispatchCurrentSubjectBinding(t *testing.T) {
	f, o, s, d := dispatchFixture(t)
	ctx := context.Background()
	i, err := f.h.loadRotationJoinIntent(ctx, o, f.preview.Id, s)
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
	p, err := f.h.joinAdmissionLocal(ctx, tx, a, i, o, versions)
	_ = tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	factory := func(context.Context) (*http.Client, func(), error) { return d.route.client, nil, nil }
	for _, subject := range []string{"candidate-user", "auth0|candidate", "wrong-user"} {
		p.binding.Subject = subject
		identity, _, err := joinRemoteAdmission(ctx, officialRotationJoinAdapters(factory), a, i, p)
		if subject == "candidate-user" {
			if err != nil || identity.SubjectID != subject {
				t.Fatal("canonical subject rejected", err)
			}
		} else if err == nil {
			t.Fatal("noncanonical current credential subject admitted")
		}
	}
}

func TestRotationCandidatePersonalGateCoverage(t *testing.T) {
	f, o, _, _ := dispatchFixture(t)
	ctx := context.Background()
	id := f.preview.Candidates[0].AccountId
	a, err := loadRemovalAuthorization(ctx, f.pool, uuid.MustParse(o.OwnerID), f.preview.Id)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := f.h.lockRemovalGate(ctx, f.space, rotationAuthorizationKeys(uuid.MustParse(o.OwnerID), a.preview))
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	before := executionSources(t, f)
	for _, query := range []string{
		`INSERT INTO public.tsw_target_personal_access SELECT * FROM public.tsw_target_personal_access WHERE target_account_id=$1 ON CONFLICT DO NOTHING`,
		`UPDATE public.tsw_target_personal_access SET status='verifying' WHERE target_account_id=$1`,
		`DELETE FROM public.tsw_target_personal_access WHERE target_account_id=$1`,
		`INSERT INTO public.tsw_target_personal_sessions SELECT * FROM public.tsw_target_personal_sessions WHERE target_account_id=$1 ON CONFLICT DO NOTHING`,
		`UPDATE public.tsw_target_personal_sessions SET generation=gen_random_uuid() WHERE target_account_id=$1`,
		`DELETE FROM public.tsw_target_personal_sessions WHERE target_account_id=$1`,
	} {
		blocked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		_, err := f.pool.Exec(blocked, query, id)
		cancel()
		if err == nil {
			t.Fatalf("unfenced writer: %s", query)
		}
	}
	if before != executionSources(t, f) {
		t.Fatal("fenced writer changed source or epoch")
	}
	writer := *f.h
	writer.pool = f.pool
	blocked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = writer.reserveTargetRefresh(blocked, id)
	cancel()
	if err == nil {
		t.Fatal("refresh reservation was unfenced")
	}
	if before != executionSources(t, f) {
		t.Fatal("blocked refresh deleted pinned generation")
	}
	gate.close()
	var oldEpoch, newEpoch int64
	if err = f.pool.QueryRow(ctx, `SELECT version FROM public.tsw_rotation_epochs WHERE kind='target_account' AND id=$1`, id).Scan(&oldEpoch); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.reserveTargetRefresh(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = f.pool.QueryRow(ctx, `SELECT version FROM public.tsw_rotation_epochs WHERE kind='target_account' AND id=$1`, id).Scan(&newEpoch); err != nil || oldEpoch != newEpoch {
		t.Fatal("Personal refresh renewed frozen authorization", err)
	}
}

func TestRotationCandidateRefreshReservationRowOrder(t *testing.T) {
	f, _, _, _ := dispatchFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := f.preview.Candidates[0].AccountId
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM public.tsw_target_accounts WHERE id=$1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	writer := *f.h
	writer.pool = f.pool
	done := make(chan error, 1)
	go func() { _, err := writer.reserveTargetRefresh(ctx, id); done <- err }()
	for {
		var waiting bool
		if err = f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FOR UPDATE OF target,credential%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("reservation bypassed row lock: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	bounded, stop := context.WithTimeout(ctx, time.Second)
	_, err = tx.Exec(bounded, `SELECT pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||$1::text,0))`, id.String())
	stop()
	if err != nil {
		t.Fatal("refresh inverted row-first fact writers", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestRotationCandidateRefreshPublicationLockOrder(t *testing.T) {
	f, o, _, d := dispatchFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := f.preview.Candidates[0].AccountId
	writer := *f.h
	writer.pool = f.pool
	refresher := &sequencedPersonalRefresh{entered: make(chan struct{}), release: make(chan struct{}), session: d.session}
	writer.personalRefresh = refresher
	request := httptest.NewRequest("POST", "/api/owner/v1/target-accounts/"+id.String()+"/personal-session", nil).WithContext(ctx)
	request.Header.Set("Origin", "https://owner.test")
	request.Header.Set(auth.CSRFHeaderName, f.csrf)
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: f.csrf})
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: f.session})
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		writer.RefreshTargetPersonalAccess(w, request, id, ownerapi.RefreshTargetPersonalAccessParams{})
		result <- w
	}()
	select {
	case <-refresher.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	conn, err := f.h.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gate := &removalGate{conn: conn}
	defer gate.close()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock_shared(hashtextextended('tsw.rotation.action.owner/'||$1::text,0))`, o.OwnerID); err != nil {
		t.Fatal(err)
	}
	close(refresher.release)
	// Publication must be waiting at Owner, not holding candidate while it
	// waits for Owner. This is the previously inverted owner-session rotation.
	for {
		var waiting bool
		if err = f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE '%tsw.rotation.action.owner/%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case w := <-result:
			t.Fatalf("publication bypassed Owner gate %d %s", w.Code, w.Body.String())
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	bounded, stop := context.WithTimeout(ctx, time.Second)
	_, err = conn.Exec(bounded, `SELECT pg_advisory_lock_shared(hashtextextended('tsw.rotation.action.target_account/'||$1::text,0))`, id.String())
	stop()
	if err != nil {
		t.Fatal("candidate-first/owner-second publication inversion", err)
	}
	gate.close()
	select {
	case w := <-result:
		if w.Code != 200 {
			t.Fatalf("publication failed %d %s", w.Code, w.Body.String())
		}
	case <-ctx.Done():
		t.Fatal("publication deadlocked", ctx.Err())
	}
}

func TestRotationJoinDispatchMarkedSplit(t *testing.T) {
	f, owner, slot, d := dispatchFixture(t)
	before := executionSources(t, f)
	err := f.h.dispatchRotationCandidateJoin(context.Background(), owner, f.preview.Id, slot, uuid.New(), time.Minute)
	if err != joinDispatchReconcileRequired || strings.Join(d.paths, ",") != "request_join,accept_join" || executionState(t, f, slot) != "reconcile_required" || executionEvents(t, f, slot) != 4 {
		t.Fatalf("split=%v state=%s err=%v", d.paths, executionState(t, f, slot), err)
	}
	if before != executionSources(t, f) {
		t.Fatal("dispatcher wrote a source, credential, membership or usage fact")
	}
	d.paths = nil
	if err = f.h.dispatchRotationCandidateJoin(context.Background(), owner, f.preview.Id, slot, uuid.New(), time.Minute); err != joinDispatchReconcileRequired || len(d.paths) != 0 {
		t.Fatalf("takeover replay=%v err=%v", d.paths, err)
	}
}
