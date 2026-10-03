//go:build integration

package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

type credentialMock struct {
	t                    *testing.T
	f                    *removalFixture
	slot                 uuid.UUID
	webCalls, oauthCalls int
	web                  platform.WorkspaceAccess
	oauth                platform.DeliveryCredentialSet
	hook                 func(string)
	fail                 string
}

func (m *credentialMock) marker(stage string) {
	m.t.Helper()
	var exists bool
	if err := m.f.pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_events ev JOIN public.tsw_rotation_join_credential_attempts a USING(attempt_id) WHERE a.slot_id=$1 AND ev.stage=$2 AND ev.event='started')`, m.slot, stage).Scan(&exists); err != nil || !exists {
		m.t.Fatal("credential action without durable marker", err)
	}
	if m.hook != nil {
		m.hook(stage)
	}
}
func (m *credentialMock) ExchangeCandidateWorkspace(_ context.Context, p platform.PersonalSession, w, u string) (platform.WorkspaceAccess, error) {
	m.webCalls++
	m.marker("web")
	if w != m.f.space.String() || u != "candidate-user" || p.AccessToken == "" {
		m.t.Fatal("wrong original exchange")
	}
	if m.fail == "web" {
		return platform.WorkspaceAccess{}, errors.New("untrusted secret failure")
	}
	return m.web, nil
}
func (m *credentialMock) CreateCandidateOAuth(_ context.Context, r platform.DeliveryCredentialRequest, u string) (platform.DeliveryCredentialSet, error) {
	m.oauthCalls++
	m.marker("oauth")
	if r.Workspace != m.f.space.String() || r.Identifier != m.f.preview.Candidates[0].Identifier || r.Password != "password" || r.TOTPSecret != "JBSWY3DPEHPK3PXP" || u != "candidate-user" {
		m.t.Fatal("wrong original grant")
	}
	if m.fail == "oauth" {
		return platform.DeliveryCredentialSet{}, errors.New("lost upstream response")
	}
	return m.oauth, nil
}
func credentialFixture(t *testing.T) (*removalFixture, ownerContext, uuid.UUID, *dispatchTransport, *credentialMock) {
	t.Helper()
	f, o, slot, d := membershipDispatched(t)
	d.membershipBody = fmt.Sprintf(`{"complete":true,"members":[{"kind":"member","platform_member_id":"original-member","platform_account_user_id":"candidate-user","identifier":%q,"status":"active","seat_type":"prolite"}]}`, f.preview.Candidates[0].Identifier)
	if err := f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
		t.Fatal(err)
	}
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	jwt := func(plan, scope string) string {
		b, _ := json.Marshal(map[string]any{"exp": expiry.Unix(), "sub": "auth0|candidate", "scope": scope, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": f.space.String(), "chatgpt_user_id": "candidate-user", "chatgpt_plan_type": plan}})
		return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".mock"
	}
	m := &credentialMock{t: t, f: f, slot: slot, web: platform.WorkspaceAccess{WorkspaceID: f.space.String(), AccessToken: jwt("k12", "organization.read"), DeviceID: "original-device", SessionID: uuid.NewString(), ExpiresAt: expiry, Cookies: []platform.SessionCookie{{Name: "__Secure-next-auth.session-token", Value: "cookie"}, {Name: "_account", Value: f.space.String()}, {Name: "oai-workspace", Value: f.space.String()}}}, oauth: platform.DeliveryCredentialSet{WorkspaceID: f.space.String(), PlatformSubjectID: "candidate-user", AccessToken: jwt("team", platform.CodexScope), IDToken: jwt("team", platform.CodexScope), RefreshToken: "original-refresh", ExpiresIn: 3600, Scope: platform.CodexScope}}
	f.h.rotationCredentialAdapters = func(platform.DiscoveryClient) platform.RotationCredentialAdapter { return m }
	return f, o, slot, d, m
}
func credentialCounts(t *testing.T, f *removalFixture, slot uuid.UUID) (int, int, int) {
	t.Helper()
	var a, c, g int
	if err := f.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=$1),(SELECT count(*) FROM public.tsw_rotation_join_credential_components c JOIN public.tsw_rotation_join_credential_attempts a USING(attempt_id) WHERE a.slot_id=$1),(SELECT count(*) FROM public.tsw_rotation_join_credential_generations g JOIN public.tsw_rotation_join_credential_attempts a USING(attempt_id) WHERE a.slot_id=$1)`, slot).Scan(&a, &c, &g); err != nil {
		t.Fatal(err)
	}
	return a, c, g
}
func TestRotationJoinCredentialsSaveOriginalAndReplay(t *testing.T) {
	f, o, slot, d, m := credentialFixture(t)
	posts := len(d.paths)
	before := credentialSources(t, f)
	for n := 0; n < 2; n++ {
		if err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, n > 0); err != nil {
			t.Fatal(err)
		}
	}
	a, c, g := credentialCounts(t, f, slot)
	if before != credentialSources(t, f) || a != 1 || c != 2 || g != 1 || m.webCalls != 1 || m.oauthCalls != 1 || len(d.paths) != posts || executionState(t, f, slot) != "reconcile_required" {
		t.Fatalf("attempt=%d components=%d generations=%d web=%d oauth=%d", a, c, g, m.webCalls, m.oauthCalls)
	}
}

func credentialSources(t *testing.T, f *removalFixture) string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'tsw_%' AND tablename NOT LIKE 'tsw_rotation_join_credential_%' ORDER BY tablename`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	var result string
	for _, name := range tables {
		var data string
		if err = f.pool.QueryRow(context.Background(), `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text,'[]') FROM public.`+name+` t`).Scan(&data); err != nil {
			t.Fatal(err)
		}
		result += name + data
	}
	return rotationHash(result)
}
func TestRotationJoinCredentialsCheckpointFailureAndRepair(t *testing.T) {
	for _, stage := range []string{"attempt", "web_marker", "web", "oauth_marker", "oauth", "generation"} {
		t.Run(stage, func(t *testing.T) {
			f, o, slot, d, m := credentialFixture(t)
			before := credentialSources(t, f)
			posts := len(d.paths)
			table := "tsw_rotation_join_credential_components"
			predicate := "NEW.kind='" + stage + "'"
			switch stage {
			case "attempt":
				table = "tsw_rotation_join_credential_attempts"
				predicate = "true"
			case "web_marker", "oauth_marker":
				table = "tsw_rotation_join_credential_events"
				predicate = "NEW.stage='" + strings.TrimSuffix(stage, "_marker") + "'"
			case "generation":
				table = "tsw_rotation_join_credential_generations"
				predicate = "true"
			}
			f.exec(t, `CREATE FUNCTION public.fail_credential_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF `+predicate+` THEN RAISE EXCEPTION 'injected checkpoint failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_credential_checkpoint BEFORE INSERT ON public.`+table+` FOR EACH ROW EXECUTE FUNCTION public.fail_credential_checkpoint()`)
			err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false)
			if err == nil {
				t.Fatal("write failure published")
			}
			a, c, g := credentialCounts(t, f, slot)
			expectedC := 0
			if stage == "oauth_marker" || stage == "oauth" {
				expectedC = 1
			}
			if stage == "generation" {
				expectedC = 2
			}
			if c != expectedC || g != 0 || (stage == "attempt" && a != 0) {
				t.Fatalf("partial a=%d c=%d g=%d", a, c, g)
			}
			f.exec(t, `DROP TRIGGER fail_credential_checkpoint ON public.`+table+`; DROP FUNCTION public.fail_credential_checkpoint()`)
			restarted := *f.h
			err = restarted.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, stage != "attempt")
			uncertain := stage == "web" || stage == "oauth"
			if uncertain && !errors.Is(err, joinCredentialsReview) || !uncertain && err != nil {
				t.Fatalf("repair %s err=%v", stage, err)
			}
			a, c, g = credentialCounts(t, f, slot)
			if a != 1 || uncertain && g != 0 || !uncertain && (c != 2 || g != 1) || m.webCalls != 1 || (stage != "web" && m.oauthCalls != 1) || len(d.paths) != posts || before != credentialSources(t, f) {
				t.Fatalf("unsafe repair %s a=%d c=%d g=%d web=%d oauth=%d", stage, a, c, g, m.webCalls, m.oauthCalls)
			}
		})
	}
}
func TestRotationJoinCredentialsLostResponsePreservesAttempt(t *testing.T) {
	for _, stage := range []string{"web", "oauth"} {
		t.Run(stage, func(t *testing.T) {
			f, o, slot, d, m := credentialFixture(t)
			before := credentialSources(t, f)
			posts := len(d.paths)
			m.fail = stage
			for n := 0; n < 3; n++ {
				err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, n > 0)
				if !errors.Is(err, joinCredentialsReview) {
					t.Fatalf("lost response=%v", err)
				}
			}
			a, c, g := credentialCounts(t, f, slot)
			want := 0
			if stage == "oauth" {
				want = 1
			}
			if a != 1 || c != want || g != 0 || m.webCalls != 1 || m.oauthCalls != want || len(d.paths) != posts || before != credentialSources(t, f) {
				t.Fatal("lost response reissued or changed original obligation")
			}
		})
	}
}
func TestRotationJoinCredentialsRejectsIdentityCompletenessAndMembers(t *testing.T) {
	for _, mode := range []string{"web_workspace", "web_user", "oauth_workspace", "oauth_user", "missing_refresh", "missing_scope", "missing_expiry", "member_absent", "member_user", "personal_generation", "stopped", "unknown_evidence"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, d, m := credentialFixture(t)
			switch mode {
			case "web_workspace":
				m.web.WorkspaceID = uuid.NewString()
			case "web_user":
				m.web.AccessToken = strings.ReplaceAll(m.web.AccessToken, "mock", "invalid") // Decode and change canonical user, preserving valid JWT structure.
				parts := strings.Split(m.web.AccessToken, ".")
				raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.ReplaceAll(string(raw), "candidate-user", "wrong-user")))
				m.web.AccessToken = strings.Join(parts, ".")
			case "oauth_workspace":
				m.oauth.WorkspaceID = uuid.NewString()
			case "oauth_user":
				m.oauth.PlatformSubjectID = "other-user"
			case "missing_refresh":
				m.oauth.RefreshToken = ""
			case "missing_scope":
				m.oauth.Scope = ""
			case "missing_expiry":
				m.oauth.ExpiresIn = 0
			case "member_absent":
				d.membershipBody = `{"complete":true,"members":[]}`
			case "member_user":
				d.membershipBody = strings.ReplaceAll(d.membershipBody, "candidate-user", "other-user")
			case "personal_generation":
				f.exec(t, `UPDATE public.tsw_target_personal_sessions SET generation=$2 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId, uuid.New())
			case "stopped":
				f.exec(t, `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
			case "unknown_evidence":
				d.membershipBody = `{"complete":false,"members":[]}`
				if err := f.h.reconcileRotationJoinMembership(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute); !errors.Is(err, joinDispatchReconcileRequired) {
					t.Fatal(err)
				}
			}
			before := credentialSources(t, f)
			posts := len(d.paths)
			err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false)
			if err == nil {
				t.Fatal("invalid credentials/member admitted")
			}
			_, _, g := credentialCounts(t, f, slot)
			if g != 0 || posts != len(d.paths) || before != credentialSources(t, f) {
				t.Fatal("failed validation discharged or mutated original")
			}
			if (strings.HasPrefix(mode, "member_") || mode == "personal_generation" || mode == "stopped" || mode == "unknown_evidence") && (m.webCalls != 0 || m.oauthCalls != 0) {
				t.Fatal("credential action despite invalid original proof")
			}
		})
	}
}

func credentialSQLClaim(t *testing.T, f *removalFixture, o ownerContext, slot uuid.UUID) joinCredentialAttempt {
	t.Helper()
	i, p := membershipSQLAdmission(t, f, o, slot)
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	a, err := f.h.claimJoinCredentialAttempt(context.Background(), tx, i, p, o, uuid.New(), time.Minute, true)
	if err == nil {
		err = tx.Commit(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestRotationJoinCredentialsSQLRequiresDurableMarker(t *testing.T) {
	f, o, slot, _, m := credentialFixture(t)
	a := credentialSQLClaim(t, f, o, slot)
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = appendCredentialEvent(ctx, tx, a, "web", "started", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	err = f.h.appendCredentialComponent(ctx, tx, a, "web", m.web, time.Now().UTC(), m.web.ExpiresAt)
	if err == nil {
		t.Fatal("response checkpoint accepted a non-durable start marker")
	}
}

func TestRotationJoinCredentialsSchema34BindingDigestAndPublicationGuards(t *testing.T) {
	f, o, slot, _, _ := credentialFixture(t)
	ctx := context.Background()
	// Retain two durable sealed checkpoints, but inject the final commit failure.
	f.exec(t, `CREATE FUNCTION public.fail_credential_publish() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected'; END$$; CREATE TRIGGER fail_credential_publish BEFORE INSERT ON public.tsw_rotation_join_credential_generations FOR EACH ROW EXECUTE FUNCTION public.fail_credential_publish()`)
	if err := f.h.saveRotationJoinCredentials(ctx, o, f.preview.Id, slot, uuid.New(), time.Minute, false); err == nil {
		t.Fatal("publication injection failed")
	}
	f.exec(t, `DROP TRIGGER fail_credential_publish ON public.tsw_rotation_join_credential_generations; DROP FUNCTION public.fail_credential_publish()`)
	before := credentialSources(t, f)
	a := credentialSQLClaim(t, f, o, slot)
	for _, query := range []string{
		`UPDATE public.tsw_rotation_join_credential_attempts SET workspace_id=gen_random_uuid() WHERE slot_id=$1`,
		`UPDATE public.tsw_rotation_join_credential_attempts SET subject_id='replacement' WHERE slot_id=$1`,
		`UPDATE public.tsw_rotation_join_credential_attempts SET generation=gen_random_uuid() WHERE slot_id=$1`,
		`DELETE FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=$1`,
		`UPDATE public.tsw_rotation_join_credential_components SET sealed=decode(repeat('aa',32),'hex') WHERE attempt_id=(SELECT attempt_id FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=$1)`,
		`UPDATE public.tsw_rotation_join_credential_events SET event='review_required' WHERE attempt_id=(SELECT attempt_id FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=$1)`,
		`DELETE FROM public.tsw_rotation_join_credential_components WHERE attempt_id=(SELECT attempt_id FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=$1)`,
	} {
		if _, err := f.pool.Exec(ctx, query, slot); err == nil {
			t.Fatal("unguarded SQL", query)
		}
	}
	w, oc, err := f.h.validateSavedJoinCredentials(ctx, f.pool, a)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"workspace", "candidate", "web_digest", "oauth_digest", "membership", "generation", "stale_token", "stale_epoch", "expiry", "verified_future"} {
		t.Run(mode, func(t *testing.T) {
			changed := a
			web, oauth := w, oc
			verified := time.Now().UTC()
			switch mode {
			case "workspace":
				changed.binding.workspace = uuid.New()
			case "candidate":
				changed.binding.target = uuid.New()
			case "generation":
				changed.binding.generation = uuid.New()
			case "web_digest":
				web.digest = strings.Repeat("a", 64)
			case "oauth_digest":
				oauth.digest = strings.Repeat("b", 64)
			case "membership":
				changed.membershipDigest = strings.Repeat("c", 64)
			case "stale_token":
				changed.lease.token = uuid.New()
			case "stale_epoch":
				changed.lease.epoch--
			case "expiry":
				web.expires = time.Now().Add(-time.Minute)
			case "verified_future":
				verified = time.Now().Add(time.Minute)
			}
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if err = publishJoinCredentials(ctx, tx, changed, web, oauth, verified); err == nil {
				err = tx.Commit(ctx)
			}
			if err == nil {
				t.Fatal("forged publication accepted", mode)
			}
		})
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = publishJoinCredentials(ctx, tx, a, w, oc, time.Now().UTC()); err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`UPDATE public.tsw_rotation_join_credential_generations SET workspace_id=gen_random_uuid() WHERE attempt_id=$1`, `DELETE FROM public.tsw_rotation_join_credential_generations WHERE attempt_id=$1`} {
		if _, err = f.pool.Exec(ctx, query, a.binding.attempt); err == nil {
			t.Fatal("publication mutable")
		}
	}
	if before != credentialSources(t, f) {
		t.Fatal("SQL guards changed original source")
	}
}
func TestRotationJoinCredentialsSchema34RejectsUnmarkedDigestAndOrphan(t *testing.T) {
	for _, mode := range []string{"unmarked", "digest", "orphan", "cross_space_attempt"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, _, m := credentialFixture(t)
			ctx := context.Background()
			a := credentialSQLClaim(t, f, o, slot)
			if mode == "cross_space_attempt" {
				if _, err := f.pool.Exec(ctx, `INSERT INTO public.tsw_rotation_join_credential_attempts(slot_id,attempt_id,generation,candidate_account_id,workspace_id,platform_workspace_id,secret_revision,subject_id,membership_attempt,membership_digest,platform_member_id) SELECT slot_id,gen_random_uuid(),gen_random_uuid(),candidate_account_id,gen_random_uuid(),platform_workspace_id,secret_revision,subject_id,membership_attempt,membership_digest,platform_member_id FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=$1`, slot); err == nil {
					t.Fatal("cross-space replacement accepted")
				}
				return
			}
			if mode == "digest" {
				tx, err := f.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err = appendCredentialEvent(ctx, tx, a, "web", "started", time.Now().UTC()); err == nil {
					err = tx.Commit(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if mode == "orphan" {
				err = publishJoinCredentials(ctx, tx, a, joinCredentialComponent{digest: strings.Repeat("a", 64), expires: m.web.ExpiresAt}, joinCredentialComponent{digest: strings.Repeat("b", 64), expires: m.web.ExpiresAt}, time.Now().UTC())
			} else if mode == "digest" {
				l := a.lease
				_, err = tx.Exec(ctx, `INSERT INTO public.tsw_rotation_join_credential_components(attempt_id,kind,key_version,nonce,sealed,sealed_digest,observed_at,expires_at,lease_epoch,lease_owner,lease_token,owner_session) VALUES($1,'web',1,decode(repeat('aa',12),'hex'),decode(repeat('ab',32),'hex'),$2,clock_timestamp(),clock_timestamp()+interval '1 hour',$3,$4,$5,$6)`, a.binding.attempt, strings.Repeat("a", 64), l.epoch, l.workerID, l.token, l.owner.SessionID)
			} else {
				err = f.h.appendCredentialComponent(ctx, tx, a, "web", m.web, time.Now().UTC(), m.web.ExpiresAt)
			}
			if err == nil {
				err = tx.Commit(ctx)
			}
			if err == nil {
				t.Fatal("SQL guard accepted", mode)
			}
		})
	}
}
func TestRotationJoinCredentialsActionAndFinalFencing(t *testing.T) {
	for _, mode := range []string{"owner", "source", "personal", "gate_lost", "lease", "egress", "stop"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, d, m := credentialFixture(t)
			duration := time.Minute
			posts := len(d.paths)
			var after string
			m.hook = func(stage string) {
				if stage != "web" {
					return
				}
				var err error
				switch mode {
				case "owner":
					_, err = d.gateConn.Exec(context.Background(), `UPDATE public.tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE id=$1`, o.SessionID)
				case "source":
					_, err = d.gateConn.Exec(context.Background(), `UPDATE public.tsw_standby_child_batches SET version=version+1 WHERE id=$1`, f.preview.BatchId)
				case "personal":
					_, err = d.gateConn.Exec(context.Background(), `UPDATE public.tsw_target_personal_sessions SET generation=$2 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId, uuid.New())
				case "gate_lost":
					_, err = d.gateConn.Exec(context.Background(), `SELECT pg_advisory_unlock_all()`)
				case "lease":
					var deadline time.Time
					err = f.pool.QueryRow(context.Background(), `SELECT lease_expires_at FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=$1`, slot).Scan(&deadline)
					if err != nil || !deadline.After(time.Now()) {
						t.Fatal("mock action did not reach the live lease", err)
					}
					time.Sleep(time.Until(deadline) + 20*time.Millisecond)
				case "egress":
					d.route.measure = func() error { return errors.New("route drift") }
				case "stop":
					_, err = d.gateConn.Exec(context.Background(), `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
				}
				if err != nil {
					t.Fatal(err)
				}
				after = credentialSources(t, f)
			}
			if mode == "lease" {
				duration = 5 * time.Second
			}
			if err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), duration, false); err == nil {
				t.Fatal("fenced action published")
			}
			a, c, g := credentialCounts(t, f, slot)
			if a != 1 || c != 0 || g != 0 || m.webCalls != 1 || m.oauthCalls != 0 || posts != len(d.paths) || after != credentialSources(t, f) {
				t.Fatal("fencing lost marker or published")
			}
		})
	}
}
func TestRotationJoinCredentialsConcurrentClaimAndStopRead(t *testing.T) {
	for _, mode := range []string{"concurrent", "stop"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot, d, m := credentialFixture(t)
			f.h.pool = f.pool
			before := credentialSources(t, f)
			posts := len(d.paths)
			entered, release := make(chan struct{}), make(chan struct{})
			first := true
			d.identityHook = func() {
				if first {
					first = false
					close(entered)
					<-release
				}
			}
			result := make(chan error, 1)
			go func() {
				result <- f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false)
			}()
			select {
			case <-entered:
			case err := <-result:
				t.Fatalf("read not reached %v", err)
			case <-time.After(8 * time.Second):
				t.Fatal("read blocked")
			}
			if mode == "concurrent" {
				err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, true)
				if !errors.Is(err, joinCredentialsBusy) {
					close(release)
					<-result
					t.Fatalf("concurrent=%v", err)
				}
			} else {
				control := *f.h
				control.pool = f.pool
				stopped := make(chan int, 1)
				go func() {
					response := removalRequest(&control, f.session, f.csrf, "POST", f.preview.Id, uuid.Nil, "stop", map[string]any{"confirmed": true})
					stopped <- response.Code
				}()
				select {
				case code := <-stopped:
					if code != 200 {
						t.Fatalf("stop=%d", code)
					}
				case <-time.After(2 * time.Second):
					close(release)
					<-result
					t.Fatal("credential read held Workspace")
				}
				before = credentialSources(t, f)
			}
			close(release)
			err := <-result
			_, c, g := credentialCounts(t, f, slot)
			if mode == "concurrent" && (err != nil || c != 2 || g != 1) || mode == "stop" && (err == nil || c != 0 || g != 0 || m.webCalls != 0 || m.oauthCalls != 0) || posts != len(d.paths) || before != credentialSources(t, f) {
				t.Fatalf("unsafe concurrency %s c=%d g=%d err=%v", mode, c, g, err)
			}
		})
	}
}

func TestRotationJoinCredentialsSQLRequiresDurableComponents(t *testing.T) {
	f, o, slot, _, m := credentialFixture(t)
	ctx := context.Background()
	f.exec(t, `CREATE FUNCTION public.fail_oauth_marker() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.stage='oauth' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_oauth_marker BEFORE INSERT ON public.tsw_rotation_join_credential_events FOR EACH ROW EXECUTE FUNCTION public.fail_oauth_marker()`)
	if err := f.h.saveRotationJoinCredentials(ctx, o, f.preview.Id, slot, uuid.New(), time.Minute, false); err == nil {
		t.Fatal("marker injection failed")
	}
	f.exec(t, `DROP TRIGGER fail_oauth_marker ON public.tsw_rotation_join_credential_events; DROP FUNCTION public.fail_oauth_marker()`)
	a := credentialSQLClaim(t, f, o, slot)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = appendCredentialEvent(ctx, tx, a, "oauth", "started", time.Now().UTC()); err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	tx, err = f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	observed := time.Now().UTC().Truncate(time.Microsecond)
	expiry, err := platform.ValidateRotationCandidateOAuth(m.oauth, f.space.String(), "candidate-user", observed)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.h.appendCredentialComponent(ctx, tx, a, "oauth", m.oauth, observed, expiry); err != nil {
		t.Fatal(err)
	}
	web, oauth, err := f.h.validateSavedJoinCredentials(ctx, tx, a)
	if err != nil {
		t.Fatal(err)
	}
	if err = publishJoinCredentials(ctx, tx, a, web, oauth, time.Now().UTC()); err == nil {
		t.Fatal("publication preceded durable OAuth checkpoint")
	}
}

type credentialRequestMock struct {
	*credentialMock
	client *http.Client
}

func (m *credentialRequestMock) CreateCandidateOAuth(ctx context.Context, r platform.DeliveryCredentialRequest, u string) (platform.DeliveryCredentialSet, error) {
	m.oauthCalls++
	m.marker("oauth")
	for _, path := range []string{"/api/accounts/password/verify", "/oauth/token"} {
		req, err := http.NewRequestWithContext(ctx, "POST", "https://auth.openai.com"+path, strings.NewReader("sealed-at-rest-only"))
		if err != nil {
			return platform.DeliveryCredentialSet{}, err
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return platform.DeliveryCredentialSet{}, err
		}
		resp.Body.Close()
	}
	return m.oauth, nil
}

type credentialTestTransport func(*http.Request) (*http.Response, error)

func (fn credentialTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func TestRotationJoinCredentialsRechecksEveryCredentialRequest(t *testing.T) {
	f, o, slot, d, m := credentialFixture(t)
	calls := 0
	d.route.client.Transport = credentialTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "auth.openai.com" {
			return d.RoundTrip(r)
		}
		if d.gateConn.PgConn().TxStatus() != 'I' {
			t.Fatal("credential I/O inside source transaction")
		}
		calls++
		if _, err := d.gateConn.Exec(context.Background(), `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id); err != nil {
			t.Fatal(err)
		}
		return removalHTTPResponse(200, `{}`), nil
	})
	f.h.rotationCredentialAdapters = func(factory platform.DiscoveryClient) platform.RotationCredentialAdapter {
		client, _, err := factory(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return &credentialRequestMock{credentialMock: m, client: client}
	}
	if err := f.h.saveRotationJoinCredentials(context.Background(), o, f.preview.Id, slot, uuid.New(), time.Minute, false); err == nil {
		t.Fatal("stopped credential flow published")
	}
	_, c, g := credentialCounts(t, f, slot)
	if calls != 1 || c != 1 || g != 0 {
		t.Fatalf("new credential request after stop calls=%d c=%d g=%d", calls, c, g)
	}
}
func TestRotationJoinCredentialsLeaseTakeoverRetainsUnknownAndRejectsLateResponse(t *testing.T) {
	f, o, slot, _, m := credentialFixture(t)
	ctx := context.Background()
	a := credentialSQLClaim(t, f, o, slot)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = appendCredentialEvent(ctx, tx, a, "web", "started", time.Now().UTC()); err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	// Voluntary release and a new epoch model a replaced worker; no binding is edited.
	f.exec(t, `UPDATE public.tsw_rotation_join_credential_attempts SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,owner_session=NULL WHERE slot_id=$1`, slot)
	replacement := credentialSQLClaim(t, f, o, slot)
	if replacement.binding != a.binding || replacement.lease.epoch <= a.lease.epoch {
		t.Fatal("takeover replaced original attempt")
	}
	tx, err = f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = f.h.appendCredentialComponent(ctx, tx, a, "web", m.web, time.Now().UTC(), m.web.ExpiresAt); err == nil {
		t.Fatal("late response from previous lease accepted")
	}
	_ = tx.Rollback(ctx)
	f.exec(t, `UPDATE public.tsw_rotation_join_credential_attempts SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,owner_session=NULL WHERE slot_id=$1`, slot)
	if err = f.h.saveRotationJoinCredentials(ctx, o, f.preview.Id, slot, uuid.New(), time.Minute, true); !errors.Is(err, joinCredentialsReview) {
		t.Fatalf("unknown takeover=%v", err)
	}
	_, c, g := credentialCounts(t, f, slot)
	if c != 0 || g != 0 || m.webCalls != 0 || m.oauthCalls != 0 {
		t.Fatal("takeover reissued unknown exchange")
	}
}
func TestRotationJoinCredentialsMigration34DownUp(t *testing.T) {
	f, _, _, _, _ := credentialFixture(t)
	membershipSchemaVersion(t, 34)
	before := credentialSources(t, f)
	membershipSchemaVersion(t, 33)
	var absent bool
	if err := f.pool.QueryRow(context.Background(), `SELECT to_regclass('public.tsw_rotation_join_credential_attempts') IS NULL AND to_regprocedure('public.tsw_rotation_join_credential_authority(uuid,uuid)') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("schema34 down cleanup", err)
	}
	membershipSchemaVersion(t, 34)
	membershipSchemaVersion(t, 34)
	var guards int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_trigger WHERE tgname IN ('tsw_rotation_join_credential_attempt_guard','tsw_rotation_join_credential_event_guard','tsw_rotation_join_credential_component_guard','tsw_rotation_join_credential_generation_guard') AND tgenabled='O'`).Scan(&guards); err != nil || guards != 4 {
		t.Fatal("schema34 guards", guards, err)
	}
	if before != credentialSources(t, f) {
		t.Fatal("migration34 mutated original source/journal33")
	}
}
