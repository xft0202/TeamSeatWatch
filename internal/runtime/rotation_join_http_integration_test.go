//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

func joinHTTPRequest(h *OwnerAuthHandler, f *removalFixture, preview, slot uuid.UUID, method, action, body string, changes ...func(*http.Request)) *httptest.ResponseRecorder {
	path := fmt.Sprintf("/api/owner/v1/expiry-rotation/previews/%s/removal/slots/%s/join", preview, slot)
	if action != "" {
		path += "/" + action
	}
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Origin", "https://owner.test")
	req.Header.Set(auth.CSRFHeaderName, f.csrf)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: f.session})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: f.csrf})
	for _, change := range changes {
		change(req)
	}
	w := httptest.NewRecorder()
	ownerapi.HandlerWithOptions(h, ownerapi.StdHTTPServerOptions{ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
		if isCSRFBindingError(err) {
			writeProblem(w, r, 403, "csrf_rejected", "Forbidden", "Origin or CSRF validation failed", 0)
			return
		}
		writeProblem(w, r, 400, "invalid_request", "Invalid Request", "Invalid original slot path", 0)
	}}).ServeHTTP(w, req)
	return w
}
func joinHTTPStatus(t *testing.T, w *httptest.ResponseRecorder) ownerapi.RotationJoinStatus {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var status ownerapi.RotationJoinStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	return status
}
func TestRotationJoinHTTPStatusPassiveAndInputStrict(t *testing.T) {
	f, _, slot, d := dispatchFixture(t)
	before := credentialSources(t, f)
	posts := len(d.paths)
	for n := 0; n < 2; n++ {
		s := joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "GET", "", ""))
		if s.Phase != "not_started" || s.NextAction != "run" {
			t.Fatalf("unexpected status %+v", s)
		}
	}
	if before != credentialSources(t, f) || len(d.paths) != posts {
		t.Fatal("GET acquired credentials or joined")
	}
	for _, body := range []string{`{"confirmed":true,"accountId":"replacement"}`, `{"confirmed":true,"Confirmed":true}`, `{"confirmed":false}`, `{"confirmed":true} {}`} {
		w := joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "run", body)
		if w.Code != 422 {
			t.Fatalf("non-exact action accepted %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if joinHTTPRequest(f.h, f, uuid.New(), slot, "GET", "", "").Code != 404 || joinHTTPRequest(f.h, f, f.preview.Id, uuid.New(), "GET", "", "").Code != 404 {
		t.Fatal("cross-scope slot exposed")
	}
}

func TestRotationJoinHTTPRegisteredRunVerifyPartialRepairAndRedaction(t *testing.T) {
	f, _, slot, d := dispatchFixture(t)
	// Released-slot setup is mocked; registered HTTP routes below use official
	// adapter implementations and the same generated registration as production.
	f.h.rotationCredentialAdapters = func(c platform.DiscoveryClient) platform.RotationCredentialAdapter {
		return platform.OfficialRotationCredentialAdapter{Client: c}
	}
	s := joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "run", `{"confirmed":true}`))
	if s.NextAction != "verify" {
		t.Fatalf("run %+v", s)
	}
	posts := len(d.paths)
	s = joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "run", `{"confirmed":true}`))
	if len(d.paths) != posts {
		t.Fatal("duplicate HTTP replayed join")
	}
	d.membershipBody = fmt.Sprintf(`{"complete":true,"members":[{"kind":"member","platform_member_id":"original-member","platform_account_user_id":"candidate-user","identifier":%q,"status":"active","seat_type":"prolite"}]}`, f.preview.Candidates[0].Identifier)
	s = joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "verify", `{"confirmed":true}`))
	if s.Membership != "confirmed" || s.NextAction != "save" {
		t.Fatalf("verify %+v", s)
	}
	before := credentialSources(t, f)
	// The sourced exchange and PKCE login execute only through the admitted mock
	// route; no private credential adapter or handler substitutes public behavior.
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	web := httpCredentialToken(t, f.space.String(), "candidate-user", "k12", "organization.read", expiry)
	oauth := httpCredentialToken(t, f.space.String(), "candidate-user", "team", platform.CodexScope, expiry)
	grants := 0
	d.route.client.Transport = credentialTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "chatgpt.com" && r.URL.Path == "/api/auth/session" && r.URL.Query().Get("exchange_workspace_token") == "true" {
			body, _ := json.Marshal(map[string]any{"accessToken": web, "expires": expiry.Format(time.RFC3339), "account": map[string]string{"id": f.space.String()}, "user": map[string]string{"id": "candidate-user"}})
			return removalHTTPResponse(200, string(body)), nil
		}
		if r.URL.Host == "auth.openai.com" || r.URL.Path == "/api/auth/providers" || r.URL.Path == "/api/auth/csrf" || r.URL.Path == "/api/auth/signin/openai" {
			switch r.URL.Path {
			case "/api/auth/providers":
				return removalHTTPResponse(200, `{}`), nil
			case "/api/auth/csrf":
				return removalHTTPResponse(200, `{"csrfToken":"mock"}`), nil
			case "/api/auth/signin/openai":
				return removalHTTPResponse(200, `{"url":"https://auth.openai.com/log-in/password"}`), nil
			case "/log-in/password":
				return removalHTTPResponse(200, `log-in/password`), nil
			case "/api/accounts/password/verify":
				return removalHTTPResponse(200, `{"continue_url":"https://auth.openai.com/mfa-challenge/challenge-12345678"}`), nil
			case "/mfa-challenge/challenge-12345678":
				return removalHTTPResponse(200, `mfa totp`), nil
			case "/api/accounts/mfa/verify":
				return removalHTTPResponse(200, `{"continue_url":"https://auth.openai.com/ready"}`), nil
			case "/ready", "/sign-in-with-chatgpt/codex/consent", "/selected":
				return removalHTTPResponse(200, `ready`), nil
			case "/api/accounts/workspace/select":
				return removalHTTPResponse(200, `{"continue_url":"https://auth.openai.com/selected"}`), nil
			case "/oauth/authorize":
				response := removalHTTPResponse(302, "")
				response.Header.Set("Location", "http://localhost:1455/auth/callback?code=mock-code&state="+r.URL.Query().Get("state"))
				return response, nil
			case "/oauth/token":
				grants++
				body, _ := json.Marshal(platform.DeliveryCredentialSet{AccessToken: oauth, IDToken: oauth, RefreshToken: "mock-refresh-secret", ExpiresIn: 3600, Scope: platform.CodexScope})
				return removalHTTPResponse(200, string(body)), nil
			default:
				t.Fatalf("invented credential request %s", r.URL)
			}
		}
		return d.RoundTrip(r)
	})
	f.exec(t, `CREATE FUNCTION public.fail_http_generation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected'; END$$; CREATE TRIGGER fail_http_generation BEFORE INSERT ON public.tsw_rotation_join_credential_generations FOR EACH ROW EXECUTE FUNCTION public.fail_http_generation()`)
	w := joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "save", `{"confirmed":true}`)
	if w.Code == 200 {
		t.Fatal("injected publication failure claimed success")
	}
	s = joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "GET", "", ""))
	if s.Credentials != "partial" || s.NextAction != "repair" {
		t.Fatalf("partial %+v; save=%s", s, w.Body.String())
	}
	f.exec(t, `DROP TRIGGER fail_http_generation ON public.tsw_rotation_join_credential_generations; DROP FUNCTION public.fail_http_generation()`)
	w = joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "repair", `{"confirmed":true}`)
	s = joinHTTPStatus(t, w)
	if s.Credentials != "complete" || s.NextAction != "observe" || grants != 1 || len(d.paths) != posts || before != credentialSources(t, f) {
		t.Fatalf("repair %+v grants=%d", s, grants)
	}
	for _, secret := range []string{web, oauth, "mock-refresh-secret", "sealed", "nonce", "leaseToken", "password", "totp", "cookie"} {
		if bytes.Contains(w.Body.Bytes(), []byte(secret)) {
			t.Fatal("secret leaked", secret)
		}
	}
}
func httpCredentialToken(t *testing.T, w, u, plan, scope string, expiry time.Time) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"exp": expiry.Unix(), "sub": "auth0|candidate", "scope": scope, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": w, "chatgpt_user_id": u, "chatgpt_plan_type": plan}})
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".mock"
}

func TestRotationJoinHTTPAuthenticationAndCSRFBoundaries(t *testing.T) {
	f, _, slot, d := dispatchFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"missing_csrf", func(r *http.Request) { r.Header.Del(auth.CSRFHeaderName) }},
		{"invalid_csrf", func(r *http.Request) { r.Header.Set(auth.CSRFHeaderName, "invalid") }},
		{"foreign_origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.test") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "run", `{"confirmed":true}`, tc.change)
			if w.Code != 403 || len(d.paths) != 0 {
				t.Fatalf("boundary status=%d paths=%v", w.Code, d.paths)
			}
		})
	}
	w := joinHTTPRequest(f.h, f, f.preview.Id, slot, "GET", "", "", func(r *http.Request) { r.Header.Del("Cookie") })
	if w.Code != 401 {
		t.Fatalf("unauthenticated GET=%d", w.Code)
	}
	// A second authenticated Owner is impossible under tsw_owners_singleton_uq.
	// Keep that invariant intact and test a real different preview's slot pair.
	other := uuid.New()
	f.exec(t, `INSERT INTO tsw_expiry_rotation_previews SELECT (jsonb_populate_record(NULL::tsw_expiry_rotation_previews,to_jsonb(p)||jsonb_build_object('id',$2::text,'idempotency_key',$3::text))).* FROM tsw_expiry_rotation_previews p WHERE id=$1`, f.preview.Id, other, uuid.New())
	for _, method := range []string{"GET", "POST"} {
		action := ""
		if method == "POST" {
			action = "run"
		}
		w = joinHTTPRequest(f.h, f, other, slot, method, action, `{"confirmed":true}`)
		if w.Code != 404 || len(d.paths) != 0 {
			t.Fatalf("existing cross-preview %s status=%d paths=%v", method, w.Code, d.paths)
		}
		w = joinHTTPRequest(f.h, f, f.preview.Id, slot, method, action, `{"confirmed":true}`, func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "mismatched-session"})
			r.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: f.csrf})
		})
		if w.Code != 401 || len(d.paths) != 0 {
			t.Fatalf("mismatched session %s=%d", method, w.Code)
		}
	}
}

func TestRotationJoinHTTPCurrentAuthorityAndSourceDrift(t *testing.T) {
	for _, name := range []string{"revoked_session", "expired_session", "current_role", "pinned_generation", "source_version"} {
		t.Run(name, func(t *testing.T) {
			f, o, slot, d := dispatchFixture(t)
			want := 409
			switch name {
			case "revoked_session":
				f.exec(t, `UPDATE tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE id=$1`, o.SessionID)
				want = 401
			case "expired_session":
				f.exec(t, `UPDATE tsw_owner_sessions SET created_at=clock_timestamp()-interval '2 hours',last_seen_at=clock_timestamp()-interval '1 hour',idle_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, o.SessionID)
				want = 401
			case "current_role":
				d.role = "member"
			case "pinned_generation":
				d.route.measure = func() error {
					_, err := d.gateConn.Exec(context.Background(), `UPDATE tsw_target_personal_sessions SET generation=$2 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId, uuid.New())
					return err
				}
			case "source_version":
				f.exec(t, `UPDATE tsw_target_accounts SET version=version+1 WHERE id=$1`, f.preview.Candidates[0].AccountId)
			}
			w := joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "run", `{"confirmed":true}`)
			a, c, g := credentialCounts(t, f, slot)
			if w.Code != want || len(d.paths) != 0 || a+c+g != 0 {
				t.Fatalf("%s status=%d want=%d paths=%v", name, w.Code, want, d.paths)
			}
		})
	}
}

func TestRotationJoinHTTPUnknownResultAndConcurrentSubmitNeverReplay(t *testing.T) {
	f, _, slot, d := dispatchFixture(t)
	// Dispatch retains its admitted connection during I/O. Status/concurrent
	// submission therefore needs the normal multi-connection fixture pool.
	f.h.pool = f.pool
	started, release := make(chan struct{}), make(chan struct{})
	d.remoteError = io.ErrUnexpectedEOF
	d.hook = func(stage string) {
		if stage == "request_join" {
			close(started)
			<-release
		}
	}
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "run", `{"confirmed":true}`) }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("mock request did not start")
	}
	s := joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "GET", "", ""))
	if s.NextAction != "none" || s.Diagnostic != "action_in_progress" {
		t.Fatalf("live lease %+v", s)
	}
	duplicate := joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "run", `{"confirmed":true}`)
	if duplicate.Code != 200 || len(d.paths) != 1 {
		t.Fatalf("concurrent replay status=%d paths=%v", duplicate.Code, d.paths)
	}
	close(release)
	s = joinHTTPStatus(t, <-first)
	if s.NextAction != "verify" || s.Credentials != "missing" {
		t.Fatalf("unknown request %+v", s)
	}
	for n := 0; n < 2; n++ {
		s = joinHTTPStatus(t, joinHTTPRequest(f.h, f, f.preview.Id, slot, "POST", "run", `{"confirmed":true}`))
		if len(d.paths) != 1 || s.NextAction != "verify" {
			t.Fatalf("lost response replay %+v paths=%v", s, d.paths)
		}
	}
}
