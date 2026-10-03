//go:build integration

package runtime

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/audit"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/internalapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/publicaccess"
)

func inventoryHTTP(f *removalFixture, id uuid.UUID, method, action, body string, changes ...func(*http.Request)) *httptest.ResponseRecorder {
	path := "/api/owner/v1/public-inventory/" + id.String()
	if action != "" {
		path += "/" + action
	}
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Origin", "https://owner.test")
	request.Header.Set(auth.CSRFHeaderName, f.csrf)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: f.session})
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: f.csrf})
	for _, change := range changes {
		change(request)
	}
	w := httptest.NewRecorder()
	ownerapi.Handler(f.h).ServeHTTP(w, request)
	return w
}
func registeredZIPRequest(h *PublicRedeemHandler, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	request := httptest.NewRequest(method, "/internal/v1/public"+path, bytes.NewReader(raw))
	request.RemoteAddr = "198.51.100.9:3000"
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	internalapi.Handler(h).ServeHTTP(response, request)
	return response
}
func publicZIPCounts(t *testing.T, f *removalFixture) (int, int, int) {
	t.Helper()
	var orders, receivers, delivered int
	err := f.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM public.tsw_public_zip_orders),(SELECT count(*) FROM public.tsw_batch_zip_receivers),(SELECT count(*) FROM public.tsw_batch_zip_delivered)`).Scan(&orders, &receivers, &delivered)
	if err != nil {
		t.Fatal(err)
	}
	return orders, receivers, delivered
}
func publicZIPOriginalDigest(t *testing.T, f *removalFixture) string {
	t.Helper()
	// Compare the stored original facts, rather than a new-action view whose
	// rows disappear when its short evidence clock or initial session expires.
	var value string
	err := f.pool.QueryRow(context.Background(), `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_candidate_join_intents t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_join_executions t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_join_credential_generations t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_usage_ledger t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_removal_slots t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_removal_evidence t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_join_usage_evidence t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_join_membership_evidence t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.tsw_rotation_epochs t))::text`).Scan(&value)
	if err != nil {
		t.Fatal(err)
	}
	return rotationHash(value)
}
func inventoryTimeFixture(t *testing.T, f *removalFixture, id uuid.UUID, claim, access time.Time) {
	t.Helper()
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	// Advance only the disposable clock facts; production immutable guards are
	// restored before every actual authorization/claim/download request.
	_, err = tx.Exec(context.Background(), `SET LOCAL session_replication_role='replica'`)
	if err == nil {
		_, err = tx.Exec(context.Background(), `UPDATE public.tsw_public_zip_inventory SET claim_expires_at=$2,access_expires_at=$3 WHERE package_id=$1`, id, claim, access)
	}
	if err == nil {
		_, err = tx.Exec(context.Background(), `SET LOCAL session_replication_role='origin'`)
	}
	if err == nil {
		err = tx.Commit(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
}

func rotationFault(t *testing.T, f *removalFixture, enable bool) {
	t.Helper()
	if enable {
		f.exec(t, `CREATE FUNCTION public.public_zip_rotation_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'mock new session save failure'; END $$; CREATE TRIGGER public_zip_rotation_fault BEFORE INSERT ON public.tsw_owner_sessions FOR EACH ROW EXECUTE FUNCTION public.public_zip_rotation_fault()`)
	} else {
		f.exec(t, `DROP TRIGGER public_zip_rotation_fault ON public.tsw_owner_sessions; DROP FUNCTION public.public_zip_rotation_fault()`)
	}
}
func acceptInventoryRotation(t *testing.T, f *removalFixture, id uuid.UUID, w *httptest.ResponseRecorder, oldToken string) {
	t.Helper()
	next := ""
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == auth.SessionCookieName {
			next = cookie.Value
		}
	}
	if next == "" || next == oldToken {
		t.Fatal("sensitive inventory authorization did not issue new session")
	}
	denied := inventoryHTTP(f, id, "GET", "", "", func(r *http.Request) {
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: oldToken})
	})
	if denied.Code != 401 {
		t.Fatal("original Owner token still authorized", denied.Code)
	}
	f.session = next
	allowed := inventoryHTTP(f, id, "GET", "", "")
	if allowed.Code != 200 {
		t.Fatal("new Owner token rejected", allowed.Code, allowed.Body.String())
	}
}

type interruptedZIPWriter struct {
	header http.Header
	status int
}

func (w *interruptedZIPWriter) Header() http.Header    { return w.header }
func (w *interruptedZIPWriter) WriteHeader(status int) { w.status = status }
func (w *interruptedZIPWriter) Write([]byte) (int, error) {
	return 0, errors.New("mock client transfer interrupted")
}

func TestPublicZIPRegisteredWholeOrderAuthorizationAndFaults(t *testing.T) {
	// Exactly one accepted upstream mock qualification chain. Every current-ticket
	// case below shares its original object; no lifecycle is replayed per subtest.
	f, owner, slot := zipFixture(t)
	ctx := context.Background()
	a, err := f.h.prepareBatchZIP(ctx, owner, f.preview.Id)
	if err != nil {
		t.Fatal(err)
	}
	original := zipData(t, f, a)
	before := publicZIPOriginalDigest(t, f)
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, 20))
	claimExpiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	accessExpiry := claimExpiry.Add(time.Hour)
	activation, _ := json.Marshal(map[string]any{"cardSecret": secret, "claimExpiresAt": claimExpiry, "accessExpiresAt": accessExpiry, "confirmed": true})
	h := NewPublicRedeemHandler(f.pool, f.h.keyRing, nil)
	var cookie *http.Cookie
	t.Run("independent_inventory_authenticated_strict_activation", func(t *testing.T) {
		if n, _, _ := publicZIPCounts(t, f); n != 0 {
			t.Fatal("generation made Public sale")
		}
		w := inventoryHTTP(f, a.id, "GET", "", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), "not_activated") {
			t.Fatal(w.Code, w.Body.String())
		}
		w = inventoryHTTP(f, a.id, "POST", "", string(activation), func(r *http.Request) { r.Header.Del("Cookie") })
		if w.Code != 401 && w.Code != 403 {
			t.Fatal("missing Owner session", w.Code)
		}
		w = inventoryHTTP(f, a.id, "POST", "", string(activation), func(r *http.Request) { r.Header.Del(auth.CSRFHeaderName) })
		if w.Code < 400 {
			t.Fatal("missing CSRF", w.Code)
		}
		malformed := strings.TrimSuffix(string(activation), "}") + `,"extra":true}`
		w = inventoryHTTP(f, a.id, "POST", "", malformed)
		if w.Code < 400 {
			t.Fatal("unknown body fields accepted")
		}
		rotationFault(t, f, true)
		w = inventoryHTTP(f, a.id, "POST", "", string(activation))
		if w.Code != 500 {
			t.Fatal("rotation fault not reported", w.Code, w.Body.String())
		}
		rotationFault(t, f, false)
		rollback := inventoryHTTP(f, a.id, "GET", "", "")
		if rollback.Code != 200 || !strings.Contains(rollback.Body.String(), "not_activated") {
			t.Fatal("rotation failure partially activated inventory or revoked session", rollback.Code, rollback.Body.String())
		}
		oldOwnerToken := f.session
		w = inventoryHTTP(f, a.id, "POST", "", string(activation))
		if w.Code != 200 || strings.Contains(w.Body.String(), secret) {
			t.Fatal(w.Code, w.Body.String())
		}
		acceptInventoryRotation(t, f, a.id, w, oldOwnerToken)
		w = inventoryHTTP(f, a.id, "POST", "", string(activation))
		if w.Code != 200 || len(w.Result().Cookies()) != 0 {
			t.Fatal("idempotent activation rotated session", w.Code, w.Header())
		}
		if n, r, d := publicZIPCounts(t, f); n != 0 || r != 0 || d != 0 {
			t.Fatal("activation became sale", n, r, d)
		}
		if before != publicZIPOriginalDigest(t, f) {
			t.Fatal("inventory activation changed the original source")
		}
	})
	t.Run("expired_permission_and_uniform_invalid_card", func(t *testing.T) {
		denied := registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x74}, 20))}, nil)
		inventoryTimeFixture(t, f, a.id, time.Now().Add(-time.Minute), accessExpiry)
		expired := registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		if denied.Code != 404 || expired.Code != 404 || !bytes.Equal(denied.Body.Bytes(), expired.Body.Bytes()) {
			t.Fatal("card existence leaked", denied.Code, expired.Code, denied.Body.String(), expired.Body.String())
		}
		inventoryTimeFixture(t, f, a.id, claimExpiry, accessExpiry)
		f.exec(t, `UPDATE public.tsw_public_zip_inventory SET enabled=false WHERE package_id=$1`, a.id)
		unavailable := registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		if unavailable.Code != 404 || !bytes.Equal(denied.Body.Bytes(), unavailable.Body.Bytes()) {
			t.Fatal("permission failure leaked", unavailable.Code)
		}
		f.exec(t, `UPDATE public.tsw_public_zip_inventory SET enabled=true WHERE package_id=$1`, a.id)
	})
	t.Run("late_archived_first_claim_keeps_current_qualification", func(t *testing.T) {
		// Change only the mock historical release clock, with production guards
		// restored before the test. Current zero/member/credential facts stay fresh.
		tx, e := f.pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(ctx, `SET LOCAL session_replication_role='replica'; UPDATE public.tsw_rotation_removal_evidence SET observed_at=clock_timestamp()-interval '45 seconds'; SET LOCAL session_replication_role='origin'`)
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if e != nil {
			t.Fatal(e)
		}
		var newActionReady, archivedReady bool
		if e = f.pool.QueryRow(ctx, `SELECT public.tsw_rotation_join_usage_ready($2),public.tsw_archived_batch_zip_ready($1,$2)`, a.id, slot).Scan(&newActionReady, &archivedReady); e != nil {
			t.Fatal(e)
		}
		if newActionReady || !archivedReady {
			t.Fatal("archived object reused historical new-action clock or lost current authority", newActionReady, archivedReady)
		}
		for _, fault := range []struct{ before, after string }{
			{`UPDATE public.tsw_expiry_rotation_previews SET status='revoked',revoked_at=clock_timestamp(),revoked_by=owner_id`, `UPDATE public.tsw_expiry_rotation_previews SET status='authorized',revoked_at=NULL,revoked_by=NULL`},
			{`UPDATE public.tsw_rotation_join_usage_evidence SET observed_at=now()-interval '6 minutes',expires_at=now()-interval '1 minute'`, `UPDATE public.tsw_rotation_join_usage_evidence SET observed_at=now(),expires_at=now()+interval '5 minutes'`},
			{`UPDATE public.tsw_rotation_join_membership_evidence SET result='unknown',platform_member_id=NULL`, `UPDATE public.tsw_rotation_join_membership_evidence membership SET result='confirmed',platform_member_id=(SELECT platform_member_id FROM public.tsw_rotation_join_credential_attempts ca WHERE ca.slot_id=membership.slot_id)`},
		} {
			tx, e = f.pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			_, e = tx.Exec(ctx, `SET LOCAL session_replication_role='replica'`)
			if e == nil {
				_, e = tx.Exec(ctx, fault.before)
			}
			if e == nil {
				_, e = tx.Exec(ctx, `SET LOCAL session_replication_role='origin'`)
			}
			if e == nil {
				e = tx.Commit(ctx)
			} else {
				_ = tx.Rollback(ctx)
			}
			if e != nil {
				t.Fatal(e)
			}
			blocked := registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
			if blocked.Code != 404 {
				t.Fatal("invalid current qualification claimed", fault.before, blocked.Code, blocked.Body.String())
			}
			tx, e = f.pool.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			_, e = tx.Exec(ctx, `SET LOCAL session_replication_role='replica'`)
			if e == nil {
				_, e = tx.Exec(ctx, fault.after)
			}
			if e == nil {
				_, e = tx.Exec(ctx, `SET LOCAL session_replication_role='origin'`)
			}
			if e == nil {
				e = tx.Commit(ctx)
			} else {
				_ = tx.Rollback(ctx)
			}
			if e != nil {
				t.Fatal(e)
			}
		}
		// A separate same-owner/auth-version session with a rotated audit is not
		// a successor of the original authorization. Reject that unrelated branch.
		currentRequest := httptest.NewRequest("GET", "/", nil)
		currentRequest.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: f.session})
		current, e := f.h.session(currentRequest, false)
		if e != nil {
			t.Fatal(e)
		}
		unrelated := uuid.New()
		tx, e = f.pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(ctx, `UPDATE public.tsw_owner_sessions SET revoked_at=now(),revocation_reason='owner_request' WHERE id=$1`, current.SessionID)
		if e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO public.tsw_owner_sessions(id,owner_id,token_hash,auth_version,idle_expires_at,absolute_expires_at)SELECT $2,owner_id,decode(repeat('99',32),'hex'),auth_version,idle_expires_at,absolute_expires_at FROM public.tsw_owner_sessions WHERE id=$1`, current.SessionID, unrelated)
		}
		if e == nil {
			_, e = audit.Write(ctx, tx, audit.Event{Type: audit.SessionRotated, Actor: audit.ActorOwner, OwnerID: f.owner, EntityType: "owner_session", EntityID: unrelated.String(), Outcome: audit.OutcomeSucceeded, CorrelationID: "mock-unrelated-branch", Details: audit.SessionDetails{Reason: "session_revocation", PredecessorSessionID: uuid.NewString()}, IdempotencyKey: "mock-unrelated-branch"})
		}
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if e != nil {
			t.Fatal(e)
		}
		blocked := registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		if blocked.Code != 404 {
			t.Fatal("unrelated rotated session continued original authority", blocked.Code, blocked.Body.String())
		}
		f.exec(t, `UPDATE public.tsw_owner_sessions SET revoked_at=NULL,revocation_reason=NULL WHERE id=$1`, current.SessionID)
		f.exec(t, `DELETE FROM public.tsw_owner_sessions WHERE id=$1`, unrelated)
		tx, e = f.pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		nextToken, _, e := f.h.rotateSessionTx(ctx, tx, current, "public_inventory_authorization", currentRequest)
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if e != nil {
			t.Fatal(e)
		}
		f.session = nextToken
		if e = f.pool.QueryRow(ctx, `SELECT public.tsw_archived_batch_zip_ready($1,$2)`, a.id, slot).Scan(&archivedReady); e != nil || !archivedReady {
			t.Fatal("legitimate two-step rotation chain lost original authority", e)
		}
		f.exec(t, `TRUNCATE public.tsw_rate_limit_buckets`)
		// The deliberate mock clock/current-fact edits above are finished. Claims,
		// recovery and downloads must preserve these exact stored original facts.
		before = publicZIPOriginalDigest(t, f)
	})
	t.Run("atomic_order_fault_rolls_back_reservation", func(t *testing.T) {
		f.exec(t, `CREATE FUNCTION public.public_zip_order_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'mock order save failure'; END $$; CREATE TRIGGER public_zip_order_fault BEFORE INSERT ON public.tsw_public_zip_orders FOR EACH ROW EXECUTE FUNCTION public.public_zip_order_fault()`)
		w := registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		if w.Code != 503 {
			t.Fatal(w.Code, w.Body.String())
		}
		f.exec(t, `DROP TRIGGER public_zip_order_fault ON public.tsw_public_zip_orders; DROP FUNCTION public.public_zip_order_fault()`)
		if n, r, d := publicZIPCounts(t, f); n != 0 || r != 0 || d != 0 {
			t.Fatal("partial sale survived", n, r, d)
		}
	})
	t.Run("concurrent_first_claim_same_original_customer", func(t *testing.T) {
		replies := make(chan *httptest.ResponseRecorder, 3)
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				replies <- registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
			}()
		}
		wg.Wait()
		close(replies)
		for w := range replies {
			if w.Code != 200 || len(w.Result().Cookies()) != 1 || !strings.Contains(w.Body.String(), `"deliveryFormat":"zip"`) {
				t.Fatal(w.Code, w.Body.String())
			}
			cookie = w.Result().Cookies()[0]
		}
		if n, r, d := publicZIPCounts(t, f); n != 1 || r != 1 || d != 0 {
			t.Fatal("duplicate or fake delivery", n, r, d)
		}
		var protections int
		f.pool.QueryRow(ctx, `SELECT count(*) FROM public.tsw_batch_zip_protections`).Scan(&protections)
		if protections != a.count {
			t.Fatal("incomplete protection", protections)
		}
		if err := f.h.ReserveBatchZIP(ctx, a.id, BatchZIPRecipient{"public", "other-customer", "other-order"}); err == nil {
			t.Fatal("second customer accepted")
		}
		if err := f.h.ReserveBatchZIP(ctx, a.id, BatchZIPRecipient{"owner_channel", "same-name", "different-channel"}); err == nil {
			t.Fatal("channel name forged Public sale")
		}
		if _, err := f.pool.Exec(ctx, `UPDATE public.tsw_public_zip_orders SET customer_id='other'`); err == nil {
			t.Fatal("mutable original order")
		}
	})
	t.Run("restart_status_recovery_never_regenerates", func(t *testing.T) {
		h = NewPublicRedeemHandler(f.pool, f.h.keyRing, nil)
		status := registeredZIPRequest(h, "GET", "/redeem/state", nil, cookie)
		if status.Code != 200 || bytes.Contains(status.Body.Bytes(), []byte("password")) || bytes.Contains(status.Body.Bytes(), []byte("original-refresh")) {
			t.Fatal(status.Code, status.Body.String())
		}
		// Claim deadline has passed, but independently authorized original access is
		// still valid. Recovery is the same order, never a fresh platform grant.
		inventoryTimeFixture(t, f, a.id, time.Now().Add(-time.Minute), accessExpiry)
		restored := registeredZIPRequest(h, "POST", "/redeem/reclaim", map[string]string{"cardSecret": secret}, nil)
		if restored.Code != 202 || !strings.Contains(restored.Body.String(), `"result":"restored"`) {
			t.Fatal(restored.Code, restored.Body.String())
		}
		cookie = restored.Result().Cookies()[0]
		poll := registeredZIPRequest(h, "GET", "/redeem/reclaim/status", nil, cookie)
		if poll.Code != 200 {
			t.Fatal(poll.Code, poll.Body.String())
		}
		inventoryTimeFixture(t, f, a.id, claimExpiry, accessExpiry)
		if n, r, d := publicZIPCounts(t, f); n != 1 || r != 1 || d != 0 {
			t.Fatal(n, r, d)
		}
	})
	t.Run("archive_key_and_transfer_fault_keep_pending", func(t *testing.T) {
		saved := h.keyRing
		h.keyRing = nil
		w := registeredZIPRequest(h, "POST", "/redeem/download", nil, cookie)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "public_delivery_pending") {
			t.Fatal(w.Code, w.Body.String())
		}
		h.keyRing = saved
		writer := &interruptedZIPWriter{header: http.Header{}}
		request := httptest.NewRequest("POST", "/internal/v1/public/redeem/download", nil)
		request.AddCookie(cookie)
		internalapi.Handler(h).ServeHTTP(writer, request)
		if writer.status != 200 {
			t.Fatal(writer.status)
		}
		if n, r, d := publicZIPCounts(t, f); n != 1 || r != 1 || d != 0 {
			t.Fatal("write failure became delivery", n, r, d)
		}
	})
	t.Run("cross_workspace_legacy_second_sale_denied", func(t *testing.T) {
		legacy := zipLegacyPublicationFixture(t, f)
		if err := legacy.publish(ctx); err == nil {
			t.Fatal("other Workspace bypassed global original protection")
		}
	})
	t.Run("registered_gateway_frontend_backend_original_download", func(t *testing.T) {
		// Browser is opt-in only to make a missing Chrome/build an explicit failed
		// whole-ticket gate, while ordinary integration can run without Node.
		if os.Getenv("TSW_PUBLIC_BROWSER") != "1" {
			t.Skip("TSW_PUBLIC_BROWSER=1 requires compiled Public and desktop Chrome")
		}
		f.exec(t, `TRUNCATE public.tsw_rate_limit_buckets`)
		private := httptest.NewTLSServer(internalapi.Handler(h))
		defer private.Close()
		client := private.Client()
		client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{{}}
		static, err := filepath.Abs("../../web/dist/public")
		if err != nil {
			t.Fatal(err)
		}
		gateway, closeGateway, err := NewGatewayHandler(GatewayConfig{ControlURL: private.URL + privateHealthPath, ProbeClient: client, StaticDir: static})
		if err != nil {
			t.Fatal(err)
		}
		defer closeGateway()
		server := httptest.NewTLSServer(gateway)
		defer server.Close()
		command := exec.Command("node", "../../web/tools/public-browser.mjs", server.URL, secret, a.filename)
		command.Env = append(os.Environ(), "TSW_BROWSER_EVIDENCE="+os.Getenv("TSW_BROWSER_EVIDENCE"))
		output, err := command.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal("registered browser boundary", err)
		}
	})
	t.Run("original_ZIP_and_dynamic_token_permission_expiry", func(t *testing.T) {
		w := registeredZIPRequest(h, "POST", "/redeem/download", nil, cookie)
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" || !bytes.Equal(w.Body.Bytes(), original) {
			t.Fatal(w.Code, w.Header())
		}
		if n, r, d := publicZIPCounts(t, f); n != 1 || r != 1 || d != 1 {
			t.Fatal(n, r, d)
		}
		if before != publicZIPOriginalDigest(t, f) || zipCount(t, f) != 1 {
			t.Fatal("Public changed original source or regenerated archive")
		}
		hash, _ := publicaccess.HashToken(cookie.Value)
		f.exec(t, `UPDATE public.tsw_public_zip_tokens SET expires_at=clock_timestamp()-interval '1 minute' WHERE token_hash=$1`, hash[:])
		w = registeredZIPRequest(h, "GET", "/redeem/state", nil, cookie)
		if w.Code != 404 {
			t.Fatal("expired cookie", w.Code)
		}
		restore := registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		if restore.Code != 200 {
			t.Fatal(restore.Code, restore.Body.String())
		}
		cookie = restore.Result().Cookies()[0]
		f.exec(t, `UPDATE public.tsw_public_zip_inventory SET enabled=false WHERE package_id=$1`, a.id)
		w = registeredZIPRequest(h, "POST", "/redeem/download", nil, cookie)
		if w.Code != 404 {
			t.Fatal("permission disappeared", w.Code)
		}
		f.exec(t, `UPDATE public.tsw_public_zip_inventory SET enabled=true WHERE package_id=$1`, a.id)
		inventoryTimeFixture(t, f, a.id, time.Now().Add(-2*time.Minute), time.Now().Add(-time.Minute))
		w = registeredZIPRequest(h, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		if w.Code != 404 {
			t.Fatal("expired access", w.Code)
		}
		inventoryTimeFixture(t, f, a.id, claimExpiry, accessExpiry)
	})
	t.Run("permanent_revocation_all_boundaries_preserve_protection", func(t *testing.T) {
		f.exec(t, `TRUNCATE public.tsw_rate_limit_buckets`)
		rotationFault(t, f, true)
		failed := inventoryHTTP(f, a.id, "POST", "revoke", `{"confirmed":true}`)
		if failed.Code != 500 {
			t.Fatal("revocation rotation fault", failed.Code)
		}
		rotationFault(t, f, false)
		stillOwner := inventoryHTTP(f, a.id, "GET", "", "")
		stillPublic := registeredZIPRequest(h, "GET", "/redeem/state", nil, cookie)
		if stillOwner.Code != 200 || stillPublic.Code != 200 {
			t.Fatal("rotation failure partially revoked original authorization", stillOwner.Code, stillPublic.Code)
		}
		oldOwnerToken := f.session
		w := inventoryHTTP(f, a.id, "POST", "revoke", `{"confirmed":true}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "revoked") {
			t.Fatal(w.Code, w.Body.String())
		}
		acceptInventoryRotation(t, f, a.id, w, oldOwnerToken)
		w = inventoryHTTP(f, a.id, "POST", "revoke", `{"confirmed":true}`)
		if w.Code != 200 || len(w.Result().Cookies()) != 0 {
			t.Fatal("idempotent revocation rotated session", w.Code, w.Header())
		}
		for _, path := range []string{"/redeem/confirm", "/redeem/reclaim", "/redeem/credential-status"} {
			w := registeredZIPRequest(h, "POST", path, map[string]string{"cardSecret": secret}, nil)
			if w.Code != 404 {
				t.Fatal(path, w.Code, w.Body.String())
			}
		}
		for _, path := range []string{"/redeem/state", "/redeem/records", "/redeem/reclaim/status", "/redeem/download"} {
			method := "GET"
			if path == "/redeem/download" {
				method = "POST"
			}
			w := registeredZIPRequest(h, method, path, nil, cookie)
			if w.Code != 404 {
				t.Fatal(path, w.Code, w.Body.String())
			}
		}
		if n, r, d := publicZIPCounts(t, f); n != 1 || r != 1 || d != 1 {
			t.Fatal(n, r, d)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE public.tsw_public_zip_inventory SET revoked_at=NULL,enabled=true WHERE package_id=$1`, a.id); err == nil {
			t.Fatal("revocation undone")
		}
	})
}
