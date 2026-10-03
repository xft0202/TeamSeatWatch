//go:build integration

package runtime

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
)

func zipFixture(t *testing.T) (*removalFixture, ownerContext, uuid.UUID) {
	t.Helper()
	f, o, slot, _, _ := usageFixture(t)
	usageObserve(t, f, o, slot, false)
	f.h.pool = f.pool
	return f, o, slot
}
func zipCount(t *testing.T, f *removalFixture) int {
	t.Helper()
	var n int
	if e := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.tsw_batch_zip_archives`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func zipData(t *testing.T, f *removalFixture, a batchZIPRecord) []byte {
	t.Helper()
	data, e := f.h.openBatchZIP(a)
	if e != nil {
		t.Fatal(e)
	}
	return data
}
func zipHTTP(f *removalFixture, preview uuid.UUID, method, action, body string, changes ...func(*http.Request)) *httptest.ResponseRecorder {
	path := fmt.Sprintf("/api/owner/v1/expiry-rotation/previews/%s/batch-zip", preview)
	if action != "" {
		path += "/" + action
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Origin", "https://owner.test")
	req.Header.Set(auth.CSRFHeaderName, f.csrf)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: f.session})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: f.csrf})
	for _, c := range changes {
		c(req)
	}
	w := httptest.NewRecorder()
	ownerapi.HandlerWithOptions(f.h, ownerapi.StdHTTPServerOptions{ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, e error) {
		if isCSRFBindingError(e) {
			writeProblem(w, r, 403, "csrf_rejected", "Forbidden", "Rejected", 0)
			return
		}
		writeProblem(w, r, 400, "invalid_request", "Invalid", "Invalid", 0)
	}}).ServeHTTP(w, req)
	return w
}
func TestBatchZIPRegisteredOwnerWholeObjectOriginalReplay(t *testing.T) {
	f, o, slot := zipFixture(t)
	before := usageOriginalDigest(t, f)
	w := zipHTTP(f, f.preview.Id, "GET", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"canGenerate":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if zipCount(t, f) != 0 {
		t.Fatal("GET generated")
	}
	w = zipHTTP(f, f.preview.Id, "POST", "", `{"confirmed":true}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"phase":"prepared"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	a, e := readBatchZIP(context.Background(), f.pool, uuid.MustParse(f.owner), f.preview.Id)
	if e != nil {
		t.Fatal(e)
	}
	data := zipData(t, f, a)
	z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil || len(z.File) != 2 {
		t.Fatal(z, e)
	}
	for _, file := range z.File {
		r, _ := file.Open()
		b, _ := io.ReadAll(r)
		r.Close()
		if file.Name == "account-materials.txt" && string(b) != f.preview.Candidates[0].Identifier+"----password----JBSWY3DPEHPK3PXP\n" {
			t.Fatal(string(b))
		}
		if file.Name == "sub2api_all.json" && (!bytes.Contains(b, []byte("original-refresh")) || !bytes.Contains(b, []byte(f.space.String()))) {
			t.Fatal("wrong OAuth source")
		}
	}
	download := zipHTTP(f, f.preview.Id, "GET", "download", "")
	if download.Code != 200 || !bytes.Equal(download.Body.Bytes(), data) || download.Header().Get("Content-Type") != "application/zip" || download.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(download.Code, download.Header())
	}
	if before != usageOriginalDigest(t, f) || executionState(t, f, slot) != "reconcile_required" {
		t.Fatal("generation discharged original obligation")
	}
	restarted := *f.h
	f.h = &restarted
	again, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id)
	if e != nil || again.id != a.id || !bytes.Equal(zipData(t, f, again), data) || zipCount(t, f) != 1 {
		t.Fatal("restart regenerated", e)
	}
	if bytes.Contains(a.sealed, []byte("password")) || bytes.Contains(a.sealed, []byte("original-refresh")) {
		t.Fatal("archive stored plaintext")
	}
	for _, key := range []string{"password", "TOTP", "access_token", "refresh_token", "nonce", "sealed_archive", "customer_id", "authorization_id"} {
		if strings.Contains(w.Body.String(), key) {
			t.Fatal("status leaked", key)
		}
	}
}
func TestBatchZIPHTTPAuthorizationAndStrictBody(t *testing.T) {
	f, _, _ := zipFixture(t)
	for _, body := range []string{`{}`, `{"confirmed":false}`, `{"confirmed":true,"accountId":"replace"}`, `{"confirmed":true,"Confirmed":true}`, `{"confirmed":true,"confirmed":true}`, `{"confirmed":true} {}`} {
		if w := zipHTTP(f, f.preview.Id, "POST", "", body); w.Code != 422 {
			t.Fatal(body, w.Code)
		}
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del(auth.CSRFHeaderName) }, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.test") }, func(r *http.Request) { r.Header.Set(auth.CSRFHeaderName, "bad") }} {
		if w := zipHTTP(f, f.preview.Id, "POST", "", `{"confirmed":true}`, change); w.Code != 403 {
			t.Fatal("CSRF", w.Code)
		}
	}
	for _, method := range []string{"GET", "POST"} {
		if w := zipHTTP(f, f.preview.Id, method, "", `{"confirmed":true}`, func(r *http.Request) { r.Header.Del("Cookie") }); w.Code != func() int {
			if method == "GET" {
				return 401
			}
			return 403
		}() {
			t.Fatal("unauthenticated", w.Code)
		}
	}
	if zipHTTP(f, uuid.New(), "GET", "", "").Code != 404 || zipHTTP(f, uuid.New(), "POST", "", `{"confirmed":true}`).Code != 404 || zipHTTP(f, f.preview.Id, "GET", "download", "").Code != 404 {
		t.Fatal("scope/preparation exposed")
	}
	if zipCount(t, f) != 0 {
		t.Fatal("rejected input generated")
	}
}
func TestBatchZIPAtomicSaveAssociationFailureAndRecovery(t *testing.T) {
	for _, table := range []string{"tsw_batch_zip_archives", "tsw_batch_zip_members"} {
		t.Run(table, func(t *testing.T) {
			f, o, slot := zipFixture(t)
			before := usageOriginalDigest(t, f)
			f.exec(t, `CREATE FUNCTION public.fail_zip_insert()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected archive association failure';END$$;CREATE TRIGGER fail_zip_insert BEFORE INSERT ON public.`+table+` FOR EACH ROW EXECUTE FUNCTION public.fail_zip_insert()`)
			if _, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id); e == nil {
				t.Fatal("injected write succeeded")
			}
			if zipCount(t, f) != 0 || before != usageOriginalDigest(t, f) || !usageReady(t, f, slot) {
				t.Fatal("failure released or half-persisted original")
			}
			f.exec(t, `DROP TRIGGER fail_zip_insert ON public.`+table+`;DROP FUNCTION public.fail_zip_insert()`)
			restarted := *f.h
			f.h = &restarted
			if _, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id); e != nil || zipCount(t, f) != 1 {
				t.Fatal(e)
			}
		})
	}
}
func TestBatchZIPConcurrentGenerationAndPermanentSingleCustomer(t *testing.T) {
	f, o, slot := zipFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	result := make(chan batchZIPRecord, 8)
	fail := make(chan error, 8)
	for range 8 {
		wg.Go(func() { a, e := f.h.prepareBatchZIP(ctx, o, f.preview.Id); result <- a; fail <- e })
	}
	wg.Wait()
	close(result)
	close(fail)
	var original uuid.UUID
	for e := range fail {
		if e != nil {
			t.Fatal(e)
		}
	}
	for a := range result {
		if original == uuid.Nil {
			original = a.id
		}
		if a.id != original {
			t.Fatal("second version")
		}
	}
	if zipCount(t, f) != 1 {
		t.Fatal("duplicate archives")
	}
	before := usageOriginalDigest(t, f)
	r := BatchZIPRecipient{"owner_channel", "global-customer-a", "frozen-channel-order"}
	wrong := BatchZIPRecipient{"public", "global-customer-b", "independent-card-order"}
	if _, _, e := f.h.ReadBatchZIPForRecipient(ctx, original, r); e == nil {
		t.Fatal("bytes before reservation")
	}
	errs := make(chan error, 2)
	for _, receiver := range []BatchZIPRecipient{r, wrong} {
		receiver := receiver
		wg.Go(func() { errs <- f.h.ReserveBatchZIP(ctx, original, receiver) })
	}
	wg.Wait()
	close(errs)
	succeeded := 0
	for e := range errs {
		if e == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatal("not exactly one customer", succeeded)
	}
	var win BatchZIPRecipient
	if e := f.pool.QueryRow(ctx, `SELECT channel,customer_id,authorization_id FROM public.tsw_batch_zip_receivers`).Scan(&win.Channel, &win.CustomerID, &win.AuthorizationID); e != nil {
		t.Fatal(e)
	}
	a, _ := readBatchZIP(ctx, f.pool, uuid.MustParse(f.owner), f.preview.Id)
	data := zipData(t, f, a)
	for range 2 {
		if e := f.h.ReserveBatchZIP(ctx, original, win); e != nil {
			t.Fatal(e)
		}
		_, b, e := f.h.ReadBatchZIPForRecipient(ctx, original, win)
		if e != nil || !bytes.Equal(data, b) {
			t.Fatal("original reget", e)
		}
	}
	other := win
	other.Channel = "public"
	if win.Channel == "public" {
		other.Channel = "owner_channel"
	}
	if e := f.h.ReserveBatchZIP(ctx, original, other); e == nil {
		t.Fatal("channel orders conflated")
	}
	if before != usageOriginalDigest(t, f) || usageReady(t, f, slot) {
		t.Fatal("original obligation modified or protected account ready")
	}
	if _, clear, e := rotationCandidateLedgerLookup(ctx, f.pool, f.preview.Candidates[0].AccountId, uuid.New()); e != nil || clear {
		t.Fatal("cross Workspace bypass", clear, e)
	}
	_, protection, e := f.h.persistedRotationEvidence(ctx, f.preview.Candidates[0].AccountId, uuid.New(), time.Now(), time.Now().Add(time.Minute))
	if e != nil || protection.Status != "sale_reserved" {
		t.Fatal("other Workspace lost protection", protection, e)
	}
	if w := zipHTTP(f, f.preview.Id, "GET", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"phase":"reserved"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if e = f.h.MarkBatchZIPDelivered(ctx, original, win, "final-receipt"); e != nil {
		t.Fatal(e)
	}
	if e = f.h.MarkBatchZIPDelivered(ctx, original, win, "final-receipt"); e != nil {
		t.Fatal("receipt replay", e)
	}
	if e = f.h.MarkBatchZIPDelivered(ctx, original, win, "new-receipt"); e == nil {
		t.Fatal("final receipt rewritten")
	}
	for _, table := range []string{"tsw_batch_zip_archives", "tsw_batch_zip_members", "tsw_batch_zip_receivers", "tsw_batch_zip_protections", "tsw_batch_zip_delivered"} {
		if _, e = f.pool.Exec(ctx, `DELETE FROM public.`+table); e == nil {
			t.Fatal("protection/original deletable", table)
		}
	}
	restarted := *f.h
	f.h = &restarted
	changed, _ := targetdomain.SealMaterial("changed-password", f.h.keyRing)
	f.exec(t, `UPDATE public.tsw_target_credentials SET password_secret=$2,secret_revision=secret_revision+1,version=version+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId, changed)
	_, b, e := f.h.ReadBatchZIPForRecipient(ctx, original, win)
	if e != nil || !bytes.Equal(b, data) {
		t.Fatal("later source change regenerated or blocked original", e)
	}
}
func TestBatchZIPReservationAtomicFailureRetainsOriginal(t *testing.T) {
	for _, table := range []string{"tsw_batch_zip_receivers", "tsw_batch_zip_protections"} {
		t.Run(table, func(t *testing.T) {
			f, o, slot := zipFixture(t)
			a, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id)
			if e != nil {
				t.Fatal(e)
			}
			before := usageOriginalDigest(t, f)
			f.exec(t, `CREATE FUNCTION public.fail_zip_receiver()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected receiver failure';END$$;CREATE TRIGGER fail_zip_receiver BEFORE INSERT ON public.`+table+` FOR EACH ROW EXECUTE FUNCTION public.fail_zip_receiver()`)
			r := BatchZIPRecipient{"public", "same-customer", "authorized-public-order"}
			if e = f.h.ReserveBatchZIP(context.Background(), a.id, r); e == nil {
				t.Fatal("write succeeded")
			}
			var n int
			_ = f.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM public.tsw_batch_zip_receivers)+(SELECT count(*) FROM public.tsw_batch_zip_protections)`).Scan(&n)
			if n != 0 || !usageReady(t, f, slot) || before != usageOriginalDigest(t, f) {
				t.Fatal("failed reservation half-protected/discharged")
			}
			if _, _, e = f.h.ReadBatchZIPForRecipient(context.Background(), a.id, r); e == nil {
				t.Fatal("write failure exposed material")
			}
			f.exec(t, `DROP TRIGGER fail_zip_receiver ON public.`+table+`;DROP FUNCTION public.fail_zip_receiver()`)
			if e = f.h.ReserveBatchZIP(context.Background(), a.id, r); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestBatchZIPQualificationChangesNeverProducePackage(t *testing.T) {
	for _, mode := range []string{"totp", "material_write", "unknown", "account_scope", "positive_history", "revoked", "stop", "old_customer"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot := zipFixture(t)
			switch mode {
			case "totp":
				sealed, _ := targetdomain.SealMaterial("invalid!", f.h.keyRing)
				f.exec(t, `UPDATE public.tsw_target_credentials SET totp_secret=$2,secret_revision=secret_revision+1,version=version+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId, sealed)
			case "material_write":
				f.exec(t, `UPDATE public.tsw_target_credentials SET material_status='needs_totp',version=version+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId)
			case "unknown", "account_scope", "positive_history":
				m := &usageMock{f: f, scope: "workspace", result: "unknown"}
				if mode == "account_scope" {
					m.scope = "account"
					m.result = "zero"
				}
				if mode == "positive_history" {
					m.result = "positive"
				}
				f.h.rotationUsageAdapters = func(platform.DiscoveryClient) platform.RotationUsageReader { return m }
				usageObserve(t, f, o, slot, true)
			case "revoked":
				f.exec(t, `UPDATE public.tsw_expiry_rotation_previews SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1`, f.preview.Id, f.owner)
			case "stop":
				f.exec(t, `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
			case "old_customer":
				f.exec(t, `INSERT INTO public.tsw_rotation_global_protections(target_account_id,status,evidence_source,evidence_id,observed_at)VALUES($1,'delivered','fixture',repeat('f',64),clock_timestamp())`, f.preview.Candidates[0].AccountId)
			}
			before := usageOriginalDigest(t, f)
			if _, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id); e == nil || zipCount(t, f) != 0 {
				t.Fatal("unqualified package", mode, e)
			}
			if before != usageOriginalDigest(t, f) || executionState(t, f, slot) != "reconcile_required" {
				t.Fatal("rejection released original")
			}
		})
	}
}
func TestBatchZIPMigration36DownUpImmutableSources(t *testing.T) {
	f, o, _ := zipFixture(t)
	a, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id)
	if e != nil {
		t.Fatal(e)
	}
	_ = a
	before := usageOriginalDigest(t, f)
	membershipSchemaVersion(t, 35)
	var absent bool
	if e = f.pool.QueryRow(context.Background(), `SELECT to_regclass('public.tsw_batch_zip_archives') IS NULL AND to_regclass('public.tsw_rotation_effective_protections') IS NULL AND to_regprocedure('public.tsw_rotation_join_usage_ready_before_zip(uuid)') IS NULL`).Scan(&absent); e != nil || !absent {
		t.Fatal(absent, e)
	}
	membershipSchemaVersion(t, migrations.RequiredVersion)
	membershipSchemaVersion(t, migrations.RequiredVersion)
	if before != usageOriginalDigest(t, f) {
		t.Fatal("migration mutated slot/source obligation")
	}
	if _, e = f.h.prepareBatchZIP(context.Background(), o, f.preview.Id); e != nil {
		t.Fatal(e)
	}
}

func TestBatchZIPRegistered101AccountsAndNoPartialSubset(t *testing.T) {
	f, o, slots := zipWholeBatchFixture(t, 101)
	if len(slots) != 101 {
		t.Fatal(len(slots))
	}
	w := zipHTTP(f, f.preview.Id, "POST", "", `{"confirmed":true}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	download := zipHTTP(f, f.preview.Id, "GET", "download", "")
	if download.Code != 200 {
		t.Fatal(download.Code)
	}
	z, e := zip.NewReader(bytes.NewReader(download.Body.Bytes()), int64(download.Body.Len()))
	if e != nil || len(z.File) != 4 {
		t.Fatal(e, len(z.File))
	}
	names := map[string]int{}
	for _, file := range z.File {
		r, _ := file.Open()
		data, _ := io.ReadAll(r)
		r.Close()
		if file.Name == "account-materials.txt" {
			names[file.Name] = len(strings.Split(strings.TrimSpace(string(data)), "\n"))
			continue
		}
		var bundle struct {
			Accounts []json.RawMessage `json:"accounts"`
		}
		if e = json.Unmarshal(data, &bundle); e != nil {
			t.Fatal(e)
		}
		names[file.Name] = len(bundle.Accounts)
	}
	if names["account-materials.txt"] != 101 || names["sub2api_all.json"] != 101 || names["split/sub2api_001_100.json"] != 100 || names["split/sub2api_101_101.json"] != 1 {
		t.Fatal(names)
	}
	a, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id)
	if e != nil || a.count != 101 {
		t.Fatal(a, e)
	}
}
func TestBatchZIPFirstCustomerExposureRechecksOriginalSnapshot(t *testing.T) {
	for _, mode := range []string{"positive", "unknown", "credentials", "windows"} {
		t.Run(mode, func(t *testing.T) {
			f, o, slot := zipFixture(t)
			a, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id)
			if e != nil {
				t.Fatal(e)
			}
			data := zipData(t, f, a)
			switch mode {
			case "positive", "unknown":
				m := &usageMock{f: f, scope: "workspace", result: mode}
				f.h.rotationUsageAdapters = func(platform.DiscoveryClient) platform.RotationUsageReader { return m }
				usageObserve(t, f, o, slot, true)
			case "credentials":
				changed, _ := targetdomain.SealMaterial("changed-password", f.h.keyRing)
				f.exec(t, `UPDATE public.tsw_target_credentials SET password_secret=$2,secret_revision=secret_revision+1,version=version+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId, changed)
			case "windows":
				m := &usageMock{f: f, scope: "workspace", result: "zero"}
				f.h.rotationUsageAdapters = func(platform.DiscoveryClient) platform.RotationUsageReader { return m }
				usageObserve(t, f, o, slot, true)
			}
			before := usageOriginalDigest(t, f)
			r := BatchZIPRecipient{"owner_channel", "first-customer", "order"}
			if e = f.h.ReserveBatchZIP(context.Background(), a.id, r); e == nil {
				t.Fatal("stale original became first customer exposure", mode)
			}
			if _, _, e = f.h.ReadBatchZIPForRecipient(context.Background(), a.id, r); e == nil {
				t.Fatal("unreserved full materials exposed")
			}
			again, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id)
			if e != nil || again.id != a.id || !bytes.Equal(data, zipData(t, f, again)) || before != usageOriginalDigest(t, f) {
				t.Fatal("stale qualification replaced original package/obligation", e)
			}
		})
	}
}
