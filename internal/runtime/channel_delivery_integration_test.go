//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
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
)

type channelMock struct {
	mu                        sync.Mutex
	remote                    map[uuid.UUID]ChannelReception
	pushes                    map[uuid.UUID]int
	receivedObjects           []ChannelObject
	destination               ChannelDestination
	final                     bool
	partial                   bool
	partialReception          bool
	timeout                   bool
	receivePreparationFailure bool
	finalPreparationFailure   bool
	unresolvedReception       bool
	unresolvedFinal           bool
	authorizeHook             func()
	hook                      func()
	finalHook                 func()
	zip                       []byte
	deliverCalls              int
	finalReceipts             []ChannelFinalReceipt
	recipient                 BatchZIPRecipient
}

func (m *channelMock) Receive(ctx context.Context, d ChannelDestination, o ChannelObject, fence func(context.Context) error) (ChannelReception, error) {
	if m.receivePreparationFailure {
		return ChannelReception{}, errChannelPending
	}
	if e := fence(ctx); e != nil {
		return ChannelReception{}, e
	}
	m.mu.Lock()
	m.pushes[o.AccountID]++
	m.destination = d
	m.receivedObjects = append(m.receivedObjects, o)
	r := ChannelReception{RemoteObjectID: o.AccountID.String(), ReceiptID: "received-" + o.AccountID.String(), ObservedAt: time.Now().UTC()}
	if !m.unresolvedReception {
		m.remote[o.AccountID] = r
	}
	hook, timeout, partial, count := m.hook, m.timeout, m.partialReception, len(m.remote)
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	if timeout || m.unresolvedReception || partial && count > 1 {
		return ChannelReception{}, errChannelPending
	}
	return r, nil
}
func (m *channelMock) Inspect(_ context.Context, d ChannelDestination, o ChannelObject) (ChannelReception, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d != m.destination {
		return ChannelReception{}, errChannelPending
	}
	r, ok := m.remote[o.AccountID]
	if !ok {
		return r, errChannelPending
	}
	return r, nil
}
func (m *channelMock) AuthorizeZIP(context.Context, ChannelDestination, []ChannelObject) (BatchZIPRecipient, error) {
	if !m.final {
		return BatchZIPRecipient{}, errChannelFinalUnavailable
	}
	if m.authorizeHook != nil {
		m.authorizeHook()
	}
	return m.recipient, nil
}
func (m *channelMock) DeliverZIP(ctx context.Context, _ ChannelDestination, objects []ChannelObject, r BatchZIPRecipient, _ string, data []byte, fence func(context.Context) error) ([]ChannelFinalReceipt, error) {
	if m.finalPreparationFailure {
		return nil, errChannelPending
	}
	if e := fence(ctx); e != nil {
		return nil, e
	}
	m.deliverCalls++
	m.zip = bytes.Clone(data)
	m.finalReceipts = nil
	if m.unresolvedFinal {
		return nil, errChannelPending
	}
	for _, o := range objects {
		m.finalReceipts = append(m.finalReceipts, ChannelFinalReceipt{AccountID: o.AccountID, RemoteObjectID: o.AccountID.String(), ReceiptID: "final-" + o.AccountID.String(), CustomerID: r.CustomerID, AuthorizationID: r.AuthorizationID, PackageDigest: o.PackageDigest, ObservedAt: time.Now().UTC()})
	}
	if m.finalHook != nil {
		m.finalHook()
	}
	if m.partial && len(m.finalReceipts) > 1 {
		return m.finalReceipts[:1], errChannelPending
	}
	return m.finalReceipts, nil
}
func (m *channelMock) InspectZIP(context.Context, ChannelDestination, []ChannelObject, BatchZIPRecipient) ([]ChannelFinalReceipt, error) {
	return m.finalReceipts, nil
}
func channelFixture(t *testing.T, n int) (*removalFixture, ownerContext, batchZIPRecord, *channelMock) {
	t.Helper()
	var f *removalFixture
	var o ownerContext
	if n == 1 {
		f, o, _ = zipFixture(t)
	} else {
		f, o, _ = zipWholeBatchFixture(t, n)
	}
	a, e := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id)
	if e != nil {
		t.Fatal(e)
	}
	key, nonce, sealed, e := auth.EncryptSecret([]byte("original-channel-secret"), f.h.keyRing)
	if e != nil {
		t.Fatal(e)
	}
	// Replace only the placeholder encrypted upstream destination fixture. This
	// transaction-local setup never changes production triggers or saved epochs.
	tx, e := f.pool.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(context.Background(), `SET LOCAL session_replication_role='replica';`); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(context.Background(), `UPDATE public.tsw_delivery_destinations SET secret_key_version=$2,secret_nonce=$3,secret_ciphertext=$4 WHERE id=$1`, f.preview.DestinationId, key, nonce, sealed); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(context.Background(), `SET LOCAL session_replication_role='origin'`); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(context.Background()); e != nil {
		t.Fatal(e)
	}
	m := &channelMock{remote: map[uuid.UUID]ChannelReception{}, pushes: map[uuid.UUID]int{}, recipient: BatchZIPRecipient{"owner_channel", "actual-customer", "actual-channel-authorization"}}
	f.h.channelDelivery = m
	return f, o, a, m
}
func channelHTTP(f *removalFixture, preview uuid.UUID, method, action, body string, changes ...func(*http.Request)) *httptest.ResponseRecorder {
	path := "/api/owner/v1/expiry-rotation/previews/" + preview.String() + "/channel-delivery"
	if action != "" {
		path += "/" + action
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Origin", "https://owner.test")
	req.Header.Set(auth.CSRFHeaderName, f.csrf)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: f.session})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: f.csrf})
	for _, change := range changes {
		change(req)
	}
	w := httptest.NewRecorder()
	ownerapi.HandlerWithOptions(f.h, ownerapi.StdHTTPServerOptions{ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, e error) {
		writeProblem(w, r, 403, "csrf_rejected", "Forbidden", "Rejected", 0)
	}}).ServeHTTP(w, req)
	return w
}
func channelState(t *testing.T, f *removalFixture) ownerapi.ChannelDeliveryStatus {
	t.Helper()
	w := channelHTTP(f, f.preview.Id, "GET", "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var s ownerapi.ChannelDeliveryStatus
	if e := json.Unmarshal(w.Body.Bytes(), &s); e != nil {
		t.Fatal(e)
	}
	return s
}
func channelCounts(t *testing.T, f *removalFixture) (int, int, int, int) {
	t.Helper()
	var objects, attempts, receipts, delivered int
	if e := f.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM public.tsw_channel_objects),(SELECT count(*) FROM public.tsw_channel_attempts),(SELECT count(*) FROM public.tsw_channel_receipts),(SELECT count(*) FROM public.tsw_batch_zip_delivered)`).Scan(&objects, &attempts, &receipts, &delivered); e != nil {
		t.Fatal(e)
	}
	return objects, attempts, receipts, delivered
}
func TestChannelRegisteredWholeBatchReceptionAndSeparateFinal(t *testing.T) {
	f, o, a, m := channelFixture(t, 2)
	before := usageOriginalDigest(t, f)
	if s := channelState(t, f); s.Phase != "ready" || len(s.Objects) != 0 {
		t.Fatal(s)
	}
	if w := channelHTTP(f, f.preview.Id, "POST", "receive", `{"confirmed":true}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	s := channelState(t, f)
	if s.Phase != "received" || s.ReceivedCount != 2 || s.DeliveredCount != 0 || len(s.Objects) != 2 {
		t.Fatal(s)
	}
	if m.destination.ID != f.preview.DestinationId || m.destination.Secret != "original-channel-secret" || m.destination.Group != "42" {
		t.Fatal("wrong destination")
	}
	for _, o := range m.receivedObjects {
		if bytes.Contains(o.OAuth, []byte("password")) || bytes.Contains(o.OAuth, []byte("JBSWY")) {
			t.Fatal("reception exposed full materials")
		}
	}
	for range 2 {
		if e := f.h.runChannel(context.Background(), o, f.preview.Id, true); e != nil {
			t.Fatal(e)
		}
	}
	for _, count := range m.pushes {
		if count != 1 {
			t.Fatal("duplicate push")
		}
	}
	if before != usageOriginalDigest(t, f) {
		t.Fatal("channel discharged slot obligation")
	}
	if e := f.h.ReserveBatchZIP(context.Background(), a.id, BatchZIPRecipient{"public", "another-customer", "card-authorization"}); e == nil {
		t.Fatal("Public sold channel-held objects")
	}
	proof, _, e := f.h.persistedRotationEvidence(context.Background(), s.Objects[0].AccountId, uuid.New(), time.Now(), time.Now().Add(time.Minute))
	_ = proof
	if e != nil {
		t.Fatal(e)
	}
	m.final = true
	if w := channelHTTP(f, f.preview.Id, "POST", "reconcile", `{"confirmed":true}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	s = channelState(t, f)
	if s.Phase != "delivered" || s.DeliveredCount != 2 || m.deliverCalls != 1 || !bytes.Equal(m.zip, zipData(t, f, a)) {
		t.Fatal(s, m.deliverCalls)
	}
	restarted := *f.h
	f.h = &restarted
	if e = f.h.runChannel(context.Background(), o, f.preview.Id, true); e != nil {
		t.Fatal(e)
	}
	if m.deliverCalls != 1 {
		t.Fatal("duplicate final delivery")
	}
	if e = f.h.ReserveBatchZIP(context.Background(), a.id, BatchZIPRecipient{"owner_channel", "other-customer", "other-order"}); e == nil {
		t.Fatal("second customer")
	}
	for _, table := range []string{"tsw_channel_deliveries", "tsw_channel_objects", "tsw_channel_attempts", "tsw_channel_receipts", "tsw_channel_associations", "tsw_channel_final_attempts"} {
		if _, e = f.pool.Exec(context.Background(), "DELETE FROM public."+table); e == nil {
			t.Fatal("mutable original", table)
		}
	}
	if before != usageOriginalDigest(t, f) {
		t.Fatal("final receipt discharged original slot")
	}
}
func TestChannelTimeoutPartialRestartAndFrozenTarget(t *testing.T) {
	f, o, a, m := channelFixture(t, 2)
	m.timeout = true
	before := usageOriginalDigest(t, f)
	if e := f.h.runChannel(context.Background(), o, f.preview.Id, true); e != nil {
		t.Fatal(e)
	}
	s := channelState(t, f)
	if s.ReceivedCount != 0 || s.Objects[0].Reception != "receipt_pending" {
		t.Fatal(s)
	}
	f.exec(t, `UPDATE public.tsw_delivery_destinations SET endpoint='https://changed.fixture.test/api/v1',target_group='99',revision=revision+1 WHERE id=$1`, f.preview.DestinationId)
	before = usageOriginalDigest(t, f)
	restarted := *f.h
	f.h = &restarted
	m.timeout = false
	if e := f.h.runChannel(context.Background(), o, f.preview.Id, false); e != nil {
		t.Fatal(e)
	}
	s = channelState(t, f)
	if s.ReceivedCount != 2 || s.DeliveredCount != 0 || m.destination.Endpoint != "https://hub.fixture.test/api/v1" {
		t.Fatal(s)
	}
	for _, count := range m.pushes {
		if count != 1 {
			t.Fatal("restart repushed")
		}
	}
	if before != usageOriginalDigest(t, f) || zipCount(t, f) != 1 || a.id != *s.PackageId {
		t.Fatal("changed original")
	}
}
func TestChannelReceiptAssociationDatabaseFailuresRemainOriginal(t *testing.T) {
	for _, table := range []string{"tsw_channel_attempts", "tsw_channel_receipts", "tsw_channel_associations"} {
		t.Run(table, func(t *testing.T) {
			f, o, a, m := channelFixture(t, 1)
			before := usageOriginalDigest(t, f)
			f.exec(t, `CREATE FUNCTION public.fail_channel_write()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected channel persistence failure';END$$;CREATE TRIGGER fail_channel_write BEFORE INSERT ON public.`+table+` FOR EACH ROW EXECUTE FUNCTION public.fail_channel_write()`)
			if e := f.h.runChannel(context.Background(), o, f.preview.Id, true); e == nil {
				t.Fatal("failed gate succeeded")
			}
			objects, attempts, receipts, delivered := channelCounts(t, f)
			if objects != 1 || delivered != 0 {
				t.Fatal(objects, attempts, receipts, delivered)
			}
			if table == "tsw_channel_attempts" && len(m.pushes) != 0 || table == "tsw_channel_receipts" && receipts != 0 || table == "tsw_channel_associations" && receipts != 1 {
				t.Fatal("false persistence")
			}
			if table == "tsw_channel_associations" && channelState(t, f).Objects[0].Reception != "record_pending" {
				t.Fatal("false received terminal")
			}
			f.exec(t, `DROP TRIGGER fail_channel_write ON public.`+table+`;DROP FUNCTION public.fail_channel_write()`)
			restarted := *f.h
			f.h = &restarted
			if e := f.h.runChannel(context.Background(), o, f.preview.Id, true); e != nil {
				t.Fatal(e)
			}
			if s := channelState(t, f); s.ReceivedCount != 1 || s.DeliveredCount != 0 || *s.PackageId != a.id {
				t.Fatal(s)
			}
			for _, count := range m.pushes {
				if count != 1 {
					t.Fatal("record failure repeated remote mutation")
				}
			}
			if before != usageOriginalDigest(t, f) {
				t.Fatal("replaced original obligation")
			}
		})
	}
}
func TestChannelFinalPartialAndAssociationFaultRecovery(t *testing.T) {
	for _, mode := range []string{"partial", "raw_write", "association", "completion"} {
		t.Run(mode, func(t *testing.T) {
			n := 1
			if mode == "partial" {
				n = 2
			}
			f, o, a, m := channelFixture(t, n)
			m.final = true
			table, predicate := "tsw_channel_receipts", "NEW.stage='delivered'"
			if mode == "association" {
				table = "tsw_channel_associations"
			}
			if mode == "completion" {
				table = "tsw_batch_zip_delivered"
				predicate = "true"
			}
			if mode == "partial" {
				m.partial = true
			} else {
				f.exec(t, `CREATE FUNCTION public.fail_channel_final()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF `+predicate+` THEN RAISE EXCEPTION 'injected final persistence failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_channel_final BEFORE INSERT ON public.`+table+` FOR EACH ROW EXECUTE FUNCTION public.fail_channel_final()`)
			}
			e := f.h.runChannel(context.Background(), o, f.preview.Id, true)
			if mode != "partial" && e == nil {
				t.Fatal("failed final succeeded")
			}
			s := channelState(t, f)
			if s.DeliveredCount == n {
				t.Fatal("failed final terminal", s)
			}
			if mode == "partial" {
				if s.DeliveredCount != 1 || s.Phase != "partial" {
					t.Fatal(s)
				}
			}
			if mode != "partial" {
				f.exec(t, `DROP TRIGGER fail_channel_final ON public.`+table+`;DROP FUNCTION public.fail_channel_final()`)
			}
			f.exec(t, `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
			restarted := *f.h
			f.h = &restarted
			if e = f.h.runChannel(context.Background(), o, f.preview.Id, false); e != nil {
				t.Fatal(e)
			}
			s = channelState(t, f)
			if s.DeliveredCount != n || s.Phase != "delivered" || m.deliverCalls != 1 || !bytes.Equal(m.zip, zipData(t, f, a)) {
				t.Fatal(s, m.deliverCalls)
			}
			for _, count := range m.pushes {
				if count != 1 {
					t.Fatal("partial recreated original")
				}
			}
		})
	}
}
func TestChannelFirstExposureAuthorityAndScopeRejections(t *testing.T) {
	for _, mode := range []string{"stop", "revoke", "destination", "credentials", "other_customer"} {
		t.Run(mode, func(t *testing.T) {
			f, o, a, m := channelFixture(t, 1)
			switch mode {
			case "stop":
				f.exec(t, `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
			case "revoke":
				f.exec(t, `UPDATE public.tsw_expiry_rotation_previews SET status='revoked',revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1`, f.preview.Id, f.owner)
			case "destination":
				f.exec(t, `UPDATE public.tsw_delivery_destinations SET revision=revision+1 WHERE id=$1`, f.preview.DestinationId)
			case "credentials":
				f.exec(t, `UPDATE public.tsw_target_credentials SET material_status='needs_totp',version=version+1 WHERE target_account_id=$1`, f.preview.Candidates[0].AccountId)
			case "other_customer":
				if e := f.h.ReserveBatchZIP(context.Background(), a.id, BatchZIPRecipient{"public", "actual-public-customer", "actual-public-order"}); e != nil {
					t.Fatal(e)
				}
			}
			if e := f.h.runChannel(context.Background(), o, f.preview.Id, true); e == nil {
				t.Fatal("exposure authorized", mode)
			}
			if len(m.pushes) != 0 {
				t.Fatal("rejected scope exposed")
			}
		})
	}
	f, _, _, m := channelFixture(t, 1)
	for _, body := range []string{`{}`, `{"confirmed":false}`, `{"confirmed":true,"customer":"fake"}`, `{"confirmed":true,"confirmed":true}`, `{"confirmed":true}{}`} {
		if w := channelHTTP(f, f.preview.Id, "POST", "receive", body); w.Code != 422 {
			t.Fatal(body, w.Code)
		}
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del(auth.CSRFHeaderName) }, func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }, func(r *http.Request) { r.Header.Del("Cookie") }} {
		if w := channelHTTP(f, f.preview.Id, "POST", "receive", `{"confirmed":true}`, change); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if w := channelHTTP(f, uuid.New(), "POST", "receive", `{"confirmed":true}`); w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(m.pushes) != 0 {
		t.Fatal("invalid request pushed")
	}
}
func TestChannelMigration37DownUpAndGlobalProtection(t *testing.T) {
	f, o, _, _ := channelFixture(t, 1)
	if e := f.h.runChannel(context.Background(), o, f.preview.Id, true); e != nil {
		t.Fatal(e)
	}
	_, protection, e := f.h.persistedRotationEvidence(context.Background(), f.preview.Candidates[0].AccountId, uuid.New(), time.Now(), time.Now().Add(time.Minute))
	if e != nil || protection.Status != "delivery_pending" {
		t.Fatal(protection, e)
	}
	if _, clear, e := rotationCandidateLedgerLookup(context.Background(), f.pool, f.preview.Candidates[0].AccountId, uuid.New()); e != nil || clear {
		t.Fatal(clear, e)
	}
	before := usageOriginalDigest(t, f)
	membershipSchemaVersion(t, 36)
	var absent bool
	if e = f.pool.QueryRow(context.Background(), `SELECT to_regclass('public.tsw_channel_deliveries') IS NULL`).Scan(&absent); e != nil || !absent {
		t.Fatal(absent, e)
	}
	membershipSchemaVersion(t, migrations.RequiredVersion)
	membershipSchemaVersion(t, migrations.RequiredVersion)
	if before != usageOriginalDigest(t, f) {
		t.Fatal("migration changed original")
	}
}

func TestChannel101OriginalObjectsAndPartialReception(t *testing.T) {
	f, o, a, m := channelFixture(t, 101)
	m.partialReception = true
	if e := f.h.runChannel(context.Background(), o, f.preview.Id, true); e != nil {
		t.Fatal(e)
	}
	s := channelState(t, f)
	if len(s.Objects) != 101 || s.ReceivedCount != 1 || s.Phase != "partial" || s.DeliveredCount != 0 {
		t.Fatal(len(s.Objects), s.ReceivedCount, s.Phase)
	}
	restarted := *f.h
	f.h = &restarted
	m.partialReception = false
	if e := f.h.runChannel(context.Background(), o, f.preview.Id, false); e != nil {
		t.Fatal(e)
	}
	s = channelState(t, f)
	if s.ReceivedCount != 101 || s.DeliveredCount != 0 || *s.PackageId != a.id || len(m.pushes) != 101 {
		t.Fatal(s.ReceivedCount, s.DeliveredCount)
	}
	for _, count := range m.pushes {
		if count != 1 {
			t.Fatal("partition caused a second reception")
		}
	}
}
func TestChannelConcurrentStopRevokeAndSourceFences(t *testing.T) {
	for _, mode := range []string{"stop", "owner_revoke", "source_writer", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			f, o, _, m := channelFixture(t, 1)
			m.final = true
			var sourceDone chan error
			m.hook = func() {
				switch mode {
				case "stop":
					f.exec(t, `UPDATE public.tsw_rotation_removals SET stopped_at=clock_timestamp() WHERE preview_id=$1`, f.preview.Id)
				case "owner_revoke":
					m.final = false
					sourceDone = make(chan error, 1)
					go func() {
						_, err := f.pool.Exec(context.Background(), `UPDATE public.tsw_owner_sessions SET revoked_at=clock_timestamp(),revocation_reason='fixture' WHERE id=$1`, o.SessionID)
						sourceDone <- err
					}()
					select {
					case err := <-sourceDone:
						t.Fatalf("Owner revoke bypassed action fence: %v", err)
					case <-time.After(25 * time.Millisecond):
					}
				case "source_writer":
					sourceDone = make(chan error, 1)
					go func() {
						_, e := f.pool.Exec(context.Background(), `UPDATE public.tsw_target_accounts SET version=version+1 WHERE id=$1`, f.preview.Candidates[0].AccountId)
						sourceDone <- e
					}()
					select {
					case e := <-sourceDone:
						t.Fatalf("source writer bypassed exposure fence: %v", e)
					case <-time.After(25 * time.Millisecond):
					}
				case "concurrent":
					second := *f.h
					if e := second.runChannel(context.Background(), o, f.preview.Id, true); e != errChannelPending {
						t.Fatal("concurrent mutation", e)
					}
				}
			}
			e := f.h.runChannel(context.Background(), o, f.preview.Id, true)
			if sourceDone != nil {
				if sourceErr := <-sourceDone; sourceErr != nil {
					t.Fatal(sourceErr)
				}
			}
			if mode != "concurrent" && mode != "owner_revoke" && e == nil {
				t.Fatal("authority/source loss finalized")
			}
			if mode == "concurrent" && e != nil {
				t.Fatal(e)
			}
			var received int
			if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.tsw_channel_associations WHERE stage='received'`).Scan(&received); err != nil || received != 1 {
				t.Fatal("verified received fact lost", received, err)
			}
			if mode != "concurrent" && m.deliverCalls != 0 {
				t.Fatal("revoked final materials exposed")
			}
			for _, count := range m.pushes {
				if count != 1 {
					t.Fatal("concurrent repeated push")
				}
			}
		})
	}
}

func TestChannelReadOnlyPreparationFailureCanResumeOriginalPhase(t *testing.T) {
	for _, phase := range []string{"receive", "final", "zip_read"} {
		t.Run(phase, func(t *testing.T) {
			f, o, a, m := channelFixture(t, 1)
			m.final = phase != "receive"
			m.receivePreparationFailure = phase == "receive"
			m.finalPreparationFailure = phase == "final"
			replaceCiphertext := func(sealed []byte) {
				tx, e := f.pool.Begin(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				defer tx.Rollback(context.Background())
				if _, e = tx.Exec(context.Background(), `SET LOCAL session_replication_role='replica'`); e != nil {
					t.Fatal(e)
				}
				if _, e = tx.Exec(context.Background(), `UPDATE public.tsw_batch_zip_archives SET sealed_archive=$2 WHERE id=$1`, a.id, sealed); e != nil {
					t.Fatal(e)
				}
				if _, e = tx.Exec(context.Background(), `SET LOCAL session_replication_role='origin'`); e != nil {
					t.Fatal(e)
				}
				if e = tx.Commit(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "zip_read" {
				m.authorizeHook = func() {
					// A temporary archive read/decryption fault occurs after OAuth
					// reception, before the final external write boundary.
					corrupt := bytes.Clone(a.sealed)
					corrupt[0] ^= 1
					replaceCiphertext(corrupt)
				}
			}
			e := f.h.runChannel(context.Background(), o, f.preview.Id, true)
			if phase != "receive" && e == nil {
				t.Fatal("final preparation fault not surfaced")
			}
			objects, attempts, _, delivered := channelCounts(t, f)
			wantAttempts := 1
			if phase == "receive" {
				wantAttempts = 0
			}
			var finalAttempts int
			if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM public.tsw_channel_final_attempts`).Scan(&finalAttempts); err != nil || finalAttempts != 0 || attempts != wantAttempts || objects != 1 || delivered != 0 || m.deliverCalls != 0 {
				t.Fatal("preparation consumed write stage", err, finalAttempts, objects, attempts, delivered)
			}
			_, protection, err := f.h.persistedRotationEvidence(context.Background(), f.preview.Candidates[0].AccountId, uuid.New(), time.Now(), time.Now().Add(time.Minute))
			if err != nil || protection.Status == "none" {
				t.Fatal("preparation lost original hold", protection, err)
			}
			if phase == "zip_read" {
				replaceCiphertext(a.sealed)
			}
			m.authorizeHook = nil
			m.receivePreparationFailure = false
			m.finalPreparationFailure = false
			if e = f.h.runChannel(context.Background(), o, f.preview.Id, phase == "receive"); e != nil {
				t.Fatal("original stage did not resume", e)
			}
			if m.pushes[f.preview.Candidates[0].AccountId] != 1 || phase != "receive" && (m.deliverCalls != 1 || !bytes.Equal(m.zip, zipData(t, f, a))) {
				t.Fatal("resumption changed original object or ZIP")
			}
		})
	}
}

func TestChannelUnknownWriteAndEmptyInspectNeverResend(t *testing.T) {
	for _, phase := range []string{"receive", "final"} {
		t.Run(phase, func(t *testing.T) {
			f, o, _, m := channelFixture(t, 1)
			m.final = phase == "final"
			m.unresolvedReception = phase == "receive"
			m.unresolvedFinal = phase == "final"
			for range 3 {
				// Restarting the handler retains the durable original write marker.
				restarted := *f.h
				if e := restarted.runChannel(context.Background(), o, f.preview.Id, true); e != nil && e != errChannelPending {
					t.Fatal(e)
				}
			}
			if m.pushes[f.preview.Candidates[0].AccountId] != 1 || phase == "final" && m.deliverCalls != 1 {
				t.Fatal("empty query authorized uncertain resend", m.pushes, m.deliverCalls)
			}
			objects, attempts, _, delivered := channelCounts(t, f)
			if objects != 1 || attempts != 1 || delivered != 0 {
				t.Fatal("uncertain original obligation lost", objects, attempts, delivered)
			}
		})
	}
}

func TestChannelFirstEntryUsesArchivedQualificationAfterReleaseWindow(t *testing.T) {
	f, _, a, m := channelFixture(t, 1)
	// Move only the completed historical removal observation outside the former
	// 30-second action window; current Workspace usage and credentials stay live.
	tx, e := f.pool.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(context.Background(), `SET LOCAL session_replication_role='replica'`); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(context.Background(), `UPDATE public.tsw_rotation_removal_evidence SET observed_at=clock_timestamp()-interval '45 seconds' WHERE slot_id=(SELECT slot_id FROM public.tsw_batch_zip_members WHERE package_id=$1)`, a.id); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(context.Background(), `SET LOCAL session_replication_role='origin'`); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(context.Background()); e != nil {
		t.Fatal(e)
	}
	before := usageOriginalDigest(t, f)
	var actionReady, archivedReady bool
	if e = f.pool.QueryRow(context.Background(), `SELECT public.tsw_rotation_join_usage_ready(slot_id),public.tsw_archived_batch_zip_ready(package_id,slot_id) FROM public.tsw_batch_zip_members WHERE package_id=$1`, a.id).Scan(&actionReady, &archivedReady); e != nil || actionReady || !archivedReady {
		t.Fatal("late archived fixture", actionReady, archivedReady, e)
	}
	if s := channelState(t, f); s.Phase != "ready" || s.NextAction != "receive" || s.DestinationName == nil || len(s.Objects) != 0 {
		t.Fatal("GET hid original continuation", s)
	}
	if objects, attempts, receipts, delivered := channelCounts(t, f); objects != 0 || attempts != 0 || receipts != 0 || delivered != 0 || before != usageOriginalDigest(t, f) {
		t.Fatal("GET created obligations or replayed prior phases")
	}
	if w := channelHTTP(f, f.preview.Id, "POST", "receive", `{"confirmed":true}`); w.Code != 200 || m.pushes[f.preview.Candidates[0].AccountId] != 1 {
		t.Fatal("POST disagreed with archived GET", w.Code, w.Body.String())
	}
	if before != usageOriginalDigest(t, f) {
		t.Fatal("channel entry replayed completed lifecycle")
	}
}
