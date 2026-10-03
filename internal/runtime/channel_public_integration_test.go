//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
)

func activateCombinedInventory(t *testing.T, f *removalFixture, a batchZIPRecord) (*PublicRedeemHandler, string) {
	t.Helper()
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 20))
	claim := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	body, err := json.Marshal(map[string]any{"cardSecret": secret, "claimExpiresAt": claim, "accessExpiresAt": claim.Add(time.Hour), "confirmed": true})
	if err != nil {
		t.Fatal(err)
	}
	oldToken := f.session
	w := inventoryHTTP(f, a.id, "POST", "", string(body))
	if w.Code != http.StatusOK {
		t.Fatal("combined registered inventory activation", w.Code, w.Body.String())
	}
	acceptInventoryRotation(t, f, a.id, w, oldToken)
	return NewPublicRedeemHandler(f.pool, f.h.keyRing, nil), secret
}

func waitCombinedActionWaiters(t *testing.T, f *removalFixture, minimum int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Both registered callers and the blocker can fill the bounded application
	// pool. Observe actual PostgreSQL waiters without consuming their connections.
	observer, err := pgx.ConnectConfig(ctx, f.pool.Config().ConnConfig)
	if err != nil {
		t.Fatal("connect read-only account fence observer", err)
	}
	defer observer.Close(context.Background())
	for {
		var count int
		err := observer.QueryRow(ctx, `SELECT count(*) FROM pg_locks lock JOIN pg_stat_activity activity ON activity.pid=lock.pid WHERE lock.locktype='advisory' AND NOT lock.granted AND activity.datname=current_database() AND activity.query LIKE '%tsw.rotation.action.%'`).Scan(&count)
		if err != nil {
			t.Fatal("observe combined account fence", err)
		}
		if count >= minimum {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting account actions=%d, want at least%d", count, minimum)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func combinedResponse(t *testing.T, result <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case response := <-result:
		return response
	case <-time.After(5 * time.Second):
		t.Fatal("combined registered request did not complete")
		return nil
	}
}

func combinedMigrationGuards(t *testing.T, f *removalFixture) {
	t.Helper()
	if migrations.RequiredVersion != 38 {
		t.Fatal("combined release requires both migrations")
	}
	read := func() (string, string, int) {
		var shared, protection string
		var guards int
		err := f.pool.QueryRow(context.Background(), `SELECT (SELECT prosrc FROM pg_proc WHERE oid='public.tsw_archived_batch_zip_ready(uuid,uuid)'::regprocedure),pg_get_viewdef('public.tsw_rotation_effective_protections'::regclass,true),(SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname IN ('tsw_channel_receiver_guard','tsw_channel_protection_guard','tsw_channel_legacy_guard','tsw_channel_zip_guard'))`).Scan(&shared, &protection, &guards)
		if err != nil {
			t.Fatal(err)
		}
		if guards != 4 || !strings.Contains(protection, "tsw_channel_objects") {
			t.Fatal("channel guards or permanent holds lost", guards, protection)
		}
		return shared, protection, guards
	}
	before := publicZIPOriginalDigest(t, f)
	shared, protection, guards := read()
	membershipSchemaVersion(t, 37)
	var publicAbsent bool
	if err := f.pool.QueryRow(context.Background(), `SELECT to_regclass('public.tsw_public_zip_inventory') IS NULL`).Scan(&publicAbsent); err != nil || !publicAbsent {
		t.Fatal("Public migration down did not preserve channel-only schema", publicAbsent, err)
	}
	for _, version := range []int64{37, 38, 38} {
		membershipSchemaVersion(t, version)
		nextShared, nextProtection, nextGuards := read()
		if nextShared != shared || nextProtection != protection || nextGuards != guards {
			t.Fatal("Public migration replaced shared channel qualification or guards", version)
		}
	}
	if before != publicZIPOriginalDigest(t, f) {
		t.Fatal("combined migration changed original qualification")
	}
}

func TestChannelPublicCombinedWholeObjectAndCompetition(t *testing.T) {
	t.Run("channel_hold_wins_and_original_fixed_path", func(t *testing.T) {
		f, _, a, channel := channelFixture(t, 1)
		combinedMigrationGuards(t, f)
		public, secret := activateCombinedInventory(t, f, a)
		ctx := context.Background()
		// Move only the mock completed release clock. The registered inventory
		// action above supplied real controlled session rotation audit facts.
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SET LOCAL session_replication_role='replica'; UPDATE public.tsw_rotation_removal_evidence SET observed_at=clock_timestamp()-interval '45 seconds'; SET LOCAL session_replication_role='origin'`)
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
		var actionReady, archivedReady bool
		err = f.pool.QueryRow(ctx, `SELECT public.tsw_rotation_join_usage_ready(slot_id),public.tsw_archived_batch_zip_ready(package_id,slot_id) FROM public.tsw_batch_zip_members WHERE package_id=$1`, a.id).Scan(&actionReady, &archivedReady)
		if err != nil || actionReady || !archivedReady {
			t.Fatal("late qualification or controlled rotation lost", actionReady, archivedReady, err)
		}
		if s := channelState(t, f); s.Phase != "ready" || s.NextAction != "receive" || len(s.Objects) != 0 {
			t.Fatal("registered channel status lost original continuation", s)
		}
		original, before := zipData(t, f, a), publicZIPOriginalDigest(t, f)
		entered, release := make(chan struct{}), make(chan struct{}, 1)
		defer close(release)
		channel.hook = func() {
			close(entered)
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
		}
		channelDone, publicDone := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
		go func() { channelDone <- channelHTTP(f, f.preview.Id, "POST", "receive", `{"confirmed":true}`) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("channel did not enter original exposure")
		}
		go func() {
			publicDone <- registeredZIPRequest(public, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		}()
		waitCombinedActionWaiters(t, f, 1)
		// Release through a buffered signal; defer still closes on test failure.
		release <- struct{}{}
		channelResponse, publicResponse := combinedResponse(t, channelDone), combinedResponse(t, publicDone)
		if channelResponse.Code != 200 || publicResponse.Code != 404 {
			t.Fatal("channel-held account became Public order", channelResponse.Code, channelResponse.Body.String(), publicResponse.Code, publicResponse.Body.String())
		}
		if s := channelState(t, f); s.Phase != "received" || s.ReceivedCount != 1 || s.DeliveredCount != 0 || len(s.Objects) != 1 {
			t.Fatal("reception fabricated final delivery", s)
		}
		if orders, receivers, delivered := publicZIPCounts(t, f); orders != 0 || receivers != 0 || delivered != 0 {
			t.Fatal("channel reception manufactured customer sale", orders, receivers, delivered)
		}
		_, err = f.pool.Exec(ctx, `INSERT INTO public.tsw_batch_zip_receivers(package_id,channel,customer_id,authorization_id)VALUES($1,'public','other-customer','other-card')`, a.id)
		if err == nil || !strings.Contains(err.Error(), "original channel obligation cannot become Public sale") {
			t.Fatal("migration38 bypassed37 receiver guard", err)
		}
		_, protection, err := f.h.persistedRotationEvidence(ctx, f.preview.Candidates[0].AccountId, uuid.New(), time.Now(), time.Now().Add(time.Minute))
		if err != nil || protection.Status != "delivery_pending" {
			t.Fatal("channel hold not effective in another Workspace", protection, err)
		}
		channel.hook = nil
		channel.final = true
		for range 2 {
			w := channelHTTP(f, f.preview.Id, "POST", "reconcile", `{"confirmed":true}`)
			if w.Code != 200 {
				t.Fatal("original fixed-path final continuation", w.Code, w.Body.String())
			}
		}
		if s := channelState(t, f); s.Phase != "delivered" || s.DeliveredCount != 1 || channel.deliverCalls != 1 || !bytes.Equal(channel.zip, original) {
			t.Fatal("original final receipt/replay changed", s, channel.deliverCalls)
		}
		if orders, receivers, delivered := publicZIPCounts(t, f); orders != 0 || receivers != 1 || delivered != 1 {
			t.Fatal("final customer association count", orders, receivers, delivered)
		}
		denied := registeredZIPRequest(public, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		if denied.Code != 404 || channel.pushes[f.preview.Candidates[0].AccountId] != 1 || zipCount(t, f) != 1 || before != publicZIPOriginalDigest(t, f) {
			t.Fatal("original channel delivery was resold or regenerated", denied.Code)
		}
	})

	t.Run("Public_claim_wins_concurrent_first_channel_entry", func(t *testing.T) {
		f, _, a, channel := channelFixture(t, 1)
		public, secret := activateCombinedInventory(t, f, a)
		original, before := zipData(t, f, a), publicZIPOriginalDigest(t, f)
		ctx := context.Background()
		blocker, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		_, err = blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||$1::text,0))`, f.preview.Candidates[0].AccountId)
		if err != nil {
			t.Fatal(err)
		}
		publicDone, channelDone := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
		go func() {
			publicDone <- registeredZIPRequest(public, "POST", "/redeem/confirm", map[string]string{"cardSecret": secret}, nil)
		}()
		waitCombinedActionWaiters(t, f, 1)
		go func() { channelDone <- channelHTTP(f, f.preview.Id, "POST", "receive", `{"confirmed":true}`) }()
		waitCombinedActionWaiters(t, f, 2)
		if err = blocker.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		publicResponse, channelResponse := combinedResponse(t, publicDone), combinedResponse(t, channelDone)
		if publicResponse.Code != 200 || len(publicResponse.Result().Cookies()) != 1 || channelResponse.Code < 400 {
			t.Fatal("both concurrent customer routes succeeded", publicResponse.Code, publicResponse.Body.String(), channelResponse.Code, channelResponse.Body.String())
		}
		if objects, attempts, receipts, delivered := channelCounts(t, f); objects != 0 || attempts != 0 || receipts != 0 || delivered != 0 || len(channel.pushes) != 0 {
			t.Fatal("losing channel created obligations or remote exposure", objects, attempts, receipts, delivered)
		}
		if orders, receivers, delivered := publicZIPCounts(t, f); orders != 1 || receivers != 1 || delivered != 0 {
			t.Fatal("Public winner did not retain its unique original order", orders, receivers, delivered)
		}
		cookie := publicResponse.Result().Cookies()[0]
		for range 2 {
			w := registeredZIPRequest(public, "POST", "/redeem/download", nil, cookie)
			if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" || !bytes.Equal(w.Body.Bytes(), original) {
				t.Fatal("Public original download changed", w.Code, w.Header())
			}
		}
		if w := channelHTTP(f, f.preview.Id, "POST", "receive", `{"confirmed":true}`); w.Code < 400 {
			t.Fatal("Public original customer was sold through channel", w.Code)
		}
		if orders, receivers, delivered := publicZIPCounts(t, f); orders != 1 || receivers != 1 || delivered != 1 || zipCount(t, f) != 1 || before != publicZIPOriginalDigest(t, f) {
			t.Fatal("original Public winner changed on replay", orders, receivers, delivered)
		}
	})
}
