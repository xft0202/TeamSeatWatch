//go:build integration

package runtime

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/internalapi"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
	"github.com/teamseatwatch/teamseatwatch/internal/publicaccess"
)

func TestPublicRedeemIntegrationLifecycleAndDynamicAuthorization(t *testing.T) {
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	ids, _, _ := seedCardActivationGraph(t, ctx, pool)
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 20))
	keyVersion, lookup, err := oauthdomain.LookupHMAC(cardIntegrationKeyRing{}, secret)
	if err != nil {
		t.Fatal(err)
	}
	cardID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_cards(id,membership_id,hmac_key_version,lookup_hmac,display_suffix,redemption_deadline) VALUES($1,$2,$3,$4,'61AAAAAA',now()+interval '1 day')`, cardID, ids.membership, keyVersion, lookup[:]); err != nil {
		t.Fatal(err)
	}
	handler := NewPublicRedeemHandler(pool, cardIntegrationKeyRing{}, nil)

	var orderCount int
	check := publicRedeemRequest(t, handler, http.MethodPost, "/api/public/v1/redeem/credential-status", map[string]any{"cardSecret": secret}, nil)
	if check.Code != http.StatusOK {
		t.Fatalf("credential check status=%d body=%s", check.Code, check.Body.String())
	}
	var checkPayload internalapi.CredentialStatus
	decodePublicJSON(t, check, &checkPayload)
	if !checkPayload.CheckQueued {
		t.Fatalf("credential check=%+v want queued", checkPayload)
	}
	var reclaimCheckCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_tasks WHERE task_type='oauth_reclaim'`).Scan(&reclaimCheckCount); err != nil {
		t.Fatal(err)
	}
	if reclaimCheckCount != 0 {
		t.Fatalf("credential status created reclaim tasks=%d", reclaimCheckCount)
	}

	if _, err := pool.Exec(ctx, `UPDATE tsw_batches SET planned_at=now()-interval '1 second' WHERE id=(SELECT batch_id FROM tsw_batch_memberships WHERE id=$1)`, ids.membership); err != nil {
		t.Fatal(err)
	}
	expired := publicRedeemRequest(t, handler, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": secret}, nil)
	if expired.Code != http.StatusNotFound {
		t.Fatalf("expired claim status=%d body=%s", expired.Code, expired.Body.String())
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_batches SET planned_at=now()+interval '1 day' WHERE id=(SELECT batch_id FROM tsw_batch_memberships WHERE id=$1)`, ids.membership); err != nil {
		t.Fatal(err)
	}

	responses := make(chan *httptest.ResponseRecorder, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			responses <- publicRedeemRequest(t, handler, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": secret}, nil)
		}()
	}
	wait.Wait()
	close(responses)
	var cookies []*http.Cookie
	for response := range responses {
		if response.Code != http.StatusOK {
			t.Fatalf("concurrent claim status=%d body=%s", response.Code, response.Body.String())
		}
		cookies = append(cookies, response.Result().Cookies()...)
	}
	if len(cookies) != 2 {
		t.Fatalf("concurrent claim cookies=%d want 2", len(cookies))
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_orders WHERE card_id=$1`, cardID).Scan(&orderCount); err != nil {
		t.Fatal(err)
	}
	if orderCount != 1 {
		t.Fatalf("order count=%d want 1", orderCount)
	}
	accessCookie := cookies[0]
	if accessCookie.Name != "tsw_redeem_access" || len(accessCookie.Value) < 43 || !accessCookie.HttpOnly || !accessCookie.Secure || accessCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe access cookie=%+v", accessCookie)
	}

	var lastUsed *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_used_at FROM tsw_public_tokens WHERE card_id=$1 ORDER BY issued_at LIMIT 1`, cardID).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	state := publicRedeemRequest(t, handler, http.MethodGet, "/api/public/v1/redeem/state", nil, accessCookie)
	if state.Code != http.StatusOK {
		t.Fatalf("state status=%d body=%s", state.Code, state.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT last_used_at FROM tsw_public_tokens WHERE card_id=$1 ORDER BY issued_at LIMIT 1`, cardID).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed != nil {
		t.Fatalf("state read changed token last_used_at=%v", lastUsed)
	}
	records := publicRedeemRequest(t, handler, http.MethodGet, "/api/public/v1/redeem/records", nil, accessCookie)
	if records.Code != http.StatusOK {
		t.Fatalf("records status=%d body=%s", records.Code, records.Body.String())
	}

	for range 2 {
		download := publicRedeemRequest(t, handler, http.MethodPost, "/api/public/v1/redeem/download", nil, accessCookie)
		if download.Code != http.StatusOK || download.Header().Get("Content-Type") != "application/json" || !bytes.Equal(download.Body.Bytes(), []byte("{}")) {
			t.Fatalf("download status=%d body=%s", download.Code, download.Body.String())
		}
	}
	reclaim := publicRedeemRequest(t, handler, http.MethodPost, "/api/public/v1/redeem/reclaim", map[string]any{"cardSecret": secret}, nil)
	if reclaim.Code != http.StatusAccepted {
		t.Fatalf("reclaim without old cookie status=%d body=%s", reclaim.Code, reclaim.Body.String())
	}
	var reclaimPayload internalapi.ReclaimStatus
	decodePublicJSON(t, reclaim, &reclaimPayload)
	if reclaimPayload.Result == nil || (*reclaimPayload.Result != internalapi.ReclaimStatusResultQueued && *reclaimPayload.Result != internalapi.ReclaimStatusResultChecking) {
		t.Fatalf("reclaim payload=%+v", reclaimPayload)
	}
	var reclaimCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_tasks WHERE task_type='oauth_reclaim' AND oauth_asset_id=$1`, ids.asset).Scan(&reclaimCount); err != nil {
		t.Fatal(err)
	}
	if reclaimCount != 1 {
		t.Fatalf("reclaim task count=%d want 1", reclaimCount)
	}
	reclaimCookies := reclaim.Result().Cookies()
	if len(reclaimCookies) != 1 {
		t.Fatalf("reclaim cookies=%d want 1", len(reclaimCookies))
	}
	reclaimStatus := publicRedeemRequest(t, handler, http.MethodGet, "/api/public/v1/redeem/reclaim/status", nil, reclaimCookies[0])
	if reclaimStatus.Code != http.StatusOK {
		t.Fatalf("reclaim status=%d body=%s", reclaimStatus.Code, reclaimStatus.Body.String())
	}
	if download := publicRedeemRequest(t, handler, http.MethodPost, "/api/public/v1/redeem/download", nil, reclaimCookies[0]); download.Code != http.StatusNotFound {
		t.Fatalf("reclaim-status token authorized download: status=%d body=%s", download.Code, download.Body.String())
	}
	var statusTokenKind string
	if err := pool.QueryRow(ctx, `SELECT token_kind FROM tsw_public_tokens WHERE token_hash=$1`, tokenHashForIntegration(t, reclaimCookies[0].Value)).Scan(&statusTokenKind); err != nil {
		t.Fatal(err)
	}
	if statusTokenKind != "reclaim_status" {
		t.Fatalf("reclaim token kind=%q want reclaim_status", statusTokenKind)
	}

	newVersion := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_delivery_versions(id,oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id) VALUES($1,$2,2,'{"new":true}',decode(repeat('01',32),'hex'),'subject',$3)`, newVersion, ids.asset, ids.workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tsw_oauth_assets SET current_generation=2,current_delivery_version_id=$2 WHERE id=$1`, ids.asset, newVersion); err != nil {
		t.Fatal(err)
	}
	stale := publicRedeemRequest(t, handler, http.MethodGet, "/api/public/v1/redeem/state", nil, accessCookie)
	if stale.Code != http.StatusNotFound {
		t.Fatalf("stale version state status=%d body=%s", stale.Code, stale.Body.String())
	}
}

func publicRedeemRequest(t *testing.T, handler *PublicRedeemHandler, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var input *bytes.Reader
	if body == nil {
		input = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		input = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, input)
	request.RemoteAddr = "198.51.100.9:3000"
	request.Header.Set("User-Agent", "ticket09-integration")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	switch path {
	case "/api/public/v1/redeem/confirm":
		handler.ConfirmPublicRedeem(response, request)
	case "/api/public/v1/redeem/state":
		handler.GetPublicRedeemState(response, request)
	case "/api/public/v1/redeem/records":
		handler.ListPublicRedeemRecords(response, request)
	case "/api/public/v1/redeem/credential-status":
		handler.CheckPublicRedeemCredentialStatus(response, request)
	case "/api/public/v1/redeem/reclaim":
		handler.RequestPublicRedeemReclaim(response, request)
	case "/api/public/v1/redeem/reclaim/status":
		handler.GetPublicRedeemReclaimStatus(response, request)
	case "/api/public/v1/redeem/download":
		handler.DownloadPublicRedeemDelivery(response, request)
	default:
		t.Fatalf("unknown public path %s", path)
	}
	return response
}

func tokenHashForIntegration(t *testing.T, value string) []byte {
	t.Helper()
	hash, err := publicaccess.HashToken(value)
	if err != nil {
		t.Fatal(err)
	}
	return hash[:]
}

func decodePublicJSON(t *testing.T, response *httptest.ResponseRecorder, value any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), value); err != nil {
		t.Fatalf("decode public response: %v body=%s", err, response.Body.String())
	}
}
