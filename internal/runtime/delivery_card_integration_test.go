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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
	"github.com/teamseatwatch/teamseatwatch/internal/migrations"
)

type cardIntegrationKeyRing struct{ key [32]byte }

func (r cardIntegrationKeyRing) Current() (uint16, [32]byte)            { return 7, r.key }
func (r cardIntegrationKeyRing) Lookup(version uint16) ([32]byte, bool) { return r.key, version == 7 }

func TestCardActivationIntegrationIsIdempotentAndConflictSafe(t *testing.T) {
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

	ids, sessionToken, csrfToken := seedCardActivationGraph(t, ctx, pool)
	origins, err := auth.ParseOriginPolicy("https://owner.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := &OwnerAuthHandler{pool: pool, keyRing: cardIntegrationKeyRing{}, origins: origins}
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 20))
	otherSecret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 20))

	first := activateCardIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, secret, "idempotency-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("first activation status=%d body=%s", first.Code, first.Body.String())
	}
	firstCard := decodeCardActivation(t, first)

	retry := activateCardIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, secret, "idempotency-after-lost-response")
	if retry.Code != http.StatusOK {
		t.Fatalf("same-secret retry status=%d body=%s", retry.Code, retry.Body.String())
	}
	retryCard := decodeCardActivation(t, retry)
	if retryCard.CardId != firstCard.CardId || retryCard.DisplaySuffix != firstCard.DisplaySuffix {
		t.Fatalf("same-secret retry changed card: first=%+v retry=%+v", firstCard, retryCard)
	}

	conflict := activateCardIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, otherSecret, "idempotency-other")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("different-secret status=%d body=%s", conflict.Code, conflict.Body.String())
	}

	var cardCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cards WHERE membership_id=$1`, ids.membership).Scan(&cardCount); err != nil {
		t.Fatal(err)
	}
	if cardCount != 1 {
		t.Fatalf("card count=%d want 1", cardCount)
	}
}

func TestCardActivationIntegrationConcurrentSameSecretCreatesOneCard(t *testing.T) {
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
	ids, sessionToken, csrfToken := seedCardActivationGraph(t, ctx, pool)
	origins, _ := auth.ParseOriginPolicy("https://owner.test")
	handler := &OwnerAuthHandler{pool: pool, keyRing: cardIntegrationKeyRing{}, origins: origins}
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 20))

	results := make(chan int, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			results <- activateCardIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, secret, "concurrent-key").Code
		}()
	}
	wait.Wait()
	close(results)
	statuses := make([]int, 0, 2)
	for status := range results {
		statuses = append(statuses, status)
	}
	if len(statuses) != 2 || !((statuses[0] == http.StatusCreated && statuses[1] == http.StatusOK) || (statuses[1] == http.StatusCreated && statuses[0] == http.StatusOK)) {
		t.Fatalf("concurrent statuses=%v want one 201 and one 200", statuses)
	}
	var cardCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_cards WHERE membership_id=$1`, ids.membership).Scan(&cardCount); err != nil {
		t.Fatal(err)
	}
	if cardCount != 1 {
		t.Fatalf("card count=%d want 1", cardCount)
	}
}

type cardGraphIDs struct {
	owner, workspace, membership, asset, deliveryVersion string
}

func seedCardActivationGraph(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (cardGraphIDs, string, string) {
	t.Helper()
	id := func() string { return uuid.New().String() }
	ids := cardGraphIDs{owner: id(), workspace: id(), membership: id(), asset: id(), deliveryVersion: id()}
	motherID, bindingID, batchID, targetID, operationID, operationTargetID := id(), id(), id(), id(), id(), id()
	sessionToken, sessionHash, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	csrfTokenBytes := bytes.Repeat([]byte{0x55}, 32)
	csrfToken := base64.RawURLEncoding.EncodeToString(csrfTokenBytes)
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_owners(id,username,password_hash,totp_ciphertext,totp_nonce,totp_key_version) VALUES ($1,'owner','hash',decode(repeat('11',16),'hex'),decode(repeat('22',12),'hex'),1)`, []any{ids.owner}},
		{`INSERT INTO tsw_owner_sessions(owner_id,token_hash,auth_version,idle_expires_at,absolute_expires_at) VALUES ($1,$2,1,now()+interval '1 hour',now()+interval '2 hours')`, []any{ids.owner, sessionHash[:]}},
		{`INSERT INTO tsw_mother_accounts(id,display_name) VALUES ($1,'mother')`, []any{motherID}},
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES ($1,'workspace-card','workspace')`, []any{ids.workspace}},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id) VALUES ($1,$2,$3)`, []any{bindingID, motherID, ids.workspace}},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,status,planned_at) VALUES ($1,$2,1,'serving',now()+interval '1 day')`, []any{batchID, bindingID}},
		{`INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES ($1,'target@example.com',decode(repeat('33',32),'hex'),1,'target')`, []any{targetID}},
		{`INSERT INTO tsw_target_credentials(target_account_id,password_secret) VALUES ($1,'password')`, []any{targetID}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id) VALUES ($1,$2,$3,$4,'join','card-op1',decode(repeat('44',32),'hex'),'{}','card-integration')`, []any{operationID, ids.owner, ids.workspace, batchID}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal) VALUES ($1,$2,$3,1)`, []any{operationTargetID, operationID, targetID}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at) VALUES ($1,$2,$3,$4,now())`, []any{ids.membership, batchID, targetID, operationTargetID}},
		{`UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2,status='succeeded',completed_at=now() WHERE id=$1`, []any{operationTargetID, ids.membership}},
		{`INSERT INTO tsw_oauth_assets(id,membership_id,status,current_generation,platform_subject_id) VALUES ($1,$2,'ready',1,'subject')`, []any{ids.asset, ids.membership}},
		{`INSERT INTO tsw_delivery_versions(id,oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id) VALUES ($1,$2,1,'{}',decode(repeat('00',32),'hex'),'subject',$3)`, []any{ids.deliveryVersion, ids.asset, ids.workspace}},
		{`UPDATE tsw_oauth_assets SET current_delivery_version_id=$2 WHERE id=$1`, []any{ids.asset, ids.deliveryVersion}},
	}
	for _, item := range queries {
		if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatalf("seed failed: %v", err)
		}
	}
	return ids, sessionToken, csrfToken
}

func activateCardIntegrationRequest(t *testing.T, handler *OwnerAuthHandler, membershipID, sessionToken, csrfToken, secret, idempotency string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"cardSecret": secret, "idempotencyKey": idempotency})
	request := httptest.NewRequest(http.MethodPost, "/api/owner/v1/memberships/"+membershipID+"/card", bytes.NewReader(body))
	request.SetPathValue("membershipId", membershipID)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfToken})
	request.Header.Set(auth.CSRFHeaderName, csrfToken)
	request.Header.Set("Origin", "https://owner.test")
	request.Header.Set("User-Agent", "integration")
	response := httptest.NewRecorder()
	handler.activateMembershipCard(response, request)
	return response
}

func decodeCardActivation(t *testing.T, response *httptest.ResponseRecorder) ownerapi.CardActivation {
	t.Helper()
	var result ownerapi.CardActivation
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode card activation: %v body=%s", err, response.Body.String())
	}
	return result
}
