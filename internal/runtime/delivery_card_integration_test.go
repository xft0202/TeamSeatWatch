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
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
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

func TestOwnerDeliveryReclaimAuthorizationIntegrationIsFencedAndIdempotent(t *testing.T) {
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
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 20))
	if response := activateCardIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, secret, "reclaim-card-1"); response.Code != http.StatusCreated {
		t.Fatalf("card activation status=%d body=%s", response.Code, response.Body.String())
	}
	orderTag, err := pool.Exec(ctx, `INSERT INTO tsw_orders(membership_id,card_id,oauth_asset_id,current_delivery_version_id)
		SELECT membership.id,card.id,asset.id,asset.current_delivery_version_id
		FROM tsw_batch_memberships membership
		JOIN tsw_cards card ON card.membership_id=membership.id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
		WHERE membership.id=$1`, ids.membership)
	if err != nil {
		t.Fatal(err)
	}
	if orderTag.RowsAffected() != 1 {
		t.Fatalf("created original orders=%d want 1", orderTag.RowsAffected())
	}

	notTerminal := authorizeDeliveryReclaimIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, "owner-reclaim-before-failure", true)
	if notTerminal.Code != http.StatusConflict {
		t.Fatalf("non-terminal status=%d body=%s", notTerminal.Code, notTerminal.Body.String())
	}
	missingCSRF := authorizeDeliveryReclaimIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, "owner-reclaim-no-csrf", false)
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d body=%s", missingCSRF.Code, missingCSRF.Body.String())
	}

	if _, err := pool.Exec(ctx, `UPDATE tsw_oauth_assets SET status='unavailable',unavailable_reason='full_relogin_failed' WHERE id=$1`, ids.asset); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tsw_tasks(workspace_id,membership_id,oauth_asset_id,task_type,dedupe_key,input_snapshot,status,correlation_id,max_attempts,finished_at,reclaim_tier,reclaim_result,reclaim_stage)
		VALUES ($1,$2,$3,'oauth_reclaim','previous-terminal-reclaim',jsonb_build_object('order_id',(SELECT id::text FROM tsw_orders WHERE membership_id=$2)),'failed','previous-reclaim',3,now(),'full_relogin','unrecoverable','publish')`, ids.workspace, ids.membership, ids.asset); err != nil {
		t.Fatal(err)
	}

	var firstOrderID string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM tsw_orders WHERE membership_id=$1`, ids.membership).Scan(&firstOrderID); err != nil {
		t.Fatal(err)
	}
	if firstOrderID == "" {
		t.Fatal("original order id is empty")
	}

	type authorizationResult struct {
		key      string
		response *httptest.ResponseRecorder
	}
	results := make(chan authorizationResult, 2)
	var wait sync.WaitGroup
	for _, key := range []string{"owner-reclaim-idem-1", "owner-reclaim-idem-2"} {
		wait.Add(1)
		go func(idempotencyKey string) {
			defer wait.Done()
			results <- authorizationResult{key: idempotencyKey, response: authorizeDeliveryReclaimIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, idempotencyKey, true)}
		}(key)
	}
	wait.Wait()
	close(results)
	var acceptedKey string
	var acceptedResponse *httptest.ResponseRecorder
	accepted, conflicted := 0, 0
	for result := range results {
		switch result.response.Code {
		case http.StatusAccepted:
			accepted++
			acceptedKey, acceptedResponse = result.key, result.response
		case http.StatusConflict:
			conflicted++
		default:
			t.Fatalf("concurrent authorization key=%s status=%d body=%s", result.key, result.response.Code, result.response.Body.String())
		}
	}
	if accepted != 1 || conflicted != 1 {
		t.Fatalf("concurrent outcomes accepted=%d conflicted=%d; want 1/1", accepted, conflicted)
	}
	retry := authorizeDeliveryReclaimIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, acceptedKey, true)
	if retry.Code != http.StatusAccepted || retry.Body.String() != acceptedResponse.Body.String() {
		t.Fatalf("idempotent retry status=%d body=%s; first=%s", retry.Code, retry.Body.String(), acceptedResponse.Body.String())
	}
	otherKey := "owner-reclaim-third-key"
	conflict := authorizeDeliveryReclaimIntegrationRequest(t, handler, ids.membership, sessionToken, csrfToken, otherKey, true)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("second active authorization status=%d body=%s", conflict.Code, conflict.Body.String())
	}

	var queuedCount, ownerAuditCount int
	var origin string
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_tasks WHERE oauth_asset_id=$1 AND task_type='oauth_reclaim' AND status='queued'`, ids.asset).Scan(&queuedCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT input_snapshot->>'origin' FROM tsw_tasks WHERE oauth_asset_id=$1 AND dedupe_key LIKE 'oauth-reclaim:%' AND status='queued'`, ids.asset).Scan(&origin); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tsw_audit_events WHERE event_type=$1 AND actor_type='owner' AND entity_type='oauth_asset' AND entity_id=$2`, audit.OwnerDeliveryReclaimAuthorized, ids.asset).Scan(&ownerAuditCount); err != nil {
		t.Fatal(err)
	}
	if queuedCount != 1 || ownerAuditCount != 1 || origin != "owner" {
		t.Fatalf("queued=%d ownerAudit=%d origin=%q; want 1/1/owner", queuedCount, ownerAuditCount, origin)
	}
}

func authorizeDeliveryReclaimIntegrationRequest(t *testing.T, handler *OwnerAuthHandler, membershipID, sessionToken, csrfToken, idempotencyKey string, includeCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"idempotencyKey": idempotencyKey})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/owner/v1/deliveries/"+membershipID+"/reclaim", bytes.NewReader(body))
	request.SetPathValue("membershipId", membershipID)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	if includeCSRF {
		request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfToken})
		request.Header.Set(auth.CSRFHeaderName, csrfToken)
	}
	request.Header.Set("Origin", "https://owner.test")
	request.Header.Set("User-Agent", "integration")
	response := httptest.NewRecorder()
	handler.authorizeDeliveryReclaim(response, request)
	return response
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

type cardRevocationFixture struct {
	pool         *pgxpool.Pool
	ids          cardGraphIDs
	sessionToken string
	csrfToken    string
	secret       string
	owner        *OwnerAuthHandler
	public       *PublicRedeemHandler
}

func newCardRevocationFixture(t *testing.T) cardRevocationFixture {
	t.Helper()
	dsn := os.Getenv("TSW_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TSW_TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
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
	t.Cleanup(pool.Close)
	ids, sessionToken, csrfToken := seedCardActivationGraph(t, ctx, pool)
	origins, err := auth.ParseOriginPolicy("https://owner.test")
	if err != nil {
		t.Fatal(err)
	}
	owner := &OwnerAuthHandler{pool: pool, keyRing: cardIntegrationKeyRing{}, origins: origins}
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 20))
	if response := activateCardIntegrationRequest(t, owner, ids.membership, sessionToken, csrfToken, secret, "revoke-card-1"); response.Code != http.StatusCreated {
		t.Fatalf("card activation status=%d body=%s", response.Code, response.Body.String())
	}
	return cardRevocationFixture{
		pool: pool, ids: ids, sessionToken: sessionToken, csrfToken: csrfToken, secret: secret,
		owner: owner, public: NewPublicRedeemHandler(pool, cardIntegrationKeyRing{}, nil),
	}
}

func seedOtherWorkspaceDelivery(t *testing.T, fixture cardRevocationFixture) (cardGraphIDs, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	id := func() string { return uuid.NewString() }
	workspaceID, bindingID, batchID := id(), id(), id()
	operationID, operationTargetID := id(), id()
	membershipID, assetID, versionID := id(), id(), id()
	var ownerID, motherID, targetID string
	if err := fixture.pool.QueryRow(ctx, `SELECT operation.owner_id::text,binding.mother_account_id::text,membership.target_account_id::text
		FROM tsw_batch_memberships membership
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_mother_workspace_bindings binding ON binding.id=batch.binding_id
		JOIN tsw_operations operation ON operation.batch_id=batch.id
		WHERE membership.id=$1`, fixture.ids.membership).Scan(&ownerID, &motherID, &targetID); err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES ($1,$2,'other workspace')`, []any{workspaceID, "other-" + workspaceID}},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id) VALUES ($1,$2,$3)`, []any{bindingID, motherID, workspaceID}},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,status,planned_at) VALUES ($1,$2,1,'serving',now()+interval '1 day')`, []any{batchID, bindingID}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id) VALUES ($1,$2,$3,$4,'join',$5,decode(repeat('77',32),'hex'),'{}','other-workspace-card')`, []any{operationID, ownerID, workspaceID, batchID, "other-workspace-" + operationID}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,target_account_id,ordinal) VALUES ($1,$2,$3,1)`, []any{operationTargetID, operationID, targetID}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at) VALUES ($1,$2,$3,$4,now())`, []any{membershipID, batchID, targetID, operationTargetID}},
		{`UPDATE tsw_operation_targets SET target_account_id=NULL,membership_id=$2,status='succeeded',completed_at=now() WHERE id=$1`, []any{operationTargetID, membershipID}},
		{`INSERT INTO tsw_oauth_assets(id,membership_id,status,current_generation,platform_subject_id) VALUES ($1,$2,'ready',1,'other-subject')`, []any{assetID, membershipID}},
		{`INSERT INTO tsw_delivery_versions(id,oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id) VALUES ($1,$2,1,'{"other":true}',decode(repeat('00',32),'hex'),'other-subject',$3)`, []any{versionID, assetID, workspaceID}},
		{`UPDATE tsw_oauth_assets SET current_delivery_version_id=$2 WHERE id=$1`, []any{assetID, versionID}},
	}
	for _, item := range queries {
		if _, err := fixture.pool.Exec(ctx, item.query, item.args...); err != nil {
			t.Fatalf("seed other Workspace delivery: %v", err)
		}
	}
	ids := cardGraphIDs{owner: ownerID, workspace: workspaceID, membership: membershipID, asset: assetID, deliveryVersion: versionID}
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, 20))
	if response := activateCardIntegrationRequest(t, fixture.owner, membershipID, fixture.sessionToken, fixture.csrfToken, secret, "other-workspace-card-1"); response.Code != http.StatusCreated {
		t.Fatalf("other Workspace card activation status=%d body=%s", response.Code, response.Body.String())
	}
	claimed := publicRedeemRequest(t, fixture.public, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": secret}, nil)
	if claimed.Code != http.StatusOK {
		t.Fatalf("other Workspace claim status=%d body=%s", claimed.Code, claimed.Body.String())
	}
	cookies := claimed.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("other Workspace customer cookies=%d want 1", len(cookies))
	}
	return ids, cookies[0]
}

func revokeCardIntegrationRequest(t *testing.T, handler *OwnerAuthHandler, membershipID, sessionToken, csrfToken string, includeCSRF, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]bool{"confirm": confirm})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/owner/v1/deliveries/"+membershipID+"/card/revoke", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	if includeCSRF {
		request.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: csrfToken})
		request.Header.Set(auth.CSRFHeaderName, csrfToken)
	}
	request.Header.Set("Origin", "https://owner.test")
	request.Header.Set("User-Agent", "integration")
	response := httptest.NewRecorder()
	handler.RevokeDeliveryCard(response, request, ownerapi.MembershipId(uuid.MustParse(membershipID)), ownerapi.RevokeDeliveryCardParams{})
	return response
}

func assertNoSuccessfulPublicAccessAfterRevoke(t *testing.T, fixture cardRevocationFixture) {
	t.Helper()
	var lateSuccesses int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*)
		FROM tsw_audit_events access
		JOIN tsw_cards card ON card.id=access.retention_scope_id
		WHERE access.retention_scope_type='card' AND access.retention_scope_id=(SELECT id FROM tsw_cards WHERE membership_id=$1)
		  AND access.actor_type='anonymous' AND access.event_type LIKE 'public.%'
		  AND access.outcome='succeeded' AND access.occurred_at > card.revoked_at`, fixture.ids.membership).Scan(&lateSuccesses); err != nil {
		t.Fatal(err)
	}
	if lateSuccesses != 0 {
		t.Fatalf("successful public access after revoke commit=%d", lateSuccesses)
	}
}

func listDeliveryRecordsIntegrationRequest(t *testing.T, fixture cardRevocationFixture, params ownerapi.ListDeliveryRecordsParams) ownerapi.DeliveryRecordList {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/owner/v1/deliveries", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: fixture.sessionToken})
	response := httptest.NewRecorder()
	fixture.owner.ListDeliveryRecords(response, request, params)
	if response.Code != http.StatusOK {
		t.Fatalf("delivery list status=%d body=%s", response.Code, response.Body.String())
	}
	var result ownerapi.DeliveryRecordList
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode delivery list: %v body=%s", err, response.Body.String())
	}
	return result
}

func TestCardRevocationIntegrationSerializesFirstClaimAndPreservesService(t *testing.T) {
	fixture := newCardRevocationFixture(t)
	if response := revokeCardIntegrationRequest(t, fixture.owner, fixture.ids.membership, fixture.sessionToken, fixture.csrfToken, false, true); response.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d body=%s", response.Code, response.Body.String())
	}
	if response := revokeCardIntegrationRequest(t, fixture.owner, fixture.ids.membership, fixture.sessionToken, fixture.csrfToken, true, false); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing confirmation status=%d body=%s", response.Code, response.Body.String())
	}

	start := make(chan struct{})
	claimResult := make(chan *httptest.ResponseRecorder, 1)
	revokeResult := make(chan *httptest.ResponseRecorder, 1)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		claimResult <- publicRedeemRequest(t, fixture.public, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": fixture.secret}, nil)
	}()
	go func() {
		defer wait.Done()
		<-start
		revokeResult <- revokeCardIntegrationRequest(t, fixture.owner, fixture.ids.membership, fixture.sessionToken, fixture.csrfToken, true, true)
	}()
	close(start)
	wait.Wait()
	claim := <-claimResult
	revoked := <-revokeResult
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	if claim.Code != http.StatusOK && claim.Code != http.StatusNotFound {
		t.Fatalf("racing first claim status=%d body=%s", claim.Code, claim.Body.String())
	}

	var cardStatus, membershipState, batchStatus, assetStatus string
	var orderCount, activeTokenCount, revocationAuditCount int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT card.status,membership.state,batch.status,asset.status
		FROM tsw_cards card JOIN tsw_batch_memberships membership ON membership.id=card.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id WHERE membership.id=$1`, fixture.ids.membership).Scan(&cardStatus, &membershipState, &batchStatus, &assetStatus); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_orders WHERE membership_id=$1`, fixture.ids.membership).Scan(&orderCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_public_tokens WHERE card_id=(SELECT id FROM tsw_cards WHERE membership_id=$1) AND revoked_at IS NULL`, fixture.ids.membership).Scan(&activeTokenCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_audit_events WHERE event_type=$1 AND entity_id=(SELECT id FROM tsw_cards WHERE membership_id=$2)`, audit.OwnerCardRevoked, fixture.ids.membership).Scan(&revocationAuditCount); err != nil {
		t.Fatal(err)
	}
	wantOrders := 0
	if claim.Code == http.StatusOK {
		wantOrders = 1
	}
	if cardStatus != "revoked" || membershipState != "active" || batchStatus != "serving" || assetStatus != "ready" || orderCount != wantOrders || activeTokenCount != 0 || revocationAuditCount != 1 {
		t.Fatalf("after race: card=%s membership=%s batch=%s asset=%s orders=%d active_tokens=%d revocation_audits=%d", cardStatus, membershipState, batchStatus, assetStatus, orderCount, activeTokenCount, revocationAuditCount)
	}
	if response := publicRedeemRequest(t, fixture.public, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": fixture.secret}, nil); response.Code != http.StatusNotFound {
		t.Fatalf("post-commit claim/restore status=%d body=%s", response.Code, response.Body.String())
	}
	assertNoSuccessfulPublicAccessAfterRevoke(t, fixture)
}

func TestCardRevocationIntegrationDeniesLegacyTokensAndSerializesDownloadAndReissue(t *testing.T) {
	fixture := newCardRevocationFixture(t)
	otherIDs, otherCookie := seedOtherWorkspaceDelivery(t, fixture)
	claimed := publicRedeemRequest(t, fixture.public, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": fixture.secret}, nil)
	if claimed.Code != http.StatusOK {
		t.Fatalf("initial claim status=%d body=%s", claimed.Code, claimed.Body.String())
	}
	customerCookies := claimed.Result().Cookies()
	if len(customerCookies) != 1 {
		t.Fatalf("customer cookies=%d want 1", len(customerCookies))
	}
	legacyCookie := customerCookies[0]
	serviceFilter := ownerapi.DeliveryServiceStatusQuery("active")
	cardFilter := ownerapi.DeliveryCardStatusQuery("active")
	orderFilter := ownerapi.DeliveryOrderStatusQuery("claimed")
	activeDeliveries := listDeliveryRecordsIntegrationRequest(t, fixture, ownerapi.ListDeliveryRecordsParams{
		ServiceStatus: &serviceFilter, CardStatus: &cardFilter, OrderStatus: &orderFilter,
	})
	if activeDeliveries.Total != 2 || len(activeDeliveries.Items) != 2 {
		t.Fatalf("active claimed delivery filter total=%d items=%d want 2", activeDeliveries.Total, len(activeDeliveries.Items))
	}
	reclaim := publicRedeemRequest(t, fixture.public, http.MethodPost, "/api/public/v1/redeem/reclaim", map[string]any{"cardSecret": fixture.secret}, nil)
	if reclaim.Code != http.StatusAccepted {
		t.Fatalf("initial reclaim status=%d body=%s", reclaim.Code, reclaim.Body.String())
	}
	reclaimCookies := reclaim.Result().Cookies()
	if len(reclaimCookies) != 1 {
		t.Fatalf("reclaim cookies=%d want 1", len(reclaimCookies))
	}
	var orderID, assetStatusBefore string
	if err := fixture.pool.QueryRow(context.Background(), `SELECT id::text FROM tsw_orders WHERE membership_id=$1`, fixture.ids.membership).Scan(&orderID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT status FROM tsw_oauth_assets WHERE id=$1`, fixture.ids.asset).Scan(&assetStatusBefore); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	restoreResult := make(chan *httptest.ResponseRecorder, 1)
	downloadResult := make(chan *httptest.ResponseRecorder, 1)
	revokeResult := make(chan *httptest.ResponseRecorder, 1)
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		<-start
		restoreResult <- publicRedeemRequest(t, fixture.public, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": fixture.secret}, nil)
	}()
	go func() {
		defer wait.Done()
		<-start
		downloadResult <- publicRedeemRequest(t, fixture.public, http.MethodPost, "/api/public/v1/redeem/download", nil, legacyCookie)
	}()
	go func() {
		defer wait.Done()
		<-start
		revokeResult <- revokeCardIntegrationRequest(t, fixture.owner, fixture.ids.membership, fixture.sessionToken, fixture.csrfToken, true, true)
	}()
	close(start)
	wait.Wait()
	restored, downloaded, revoked := <-restoreResult, <-downloadResult, <-revokeResult
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	if restored.Code != http.StatusOK && restored.Code != http.StatusNotFound {
		t.Fatalf("racing restore/token issue status=%d body=%s", restored.Code, restored.Body.String())
	}
	if downloaded.Code != http.StatusOK && downloaded.Code != http.StatusNotFound {
		t.Fatalf("racing download status=%d body=%s", downloaded.Code, downloaded.Body.String())
	}

	for _, attempt := range []struct {
		name   string
		method string
		path   string
		body   any
		cookie *http.Cookie
	}{
		{name: "legacy state", method: http.MethodGet, path: "/api/public/v1/redeem/state", cookie: legacyCookie},
		{name: "legacy records", method: http.MethodGet, path: "/api/public/v1/redeem/records", cookie: legacyCookie},
		{name: "legacy download", method: http.MethodPost, path: "/api/public/v1/redeem/download", cookie: legacyCookie},
		{name: "reclaim status", method: http.MethodGet, path: "/api/public/v1/redeem/reclaim/status", cookie: reclaimCookies[0]},
		{name: "order restore and token reissue", method: http.MethodPost, path: "/api/public/v1/redeem/confirm", body: map[string]any{"cardSecret": fixture.secret}},
		{name: "reclaim creation", method: http.MethodPost, path: "/api/public/v1/redeem/reclaim", body: map[string]any{"cardSecret": fixture.secret}},
		{name: "credential status", method: http.MethodPost, path: "/api/public/v1/redeem/credential-status", body: map[string]any{"cardSecret": fixture.secret}},
	} {
		response := publicRedeemRequest(t, fixture.public, attempt.method, attempt.path, attempt.body, attempt.cookie)
		if response.Code != http.StatusNotFound {
			t.Errorf("%s after revoke status=%d body=%s", attempt.name, response.Code, response.Body.String())
		}
	}
	var deniedDownloadAuditCount, deniedStateAuditCount, deniedRecordsAuditCount int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT
		count(*) FILTER (WHERE event_type=$1 AND outcome='denied'),
		count(*) FILTER (WHERE event_type=$2 AND outcome='denied'),
		count(*) FILTER (WHERE event_type=$3 AND outcome='denied')
		FROM tsw_audit_events WHERE retention_scope_type='card' AND retention_scope_id=(SELECT id FROM tsw_cards WHERE membership_id=$4)`,
		audit.PublicDownloadDenied, audit.PublicStateRead, audit.PublicRecordsRead, fixture.ids.membership).Scan(&deniedDownloadAuditCount, &deniedStateAuditCount, &deniedRecordsAuditCount); err != nil {
		t.Fatal(err)
	}
	if deniedDownloadAuditCount == 0 || deniedStateAuditCount == 0 || deniedRecordsAuditCount == 0 {
		t.Fatalf("revoked public denial audits download=%d state=%d records=%d", deniedDownloadAuditCount, deniedStateAuditCount, deniedRecordsAuditCount)
	}
	var cardStatus, membershipState, batchStatus, assetStatus, retainedOrderID string
	var tokenCount, activeTokenCount, reclaimStatusTokenCount, taskCount, auditCount, auditedTokenCount int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT card.status,membership.state,batch.status,asset.status,ord.id::text
		FROM tsw_cards card JOIN tsw_batch_memberships membership ON membership.id=card.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id
		JOIN tsw_orders ord ON ord.membership_id=membership.id WHERE membership.id=$1`, fixture.ids.membership).Scan(&cardStatus, &membershipState, &batchStatus, &assetStatus, &retainedOrderID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*),count(*) FILTER (WHERE revoked_at IS NULL),count(*) FILTER (WHERE token_kind='reclaim_status') FROM tsw_public_tokens WHERE card_id=(SELECT id FROM tsw_cards WHERE membership_id=$1)`, fixture.ids.membership).Scan(&tokenCount, &activeTokenCount, &reclaimStatusTokenCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*),COALESCE(max((details->>'revoked_token_count')::int),0) FROM tsw_audit_events WHERE event_type=$1 AND entity_id=(SELECT id FROM tsw_cards WHERE membership_id=$2)`, audit.OwnerCardRevoked, fixture.ids.membership).Scan(&auditCount, &auditedTokenCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_tasks WHERE oauth_asset_id=$1 AND task_type='oauth_reclaim'`, fixture.ids.asset).Scan(&taskCount); err != nil {
		t.Fatal(err)
	}
	if retainedOrderID != orderID || cardStatus != "revoked" || membershipState != "active" || batchStatus != "serving" || assetStatus != assetStatusBefore || tokenCount < 2 || activeTokenCount != 0 || reclaimStatusTokenCount != 1 || auditCount != 1 || auditedTokenCount != tokenCount || taskCount != 1 {
		t.Fatalf("after revoke: order=%s want=%s card=%s membership=%s batch=%s asset=%s tokens=%d active_tokens=%d audits=%d audited_tokens=%d reclaim_tasks=%d", retainedOrderID, orderID, cardStatus, membershipState, batchStatus, assetStatus, tokenCount, activeTokenCount, auditCount, auditedTokenCount, taskCount)
	}
	revokedFilter := ownerapi.DeliveryCardStatusQuery("revoked")
	claimedFilter := ownerapi.DeliveryOrderStatusQuery("claimed")
	serviceFilterAfterRevoke := ownerapi.DeliveryServiceStatusQuery("active")
	revokedDeliveries := listDeliveryRecordsIntegrationRequest(t, fixture, ownerapi.ListDeliveryRecordsParams{
		ServiceStatus: &serviceFilterAfterRevoke, CardStatus: &revokedFilter, OrderStatus: &claimedFilter,
	})
	if revokedDeliveries.Total != 1 || len(revokedDeliveries.Items) != 1 || revokedDeliveries.Items[0].MembershipId.String() != fixture.ids.membership {
		t.Fatalf("revoked delivery filter total=%d items=%+v", revokedDeliveries.Total, revokedDeliveries.Items)
	}
	var otherCardStatus, otherMembershipState, otherBatchStatus, otherAssetStatus, otherTargetID string
	var otherActiveTokens int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT card.status,membership.state,batch.status,asset.status,membership.target_account_id::text,
		(SELECT count(*) FROM tsw_public_tokens token WHERE token.card_id=card.id AND token.revoked_at IS NULL)
		FROM tsw_cards card JOIN tsw_batch_memberships membership ON membership.id=card.membership_id
		JOIN tsw_batches batch ON batch.id=membership.batch_id
		JOIN tsw_oauth_assets asset ON asset.membership_id=membership.id WHERE membership.id=$1`, otherIDs.membership).Scan(&otherCardStatus, &otherMembershipState, &otherBatchStatus, &otherAssetStatus, &otherTargetID, &otherActiveTokens); err != nil {
		t.Fatal(err)
	}
	var primaryTargetID string
	if err := fixture.pool.QueryRow(context.Background(), `SELECT target_account_id::text FROM tsw_batch_memberships WHERE id=$1`, fixture.ids.membership).Scan(&primaryTargetID); err != nil {
		t.Fatal(err)
	}
	if otherCardStatus != "active" || otherMembershipState != "active" || otherBatchStatus != "serving" || otherAssetStatus != "ready" || otherTargetID != primaryTargetID || otherActiveTokens != 1 {
		t.Fatalf("other Workspace delivery changed: card=%s membership=%s batch=%s asset=%s target=%s primary_target=%s active_tokens=%d", otherCardStatus, otherMembershipState, otherBatchStatus, otherAssetStatus, otherTargetID, primaryTargetID, otherActiveTokens)
	}
	otherDownload := publicRedeemRequest(t, fixture.public, http.MethodPost, "/api/public/v1/redeem/download", nil, otherCookie)
	if otherDownload.Code != http.StatusOK {
		t.Fatalf("other Workspace download status=%d body=%s", otherDownload.Code, otherDownload.Body.String())
	}
	idempotentResponse := revokeCardIntegrationRequest(t, fixture.owner, fixture.ids.membership, fixture.sessionToken, fixture.csrfToken, true, true)
	if idempotentResponse.Code != http.StatusOK {
		t.Fatalf("idempotent revoke status=%d body=%s", idempotentResponse.Code, idempotentResponse.Body.String())
	}
	var idempotentResult ownerapi.RevokeDeliveryCardResponse
	if err := json.Unmarshal(idempotentResponse.Body.Bytes(), &idempotentResult); err != nil {
		t.Fatalf("decode idempotent revoke response: %v body=%s", err, idempotentResponse.Body.String())
	}
	if idempotentResult.RevokedTokenCount != auditedTokenCount {
		t.Fatalf("idempotent revoke token count=%d want %d", idempotentResult.RevokedTokenCount, auditedTokenCount)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM tsw_audit_events WHERE event_type=$1 AND entity_id=(SELECT id FROM tsw_cards WHERE membership_id=$2)`, audit.OwnerCardRevoked, fixture.ids.membership).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("idempotent revoke audit count=%d want 1", auditCount)
	}
	assertNoSuccessfulPublicAccessAfterRevoke(t, fixture)
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE tsw_oauth_assets SET status='unavailable',unavailable_reason='full_relogin_failed' WHERE id=$1`, fixture.ids.asset); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE tsw_tasks SET status='failed',reclaim_result='unrecoverable',finished_at=now() WHERE oauth_asset_id=$1 AND task_type='oauth_reclaim'`, fixture.ids.asset); err != nil {
		t.Fatal(err)
	}
	ownerReclaim := authorizeDeliveryReclaimIntegrationRequest(t, fixture.owner, fixture.ids.membership, fixture.sessionToken, fixture.csrfToken, "owner-reclaim-after-revoke", true)
	if ownerReclaim.Code != http.StatusConflict {
		t.Fatalf("owner reclaim after revoke status=%d body=%s", ownerReclaim.Code, ownerReclaim.Body.String())
	}
}
