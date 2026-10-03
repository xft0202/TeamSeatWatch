//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	oauthdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/oauth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/task"
)

type zipLegacyPublication struct {
	store   *task.Store
	item    task.Task
	attempt task.DeliveryAttempt
	target  task.DeliveryTarget
	value   platform.DeliveryCredentialSet
	probe   platform.DeliveryLiveness
	secret  string
}

// Seed an already-running typed mock legacy attempt in another Workspace. These
// upstream rows existed before the original preview; only fixture construction
// suppresses epoch churn. Production publication/reservation triggers run after
// restoring origin. This fixture makes no real platform request or usage claim.
func zipLegacyPublicationFixture(t *testing.T, f *removalFixture) zipLegacyPublication {
	t.Helper()
	ctx := context.Background()
	workspace, binding, batch, operation, operationTarget, membership, asset, taskID, attemptID, card := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	secret := "TSW1-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, 20))
	key, lookup, err := oauthdomain.LookupHMAC(f.h.keyRing, secret)
	if err != nil {
		t.Fatal(err)
	}
	item := task.Task{ID: taskID.String(), TaskType: "oauth_generate", WorkspaceID: workspace.String(), MembershipID: membership.String(), OAuthAssetID: asset.String(), LeaseToken: uuid.New(), AttemptNo: 1, CorrelationID: "mock-zip-legacy-publication"}
	attempt := task.DeliveryAttempt{ID: attemptID.String(), Generation: 1, AttemptNo: 1}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name)VALUES($1,$2,'mock legacy Workspace')`, []any{workspace, workspace.String()}},
		{`INSERT INTO tsw_mother_workspace_bindings(id,mother_account_id,workspace_id)VALUES($1,$2,$3)`, []any{binding, f.mother, workspace}},
		{`INSERT INTO tsw_batches(id,binding_id,sequence_no,planned_at,status)VALUES($1,$2,1,now()+interval '1 day','serving')`, []any{batch, binding}},
		{`INSERT INTO tsw_operations(id,owner_id,workspace_id,batch_id,operation_type,idempotency_key,request_hash,input_snapshot,correlation_id)VALUES($1,$2,$3,$4,'join','mock-zip-legacy',decode(repeat('63',32),'hex'),'{}','mock-zip-legacy')`, []any{operation, f.owner, workspace, batch}},
		{`INSERT INTO tsw_operation_targets(id,operation_id,membership_id,ordinal,status,completed_at)VALUES($1,$2,$3,1,'succeeded',now())`, []any{operationTarget, operation, membership}},
		{`INSERT INTO tsw_batch_memberships(id,batch_id,target_account_id,join_operation_target_id,joined_at)VALUES($1,$2,$3,$4,now())`, []any{membership, batch, f.preview.Candidates[0].AccountId, operationTarget}},
		{`INSERT INTO tsw_oauth_assets(id,membership_id,status,current_generation)VALUES($1,$2,'generating',1)`, []any{asset, membership}},
		{`INSERT INTO tsw_tasks(id,membership_id,oauth_asset_id,workspace_id,task_type,dedupe_key,input_snapshot,correlation_id,status,lease_owner,lease_token,lease_expires_at,attempt_count,max_attempts)VALUES($1,$2,$3,$4,'oauth_generate','mock-zip-legacy','{}','mock-zip-legacy','running','mock',$5,now()+interval '10 minutes',1,3)`, []any{taskID, membership, asset, workspace, item.LeaseToken}},
		{`INSERT INTO tsw_oauth_attempts(id,oauth_asset_id,task_id,generation,attempt_no,attempt_kind,strategy)VALUES($1,$2,$3,1,1,'generate','pkce')`, []any{attemptID, asset, taskID}},
		{`UPDATE tsw_oauth_assets SET current_attempt_id=$2 WHERE id=$1`, []any{asset, attemptID}},
		{`INSERT INTO tsw_cards(id,membership_id,hmac_key_version,lookup_hmac,display_suffix,redemption_deadline)VALUES($1,$2,$3,$4,'6BMOCK00',now()+interval '1 day')`, []any{card, membership, key, lookup[:]}},
	}
	for _, q := range queries {
		if _, err = tx.Exec(ctx, q.query, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role='origin'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return zipLegacyPublication{
		store: task.NewStore(f.pool, f.h.keyRing), item: item, attempt: attempt,
		target: task.DeliveryTarget{WorkspaceID: workspace.String(), PlatformWorkspace: workspace.String(), PlatformSubjectID: "mock-subject"},
		value:  platform.DeliveryCredentialSet{AccessToken: "mock-access", RefreshToken: "mock-refresh", IDToken: "mock-id", WorkspaceID: workspace.String(), PlatformSubjectID: "mock-subject"},
		probe:  platform.DeliveryLiveness{Status: "ok", HTTPStatus: 200, WorkspaceID: workspace.String(), PlatformSubjectID: "mock-subject", ObservedAt: time.Now().UTC()}, secret: secret,
	}
}

func (l zipLegacyPublication) publish(ctx context.Context) error {
	return l.store.FinishDeliveryAttempt(ctx, l.item, l.attempt, l.target, l.value, l.probe)
}

func zipLegacyCustomerReget(t *testing.T, f *removalFixture, l zipLegacyPublication) {
	t.Helper()
	h := NewPublicRedeemHandler(f.pool, f.h.keyRing, nil)
	claim := publicRedeemRequest(t, h, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": l.secret}, nil)
	if claim.Code != http.StatusOK || len(claim.Result().Cookies()) != 1 {
		t.Fatalf("original legacy customer claim: %d %s", claim.Code, claim.Body.String())
	}
	cookie := claim.Result().Cookies()[0]
	first := publicRedeemRequest(t, h, http.MethodPost, "/api/public/v1/redeem/download", nil, cookie)
	second := publicRedeemRequest(t, h, http.MethodPost, "/api/public/v1/redeem/download", nil, cookie)
	if first.Code != http.StatusOK || second.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) || !strings.Contains(first.Body.String(), "mock-access") {
		t.Fatalf("original legacy version reget: %d/%d", first.Code, second.Code)
	}
}

func TestBatchZIPLegacyPublicationAfterProtection(t *testing.T) {
	for _, zipFirst := range []bool{true, false} {
		name := "legacy_first"
		if zipFirst {
			name = "zip_first"
		}
		t.Run(name, func(t *testing.T) {
			f, o, _ := zipFixture(t)
			l := zipLegacyPublicationFixture(t, f)
			ctx := context.Background()
			a, err := f.h.prepareBatchZIP(ctx, o, f.preview.Id)
			if err != nil {
				t.Fatal(err)
			}
			r := BatchZIPRecipient{"owner_channel", "original-customer", "original-order"}
			if !zipFirst {
				if err = l.publish(ctx); err != nil {
					t.Fatal(err)
				}
				if err = f.h.ReserveBatchZIP(ctx, a.id, r); err == nil {
					t.Fatal("ZIP reservation bypassed existing legacy version")
				}
				zipLegacyCustomerReget(t, f, l)
				return
			}
			if err = f.h.ReserveBatchZIP(ctx, a.id, r); err != nil {
				t.Fatal(err)
			}
			before := usageOriginalDigest(t, f)
			if err = l.publish(ctx); err == nil {
				t.Fatal("legacy task published a second customer's version")
			}
			if _, err = f.pool.Exec(ctx, `INSERT INTO tsw_delivery_versions(oauth_asset_id,generation,payload,payload_sha256,validated_platform_subject_id,validated_workspace_id)VALUES($1,2,'{}',decode(repeat('63',32),'hex'),'mock-subject',$2)`, l.item.OAuthAssetID, l.item.WorkspaceID); err == nil {
				t.Fatal("direct SQL bypassed publication guard")
			}
			if before != usageOriginalDigest(t, f) {
				t.Fatal("failed publication changed original source obligations")
			}
			h := NewPublicRedeemHandler(f.pool, f.h.keyRing, nil)
			claim := publicRedeemRequest(t, h, http.MethodPost, "/api/public/v1/redeem/confirm", map[string]any{"cardSecret": l.secret}, nil)
			if claim.Code != http.StatusNotFound {
				t.Fatalf("legacy Public claim after protection: %d", claim.Code)
			}
			_, original, err := f.h.ReadBatchZIPForRecipient(ctx, a.id, r)
			if err != nil || !bytes.Equal(original, zipData(t, f, a)) {
				t.Fatal("original ZIP customer reget changed", err)
			}
			var active bool
			if err = f.pool.QueryRow(ctx, `SELECT state='active' FROM tsw_batch_memberships WHERE id=$1`, l.item.MembershipID).Scan(&active); err != nil || !active {
				t.Fatal("internal other-Workspace membership changed", err)
			}
		})
	}
}

func TestBatchZIPLegacyPublicationReservationRace(t *testing.T) {
	for _, zipFirst := range []bool{true, false} {
		name := "legacy_first"
		if zipFirst {
			name = "zip_first"
		}
		t.Run(name, func(t *testing.T) {
			f, o, _ := zipFixture(t)
			l := zipLegacyPublicationFixture(t, f)
			a, err := f.h.prepareBatchZIP(context.Background(), o, f.preview.Id)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||$1::text,0))`, f.preview.Candidates[0].AccountId); err != nil {
				t.Fatal(err)
			}
			r := BatchZIPRecipient{"public", "race-customer", "race-order"}
			reserved, published := make(chan error, 1), make(chan error, 1)
			wait := func(publication bool) {
				t.Helper()
				for {
					var waiting bool
					if err = f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE '%tsw.rotation.action.target_account/%' AND (query LIKE '%FROM public.tsw_oauth_assets asset%')=$1)`, publication).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						return
					}
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
			}
			reserve := func() { reserved <- f.h.ReserveBatchZIP(ctx, a.id, r) }
			publish := func() { published <- l.publish(ctx) }
			if zipFirst {
				go reserve()
				wait(false)
				go publish()
				wait(true)
			} else {
				go publish()
				wait(true)
				go reserve()
				wait(false)
			}
			// A publisher waiting on the account must not already hold asset rows.
			var asset string
			if err = tx.QueryRow(ctx, `SELECT id::text FROM tsw_oauth_assets WHERE id=$1 FOR UPDATE NOWAIT`, l.item.OAuthAssetID).Scan(&asset); err != nil {
				t.Fatal("publication acquired asset before account", err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			re, pe := <-reserved, <-published
			if zipFirst && (re != nil || pe == nil) || !zipFirst && (pe != nil || re == nil) {
				t.Fatalf("account fence winner zip=%t reserve=%v publish=%v", zipFirst, re, pe)
			}
			var versions, protections int
			if err = f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM tsw_delivery_versions WHERE oauth_asset_id=$1),(SELECT count(*) FROM tsw_batch_zip_protections WHERE target_account_id=$2)`, l.item.OAuthAssetID, f.preview.Candidates[0].AccountId).Scan(&versions, &protections); err != nil || versions+protections != 1 {
				t.Fatalf("race exposed both customers versions=%d protections=%d err=%v", versions, protections, err)
			}
			if zipFirst {
				_, data, err := f.h.ReadBatchZIPForRecipient(ctx, a.id, r)
				if err != nil || !bytes.Equal(data, zipData(t, f, a)) {
					t.Fatal("race original ZIP reget", err)
				}
			} else {
				zipLegacyCustomerReget(t, f, l)
			}
		})
	}
}
