//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/generated/ownerapi"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type removalHTTPFixture struct {
	mu           sync.Mutex
	workspace    string
	members      []platform.Member
	role         string
	status       int
	remove       bool
	fail         error
	partialAfter bool
	calls, reads int
	onDelete     func()
	onSnapshot   func(int)
}

func (f *removalHTTPFixture) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "chatgpt.com" || r.URL.Scheme != "https" {
		return nil, fmt.Errorf("unexpected host")
	}
	f.mu.Lock()
	role, workspace := f.role, f.workspace
	if strings.HasPrefix(r.URL.Path, "/backend-api/accounts/check/") && r.Method == "GET" {
		f.mu.Unlock()
		body := fmt.Sprintf(`{"accounts":{"selected":{"account":{"account_id":%q,"name":"fixture","plan_type":"team","structure":"workspace","workspace_role":%q}}}}`, workspace, role)
		return removalHTTPResponse(200, body), nil
	}
	if r.URL.Path == "/backend-api/accounts/"+workspace+"/users" && r.Method == "GET" {
		f.reads++
		members := append([]platform.Member(nil), f.members...)
		partial := f.partialAfter && f.calls > 0
		read, hook := f.reads, f.onSnapshot
		f.mu.Unlock()
		if hook != nil {
			hook(read)
		}
		items := []map[string]string{}
		for _, m := range members {
			items = append(items, map[string]string{"id": m.PlatformMemberID, "account_user_id": m.PlatformAccountUserID, "email": m.Identifier, "role": m.Role, "seat_type": m.SeatType})
		}
		total := len(items)
		if partial {
			total++
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if offset < 0 || offset > len(items) {
			return nil, fmt.Errorf("invalid mock paging offset")
		}
		page := items[offset:min(offset+100, len(items))]
		raw, _ := json.Marshal(map[string]any{"items": page, "offset": offset, "limit": 100, "total": total})
		return removalHTTPResponse(200, string(raw)), nil
	}
	if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/backend-api/accounts/"+workspace+"/users/") {
		f.calls++
		member := strings.TrimPrefix(r.URL.Path, "/backend-api/accounts/"+workspace+"/users/")
		if r.Header.Get("Chatgpt-Account-Id") != workspace || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || r.Body != nil {
			f.mu.Unlock()
			return nil, fmt.Errorf("wrong scoped mutation")
		}
		if f.remove {
			kept := []platform.Member{}
			for _, m := range f.members {
				if m.PlatformMemberID != member {
					kept = append(kept, m)
				}
			}
			f.members = kept
		}
		status, err, hook := f.status, f.fail, f.onDelete
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
		if err != nil {
			return nil, err
		}
		return removalHTTPResponse(status, `{}`), nil
	}
	f.mu.Unlock()
	return nil, fmt.Errorf("unexpected method/path: %s %s", r.Method, r.URL.Path)
}
func removalHTTPResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

type removalFixture struct {
	pool                 *pgxpool.Pool
	h                    *OwnerAuthHandler
	owner, session, csrf string
	mother, space        uuid.UUID
	preview              ownerapi.ExpiryRotationPreview
	http                 *removalHTTPFixture
	key                  uuid.UUID
}

func newRemovalFixture(t *testing.T, n int, sessionWindow ...time.Duration) *removalFixture {
	return newRemovalFixtureWithUsage(t, n, false, sessionWindow...)
}
func newRemovalFixtureWithUsage(t *testing.T, n int, noFirstUse bool, sessionWindow ...time.Duration) *removalFixture {
	t.Helper()
	pool, h, owner, session, csrf := childReviewFixture(t)
	ctx := context.Background()
	f := &removalFixture{pool: pool, h: h, owner: owner, session: session, csrf: csrf, mother: uuid.New(), space: uuid.New(), key: uuid.New()}
	run, generation, exchange, batch, dest, draft := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	seed(`INSERT INTO tsw_mother_accounts(id,display_name) VALUES($1,'removal mother')`, f.mother)
	seed(`INSERT INTO tsw_mother_account_credentials(mother_account_id,login_identifier,identifier_hmac,identifier_key_version,password_secret,totp_secret) VALUES($1,'mother@remove.test',decode(repeat('31',32),'hex'),1,'pw','totp')`, f.mother)
	seed(`INSERT INTO tsw_workspaces(id,platform_workspace_id,display_name) VALUES($1,$2,'removal fixture')`, f.space, f.space.String())
	personal := platform.PersonalSession{AccessToken: "fixture-personal", DeviceID: "fixture-device", Cookies: []platform.SessionCookie{{Name: "__Secure-next-auth.session-token", Value: "fixture-cookie"}}, ExpiresAt: time.Now().Add(time.Hour)}
	v, nonce, sealed, err := sealPersonalSession(h.keyRing, f.mother, 1, personal)
	if err != nil {
		t.Fatal(err)
	}
	seed(`INSERT INTO tsw_mother_personal_sessions(mother_account_id,secret_revision,generation,key_version,nonce,sealed_session,expires_at) VALUES($1,1,$2,$3,$4,$5,$6)`, f.mother, generation, int16(v), nonce, sealed, personal.ExpiresAt)
	seed(`INSERT INTO tsw_mother_discoveries(mother_account_id,run_id,secret_revision,session_generation,status) VALUES($1,$2,1,$3,'discovered')`, f.mother, run, generation)
	seed(`INSERT INTO tsw_mother_workspace_visibility(mother_account_id,workspace_id,run_id,access_status,workspace_role) VALUES($1,$2,$3,'readable','owner')`, f.mother, f.space, run)
	access := fixtureWorkspaceAccess(f.space.String())
	b := workspaceAccessBinding{motherID: f.mother, workspaceID: f.space, run: run, generation: generation, revision: 1, attempt: 1, exchangeID: exchange}
	v, nonce, sealed, err = sealWorkspaceAccess(h.keyRing, b, access)
	if err != nil {
		t.Fatal(err)
	}
	seed(`INSERT INTO tsw_selected_workspace_tokens(mother_account_id,workspace_id,discovery_run_id,session_generation,secret_revision,exchange_id,status,key_version,nonce,sealed_access,expires_at) VALUES($1,$2,$3,$4,1,$5,'ready',$6,$7,$8,$9)`, f.mother, f.space, run, generation, exchange, int16(v), nonce, sealed, access.ExpiresAt)
	var verification int64
	active := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	err = pool.QueryRow(ctx, `INSERT INTO tsw_workspace_verifications(workspace_id,mother_account_id,discovery_run_id,session_generation,secret_revision,token_attempt,token_exchange_id,source,outcome,permission,completeness,observed_at,expires_at,active_until,seat_limit,member_count,pending_invite_count,seat_type_counts) VALUES($1,$2,$3,$4,1,1,$5,'injected_platform_reader','verified','read','complete',now()-interval '1 second',now()+interval '4 minutes',$6,2,$7,$7,jsonb_build_object('default',0,'usage_based',0,'automation',0,'prolite',$7::int)) RETURNING id`, f.space, f.mother, run, generation, exchange, active, n).Scan(&verification)
	if err != nil {
		t.Fatal(err)
	}
	seed(`INSERT INTO tsw_standby_child_batches(id,name) VALUES($1,'removal standby')`, batch)
	children := []ownerapi.OperationDraftChild{}
	assignments := []ownerapi.ExpiryRotationAssignment{}
	members := []platform.Member{}
	all := []platform.Member{}
	pw, _ := targetdomain.SealMaterial("password", h.keyRing)
	totp, _ := targetdomain.SealMaterial("JBSWY3DPEHPK3PXP", h.keyRing)
	for i := 1; i <= n; i++ {
		original, child := uuid.New(), uuid.New()
		identifier := fmt.Sprintf("old%d@remove.test", i)
		candidate := fmt.Sprintf("candidate%d@remove.test", i)
		member := fmt.Sprintf("member-%d", i)
		seed(`INSERT INTO tsw_target_accounts(id,identifier,identifier_hmac,identifier_key_version,display_label) VALUES($1,$2,decode($3,'hex'),1,'fixture'),($4,$5,decode($6,'hex'),1,'fixture')`, original, identifier, fmt.Sprintf("%064x", 2*i), child, candidate, fmt.Sprintf("%064x", 2*i+1))
		seed(`INSERT INTO tsw_target_credentials(target_account_id,password_secret,totp_secret,material_status,materials_sealed) VALUES($1,$2,$3,'complete',true)`, child, pw, totp)
		seed(`INSERT INTO tsw_standby_child_memberships(target_account_id,batch_id) VALUES($1,$2)`, child, batch)
		seed(`INSERT INTO tsw_workspace_verification_entries(verification_id,kind,identifier,identifier_hmac,identifier_key_version,status,platform_member_id,role,seat_type) VALUES($1,'member',$2,decode($3,'hex'),1,'active',$4,'member','prolite'),($1,'pending_invite',$5,decode($6,'hex'),1,'pending',NULL,NULL,'prolite')`, verification, identifier, fmt.Sprintf("%064x", 2*i), member, candidate, fmt.Sprintf("%064x", 2*i+1))
		seed(`INSERT INTO tsw_rotation_usage_ledger(target_account_id,workspace_id,usage_state,ever_used,evidence_source,evidence_id,observed_at,expires_at) VALUES($1,$2,'used',true,'workspace_usage_probe',repeat('a',64),now()-interval '1 second',now()+interval '4 minutes'),($3,$2,'never_used',false,'workspace_usage_probe',repeat('b',64),now()-interval '1 second',now()+interval '4 minutes')`, original, f.space, child)
		if noFirstUse {
			seed(`DELETE FROM tsw_rotation_usage_ledger WHERE target_account_id=$1`, child)
		}
		children = append(children, ownerapi.OperationDraftChild{AccountId: child, MembershipVersion: 1})
		assignments = append(assignments, ownerapi.ExpiryRotationAssignment{PlatformMemberId: member, AccountId: child})
		m := platform.Member{Kind: "member", PlatformMemberID: member, Identifier: identifier, Status: "listed", Role: "member", SeatType: "prolite"}
		members = append(members, m)
		all = append(all, m, platform.Member{Kind: "pending_invite", Identifier: candidate, Status: "pending", SeatType: "prolite"})
	}
	seed(`INSERT INTO tsw_delivery_destinations(id,name,endpoint,target_group,secret_key_version,secret_nonce,secret_ciphertext,test_connection,test_target,test_revision,tested_at) VALUES($1,'delivery','https://hub.fixture.test/api/v1','42',1,decode(repeat('11',12),'hex'),decode(repeat('22',32),'hex'),'connected','connected',1,now())`, dest)
	raw, _ := json.Marshal(children)
	var batchVersion int64
	if err = pool.QueryRow(ctx, `SELECT version FROM tsw_standby_child_batches WHERE id=$1`, batch).Scan(&batchVersion); err != nil {
		t.Fatal(err)
	}
	seed(`INSERT INTO tsw_operation_selection_drafts(id,owner_id,version,step,mother_account_id,mother_revision,workspace_id,visibility_run_id,session_generation,verification_id,batch_id,batch_version,children,destination_id,destination_revision) VALUES($1,$2,1,'complete',$3,1,$4,$5,$6,$7,$8,$9,$10,$11,1)`, draft, owner, f.mother, f.space, run, generation, verification, batch, batchVersion, raw, dest)
	paid, count := 2, n
	h.selectedWorkspaceReader = fixedSelectedWorkspaceReader{facts: platform.SelectedWorkspaceFacts{Permission: "read", Result: platform.Result{Outcome: platform.OutcomeOperational, Completeness: platform.Complete, ActiveUntil: &active, SeatLimit: &paid, MemberCount: &count, PendingInviteCount: &count, SeatTypeCounts: map[string]int{"default": 0, "usage_based": 0, "automation": 0, "prolite": n}, Members: all}}}
	h.rotationCapability = officialRotationCapability{handler: h}
	if len(sessionWindow) > 0 {
		seed(`UPDATE tsw_owner_sessions SET idle_expires_at=$2,absolute_expires_at=$2 WHERE owner_id=$1`, owner, time.Now().Add(sessionWindow[0]))
	}
	path := "/api/owner/v1/expiry-rotation/previews"
	f.preview = rotationResult(t, rotationRequest(h, session, csrf, "POST", path, nil), 200)
	if f.preview.Status != "ready" {
		t.Fatalf("preview not ready: %+v", f.preview)
	}
	f.preview = rotationResult(t, rotationRequest(h, session, csrf, "POST", path+"/"+f.preview.Id.String()+"/confirm", map[string]any{"confirmed": true, "digest": f.preview.Digest, "idempotencyKey": uuid.New(), "assignments": assignments}), 200)
	f.http = &removalHTTPFixture{workspace: f.space.String(), members: members, role: "owner", status: 204, remove: true}
	client := &http.Client{Timeout: time.Second, Transport: f.http}
	factory := func(context.Context) (*http.Client, func(), error) { return client, func() {}, nil }
	h.workspaceMemberRemover = platform.OfficialWorkspaceMemberRemover{Client: factory}
	h.discovery = platform.AccountsCheckDiscovery{Client: factory}
	return f
}
func (f *removalFixture) start(t *testing.T) ownerapi.RotationRemoval {
	t.Helper()
	return removalResult(t, removalRequest(f.h, f.session, f.csrf, "POST", f.preview.Id, uuid.Nil, "start", map[string]any{"confirmed": true, "authorizationDigest": *f.preview.AuthorizationDigest, "idempotencyKey": f.key}), 200)
}
func (f *removalFixture) action(t *testing.T, slot uuid.UUID, action string) ownerapi.RotationRemoval {
	t.Helper()
	return removalResult(t, removalRequest(f.h, f.session, f.csrf, "POST", f.preview.Id, slot, action, map[string]any{"confirmed": true}), 200)
}
func removalResult(t *testing.T, w interface{ Result() *http.Response }, status int) ownerapi.RotationRemoval {
	t.Helper()
	r := w.Result()
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	if r.StatusCode != status {
		t.Fatalf("status=%d want=%d %s", r.StatusCode, status, raw)
	}
	var out ownerapi.RotationRemoval
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
