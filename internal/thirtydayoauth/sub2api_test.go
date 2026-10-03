package thirtydayoauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestOAuthSub2APIBuildPreservesDeliveryShape(t *testing.T) {
	claims := map[string]any{
		"email": "claim@example.com",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "account-from-claim",
			"chatgpt_plan_type":  "team",
			"chatgpt_user_id":    "user-from-claim",
			"organizations":      []map[string]any{{"id": "org-from-claim"}},
		},
	}
	now := time.Date(2026, 7, 30, 1, 2, 3, 0, time.UTC)
	claims["exp"] = now.Add(2 * time.Hour).Unix()
	idToken := testJWT(t, claims)
	accessToken := testJWT(t, map[string]any{
		"exp":                         now.Add(time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "account-from-claim"},
	})
	firstOK := time.Date(2026, 7, 22, 20, 28, 0, 0, time.FixedZone("UTC+8", 8*60*60))

	entry, err := BuildSub2APIAt(now, BuildInput{
		Email: "source@example.com", WorkspaceID: "account-from-claim", RefreshToken: "refresh", AccessToken: accessToken,
		IDToken: idToken, ExpiresIn: 3600, Name: "vehicle", FirstOK: firstOK, UsageCycle: "30D",
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry["name"] != "7月22日20.28发车-30D-vehicle" || entry["platform"] != "openai" || entry["type"] != "oauth" {
		t.Fatalf("identity shape changed: %#v", entry)
	}
	if entry["plan_type"] != "team" || entry["concurrency"] != 100 || entry["priority"] != 1 || entry["rate_multiplier"] != 1 || entry["auto_pause_on_expired"] != true {
		t.Fatalf("delivery controls changed: %#v", entry)
	}
	credentials, ok := entry["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("credentials=%T", entry["credentials"])
	}
	wantCredentials := map[string]any{
		"access_token": accessToken, "refresh_token": "refresh", "id_token": idToken,
		"chatgpt_account_id": "account-from-claim", "chatgpt_user_id": "user-from-claim",
		"client_id": ClientID, "email": "claim@example.com", "expires_at": now.Add(time.Hour).Unix(),
		"model_mapping": ModelMapping(), "organization_id": "org-from-claim", "plan_type": "team", "token_type": "Bearer",
	}
	if !reflect.DeepEqual(credentials, wantCredentials) {
		t.Fatalf("credentials changed\n got=%#v\nwant=%#v", credentials, wantCredentials)
	}
	wantExtra := map[string]any{
		"email": "claim@example.com", "privacy_mode": "training_off",
		"openai_oauth_responses_websockets_v2_enabled": false,
		"openai_oauth_responses_websockets_v2_mode":    "off",
	}
	if !reflect.DeepEqual(entry["extra"], wantExtra) {
		t.Fatalf("extra changed: %#v", entry["extra"])
	}
}

func TestBuildNameAlwaysRendersUTCPlus8(t *testing.T) {
	instant := time.Date(2026, 8, 7, 7, 18, 0, 0, time.UTC)
	want := "8月7日15.18发车-30D-samanthataylor23114+klj5"
	if got := BuildName(instant, "30D", "samanthataylor23114+klj5@example.com", ""); got != want {
		t.Fatalf("UTC 时间应转为 UTC+8: want=%q got=%q", want, got)
	}
	otherZone := time.FixedZone("UTC-5", -5*60*60)
	if got := BuildName(instant.In(otherZone), "30D", "samanthataylor23114+klj5@example.com", ""); got != want {
		t.Fatalf("同一时刻不应受输入时区影响: want=%q got=%q", want, got)
	}
}

func TestOAuthSub2APIUsesJWTExpiryWhenPersistedExpiresInIsZero(t *testing.T) {
	firstOK := time.Date(2026, 3, 5, 9, 7, 0, 0, time.UTC)
	now := time.Date(2026, 3, 6, 9, 7, 0, 0, time.UTC)
	expiresAt := now.Add(10 * 24 * time.Hour).Unix()
	accessToken := testJWT(t, map[string]any{
		"exp":                         expiresAt,
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace"},
	})
	for _, tc := range []struct {
		cycle string
		want  string
	}{
		{cycle: "7D", want: "3月5日17.07发车-7D-member"},
		{cycle: "30D", want: "3月5日17.07发车-30D-member"},
		{cycle: "", want: "3月5日17.07发车-未知-member"},
	} {
		entry, err := BuildSub2APIAt(now, BuildInput{
			Email: "member@example.com", WorkspaceID: "workspace", RefreshToken: "refresh",
			AccessToken: accessToken, ExpiresIn: 0, FirstOK: firstOK, UsageCycle: tc.cycle,
		})
		if err != nil {
			t.Fatalf("cycle %q: %v", tc.cycle, err)
		}
		if entry["name"] != tc.want {
			t.Errorf("cycle %q: name=%q want=%q", tc.cycle, entry["name"], tc.want)
		}
		credentials := entry["credentials"].(map[string]any)
		if credentials["chatgpt_account_id"] != "workspace" || credentials["expires_at"] != expiresAt {
			t.Fatalf("fallback shape changed: %#v", credentials)
		}
	}
}

func TestOAuthSub2APIStrictAccessTokenValidation(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	jwt := func(claims map[string]any) string { return testJWT(t, claims) }
	tests := []struct {
		name        string
		accessToken string
		workspaceID string
		wantErr     error
	}{
		{name: "malformed", accessToken: "not-a-jwt", workspaceID: "workspace", wantErr: ErrAccessTokenMalformed},
		{name: "missing expiry", accessToken: jwt(map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace"}}), workspaceID: "workspace", wantErr: ErrAccessTokenExpiryMissing},
		{name: "expired", accessToken: jwt(map[string]any{"exp": now.Unix(), "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace"}}), workspaceID: "workspace", wantErr: ErrAccessTokenExpired},
		{name: "missing workspace", accessToken: jwt(map[string]any{"exp": now.Add(time.Hour).Unix()}), workspaceID: "workspace", wantErr: ErrAccessTokenWorkspaceMissing},
		{name: "workspace mismatch", accessToken: jwt(map[string]any{"exp": now.Add(time.Hour).Unix(), "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "other"}}), workspaceID: "workspace", wantErr: ErrAccessTokenWorkspaceMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildSub2APIAt(now, BuildInput{WorkspaceID: tc.workspaceID, AccessToken: tc.accessToken})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v want=%v", err, tc.wantErr)
			}
		})
	}
}

func TestOAuthSub2APIExplicitExpiryFallbackRequiresValidJWTAndFutureExpiry(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	accessToken := testJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace"},
	})
	entry, err := BuildSub2APIAt(now, BuildInput{
		WorkspaceID: "workspace", AccessToken: accessToken, ExpiresAt: now.Add(30 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := entry["credentials"].(map[string]any)
	if credentials["expires_at"] != now.Add(30*time.Minute).Unix() {
		t.Fatalf("expires_at=%v", credentials["expires_at"])
	}
}

func TestOAuthSub2APIIssuedAtFallbackAndJWTExpiryPriority(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	withoutExpiry := testJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace"},
	})
	entry, err := BuildSub2APIAt(now, BuildInput{
		WorkspaceID: "workspace", AccessToken: withoutExpiry,
		IssuedAt: now.Add(-time.Minute), ExpiresIn: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := entry["credentials"].(map[string]any)
	if got, want := credentials["expires_at"], now.Add(59*time.Minute).Unix(); got != want {
		t.Fatalf("issued-at fallback expires_at=%v want=%v", got, want)
	}

	tokenExpiry := now.Add(2 * time.Hour).Unix()
	withExpiry := testJWT(t, map[string]any{
		"exp":                         tokenExpiry,
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "workspace"},
	})
	entry, err = BuildSub2APIAt(now, BuildInput{
		WorkspaceID: "workspace", AccessToken: withExpiry, ExpiresAt: now.Add(8 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials = entry["credentials"].(map[string]any)
	if got := credentials["expires_at"]; got != tokenExpiry {
		t.Fatalf("JWT expiry lost priority: expires_at=%v want=%d", got, tokenExpiry)
	}
}

func TestOAuthSub2APIDecodeIDTokenUserFallback(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"a@example.com","https://api.openai.com/auth":{"user_id":"legacy-user","organizations":[{"id":"org"}]}}`))
	got := DecodeIDToken("header." + payload + ".signature")
	want := IDTokenInfo{Email: "a@example.com", UserID: "legacy-user", OrgID: "org"}
	if got != want {
		t.Fatalf("claims=%#v want=%#v", got, want)
	}
	if got := DecodeIDToken("invalid"); got != (IDTokenInfo{}) {
		t.Fatalf("invalid token claims=%#v", got)
	}
}

func TestOAuthSub2APIModelMappingReturnsIndependentMaps(t *testing.T) {
	first := ModelMapping()
	first["gpt-5.2"] = "changed"
	second := ModelMapping()
	if second["gpt-5.2"] != "gpt-5.2" || len(second) != 9 {
		t.Fatalf("model mapping is mutable across calls: %#v", second)
	}
}

func TestOAuthSub2APIWorkspaceNameTag(t *testing.T) {
	if got := WorkspaceNameTag("怪兽TEAM-月-robinburkhart6613+q805@gmail.com"); got != "6613+q805" {
		t.Fatalf("tag=%q", got)
	}
}

// TestOAuthSub2APIBuildEmptyModelMapping 钉住轮转交付的硬不变量：
// 显式 EmptyModelMapping 时必须推 model_mapping: {}，绝不回填默认映射。
func TestOAuthSub2APIBuildEmptyModelMapping(t *testing.T) {
	now := time.Date(2026, 9, 9, 5, 0, 0, 0, time.UTC)
	claims := map[string]any{
		"email": "empty-map@example.com",
		"exp":   now.Add(2 * time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acc-empty-map",
			"chatgpt_plan_type":  "self_serve_business_prolite",
		},
	}
	idToken := testJWT(t, claims)
	accessToken := testJWT(t, map[string]any{
		"exp":                         now.Add(time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acc-empty-map"},
	})
	entry, err := BuildSub2APIAt(now, BuildInput{
		Email: "empty-map@example.com", WorkspaceID: "acc-empty-map", RefreshToken: "rt",
		AccessToken: accessToken, IDToken: idToken, ExpiresIn: 3600, Name: "kxj-rotation-test",
		EmptyModelMapping: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials, ok := entry["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("credentials=%T", entry["credentials"])
	}
	mapping, ok := credentials["model_mapping"].(map[string]string)
	if !ok {
		t.Fatalf("model_mapping 类型=%T", credentials["model_mapping"])
	}
	if len(mapping) != 0 {
		t.Fatalf("轮转推送必须空模型映射，实际 %#v", mapping)
	}
}
