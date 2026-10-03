// Package thirtydayoauth defines the reusable 30D Team OAuth to Sub2API delivery format.
package thirtydayoauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	// ClientID is the OpenAI OAuth client used by delivered 30D Team accounts.
	ClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	// Concurrency is the Sub2API concurrency assigned to 30D Team OAuth accounts.
	Concurrency = 100
)

var oauthDeliveryUTCPlus8 = time.FixedZone("UTC+8", 8*60*60)

var (
	ErrAccessTokenMalformed         = errors.New("access token JWT malformed")
	ErrAccessTokenExpiryMissing     = errors.New("access token expiry missing")
	ErrAccessTokenExpired           = errors.New("access token expired")
	ErrAccessTokenWorkspaceMissing  = errors.New("access token Workspace claim missing")
	ErrAccessTokenWorkspaceMismatch = errors.New("access token Workspace claim mismatch")
)

// BuildInput contains the source values needed to build one Sub2API account.
type BuildInput struct {
	Email        string
	WorkspaceID  string
	RefreshToken string
	AccessToken  string
	IDToken      string
	ExpiresIn    int64
	ExpiresAt    int64
	IssuedAt     time.Time
	Name         string
	FirstOK      time.Time
	UsageCycle   string
	// ModelMapping 是自定义模型映射（per-space 配置）；空时回退默认 ModelMapping()。
	ModelMapping map[string]string
	// EmptyModelMapping 显式要求推送空模型映射（model_mapping: {}）。
	// 轮转交付的硬不变量是「推送账号不带模型映射」：调用方必须用它表达
	// 「就是空」，否则会落到 ModelMapping() 默认映射（2026-09-09 现场）。
	EmptyModelMapping bool
}

// IDTokenInfo contains the delivery claims extracted from an OAuth ID token.
type IDTokenInfo struct {
	Email     string
	AccountID string
	UserID    string
	OrgID     string
	PlanType  string
}

// ModelMapping returns a fresh identity mapping for the models delivered to Sub2API.
func ModelMapping() map[string]string {
	return map[string]string{
		"gpt-5.2":       "gpt-5.2",
		"gpt-5.3-codex": "gpt-5.3-codex",
		"gpt-5.4":       "gpt-5.4",
		"gpt-5.4-mini":  "gpt-5.4-mini",
		"gpt-5.5":       "gpt-5.5",
		"gpt-image-2":   "gpt-image-2",
		"gpt-5.6-sol":   "gpt-5.6-sol",
		"gpt-5.6-terra": "gpt-5.6-terra",
		"gpt-5.6-luna":  "gpt-5.6-luna",
	}
}

// BuildSub2API builds one OAuth account after validating its access-token claims.
func BuildSub2API(input BuildInput) (map[string]any, error) {
	return BuildSub2APIAt(time.Now(), input)
}

// BuildSub2APIAt builds one OAuth account without probing or exchanging the refresh token.
// The access-token JWT is always validated. Its exp claim is authoritative; an
// explicit absolute expiry or an issuance time plus TTL is accepted only when
// the otherwise-valid JWT omits exp.
func BuildSub2APIAt(now time.Time, input BuildInput) (map[string]any, error) {
	now = now.UTC()
	accessInfo, err := decodeAccessToken(input.AccessToken)
	if err != nil {
		return nil, err
	}
	workspaceID := strings.TrimSpace(input.WorkspaceID)
	if accessInfo.WorkspaceID == "" {
		return nil, ErrAccessTokenWorkspaceMissing
	}
	if accessInfo.WorkspaceID != workspaceID {
		return nil, errors.Join(ErrAccessTokenWorkspaceMismatch,
			errors.New("token="+accessInfo.WorkspaceID+" target="+workspaceID))
	}
	expiresAt, err := resolveExpiresAt(now, accessInfo.ExpiresAt, input)
	if err != nil {
		return nil, err
	}

	info := DecodeIDToken(input.IDToken)
	email := input.Email
	if info.Email != "" {
		email = info.Email
	}
	name := BuildName(input.FirstOK, input.UsageCycle, email, input.Name)
	mapping := ModelMapping()
	if input.EmptyModelMapping {
		// 显式空映射优先于默认映射：轮转交付必须推 {}。
		mapping = map[string]string{}
	}
	if len(input.ModelMapping) > 0 {
		mapping = make(map[string]string, len(input.ModelMapping))
		for k, v := range input.ModelMapping {
			mapping[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	credentials := map[string]any{
		"access_token":       input.AccessToken,
		"refresh_token":      input.RefreshToken,
		"id_token":           input.IDToken,
		"chatgpt_account_id": workspaceID,
		"chatgpt_user_id":    info.UserID,
		"client_id":          ClientID,
		"email":              email,
		"expires_at":         expiresAt,
		"model_mapping":      mapping,
		"organization_id":    info.OrgID,
		"plan_type":          info.PlanType,
		"token_type":         "Bearer",
	}
	return map[string]any{
		"name":        name,
		"platform":    "openai",
		"type":        "oauth",
		"plan_type":   info.PlanType,
		"credentials": credentials,
		"extra": map[string]any{
			"email":        email,
			"privacy_mode": "training_off",
			"openai_oauth_responses_websockets_v2_enabled": false,
			"openai_oauth_responses_websockets_v2_mode":    "off",
		},
		"concurrency":           Concurrency,
		"priority":              1,
		"rate_multiplier":       1,
		"auto_pause_on_expired": true,
	}, nil
}

type accessTokenInfo struct {
	ExpiresAt   int64
	WorkspaceID string
}

func decodeAccessToken(accessToken string) (accessTokenInfo, error) {
	var info accessTokenInfo
	parts := strings.Split(strings.TrimSpace(accessToken), ".")
	if len(parts) != 3 || parts[1] == "" {
		return info, ErrAccessTokenMalformed
	}
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return info, errors.Join(ErrAccessTokenMalformed, err)
	}
	var claims struct {
		ExpiresAt json.Number `json:"exp"`
		Auth      struct {
			WorkspaceID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return info, errors.Join(ErrAccessTokenMalformed, err)
	}
	if claims.ExpiresAt != "" {
		expiresAt, err := claims.ExpiresAt.Int64()
		if err != nil {
			return info, errors.Join(ErrAccessTokenMalformed, err)
		}
		info.ExpiresAt = expiresAt
	}
	info.WorkspaceID = strings.TrimSpace(claims.Auth.WorkspaceID)
	return info, nil
}

// AccessTokenWorkspaceID 解析 access token 的 workspace claim（chatgpt_account_id）。
// 跨空间激活污染防护用：校验复用登录态拿到的 AT 是否属于目标空间。
func AccessTokenWorkspaceID(accessToken string) (string, error) {
	info, err := decodeAccessToken(accessToken)
	if err != nil {
		return "", err
	}
	return info.WorkspaceID, nil
}

func resolveExpiresAt(now time.Time, tokenExpiresAt int64, input BuildInput) (int64, error) {
	expiresAt := tokenExpiresAt
	if expiresAt <= 0 {
		expiresAt = input.ExpiresAt
	}
	if expiresAt <= 0 && input.ExpiresIn > 0 && !input.IssuedAt.IsZero() {
		issuedAt := input.IssuedAt.UTC().Unix()
		if issuedAt > 0 && input.ExpiresIn <= int64(^uint64(0)>>1)-issuedAt {
			expiresAt = issuedAt + input.ExpiresIn
		}
	}
	if expiresAt <= 0 {
		return 0, ErrAccessTokenExpiryMissing
	}
	if expiresAt <= now.Unix() {
		return 0, ErrAccessTokenExpired
	}
	return expiresAt, nil
}

func decodeJWTPart(part string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(part)
}

// BuildName builds the stable vehicle/departure label used by OAuth deliveries:
// <M月D日HH.MM>发车-<7D|30D|未知>-<账号名>.
// The departure clock is always rendered in UTC+8 regardless of the caller,
// database driver, container, or host timezone.
func BuildName(firstOK time.Time, usageCycle, email, fallbackName string) string {
	local := strings.TrimSpace(fallbackName)
	if local == "" {
		local = strings.TrimSpace(email)
		if idx := strings.Index(local, "@"); idx > 0 {
			local = local[:idx]
		}
	}
	cycle := strings.TrimSpace(usageCycle)
	if cycle == "" {
		cycle = "未知"
	}
	name := firstOK.In(oauthDeliveryUTCPlus8).Format("1月2日15.04") + "发车-" + cycle
	if local != "" {
		name += "-" + local
	}
	return name
}

// WorkspaceNameTag extracts the filesystem-safe suffix used in OAuth export filenames.
func WorkspaceNameTag(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	local := name
	if idx := strings.Index(name, "@"); idx >= 0 {
		local = name[:idx]
	}
	var b strings.Builder
	for _, r := range local {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '+', r == '.', r == '-':
			b.WriteRune(r)
		}
	}
	cleaned := []rune(strings.Trim(compactRepeatedSeparators(b.String()), "_.-+"))
	if len(cleaned) > 9 {
		cleaned = cleaned[len(cleaned)-9:]
	}
	return strings.Trim(string(cleaned), "_.-+")
}

// DecodeIDToken decodes the unsigned JWT payload needed by the delivery format.
// Invalid or incomplete tokens return zero-value claims.
func DecodeIDToken(idToken string) IDTokenInfo {
	var info IDTokenInfo
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return info
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return info
	}
	var claims struct {
		Email string `json:"email"`
		Auth  struct {
			ChatgptAccountID string `json:"chatgpt_account_id"`
			ChatgptPlanType  string `json:"chatgpt_plan_type"`
			ChatgptUserID    string `json:"chatgpt_user_id"`
			UserID           string `json:"user_id"`
			Organizations    []struct {
				ID string `json:"id"`
			} `json:"organizations"`
		} `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return info
	}
	info.Email = claims.Email
	info.AccountID = claims.Auth.ChatgptAccountID
	info.PlanType = claims.Auth.ChatgptPlanType
	info.UserID = claims.Auth.ChatgptUserID
	if info.UserID == "" {
		info.UserID = claims.Auth.UserID
	}
	if len(claims.Auth.Organizations) > 0 {
		info.OrgID = claims.Auth.Organizations[0].ID
	}
	return info
}

func compactRepeatedSeparators(s string) string {
	isSeparator := func(r rune) bool { return r == '-' || r == '.' || r == '+' || r == '_' }
	var b strings.Builder
	var previous rune = -1
	for _, r := range s {
		if isSeparator(r) && isSeparator(previous) {
			continue
		}
		b.WriteRune(r)
		previous = r
	}
	return b.String()
}
