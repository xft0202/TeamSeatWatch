package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/teamseatwatch/teamseatwatch/internal/auth"
	oauthdomain "github.com/teamseatwatch/teamseatwatch/internal/oauth"
)

// DeliveryCredentialRequest is the input required by TeamSeatWatch's
// workspace-bound customer delivery flow.
type DeliveryCredentialRequest struct {
	Identifier string
	Password   string
	TOTPSecret string
	Recovery   string
	Workspace  string
}

type DeliveryCredentialSet struct {
	RefreshToken      string `json:"refresh_token"`
	AccessToken       string `json:"access_token"`
	IDToken           string `json:"id_token"`
	PlatformSubjectID string `json:"platform_subject_id"`
	WorkspaceID       string `json:"workspace_id"`
	ExpiresIn         int64  `json:"expires_in"`
	Scope             string `json:"scope"`
}

type DeliveryLiveness struct {
	Status            oauthdomain.ProbeStatus
	HTTPStatus        int
	ErrorCode         string
	Origin            string
	ObservedAt        time.Time
	PlatformSubjectID string
	WorkspaceID       string
}

type DeliveryAdapter interface {
	CreateDeliveryCredentials(context.Context, DeliveryCredentialRequest) (DeliveryCredentialSet, error)
	CheckDeliveryLiveness(context.Context, string, string) (DeliveryLiveness, error)
}

var _ DeliveryAdapter = (*HTTPReader)(nil)

const (
	officialChatBase = "https://chatgpt.com"
	officialAuthBase = "https://auth.openai.com"
	maxAuthHops      = 12
)

const browserAuthUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

var authChallengePattern = regexp.MustCompile(`(?:(?:"challenge_id"|"challengeId"|"mfaChallengeId"|"mfa_challenge_id")\s*:\s*"([A-Za-z0-9_-]{8,})"|/mfa-challenge/([A-Za-z0-9_-]{8,}))`)

// CreateDeliveryCredentials performs the real account login and workspace-bound PKCE grant.
// The client is lease-owned, so every stage shares its transport and cookie jar.
func (r *HTTPReader) CreateDeliveryCredentials(ctx context.Context, input DeliveryCredentialRequest) (DeliveryCredentialSet, error) {
	if strings.TrimSpace(input.Identifier) == "" || strings.TrimSpace(input.Password) == "" || strings.TrimSpace(input.Workspace) == "" {
		return DeliveryCredentialSet{}, errors.New("delivery credential input is incomplete")
	}
	if strings.TrimSpace(input.TOTPSecret) == "" {
		return DeliveryCredentialSet{}, errors.New("delivery credential input requires TOTP")
	}
	jar, err := ensureCookieJar(r.client)
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	deviceID, err := newBrowserID()
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	loggingID, err := newBrowserID()
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	loginURL, err := r.beginAccountLogin(ctx, input.Identifier, deviceID, loggingID)
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	pageURL, pageBody, err := r.followBrowserRedirect(ctx, jar, loginURL, officialChatBase+"/login")
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	if !strings.Contains(strings.ToLower(pageURL+string(pageBody)), "log-in/password") {
		pageURL, pageBody, err = r.followBrowserRedirect(ctx, jar, officialAuthBase+"/log-in/password", pageURL)
		if err != nil {
			return DeliveryCredentialSet{}, err
		}
	}
	if !strings.Contains(strings.ToLower(pageURL+string(pageBody)), "log-in/password") {
		return DeliveryCredentialSet{}, errors.New("delivery login did not reach password page")
	}
	continueURL, err := r.submitPassword(ctx, jar, input.Password)
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	pageURL, pageBody, err = r.followBrowserRedirect(ctx, jar, continueURL, officialAuthBase+"/log-in/password")
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	if requiresTOTP(pageURL, pageBody) {
		code, codeErr := auth.TOTPCode(input.TOTPSecret, time.Now())
		if codeErr != nil {
			return DeliveryCredentialSet{}, fmt.Errorf("generate TOTP: %w", codeErr)
		}
		continueURL, err = r.submitTOTP(ctx, jar, pageURL, pageBody, code, input.Workspace)
		if err != nil {
			return DeliveryCredentialSet{}, err
		}
		if continueURL != "" {
			pageURL, pageBody, err = r.followBrowserRedirect(ctx, jar, continueURL, pageURL)
			if err != nil {
				return DeliveryCredentialSet{}, err
			}
		}
	}
	if err := r.selectWorkspace(ctx, jar, input.Workspace, pageURL); err != nil {
		return DeliveryCredentialSet{}, err
	}
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	state, err := randomState()
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	code, err := captureWithJar(ctx, r.client, jar, BuildWorkspaceAuthorizeURL(challenge, state, input.Workspace), state)
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	result, err := ExchangePKCECode(ctx, &http.Client{Transport: r.client.Transport, Jar: jar, Timeout: r.client.Timeout}, code, verifier)
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	result, err = validateDeliveryIdentity(result, input.Workspace)
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	return result, nil
}

func (r *HTTPReader) beginAccountLogin(ctx context.Context, identifier, deviceID, loggingID string) (string, error) {
	if _, err := r.authJSON(ctx, http.MethodGet, "/api/auth/providers", nil, officialChatBase+"/login"); err != nil {
		return "", fmt.Errorf("providers: %w", err)
	}
	csrfBody, err := r.authJSON(ctx, http.MethodGet, "/api/auth/csrf", nil, officialChatBase+"/login")
	if err != nil {
		return "", fmt.Errorf("csrf: %w", err)
	}
	var csrf struct {
		Token string `json:"csrfToken"`
	}
	if json.Unmarshal(csrfBody, &csrf) != nil || strings.TrimSpace(csrf.Token) == "" {
		return "", errors.New("csrf response is incomplete")
	}
	query := url.Values{
		"prompt": {"login"}, "login_hint": {identifier}, "screen_hint": {"login_or_signup"},
		"ext-oai-did": {deviceID}, "auth_session_logging_id": {loggingID},
		"ext-passkey-client-capabilities": {"1111"},
	}
	form := url.Values{"callbackUrl": {officialChatBase + "/login"}, "csrfToken": {csrf.Token}, "json": {"true"}}
	body, err := r.authJSON(ctx, http.MethodPost, "/api/auth/signin/openai?"+query.Encode(), []byte(form.Encode()), officialChatBase+"/login")
	if err != nil {
		return "", fmt.Errorf("signin: %w", err)
	}
	var response struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(body, &response) != nil || strings.TrimSpace(response.URL) == "" {
		return "", errors.New("signin response is incomplete")
	}
	return response.URL, nil
}

func (r *HTTPReader) submitPassword(ctx context.Context, jar http.CookieJar, password string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"password": password})
	body, err := r.authJSONWithJar(ctx, jar, http.MethodPost, officialAuthBase+"/api/accounts/password/verify", payload, officialAuthBase+"/log-in/password")
	if err != nil {
		return "", fmt.Errorf("password verification: %w", err)
	}
	return continueURLFromJSON(body), nil
}

func (r *HTTPReader) submitTOTP(ctx context.Context, jar http.CookieJar, currentURL string, page []byte, code, workspaceID string) (string, error) {
	challenge := extractMFAChallenge(currentURL, page)
	attempts := make([]struct {
		endpoint string
		payload  map[string]string
	}, 0, 6)
	if challenge != "" {
		attempts = append(attempts,
			struct {
				endpoint string
				payload  map[string]string
			}{officialAuthBase + "/api/accounts/mfa/verify", map[string]string{"code": code, "type": "totp", "id": challenge}},
			struct {
				endpoint string
				payload  map[string]string
			}{officialAuthBase + "/api/accounts/mfa/verify", map[string]string{"otp": code, "type": "totp", "id": challenge}},
			struct {
				endpoint string
				payload  map[string]string
			}{officialAuthBase + "/api/accounts/mfa/challenge/" + challenge + "/verify", map[string]string{"code": code, "type": "totp"}},
		)
	}
	attempts = append(attempts,
		struct {
			endpoint string
			payload  map[string]string
		}{officialAuthBase + "/api/accounts/mfa/verify", map[string]string{"code": code, "type": "totp"}},
		struct {
			endpoint string
			payload  map[string]string
		}{officialAuthBase + "/api/accounts/mfa/verify", map[string]string{"otp": code, "type": "totp"}},
		struct {
			endpoint string
			payload  map[string]string
		}{officialAuthBase + "/api/accounts/mfa/totp/verify", map[string]string{"code": code}},
	)
	for _, attempt := range attempts {
		payload, _ := json.Marshal(attempt.payload)
		response, err := r.authJSONWithJar(ctx, jar, http.MethodPost, attempt.endpoint, payload, currentURL)
		if err != nil {
			continue
		}
		if next := continueURLFromJSON(response); next != "" {
			return next, nil
		}
		if ids, snapshotErr := r.workspaceIDs(ctx, jar); snapshotErr == nil && containsWorkspace(ids, workspaceID) {
			return "", nil
		}
	}
	return "", errors.New("TOTP verification was not confirmed")
}

func extractMFAChallenge(currentURL string, page []byte) string {
	matches := authChallengePattern.FindStringSubmatch(currentURL + " " + string(page))
	for index := 1; index < len(matches); index++ {
		if value := strings.TrimSpace(matches[index]); value != "" {
			return value
		}
	}
	return ""
}

func (r *HTTPReader) selectWorkspace(ctx context.Context, jar http.CookieJar, workspaceID, referer string) error {
	if _, err := r.authJSONWithJar(ctx, jar, http.MethodGet, officialAuthBase+"/sign-in-with-chatgpt/codex/consent", nil, referer); err != nil {
		return fmt.Errorf("workspace consent: %w", err)
	}
	payload, _ := json.Marshal(map[string]string{"workspace_id": workspaceID})
	body, err := r.authJSONWithJar(ctx, jar, http.MethodPost, officialAuthBase+"/api/accounts/workspace/select", payload, officialAuthBase+"/workspace")
	if err != nil {
		return fmt.Errorf("workspace selection: %w", err)
	}
	if next := continueURLFromJSON(body); next != "" {
		_, _, err = r.followBrowserRedirect(ctx, jar, next, officialAuthBase+"/workspace")
		return err
	}
	ids, snapshotErr := r.workspaceIDs(ctx, jar)
	if snapshotErr != nil || !containsWorkspace(ids, workspaceID) {
		return errors.New("workspace selection was not confirmed")
	}
	return nil
}

func (r *HTTPReader) workspaceIDs(ctx context.Context, jar http.CookieJar) ([]string, error) {
	body, err := r.authJSONWithJar(ctx, jar, http.MethodGet, officialAuthBase+"/api/accounts/client_auth_session_dump", nil, officialAuthBase+"/workspace")
	if err != nil {
		return nil, err
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, errors.New("workspace session dump is invalid")
	}
	found := make(map[string]struct{})
	collectWorkspaceIDs(root, found, 0)
	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	return ids, nil
}

func collectWorkspaceIDs(value any, found map[string]struct{}, depth int) {
	if depth > 6 {
		return
	}
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			switch key {
			case "workspaces", "organizations", "accounts":
				collectWorkspaceEntries(child, found, depth+1)
			case "client_auth_session", "payload", "page":
				collectWorkspaceIDs(child, found, depth+1)
			}
		}
	case []any:
		for _, child := range current {
			collectWorkspaceIDs(child, found, depth+1)
		}
	}
}

func collectWorkspaceEntries(value any, found map[string]struct{}, depth int) {
	if depth > 6 {
		return
	}
	switch current := value.(type) {
	case []any:
		for _, item := range current {
			collectWorkspaceEntries(item, found, depth+1)
		}
	case map[string]any:
		for _, key := range []string{"id", "workspace_id", "account_id"} {
			if candidate, ok := current[key].(string); ok && strings.TrimSpace(candidate) != "" {
				found[strings.TrimSpace(candidate)] = struct{}{}
			}
		}
		for _, key := range []string{"workspace", "membership", "workspaces", "organizations"} {
			if child, ok := current[key]; ok {
				collectWorkspaceEntries(child, found, depth+1)
			}
		}
	}
}

func containsWorkspace(ids []string, workspaceID string) bool {
	for _, id := range ids {
		if strings.EqualFold(strings.TrimSpace(id), strings.TrimSpace(workspaceID)) {
			return true
		}
	}
	return false
}
func ValidateDeliveryIdentity(result DeliveryCredentialSet, workspaceID string) (DeliveryCredentialSet, error) {
	return validateDeliveryIdentity(result, workspaceID)
}

func validateDeliveryIdentity(result DeliveryCredentialSet, workspaceID string) (DeliveryCredentialSet, error) {
	actualWorkspace, subject := tokenIdentity(result.IDToken)
	if actualWorkspace == "" {
		actualWorkspace, subject = tokenIdentity(result.AccessToken)
	}
	if actualWorkspace == "" || !strings.EqualFold(actualWorkspace, strings.TrimSpace(workspaceID)) {
		return DeliveryCredentialSet{}, errors.New("PKCE token workspace identity is missing or mismatched")
	}
	if subject == "" {
		return DeliveryCredentialSet{}, errors.New("PKCE token subject identity is missing")
	}
	result.WorkspaceID = actualWorkspace
	result.PlatformSubjectID = subject
	return result, nil
}

func tokenIdentity(token string) (workspaceID, subjectID string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var claims struct {
		Subject string `json:"sub"`
		Auth    struct {
			Workspace string `json:"chatgpt_account_id"`
			User      string `json:"chatgpt_user_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return "", ""
	}
	subjectID = strings.TrimSpace(claims.Auth.User)
	if subjectID == "" {
		subjectID = strings.TrimSpace(claims.Subject)
	}
	return strings.TrimSpace(claims.Auth.Workspace), subjectID
}

func continueURLFromJSON(body []byte) string {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return ""
	}
	return findContinueURL(root, 0)
}

func findContinueURL(value any, depth int) string {
	if depth > 4 {
		return ""
	}
	switch current := value.(type) {
	case map[string]any:
		for _, key := range []string{"continue_url", "redirect_url", "url"} {
			if candidate, ok := current[key].(string); ok && strings.TrimSpace(candidate) != "" {
				return strings.TrimSpace(candidate)
			}
		}
		for _, key := range []string{"payload", "page", "data"} {
			if child, ok := current[key]; ok {
				if candidate := findContinueURL(child, depth+1); candidate != "" {
					return candidate
				}
			}
		}
	case []any:
		for _, child := range current {
			if candidate := findContinueURL(child, depth+1); candidate != "" {
				return candidate
			}
		}
	}
	return ""
}

func requiresTOTP(pageURL string, body []byte) bool {
	lower := strings.ToLower(pageURL + " " + string(body))
	return strings.Contains(lower, "mfa") || strings.Contains(lower, "totp") || strings.Contains(lower, "authenticator")
}

func newBrowserID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(value[0:4]), hex.EncodeToString(value[4:6]),
		hex.EncodeToString(value[6:8]), hex.EncodeToString(value[8:10]),
		hex.EncodeToString(value[10:16])), nil
}
func randomState() (string, error) {
	verifier, _, err := GeneratePKCE()
	return verifier, err
}

func ensureCookieJar(client *http.Client) (http.CookieJar, error) {
	if client == nil {
		return nil, errors.New("http client is required")
	}
	if client.Jar != nil {
		return client.Jar, nil
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client.Jar = jar
	return jar, nil
}

func (r *HTTPReader) authJSON(ctx context.Context, method, path string, body []byte, referer string) ([]byte, error) {
	jar, err := ensureCookieJar(r.client)
	if err != nil {
		return nil, err
	}
	base := officialAuthBase
	if strings.HasPrefix(path, "/api/auth/") {
		base = officialChatBase
	}
	return r.authJSONWithJar(ctx, jar, method, base+path, body, referer)
}

func (r *HTTPReader) authJSONWithJar(ctx context.Context, jar http.CookieJar, method, target string, body []byte, referer string) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, errors.New("authentication request is invalid")
	}
	req.Header.Set("Accept", "application/json, text/html;q=0.9")
	req.Header.Set("User-Agent", browserAuthUA)
	origin := officialAuthBase
	if strings.HasPrefix(target, officialChatBase) {
		origin = officialChatBase
	}
	req.Header.Set("Origin", origin)
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	if body != nil {
		if strings.Contains(target, "/api/auth/signin/openai") {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	client := &http.Client{Transport: r.client.Transport, Jar: jar, Timeout: r.client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if readErr != nil || len(payload) > maxResponseBody {
		return nil, errors.New("authentication response is incomplete")
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return nil, fmt.Errorf("authentication redirect missing location")
		}
		return json.Marshal(map[string]string{"continue_url": resolveURL(target, location)})
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("authentication request rejected: HTTP %d", response.StatusCode)
	}
	return payload, nil
}

func (r *HTTPReader) followBrowserRedirect(ctx context.Context, jar http.CookieJar, startURL, referer string) (string, []byte, error) {
	current := strings.TrimSpace(startURL)
	if current == "" {
		return "", nil, errors.New("authentication redirect URL is empty")
	}
	client := &http.Client{Transport: r.client.Transport, Jar: jar, Timeout: r.client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for hop := 0; hop < maxAuthHops; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return current, nil, errors.New("authentication redirect URL is invalid")
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json")
		req.Header.Set("User-Agent", browserAuthUA)
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		response, err := client.Do(req)
		if err != nil {
			return current, nil, err
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
		response.Body.Close()
		if readErr != nil || len(payload) > maxResponseBody {
			return current, nil, errors.New("authentication page is incomplete")
		}
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				return current, payload, fmt.Errorf("authentication page rejected: HTTP %d", response.StatusCode)
			}
			return current, payload, nil
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return current, nil, errors.New("authentication redirect missing location")
		}
		current = resolveURL(current, location)
		referer = req.URL.String()
	}
	return current, nil, errors.New("authentication redirect limit exceeded")
}

func captureWithJar(ctx context.Context, source *http.Client, jar http.CookieJar, authorizeURL, expectedState string) (string, error) {
	client := &http.Client{Transport: source.Transport, Jar: jar, Timeout: source.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	current := authorizeURL
	accountChosen := false
	for hop := 0; hop < maxAuthHops; hop++ {
		if code, callbackErr := authorizationCallbackCode(current, expectedState); callbackErr != nil {
			return "", callbackErr
		} else if code != "" {
			return code, nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return "", errors.New("authorization URL is invalid")
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json")
		req.Header.Set("User-Agent", browserAuthUA)
		response, err := client.Do(req)
		if err != nil {
			return "", err
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
		response.Body.Close()
		if readErr != nil || len(payload) > maxResponseBody {
			return "", errors.New("authorization response is incomplete")
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			if strings.Contains(current, "/choose-an-account") && !accountChosen {
				accountChosen = true
				next, selectErr := selectAuthorizationAccount(ctx, rClient(source, jar), current, payload)
				if selectErr != nil {
					return "", selectErr
				}
				if next == "" {
					return "", errors.New("account selection returned no continuation")
				}
				current = resolveURL(current, next)
				continue
			}
			if strings.Contains(current, "/codex/consent") {
				next, selectErr := submitAuthorizationWorkspace(ctx, rClient(source, jar), current, payload, queryWorkspace(authorizeURL))
				if selectErr != nil {
					return "", selectErr
				}
				if next == "" {
					return "", errors.New("workspace consent returned no continuation")
				}
				current = resolveURL(current, next)
				continue
			}
			return "", fmt.Errorf("authorization stopped before callback: HTTP %d", response.StatusCode)
		}
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			return "", fmt.Errorf("authorization stopped before callback: HTTP %d", response.StatusCode)
		}
		next := strings.TrimSpace(response.Header.Get("Location"))
		if next == "" {
			return "", errors.New("authorization redirect missing location")
		}
		next = resolveURL(current, next)
		parsed, err := url.Parse(next)
		if err != nil {
			return "", errors.New("authorization callback URL is invalid")
		}
		if parsed.Scheme+"://"+parsed.Host+parsed.Path == CodexRedirectURI {
			code := strings.TrimSpace(parsed.Query().Get("code"))
			state := parsed.Query().Get("state")
			if code == "" {
				return "", errors.New("authorization callback has no code")
			}
			if expectedState != "" && state != expectedState {
				return "", errors.New("authorization callback state mismatch")
			}
			return code, nil
		}
		current = next
	}
	return "", errors.New("authorization redirect limit exceeded")
}

func authorizationCallbackCode(rawURL, expectedState string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme+"://"+parsed.Host+parsed.Path != CodexRedirectURI {
		return "", nil
	}
	code := strings.TrimSpace(parsed.Query().Get("code"))
	if code == "" {
		return "", errors.New("authorization callback has no code")
	}
	if expectedState != "" && parsed.Query().Get("state") != expectedState {
		return "", errors.New("authorization callback state mismatch")
	}
	return code, nil
}

func rClient(source *http.Client, _ http.CookieJar) *HTTPReader {
	return &HTTPReader{client: source, config: HTTPConfig{baseURL: mustURL(officialAuthBase)}}
}

func mustURL(raw string) *url.URL {
	parsed, _ := url.Parse(raw)
	return parsed
}

func queryWorkspace(authorizeURL string) string {
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Query().Get("allowed_workspace_id"))
}

var accountSessionPattern = regexp.MustCompile(`us_[A-Za-z0-9]{16,}`)

func selectAuthorizationAccount(ctx context.Context, reader *HTTPReader, current string, body []byte) (string, error) {
	sessionID := accountSessionPattern.Find(body)
	if len(sessionID) == 0 {
		return "", errors.New("account selection page has no session id")
	}
	payload, _ := json.Marshal(map[string]string{"session_id": string(sessionID)})
	response, err := reader.authJSONWithJar(ctx, reader.client.Jar, http.MethodPost, officialAuthBase+"/api/accounts/session/select", payload, current)
	if err != nil {
		return "", fmt.Errorf("account selection: %w", err)
	}
	return continueURLFromJSON(response), nil
}

func submitAuthorizationWorkspace(ctx context.Context, reader *HTTPReader, current string, _ []byte, workspaceID string) (string, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return "", errors.New("workspace consent has no target")
	}
	payload, _ := json.Marshal(map[string]string{"workspace_id": workspaceID})
	response, err := reader.authJSONWithJar(ctx, reader.client.Jar, http.MethodPost, officialAuthBase+"/api/accounts/workspace/select", payload, current)
	if err != nil {
		return "", fmt.Errorf("workspace consent: %w", err)
	}
	return continueURLFromJSON(response), nil
}

func resolveURL(base, reference string) string {
	parsed, err := url.Parse(reference)
	if err != nil {
		return ""
	}
	if parsed.IsAbs() {
		return parsed.String()
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(parsed).String()
}

// CheckDeliveryLiveness uses only the current access token. It never refreshes, relogs in,
// or changes membership, and always probes the official ChatGPT read endpoint.
func (r *HTTPReader) CheckDeliveryLiveness(ctx context.Context, accessToken, workspaceID string) (DeliveryLiveness, error) {
	result := DeliveryLiveness{Status: oauthdomain.ProbeUnknown, Origin: "generation", ObservedAt: time.Now().UTC()}
	accessToken = strings.TrimSpace(accessToken)
	workspaceID = strings.TrimSpace(workspaceID)
	if accessToken == "" || workspaceID == "" {
		result.ErrorCode = "oauth_probe_input_invalid"
		return result, errors.New("oauth probe input is incomplete")
	}
	claimedWorkspace, subject := tokenIdentity(accessToken)
	result.WorkspaceID = claimedWorkspace
	result.PlatformSubjectID = subject
	target := officialChatBase + "/backend-api/wham/usage?workspace_id=" + url.QueryEscape(workspaceID)
	jar, err := ensureCookieJar(r.client)
	if err != nil {
		result.Status = oauthdomain.ProbeTransientFailure
		result.ErrorCode = "oauth_probe_configuration_invalid"
		return result, err
	}
	payload, status, err := r.bearerRequest(ctx, jar, target, accessToken)
	if err != nil {
		result.Status = oauthdomain.ProbeTransientFailure
		result.ErrorCode = "oauth_probe_transport_failure"
		return result, err
	}
	result.HTTPStatus = status
	result.ErrorCode = upstreamCode(payload)
	switch {
	case status >= 200 && status < 300:
		result.Status = oauthdomain.ProbeOK
	case status == http.StatusUnauthorized:
		result.Status = oauthdomain.ProbeAuthError
	case status == http.StatusPaymentRequired && result.ErrorCode == "deactivated_workspace":
		result.Status = oauthdomain.ProbeDeactivatedWorkspace
	case status == http.StatusTooManyRequests:
		result.Status = oauthdomain.ProbeRateLimited
	case status >= 500:
		result.Status = oauthdomain.ProbeTransientFailure
	default:
		result.Status = oauthdomain.ProbeUnknown
	}
	var identity struct {
		PlatformSubjectID string `json:"platform_subject_id"`
		WorkspaceID       string `json:"workspace_id"`
	}
	if json.Unmarshal(payload, &identity) == nil {
		if strings.TrimSpace(identity.PlatformSubjectID) != "" {
			result.PlatformSubjectID = strings.TrimSpace(identity.PlatformSubjectID)
		}
		if strings.TrimSpace(identity.WorkspaceID) != "" {
			result.WorkspaceID = strings.TrimSpace(identity.WorkspaceID)
		}
	}
	if result.WorkspaceID != "" && !strings.EqualFold(result.WorkspaceID, workspaceID) {
		result.Status = oauthdomain.ProbeUnknown
		result.ErrorCode = "workspace_identity_mismatch"
	}
	return result, nil
}

func (r *HTTPReader) bearerRequest(ctx context.Context, jar http.CookieJar, target, accessToken string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Origin", officialChatBase)
	req.Header.Set("User-Agent", CodexTokenUA)
	client := &http.Client{Transport: r.client.Transport, Jar: jar, Timeout: r.client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if readErr != nil || len(payload) > maxResponseBody {
		return nil, response.StatusCode, errors.New("oauth probe response is incomplete")
	}
	return payload, response.StatusCode, nil
}
