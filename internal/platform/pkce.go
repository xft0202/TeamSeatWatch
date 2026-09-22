package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	CodexClientID    = "app_EMoamEEZ73f0CkXaXp7hrann"
	CodexRedirectURI = "http://localhost:1455/auth/callback"
	AuthorizeURL     = "https://auth.openai.com/oauth/authorize"
	TokenURL         = "https://auth.openai.com/oauth/token"
	CodexScope       = "openid profile email offline_access api.connectors.read api.connectors.invoke"
	CodexOriginator  = "codex_cli_rs"
	CodexTokenUA     = "codex_cli_rs/0.146.0"
)

func GeneratePKCE() (verifier, challenge string, err error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(value)
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// BuildWorkspaceAuthorizeURL constructs the official workspace-bound grant request.
// Workspace flows intentionally omit account-selection prompt fields.
func BuildWorkspaceAuthorizeURL(challenge, state, workspaceID string) string {
	query := url.Values{
		"response_type":              {"code"},
		"client_id":                  {CodexClientID},
		"redirect_uri":               {CodexRedirectURI},
		"scope":                      {CodexScope},
		"code_challenge":             {challenge},
		"code_challenge_method":      {"S256"},
		"state":                      {state},
		"id_token_add_organizations": {"true"},
		"codex_cli_simplified_flow":  {"true"},
		"originator":                 {CodexOriginator},
		"allowed_workspace_id":       {strings.TrimSpace(workspaceID)},
	}
	return AuthorizeURL + "?" + query.Encode()
}

func CapturePKCEAuthorizationCode(ctx context.Context, client *http.Client, authorizeURL, expectedState string) (string, error) {
	if client == nil || strings.TrimSpace(authorizeURL) == "" {
		return "", errors.New("PKCE authorization input is invalid")
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	follow := &http.Client{Transport: transport, Jar: client.Jar, Timeout: client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	current := authorizeURL
	for hop := 0; hop < 12; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return "", errors.New("PKCE authorization request is invalid")
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json")
		req.Header.Set("User-Agent", CodexTokenUA)
		response, err := follow.Do(req)
		if err != nil {
			return "", err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
		response.Body.Close()
		if readErr != nil || len(body) > maxResponseBody {
			return "", errors.New("PKCE authorization response is incomplete")
		}
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			return "", errors.New("PKCE authorization stopped before callback")
		}
		location := response.Header.Get("Location")
		if location == "" {
			return "", errors.New("PKCE authorization redirect has no location")
		}
		base, err := url.Parse(current)
		if err != nil {
			return "", errors.New("PKCE authorization URL is invalid")
		}
		next, err := base.Parse(location)
		if err != nil {
			return "", errors.New("PKCE authorization redirect is invalid")
		}
		if next.Scheme+"://"+next.Host+next.Path == strings.TrimSuffix(CodexRedirectURI, "/") {
			query := next.Query()
			code := query.Get("code")
			state := query.Get("state")
			if code == "" {
				return "", errors.New("PKCE callback has no authorization code")
			}
			if expectedState != "" && state != expectedState {
				return "", errors.New("PKCE callback state mismatch")
			}
			return code, nil
		}
		current = next.String()
		_ = body
	}
	return "", errors.New("PKCE authorization redirect limit exceeded")
}

func ExchangePKCECode(ctx context.Context, client *http.Client, code, verifier string) (DeliveryCredentialSet, error) {
	if client == nil || strings.TrimSpace(code) == "" || strings.TrimSpace(verifier) == "" {
		return DeliveryCredentialSet{}, errors.New("PKCE token exchange input is invalid")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {CodexClientID},
		"code":          {code},
		"redirect_uri":  {CodexRedirectURI},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", CodexTokenUA)
	req.Header.Set("originator", CodexOriginator)
	response, err := client.Do(req)
	if err != nil {
		return DeliveryCredentialSet{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return DeliveryCredentialSet{}, errors.New("PKCE token exchange rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil || len(raw) > maxResponseBody {
		return DeliveryCredentialSet{}, errors.New("PKCE token response is incomplete")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var result DeliveryCredentialSet
	if err := decoder.Decode(&result); err != nil {
		return DeliveryCredentialSet{}, errors.New("PKCE token response is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return DeliveryCredentialSet{}, errors.New("PKCE token response has trailing data")
	}
	if strings.TrimSpace(result.AccessToken) == "" || strings.TrimSpace(result.RefreshToken) == "" || strings.TrimSpace(result.IDToken) == "" {
		return DeliveryCredentialSet{}, errors.New("PKCE token response is incomplete")
	}
	return result, nil
}
