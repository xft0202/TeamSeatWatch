package platform

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type deliveryFlowTransport struct {
	state          string
	workspaceSteps int
	unexpected     string
}

func (f *deliveryFlowTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	respond := func(status int, headers http.Header, body string) (*http.Response, error) {
		if headers == nil {
			headers = make(http.Header)
		}
		return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	}
	path := req.URL.Host + req.URL.Path
	switch {
	case path == "chatgpt.com/api/auth/providers":
		return respond(http.StatusOK, nil, `{}`)
	case path == "chatgpt.com/api/auth/csrf":
		return respond(http.StatusOK, nil, `{"csrfToken":"csrf"}`)
	case path == "chatgpt.com/api/auth/signin/openai":
		query := req.URL.Query()
		if query.Get("ext-oai-did") == "" || query.Get("auth_session_logging_id") == "" || query.Get("ext-passkey-client-capabilities") != "1111" {
			return respond(http.StatusBadRequest, nil, `{"code":"missing_signin_context"}`)
		}
		return respond(http.StatusOK, nil, `{"url":"https://auth.openai.com/login/start"}`)
	case path == "auth.openai.com/login/start":
		return respond(http.StatusFound, http.Header{"Location": []string{"https://auth.openai.com/log-in/password"}}, "")
	case path == "auth.openai.com/log-in/password":
		return respond(http.StatusOK, nil, `<div>log-in/password</div>`)
	case path == "auth.openai.com/api/accounts/password/verify":
		body, _ := io.ReadAll(req.Body)
		if !strings.Contains(string(body), `"password":"pw"`) {
			return respond(http.StatusBadRequest, nil, `{"code":"bad_password_payload"}`)
		}
		return respond(http.StatusOK, nil, `{"continue_url":"https://auth.openai.com/after-password"}`)
	case path == "auth.openai.com/after-password":
		return respond(http.StatusOK, nil, `<div>/mfa-challenge/challenge-12345678</div>`)
	case path == "auth.openai.com/api/accounts/mfa/verify", path == "auth.openai.com/api/accounts/mfa/totp/verify":
		body, _ := io.ReadAll(req.Body)
		if !strings.Contains(string(body), `"type":"totp"`) && !strings.Contains(string(body), `"code":"`) {
			return respond(http.StatusBadRequest, nil, `{"code":"bad_totp_payload"}`)
		}
		if path == "auth.openai.com/api/accounts/mfa/verify" && !strings.Contains(string(body), `"id":"challenge-12345678"`) {
			return respond(http.StatusBadRequest, nil, `{"code":"missing_challenge_id"}`)
		}
		return respond(http.StatusOK, nil, `{"continue_url":"https://auth.openai.com/after-totp"}`)
	case path == "auth.openai.com/after-totp":
		return respond(http.StatusOK, nil, `authenticated`)
	case path == "auth.openai.com/sign-in-with-chatgpt/codex/consent":
		return respond(http.StatusOK, nil, `<div>consent</div>`)
	case path == "auth.openai.com/api/accounts/workspace/select":
		f.workspaceSteps++
		if f.workspaceSteps == 1 {
			return respond(http.StatusOK, nil, `{"continue_url":"https://auth.openai.com/workspace-selected"}`)
		}
		return respond(http.StatusFound, http.Header{"Location": []string{"http://localhost:1455/auth/callback?code=AUTH-CODE&state=" + url.QueryEscape(f.state)}}, "")
	case path == "auth.openai.com/workspace-selected":
		return respond(http.StatusOK, nil, `selected`)
	case path == "auth.openai.com/oauth/authorize":
		f.state = req.URL.Query().Get("state")
		if req.URL.Query().Get("allowed_workspace_id") != "workspace-1" || req.URL.Query().Get("code_challenge_method") != "S256" {
			return respond(http.StatusBadRequest, nil, `{"code":"bad_authorize_query"}`)
		}
		return respond(http.StatusFound, http.Header{"Location": []string{"https://auth.openai.com/choose-an-account"}}, "")
	case path == "auth.openai.com/choose-an-account":
		return respond(http.StatusOK, nil, `<div>us_12345678901234567890</div>`)
	case path == "auth.openai.com/api/accounts/session/select":
		return respond(http.StatusOK, nil, `{"continue_url":"https://auth.openai.com/codex/consent"}`)
	case path == "auth.openai.com/codex/consent":
		return respond(http.StatusOK, nil, `<div>consent</div>`)
	case path == "auth.openai.com/oauth/token":
		body, _ := io.ReadAll(req.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("code") != "AUTH-CODE" || form.Get("grant_type") != "authorization_code" || form.Get("code_verifier") == "" {
			return respond(http.StatusBadRequest, nil, `{"code":"bad_token_payload"}`)
		}
		idToken := testJWT(`{"https://api.openai.com/auth":{"chatgpt_account_id":"workspace-1","chatgpt_user_id":"user-1"},"sub":"fallback-user"}`)
		return respond(http.StatusOK, nil, `{"access_token":"`+idToken+`","refresh_token":"refresh","id_token":"`+idToken+`","expires_in":3600,"scope":"openid"}`)
	default:
		f.unexpected = path
		return respond(http.StatusNotFound, nil, `{"code":"not_found"}`)
	}
}

func testJWT(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + encoded + ".signature"
}

func TestCreateDeliveryCredentialsRunsWorkspacePKCEFlow(t *testing.T) {
	transport := &deliveryFlowTransport{}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	config, err := NewHTTPConfig("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := config.Reader(client, Credentials{LoginIdentifier: "member@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.CreateDeliveryCredentials(context.Background(), DeliveryCredentialRequest{
		Identifier: "member@example.com", Password: "pw", TOTPSecret: "JBSWY3DPEHPK3PXP", Workspace: "workspace-1",
	})
	if err != nil {
		t.Fatalf("%v (unexpected=%s)", err, transport.unexpected)
	}
	if result.RefreshToken != "refresh" || result.WorkspaceID != "workspace-1" || result.PlatformSubjectID != "user-1" {
		t.Fatalf("unexpected delivery result: %+v", result)
	}
	if transport.workspaceSteps != 2 {
		t.Fatalf("workspace selection steps=%d want 2", transport.workspaceSteps)
	}
}

func TestCreateDeliveryCredentialsRequiresTOTP(t *testing.T) {
	config, err := NewHTTPConfig("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := config.Reader(&http.Client{Transport: &deliveryFlowTransport{}, Timeout: time.Second}, Credentials{LoginIdentifier: "member@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.CreateDeliveryCredentials(context.Background(), DeliveryCredentialRequest{Identifier: "member@example.com", Password: "pw", Workspace: "workspace-1"})
	if err == nil || !strings.Contains(err.Error(), "requires TOTP") {
		t.Fatalf("err=%v", err)
	}
}

type deliveryProbeTransport struct{}

func (deliveryProbeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != officialChatBase+"/backend-api/wham/usage?workspace_id=workspace-1" {
		return nil, &url.Error{Op: "GET", URL: req.URL.String(), Err: io.ErrUnexpectedEOF}
	}
	if req.Header.Get("Authorization") == "" || req.URL.Host != "chatgpt.com" {
		return nil, io.ErrUnexpectedEOF
	}
	return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":"token_invalidated"}`)), Request: req}, nil
}

func TestCheckDeliveryLivenessUsesOfficialReadEndpoint(t *testing.T) {
	config, err := NewHTTPConfig("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := config.OAuthReader(&http.Client{Transport: deliveryProbeTransport{}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	token := testJWT(`{"https://api.openai.com/auth":{"chatgpt_account_id":"workspace-1","chatgpt_user_id":"user-1"}}`)
	result, err := reader.CheckDeliveryLiveness(context.Background(), token, "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "auth_error" || result.HTTPStatus != http.StatusUnauthorized || result.PlatformSubjectID != "user-1" {
		t.Fatalf("unexpected probe result: %+v", result)
	}
}

func TestTokenIdentityPrefersPlatformUserClaim(t *testing.T) {
	workspace, subject := tokenIdentity(testJWT(`{"https://api.openai.com/auth":{"chatgpt_account_id":"workspace-1","chatgpt_user_id":"user-1"},"sub":"jwt-sub"}`))
	if workspace != "workspace-1" || subject != "user-1" {
		t.Fatalf("workspace=%q subject=%q", workspace, subject)
	}
	fallback := testJWT(`{"https://api.openai.com/auth":{"chatgpt_account_id":"workspace-1"},"sub":"jwt-sub"}`)
	_, subject = tokenIdentity(fallback)
	if subject != "jwt-sub" {
		t.Fatalf("fallback subject=%q", subject)
	}
}

func TestGeneratePKCEProducesS256Challenge(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	if challenge != want {
		t.Fatalf("challenge=%q want %q", challenge, want)
	}
}
