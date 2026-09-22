package platform

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type pkceRoundTrip func(*http.Request) (*http.Response, error)

func (f pkceRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBuildWorkspaceAuthorizeURLUsesReferenceContract(t *testing.T) {
	raw := BuildWorkspaceAuthorizeURL("challenge", "state", "workspace-123")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	checks := map[string]string{
		"response_type": "code", "client_id": CodexClientID, "redirect_uri": CodexRedirectURI,
		"scope": CodexScope, "code_challenge": "challenge", "code_challenge_method": "S256",
		"state": "state", "id_token_add_organizations": "true", "codex_cli_simplified_flow": "true",
		"originator": CodexOriginator, "allowed_workspace_id": "workspace-123",
	}
	for key, want := range checks {
		if query.Get(key) != want {
			t.Fatalf("%s=%q want %q", key, query.Get(key), want)
		}
	}
	if query.Has("prompt") || query.Has("login_hint") {
		t.Fatal("workspace authorize URL contains legacy account-selection fields")
	}
}

func TestCapturePKCEAuthorizationCodeFollowsRedirectAndChecksState(t *testing.T) {
	client := &http.Client{Transport: pkceRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{CodexRedirectURI + "?code=CODE&state=" + req.URL.Query().Get("state")}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})}
	code, err := CapturePKCEAuthorizationCode(context.Background(), client, AuthorizeURL+"?state=state", "state")
	if err != nil || code != "CODE" {
		t.Fatalf("code=%q err=%v", code, err)
	}
	if _, err := CapturePKCEAuthorizationCode(context.Background(), client, AuthorizeURL+"?state=state", "other"); err == nil {
		t.Fatal("state mismatch must be rejected")
	}
}

func TestExchangePKCECodeRejectsTrailingJSON(t *testing.T) {
	client := &http.Client{Transport: pkceRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"AT","refresh_token":"RT","id_token":"ID"}{"unexpected":true}`)), Request: req}, nil
	})}
	if _, err := ExchangePKCECode(context.Background(), client, "CODE", "VERIFIER"); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("err=%v want trailing-data rejection", err)
	}
}

func TestExchangePKCECodeRejectsOversizedResponse(t *testing.T) {
	client := &http.Client{Transport: pkceRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBody+1))), Request: req}, nil
	})}
	if _, err := ExchangePKCECode(context.Background(), client, "CODE", "VERIFIER"); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err=%v want oversized-response rejection", err)
	}
}
func TestExchangePKCECodeUsesReferenceFormAndHeaders(t *testing.T) {
	client := &http.Client{Transport: pkceRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != TokenURL || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || req.Header.Get("originator") != CodexOriginator || req.Header.Get("User-Agent") != CodexTokenUA {
			t.Fatalf("unexpected token request: %s headers=%v", req.URL, req.Header)
		}
		body, _ := io.ReadAll(req.Body)
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{"grant_type": "authorization_code", "client_id": CodexClientID, "code": "CODE", "redirect_uri": CodexRedirectURI, "code_verifier": "VERIFIER"} {
			if form.Get(key) != want {
				t.Fatalf("form %s=%q want %q", key, form.Get(key), want)
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"AT","refresh_token":"RT","id_token":"ID"}`)), Request: req}, nil
	})}
	result, err := ExchangePKCECode(context.Background(), client, "CODE", "VERIFIER")
	if err != nil || result.AccessToken != "AT" || result.RefreshToken != "RT" || result.IDToken != "ID" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
