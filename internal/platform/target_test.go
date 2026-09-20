package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClassifyTargetProbePreservesUncertainty(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		code      string
		err       error
		malformed bool
		want      TargetProbeStatus
	}{
		{name: "available", status: http.StatusOK, want: TargetAvailable},
		{name: "credential invalid", status: http.StatusUnauthorized, want: TargetCredentialInvalid},
		{name: "terminal account state", status: http.StatusForbidden, code: "account_deactivated", want: TargetDefinitelyUnavailable},
		{name: "rate limited", status: http.StatusTooManyRequests, want: TargetTransientFailure},
		{name: "network failure", err: context.DeadlineExceeded, want: TargetTransientFailure},
		{name: "malformed response", status: http.StatusOK, malformed: true, want: TargetUnknown},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ClassifyTargetProbe(testCase.status, testCase.code, testCase.err, testCase.malformed); got != testCase.want {
				t.Fatalf("got %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestProbeTargetUsesReferenceReadOnlyRouteAndParsesErrorCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/backend-api/wham/usage" {
			t.Fatalf("got %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Originator") != "codex_cli_rs" || r.Header.Get("Version") != "0.125.0" {
			t.Fatalf("missing reference request identity")
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "user@example.com" || password == "" {
			t.Fatalf("unexpected authorization header")
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"account_deactivated"}}`))
	}))
	defer server.Close()
	reader := &HTTPReader{
		client:      server.Client(),
		config:      HTTPConfig{baseURL: mustURL(t, server.URL)},
		credentials: Credentials{LoginIdentifier: "user@example.com", Password: string(make([]byte, 16))},
	}
	result, err := reader.ProbeTarget(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != TargetDefinitelyUnavailable || result.ErrorCode != "account_deactivated" || result.HTTPStatus != http.StatusForbidden {
		t.Fatalf("unexpected probe result: %#v", result)
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
