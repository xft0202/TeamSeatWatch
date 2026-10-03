package platform

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type usageRoundTrip func(*http.Request) (*http.Response, error)

func (f usageRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func usagePayload(now time.Time, p5, p7 string) string {
	return fmt.Sprintf(`{"account_id":"workspace","user_id":"canonical","rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":%s,"limit_window_seconds":18000,"reset_at":%d},"secondary_window":{"used_percent":%s,"limit_window_seconds":604800,"reset_at":%d}}}`, p5, now.Add(time.Hour).Unix(), p7, now.Add(time.Hour).Unix())
}
func TestRotationUsageMeasuredVerdictsAndTrueScope(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct{ name, body, result string }{
		{"zero", usagePayload(now, "0", "0"), "zero"},
		{"positive", usagePayload(now, "0.1", "0"), "positive"},
		{"partial_positive", strings.Replace(usagePayload(now, "0.1", "0"), `"used_percent":0,`, ``, 1), "positive"},
		{"missing_percent", strings.Replace(usagePayload(now, "0", "0"), `"used_percent":0,`, ``, 1), "unknown"},
		{"null_percent", strings.Replace(usagePayload(now, "0", "0"), `"used_percent":0,`, `"used_percent":null,`, 1), "unknown"},
		{"negative", usagePayload(now, "-1", "0"), "unknown"},
		{"string_percent", usagePayload(now, `"0"`, "0"), "unknown"},
		{"denied", strings.Replace(usagePayload(now, "0", "0"), `"allowed":true`, `"allowed":false`, 1), "unknown"},
		{"conflict", strings.Replace(usagePayload(now, "0", "0"), `"limit_reached":false`, `"limit_reached":true`, 1), "unknown"},
		{"unknown_window_zero", strings.Replace(usagePayload(now, "0", "0"), `604800`, `2592000`, 1), "unknown"},
		{"unknown_window_positive", strings.Replace(usagePayload(now, "0", "2"), `604800`, `2592000`, 1), "positive"},
		{"extra_window", strings.Replace(usagePayload(now, "0", "0"), `"rate_limit":`, `"additional_rate_limits":[{}],"rate_limit":`, 1), "unknown"},
		{"account_mismatch", strings.Replace(usagePayload(now, "3", "0"), `"workspace"`, `"other"`, 1), "unknown"},
		{"identity_mismatch", strings.Replace(usagePayload(now, "3", "0"), `"canonical"`, `"other"`, 1), "unknown"},
		{"expired_window", usagePayload(now.Add(-2*time.Hour), "0", "0"), "unknown"},
		{"duplicate_window", strings.Replace(usagePayload(now, "0", "0"), `604800`, `18000`, 1), "unknown"},
		{"invented_scope", strings.Replace(usagePayload(now, "0", "0"), `"rate_limit":`, `"usage_scope":"workspace","workspace_id":"workspace","rate_limit":`, 1), "zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRotationUsage([]byte(tc.body), "workspace", "canonical", now)
			if got.Result != tc.result || got.Scope != "account" || got.WorkspaceID != "" {
				t.Fatalf("%+v", got)
			}
		})
	}
}
func TestRotationUsageFixedOfficialHTTPAndFailures(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, status := range []int{200, 302, 401, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			source := &http.Client{Timeout: time.Second, Transport: usageRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.String() != personalUsageURL || r.Header.Get("Chatgpt-Account-Id") != "workspace" || r.Header.Get("Authorization") != "Bearer "+candidateOAuth(t, now).AccessToken || r.Header.Get("User-Agent") != "codex_cli_rs/0.146.0" || r.Header.Get("Cookie") != "" || r.Body != nil {
					t.Fatal("wrong admitted scoped read")
				}
				for _, legacy := range []string{"Originator", "Version", "X-OpenAI-Target-Path", "X-OpenAI-Target-Route", "OpenAI-Beta"} {
					if r.Header.Get(legacy) != "" {
						t.Fatal("legacy header in OAuth liveness", legacy)
					}
				}
				h := http.Header{"Content-Type": []string{"application/json"}, "Location": []string{"https://foreign.test/secret"}}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(usagePayload(now, "0", "0"))), Request: r}, nil
			})}
			p := OfficialRotationUsageReader{Client: func(context.Context) (*http.Client, func(), error) { return source, nil, nil }}
			got, err := p.ReadRotationUsage(context.Background(), candidateOAuth(t, now), "canonical")
			if err != nil || calls != 1 || status == 200 && got.Result != "zero" || status != 200 && got.Result != "unknown" || got.Scope != "account" {
				t.Fatalf("%+v calls=%d err=%v", got, calls, err)
			}
		})
	}
	bad := candidateOAuth(t, now)
	bad.WorkspaceID = "other"
	calls := 0
	p := OfficialRotationUsageReader{Client: func(context.Context) (*http.Client, func(), error) { calls++; return nil, nil, nil }}
	if _, err := p.ReadRotationUsage(context.Background(), bad, "canonical"); err == nil || calls != 0 {
		t.Fatal("invalid binding reached client")
	}
}
