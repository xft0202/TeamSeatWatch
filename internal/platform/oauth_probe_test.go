package platform

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type probeStatusTransport struct {
	status int
	body   string
}

func (t probeStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Request:    req,
	}, nil
}

func TestCheckDeliveryLivenessPreservesFailureClassification(t *testing.T) {
	token := testJWT(`{"https://api.openai.com/auth":{"chatgpt_account_id":"workspace-1","chatgpt_user_id":"user-1"}}`)
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "deactivated workspace", status: http.StatusPaymentRequired, body: `{"code":"deactivated_workspace"}`, want: "deactivated_workspace"},
		{name: "forbidden remains unknown", status: http.StatusForbidden, body: `{"code":"auth_error"}`, want: "unknown"},
		{name: "rate limited", status: http.StatusTooManyRequests, body: `{"code":"rate_limit"}`, want: "rate_limited"},
		{name: "server failure", status: http.StatusBadGateway, body: `{"code":"upstream_other"}`, want: "transient_failure"},
		{name: "workspace mismatch", status: http.StatusOK, body: `{"workspace_id":"workspace-2"}`, want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewHTTPConfig("https://fixture.invalid")
			if err != nil {
				t.Fatal(err)
			}
			reader, err := config.OAuthReader(&http.Client{Transport: probeStatusTransport{status: tt.status, body: tt.body}, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			result, err := reader.CheckDeliveryLiveness(context.Background(), token, "workspace-1")
			if err != nil {
				t.Fatal(err)
			}
			if string(result.Status) != tt.want {
				t.Fatalf("status=%q want %q result=%+v", result.Status, tt.want, result)
			}
		})
	}
}
