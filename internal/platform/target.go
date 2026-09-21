package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TargetProbeStatus is deliberately narrower than transport errors. A network
// failure can be retried, but it is never evidence that the account is banned.
type TargetProbeStatus string

const (
	TargetAvailable             TargetProbeStatus = "available"
	TargetCredentialInvalid     TargetProbeStatus = "credential_invalid"
	TargetDefinitelyUnavailable TargetProbeStatus = "definitely_unavailable"
	TargetTransientFailure      TargetProbeStatus = "transient_failure"
	TargetUnknown               TargetProbeStatus = "unknown"
)

type TargetProbeResult struct {
	Status     TargetProbeStatus
	Endpoint   string
	Origin     string
	HTTPStatus int
	ErrorCode  string
	ObservedAt time.Time
}

func ClassifyTargetProbe(status int, errorCode string, err error, malformed bool) TargetProbeStatus {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return TargetTransientFailure
		}
		return TargetTransientFailure
	}
	if malformed {
		return TargetUnknown
	}
	if status == http.StatusForbidden && strings.EqualFold(errorCode, "account_deactivated") {
		return TargetDefinitelyUnavailable
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return TargetCredentialInvalid
	}
	if status >= 200 && status < 300 {
		return TargetAvailable
	}
	if status == http.StatusTooManyRequests || status >= 500 {
		return TargetTransientFailure
	}
	return TargetUnknown
}

func targetProbeErrorCode(body []byte) string {
	var root map[string]any
	if json.Unmarshal(body, &root) != nil {
		return ""
	}
	for _, key := range []string{"error", "detail"} {
		if nested, ok := root[key].(map[string]any); ok {
			if code, ok := nested["code"].(string); ok {
				return boundedUpstreamCode(code)
			}
		}
	}
	for _, key := range []string{"code", "error_code"} {
		if code, ok := root[key].(string); ok {
			return boundedUpstreamCode(code)
		}
	}
	return ""
}

// ProbeTarget uses one lease-owned client and one read-only account endpoint.
// It never calls join, remove, refresh, relogin, or membership APIs.
func (r *HTTPReader) ProbeTarget(ctx context.Context) (TargetProbeResult, error) {
	result := TargetProbeResult{Endpoint: "account_usage", Origin: "worker", ObservedAt: time.Now().UTC()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.config.baseURL.ResolveReference(&url.URL{Path: "/backend-api/wham/usage"}).String(), nil)
	if err != nil {
		result.Status = TargetUnknown
		result.ErrorCode = "request_invalid"
		return result, err
	}
	// TeamSeatWatch's platform adapter authenticates the prepared target account;
	// the read route and Codex request identity match the proven reference probe.
	req.SetBasicAuth(r.credentials.LoginIdentifier, r.credentials.Password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("OpenAI-Beta", "responses=experimental")
	req.Header.Set("Originator", "codex_cli_rs")
	req.Header.Set("Version", "0.125.0")
	req.Header.Set("User-Agent", "codex_cli_rs/0.125.0")
	req.Header.Set("X-OpenAI-Target-Path", "/backend-api/wham/usage")
	req.Header.Set("X-OpenAI-Target-Route", "/backend-api/wham/usage")
	response, err := r.client.Do(req)
	if err != nil {
		result.Status = ClassifyTargetProbe(0, "", err, false)
		result.ErrorCode = "transport_failure"
		return result, err
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if readErr != nil || len(body) > maxResponseBody {
		result.Status = ClassifyTargetProbe(response.StatusCode, "", nil, true)
		result.ErrorCode = "incomplete_response"
		return result, nil
	}
	var payload map[string]any
	malformed := len(body) == 0 || json.Unmarshal(body, &payload) != nil
	result.ErrorCode = targetProbeErrorCode(body)
	if malformed && result.ErrorCode == "" {
		result.ErrorCode = "invalid_response"
	}
	result.Status = ClassifyTargetProbe(response.StatusCode, result.ErrorCode, nil, malformed)
	return result, nil
}
