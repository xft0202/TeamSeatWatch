package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
)

// RotationUsageEvidence contains measured facts only. A selected Workspace
// header does not certify that upstream quotas are isolated to that Workspace.
// Responses without an explicit scope retain the conservative account scope.
type RotationUsageEvidence struct {
	Scope       string                `json:"scope"`
	WorkspaceID string                `json:"workspaceId,omitempty"`
	Result      string                `json:"result"`
	Diagnostic  string                `json:"diagnostic"`
	ObservedAt  time.Time             `json:"observedAt"`
	Windows     []RotationUsageWindow `json:"windows"`
}
type RotationUsageWindow struct {
	Seconds     int64     `json:"seconds"`
	UsedPercent float64   `json:"usedPercent"`
	ResetsAt    time.Time `json:"resetsAt"`
}
type RotationUsageReader interface {
	ReadRotationUsage(context.Context, DeliveryCredentialSet, string) (RotationUsageEvidence, error)
}
type OfficialRotationUsageReader struct{ Client DiscoveryClient }

var ErrRotationUsageUnavailable = errors.New("rotation usage unavailable")

func (p OfficialRotationUsageReader) ReadRotationUsage(ctx context.Context, credential DeliveryCredentialSet, subject string) (RotationUsageEvidence, error) {
	out := RotationUsageEvidence{Result: "unknown", Scope: "account", Diagnostic: "usage_unknown", Windows: []RotationUsageWindow{}}
	if _, err := ValidateRotationCandidateOAuth(credential, credential.WorkspaceID, subject, time.Now()); err != nil || p.Client == nil {
		return out, ErrRotationUsageUnavailable
	}
	source, release, err := p.Client(ctx)
	if release != nil {
		defer release()
	}
	if err != nil || source == nil || source.Transport == nil || source.Timeout <= 0 {
		return out, ErrRotationUsageUnavailable
	}
	client := *source
	client.Jar = nil
	client.Transport = personalUsageGuard{next: source.Transport}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, personalUsageURL, nil)
	if err != nil {
		return out, err
	}
	buildCodexOAuthUsageHeaders(req, credential.AccessToken, credential.WorkspaceID)
	response, err := client.Do(req)
	out.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	if err != nil {
		return out, nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == 401 || response.StatusCode == 403 {
			out.Diagnostic = "usage_credentials_invalid"
		}
		return out, nil
	}
	content, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || content != "application/json" {
		return out, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPersonalUsageBytes+1))
	if err != nil || len(body) > maxPersonalUsageBytes {
		return out, nil
	}
	return parseRotationUsage(body, credential.WorkspaceID, subject, out.ObservedAt), nil
}

func parseRotationUsage(body []byte, workspace, subject string, observed time.Time) RotationUsageEvidence {
	out := RotationUsageEvidence{Result: "unknown", Scope: "account", Diagnostic: "usage_incomplete", ObservedAt: observed, Windows: []RotationUsageWindow{}}
	var payload struct {
		Account string `json:"account_id"`
		User    string `json:"user_id"`
		Rate    struct {
			Allowed   *bool           `json:"allowed"`
			Reached   *bool           `json:"limit_reached"`
			Primary   json.RawMessage `json:"primary_window"`
			Secondary json.RawMessage `json:"secondary_window"`
		} `json:"rate_limit"`
		Additional json.RawMessage `json:"additional_rate_limits"`
	}
	if credentialJSON(body, &payload) != nil {
		return out
	}
	if payload.Account != "" && payload.Account != workspace || payload.User != "" && payload.User != subject {
		out.Diagnostic = "usage_scope_mismatch"
		return out
	}

	seen := map[int64]bool{}
	complete := true
	positive := false
	for _, raw := range []json.RawMessage{payload.Rate.Primary, payload.Rate.Secondary} {
		var window struct {
			Used    *float64 `json:"used_percent"`
			Seconds *int64   `json:"limit_window_seconds"`
			Reset   *int64   `json:"reset_at"`
		}
		if json.Unmarshal(raw, &window) != nil || window.Used == nil || *window.Used < 0 || *window.Used > 100 || window.Seconds == nil || (*window.Seconds <= 0 || *window.Seconds > 31536000) || window.Reset == nil || !time.Unix(*window.Reset, 0).After(observed) || seen[*window.Seconds] {
			complete = false
			continue
		}
		seen[*window.Seconds] = true
		out.Windows = append(out.Windows, RotationUsageWindow{Seconds: *window.Seconds, UsedPercent: *window.Used, ResetsAt: time.Unix(*window.Reset, 0).UTC()})
		positive = positive || *window.Used > 0
	}
	if positive {
		out.Result = "positive"
		out.Diagnostic = "usage_positive"
		return out
	}
	if len(payload.Additional) > 0 && string(payload.Additional) != "null" && string(payload.Additional) != "[]" {
		complete = false
	}
	if complete && seen[18000] && seen[604800] && payload.Rate.Allowed != nil && *payload.Rate.Allowed && payload.Rate.Reached != nil && !*payload.Rate.Reached {
		out.Result = "zero"
		out.Diagnostic = "usage_zero"
	}
	return out
}

// Migrated from the reference OAuth liveness builder. These requests carry
// only the current official CLI user agent plus bearer/account identity.
func buildCodexOAuthUsageHeaders(req *http.Request, accessToken, chatgptAccountID string) {
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "codex_cli_rs/0.146.0")
	if chatgptAccountID != "" {
		req.Header.Set("chatgpt-account-id", chatgptAccountID)
	}
}
