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

// JoinAttemptResult keeps platform response handling bounded and redacted. The
// body itself never leaves the adapter; only semantic and transport evidence is
// handed to the durable operation boundary.
type JoinAttemptResult struct {
	HTTPStatus           int
	ErrorCode            string
	Semantic             string
	RequestSent          bool
	RequestMayHaveEffect bool
	Success              bool
}

type MembershipResult struct {
	Present          bool
	Complete         bool
	HTTPStatus       int
	ErrorCode        string
	PlatformMemberID string
	ObservedAt       time.Time
}

// Joiner exposes each side-effect stage separately so the worker can persist
// and remeasure the sticky egress lease before every possibly delivered POST.
type Joiner interface {
	RequestJoin(context.Context, string) (JoinAttemptResult, error)
	AcceptJoin(context.Context, string) (JoinAttemptResult, error)
	VerifyMembership(context.Context, string, string) (MembershipResult, error)
}

func (r *HTTPReader) RequestJoin(ctx context.Context, workspace string) (JoinAttemptResult, error) {
	return r.joinStage(ctx, workspace, "/invites/request")
}

func (r *HTTPReader) AcceptJoin(ctx context.Context, workspace string) (JoinAttemptResult, error) {
	return r.joinStage(ctx, workspace, "/invites/accept")
}

// Join retains the focused adapter contract while production worker execution
// uses the split methods so it can fence between side-effect stages.
func (r *HTTPReader) Join(ctx context.Context, workspace string) (JoinAttemptResult, error) {
	request, err := r.RequestJoin(ctx, workspace)
	if err != nil || requestTerminates(request.ErrorCode) || !request.RequestMayHaveEffect {
		return request, err
	}
	return r.AcceptJoin(ctx, workspace)
}

func (r *HTTPReader) joinStage(ctx context.Context, workspace, suffix string) (JoinAttemptResult, error) {
	result := JoinAttemptResult{RequestSent: true, RequestMayHaveEffect: true}
	response, err := r.joinRequest(ctx, workspace, suffix)
	if err != nil {
		return result, err
	}
	result.HTTPStatus = response.status
	result.ErrorCode = response.errorCode
	result.Semantic = response.semantic
	result.Success = response.status >= 200 && response.status < 300
	result.RequestMayHaveEffect = requestMayHaveSideEffect(response.status, result.Success, response.errorCode)
	return result, nil
}

func (r *HTTPReader) VerifyMembership(ctx context.Context, workspace, identifier string) (MembershipResult, error) {
	result := MembershipResult{ObservedAt: time.Now().UTC()}
	path := "/workspaces/" + url.PathEscape(strings.TrimSpace(workspace)) + "/members"
	response, body, err := r.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return result, err
	}
	result.HTTPStatus = response.StatusCode
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		result.ErrorCode = upstreamCode(body)
		return result, nil
	}
	var payload struct {
		Complete *bool    `json:"complete"`
		Members  []Member `json:"members"`
	}
	if len(body) == 0 || json.Unmarshal(body, &payload) != nil || payload.Complete == nil {
		result.ErrorCode = "incomplete_response"
		return result, nil
	}
	members, valid := validMembers(payload.Members)
	result.Complete = *payload.Complete && valid
	for _, member := range members {
		if member.Kind == "member" && strings.EqualFold(strings.TrimSpace(member.Identifier), strings.TrimSpace(identifier)) {
			result.Present = true
			result.PlatformMemberID = member.PlatformMemberID
			return result, nil
		}
	}
	if !result.Complete {
		result.ErrorCode = "incomplete_membership_fact"
	}
	return result, nil
}

type joinResponse struct {
	status    int
	errorCode string
	semantic  string
}

func (r *HTTPReader) joinRequest(ctx context.Context, workspace, suffix string) (joinResponse, error) {
	path := "/backend-api/accounts/" + url.PathEscape(strings.TrimSpace(workspace)) + suffix
	response, body, err := r.doJSON(ctx, http.MethodPost, path, strings.NewReader("{}"))
	if err != nil {
		return joinResponse{}, err
	}
	return joinResponse{status: response.StatusCode, errorCode: upstreamCode(body), semantic: classifyMembershipResponseSemantic(body)}, nil
}

func (r *HTTPReader) doJSON(ctx context.Context, method, path string, body io.Reader) (*http.Response, []byte, error) {
	target := r.config.baseURL.ResolveReference(&url.URL{Path: strings.TrimSuffix(r.config.baseURL.Path, "/") + path})
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, nil, err
	}
	request.SetBasicAuth(r.credentials.LoginIdentifier, r.credentials.Password)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://chatgpt.com")
	request.Header.Set("Referer", "https://chatgpt.com/")
	request.Header.Set("User-Agent", "TeamSeatWatch/1")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if readErr != nil || len(data) > maxResponseBody {
		return response, nil, errors.New("platform response incomplete")
	}
	return response, data, nil
}

func upstreamCode(body []byte) string {
	var value map[string]any
	if json.Unmarshal(body, &value) != nil {
		return ""
	}
	for _, key := range []string{"code", "error_code", "status"} {
		if code, ok := value[key].(string); ok {
			return boundedUpstreamCode(code)
		}
	}
	if detail, ok := value["detail"].(map[string]any); ok {
		if code, ok := detail["code"].(string); ok {
			return boundedUpstreamCode(code)
		}
	}
	return ""
}

func boundedUpstreamCode(raw string) string {
	value := strings.ToLower(strings.TrimSpace(strings.NewReplacer("-", "_", " ", "_").Replace(raw)))
	switch value {
	case "account_deactivated", "auth_error", "deactivated_workspace", "domain_restricted", "invalid_request", "rate_limit", "token_invalidated", "workspace_not_found":
		return value
	case "":
		return ""
	default:
		return "upstream_other"
	}
}

// NormalizeDiagnostic is the persistence boundary for platform/worker result codes.
// It prevents raw upstream values from reaching operation targets, audit, or APIs.
func NormalizeDiagnostic(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "available", "credential_invalid", "definitely_unavailable", "transient_failure", "unknown", "account_deactivated", "auth_error", "deactivated_workspace", "domain_restricted", "invalid_request", "rate_limit", "token_invalidated", "workspace_not_found", "upstream_other",
		"transport_failure", "incomplete_response", "invalid_response", "request_invalid", "preflight_transport_failure", "platform_configuration_invalid", "platform_credential_unavailable",
		"join_request_failed", "join_request_rejected", "accept_uncertain", "membership_unknown", "incomplete_membership_fact", "member_not_confirmed", "member_confirmed",
		"remove_confirmed", "remove_rejected", "remove_retry_scheduled", "remove_attempts_exhausted", "remove_transport_unknown", "membership_snapshot_incomplete", "owner_missing", "target_is_owner", "target_identity_ambiguous", "reconciled_present",
		"proxy_egress_drift", "proxy_capacity_exhausted", "attempts_exhausted", "lease_lost", "publication_fenced", "reconcile_absent", "reconciliation_attempts_exhausted", "platform_unknown":
		return value
	default:
		return "diagnostic_other"
	}
}

func requestMayHaveSideEffect(status int, success bool, errorCode string) bool {
	if success || status == 0 || status >= 200 && status < 300 {
		return true
	}
	if requestTerminates(errorCode) {
		return false
	}
	return status == http.StatusConflict || status == http.StatusForbidden || status == http.StatusTooManyRequests || status >= 500
}

func requestTerminates(code string) bool {
	switch strings.TrimSpace(code) {
	case "domain_restricted", "workspace_not_found", "deactivated_workspace":
		return true
	default:
		return false
	}
}

func classifyMembershipResponseSemantic(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "empty"
	}
	var decoded any
	if json.Unmarshal(body, &decoded) != nil {
		return "text"
	}
	switch value := decoded.(type) {
	case map[string]any:
		if success, ok := value["success"].(bool); ok {
			if success {
				return "success_true"
			}
			return "success_false"
		}
		for _, key := range []string{"status", "code"} {
			if raw, ok := value[key].(string); ok {
				return semanticField(key, raw)
			}
		}
		if detail, ok := value["detail"].(map[string]any); ok {
			if raw, ok := detail["code"].(string); ok {
				return semanticField("code", raw)
			}
		}
		return "json_object"
	case []any:
		return "json_array"
	default:
		return "json_scalar"
	}
}

func semanticField(kind, raw string) string {
	value := strings.ToLower(strings.TrimSpace(strings.NewReplacer("-", "_", " ", "_").Replace(raw)))
	switch value {
	case "accepted", "account_deactivated", "already_accepted", "already_pending", "auth_error", "deactivated_workspace", "domain_restricted", "error", "invite_pending", "invalid_request", "ok", "pending", "rate_limit", "success", "token_invalidated", "workspace_not_found":
		return kind + "_" + value
	default:
		return kind + "_other"
	}
}
