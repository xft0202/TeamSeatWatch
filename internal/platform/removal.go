package platform

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ExactMemberSnapshot is a complete live membership fact. DeclaredMemberCount
// equals the number of validated member entries; partial pages never reach the
// removal worker through this type.
type ExactMemberSnapshot struct {
	Fact                Result
	DeclaredMemberCount int
}

// RemoveMemberResult describes only the bounded transport conclusion. A
// successful response remains provisional until an ExactMemberSnapshot proves
// the frozen membership identity is absent.
type RemoveMemberResult struct {
	HTTPStatus           int
	ErrorCode            string
	Accepted             bool
	Retryable            bool
	RequestMayHaveEffect bool
}

// Remover keeps mutation and reconciliation on the same lease-owned adapter.
type Remover interface {
	SnapshotMembers(context.Context, string) (ExactMemberSnapshot, error)
	RemoveMember(context.Context, string, string) (RemoveMemberResult, error)
}

func (r *HTTPReader) SnapshotMembers(ctx context.Context, workspace string) (ExactMemberSnapshot, error) {
	fact, err := r.ReadMembers(ctx, workspace)
	if err != nil {
		return ExactMemberSnapshot{}, err
	}
	memberCount := 0
	for _, member := range fact.Members {
		if member.Kind == "member" {
			memberCount++
		}
	}
	if fact.Outcome != OutcomeOperational || fact.Completeness != Complete || fact.MemberCount == nil || *fact.MemberCount != memberCount {
		return ExactMemberSnapshot{}, errors.New("membership snapshot is not exact")
	}
	return ExactMemberSnapshot{Fact: fact, DeclaredMemberCount: *fact.MemberCount}, nil
}

func (r *HTTPReader) RemoveMember(ctx context.Context, workspace, liveMemberID string) (RemoveMemberResult, error) {
	workspace = strings.TrimSpace(workspace)
	liveMemberID = strings.TrimSpace(liveMemberID)
	if workspace == "" || liveMemberID == "" {
		return RemoveMemberResult{}, errors.New("remove member target is invalid")
	}
	result := RemoveMemberResult{RequestMayHaveEffect: true}
	path := "/backend-api/accounts/" + url.PathEscape(workspace) + "/users/" + url.PathEscape(liveMemberID)
	response, body, err := r.doJSON(ctx, http.MethodDelete, path, nil)
	if err != nil {
		result.Retryable = true
		return result, err
	}
	result.HTTPStatus = response.StatusCode
	result.ErrorCode = upstreamCode(body)
	result.Accepted = response.StatusCode >= 200 && response.StatusCode < 300
	result.Retryable = response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500
	result.RequestMayHaveEffect = requestMayHaveSideEffect(response.StatusCode, result.Accepted, result.ErrorCode)
	return result, nil
}
