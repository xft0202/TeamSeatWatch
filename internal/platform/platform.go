package platform

import (
	"context"
	"errors"
	"time"
)

// Endpoint identifies independent read capabilities. Success at one endpoint
// cannot recover a terminal conclusion established by a different endpoint.
type Endpoint string

const (
	EndpointExchange      Endpoint = "workspace_exchange"
	EndpointSubscription  Endpoint = "workspace_subscription"
	EndpointCapacity      Endpoint = "seat_counter"
	EndpointJoin          Endpoint = "workspace_join"
	EndpointMembers       Endpoint = "workspace_members"
	EndpointPendingInvite Endpoint = "pending_invites"
)

type Outcome string

const (
	OutcomeOperational  Outcome = "operational"
	OutcomeDeactivated  Outcome = "deactivated_workspace"
	OutcomeNotFound     Outcome = "workspace_not_found"
	OutcomeUnauthorized Outcome = "unauthorized"
	OutcomeForbidden    Outcome = "forbidden"
	OutcomeRateLimited  Outcome = "rate_limited"
	OutcomeServerError  Outcome = "server_error"
	OutcomeTimeout      Outcome = "timeout"
	OutcomeNetworkError Outcome = "network_error"
	OutcomeIncomplete   Outcome = "incomplete"
)

type Completeness string

const (
	Complete Completeness = "complete"
	Partial  Completeness = "partial"
	Unknown  Completeness = "unknown"
)

type Result struct {
	Endpoint           Endpoint
	Outcome            Outcome
	HTTPStatus         int
	ObservedAt         time.Time
	ActiveUntil        *time.Time
	SeatLimit          *int
	MemberCount        *int
	PendingInviteCount *int
	Completeness       Completeness
	Members            []Member
}

type Member struct {
	Kind             string `json:"kind"`
	PlatformMemberID string `json:"platform_member_id"`
	Identifier       string `json:"identifier"`
	Status           string `json:"status"`
	Role             string `json:"role"`
}

// Reader is intentionally split by capability so fixtures can control each
// response and an incomplete snapshot cannot be mistaken for another fact.
type Reader interface {
	ReadExchange(context.Context, string) (Result, error)
	ReadSubscription(context.Context, string) (Result, error)
	ReadCapacity(context.Context, string) (Result, error)
	ReadJoin(context.Context, string) (Result, error)
	ReadMembers(context.Context, string) (Result, error)
	ReadPendingInvites(context.Context, string) (Result, error)
}

// Classify maps transport evidence to a bounded domain outcome. Only the exact
// 402 code is deactivation; every unrelated or weak failure stays non-terminal.
func Classify(status int, code string, err error) Outcome {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return OutcomeTimeout
		}
		return OutcomeNetworkError
	}
	switch {
	case status == 402 && code == string(OutcomeDeactivated):
		return OutcomeDeactivated
	case status == 404 && code == string(OutcomeNotFound):
		return OutcomeNotFound
	case status >= 200 && status < 300:
		return OutcomeOperational
	case status == 401:
		return OutcomeUnauthorized
	case status == 403:
		return OutcomeForbidden
	case status == 429:
		return OutcomeRateLimited
	case status >= 500:
		return OutcomeServerError
	default:
		return OutcomeIncomplete
	}
}
