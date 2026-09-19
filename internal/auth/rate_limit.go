package auth

import "time"

// Rate-limit policy is fixed product behavior and is mirrored by PostgreSQL constraints.
const (
	RateLimitWindow   = 15 * time.Minute
	RateLimitFailures = 5
	RateLimitBlock    = 15 * time.Minute
)

// RateLimitState is the pure decision model used by focused policy tests.
type RateLimitState struct {
	Failures     int
	BlockedUntil time.Time
}

// RegisterFailure applies one failure without shortening an active block.
func RegisterFailure(state RateLimitState, now time.Time) RateLimitState {
	if !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil) {
		return state
	}
	state.Failures++
	if state.Failures >= RateLimitFailures {
		state.BlockedUntil = now.Add(RateLimitBlock)
	}
	return state
}

// RateLimited reports whether the authoritative block deadline is still active.
func RateLimited(state RateLimitState, now time.Time) bool {
	return !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil)
}
