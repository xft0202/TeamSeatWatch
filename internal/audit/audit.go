package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// EventType identifies a registered audit fact.
type EventType string

// ActorType identifies the principal class that caused an audit fact.
type ActorType string

// Outcome is the registered result category for an audit fact.
type Outcome string

const (
	OwnerCreated     EventType = "owner.created"
	OwnerReset       EventType = "owner.reset"
	LoginSucceeded   EventType = "owner.login_succeeded"
	LoginFailed      EventType = "owner.login_failed"
	RecoveryCodeUsed EventType = "owner.recovery_code_used"
	SessionRotated   EventType = "owner.session_rotated"
	SessionRevoked   EventType = "owner.session_revoked"

	ActorSystem    ActorType = "system"
	ActorAnonymous ActorType = "anonymous"
	ActorOwner     ActorType = "owner"

	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeDenied    Outcome = "denied"
)

const ownerSecurityScope = "owner_security"

// ErrIdempotencyConflict means a stable event key was reused for a different conclusion.
var ErrIdempotencyConflict = errors.New("audit event key has conflicting content")

// Details is sealed so callers cannot pass arbitrary maps or request-derived payloads.
type Details interface{ auditDetails() }

// NoDetails is the explicit empty payload for events that permit no detail fields.
type NoDetails struct{}

func (NoDetails) auditDetails() {}

// AuthVersionDetails records only the non-secret authentication material generation.
type AuthVersionDetails struct {
	AuthVersion int64 `json:"auth_version"`
}

func (AuthVersionDetails) auditDetails() {}

// LoginDetails records which approved second-factor class completed login.
type LoginDetails struct {
	Factor string `json:"factor"`
}

func (LoginDetails) auditDetails() {}

// LoginFailureDetails records only the attempted factor class and optional limit domain.
type LoginFailureDetails struct {
	Factor        string `json:"factor"`
	RateLimitKind string `json:"rate_limit_kind,omitempty"`
}

func (LoginFailureDetails) auditDetails() {}

// SessionDetails records a registered session lifecycle reason.
type SessionDetails struct {
	Reason string `json:"reason"`
}

func (SessionDetails) auditDetails() {}

// Event contains the stable, non-secret fields accepted by the audit registry.
type Event struct {
	Type              EventType
	Actor             ActorType
	OwnerID           string
	EntityType        string
	EntityID          string
	Outcome           Outcome
	CorrelationID     string
	SourceFingerprint []byte
	Details           Details
	IdempotencyKey    string
	OccurredAt        time.Time
}

type spec struct {
	actor    ActorType
	entity   string
	outcomes []Outcome
	details  string
	scope    string
}

var registry = map[EventType]spec{
	OwnerCreated:     {ActorSystem, "owner", []Outcome{OutcomeSucceeded}, "auth_version", ownerSecurityScope},
	OwnerReset:       {ActorSystem, "owner", []Outcome{OutcomeSucceeded}, "auth_version", ownerSecurityScope},
	LoginSucceeded:   {ActorAnonymous, "owner_session", []Outcome{OutcomeSucceeded}, "login", ownerSecurityScope},
	LoginFailed:      {ActorAnonymous, "owner", []Outcome{OutcomeFailed, OutcomeDenied}, "login_failure", ownerSecurityScope},
	RecoveryCodeUsed: {ActorAnonymous, "owner_session", []Outcome{OutcomeSucceeded}, "none", ownerSecurityScope},
	SessionRotated:   {ActorOwner, "owner_session", []Outcome{OutcomeSucceeded}, "session", ownerSecurityScope},
	SessionRevoked:   {ActorOwner, "owner_session", []Outcome{OutcomeSucceeded}, "session", ownerSecurityScope},
}

// Write appends an event or returns the original event for an exact idempotent retry.
func Write(ctx context.Context, tx pgx.Tx, event Event) (string, error) {
	details, eventSpec, err := validate(event)
	if err != nil {
		return "", err
	}
	eventKey := stableKey(event)
	var eventID string
	err = tx.QueryRow(ctx, `
		INSERT INTO tsw_audit_events (
			event_key, retention_scope_type, retention_scope_id, actor_type,
			owner_id, event_type, entity_type, entity_id, outcome, correlation_id,
			source_fingerprint, details, occurred_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $3, $5, $6, $7, $8, $9, $10, $11,
			COALESCE($12::timestamptz, now()),
			COALESCE($12::timestamptz, now()) + interval '7 days'
		)
		ON CONFLICT (event_key) DO NOTHING
		RETURNING id`, eventKey[:], eventSpec.scope, event.OwnerID, event.Actor, event.Type,
		event.EntityType, event.EntityID, event.Outcome, event.CorrelationID,
		nullBytes(event.SourceFingerprint), details, nullTime(event.OccurredAt)).Scan(&eventID)
	if err == nil {
		return eventID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	// A conflict never updates the append-only row; the follow-up read distinguishes retry from contradiction.
	err = tx.QueryRow(ctx, `
		SELECT id FROM tsw_audit_events
		WHERE event_key = $1
		  AND retention_scope_type = $2
		  AND retention_scope_id = $3
		  AND actor_type = $4
		  AND owner_id = $3
		  AND event_type = $5
		  AND entity_type = $6
		  AND entity_id = $7
		  AND outcome = $8
		  AND details = $9`, eventKey[:], eventSpec.scope, event.OwnerID, event.Actor, event.Type,
		event.EntityType, event.EntityID, event.Outcome, details).Scan(&eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrIdempotencyConflict
	}
	return eventID, err
}

func validate(event Event) ([]byte, spec, error) {
	eventSpec, ok := registry[event.Type]
	if !ok {
		return nil, spec{}, errors.New("unregistered audit event")
	}
	if event.Actor != eventSpec.actor || event.EntityType != eventSpec.entity || !allowedOutcome(event.Outcome, eventSpec.outcomes) || event.OwnerID == "" || event.EntityID == "" || event.CorrelationID == "" || event.IdempotencyKey == "" {
		return nil, spec{}, errors.New("audit event does not match registry")
	}
	if len(event.SourceFingerprint) != 0 && len(event.SourceFingerprint) != 32 {
		return nil, spec{}, errors.New("invalid source fingerprint")
	}
	validDetails := false
	switch eventSpec.details {
	case "none":
		_, validDetails = event.Details.(NoDetails)
	case "auth_version":
		value, ok := event.Details.(AuthVersionDetails)
		validDetails = ok && value.AuthVersion > 0
	case "login":
		value, ok := event.Details.(LoginDetails)
		validDetails = ok && validFactor(value.Factor)
	case "login_failure":
		value, ok := event.Details.(LoginFailureDetails)
		validDetails = ok && validFactor(value.Factor) && validRateLimitKind(value.RateLimitKind)
	case "session":
		value, ok := event.Details.(SessionDetails)
		validDetails = ok && validSessionReason(event.Type, value.Reason)
	}
	if !validDetails {
		return nil, spec{}, errors.New("audit details do not match registry")
	}
	details, err := json.Marshal(event.Details)
	return details, eventSpec, err
}

func validFactor(value string) bool {
	return value == "totp" || value == "recovery_code"
}

func validRateLimitKind(value string) bool {
	return value == "" || value == "login" || value == "recovery"
}

func validSessionReason(eventType EventType, value string) bool {
	if eventType == SessionRotated {
		return value == "session_revocation"
	}
	return value == "logout" || value == "owner_request" || value == "rotation"
}

func allowedOutcome(value Outcome, allowed []Outcome) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func stableKey(event Event) [32]byte {
	hash := sha256.New()
	writeField(hash, []byte("teamseatwatch:audit:event:v1"))
	for _, field := range [][]byte{[]byte(event.Type), []byte(event.OwnerID), []byte(event.IdempotencyKey)} {
		writeField(hash, field)
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeField(writer byteWriter, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func nullTime(value time.Time) interface{} {
	if value.IsZero() {
		return nil
	}
	return value
}

func nullBytes(value []byte) interface{} {
	if len(value) == 0 {
		return nil
	}
	return value
}
