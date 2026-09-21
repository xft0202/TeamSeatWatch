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
	OwnerCreated             EventType = "owner.created"
	OwnerReset               EventType = "owner.reset"
	LoginSucceeded           EventType = "owner.login_succeeded"
	LoginFailed              EventType = "owner.login_failed"
	RecoveryCodeUsed         EventType = "owner.recovery_code_used"
	SessionRotated           EventType = "owner.session_rotated"
	SessionRevoked           EventType = "owner.session_revoked"
	MotherAccountCreated     EventType = "mother_account.created"
	MotherAccountUpdated     EventType = "mother_account.updated"
	WorkspaceCreated         EventType = "workspace.created"
	WorkspaceUpdated         EventType = "workspace.updated"
	BindingCreated           EventType = "workspace.binding_created"
	ManualVerified           EventType = "workspace.manual_verified"
	TaskStarted              EventType = "task.started"
	TaskEnded                EventType = "task.ended"
	TaskRejected             EventType = "task.rejected"
	TaskInterrupted          EventType = "task.interrupted"
	TargetProbeStarted       EventType = "target_probe.started"
	TargetProbeEnded         EventType = "target_probe.ended"
	TargetProbeRejected      EventType = "target_probe.rejected"
	TargetProbeInterrupted   EventType = "target_probe.interrupted"
	TargetAccountProbed      EventType = "target_account.probed"
	TargetAccountCreated     EventType = "target_account.created"
	TargetAccountUpdated     EventType = "target_account.updated"
	TargetCredentialsUpdated EventType = "target_credentials.updated"
	BatchCreated             EventType = "batch.created"
	BatchUpdated             EventType = "batch.updated"
	JoinOperationAuthorized  EventType = "join.operation_authorized"
	JoinTargetPreflight      EventType = "join.target_preflight"
	JoinTargetSucceeded      EventType = "join.target_succeeded"
	JoinTargetFailed         EventType = "join.target_failed"
	JoinTargetUnknown        EventType = "join.target_unknown"
	JoinReconciliationQueued EventType = "join.reconciliation_queued"
	JoinReconciliationDone   EventType = "join.reconciliation_done"
	OwnerMutationRejected    EventType = "owner.mutation_rejected"

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

// WorkspaceDetails records a bounded workspace mutation conclusion.
type WorkspaceDetails struct {
	Result string `json:"result"`
}

func (WorkspaceDetails) auditDetails() {}

type BatchDetails struct {
	Result string `json:"result"`
}

func (BatchDetails) auditDetails() {}

type OperationDetails struct {
	Operation string `json:"operation"`
	Result    string `json:"result"`
	TargetID  string `json:"target_id,omitempty"`
}

func (OperationDetails) auditDetails() {}

type JoinTargetDetails struct {
	Status         string `json:"status"`
	Result         string `json:"result"`
	Stage          string `json:"stage"`
	DiagnosticCode string `json:"diagnostic_code,omitempty"`
}

func (JoinTargetDetails) auditDetails() {}

type TargetProbeDetails struct {
	Status     string `json:"status"`
	Endpoint   string `json:"endpoint"`
	Origin     string `json:"origin"`
	HTTPStatus int    `json:"http_status,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	ObservedAt string `json:"observed_at"`
}

func (TargetProbeDetails) auditDetails() {}

// ManualVerificationDetails records the Owner's explicit platform-UI conclusion.
type ManualVerificationDetails struct {
	Conclusion  string `json:"conclusion"`
	Source      string `json:"source"`
	ObservedAt  string `json:"observed_at"`
	ActiveUntil string `json:"active_until,omitempty"`
}

func (ManualVerificationDetails) auditDetails() {}

// TaskDetails is deliberately scalar; platform responses and complete egress identity are excluded.
type TaskDetails struct {
	AttemptNo        int    `json:"attempt_no"`
	Result           string `json:"result"`
	Stage            string `json:"stage"`
	RouteMode        string `json:"route_mode,omitempty"`
	ProxyScheme      string `json:"proxy_scheme,omitempty"`
	EgressKeyVersion string `json:"egress_key_version,omitempty"`
	ProxyVerifiedAt  string `json:"proxy_verified_at,omitempty"`
}

func (TaskDetails) auditDetails() {}

type OwnerMutationRejectionDetails struct {
	Operation string `json:"operation"`
	Reason    string `json:"reason"`
}

func (OwnerMutationRejectionDetails) auditDetails() {}

// Event contains the stable, non-secret fields accepted by the audit registry.
type Event struct {
	Type              EventType
	Actor             ActorType
	OwnerID           string
	RetentionScopeID  string
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
	OwnerCreated:             {ActorSystem, "owner", []Outcome{OutcomeSucceeded}, "auth_version", ownerSecurityScope},
	OwnerReset:               {ActorSystem, "owner", []Outcome{OutcomeSucceeded}, "auth_version", ownerSecurityScope},
	LoginSucceeded:           {ActorAnonymous, "owner_session", []Outcome{OutcomeSucceeded}, "login", ownerSecurityScope},
	LoginFailed:              {ActorAnonymous, "owner", []Outcome{OutcomeFailed, OutcomeDenied}, "login_failure", ownerSecurityScope},
	RecoveryCodeUsed:         {ActorAnonymous, "owner_session", []Outcome{OutcomeSucceeded}, "none", ownerSecurityScope},
	SessionRotated:           {ActorOwner, "owner_session", []Outcome{OutcomeSucceeded}, "session", ownerSecurityScope},
	SessionRevoked:           {ActorOwner, "owner_session", []Outcome{OutcomeSucceeded}, "session", ownerSecurityScope},
	MotherAccountCreated:     {ActorOwner, "mother_account", []Outcome{OutcomeSucceeded}, "workspace", ownerSecurityScope},
	MotherAccountUpdated:     {ActorOwner, "mother_account", []Outcome{OutcomeSucceeded}, "workspace", ownerSecurityScope},
	WorkspaceCreated:         {ActorOwner, "workspace", []Outcome{OutcomeSucceeded}, "workspace", "workspace"},
	WorkspaceUpdated:         {ActorOwner, "workspace", []Outcome{OutcomeSucceeded}, "workspace", "workspace"},
	BindingCreated:           {ActorOwner, "workspace_binding", []Outcome{OutcomeSucceeded}, "workspace", "workspace"},
	ManualVerified:           {ActorOwner, "workspace", []Outcome{OutcomeSucceeded}, "manual_verification", "workspace"},
	TaskStarted:              {ActorSystem, "task", []Outcome{OutcomeSucceeded}, "task", "workspace"},
	TaskEnded:                {ActorSystem, "task", []Outcome{OutcomeSucceeded, OutcomeFailed}, "task", "workspace"},
	TaskRejected:             {ActorSystem, "task", []Outcome{OutcomeDenied, OutcomeFailed}, "task", "workspace"},
	TaskInterrupted:          {ActorSystem, "task", []Outcome{OutcomeFailed}, "task", "workspace"},
	TargetProbeStarted:       {ActorSystem, "task", []Outcome{OutcomeSucceeded}, "task", "target_account"},
	TargetProbeEnded:         {ActorSystem, "task", []Outcome{OutcomeSucceeded, OutcomeFailed}, "task", "target_account"},
	TargetProbeRejected:      {ActorSystem, "task", []Outcome{OutcomeDenied, OutcomeFailed}, "task", "target_account"},
	TargetProbeInterrupted:   {ActorSystem, "task", []Outcome{OutcomeFailed}, "task", "target_account"},
	TargetAccountProbed:      {ActorSystem, "target_account", []Outcome{OutcomeSucceeded, OutcomeFailed}, "target_probe", "target_account"},
	TargetAccountCreated:     {ActorOwner, "target_account", []Outcome{OutcomeSucceeded}, "target", "target_account"},
	TargetAccountUpdated:     {ActorOwner, "target_account", []Outcome{OutcomeSucceeded}, "target", "target_account"},
	TargetCredentialsUpdated: {ActorOwner, "target_account", []Outcome{OutcomeSucceeded}, "target", "target_account"},
	BatchCreated:             {ActorOwner, "batch", []Outcome{OutcomeSucceeded}, "batch", "workspace"},
	BatchUpdated:             {ActorOwner, "batch", []Outcome{OutcomeSucceeded}, "batch", "workspace"},
	JoinOperationAuthorized:  {ActorOwner, "operation", []Outcome{OutcomeSucceeded}, "operation", "workspace"},
	JoinTargetPreflight:      {ActorSystem, "operation_target", []Outcome{OutcomeSucceeded, OutcomeFailed}, "join_target", "workspace"},
	JoinTargetSucceeded:      {ActorSystem, "operation_target", []Outcome{OutcomeSucceeded}, "join_target", "workspace"},
	JoinTargetFailed:         {ActorSystem, "operation_target", []Outcome{OutcomeFailed}, "join_target", "workspace"},
	JoinTargetUnknown:        {ActorSystem, "operation_target", []Outcome{OutcomeFailed}, "join_target", "workspace"},
	JoinReconciliationQueued: {ActorSystem, "task", []Outcome{OutcomeSucceeded}, "task", "workspace"},
	JoinReconciliationDone:   {ActorSystem, "task", []Outcome{OutcomeSucceeded, OutcomeFailed}, "task", "workspace"},
	OwnerMutationRejected:    {ActorOwner, "owner", []Outcome{OutcomeDenied}, "owner_mutation_rejection", ownerSecurityScope},
}

// Write appends an event or returns the original event for an exact idempotent retry.
func Write(ctx context.Context, tx pgx.Tx, event Event) (string, error) {
	details, eventSpec, err := validate(event)
	if err != nil {
		return "", err
	}
	eventKey := stableKey(event)
	scopeID := event.RetentionScopeID
	if scopeID == "" {
		scopeID = event.OwnerID
	}
	var eventID string
	err = tx.QueryRow(ctx, `
		INSERT INTO tsw_audit_events (
			event_key, retention_scope_type, retention_scope_id, actor_type,
			owner_id, event_type, entity_type, entity_id, outcome, correlation_id,
			source_fingerprint, details, occurred_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
			COALESCE($13::timestamptz, now()),
			COALESCE($13::timestamptz, now()) + interval '7 days'
		)
		ON CONFLICT (event_key) DO NOTHING
		RETURNING id`, eventKey[:], eventSpec.scope, scopeID, event.Actor, nullString(event.OwnerID), event.Type,
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
		  AND owner_id IS NOT DISTINCT FROM $5
		  AND event_type = $6
		  AND entity_type = $7
		  AND entity_id = $8
		  AND outcome = $9
		  AND details = $10`, eventKey[:], eventSpec.scope, scopeID, event.Actor, nullString(event.OwnerID), event.Type,
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
	if event.Actor != eventSpec.actor || event.EntityType != eventSpec.entity || !allowedOutcome(event.Outcome, eventSpec.outcomes) || event.EntityID == "" || event.CorrelationID == "" || event.IdempotencyKey == "" {
		return nil, spec{}, errors.New("audit event does not match registry")
	}
	if event.Actor == ActorOwner && event.OwnerID == "" || (eventSpec.scope == "workspace" && event.RetentionScopeID == "") || (eventSpec.scope == "target_account" && event.RetentionScopeID == "") || (eventSpec.scope == ownerSecurityScope && event.OwnerID == "") {
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
	case "workspace":
		value, ok := event.Details.(WorkspaceDetails)
		validDetails = ok && (value.Result == "created" || value.Result == "updated" || value.Result == "bound")
	case "target":
		value, ok := event.Details.(WorkspaceDetails)
		validDetails = ok && (value.Result == "created" || value.Result == "updated" || value.Result == "credentials_updated")
	case "batch":
		value, ok := event.Details.(BatchDetails)
		validDetails = ok && (value.Result == "created" || value.Result == "updated")
	case "operation":
		value, ok := event.Details.(OperationDetails)
		validDetails = ok && value.Operation == "join" && value.Result == "authorized"
	case "join_target":
		value, ok := event.Details.(JoinTargetDetails)
		validDetails = ok && validJoinTargetStatus(value.Status) && value.Result != "" && value.Stage != ""
	case "target_probe":
		value, ok := event.Details.(TargetProbeDetails)
		validDetails = ok && validProbeStatus(value.Status) && value.Endpoint == "account_usage" && (value.Origin == "worker" || value.Origin == "owner") && value.ObservedAt != "" && value.HTTPStatus >= 0 && value.HTTPStatus <= 599
	case "manual_verification":
		value, ok := event.Details.(ManualVerificationDetails)
		validConclusion := (value.Conclusion == "deactivated" || value.Conclusion == "recovered") && value.ActiveUntil == ""
		validExpiration := value.Conclusion == "expiration_corrected" && value.ActiveUntil != ""
		validDetails = ok && (validConclusion || validExpiration) && value.Source != "" && value.ObservedAt != ""
	case "task":
		value, ok := event.Details.(TaskDetails)
		validRoute := (value.RouteMode == "" && value.ProxyScheme == "" && value.EgressKeyVersion == "" && value.ProxyVerifiedAt == "") ||
			(value.RouteMode == "direct" && value.ProxyScheme == "" && value.EgressKeyVersion == "" && value.ProxyVerifiedAt == "") ||
			(value.RouteMode == "required" && validProxyScheme(value.ProxyScheme) && value.EgressKeyVersion != "" && value.ProxyVerifiedAt != "")
		validDetails = ok && value.AttemptNo > 0 && value.Result != "" && value.Stage != "" && validRoute
	case "owner_mutation_rejection":
		value, ok := event.Details.(OwnerMutationRejectionDetails)
		validDetails = ok && validOwnerMutationOperation(value.Operation) && validOwnerMutationReason(value.Reason)
	}
	if !validDetails {
		return nil, spec{}, errors.New("audit details do not match registry")
	}
	details, err := json.Marshal(event.Details)
	return details, eventSpec, err
}

func validJoinTargetStatus(value string) bool {
	switch value {
	case "pending", "available", "credential_invalid", "definitely_unavailable", "transient_failure", "unknown", "succeeded", "failed", "blocked":
		return true
	default:
		return false
	}
}

func validProbeStatus(value string) bool {
	switch value {
	case "available", "credential_invalid", "definitely_unavailable", "transient_failure", "unknown":
		return true
	default:
		return false
	}
}

func validFactor(value string) bool {
	return value == "totp" || value == "recovery_code"
}

func validRateLimitKind(value string) bool {
	return value == "" || value == "login" || value == "recovery"
}

func validSessionReason(eventType EventType, value string) bool {
	if eventType == SessionRotated {
		return value == "session_revocation" || value == "workspace_manual_verification"
	}
	return value == "logout" || value == "owner_request" || value == "rotation"
}

func validOwnerMutationOperation(value string) bool {
	switch value {
	case "mother_account.create", "mother_account.update", "workspace.create", "workspace.update", "binding.create", "workspace_read.create", "manual_verification.create", "target_account.create", "target_account.import", "target_account.update", "target_probe.create", "batch.create", "batch.update", "join.create", "join.reconcile":
		return true
	default:
		return false
	}
}

func validOwnerMutationReason(value string) bool {
	switch value {
	case "invalid_request", "version_mismatch", "conflict", "idempotency_conflict", "workspace_not_found", "target_not_found", "batch_not_found", "join_not_ready", "join_target_not_in_batch", "join_confirmation_required":
		return true
	default:
		return false
	}
}

func validProxyScheme(value string) bool {
	return value == "http" || value == "https" || value == "socks5" || value == "socks5h"
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
	if event.RetentionScopeID != "" {
		writeField(hash, []byte(event.RetentionScopeID))
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

func nullString(value string) interface{} {
	if value == "" {
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
