-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- This slice creates only the Owner/security tables needed by Ticket 03.
CREATE TABLE tsw_owners (
    id uuid CONSTRAINT tsw_owners_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    singleton boolean NOT NULL DEFAULT true CONSTRAINT tsw_owners_singleton_ck CHECK (singleton),
    username text NOT NULL CONSTRAINT tsw_owners_username_length_ck CHECK (length(username) BETWEEN 1 AND 254),
    password_hash text NOT NULL CONSTRAINT tsw_owners_password_hash_length_ck CHECK (length(password_hash) BETWEEN 1 AND 512),
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    totp_ciphertext bytea NOT NULL CONSTRAINT tsw_owners_totp_ciphertext_ck CHECK (octet_length(totp_ciphertext) >= 16),
    totp_nonce bytea NOT NULL CONSTRAINT tsw_owners_totp_nonce_ck CHECK (octet_length(totp_nonce) = 12),
    totp_key_version smallint NOT NULL CONSTRAINT tsw_owners_totp_key_version_ck CHECK (totp_key_version BETWEEN 1 AND 32767),
    auth_version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_owners_auth_version_ck CHECK (auth_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_owners_version_ck CHECK (version > 0),
    CONSTRAINT tsw_owners_singleton_uq UNIQUE (singleton),
    CONSTRAINT tsw_owners_username_uq UNIQUE (username)
);

CREATE TABLE tsw_owner_recovery_codes (
    id uuid CONSTRAINT tsw_owner_recovery_codes_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id uuid NOT NULL CONSTRAINT tsw_owner_recovery_codes_owner_fk REFERENCES tsw_owners(id) ON DELETE RESTRICT,
    code_hash bytea NOT NULL CONSTRAINT tsw_owner_recovery_codes_code_hash_ck CHECK (octet_length(code_hash) = 32),
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tsw_owner_recovery_codes_code_hash_uq UNIQUE (code_hash),
    CONSTRAINT tsw_owner_recovery_codes_used_at_ck CHECK (used_at IS NULL OR used_at >= created_at)
);
CREATE INDEX tsw_owner_recovery_codes_owner_used_idx ON tsw_owner_recovery_codes(owner_id, used_at);
CREATE INDEX tsw_owner_recovery_codes_used_retention_idx ON tsw_owner_recovery_codes(used_at) WHERE used_at IS NOT NULL;

CREATE TABLE tsw_owner_sessions (
    id uuid CONSTRAINT tsw_owner_sessions_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id uuid NOT NULL CONSTRAINT tsw_owner_sessions_owner_fk REFERENCES tsw_owners(id) ON DELETE RESTRICT,
    token_hash bytea NOT NULL CONSTRAINT tsw_owner_sessions_token_hash_ck CHECK (octet_length(token_hash) = 32),
    auth_version bigint NOT NULL CONSTRAINT tsw_owner_sessions_auth_version_ck CHECK (auth_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason text,
    CONSTRAINT tsw_owner_sessions_token_hash_uq UNIQUE (token_hash),
    CONSTRAINT tsw_owner_sessions_expiry_ck CHECK (last_seen_at >= created_at AND idle_expires_at > last_seen_at AND absolute_expires_at > created_at AND idle_expires_at <= absolute_expires_at),
    CONSTRAINT tsw_owner_sessions_revocation_ck CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);
CREATE INDEX tsw_owner_sessions_owner_active_idx ON tsw_owner_sessions(owner_id, last_seen_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX tsw_owner_sessions_expires_idx ON tsw_owner_sessions(idle_expires_at, absolute_expires_at) WHERE revoked_at IS NULL;

CREATE TABLE tsw_rate_limit_buckets (
    id uuid CONSTRAINT tsw_rate_limit_buckets_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CONSTRAINT tsw_rate_limit_buckets_kind_ck CHECK (kind IN ('login_account', 'login_ip', 'recovery_account', 'recovery_ip')),
    subject_hash bytea NOT NULL CONSTRAINT tsw_rate_limit_buckets_subject_hash_ck CHECK (octet_length(subject_hash) = 32),
    window_started_at timestamptz NOT NULL,
    window_ends_at timestamptz NOT NULL,
    count smallint NOT NULL DEFAULT 0 CONSTRAINT tsw_rate_limit_buckets_count_ck CHECK (count BETWEEN 0 AND 5),
    blocked_until timestamptz,
    expires_at timestamptz NOT NULL,
    CONSTRAINT tsw_rate_limit_buckets_window_uq UNIQUE (kind, subject_hash, window_started_at),
    CONSTRAINT tsw_rate_limit_buckets_window_ck CHECK (window_ends_at = window_started_at + interval '15 minutes'),
    CONSTRAINT tsw_rate_limit_buckets_block_ck CHECK (blocked_until IS NULL OR blocked_until <= window_ends_at + interval '15 minutes'),
    CONSTRAINT tsw_rate_limit_buckets_retention_ck CHECK (expires_at >= COALESCE(blocked_until, window_ends_at) AND expires_at <= COALESCE(blocked_until, window_ends_at) + interval '7 days')
);
CREATE INDEX tsw_rate_limit_buckets_lookup_idx ON tsw_rate_limit_buckets(kind, subject_hash, window_ends_at DESC);
CREATE INDEX tsw_rate_limit_buckets_expires_idx ON tsw_rate_limit_buckets(expires_at);

-- Event rows are generic, seven-day facts; event-specific fields are enforced by the typed registry.
CREATE TABLE tsw_audit_events (
    id uuid CONSTRAINT tsw_audit_events_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    event_key bytea NOT NULL CONSTRAINT tsw_audit_events_event_key_ck CHECK (octet_length(event_key) = 32),
    retention_scope_type text NOT NULL CONSTRAINT tsw_audit_events_scope_type_ck CHECK (length(retention_scope_type) BETWEEN 1 AND 64),
    retention_scope_id uuid NOT NULL,
    actor_type text NOT NULL CONSTRAINT tsw_audit_events_actor_type_ck CHECK (length(actor_type) BETWEEN 1 AND 64),
    owner_id uuid CONSTRAINT tsw_audit_events_owner_fk REFERENCES tsw_owners(id) ON DELETE RESTRICT,
    event_type text NOT NULL CONSTRAINT tsw_audit_events_event_type_ck CHECK (length(event_type) BETWEEN 1 AND 128),
    entity_type text NOT NULL CONSTRAINT tsw_audit_events_entity_type_ck CHECK (length(entity_type) BETWEEN 1 AND 64),
    entity_id uuid NOT NULL,
    outcome text NOT NULL CONSTRAINT tsw_audit_events_outcome_ck CHECK (length(outcome) BETWEEN 1 AND 64),
    correlation_id text NOT NULL CONSTRAINT tsw_audit_events_correlation_id_ck CHECK (length(correlation_id) BETWEEN 1 AND 128),
    source_fingerprint bytea CONSTRAINT tsw_audit_events_source_fingerprint_ck CHECK (source_fingerprint IS NULL OR octet_length(source_fingerprint) = 32),
    details jsonb NOT NULL DEFAULT '{}'::jsonb CONSTRAINT tsw_audit_events_details_ck CHECK (jsonb_typeof(details) = 'object'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT tsw_audit_events_event_key_uq UNIQUE (event_key),
    CONSTRAINT tsw_audit_events_retention_ck CHECK (expires_at >= occurred_at AND expires_at <= occurred_at + interval '7 days')
);
CREATE INDEX tsw_audit_events_scope_occurred_idx ON tsw_audit_events(retention_scope_type, retention_scope_id, occurred_at DESC);
CREATE INDEX tsw_audit_events_entity_occurred_idx ON tsw_audit_events(entity_type, entity_id, event_type, occurred_at DESC);
CREATE INDEX tsw_audit_events_correlation_idx ON tsw_audit_events(correlation_id);
CREATE INDEX tsw_audit_events_expires_idx ON tsw_audit_events(expires_at);

-- UPDATE is always forbidden; DELETE is reserved for retention cleanup after expires_at.
-- +goose StatementBegin
CREATE FUNCTION tsw_audit_events_append_only_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.expires_at <= now() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'tsw_audit_events is append-only until expiry';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_audit_events_append_only_trigger
    BEFORE UPDATE OR DELETE ON tsw_audit_events
    FOR EACH ROW EXECUTE FUNCTION tsw_audit_events_append_only_guard();

-- +goose Down
DROP TABLE tsw_audit_events;
DROP FUNCTION tsw_audit_events_append_only_guard();
DROP TABLE tsw_rate_limit_buckets;
DROP TABLE tsw_owner_sessions;
DROP TABLE tsw_owner_recovery_codes;
DROP TABLE tsw_owners;
