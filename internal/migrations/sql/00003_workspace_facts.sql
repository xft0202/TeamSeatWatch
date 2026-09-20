-- +goose Up
-- Ticket 04 adds only the eight platform-fact tables and the task columns needed
-- for Workspace reads. Later operation/target/OAuth foreign keys arrive with their owners.
CREATE TABLE tsw_mother_accounts (
    id uuid CONSTRAINT tsw_mother_accounts_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name text NOT NULL CONSTRAINT tsw_mother_accounts_display_name_ck CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
    platform_account_ref text CONSTRAINT tsw_mother_accounts_platform_ref_ck CHECK (platform_account_ref IS NULL OR length(platform_account_ref) BETWEEN 1 AND 255),
    status text NOT NULL DEFAULT 'active' CONSTRAINT tsw_mother_accounts_status_ck CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_mother_accounts_version_ck CHECK (version > 0),
    CONSTRAINT tsw_mother_accounts_platform_ref_uq UNIQUE (platform_account_ref)
);

CREATE TABLE tsw_mother_account_credentials (
    id uuid CONSTRAINT tsw_mother_account_credentials_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    mother_account_id uuid NOT NULL CONSTRAINT tsw_mother_account_credentials_account_fk REFERENCES tsw_mother_accounts(id) ON DELETE RESTRICT,
    login_identifier text NOT NULL CONSTRAINT tsw_mother_account_credentials_identifier_ck CHECK (length(login_identifier) BETWEEN 1 AND 254),
    identifier_hmac bytea NOT NULL CONSTRAINT tsw_mother_account_credentials_hmac_ck CHECK (octet_length(identifier_hmac) = 32),
    identifier_key_version smallint NOT NULL CONSTRAINT tsw_mother_account_credentials_key_version_ck CHECK (identifier_key_version > 0),
    password_secret bytea NOT NULL CONSTRAINT tsw_mother_account_credentials_password_ck CHECK (octet_length(password_secret) > 0),
    totp_secret bytea CONSTRAINT tsw_mother_account_credentials_totp_ck CHECK (totp_secret IS NULL OR octet_length(totp_secret) > 0),
    secret_revision bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_mother_account_credentials_revision_ck CHECK (secret_revision > 0),
    last_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_mother_account_credentials_version_ck CHECK (version > 0),
    CONSTRAINT tsw_mother_account_credentials_account_uq UNIQUE (mother_account_id),
    CONSTRAINT tsw_mother_account_credentials_identifier_uq UNIQUE (identifier_key_version, identifier_hmac)
);
CREATE INDEX tsw_mother_account_credentials_account_idx ON tsw_mother_account_credentials(mother_account_id);

-- Credential rows are mutable secrets, not immutable facts. Keep them behind the
-- control role and require optimistic versioning for rotations.
-- +goose StatementBegin
CREATE FUNCTION tsw_mother_account_credentials_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.mother_account_id <> OLD.mother_account_id OR NEW.login_identifier <> OLD.login_identifier OR
       NEW.identifier_hmac <> OLD.identifier_hmac OR NEW.identifier_key_version <> OLD.identifier_key_version OR
       NEW.secret_revision <> OLD.secret_revision + 1 OR NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'credential updates require a single versioned secret rotation';
    END IF;
    IF NEW.password_secret = OLD.password_secret AND NEW.totp_secret IS NOT DISTINCT FROM OLD.totp_secret THEN
        RAISE EXCEPTION 'credential rotation must replace secret material';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_mother_account_credentials_version_trigger BEFORE UPDATE ON tsw_mother_account_credentials FOR EACH ROW EXECUTE FUNCTION tsw_mother_account_credentials_version_guard();

-- PUBLIC is defense in depth. Deployments grant the control role the minimal
-- table privileges explicitly; no other runtime role receives credential access.
REVOKE ALL ON tsw_mother_account_credentials FROM PUBLIC;

CREATE TABLE tsw_workspaces (
    id uuid CONSTRAINT tsw_workspaces_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_workspace_id text NOT NULL CONSTRAINT tsw_workspaces_platform_id_ck CHECK (length(platform_workspace_id) BETWEEN 1 AND 255),
    display_name text NOT NULL CONSTRAINT tsw_workspaces_display_name_ck CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_workspaces_version_ck CHECK (version > 0),
    CONSTRAINT tsw_workspaces_platform_id_uq UNIQUE (platform_workspace_id)
);

CREATE TABLE tsw_mother_workspace_bindings (
    id uuid CONSTRAINT tsw_mother_workspace_bindings_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    mother_account_id uuid NOT NULL CONSTRAINT tsw_mother_workspace_bindings_account_fk REFERENCES tsw_mother_accounts(id) ON DELETE RESTRICT,
    workspace_id uuid NOT NULL CONSTRAINT tsw_mother_workspace_bindings_workspace_fk REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active' CONSTRAINT tsw_mother_workspace_bindings_status_ck CHECK (status IN ('active', 'ended')),
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_mother_workspace_bindings_version_ck CHECK (version > 0),
    CONSTRAINT tsw_mother_workspace_bindings_period_ck CHECK ((status = 'active' AND ended_at IS NULL) OR (status = 'ended' AND ended_at IS NOT NULL AND ended_at >= started_at))
);
CREATE UNIQUE INDEX tsw_mother_workspace_bindings_current_uq ON tsw_mother_workspace_bindings(workspace_id) WHERE ended_at IS NULL;
CREATE INDEX tsw_mother_workspace_bindings_account_idx ON tsw_mother_workspace_bindings(mother_account_id, started_at DESC);
CREATE INDEX tsw_mother_workspace_bindings_workspace_idx ON tsw_mother_workspace_bindings(workspace_id, started_at DESC);

CREATE TABLE tsw_workspace_observations (
    id uuid CONSTRAINT tsw_workspace_observations_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL CONSTRAINT tsw_workspace_observations_workspace_fk REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    observation_type text NOT NULL CONSTRAINT tsw_workspace_observations_type_ck CHECK (observation_type IN ('exchange', 'subscription', 'capacity', 'join', 'members', 'pending_invites', 'read_error', 'manual_verification')),
    source_kind text NOT NULL CONSTRAINT tsw_workspace_observations_source_kind_ck CHECK (source_kind IN ('platform', 'owner')),
    owner_id uuid CONSTRAINT tsw_workspace_observations_owner_fk REFERENCES tsw_owners(id) ON DELETE RESTRICT,
    source_endpoint text NOT NULL CONSTRAINT tsw_workspace_observations_endpoint_ck CHECK (source_endpoint IN ('workspace_exchange', 'workspace_subscription', 'seat_counter', 'workspace_join', 'workspace_members', 'pending_invites', 'platform_ui', 'platform_subscription_page')),
    observed_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    outcome_code text NOT NULL CONSTRAINT tsw_workspace_observations_outcome_ck CHECK (outcome_code IN ('operational', 'deactivated_workspace', 'workspace_not_found', 'unauthorized', 'forbidden', 'rate_limited', 'server_error', 'timeout', 'network_error', 'incomplete', 'manual_deactivated', 'manual_recovered', 'manual_expiration_corrected')),
    active_until timestamptz,
    seat_limit integer CONSTRAINT tsw_workspace_observations_seat_limit_ck CHECK (seat_limit IS NULL OR seat_limit >= 0),
    member_count integer CONSTRAINT tsw_workspace_observations_member_count_ck CHECK (member_count IS NULL OR member_count >= 0),
    pending_invite_count integer CONSTRAINT tsw_workspace_observations_pending_count_ck CHECK (pending_invite_count IS NULL OR pending_invite_count >= 0),
    manual_note text CONSTRAINT tsw_workspace_observations_manual_note_ck CHECK (manual_note IS NULL OR length(manual_note) BETWEEN 1 AND 500),
    payload_hash bytea CONSTRAINT tsw_workspace_observations_payload_hash_ck CHECK (payload_hash IS NULL OR octet_length(payload_hash) = 32),
    CONSTRAINT tsw_workspace_observations_expiry_ck CHECK (expires_at > observed_at AND expires_at <= observed_at + interval '7 days'),
    CONSTRAINT tsw_workspace_observations_shape_ck CHECK (
        (observation_type = 'subscription' AND source_kind = 'platform' AND owner_id IS NULL AND source_endpoint = 'workspace_subscription' AND manual_note IS NULL AND seat_limit IS NULL AND member_count IS NULL AND pending_invite_count IS NULL AND ((outcome_code = 'operational' AND active_until IS NOT NULL) OR (outcome_code <> 'operational' AND active_until IS NULL)))
        OR (observation_type = 'capacity' AND source_kind = 'platform' AND owner_id IS NULL AND source_endpoint = 'seat_counter' AND active_until IS NULL AND pending_invite_count IS NULL AND manual_note IS NULL AND ((outcome_code = 'operational' AND seat_limit IS NOT NULL AND member_count IS NOT NULL) OR (outcome_code <> 'operational' AND seat_limit IS NULL AND member_count IS NULL)))
        OR (observation_type = 'join' AND source_kind = 'platform' AND owner_id IS NULL AND source_endpoint = 'workspace_join' AND active_until IS NULL AND seat_limit IS NULL AND member_count IS NULL AND pending_invite_count IS NULL AND manual_note IS NULL)
        OR (observation_type = 'members' AND source_kind = 'platform' AND owner_id IS NULL AND source_endpoint = 'workspace_members' AND outcome_code IN ('operational', 'deactivated_workspace', 'workspace_not_found') AND active_until IS NULL AND seat_limit IS NULL AND member_count IS NULL AND pending_invite_count IS NULL AND manual_note IS NULL)
        OR (observation_type = 'pending_invites' AND source_kind = 'platform' AND owner_id IS NULL AND source_endpoint = 'pending_invites' AND active_until IS NULL AND seat_limit IS NULL AND member_count IS NULL AND manual_note IS NULL AND ((outcome_code = 'operational' AND pending_invite_count IS NOT NULL) OR (outcome_code <> 'operational' AND pending_invite_count IS NULL)))
        OR (observation_type = 'exchange' AND source_kind = 'platform' AND owner_id IS NULL AND source_endpoint = 'workspace_exchange' AND active_until IS NULL AND seat_limit IS NULL AND member_count IS NULL AND pending_invite_count IS NULL AND manual_note IS NULL)
        OR (observation_type = 'read_error' AND source_kind = 'platform' AND owner_id IS NULL AND source_endpoint = 'workspace_members' AND outcome_code IN ('unauthorized', 'forbidden', 'rate_limited', 'server_error', 'timeout', 'network_error', 'incomplete') AND active_until IS NULL AND seat_limit IS NULL AND member_count IS NULL AND pending_invite_count IS NULL AND manual_note IS NULL)
        OR (observation_type = 'manual_verification' AND source_kind = 'owner' AND owner_id IS NOT NULL AND source_endpoint IN ('platform_ui', 'platform_subscription_page') AND ((outcome_code IN ('manual_deactivated', 'manual_recovered') AND active_until IS NULL) OR (outcome_code = 'manual_expiration_corrected' AND active_until IS NOT NULL)) AND seat_limit IS NULL AND member_count IS NULL AND pending_invite_count IS NULL AND payload_hash IS NULL)
    )
);
CREATE INDEX tsw_workspace_observations_owner_idx ON tsw_workspace_observations(owner_id) WHERE owner_id IS NOT NULL;
CREATE INDEX tsw_workspace_observations_latest_idx ON tsw_workspace_observations(workspace_id, observation_type, observed_at DESC);
CREATE INDEX tsw_workspace_observations_expires_idx ON tsw_workspace_observations(expires_at);

CREATE TABLE tsw_workspace_member_snapshots (
    id uuid CONSTRAINT tsw_workspace_member_snapshots_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL CONSTRAINT tsw_workspace_member_snapshots_workspace_fk REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    source_endpoint text NOT NULL CONSTRAINT tsw_workspace_member_snapshots_endpoint_ck CHECK (source_endpoint = 'workspace_members'),
    observed_at timestamptz NOT NULL,
    completeness text NOT NULL CONSTRAINT tsw_workspace_member_snapshots_completeness_ck CHECK (completeness IN ('complete', 'partial', 'unknown')),
    declared_member_count integer CONSTRAINT tsw_workspace_member_snapshots_member_count_ck CHECK (declared_member_count IS NULL OR declared_member_count >= 0),
    pending_invite_count integer CONSTRAINT tsw_workspace_member_snapshots_pending_count_ck CHECK (pending_invite_count IS NULL OR pending_invite_count >= 0),
    payload_hash bytea NOT NULL CONSTRAINT tsw_workspace_member_snapshots_payload_hash_ck CHECK (octet_length(payload_hash) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tsw_workspace_member_snapshots_expiry_ck CHECK (expires_at > observed_at AND expires_at <= observed_at + interval '7 days')
);
CREATE INDEX tsw_workspace_member_snapshots_latest_idx ON tsw_workspace_member_snapshots(workspace_id, observed_at DESC);
CREATE INDEX tsw_workspace_member_snapshots_expires_idx ON tsw_workspace_member_snapshots(expires_at);

CREATE TABLE tsw_workspace_member_snapshot_entries (
    id uuid CONSTRAINT tsw_workspace_member_snapshot_entries_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id uuid NOT NULL CONSTRAINT tsw_workspace_member_snapshot_entries_snapshot_fk REFERENCES tsw_workspace_member_snapshots(id) ON DELETE CASCADE,
    entry_kind text NOT NULL CONSTRAINT tsw_workspace_member_snapshot_entries_kind_ck CHECK (entry_kind IN ('member', 'pending_invite')),
    platform_member_id text,
    member_identifier text NOT NULL CONSTRAINT tsw_workspace_member_snapshot_entries_identifier_ck CHECK (length(member_identifier) BETWEEN 1 AND 254),
    identifier_hmac bytea NOT NULL CONSTRAINT tsw_workspace_member_snapshot_entries_hmac_ck CHECK (octet_length(identifier_hmac) = 32),
    identifier_key_version smallint NOT NULL CONSTRAINT tsw_workspace_member_snapshot_entries_key_version_ck CHECK (identifier_key_version > 0),
    platform_status text NOT NULL CONSTRAINT tsw_workspace_member_snapshot_entries_status_ck CHECK (length(platform_status) BETWEEN 1 AND 64),
    platform_role text CONSTRAINT tsw_workspace_member_snapshot_entries_role_ck CHECK (platform_role IS NULL OR length(platform_role) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tsw_workspace_member_snapshot_entries_kind_fields_ck CHECK ((entry_kind = 'member' AND platform_member_id IS NOT NULL) OR (entry_kind = 'pending_invite' AND platform_member_id IS NULL)),
    CONSTRAINT tsw_workspace_member_snapshot_entries_identifier_uq UNIQUE (snapshot_id, entry_kind, identifier_key_version, identifier_hmac)
);
CREATE INDEX tsw_workspace_member_snapshot_entries_snapshot_idx ON tsw_workspace_member_snapshot_entries(snapshot_id);
CREATE INDEX tsw_workspace_member_snapshot_entries_member_idx ON tsw_workspace_member_snapshot_entries(platform_member_id) WHERE platform_member_id IS NOT NULL;
CREATE INDEX tsw_workspace_member_snapshot_entries_hmac_idx ON tsw_workspace_member_snapshot_entries(identifier_key_version, identifier_hmac);

CREATE TABLE tsw_workspace_projections (
    workspace_id uuid CONSTRAINT tsw_workspace_projections_pk PRIMARY KEY CONSTRAINT tsw_workspace_projections_workspace_fk REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    operational_state text NOT NULL DEFAULT 'unknown' CONSTRAINT tsw_workspace_projections_state_ck CHECK (operational_state IN ('unknown', 'operational', 'deactivated', 'not_found')),
    conclusion_observation_id uuid CONSTRAINT tsw_workspace_projections_conclusion_fk REFERENCES tsw_workspace_observations(id) ON DELETE RESTRICT,
    capacity_observation_id uuid CONSTRAINT tsw_workspace_projections_capacity_fk REFERENCES tsw_workspace_observations(id) ON DELETE RESTRICT,
    latest_snapshot_id uuid CONSTRAINT tsw_workspace_projections_snapshot_fk REFERENCES tsw_workspace_member_snapshots(id) ON DELETE RESTRICT,
    active_until timestamptz,
    seat_limit integer CONSTRAINT tsw_workspace_projections_seat_limit_ck CHECK (seat_limit IS NULL OR seat_limit >= 0),
    member_count integer CONSTRAINT tsw_workspace_projections_member_count_ck CHECK (member_count IS NULL OR member_count >= 0),
    pending_invite_count integer CONSTRAINT tsw_workspace_projections_pending_count_ck CHECK (pending_invite_count IS NULL OR pending_invite_count >= 0),
    evidence_expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_workspace_projections_version_ck CHECK (version > 0),
    CONSTRAINT tsw_workspace_projections_evidence_ck CHECK ((operational_state = 'unknown' AND conclusion_observation_id IS NULL AND evidence_expires_at IS NULL) OR (operational_state <> 'unknown' AND conclusion_observation_id IS NOT NULL AND evidence_expires_at IS NOT NULL)),
    CONSTRAINT tsw_workspace_projections_capacity_ck CHECK ((capacity_observation_id IS NULL AND seat_limit IS NULL AND member_count IS NULL) OR (capacity_observation_id IS NOT NULL AND seat_limit IS NOT NULL AND member_count IS NOT NULL))
);
CREATE INDEX tsw_workspace_projections_state_idx ON tsw_workspace_projections(operational_state, updated_at DESC);
CREATE INDEX tsw_workspace_projections_attention_idx ON tsw_workspace_projections(evidence_expires_at, updated_at DESC);

CREATE TABLE tsw_tasks (
    id uuid CONSTRAINT tsw_tasks_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_task_id uuid CONSTRAINT tsw_tasks_parent_fk REFERENCES tsw_tasks(id) ON DELETE RESTRICT,
    workspace_id uuid NOT NULL CONSTRAINT tsw_tasks_workspace_fk REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    task_type text NOT NULL CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read', 'workspace_fact_cleanup')),
    dedupe_key text NOT NULL CONSTRAINT tsw_tasks_dedupe_key_ck CHECK (length(dedupe_key) BETWEEN 1 AND 128),
    input_snapshot jsonb NOT NULL CONSTRAINT tsw_tasks_input_ck CHECK (jsonb_typeof(input_snapshot) = 'object'),
    status text NOT NULL DEFAULT 'queued' CONSTRAINT tsw_tasks_status_ck CHECK (status IN ('queued', 'running', 'retry_wait', 'succeeded', 'failed', 'interrupted')),
    priority smallint NOT NULL DEFAULT 0 CONSTRAINT tsw_tasks_priority_ck CHECK (priority BETWEEN -100 AND 100),
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_owner text,
    lease_token uuid,
    lease_expires_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0 CONSTRAINT tsw_tasks_attempt_count_ck CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL DEFAULT 3 CONSTRAINT tsw_tasks_max_attempts_ck CHECK (max_attempts BETWEEN 1 AND 20),
    correlation_id text NOT NULL CONSTRAINT tsw_tasks_correlation_ck CHECK (length(correlation_id) BETWEEN 1 AND 128),
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_tasks_version_ck CHECK (version > 0),
    CONSTRAINT tsw_tasks_dedupe_uq UNIQUE (task_type, dedupe_key),
    CONSTRAINT tsw_tasks_lease_ck CHECK ((status = 'running' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND finished_at IS NULL) OR (status <> 'running' AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)),
    CONSTRAINT tsw_tasks_finished_ck CHECK ((status IN ('succeeded', 'failed', 'interrupted')) = (finished_at IS NOT NULL)),
    CONSTRAINT tsw_tasks_attempts_ck CHECK (attempt_count <= max_attempts)
);
CREATE INDEX tsw_tasks_workspace_idx ON tsw_tasks(workspace_id, created_at DESC);
CREATE INDEX tsw_tasks_runnable_idx ON tsw_tasks(priority DESC, available_at, created_at) WHERE status IN ('queued', 'retry_wait');
CREATE INDEX tsw_tasks_running_lease_idx ON tsw_tasks(lease_expires_at) WHERE status = 'running';
CREATE UNIQUE INDEX tsw_tasks_active_cleanup_uq ON tsw_tasks(workspace_id) WHERE task_type = 'workspace_fact_cleanup' AND status IN ('queued', 'retry_wait', 'running');

CREATE TABLE tsw_task_attempts (
    id uuid CONSTRAINT tsw_task_attempts_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id uuid NOT NULL CONSTRAINT tsw_task_attempts_task_fk REFERENCES tsw_tasks(id) ON DELETE CASCADE,
    attempt_no integer NOT NULL CONSTRAINT tsw_task_attempts_attempt_no_ck CHECK (attempt_no > 0),
    lease_token uuid NOT NULL,
    route_mode text NOT NULL CONSTRAINT tsw_task_attempts_route_mode_ck CHECK (route_mode IN ('direct', 'required')),
    proxy_scheme text CONSTRAINT tsw_task_attempts_proxy_scheme_ck CHECK (proxy_scheme IS NULL OR proxy_scheme IN ('http', 'https', 'socks5', 'socks5h')),
    egress_key_version text CONSTRAINT tsw_task_attempts_key_version_ck CHECK (egress_key_version IS NULL OR length(egress_key_version) BETWEEN 1 AND 64),
    egress_fingerprint bytea CONSTRAINT tsw_task_attempts_fingerprint_ck CHECK (egress_fingerprint IS NULL OR octet_length(egress_fingerprint) = 32),
    proxy_verified_at timestamptz,
    proxy_stage text CONSTRAINT tsw_task_attempts_proxy_stage_ck CHECK (proxy_stage IS NULL OR proxy_stage IN ('admitted', 'remeasured')),
    started_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tsw_task_attempts_task_no_uq UNIQUE (task_id, attempt_no),
    CONSTRAINT tsw_task_attempts_route_ck CHECK ((route_mode = 'direct' AND proxy_scheme IS NULL AND egress_key_version IS NULL AND egress_fingerprint IS NULL AND proxy_verified_at IS NULL AND proxy_stage IS NULL) OR (route_mode = 'required' AND proxy_scheme IS NOT NULL AND egress_key_version IS NOT NULL AND egress_fingerprint IS NOT NULL AND proxy_verified_at IS NOT NULL AND proxy_stage IS NOT NULL))
);
CREATE INDEX tsw_task_attempts_task_idx ON tsw_task_attempts(task_id, attempt_no DESC);
CREATE INDEX tsw_task_attempts_fingerprint_idx ON tsw_task_attempts(egress_fingerprint) WHERE egress_fingerprint IS NOT NULL;

-- Facts and attempt starts never change. Expired fact deletion is the only permitted
-- mutation and projection references force callers to recompute first.
-- +goose StatementBegin
CREATE FUNCTION tsw_workspace_fact_append_only_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.expires_at <= now() THEN RETURN OLD; END IF;
    RAISE EXCEPTION '% is append-only until expiry', TG_TABLE_NAME;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_workspace_observations_append_only_trigger BEFORE UPDATE OR DELETE ON tsw_workspace_observations FOR EACH ROW EXECUTE FUNCTION tsw_workspace_fact_append_only_guard();
CREATE TRIGGER tsw_workspace_member_snapshots_append_only_trigger BEFORE UPDATE OR DELETE ON tsw_workspace_member_snapshots FOR EACH ROW EXECUTE FUNCTION tsw_workspace_fact_append_only_guard();

-- +goose StatementBegin
CREATE FUNCTION tsw_workspace_snapshot_entries_append_only_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND (pg_trigger_depth() > 1 OR EXISTS (SELECT 1 FROM tsw_workspace_member_snapshots WHERE id = OLD.snapshot_id AND expires_at <= now())) THEN RETURN OLD; END IF;
    RAISE EXCEPTION 'tsw_workspace_member_snapshot_entries is append-only until snapshot expiry';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_workspace_member_snapshot_entries_append_only_trigger BEFORE UPDATE OR DELETE ON tsw_workspace_member_snapshot_entries FOR EACH ROW EXECUTE FUNCTION tsw_workspace_snapshot_entries_append_only_guard();

-- +goose StatementBegin
CREATE FUNCTION tsw_task_attempts_append_only_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND (pg_trigger_depth() > 1 OR EXISTS (SELECT 1 FROM tsw_tasks WHERE id = OLD.task_id AND finished_at <= now() - interval '7 days')) THEN RETURN OLD; END IF;
    RAISE EXCEPTION 'tsw_task_attempts is append-only until retention expiry';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_task_attempts_append_only_trigger BEFORE UPDATE OR DELETE ON tsw_task_attempts FOR EACH ROW EXECUTE FUNCTION tsw_task_attempts_append_only_guard();

-- +goose Down
DROP TABLE tsw_task_attempts;
DROP FUNCTION tsw_task_attempts_append_only_guard();
DROP TABLE tsw_tasks;
DROP TABLE tsw_workspace_projections;
DROP TABLE tsw_workspace_member_snapshot_entries;
DROP FUNCTION tsw_workspace_snapshot_entries_append_only_guard();
DROP TABLE tsw_workspace_member_snapshots;
DROP TABLE tsw_workspace_observations;
DROP FUNCTION tsw_workspace_fact_append_only_guard();
DROP TABLE tsw_mother_workspace_bindings;
DROP TABLE tsw_workspaces;
DROP TABLE tsw_mother_account_credentials;
DROP FUNCTION tsw_mother_account_credentials_version_guard();
DROP TABLE tsw_mother_accounts;
