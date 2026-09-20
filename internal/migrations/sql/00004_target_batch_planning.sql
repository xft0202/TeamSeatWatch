-- +goose Up
-- Ticket 05 adds target accounts, versioned credentials, planning records and
-- the target-account subject for the existing durable task queue.
CREATE TABLE tsw_target_accounts (
    id uuid CONSTRAINT tsw_target_accounts_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier text NOT NULL CONSTRAINT tsw_target_accounts_identifier_ck CHECK (length(identifier) BETWEEN 1 AND 254),
    identifier_hmac bytea NOT NULL CONSTRAINT tsw_target_accounts_hmac_ck CHECK (octet_length(identifier_hmac) = 32),
    identifier_key_version smallint NOT NULL CONSTRAINT tsw_target_accounts_key_version_ck CHECK (identifier_key_version > 0),
    display_label text NOT NULL CONSTRAINT tsw_target_accounts_display_label_ck CHECK (length(btrim(display_label)) BETWEEN 1 AND 120),
    status text NOT NULL DEFAULT 'active' CONSTRAINT tsw_target_accounts_status_ck CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_target_accounts_version_ck CHECK (version > 0),
    CONSTRAINT tsw_target_accounts_identifier_uq UNIQUE (identifier_key_version, identifier_hmac)
);
CREATE INDEX tsw_target_accounts_created_idx ON tsw_target_accounts(created_at DESC);
CREATE INDEX tsw_target_accounts_status_idx ON tsw_target_accounts(status, created_at DESC);

CREATE TABLE tsw_target_credentials (
    id uuid CONSTRAINT tsw_target_credentials_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    target_account_id uuid NOT NULL CONSTRAINT tsw_target_credentials_account_fk REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT,
    password_secret bytea NOT NULL CONSTRAINT tsw_target_credentials_password_ck CHECK (octet_length(password_secret) > 0),
    totp_secret bytea CONSTRAINT tsw_target_credentials_totp_ck CHECK (totp_secret IS NULL OR octet_length(totp_secret) > 0),
    recovery_secret bytea CONSTRAINT tsw_target_credentials_recovery_ck CHECK (recovery_secret IS NULL OR octet_length(recovery_secret) > 0),
    platform_subject_id text CONSTRAINT tsw_target_credentials_subject_ck CHECK (platform_subject_id IS NULL OR length(platform_subject_id) BETWEEN 1 AND 255),
    secret_revision bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_target_credentials_secret_revision_ck CHECK (secret_revision > 0),
    latest_probe_status text CONSTRAINT tsw_target_credentials_probe_status_ck CHECK (latest_probe_status IS NULL OR latest_probe_status IN ('available', 'credential_invalid', 'definitely_unavailable', 'transient_failure', 'unknown')),
    latest_probe_http_status integer CONSTRAINT tsw_target_credentials_probe_http_status_ck CHECK (latest_probe_http_status IS NULL OR latest_probe_http_status BETWEEN 100 AND 599),
    latest_probe_error_code text CONSTRAINT tsw_target_credentials_probe_error_ck CHECK (latest_probe_error_code IS NULL OR length(latest_probe_error_code) BETWEEN 1 AND 128),
    latest_probe_endpoint_key text CONSTRAINT tsw_target_credentials_probe_endpoint_ck CHECK (latest_probe_endpoint_key IS NULL OR latest_probe_endpoint_key = 'account_usage'),
    latest_probe_origin text CONSTRAINT tsw_target_credentials_probe_origin_ck CHECK (latest_probe_origin IS NULL OR latest_probe_origin IN ('worker', 'owner')),
    latest_probed_at timestamptz,
    last_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_target_credentials_version_ck CHECK (version > 0),
    CONSTRAINT tsw_target_credentials_account_uq UNIQUE (target_account_id),
    CONSTRAINT tsw_target_credentials_probe_shape_ck CHECK (
        (latest_probe_status IS NULL AND latest_probe_http_status IS NULL AND latest_probe_error_code IS NULL AND latest_probe_endpoint_key IS NULL AND latest_probe_origin IS NULL AND latest_probed_at IS NULL AND last_verified_at IS NULL)
        OR (latest_probe_status IS NOT NULL AND latest_probe_endpoint_key = 'account_usage' AND latest_probe_origin IS NOT NULL AND latest_probed_at IS NOT NULL AND (last_verified_at IS NULL OR last_verified_at <= latest_probed_at))
    )
);
CREATE INDEX tsw_target_credentials_probe_idx ON tsw_target_credentials(latest_probe_status, latest_probed_at DESC);
REVOKE ALL ON tsw_target_credentials FROM PUBLIC;

-- Secret revisions and probe snapshots share one mutable row but are still
-- versioned: a rotation advances secret_revision; a probe advances version only.
-- +goose StatementBegin
CREATE FUNCTION tsw_target_credentials_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    rotated boolean;
BEGIN
    IF NEW.target_account_id <> OLD.target_account_id OR NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'target credential updates require a single version step';
    END IF;
    rotated := NEW.password_secret <> OLD.password_secret OR
        NEW.totp_secret IS DISTINCT FROM OLD.totp_secret OR
        NEW.recovery_secret IS DISTINCT FROM OLD.recovery_secret;
    IF rotated THEN
        IF NEW.secret_revision <> OLD.secret_revision + 1 THEN
            RAISE EXCEPTION 'target credential rotation requires a secret revision step';
        END IF;
    ELSIF NEW.secret_revision <> OLD.secret_revision THEN
        RAISE EXCEPTION 'target credential evidence updates cannot change secret revision';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_target_credentials_version_trigger BEFORE UPDATE ON tsw_target_credentials FOR EACH ROW EXECUTE FUNCTION tsw_target_credentials_version_guard();

CREATE TABLE tsw_batches (
    id uuid CONSTRAINT tsw_batches_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    binding_id uuid NOT NULL CONSTRAINT tsw_batches_binding_fk REFERENCES tsw_mother_workspace_bindings(id) ON DELETE RESTRICT,
    sequence_no bigint NOT NULL CONSTRAINT tsw_batches_sequence_ck CHECK (sequence_no > 0),
    status text NOT NULL DEFAULT 'planned' CONSTRAINT tsw_batches_status_ck CHECK (status IN ('draft', 'planned', 'joining', 'serving', 'removing', 'ended')),
    planned_at timestamptz NOT NULL,
    service_started_at timestamptz,
    service_ended_at timestamptz,
    blocking_reason text CONSTRAINT tsw_batches_blocking_reason_ck CHECK (blocking_reason IS NULL OR length(blocking_reason) BETWEEN 1 AND 255),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_batches_version_ck CHECK (version > 0),
    CONSTRAINT tsw_batches_sequence_uq UNIQUE (binding_id, sequence_no),
    CONSTRAINT tsw_batches_dates_ck CHECK ((service_started_at IS NULL OR service_started_at >= created_at) AND (service_ended_at IS NULL OR service_started_at IS NOT NULL AND service_ended_at >= service_started_at))
);
CREATE UNIQUE INDEX tsw_batches_active_binding_uq ON tsw_batches(binding_id) WHERE status IN ('joining', 'serving', 'removing');
CREATE INDEX tsw_batches_binding_planned_idx ON tsw_batches(binding_id, planned_at DESC);
CREATE INDEX tsw_batches_status_idx ON tsw_batches(status, planned_at);

CREATE TABLE tsw_batch_targets (
    id uuid CONSTRAINT tsw_batch_targets_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id uuid NOT NULL CONSTRAINT tsw_batch_targets_batch_fk REFERENCES tsw_batches(id) ON DELETE CASCADE,
    target_account_id uuid NOT NULL CONSTRAINT tsw_batch_targets_target_fk REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT,
    ordinal integer NOT NULL CONSTRAINT tsw_batch_targets_ordinal_ck CHECK (ordinal > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tsw_batch_targets_target_uq UNIQUE (batch_id, target_account_id),
    CONSTRAINT tsw_batch_targets_ordinal_uq UNIQUE (batch_id, ordinal)
);
CREATE INDEX tsw_batch_targets_batch_idx ON tsw_batch_targets(batch_id, ordinal);
CREATE INDEX tsw_batch_targets_target_idx ON tsw_batch_targets(target_account_id, created_at DESC);

ALTER TABLE tsw_tasks ALTER COLUMN workspace_id DROP NOT NULL;
ALTER TABLE tsw_tasks ADD COLUMN target_account_id uuid CONSTRAINT tsw_tasks_target_account_fk REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read', 'workspace_fact_cleanup', 'target_account_probe'));
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read', 'workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL)
);
CREATE INDEX tsw_tasks_target_idx ON tsw_tasks(target_account_id, created_at DESC) WHERE target_account_id IS NOT NULL;

-- +goose Down
DROP INDEX tsw_tasks_target_idx;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks DROP COLUMN target_account_id;
ALTER TABLE tsw_tasks ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read', 'workspace_fact_cleanup'));
DROP TABLE tsw_batch_targets;
DROP TABLE tsw_batches;
DROP TRIGGER tsw_target_credentials_version_trigger ON tsw_target_credentials;
DROP FUNCTION tsw_target_credentials_version_guard();
DROP TABLE tsw_target_credentials;
DROP TABLE tsw_target_accounts;
