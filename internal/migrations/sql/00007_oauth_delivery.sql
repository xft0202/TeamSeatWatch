-- +goose Up
-- Ticket 08 adds relationship-scoped OAuth delivery and browser-activated cards.
-- OAuth secrets stay in the control-service database; public access is added by Ticket 09.
CREATE TABLE tsw_oauth_assets (
    id uuid CONSTRAINT tsw_oauth_assets_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_id uuid NOT NULL CONSTRAINT tsw_oauth_assets_membership_fk REFERENCES tsw_batch_memberships(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'pending' CONSTRAINT tsw_oauth_assets_status_ck CHECK (status IN ('pending','generating','ready','unavailable')),
    current_generation bigint NOT NULL DEFAULT 0 CONSTRAINT tsw_oauth_assets_generation_ck CHECK (current_generation >= 0),
    current_attempt_id uuid,
    current_delivery_version_id uuid,
    platform_subject_id text CONSTRAINT tsw_oauth_assets_subject_ck CHECK (platform_subject_id IS NULL OR length(platform_subject_id) BETWEEN 1 AND 255),
    liveness_status text CONSTRAINT tsw_oauth_assets_liveness_ck CHECK (liveness_status IS NULL OR liveness_status IN ('ok','auth_error','deactivated_workspace','rate_limited','transient_failure','unknown')),
    liveness_http_status integer CONSTRAINT tsw_oauth_assets_liveness_http_ck CHECK (liveness_http_status IS NULL OR liveness_http_status BETWEEN 100 AND 599),
    liveness_error_code text CONSTRAINT tsw_oauth_assets_liveness_error_ck CHECK (liveness_error_code IS NULL OR length(liveness_error_code) BETWEEN 1 AND 128),
    liveness_origin text CONSTRAINT tsw_oauth_assets_liveness_origin_ck CHECK (liveness_origin IS NULL OR liveness_origin IN ('generation','scheduled','owner')),
    probed_at timestamptz,
    unavailable_reason text CONSTRAINT tsw_oauth_assets_unavailable_reason_ck CHECK (unavailable_reason IS NULL OR length(unavailable_reason) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_oauth_assets_version_ck CHECK (version > 0),
    CONSTRAINT tsw_oauth_assets_membership_uq UNIQUE (membership_id)
);
CREATE INDEX tsw_oauth_assets_status_idx ON tsw_oauth_assets(status, updated_at DESC);

CREATE TABLE tsw_delivery_versions (
    id uuid CONSTRAINT tsw_delivery_versions_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    oauth_asset_id uuid NOT NULL CONSTRAINT tsw_delivery_versions_asset_fk REFERENCES tsw_oauth_assets(id) ON DELETE CASCADE,
    generation bigint NOT NULL CONSTRAINT tsw_delivery_versions_generation_ck CHECK (generation > 0),
    payload jsonb NOT NULL CONSTRAINT tsw_delivery_versions_payload_ck CHECK (jsonb_typeof(payload) = 'object'),
    payload_sha256 bytea NOT NULL CONSTRAINT tsw_delivery_versions_hash_ck CHECK (octet_length(payload_sha256) = 32),
    validated_platform_subject_id text NOT NULL CONSTRAINT tsw_delivery_versions_subject_ck CHECK (length(validated_platform_subject_id) BETWEEN 1 AND 255),
    validated_workspace_id uuid NOT NULL CONSTRAINT tsw_delivery_versions_workspace_fk REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tsw_delivery_versions_asset_generation_uq UNIQUE (oauth_asset_id, generation),
    CONSTRAINT tsw_delivery_versions_id_asset_uq UNIQUE (id, oauth_asset_id)
);
REVOKE UPDATE ON tsw_delivery_versions FROM PUBLIC;
-- Delivery payloads are the immutable source for published OAuth versions.
-- Revoke is defense in depth; the trigger also protects the table owner path.
-- +goose StatementBegin
CREATE FUNCTION tsw_delivery_versions_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'delivery versions are immutable';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_delivery_versions_immutable_trigger
    BEFORE UPDATE OR DELETE ON tsw_delivery_versions
    FOR EACH ROW EXECUTE FUNCTION tsw_delivery_versions_immutable();
CREATE INDEX tsw_delivery_versions_asset_idx ON tsw_delivery_versions(oauth_asset_id, created_at DESC);

ALTER TABLE tsw_tasks
    ADD COLUMN oauth_asset_id uuid CONSTRAINT tsw_tasks_oauth_asset_fk REFERENCES tsw_oauth_assets(id) ON DELETE RESTRICT;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read','workspace_fact_cleanup','target_account_probe','join','join_reconcile','oauth_generate','oauth_probe'));
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read','workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('join','join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('oauth_generate','oauth_probe') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NOT NULL)
);
CREATE INDEX tsw_tasks_oauth_asset_idx ON tsw_tasks(oauth_asset_id, created_at DESC) WHERE oauth_asset_id IS NOT NULL;
CREATE INDEX tsw_tasks_oauth_runnable_idx ON tsw_tasks(priority DESC, available_at, created_at) WHERE task_type IN ('oauth_generate','oauth_probe') AND status IN ('queued','retry_wait');

CREATE TABLE tsw_oauth_attempts (
    id uuid CONSTRAINT tsw_oauth_attempts_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    oauth_asset_id uuid NOT NULL CONSTRAINT tsw_oauth_attempts_asset_fk REFERENCES tsw_oauth_assets(id) ON DELETE CASCADE,
    task_id uuid NOT NULL CONSTRAINT tsw_oauth_attempts_task_fk REFERENCES tsw_tasks(id) ON DELETE CASCADE,
    generation bigint NOT NULL CONSTRAINT tsw_oauth_attempts_generation_ck CHECK (generation > 0),
    attempt_no integer NOT NULL CONSTRAINT tsw_oauth_attempts_attempt_no_ck CHECK (attempt_no > 0),
    attempt_kind text NOT NULL CONSTRAINT tsw_oauth_attempts_kind_ck CHECK (attempt_kind IN ('generate','probe','reclaim')),
    state text NOT NULL DEFAULT 'running' CONSTRAINT tsw_oauth_attempts_state_ck CHECK (state IN ('running','published','failed','superseded')),
    strategy text NOT NULL DEFAULT 'pkce' CONSTRAINT tsw_oauth_attempts_strategy_ck CHECK (length(strategy) BETWEEN 1 AND 64),
    outcome_code text CONSTRAINT tsw_oauth_attempts_outcome_ck CHECK (outcome_code IS NULL OR length(outcome_code) BETWEEN 1 AND 128),
    published_version_id uuid,
    requested_order_id uuid,
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tsw_oauth_attempts_asset_generation_no_uq UNIQUE (oauth_asset_id, generation, attempt_no),
    CONSTRAINT tsw_oauth_attempts_task_uq UNIQUE (task_id),
    CONSTRAINT tsw_oauth_attempts_completion_ck CHECK ((state IN ('published','failed','superseded')) = (finished_at IS NOT NULL))
);
CREATE UNIQUE INDEX tsw_oauth_attempts_active_uq ON tsw_oauth_attempts(oauth_asset_id) WHERE state = 'running';
CREATE INDEX tsw_oauth_attempts_asset_idx ON tsw_oauth_attempts(oauth_asset_id, created_at DESC);
ALTER TABLE tsw_oauth_assets
    ADD CONSTRAINT tsw_oauth_assets_attempt_fk FOREIGN KEY (current_attempt_id) REFERENCES tsw_oauth_attempts(id) ON DELETE RESTRICT,
    ADD CONSTRAINT tsw_oauth_assets_delivery_fk FOREIGN KEY (current_delivery_version_id, id) REFERENCES tsw_delivery_versions(id, oauth_asset_id) ON DELETE RESTRICT;
ALTER TABLE tsw_oauth_attempts
    ADD CONSTRAINT tsw_oauth_attempts_published_version_fk FOREIGN KEY (published_version_id, oauth_asset_id) REFERENCES tsw_delivery_versions(id, oauth_asset_id) ON DELETE RESTRICT;

CREATE TABLE tsw_cards (
    id uuid CONSTRAINT tsw_cards_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_id uuid NOT NULL CONSTRAINT tsw_cards_membership_fk REFERENCES tsw_batch_memberships(id) ON DELETE CASCADE,
    hmac_key_version smallint NOT NULL CONSTRAINT tsw_cards_key_version_ck CHECK (hmac_key_version > 0),
    lookup_hmac bytea NOT NULL CONSTRAINT tsw_cards_lookup_hmac_ck CHECK (octet_length(lookup_hmac) = 32),
    display_suffix text NOT NULL CONSTRAINT tsw_cards_suffix_ck CHECK (length(display_suffix) BETWEEN 4 AND 12),
    status text NOT NULL DEFAULT 'active' CONSTRAINT tsw_cards_status_ck CHECK (status IN ('active','revoked')),
    issued_at timestamptz NOT NULL DEFAULT now(),
    redemption_deadline timestamptz NOT NULL,
    first_redeemed_at timestamptz,
    revoked_at timestamptz,
    revocation_reason text CONSTRAINT tsw_cards_revocation_reason_ck CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_cards_version_ck CHECK (version > 0),
    activation_idempotency_key text CONSTRAINT tsw_cards_activation_key_ck CHECK (activation_idempotency_key IS NULL OR length(activation_idempotency_key) BETWEEN 8 AND 128),
    CONSTRAINT tsw_cards_membership_uq UNIQUE (membership_id),
    CONSTRAINT tsw_cards_status_shape_ck CHECK ((status = 'active' AND revoked_at IS NULL) OR (status = 'revoked' AND revoked_at IS NOT NULL)),
    CONSTRAINT tsw_cards_deadline_ck CHECK (redemption_deadline >= issued_at)
);
CREATE UNIQUE INDEX tsw_cards_lookup_uq ON tsw_cards(hmac_key_version, lookup_hmac);
CREATE INDEX tsw_cards_status_deadline_idx ON tsw_cards(status, redemption_deadline);
REVOKE ALL ON tsw_cards FROM PUBLIC;

-- +goose Down
REVOKE ALL ON tsw_cards FROM PUBLIC;
DROP INDEX tsw_cards_status_deadline_idx;
DROP INDEX tsw_cards_lookup_uq;
DROP TABLE tsw_cards;
ALTER TABLE tsw_oauth_attempts DROP CONSTRAINT tsw_oauth_attempts_published_version_fk;
ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_delivery_fk;
ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_attempt_fk;
DROP INDEX tsw_oauth_attempts_asset_idx;
DROP INDEX tsw_oauth_attempts_active_uq;
DROP TABLE tsw_oauth_attempts;
DROP INDEX tsw_tasks_oauth_runnable_idx;
DROP INDEX tsw_tasks_oauth_asset_idx;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_oauth_asset_fk;
ALTER TABLE tsw_tasks DROP COLUMN oauth_asset_id;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read','workspace_fact_cleanup','target_account_probe','join','join_reconcile'));
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read','workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL)
    OR (task_type IN ('join','join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL)
);
DROP TRIGGER tsw_delivery_versions_immutable_trigger ON tsw_delivery_versions;
DROP FUNCTION tsw_delivery_versions_immutable();
DROP INDEX tsw_delivery_versions_asset_idx;
DROP TABLE tsw_delivery_versions;
DROP INDEX tsw_oauth_assets_status_idx;
DROP TABLE tsw_oauth_assets;
