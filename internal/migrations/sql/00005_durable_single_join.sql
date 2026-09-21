-- +goose Up
-- Ticket 06 adds the durable single-target join boundary. The operation target is
-- the frozen authorization subject; every task and reconciliation stays attached
-- to that subject and cannot expand into a batch-wide join.
CREATE TABLE tsw_operations (
    id uuid CONSTRAINT tsw_operations_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id uuid NOT NULL CONSTRAINT tsw_operations_owner_fk REFERENCES tsw_owners(id) ON DELETE RESTRICT,
    workspace_id uuid NOT NULL CONSTRAINT tsw_operations_workspace_fk REFERENCES tsw_workspaces(id) ON DELETE RESTRICT,
    batch_id uuid NOT NULL CONSTRAINT tsw_operations_batch_fk REFERENCES tsw_batches(id) ON DELETE RESTRICT,
    operation_type text NOT NULL CONSTRAINT tsw_operations_type_ck CHECK (operation_type IN ('join')),
    idempotency_key text NOT NULL CONSTRAINT tsw_operations_idempotency_ck CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    request_hash bytea NOT NULL CONSTRAINT tsw_operations_request_hash_ck CHECK (octet_length(request_hash) = 32),
    input_snapshot jsonb NOT NULL CONSTRAINT tsw_operations_input_ck CHECK (jsonb_typeof(input_snapshot) = 'object'),
    status text NOT NULL DEFAULT 'queued' CONSTRAINT tsw_operations_status_ck CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'blocked')),
    authorized_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    correlation_id text NOT NULL CONSTRAINT tsw_operations_correlation_ck CHECK (length(correlation_id) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_operations_version_ck CHECK (version > 0),
    CONSTRAINT tsw_operations_idempotency_uq UNIQUE (owner_id, operation_type, idempotency_key),
    CONSTRAINT tsw_operations_completion_ck CHECK ((status IN ('succeeded', 'failed', 'blocked')) = (completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX tsw_operations_workspace_active_uq ON tsw_operations(workspace_id)
    WHERE operation_type = 'join' AND status IN ('queued', 'running', 'blocked');
CREATE INDEX tsw_operations_batch_idx ON tsw_operations(batch_id, created_at DESC);
CREATE INDEX tsw_operations_status_idx ON tsw_operations(status, created_at);

CREATE TABLE tsw_operation_targets (
    id uuid CONSTRAINT tsw_operation_targets_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id uuid NOT NULL CONSTRAINT tsw_operation_targets_operation_fk REFERENCES tsw_operations(id) ON DELETE CASCADE,
    target_account_id uuid CONSTRAINT tsw_operation_targets_target_fk REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT,
    membership_id uuid,
    ordinal integer NOT NULL CONSTRAINT tsw_operation_targets_ordinal_ck CHECK (ordinal > 0),
    status text NOT NULL DEFAULT 'queued' CONSTRAINT tsw_operation_targets_status_ck CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'blocked', 'unknown')),
    preflight_status text NOT NULL DEFAULT 'pending' CONSTRAINT tsw_operation_targets_preflight_status_ck CHECK (preflight_status IN ('pending', 'available', 'credential_invalid', 'definitely_unavailable', 'transient_failure', 'unknown')),
    preflight_http_status integer CONSTRAINT tsw_operation_targets_preflight_http_ck CHECK (preflight_http_status IS NULL OR preflight_http_status BETWEEN 100 AND 599),
    preflight_error_code text CONSTRAINT tsw_operation_targets_preflight_error_ck CHECK (preflight_error_code IS NULL OR length(preflight_error_code) BETWEEN 1 AND 128),
    preflight_origin text CONSTRAINT tsw_operation_targets_preflight_origin_ck CHECK (preflight_origin IS NULL OR preflight_origin = 'worker'),
    preflight_at timestamptz,
    outcome_code text CONSTRAINT tsw_operation_targets_outcome_ck CHECK (outcome_code IS NULL OR length(outcome_code) BETWEEN 1 AND 128),
    diagnostic_code text CONSTRAINT tsw_operation_targets_diagnostic_ck CHECK (diagnostic_code IS NULL OR length(diagnostic_code) BETWEEN 1 AND 128),
    platform_request_may_have_reached boolean NOT NULL DEFAULT false,
    platform_request_stage text CONSTRAINT tsw_operation_targets_platform_stage_ck CHECK (platform_request_stage IS NULL OR platform_request_stage IN ('request_join', 'accept_join')),
    platform_request_started_at timestamptz,
    last_attempt_at timestamptz,
    CONSTRAINT tsw_operation_targets_platform_request_ck CHECK (
        (platform_request_may_have_reached = false AND platform_request_stage IS NULL AND platform_request_started_at IS NULL)
        OR (platform_request_may_have_reached = true AND platform_request_stage IS NOT NULL AND platform_request_started_at IS NOT NULL)
    ),
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_operation_targets_version_ck CHECK (version > 0),
    CONSTRAINT tsw_operation_targets_subject_ck CHECK ((target_account_id IS NOT NULL) <> (membership_id IS NOT NULL)),
    CONSTRAINT tsw_operation_targets_preflight_shape_ck CHECK ((preflight_status = 'pending' AND preflight_at IS NULL AND preflight_origin IS NULL) OR (preflight_status <> 'pending' AND preflight_at IS NOT NULL AND preflight_origin = 'worker')),
    CONSTRAINT tsw_operation_targets_completion_ck CHECK ((status IN ('succeeded', 'failed', 'blocked', 'unknown')) = (completed_at IS NOT NULL)),
    CONSTRAINT tsw_operation_targets_operation_ordinal_uq UNIQUE (operation_id, ordinal)
);
CREATE UNIQUE INDEX tsw_operation_targets_target_uq ON tsw_operation_targets(operation_id, target_account_id) WHERE target_account_id IS NOT NULL;
CREATE UNIQUE INDEX tsw_operation_targets_membership_uq ON tsw_operation_targets(operation_id, membership_id) WHERE membership_id IS NOT NULL;
CREATE INDEX tsw_operation_targets_status_idx ON tsw_operation_targets(status, created_at);
CREATE INDEX tsw_operation_targets_target_idx ON tsw_operation_targets(target_account_id, created_at DESC);

CREATE TABLE tsw_batch_memberships (
    id uuid CONSTRAINT tsw_batch_memberships_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id uuid NOT NULL CONSTRAINT tsw_batch_memberships_batch_fk REFERENCES tsw_batches(id) ON DELETE CASCADE,
    target_account_id uuid NOT NULL CONSTRAINT tsw_batch_memberships_target_fk REFERENCES tsw_target_accounts(id) ON DELETE RESTRICT,
    join_operation_target_id uuid NOT NULL CONSTRAINT tsw_batch_memberships_join_target_fk REFERENCES tsw_operation_targets(id) ON DELETE RESTRICT,
    platform_member_id text CONSTRAINT tsw_batch_memberships_platform_id_ck CHECK (platform_member_id IS NULL OR length(platform_member_id) BETWEEN 1 AND 255),
    state text NOT NULL DEFAULT 'active' CONSTRAINT tsw_batch_memberships_state_ck CHECK (state IN ('active', 'removed')),
    joined_at timestamptz NOT NULL,
    removal_requested_at timestamptz,
    removed_at timestamptz,
    service_ended_at timestamptz,
    retention_due_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_batch_memberships_version_ck CHECK (version > 0),
    CONSTRAINT tsw_batch_memberships_target_uq UNIQUE (batch_id, target_account_id),
    CONSTRAINT tsw_batch_memberships_operation_target_uq UNIQUE (join_operation_target_id),
    CONSTRAINT tsw_batch_memberships_dates_ck CHECK (removed_at IS NULL OR removed_at >= joined_at),
    CONSTRAINT tsw_batch_memberships_state_shape_ck CHECK ((state = 'active' AND removed_at IS NULL) OR (state = 'removed' AND removed_at IS NOT NULL))
);
CREATE INDEX tsw_batch_memberships_batch_state_idx ON tsw_batch_memberships(batch_id, state);
CREATE INDEX tsw_batch_memberships_target_idx ON tsw_batch_memberships(target_account_id, created_at DESC);
CREATE INDEX tsw_batch_memberships_retention_idx ON tsw_batch_memberships(retention_due_at) WHERE retention_due_at IS NOT NULL;
ALTER TABLE tsw_operation_targets
    ADD CONSTRAINT tsw_operation_targets_membership_fk FOREIGN KEY (membership_id) REFERENCES tsw_batch_memberships(id) ON DELETE RESTRICT;

ALTER TABLE tsw_tasks
    ADD COLUMN operation_target_id uuid CONSTRAINT tsw_tasks_operation_target_fk REFERENCES tsw_operation_targets(id) ON DELETE RESTRICT,
    ADD COLUMN membership_id uuid CONSTRAINT tsw_tasks_membership_fk REFERENCES tsw_batch_memberships(id) ON DELETE RESTRICT;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read', 'workspace_fact_cleanup', 'target_account_probe', 'join', 'join_reconcile'));
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read', 'workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL)
    OR (task_type IN ('join', 'join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL)
);
CREATE INDEX tsw_tasks_operation_target_idx ON tsw_tasks(operation_target_id, created_at DESC) WHERE operation_target_id IS NOT NULL;
CREATE INDEX tsw_tasks_join_runnable_idx ON tsw_tasks(priority DESC, available_at, created_at) WHERE task_type IN ('join', 'join_reconcile') AND status IN ('queued', 'retry_wait');

-- +goose Down
DROP INDEX tsw_tasks_join_runnable_idx;
DROP INDEX tsw_tasks_operation_target_idx;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_membership_fk;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_operation_target_fk;
ALTER TABLE tsw_tasks DROP COLUMN membership_id;
ALTER TABLE tsw_tasks DROP COLUMN operation_target_id;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read', 'workspace_fact_cleanup', 'target_account_probe'));
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read', 'workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL)
);
ALTER TABLE tsw_operation_targets DROP CONSTRAINT tsw_operation_targets_membership_fk;
DROP TABLE tsw_batch_memberships;
DROP TABLE tsw_operation_targets;
DROP INDEX tsw_operations_status_idx;
DROP INDEX tsw_operations_batch_idx;
DROP INDEX tsw_operations_workspace_active_uq;
DROP TABLE tsw_operations;
