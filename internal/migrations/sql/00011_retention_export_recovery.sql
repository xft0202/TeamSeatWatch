-- +goose Up
-- Ticket 13 makes relationship retention executable. Expired delivery units may
-- remove their operation graph; active/planned relationships retain target data.
ALTER TABLE tsw_batch_memberships DROP CONSTRAINT tsw_batch_memberships_join_target_fk;
ALTER TABLE tsw_batch_memberships
    ADD CONSTRAINT tsw_batch_memberships_join_target_fk
    FOREIGN KEY (join_operation_target_id) REFERENCES tsw_operation_targets(id) ON DELETE CASCADE;
ALTER TABLE tsw_operation_targets DROP CONSTRAINT tsw_operation_targets_membership_fk;
ALTER TABLE tsw_operation_targets
    ADD CONSTRAINT tsw_operation_targets_membership_fk
    FOREIGN KEY (membership_id) REFERENCES tsw_batch_memberships(id) ON DELETE CASCADE;

CREATE INDEX tsw_batch_memberships_retention_workspace_idx
    ON tsw_batch_memberships(retention_due_at, batch_id)
    WHERE retention_due_at IS NOT NULL;
CREATE INDEX tsw_batches_retention_idx
    ON tsw_batches(service_ended_at, status)
    WHERE status = 'ended' AND service_ended_at IS NOT NULL;
CREATE INDEX tsw_audit_events_scope_expiry_idx
    ON tsw_audit_events(retention_scope_type, retention_scope_id, expires_at);

CREATE TABLE tsw_retention_runs (
    id uuid CONSTRAINT tsw_retention_runs_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_key text NOT NULL CONSTRAINT tsw_retention_runs_cycle_key_ck CHECK (length(cycle_key) BETWEEN 1 AND 64),
    status text NOT NULL CONSTRAINT tsw_retention_runs_status_ck CHECK (status IN ('running','succeeded','failed')),
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    deleted_memberships integer NOT NULL DEFAULT 0 CONSTRAINT tsw_retention_runs_memberships_ck CHECK (deleted_memberships >= 0),
    deleted_workspaces integer NOT NULL DEFAULT 0 CONSTRAINT tsw_retention_runs_workspaces_ck CHECK (deleted_workspaces >= 0),
    error_code text CONSTRAINT tsw_retention_runs_error_ck CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    CONSTRAINT tsw_retention_runs_cycle_uq UNIQUE (cycle_key),
    CONSTRAINT tsw_retention_runs_finished_ck CHECK ((status = 'running') = (finished_at IS NULL))
);
CREATE INDEX tsw_retention_runs_started_idx ON tsw_retention_runs(started_at DESC);

CREATE TABLE tsw_recovery_gate (
    id boolean CONSTRAINT tsw_recovery_gate_pk PRIMARY KEY DEFAULT true,
    state text NOT NULL CONSTRAINT tsw_recovery_gate_state_ck CHECK (state IN ('closed','open')),
    restored_at timestamptz,
    checked_at timestamptz NOT NULL DEFAULT now(),
    last_cleanup_at timestamptz,
    last_cleanup_cycle text
);
INSERT INTO tsw_recovery_gate(id,state) VALUES (true,'open');

ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN (
    'workspace_read','workspace_fact_cleanup','retention_cleanup','target_account_probe','join','join_reconcile',
    'oauth_generate','oauth_probe','oauth_reclaim','remove','remove_reconcile'
));
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read','workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type = 'retention_cleanup' AND workspace_id IS NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('join','join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('oauth_generate','oauth_probe','oauth_reclaim') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NOT NULL)
    OR (task_type IN ('remove','remove_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NOT NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NULL)
);
CREATE UNIQUE INDEX tsw_tasks_retention_cycle_uq ON tsw_tasks(task_type, dedupe_key) WHERE task_type='retention_cleanup';

ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_parent_fk;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_parent_fk FOREIGN KEY (parent_task_id) REFERENCES tsw_tasks(id) ON DELETE CASCADE;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tsw_audit_events_append_only_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND (OLD.expires_at <= now() OR current_setting('tsw.retention_cleanup', true) = 'on') THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'tsw_audit_events is append-only until expiry';
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE tsw_recovery_gate;
DROP INDEX tsw_tasks_retention_cycle_uq;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_parent_fk;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_parent_fk FOREIGN KEY (parent_task_id) REFERENCES tsw_tasks(id) ON DELETE RESTRICT;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION tsw_audit_events_append_only_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.expires_at <= now() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'tsw_audit_events is append-only until expiry';
END;
$$;
-- +goose StatementEnd


ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read','workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('join','join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('oauth_generate','oauth_probe','oauth_reclaim') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NOT NULL)
    OR (task_type IN ('remove','remove_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NOT NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NULL)
);
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read','workspace_fact_cleanup','target_account_probe','join','join_reconcile','oauth_generate','oauth_probe','oauth_reclaim','remove','remove_reconcile'));
DROP INDEX tsw_retention_runs_started_idx;
DROP TABLE tsw_retention_runs;
DROP INDEX tsw_audit_events_scope_expiry_idx;
DROP INDEX tsw_batches_retention_idx;
DROP INDEX tsw_batch_memberships_retention_workspace_idx;
ALTER TABLE tsw_operation_targets DROP CONSTRAINT tsw_operation_targets_membership_fk;
ALTER TABLE tsw_operation_targets
    ADD CONSTRAINT tsw_operation_targets_membership_fk
    FOREIGN KEY (membership_id) REFERENCES tsw_batch_memberships(id) ON DELETE RESTRICT;
ALTER TABLE tsw_batch_memberships DROP CONSTRAINT tsw_batch_memberships_join_target_fk;
ALTER TABLE tsw_batch_memberships
    ADD CONSTRAINT tsw_batch_memberships_join_target_fk
    FOREIGN KEY (join_operation_target_id) REFERENCES tsw_operation_targets(id) ON DELETE RESTRICT;
