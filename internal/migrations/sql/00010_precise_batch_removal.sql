-- +goose Up
-- Ticket 12 reuses the durable operation/task graph for one frozen removal
-- target per current-batch membership. A live member id is attempt evidence;
-- membership_id remains the immutable authorization and reconciliation subject.
ALTER TABLE tsw_operations DROP CONSTRAINT tsw_operations_type_ck;
ALTER TABLE tsw_operations ADD CONSTRAINT tsw_operations_type_ck CHECK (operation_type IN ('join','remove'));
DROP INDEX tsw_operations_workspace_active_uq;
CREATE UNIQUE INDEX tsw_operations_workspace_active_uq ON tsw_operations(workspace_id)
    WHERE operation_type IN ('join','remove') AND status IN ('queued','running','blocked');

ALTER TABLE tsw_operation_targets DROP CONSTRAINT tsw_operation_targets_platform_stage_ck;
ALTER TABLE tsw_operation_targets
    ADD CONSTRAINT tsw_operation_targets_platform_stage_ck CHECK (
        platform_request_stage IS NULL OR platform_request_stage IN ('request_join','accept_join','remove_member')
    ),
    ADD COLUMN remove_attempt_count integer NOT NULL DEFAULT 0
        CONSTRAINT tsw_operation_targets_remove_attempts_ck CHECK (remove_attempt_count BETWEEN 0 AND 3),
    ADD COLUMN removal_live_member_id text
        CONSTRAINT tsw_operation_targets_remove_member_id_ck CHECK (removal_live_member_id IS NULL OR length(removal_live_member_id) BETWEEN 1 AND 255);

ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN (
    'workspace_read','workspace_fact_cleanup','target_account_probe','join','join_reconcile',
    'oauth_generate','oauth_probe','oauth_reclaim','remove','remove_reconcile'
));
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read','workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('join','join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('oauth_generate','oauth_probe','oauth_reclaim') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NOT NULL)
    OR (task_type IN ('remove','remove_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NOT NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NULL)
);
CREATE INDEX tsw_tasks_remove_runnable_idx ON tsw_tasks(priority DESC,available_at,created_at)
    WHERE task_type IN ('remove','remove_reconcile') AND status IN ('queued','retry_wait');

-- +goose Down
DROP INDEX tsw_tasks_remove_runnable_idx;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read','workspace_fact_cleanup','target_account_probe','join','join_reconcile','oauth_generate','oauth_probe','oauth_reclaim'));
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read','workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('join','join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('oauth_generate','oauth_probe','oauth_reclaim') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NOT NULL)
);
ALTER TABLE tsw_operation_targets
    DROP CONSTRAINT tsw_operation_targets_remove_member_id_ck,
    DROP CONSTRAINT tsw_operation_targets_remove_attempts_ck,
    DROP COLUMN removal_live_member_id,
    DROP COLUMN remove_attempt_count,
    DROP CONSTRAINT tsw_operation_targets_platform_stage_ck;
ALTER TABLE tsw_operation_targets ADD CONSTRAINT tsw_operation_targets_platform_stage_ck CHECK (platform_request_stage IS NULL OR platform_request_stage IN ('request_join','accept_join'));
DROP INDEX tsw_operations_workspace_active_uq;
CREATE UNIQUE INDEX tsw_operations_workspace_active_uq ON tsw_operations(workspace_id)
    WHERE operation_type = 'join' AND status IN ('queued','running','blocked');
ALTER TABLE tsw_operations DROP CONSTRAINT tsw_operations_type_ck;
ALTER TABLE tsw_operations ADD CONSTRAINT tsw_operations_type_ck CHECK (operation_type IN ('join'));
