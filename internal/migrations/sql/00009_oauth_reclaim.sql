-- +goose Up
-- Ticket 10 adds customer-requested OAuth reclaim without changing the
-- original membership, target account, workspace, card, or order identity.
ALTER TABLE tsw_rate_limit_buckets
    DROP CONSTRAINT tsw_rate_limit_buckets_kind_ck,
    DROP CONSTRAINT tsw_rate_limit_buckets_count_ck;
ALTER TABLE tsw_public_tokens DROP CONSTRAINT tsw_public_tokens_kind_ck;
ALTER TABLE tsw_public_tokens
    ADD CONSTRAINT tsw_public_tokens_kind_ck CHECK (token_kind IN ('customer_access','reclaim_status'));
ALTER TABLE tsw_rate_limit_buckets
    ADD CONSTRAINT tsw_rate_limit_buckets_kind_ck CHECK (kind IN (
        'login_account', 'login_ip', 'recovery_account', 'recovery_ip',
        'public_card', 'public_ip', 'public_token', 'public_token_ip',
        'public_reclaim_card', 'public_reclaim_ip'
    )),
    ADD CONSTRAINT tsw_rate_limit_buckets_count_ck CHECK (
        (kind IN ('login_account', 'login_ip', 'recovery_account', 'recovery_ip') AND count BETWEEN 0 AND 5)
        OR (kind IN ('public_card', 'public_ip', 'public_token', 'public_token_ip', 'public_reclaim_card', 'public_reclaim_ip') AND count BETWEEN 0 AND 120)
    );

ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_status_ck;
ALTER TABLE tsw_oauth_assets
    ADD CONSTRAINT tsw_oauth_assets_status_ck CHECK (status IN ('pending','generating','reclaiming','ready','unavailable'));
ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_liveness_origin_ck;
ALTER TABLE tsw_oauth_assets
    ADD CONSTRAINT tsw_oauth_assets_liveness_origin_ck CHECK (
        liveness_origin IS NULL OR liveness_origin IN ('generation','scheduled','owner','customer','reclaim')
    );

ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read','workspace_fact_cleanup','target_account_probe','join','join_reconcile','oauth_generate','oauth_probe','oauth_reclaim'));
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read','workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('join','join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('oauth_generate','oauth_probe','oauth_reclaim') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NOT NULL)
);
CREATE INDEX tsw_tasks_oauth_reclaim_runnable_idx ON tsw_tasks(priority DESC, available_at, created_at) WHERE task_type='oauth_reclaim' AND status IN ('queued','retry_wait');
CREATE UNIQUE INDEX tsw_tasks_active_reclaim_uq ON tsw_tasks(oauth_asset_id) WHERE task_type='oauth_reclaim' AND status IN ('queued','running','retry_wait');
CREATE INDEX tsw_oauth_attempts_order_idx ON tsw_oauth_attempts(requested_order_id, created_at DESC) WHERE requested_order_id IS NOT NULL;

ALTER TABLE tsw_oauth_attempts ADD CONSTRAINT tsw_oauth_attempts_order_fk FOREIGN KEY (requested_order_id) REFERENCES tsw_orders(id) ON DELETE RESTRICT;
ALTER TABLE tsw_tasks ADD COLUMN reclaim_tier text CONSTRAINT tsw_tasks_reclaim_tier_ck CHECK (reclaim_tier IS NULL OR reclaim_tier IN ('probe_ok','token_refresh','full_relogin','unrecoverable')),
    ADD COLUMN reclaim_result text CONSTRAINT tsw_tasks_reclaim_result_ck CHECK (reclaim_result IS NULL OR length(reclaim_result) BETWEEN 1 AND 128),
    ADD COLUMN reclaim_probe_status text CONSTRAINT tsw_tasks_reclaim_probe_ck CHECK (reclaim_probe_status IS NULL OR length(reclaim_probe_status) BETWEEN 1 AND 64),
    ADD COLUMN reclaim_http_status integer CONSTRAINT tsw_tasks_reclaim_http_ck CHECK (reclaim_http_status IS NULL OR reclaim_http_status BETWEEN 100 AND 599),
    ADD COLUMN reclaim_stage text CONSTRAINT tsw_tasks_reclaim_stage_ck CHECK (reclaim_stage IS NULL OR length(reclaim_stage) BETWEEN 1 AND 64);

-- +goose Down
ALTER TABLE tsw_oauth_attempts DROP CONSTRAINT tsw_oauth_attempts_order_fk;
ALTER TABLE tsw_tasks DROP COLUMN reclaim_tier, DROP COLUMN reclaim_result, DROP COLUMN reclaim_probe_status, DROP COLUMN reclaim_http_status, DROP COLUMN reclaim_stage;
DROP INDEX tsw_oauth_attempts_order_idx;
DROP INDEX tsw_tasks_active_reclaim_uq;
DROP INDEX tsw_tasks_oauth_reclaim_runnable_idx;
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_subject_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_subject_ck CHECK (
    (task_type IN ('workspace_read','workspace_fact_cleanup') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type = 'target_account_probe' AND workspace_id IS NULL AND target_account_id IS NOT NULL AND operation_target_id IS NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('join','join_reconcile') AND workspace_id IS NOT NULL AND target_account_id IS NOT NULL AND operation_target_id IS NOT NULL AND membership_id IS NULL AND oauth_asset_id IS NULL)
    OR (task_type IN ('oauth_generate','oauth_probe') AND workspace_id IS NOT NULL AND target_account_id IS NULL AND operation_target_id IS NULL AND membership_id IS NOT NULL AND oauth_asset_id IS NOT NULL)
);
ALTER TABLE tsw_tasks DROP CONSTRAINT tsw_tasks_type_ck;
ALTER TABLE tsw_tasks ADD CONSTRAINT tsw_tasks_type_ck CHECK (task_type IN ('workspace_read','workspace_fact_cleanup','target_account_probe','join','join_reconcile','oauth_generate','oauth_probe'));
ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_liveness_origin_ck;
ALTER TABLE tsw_oauth_assets ADD CONSTRAINT tsw_oauth_assets_liveness_origin_ck CHECK (liveness_origin IS NULL OR liveness_origin IN ('generation','scheduled','owner','customer'));
ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_status_ck;
ALTER TABLE tsw_oauth_assets ADD CONSTRAINT tsw_oauth_assets_status_ck CHECK (status IN ('pending','generating','ready','unavailable'));
ALTER TABLE tsw_public_tokens DROP CONSTRAINT tsw_public_tokens_kind_ck;
DELETE FROM tsw_public_tokens WHERE token_kind='reclaim_status';
ALTER TABLE tsw_public_tokens
    ADD CONSTRAINT tsw_public_tokens_kind_ck CHECK (token_kind IN ('customer_access'));
ALTER TABLE tsw_rate_limit_buckets DROP CONSTRAINT tsw_rate_limit_buckets_kind_ck, DROP CONSTRAINT tsw_rate_limit_buckets_count_ck;
ALTER TABLE tsw_rate_limit_buckets ADD CONSTRAINT tsw_rate_limit_buckets_kind_ck CHECK (kind IN ('login_account', 'login_ip', 'recovery_account', 'recovery_ip', 'public_card', 'public_ip', 'public_token', 'public_token_ip')),
    ADD CONSTRAINT tsw_rate_limit_buckets_count_ck CHECK ((kind IN ('login_account', 'login_ip', 'recovery_account', 'recovery_ip') AND count BETWEEN 0 AND 5) OR (kind IN ('public_card', 'public_ip', 'public_token', 'public_token_ip') AND count BETWEEN 0 AND 120));
