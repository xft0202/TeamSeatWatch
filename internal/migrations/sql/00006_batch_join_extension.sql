-- +goose Up
-- Ticket 07 freezes and executes one durable target/task per planned target.
-- The mutation lease is deliberately owned by the operation row so future Remove
-- can use the same PostgreSQL fence without introducing a process-global lock.
ALTER TABLE tsw_operations
    ADD COLUMN workspace_mutation_lease_owner text,
    ADD COLUMN workspace_mutation_lease_token uuid,
    ADD COLUMN workspace_mutation_lease_expires_at timestamptz,
    ADD CONSTRAINT tsw_operations_mutation_lease_shape_ck CHECK (
        (workspace_mutation_lease_owner IS NULL AND workspace_mutation_lease_token IS NULL AND workspace_mutation_lease_expires_at IS NULL)
        OR (workspace_mutation_lease_owner IS NOT NULL AND workspace_mutation_lease_token IS NOT NULL AND workspace_mutation_lease_expires_at IS NOT NULL)
    );

DROP INDEX tsw_operations_workspace_active_uq;
CREATE UNIQUE INDEX tsw_operations_workspace_active_uq ON tsw_operations(workspace_id)
    WHERE status IN ('queued', 'running', 'blocked');

CREATE INDEX tsw_operations_mutation_lease_idx ON tsw_operations(workspace_mutation_lease_expires_at)
    WHERE workspace_mutation_lease_token IS NOT NULL;

-- +goose Down
DROP INDEX tsw_operations_mutation_lease_idx;
DROP INDEX tsw_operations_workspace_active_uq;
CREATE UNIQUE INDEX tsw_operations_workspace_active_uq ON tsw_operations(workspace_id)
    WHERE operation_type = 'join' AND status IN ('queued', 'running', 'blocked');
ALTER TABLE tsw_operations
    DROP CONSTRAINT tsw_operations_mutation_lease_shape_ck,
    DROP COLUMN workspace_mutation_lease_expires_at,
    DROP COLUMN workspace_mutation_lease_token,
    DROP COLUMN workspace_mutation_lease_owner;
