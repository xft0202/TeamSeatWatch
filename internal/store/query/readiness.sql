-- name: IsSchemaVersionApplied :one
SELECT EXISTS (
    SELECT 1
    FROM goose_db_version
    WHERE version_id = $1
      AND is_applied
);
