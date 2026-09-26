-- +goose Up
-- Owner-managed runtime settings. One row holds the whole snapshot so a save is
-- atomic and a reader can never observe a half-applied configuration.
-- Secrets (proxy password) are sealed with the deployment key ring, never stored plain.
CREATE TABLE IF NOT EXISTS tsw_settings (
    id boolean PRIMARY KEY DEFAULT true,
    version bigint NOT NULL DEFAULT 1,
    proxy jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT 'system',
    CONSTRAINT tsw_settings_singleton CHECK (id = true)
);

INSERT INTO tsw_settings (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS tsw_settings;
