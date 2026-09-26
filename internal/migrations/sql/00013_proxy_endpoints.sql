-- +goose Up
-- Proxy endpoint registry: Owner-managed egress endpoints with probe region facts.
-- Each endpoint is a full URL (socks5://user:pass@host:port or http://host:port).
-- Country/region come from the probe IP echo; they are observations, not guarantees.
CREATE TABLE IF NOT EXISTS tsw_proxy_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failed')),
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_proxy_endpoints_status ON tsw_proxy_endpoints(status);

-- +goose Down
DROP TABLE IF EXISTS tsw_proxy_endpoints;
