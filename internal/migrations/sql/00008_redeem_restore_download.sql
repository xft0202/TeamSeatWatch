-- +goose Up
-- Ticket 09 adds one-order customer access and dynamic download authorization.
-- The public gateway never receives a database role; all rows are owned by control service.

ALTER TABLE tsw_rate_limit_buckets
    DROP CONSTRAINT tsw_rate_limit_buckets_kind_ck,
    DROP CONSTRAINT tsw_rate_limit_buckets_count_ck,
    DROP CONSTRAINT tsw_rate_limit_buckets_window_ck;
ALTER TABLE tsw_rate_limit_buckets
    ADD CONSTRAINT tsw_rate_limit_buckets_kind_ck CHECK (kind IN (
        'login_account', 'login_ip', 'recovery_account', 'recovery_ip',
        'public_card', 'public_ip', 'public_token', 'public_token_ip'
    )),
    ADD CONSTRAINT tsw_rate_limit_buckets_count_ck CHECK (
        (kind IN ('login_account', 'login_ip', 'recovery_account', 'recovery_ip') AND count BETWEEN 0 AND 5)
        OR (kind IN ('public_card', 'public_ip', 'public_token', 'public_token_ip') AND count BETWEEN 0 AND 120)
    ),
    ADD CONSTRAINT tsw_rate_limit_buckets_window_ck CHECK (
        window_ends_at = window_started_at + interval '1 minute'
        OR window_ends_at = window_started_at + interval '15 minutes'
    );

ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_liveness_origin_ck;
ALTER TABLE tsw_oauth_assets
    ADD CONSTRAINT tsw_oauth_assets_liveness_origin_ck CHECK (
        liveness_origin IS NULL OR liveness_origin IN ('generation','scheduled','owner','customer')
    );

ALTER TABLE tsw_cards
    ADD CONSTRAINT tsw_cards_id_membership_uq UNIQUE (id, membership_id);
ALTER TABLE tsw_oauth_assets
    ADD CONSTRAINT tsw_oauth_assets_id_membership_uq UNIQUE (id, membership_id);

CREATE TABLE tsw_orders (
    id uuid CONSTRAINT tsw_orders_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_id uuid NOT NULL CONSTRAINT tsw_orders_membership_fk REFERENCES tsw_batch_memberships(id) ON DELETE CASCADE,
    card_id uuid NOT NULL,
    oauth_asset_id uuid NOT NULL,
    current_delivery_version_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tsw_orders_version_ck CHECK (version > 0),
    CONSTRAINT tsw_orders_card_membership_fk FOREIGN KEY (card_id, membership_id)
        REFERENCES tsw_cards(id, membership_id) ON DELETE CASCADE,
    CONSTRAINT tsw_orders_asset_membership_fk FOREIGN KEY (oauth_asset_id, membership_id)
        REFERENCES tsw_oauth_assets(id, membership_id) ON DELETE CASCADE,
    CONSTRAINT tsw_orders_delivery_asset_fk FOREIGN KEY (current_delivery_version_id, oauth_asset_id)
        REFERENCES tsw_delivery_versions(id, oauth_asset_id) ON DELETE CASCADE,
    CONSTRAINT tsw_orders_membership_uq UNIQUE (membership_id),
    CONSTRAINT tsw_orders_card_uq UNIQUE (card_id),
    CONSTRAINT tsw_orders_binding_uq UNIQUE (id, membership_id, card_id, oauth_asset_id)
);
CREATE INDEX tsw_orders_membership_idx ON tsw_orders(membership_id, created_at DESC);
CREATE INDEX tsw_orders_card_idx ON tsw_orders(card_id, created_at DESC);
CREATE INDEX tsw_orders_delivery_idx ON tsw_orders(current_delivery_version_id, created_at DESC);

CREATE TABLE tsw_public_tokens (
    id uuid CONSTRAINT tsw_public_tokens_pk PRIMARY KEY DEFAULT gen_random_uuid(),
    membership_id uuid NOT NULL,
    card_id uuid NOT NULL,
    order_id uuid NOT NULL,
    oauth_asset_id uuid NOT NULL,
    delivery_version_id uuid NOT NULL,
    token_kind text NOT NULL CONSTRAINT tsw_public_tokens_kind_ck CHECK (token_kind IN ('customer_access')),
    token_hash bytea NOT NULL CONSTRAINT tsw_public_tokens_hash_ck CHECK (octet_length(token_hash) = 32),
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    revocation_reason text CONSTRAINT tsw_public_tokens_reason_ck CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 128),
    CONSTRAINT tsw_public_tokens_hash_uq UNIQUE (token_hash),
    CONSTRAINT tsw_public_tokens_order_binding_fk FOREIGN KEY (order_id, membership_id, card_id, oauth_asset_id)
        REFERENCES tsw_orders(id, membership_id, card_id, oauth_asset_id) ON DELETE CASCADE,
    CONSTRAINT tsw_public_tokens_delivery_asset_fk FOREIGN KEY (delivery_version_id, oauth_asset_id)
        REFERENCES tsw_delivery_versions(id, oauth_asset_id) ON DELETE CASCADE,
    CONSTRAINT tsw_public_tokens_expiry_ck CHECK (expires_at > issued_at),
    CONSTRAINT tsw_public_tokens_revocation_ck CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);
CREATE INDEX tsw_public_tokens_order_idx ON tsw_public_tokens(order_id, issued_at DESC);
CREATE INDEX tsw_public_tokens_active_expiry_idx ON tsw_public_tokens(expires_at, token_kind) WHERE revoked_at IS NULL;
CREATE INDEX tsw_public_tokens_card_idx ON tsw_public_tokens(card_id, issued_at DESC);
REVOKE ALL ON tsw_public_tokens FROM PUBLIC;

-- +goose Down
REVOKE ALL ON tsw_public_tokens FROM PUBLIC;
DROP INDEX tsw_public_tokens_card_idx;
DROP INDEX tsw_public_tokens_active_expiry_idx;
DROP INDEX tsw_public_tokens_order_idx;
DROP TABLE tsw_public_tokens;
DROP INDEX tsw_orders_delivery_idx;
DROP INDEX tsw_orders_card_idx;
DROP INDEX tsw_orders_membership_idx;
DROP TABLE tsw_orders;
ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_id_membership_uq;
ALTER TABLE tsw_cards DROP CONSTRAINT tsw_cards_id_membership_uq;
ALTER TABLE tsw_oauth_assets DROP CONSTRAINT tsw_oauth_assets_liveness_origin_ck;
ALTER TABLE tsw_oauth_assets
    ADD CONSTRAINT tsw_oauth_assets_liveness_origin_ck CHECK (liveness_origin IS NULL OR liveness_origin IN ('generation','scheduled','owner'));
ALTER TABLE tsw_rate_limit_buckets
    DROP CONSTRAINT tsw_rate_limit_buckets_kind_ck,
    DROP CONSTRAINT tsw_rate_limit_buckets_count_ck,
    DROP CONSTRAINT tsw_rate_limit_buckets_window_ck;
ALTER TABLE tsw_rate_limit_buckets
    ADD CONSTRAINT tsw_rate_limit_buckets_kind_ck CHECK (kind IN ('login_account', 'login_ip', 'recovery_account', 'recovery_ip')),
    ADD CONSTRAINT tsw_rate_limit_buckets_count_ck CHECK (
        (kind IN ('login_account', 'login_ip', 'recovery_account', 'recovery_ip') AND count BETWEEN 0 AND 5)
    ),
    ADD CONSTRAINT tsw_rate_limit_buckets_window_ck CHECK (window_ends_at = window_started_at + interval '15 minutes');
