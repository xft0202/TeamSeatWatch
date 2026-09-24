-- +goose Up
-- Owner login is password-only for the single-operator deployment. Keep the old
-- columns nullable so existing databases can migrate without rebuilding Owner rows.
ALTER TABLE tsw_owners
    ALTER COLUMN totp_ciphertext DROP NOT NULL,
    ALTER COLUMN totp_nonce DROP NOT NULL,
    ALTER COLUMN totp_key_version DROP NOT NULL;

-- +goose Down
ALTER TABLE tsw_owners
    ALTER COLUMN totp_ciphertext SET NOT NULL,
    ALTER COLUMN totp_nonce SET NOT NULL,
    ALTER COLUMN totp_key_version SET NOT NULL;
