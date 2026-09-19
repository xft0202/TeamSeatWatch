package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/auth"
)

const (
	ownerLoginEnv    = "TSW_OWNER_LOGIN"
	ownerPasswordEnv = "TSW_OWNER_PASSWORD"
)

type ownerMaterials struct {
	passwordHash string
	secret       string
	keyVersion   uint16
	nonce        []byte
	ciphertext   []byte
	codes        []string
	codeHashes   [][32]byte
}

func runOwnerCommand(ctx context.Context, command string, getenv func(string) string) error {
	dsn, err := required(getenv, databaseURLEnv)
	if err != nil {
		return err
	}
	login := strings.ToLower(strings.TrimSpace(getenv(ownerLoginEnv)))
	password := getenv(ownerPasswordEnv)
	if login == "" || password == "" {
		return diagnostic("owner_credentials_missing")
	}
	keyFile, err := required(getenv, totpKeyringFileEnv)
	if err != nil {
		return err
	}
	ring, err := auth.LoadKeyRingFile(keyFile)
	if err != nil {
		return diagnostic("invalid_totp_keyring")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if command == "owner-create" {
		return createOwner(ctx, pool, ring, login, password)
	}
	return resetOwner(ctx, pool, ring, login, password)
}

func createOwner(ctx context.Context, pool *pgxpool.Pool, ring auth.KeyRing, username, password string) error {
	materials, err := prepareOwnerMaterials(ring, password)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// The singleton constraint is the final authority when two host commands race.
	var ownerID string
	err = tx.QueryRow(ctx, `
		INSERT INTO tsw_owners (
			username, password_hash, password_changed_at, totp_ciphertext,
			totp_nonce, totp_key_version, auth_version
		) VALUES ($1, $2, now(), $3, $4, $5, 1)
		RETURNING id`, username, materials.passwordHash, materials.ciphertext, materials.nonce, materials.keyVersion).Scan(&ownerID)
	if err != nil {
		return err
	}
	if err = insertRecoveryCodes(ctx, tx, ownerID, materials.codeHashes); err != nil {
		return err
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type:           audit.OwnerCreated,
		Actor:          audit.ActorSystem,
		OwnerID:        ownerID,
		EntityType:     "owner",
		EntityID:       ownerID,
		Outcome:        audit.OutcomeSucceeded,
		CorrelationID:  "owner-cli",
		Details:        audit.AuthVersionDetails{AuthVersion: 1},
		IdempotencyKey: "owner-created:" + ownerID,
	})
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	printOwnerMaterials(username, materials.secret, materials.codes)
	return nil
}

func resetOwner(ctx context.Context, pool *pgxpool.Pool, ring auth.KeyRing, username, password string) error {
	materials, err := prepareOwnerMaterials(ring, password)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Locking the sole Owner serializes auth-version increments and invalidation.
	var ownerID string
	var authVersion int64
	err = tx.QueryRow(ctx, `SELECT id, auth_version FROM tsw_owners WHERE username = $1 FOR UPDATE`, username).Scan(&ownerID, &authVersion)
	if err != nil {
		return diagnostic("owner_not_found")
	}
	authVersion++
	_, err = tx.Exec(ctx, `
		UPDATE tsw_owners
		SET password_hash = $1, password_changed_at = now(), totp_ciphertext = $2,
			totp_nonce = $3, totp_key_version = $4, auth_version = $5,
			updated_at = now(), version = version + 1
		WHERE id = $6`, materials.passwordHash, materials.ciphertext, materials.nonce, materials.keyVersion, authVersion, ownerID)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM tsw_owner_recovery_codes WHERE owner_id = $1`, ownerID); err != nil {
		return err
	}
	if err = insertRecoveryCodes(ctx, tx, ownerID, materials.codeHashes); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `
		UPDATE tsw_owner_sessions
		SET revoked_at = now(), revocation_reason = 'owner_reset'
		WHERE owner_id = $1 AND revoked_at IS NULL`, ownerID); err != nil {
		return err
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type:           audit.OwnerReset,
		Actor:          audit.ActorSystem,
		OwnerID:        ownerID,
		EntityType:     "owner",
		EntityID:       ownerID,
		Outcome:        audit.OutcomeSucceeded,
		CorrelationID:  "owner-cli",
		Details:        audit.AuthVersionDetails{AuthVersion: authVersion},
		IdempotencyKey: fmt.Sprintf("owner-reset:%s:%d", ownerID, authVersion),
	})
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	printOwnerMaterials(username, materials.secret, materials.codes)
	return nil
}

func prepareOwnerMaterials(ring auth.KeyRing, password string) (ownerMaterials, error) {
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return ownerMaterials{}, diagnostic("owner_password_invalid")
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return ownerMaterials{}, err
	}
	version, nonce, ciphertext, err := auth.EncryptTOTP([]byte(secret), ring)
	if err != nil {
		return ownerMaterials{}, err
	}
	codes, hashes, err := recoveryMaterials()
	if err != nil {
		return ownerMaterials{}, err
	}
	return ownerMaterials{
		passwordHash: passwordHash,
		secret:       secret,
		keyVersion:   version,
		nonce:        nonce,
		ciphertext:   ciphertext,
		codes:        codes,
		codeHashes:   hashes,
	}, nil
}

func insertRecoveryCodes(ctx context.Context, tx pgx.Tx, ownerID string, hashes [][32]byte) error {
	for _, hash := range hashes {
		if _, err := tx.Exec(ctx, `INSERT INTO tsw_owner_recovery_codes (owner_id, code_hash) VALUES ($1, $2)`, ownerID, hash[:]); err != nil {
			return err
		}
	}
	return nil
}

func recoveryMaterials() ([]string, [][32]byte, error) {
	codes := make([]string, 10)
	hashes := make([][32]byte, 10)
	for i := range codes {
		var err error
		codes[i], hashes[i], err = auth.NewRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
	}
	return codes, hashes, nil
}

func printOwnerMaterials(username, secret string, codes []string) {
	// These values are deliberately emitted once by the host command and never persisted in plaintext.
	fmt.Printf("owner: %s\ntotp_secret: %s\nrecovery_codes:\n", username, secret)
	for _, code := range codes {
		fmt.Println(code)
	}
}
