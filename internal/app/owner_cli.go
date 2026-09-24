package app

import (
	"context"
	"fmt"
	"strings"

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
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if command == "owner-create" {
		return createOwner(ctx, pool, login, password)
	}
	return resetOwner(ctx, pool, login, password)
}

func createOwner(ctx context.Context, pool *pgxpool.Pool, username, password string) error {
	materials, err := prepareOwnerMaterials(password)
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
			username, password_hash, password_changed_at
		) VALUES ($1, $2, now())
		RETURNING id`, username, materials.passwordHash).Scan(&ownerID)
	if err != nil {
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
	printOwnerMaterials(username)
	return nil
}

func resetOwner(ctx context.Context, pool *pgxpool.Pool, username, password string) error {
	materials, err := prepareOwnerMaterials(password)
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
		SET password_hash = $1, password_changed_at = now(), auth_version = $2,
			updated_at = now(), version = version + 1
		WHERE id = $3`, materials.passwordHash, authVersion, ownerID)
	if err != nil {
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
	printOwnerMaterials(username)
	return nil
}

func prepareOwnerMaterials(password string) (ownerMaterials, error) {
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return ownerMaterials{}, diagnostic("owner_password_invalid")
	}
	return ownerMaterials{passwordHash: passwordHash}, nil
}

func printOwnerMaterials(username string) {
	fmt.Printf("owner: %s\n", username)
}
