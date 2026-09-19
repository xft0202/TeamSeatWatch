package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
)

// RequiredVersion is the schema version required by this release.
const RequiredVersion int64 = 1

//go:embed sql/*.sql
var sqlFiles embed.FS

func Apply(ctx context.Context, db *sql.DB) error {
	files, err := fs.Sub(sqlFiles, "sql")
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, files)
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
