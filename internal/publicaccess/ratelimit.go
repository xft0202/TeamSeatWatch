package publicaccess

import (
	"context"
	"crypto/sha256"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Limit is one opaque subject bucket in the fixed public-access policy.
type Limit struct {
	Kind   string
	Hash   [32]byte
	Window time.Duration
	Max    int
}

// SubjectFingerprint keeps rate-limit subjects unlinkable across policy domains.
func SubjectFingerprint(kind, value string) [32]byte {
	return sha256.Sum256([]byte("teamseatwatch:public-rate:v1\x00" + kind + "\x00" + value))
}

// Check atomically consumes all supplied buckets. Subject ordering is stable so
// card+IP and token+IP requests cannot deadlock each other.
func Check(ctx context.Context, pool *pgxpool.Pool, limits []Limit, now time.Time) (bool, error) {
	if pool == nil || len(limits) == 0 {
		return false, pgx.ErrTxClosed
	}
	ordered := append([]Limit(nil), limits...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Kind == ordered[j].Kind {
			return string(ordered[i].Hash[:]) < string(ordered[j].Hash[:])
		}
		return ordered[i].Kind < ordered[j].Kind
	})
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	for _, limit := range ordered {
		if limit.Kind == "" || limit.Window <= 0 || limit.Max <= 0 || limit.Max > 120 {
			return false, pgx.ErrTxClosed
		}
		start := now.UTC().Truncate(limit.Window)
		end := start.Add(limit.Window)
		if _, err := tx.Exec(ctx, `
			INSERT INTO tsw_rate_limit_buckets(kind,subject_hash,window_started_at,window_ends_at,expires_at)
			VALUES ($1,$2,$3,$4,$4)
			ON CONFLICT (kind,subject_hash,window_started_at) DO NOTHING`, limit.Kind, limit.Hash[:], start, end); err != nil {
			return false, err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count FROM tsw_rate_limit_buckets WHERE kind=$1 AND subject_hash=$2 AND window_started_at=$3 FOR UPDATE`, limit.Kind, limit.Hash[:], start).Scan(&count); err != nil {
			return false, err
		}
		if count >= limit.Max {
			if err := tx.Commit(ctx); err != nil {
				return false, err
			}
			return false, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE tsw_rate_limit_buckets SET count=count+1 WHERE kind=$1 AND subject_hash=$2 AND window_started_at=$3`, limit.Kind, limit.Hash[:], start); err != nil {
			return false, err
		}
	}
	return true, tx.Commit(ctx)
}
