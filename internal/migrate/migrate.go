// Package migrate 在启动时应用嵌入的 SQL 迁移,用 schema_migrations 台账保证幂等。
package migrate

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	dbfs "github.com/SilasSolivagus/base-servers/db"
)

func Apply(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
	); err != nil {
		return fmt.Errorf("ensure ledger: %w", err)
	}

	entries, err := dbfs.FS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, name,
		).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := dbfs.FS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		up := upSection(string(body))
		if up == "" {
			return fmt.Errorf("migration %s has no +goose Up section", name)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, up); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// upSection 取 "-- +goose Up" 与 "-- +goose Down" 之间的 SQL。
func upSection(s string) string {
	up := "-- +goose Up"
	down := "-- +goose Down"
	i := strings.Index(s, up)
	if i < 0 {
		return ""
	}
	rest := s[i+len(up):]
	if j := strings.Index(rest, down); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}
