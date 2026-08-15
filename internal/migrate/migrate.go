// Package migrate runs the numbered .sql files in order, once each.
//
// It is deliberately not a framework: files are applied lexically, the applied
// set is recorded in schema_migrations, and a statement splitter that handles
// plain "--" comments is the whole parser. MySQL commits DDL implicitly, so a
// file that fails halfway stays half applied — migrations are written to be
// safe to re-run instead of relying on a rollback that does not exist.
package migrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jmoiron/sqlx"
)

const createSchemaMigrations = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    VARCHAR(128) NOT NULL,
    applied_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (version)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4`

// Apply runs every unapplied .sql file in dir, in lexical order.
func Apply(ctx context.Context, db *sqlx.DB, dir string) error {
	if _, err := db.ExecContext(ctx, createSchemaMigrations); err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("migrate: read dir %q: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	var applied []string
	if err := db.SelectContext(ctx, &applied, "SELECT version FROM schema_migrations"); err != nil {
		return fmt.Errorf("migrate: load applied versions: %w", err)
	}
	done := make(map[string]bool, len(applied))
	for _, v := range applied {
		done[v] = true
	}

	for _, name := range files {
		if done[name] {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("migrate: read %q: %w", name, err)
		}
		for i, stmt := range SplitStatements(string(body)) {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migrate: %s statement %d: %w", name, i+1, err)
			}
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES (?)", name); err != nil {
			return fmt.Errorf("migrate: record %q: %w", name, err)
		}
	}
	return nil
}

// SplitStatements cuts a file into statements on ";" and drops comment-only
// lines. Seed values must not contain a literal ";" — that is the one rule
// this parser asks of the SQL files it reads.
func SplitStatements(body string) []string {
	var (
		out []string
		cur strings.Builder
	)
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		cur.WriteString(trimmed)
		cur.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			stmt := strings.TrimSpace(cur.String())
			stmt = strings.TrimSuffix(stmt, ";")
			if stmt != "" {
				out = append(out, stmt)
			}
			cur.Reset()
		}
	}
	if stmt := strings.TrimSpace(cur.String()); stmt != "" {
		out = append(out, stmt)
	}
	return out
}
