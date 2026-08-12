// Package db dialect support centralizes every place the SQL differs between
// SQLite and PostgreSQL. Repositories ask the Dialect instead of hardcoding one
// engine, so adding or fixing engine-specific behavior happens in one file.
package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/mattn/go-sqlite3"
)

// Dialect identifies which SQL engine the connection talks to.
type Dialect int

const (
	// SQLite is the default engine, used for development and tests.
	SQLite Dialect = iota
	// Postgres is the production engine.
	Postgres
)

// DialectFromDriver maps a database/sql driver name to a Dialect.
// Unknown drivers default to SQLite, matching the connection default.
func DialectFromDriver(driver string) Dialect {
	switch driver {
	case "postgres":
		return Postgres
	default:
		return SQLite
	}
}

// String returns the dialect name for logging.
func (d Dialect) String() string {
	if d == Postgres {
		return "postgres"
	}
	return "sqlite"
}

// BindType returns the sqlx bind type used to rewrite "?" placeholders.
// SQLite keeps "?"; Postgres needs "$1, $2, ...".
func (d Dialect) BindType() int {
	if d == Postgres {
		return sqlx.DOLLAR
	}
	return sqlx.QUESTION
}

// Rebind rewrites a query written with "?" placeholders into the form this
// dialect expects. On SQLite this is a no-op.
func (d Dialect) Rebind(query string) string {
	return sqlx.Rebind(d.BindType(), query)
}

// UpsertIgnore builds an insert that silently skips rows violating a unique
// constraint. SQLite uses "INSERT OR IGNORE"; Postgres uses
// "INSERT ... ON CONFLICT DO NOTHING". The conflict target lets Postgres know
// which unique constraint to ignore.
func (d Dialect) UpsertIgnore(table, columns, placeholders, conflictTarget string) string {
	if d == Postgres {
		return fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING",
			table, columns, placeholders, conflictTarget,
		)
	}
	return fmt.Sprintf(
		"INSERT OR IGNORE INTO %s (%s) VALUES (%s)",
		table, columns, placeholders,
	)
}

// IsConstraintErr reports whether err is a unique/constraint violation.
// SQLite surfaces sqlite3.ErrConstraint; Postgres uses error code 23505.
func (d Dialect) IsConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code == sqlite3.ErrConstraint
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505" // unique_violation
	}
	return false
}

// IsDuplicateColumnErr reports whether err means a column already exists,
// letting migrateSchema stay idempotent across engines.
func (d Dialect) IsDuplicateColumnErr(err error) bool {
	if err == nil {
		return false
	}
	// SQLite reports "duplicate column name: <col>".
	if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return true
	}
	// PostgreSQL error code 42701 = duplicate_column.
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "42701"
	}
	return false
}

// TimestampType returns the column type for timestamp columns. SQLite is
// flexible, but Postgres rejects "DATETIME", so both engines use "TIMESTAMP".
func (d Dialect) TimestampType() string {
	return "TIMESTAMP"
}

// ColumnExists reports whether the given column exists on the table. SQLite uses
// PRAGMA table_info; Postgres queries information_schema.
func (d Dialect) ColumnExists(ctx context.Context, q DBTX, table, column string) (bool, error) {
	if d == Postgres {
		var n int
		err := q.QueryRowContext(ctx,
			d.Rebind(`SELECT COUNT(*) FROM information_schema.columns
			 WHERE table_name = ? AND column_name = ?`),
			table, column,
		).Scan(&n)
		if err != nil {
			return false, fmt.Errorf("check column %s.%s: %w", table, column, err)
		}
		return n > 0, nil
	}

	rows, err := q.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("check column %s.%s: %w", table, column, err)
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var (
			cid        int
			name       string
			ctype      string
			notnull    int
			dfltValue  any
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &primaryKey); err != nil {
			return false, fmt.Errorf("scan column info for %s: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
