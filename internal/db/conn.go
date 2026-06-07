package db

import (
	"context"
	"database/sql"
)

// DB is the repository-facing database handle. It is satisfied by *Conn, which
// rebinds "?" placeholders to the active dialect before delegating to the
// underlying *sql.DB. Repositories depend on this interface instead of *sql.DB
// so every query is forced through the rebinding layer at compile time.
type DB interface {
	DBTX
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error)
}

// Conn wraps a *sql.DB with a Dialect, rebinding queries on every call.
type Conn struct {
	db      *sql.DB
	dialect Dialect
}

// NewConn returns a dialect-aware wrapper over an existing *sql.DB. The dialect
// determines whether "?" placeholders are rewritten to "$1, $2, ..." (Postgres)
// or left as-is (SQLite).
func NewConn(db *sql.DB, dialect Dialect) *Conn {
	return &Conn{db: db, dialect: dialect}
}

// Dialect returns the dialect this connection uses.
func (c *Conn) Dialect() Dialect { return c.dialect }

// Underlying returns the raw *sql.DB for callers that genuinely need it (pool
// stats, health checks). Queries should go through the Conn methods instead.
func (c *Conn) Underlying() *sql.DB { return c.db }

// ExecContext rebinds the query, then delegates.
func (c *Conn) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.db.ExecContext(ctx, c.dialect.Rebind(query), args...)
}

// QueryContext rebinds the query, then delegates.
func (c *Conn) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return c.db.QueryContext(ctx, c.dialect.Rebind(query), args...)
}

// QueryRowContext rebinds the query, then delegates.
func (c *Conn) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return c.db.QueryRowContext(ctx, c.dialect.Rebind(query), args...)
}

// BeginTx starts a transaction whose queries are also rebound to the dialect.
func (c *Conn) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := c.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Tx{tx: tx, dialect: c.dialect}, nil
}

// Tx wraps a *sql.Tx with a Dialect, rebinding queries the same way as Conn.
type Tx struct {
	tx      *sql.Tx
	dialect Dialect
}

// ExecContext rebinds the query, then delegates.
func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, t.dialect.Rebind(query), args...)
}

// QueryContext rebinds the query, then delegates.
func (t *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, t.dialect.Rebind(query), args...)
}

// QueryRowContext rebinds the query, then delegates.
func (t *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(ctx, t.dialect.Rebind(query), args...)
}

// Commit commits the underlying transaction.
func (t *Tx) Commit() error { return t.tx.Commit() }

// Rollback rolls back the underlying transaction.
func (t *Tx) Rollback() error { return t.tx.Rollback() }

// Compile-time checks that the wrappers satisfy the repository interfaces.
var (
	_ DB   = (*Conn)(nil)
	_ DBTX = (*Tx)(nil)
)
