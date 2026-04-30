package db

import (
	"context"
	"database/sql"
	"fmt"
)

// DBTX is satisfied by both *sql.DB and *sql.Tx, allowing repositories
// to work inside or outside a transaction.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// WithTx runs fn inside a transaction. Commits on success, rolls back on error.
func WithTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %w (original: %v)", rbErr, err)
		}
		return err
	}
	return tx.Commit()
}
