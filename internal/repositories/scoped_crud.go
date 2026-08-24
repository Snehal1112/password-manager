package repositories

import (
	"context"
	"database/sql"

	rvdb "rocketvault/internal/db"
	"rocketvault/model"
)

// ScopedGet runs query (a "SELECT ... WHERE <predicate>" missing only its
// trailing scope clause) with the scope predicate appended, and scans the
// single resulting row with scan. Returns ErrInvalidScope for an
// unauthorizable scope, sql.ErrNoRows for no match — including a match that
// exists but is outside the given scope, which is indistinguishable by
// design (no existence oracle).
func ScopedGet[T any](ctx context.Context, conn rvdb.DBTX, query string, args []any, scope model.Scope, scan func(*sql.Row) (T, error)) (T, error) {
	var zero T
	predicate, predArgs, err := scopePredicate(scope)
	if err != nil {
		return zero, err
	}
	row := conn.QueryRowContext(ctx, query+" AND "+predicate, append(append([]any{}, args...), predArgs...)...)
	return scan(row)
}

// ScopedExec runs query (an "UPDATE ..." or "DELETE ..." missing only its
// trailing scope clause) with the scope predicate appended.
func ScopedExec(ctx context.Context, conn rvdb.DBTX, query string, args []any, scope model.Scope) (sql.Result, error) {
	predicate, predArgs, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}
	return conn.ExecContext(ctx, query+" AND "+predicate, append(append([]any{}, args...), predArgs...)...)
}

// ScopedList runs query (a "SELECT ... WHERE <predicate>" missing only its
// trailing scope clause) with the scope predicate appended, scanning every
// row with scan. tail, if non-empty, is appended after the scope predicate —
// e.g. " ORDER BY name ASC LIMIT ? OFFSET ?" — with its own placeholders
// bound by tailArgs; pass "", nil when the query needs no such clause.
func ScopedList[T any](ctx context.Context, conn rvdb.DBTX, query string, args []any, scope model.Scope, tail string, tailArgs []any, scan func(*sql.Rows) (T, error)) ([]T, error) {
	predicate, predArgs, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}
	fullArgs := append(append(append([]any{}, args...), predArgs...), tailArgs...)
	rows, err := conn.QueryContext(ctx, query+" AND "+predicate+tail, fullArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
