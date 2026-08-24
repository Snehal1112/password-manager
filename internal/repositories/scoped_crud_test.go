package repositories

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func setupScopedCRUDTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = conn.Exec(`CREATE TABLE widgets (id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, name TEXT NOT NULL)`)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec
	return conn
}

func scanWidgetName(row *sql.Row) (string, error) {
	var name string
	err := row.Scan(&name)
	return name, err
}

func TestScopedGet_VaultScopeFiltersByVault(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	vaultA, vaultB := uuid.New(), uuid.New()
	id := uuid.New()
	_, err := conn.Exec(`INSERT INTO widgets (id, vault_id, name) VALUES (?, ?, ?)`, id.String(), vaultA.String(), "widget-a")
	require.NoError(t, err)

	ctx := context.Background()
	name, err := ScopedGet(ctx, conn, `SELECT name FROM widgets WHERE id = ?`, []any{id.String()},
		model.NewVaultScope(vaultA, uuid.New()), scanWidgetName)
	require.NoError(t, err)
	require.Equal(t, "widget-a", name)

	_, err = ScopedGet(ctx, conn, `SELECT name FROM widgets WHERE id = ?`, []any{id.String()},
		model.NewVaultScope(vaultB, uuid.New()), scanWidgetName)
	require.ErrorIs(t, err, sql.ErrNoRows, "a widget in vault A must not be visible under vault B's scope")
}

func TestScopedGet_AdminScopeSeesEverything(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	id := uuid.New()
	_, err := conn.Exec(`INSERT INTO widgets (id, vault_id, name) VALUES (?, ?, ?)`, id.String(), uuid.New().String(), "widget-x")
	require.NoError(t, err)

	name, err := ScopedGet(context.Background(), conn, `SELECT name FROM widgets WHERE id = ?`, []any{id.String()},
		model.NewAdminScope(uuid.New()), scanWidgetName)
	require.NoError(t, err)
	require.Equal(t, "widget-x", name)
}

func TestScopedGet_InvalidScopeReturnsErrInvalidScope(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	_, err := ScopedGet(context.Background(), conn, `SELECT name FROM widgets WHERE id = ?`, []any{uuid.New().String()},
		model.Scope{}, scanWidgetName)
	require.ErrorIs(t, err, ErrInvalidScope)
}

func TestScopedExec_VaultScopeOnlyAffectsOwnVault(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	vaultA, vaultB := uuid.New(), uuid.New()
	id := uuid.New()
	_, err := conn.Exec(`INSERT INTO widgets (id, vault_id, name) VALUES (?, ?, ?)`, id.String(), vaultA.String(), "widget-a")
	require.NoError(t, err)

	ctx := context.Background()
	result, err := ScopedExec(ctx, conn, `UPDATE widgets SET name = ? WHERE id = ?`, []any{"renamed", id.String()},
		model.NewVaultScope(vaultB, uuid.New()))
	require.NoError(t, err)
	n, _ := result.RowsAffected()
	require.Equal(t, int64(0), n, "update scoped to the wrong vault must affect zero rows")

	result, err = ScopedExec(ctx, conn, `UPDATE widgets SET name = ? WHERE id = ?`, []any{"renamed", id.String()},
		model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	n, _ = result.RowsAffected()
	require.Equal(t, int64(1), n)
}

func TestScopedList_VaultScopeFiltersRows(t *testing.T) {
	conn := setupScopedCRUDTestDB(t)
	vaultA, vaultB := uuid.New(), uuid.New()
	_, err := conn.Exec(`INSERT INTO widgets (id, vault_id, name) VALUES (?, ?, ?), (?, ?, ?)`,
		uuid.New().String(), vaultA.String(), "a1",
		uuid.New().String(), vaultB.String(), "b1")
	require.NoError(t, err)

	rows, err := ScopedList(context.Background(), conn, `SELECT name FROM widgets WHERE 1=1`, nil,
		model.NewVaultScope(vaultA, uuid.New()), "", nil, func(r *sql.Rows) (string, error) {
			var name string
			return name, r.Scan(&name)
		})
	require.NoError(t, err)
	require.Equal(t, []string{"a1"}, rows)
}
