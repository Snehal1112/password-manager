package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/db"
)

func TestWithTx_CommitsOnSuccess(t *testing.T) {
	testDB := openTestDB(t)
	_, err := testDB.Exec(`CREATE TABLE tx_test (val TEXT)`)
	require.NoError(t, err)

	err = db.WithTx(context.Background(), testDB, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO tx_test VALUES ('hello')`)
		return err
	})
	require.NoError(t, err)

	var count int
	testDB.QueryRow(`SELECT COUNT(*) FROM tx_test`).Scan(&count)
	assert.Equal(t, 1, count)
}

func TestWithTx_RollsBackOnError(t *testing.T) {
	testDB := openTestDB(t)
	_, err := testDB.Exec(`CREATE TABLE tx_rollback (val TEXT)`)
	require.NoError(t, err)

	err = db.WithTx(context.Background(), testDB, func(tx *sql.Tx) error {
		tx.Exec(`INSERT INTO tx_rollback VALUES ('will-be-rolled-back')`)
		return fmt.Errorf("deliberate failure")
	})
	assert.Error(t, err)

	var count int
	testDB.QueryRow(`SELECT COUNT(*) FROM tx_rollback`).Scan(&count)
	assert.Equal(t, 0, count, "rows must be rolled back")
}

// openTestDB opens an in-memory SQLite database for testing.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	testDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { testDB.Close() }) //nolint:errcheck
	return testDB
}
