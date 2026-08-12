// Edge tests to push internal/db coverage over 80%.
package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// ---------------------------------------------------------------------------
// TagRepository – additional error paths
// ---------------------------------------------------------------------------

func TestTagRepository_ReplaceTags_DBError(t *testing.T) {
	db := newTagDB(t)
	repo := NewTagRepository[testEntity](NewConn(db, SQLite), "test_tags", "entity_id")
	id := uuid.New()

	// Prime a tag so there is something to delete.
	require.NoError(t, repo.AddTags(context.Background(), id, []string{"existing"}))

	// Now close the DB so all subsequent operations fail.
	db.Close() //nolint:errcheck,gosec

	err := repo.ReplaceTags(context.Background(), id, []string{"new"})
	assert.Error(t, err)
}

func TestTagRepository_AddTags_DBClosed(t *testing.T) {
	// Close the DB before AddTags to force a BeginTx error.
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	_, err = sqlDB.Exec(`
		CREATE TABLE tight_tags2 (
			entity_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (entity_id, tag)
		)
	`)
	require.NoError(t, err)
	sqlDB.Close() //nolint:errcheck,gosec // Force failure.

	repo := NewTagRepository[testEntity](NewConn(sqlDB, SQLite), "tight_tags2", "entity_id")
	id := uuid.New()

	err = repo.AddTags(context.Background(), id, []string{"atag"})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// WithTx – begin transaction error path
// ---------------------------------------------------------------------------

func TestWithTx_BeginTxError(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	// Close before use so BeginTx fails.
	db.Close() //nolint:errcheck,gosec

	err = WithTx(context.Background(), db, func(_ *sql.Tx) error { return nil })
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// OpenDatabase – pool configure error path
// ---------------------------------------------------------------------------

func TestOpenDatabase_PoolConfigureInvalidMaxOpen(t *testing.T) {
	log := logging.InitLogger()
	repo := NewRepository(log)

	// MaxOpenConns < MaxIdleConns can trigger a configuration warning but does not
	// return an error from configureConnectionPool in the current implementation.
	// Ensure no panic and that the returned db is valid.
	cfg := &DatabaseConfig{
		DriverName:       "sqlite3",
		ConnectionString: ":memory:",
		PoolConfig: ConnectionPoolConfig{
			MaxOpenConns: 1,
			MaxIdleConns: 1,
		},
	}
	db, err := repo.OpenDatabase(cfg)
	require.NoError(t, err)
	require.NotNil(t, db)
	db.Close() //nolint:errcheck,gosec
}

// ---------------------------------------------------------------------------
// seedDefaultVault idempotency
// ---------------------------------------------------------------------------

func TestSeedDefaultVault_CalledTwice(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())

	// seedDefaultVault is already called by InitializeDB; calling it again must be a no-op.
	require.NoError(t, repo.seedDefaultVault(globalDB))
}

// ---------------------------------------------------------------------------
// finalizeVaultIndexes idempotency
// ---------------------------------------------------------------------------

func TestFinalizeVaultIndexes_Idempotent(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())

	// Indexes already exist; calling again must be a no-op (CREATE INDEX IF NOT EXISTS).
	require.NoError(t, repo.finalizeVaultIndexes(globalDB))
}

// ---------------------------------------------------------------------------
// HealthCheck against closed DB
// ---------------------------------------------------------------------------

func TestHealthCheck_ClosedDB(t *testing.T) {
	// Set the global DB to a newly created, immediately closed db.
	closed, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	closed.Close() //nolint:errcheck,gosec

	prev := globalDB
	globalDB = closed
	defer func() { globalDB = prev }()

	err = HealthCheck(context.Background())
	assert.Error(t, err)
}
