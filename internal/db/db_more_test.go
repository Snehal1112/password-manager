// Package db contains additional unit tests targeting the uncovered paths in
// db.go and tags.go. All tests use an in-memory SQLite database.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// ---------------------------------------------------------------------------
// Helper: fresh initialized in-memory DBRepository
// ---------------------------------------------------------------------------

func newInitializedRepo(t *testing.T) *DBRepository {
	t.Helper()
	viper.Set("database.connection", ":memory:")
	t.Cleanup(viper.Reset)
	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())
	return repo
}

// ---------------------------------------------------------------------------
// GetDB
// ---------------------------------------------------------------------------

func TestGetDB_ReturnsNonNil(t *testing.T) {
	repo := newInitializedRepo(t)
	db := repo.GetDB()
	assert.NotNil(t, db, "GetDB must return a non-nil *sql.DB after InitializeDB")
}

func TestGetDB_BeforeInit(t *testing.T) {
	log := logging.InitLogger()
	repo := NewRepository(log)
	// Before InitializeDB the internal db field is nil
	assert.Nil(t, repo.GetDB())
}

// ---------------------------------------------------------------------------
// OpenDatabase
// ---------------------------------------------------------------------------

func TestOpenDatabase_ValidSQLite(t *testing.T) {
	log := logging.InitLogger()
	repo := NewRepository(log)

	cfg := &DatabaseConfig{
		DriverName:       "sqlite3",
		ConnectionString: ":memory:",
		PoolConfig: ConnectionPoolConfig{
			MaxOpenConns:    5,
			MaxIdleConns:    2,
			ConnMaxLifetime: time.Minute,
			ConnMaxIdleTime: 30 * time.Second,
		},
	}
	db, err := repo.OpenDatabase(cfg)
	require.NoError(t, err)
	assert.NotNil(t, db)
	db.Close() //nolint:errcheck,gosec
}

func TestOpenDatabase_InvalidDriver(t *testing.T) {
	log := logging.InitLogger()
	repo := NewRepository(log)

	cfg := &DatabaseConfig{
		DriverName:       "noexist_driver",
		ConnectionString: ":memory:",
		PoolConfig:       ConnectionPoolConfig{MaxOpenConns: 1, MaxIdleConns: 1},
	}
	db, err := repo.OpenDatabase(cfg)
	// sql.Open itself doesn't fail for unknown drivers (it's lazy), but
	// configureConnectionPool may or the driver won't be found on Ping.
	// Either way we expect no panic.
	if err == nil && db != nil {
		db.Close() //nolint:errcheck,gosec
	}
}

// ---------------------------------------------------------------------------
// LoadDatabaseConfig / loadDatabaseConfig
// ---------------------------------------------------------------------------

func TestLoadDatabaseConfig_SQLiteDefault(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	cfg, err := repo.LoadDatabaseConfig()
	require.NoError(t, err)
	assert.Equal(t, ":memory:", cfg.ConnectionString)
	assert.Equal(t, "sqlite3", cfg.DriverName)
}

func TestLoadDatabaseConfig_ExplicitDriver(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	viper.Set("database.driver", "sqlite3")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	cfg, err := repo.LoadDatabaseConfig()
	require.NoError(t, err)
	assert.Equal(t, "sqlite3", cfg.DriverName)
}

func TestLoadDatabaseConfig_EmptyConnString(t *testing.T) {
	viper.Set("database.connection", "")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	_, err := repo.LoadDatabaseConfig()
	assert.Error(t, err)
}

func TestLoadDatabaseConfig_ProductionEnvironment(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	viper.Set("environment", "prod")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	cfg, err := repo.LoadDatabaseConfig()
	require.NoError(t, err)
	assert.Equal(t, "prod", cfg.Environment)
	assert.Equal(t, 50, cfg.PoolConfig.MaxOpenConns)
}

func TestLoadDatabaseConfig_StagingEnvironment(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	viper.Set("environment", "staging")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	cfg, err := repo.LoadDatabaseConfig()
	require.NoError(t, err)
	// staging falls through to the default branch (dev settings)
	assert.Equal(t, 10, cfg.PoolConfig.MaxOpenConns)
}

func TestLoadDatabaseConfig_ProductionAlias(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	viper.Set("environment", "production")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	cfg, err := repo.LoadDatabaseConfig()
	require.NoError(t, err)
	assert.Equal(t, 50, cfg.PoolConfig.MaxOpenConns)
}

// ---------------------------------------------------------------------------
// CloseDB edge cases
// ---------------------------------------------------------------------------

func TestCloseDB_NilDB(t *testing.T) {
	log := logging.InitLogger()
	repo := NewRepository(log)
	// repo.db is nil — must return nil without panicking
	err := repo.CloseDB()
	assert.NoError(t, err)
}

func TestCloseDB_AfterInitializeDB(t *testing.T) {
	viper.Set("database.connection", "./test_close2.db")
	defer func() {
		viper.Reset()
		os.Remove("./test_close2.db") //nolint:errcheck,gosec
	}()

	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())
	require.NoError(t, repo.CloseDB())
}

// ---------------------------------------------------------------------------
// Performance metrics
// ---------------------------------------------------------------------------

func TestRecordQueryExecution(t *testing.T) {
	ResetPerformanceMetrics()

	RecordQueryExecution(50 * time.Millisecond)
	RecordQueryExecution(200 * time.Millisecond) // slow query

	m := GetPerformanceMetrics(nil)
	assert.Equal(t, int64(2), m.QueryCount)
	assert.Equal(t, int64(1), m.SlowQueryCount)
	assert.Greater(t, int64(m.TotalQueryTime), int64(0))
	assert.Greater(t, int64(m.AverageQueryTime), int64(0))
}

func TestGetPerformanceMetrics_ReturnsCopy(t *testing.T) {
	ResetPerformanceMetrics()
	m1 := GetPerformanceMetrics(nil)

	RecordQueryExecution(10 * time.Millisecond)
	m2 := GetPerformanceMetrics(nil)

	// m1 is a snapshot and must not have changed
	assert.Equal(t, int64(0), m1.QueryCount)
	assert.Equal(t, int64(1), m2.QueryCount)
}

func TestRecordQueryExecution_CustomSlowQueryThreshold(t *testing.T) {
	SetSlowQueryThreshold(300 * time.Millisecond)
	defer SetSlowQueryThreshold(100 * time.Millisecond) // restore default for other tests

	ResetPerformanceMetrics()

	RecordQueryExecution(200 * time.Millisecond) // below the 300ms threshold, not slow
	RecordQueryExecution(350 * time.Millisecond) // above the 300ms threshold, slow

	m := GetPerformanceMetrics(nil)
	assert.Equal(t, int64(2), m.QueryCount)
	assert.Equal(t, int64(1), m.SlowQueryCount, "only the 350ms query should count as slow under a 300ms threshold")
}

func TestResetPerformanceMetrics(t *testing.T) {
	RecordQueryExecution(100 * time.Millisecond)
	RecordQueryExecution(200 * time.Millisecond)

	ResetPerformanceMetrics()

	m := GetPerformanceMetrics(nil)
	assert.Equal(t, int64(0), m.QueryCount)
	assert.Equal(t, int64(0), m.SlowQueryCount)
	assert.Equal(t, time.Duration(0), m.TotalQueryTime)
}

func TestGetConnectionPoolStats_NoDBInitialized(t *testing.T) {
	repo := &DBRepository{}

	stats := repo.GetConnectionPoolStats()
	errVal, ok := stats["error"]
	assert.True(t, ok, "should return error key when the repository has no db")
	assert.Equal(t, "database not initialized", errVal)
}

func TestGetConnectionPoolStats_WithDB(t *testing.T) {
	repo := newInitializedRepo(t)

	stats := repo.GetConnectionPoolStats()
	// When DB is non-nil the error key must be absent
	_, hasErr := stats["error"]
	assert.False(t, hasErr, "no error key expected once the repository db is initialized")
	_, hasOpen := stats["open_connections"]
	assert.True(t, hasOpen)
}

// ---------------------------------------------------------------------------
// HealthCheck
// ---------------------------------------------------------------------------

func TestHealthCheck_NilDB(t *testing.T) {
	repo := &DBRepository{}

	err := repo.HealthCheck(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestHealthCheck_WithDB(t *testing.T) {
	repo := newInitializedRepo(t)

	err := repo.HealthCheck(context.Background())
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// seedBootstrapToken edge cases
// ---------------------------------------------------------------------------

func TestSeedBootstrapToken_EmptyToken(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	viper.Set("bootstrap_token", "")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())
	// No rows in bootstrap_tokens but no error
	var n int
	require.NoError(t, repo.GetDB().QueryRow("SELECT COUNT(*) FROM bootstrap_tokens").Scan(&n))
	assert.Equal(t, 0, n)
}

func TestSeedBootstrapToken_Seeded(t *testing.T) {
	token := "test-token-" + uuid.NewString()
	viper.Set("database.connection", ":memory:")
	viper.Set("bootstrap_token", token)
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())

	var n int
	require.NoError(t, repo.GetDB().QueryRow("SELECT COUNT(*) FROM bootstrap_tokens WHERE token = ?", token).Scan(&n))
	assert.Equal(t, 1, n)
}

func TestSeedBootstrapToken_Idempotent(t *testing.T) {
	token := "idempotent-token-" + uuid.NewString()
	viper.Set("database.connection", ":memory:")
	viper.Set("bootstrap_token", token)
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())

	// Calling seedBootstrapToken again must not error or duplicate
	require.NoError(t, repo.seedBootstrapToken(repo.GetDB()))

	var n int
	require.NoError(t, repo.GetDB().QueryRow("SELECT COUNT(*) FROM bootstrap_tokens WHERE token = ?", token).Scan(&n))
	assert.Equal(t, 1, n)
}

// ---------------------------------------------------------------------------
// seedAuditConfig edge cases
// ---------------------------------------------------------------------------

func TestSeedAuditConfig_Idempotent(t *testing.T) {
	repo := newInitializedRepo(t)

	// Call again — must not error or duplicate
	require.NoError(t, repo.seedAuditConfig(repo.GetDB()))

	var n int
	require.NoError(t, repo.GetDB().QueryRow("SELECT COUNT(*) FROM audit_config WHERE key = 'retention_days'").Scan(&n))
	assert.Equal(t, 1, n)
}

// ---------------------------------------------------------------------------
// TagRepository – ReplaceTags (0% covered)
// ---------------------------------------------------------------------------

func newTagDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS test_tags (
			entity_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (entity_id, tag)
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
	return db
}

type testEntity struct{}

func TestTagRepository_ReplaceTags_AddsNew(t *testing.T) {
	db := newTagDB(t)
	repo := NewTagRepository[testEntity](NewConn(db, SQLite), "test_tags", "entity_id")
	ctx := context.Background()

	id := uuid.New()
	require.NoError(t, repo.ReplaceTags(ctx, id, []string{"a", "b", "c"}))

	tags, err := repo.GetTags(ctx, id)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a", "b", "c"}, tags)
}

func TestTagRepository_ReplaceTags_Deduplicates(t *testing.T) {
	db := newTagDB(t)
	repo := NewTagRepository[testEntity](NewConn(db, SQLite), "test_tags", "entity_id")
	ctx := context.Background()

	id := uuid.New()
	require.NoError(t, repo.ReplaceTags(ctx, id, []string{"x", "x", "y", ""}))

	tags, err := repo.GetTags(ctx, id)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"x", "y"}, tags)
}

func TestTagRepository_ReplaceTags_OverwritesPrevious(t *testing.T) {
	db := newTagDB(t)
	repo := NewTagRepository[testEntity](NewConn(db, SQLite), "test_tags", "entity_id")
	ctx := context.Background()

	id := uuid.New()
	require.NoError(t, repo.AddTags(ctx, id, []string{"old1", "old2"}))
	require.NoError(t, repo.ReplaceTags(ctx, id, []string{"new1"}))

	tags, err := repo.GetTags(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []string{"new1"}, tags)
}

func TestTagRepository_ReplaceTags_EmptySliceClearsTags(t *testing.T) {
	db := newTagDB(t)
	repo := NewTagRepository[testEntity](NewConn(db, SQLite), "test_tags", "entity_id")
	ctx := context.Background()

	id := uuid.New()
	require.NoError(t, repo.AddTags(ctx, id, []string{"a", "b"}))
	require.NoError(t, repo.ReplaceTags(ctx, id, []string{}))

	tags, err := repo.GetTags(ctx, id)
	require.NoError(t, err)
	assert.Empty(t, tags)
}

// ---------------------------------------------------------------------------
// WithTx helper
// ---------------------------------------------------------------------------

func TestWithTx_Commit(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck

	_, err = db.Exec(`CREATE TABLE nums (v INTEGER)`)
	require.NoError(t, err)

	err = WithTx(context.Background(), db, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO nums (v) VALUES (42)`)
		return err
	})
	require.NoError(t, err)

	var v int
	require.NoError(t, db.QueryRow(`SELECT v FROM nums`).Scan(&v))
	assert.Equal(t, 42, v)
}

func TestWithTx_Rollback(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close() //nolint:errcheck

	_, err = db.Exec(`CREATE TABLE nums (v INTEGER)`)
	require.NoError(t, err)

	err = WithTx(context.Background(), db, func(tx *sql.Tx) error {
		_, _ = tx.Exec(`INSERT INTO nums (v) VALUES (99)`)
		return fmt.Errorf("simulated failure")
	})
	assert.Error(t, err)

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM nums`).Scan(&count))
	assert.Equal(t, 0, count, "transaction must have been rolled back")
}

// ---------------------------------------------------------------------------
// InitializeDB in-memory path (covers the remaining branches)
// ---------------------------------------------------------------------------

func TestInitializeDB_InMemory(t *testing.T) {
	viper.Set("database.connection", ":memory:")
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())
	assert.NotNil(t, repo.GetDB())

	// Verify core tables were created
	tables := []string{"users", "secrets", "keys", "certificates", "audit_logs", "vaults"}
	for _, tbl := range tables {
		var name string
		err := repo.GetDB().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl,
		).Scan(&name)
		assert.NoError(t, err, "table %s should exist", tbl)
		assert.Equal(t, tbl, name)
	}
}

func TestInitializeDB_WithBootstrapToken(t *testing.T) {
	token := "bt-" + uuid.NewString()
	viper.Set("database.connection", ":memory:")
	viper.Set("bootstrap_token", token)
	defer viper.Reset()

	log := logging.InitLogger()
	repo := NewRepository(log)
	require.NoError(t, repo.InitializeDB())

	var n int
	require.NoError(t, repo.GetDB().QueryRow(
		"SELECT COUNT(*) FROM bootstrap_tokens WHERE token = ?", token,
	).Scan(&n))
	assert.Equal(t, 1, n)
}
