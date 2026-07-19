package softdelete

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestConn wraps a *sql.DB in a dialect-aware *rvdb.Conn. Tests always use
// SQLite so the SQLite dialect is used.
func newTestConn(t *testing.T, rawDB *sql.DB) *rvdb.Conn {
	t.Helper()
	return rvdb.NewConn(rawDB, rvdb.SQLite)
}

func createPurgeTables(db *sql.DB) {
	for _, table := range []string{"secrets", "keys", "certificates"} {
		_, _ = db.Exec(fmt.Sprintf(`CREATE TABLE %s (
			id TEXT PRIMARY KEY,
			deleted_at DATETIME,
			purge_protection BOOLEAN DEFAULT FALSE
		)`, table))
	}
}

func testLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func testConfig() config.SoftDeleteConfig {
	return config.SoftDeleteConfig{
		Enabled:       true,
		RetentionDays: 30,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. NewPurgeScheduler sets all fields correctly.
func TestNewPurgeScheduler(t *testing.T) {
	rawDB := newTestDB(t)
	conn := newTestConn(t, rawDB)
	cfg := testConfig()
	log := testLogger()

	s := NewPurgeScheduler(conn, cfg, log)

	require.NotNil(t, s)
	assert.Equal(t, conn, s.db)
	assert.Equal(t, cfg, s.cfg)
	assert.Equal(t, log, s.log)
	assert.NotNil(t, s.done)
}

// 2. Start then immediately Stop does not panic.
func TestStartStop(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	s := NewPurgeScheduler(conn, testConfig(), testLogger())

	assert.NotPanics(t, func() {
		s.Start(context.Background())
		// Give the goroutine a moment to start and call purgeExpired once.
		time.Sleep(10 * time.Millisecond)
		s.Stop()
	})
}

// 3. purgeExpired with missing tables logs errors but does not panic.
func TestPurgeExpired_EmptyDB(t *testing.T) {
	// DB has no tables; every ExecContext will fail.
	rawDB := newTestDB(t)
	conn := newTestConn(t, rawDB)

	s := NewPurgeScheduler(conn, testConfig(), testLogger())

	// purgeExpired is called inside the goroutine launched by Start.
	// We just ensure no panic; errors are logged internally.
	assert.NotPanics(t, func() {
		s.Start(context.Background())
		time.Sleep(20 * time.Millisecond)
		s.Stop()
	})
}

// 4. Rows older than the retention window are deleted; newer rows are kept.
func TestPurgeExpired_WithData(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)

	// Insert one expired row (deleted 60 days ago) and one live row per table.
	expired := time.Now().AddDate(0, 0, -60).Format("2006-01-02 15:04:05")
	recent := time.Now().AddDate(0, 0, -5).Format("2006-01-02 15:04:05")

	for _, table := range []string{"secrets", "keys", "certificates"} {
		_, err := rawDB.Exec(
			fmt.Sprintf(`INSERT INTO %s (id, deleted_at, purge_protection) VALUES (?, ?, ?)`, table),
			"expired-"+table, expired, false,
		)
		require.NoError(t, err)

		_, err = rawDB.Exec(
			fmt.Sprintf(`INSERT INTO %s (id, deleted_at, purge_protection) VALUES (?, ?, ?)`, table),
			"recent-"+table, recent, false,
		)
		require.NoError(t, err)

		_, err = rawDB.Exec(
			fmt.Sprintf(`INSERT INTO %s (id, deleted_at, purge_protection) VALUES (?, ?, ?)`, table),
			"protected-"+table, expired, true,
		)
		require.NoError(t, err)
	}

	// RetentionDays=30 — the 60-day-old rows are past the threshold.
	conn := newTestConn(t, rawDB)
	s := NewPurgeScheduler(conn, testConfig(), testLogger())
	s.Start(context.Background())

	// Give the goroutine enough time to run purgeExpired once.
	time.Sleep(50 * time.Millisecond)
	s.Stop()

	for _, table := range []string{"secrets", "keys", "certificates"} {
		// Expired unprotected row must be gone.
		var count int
		err := rawDB.QueryRow(
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE id = ?`, table),
			"expired-"+table,
		).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "expected expired row to be purged from %s", table)

		// Recent row must still be present.
		err = rawDB.QueryRow(
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE id = ?`, table),
			"recent-"+table,
		).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "expected recent row to survive in %s", table)

		// Purge-protected row must still be present despite being old.
		err = rawDB.QueryRow(
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE id = ?`, table),
			"protected-"+table,
		).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "expected protected row to survive in %s", table)
	}
}

// 5. A cancelled context causes the goroutine to exit cleanly.
func TestStopViaContext(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)
	conn := newTestConn(t, rawDB)

	ctx, cancel := context.WithCancel(context.Background())

	s := NewPurgeScheduler(conn, testConfig(), testLogger())
	s.Start(ctx)

	// Cancel the context; the goroutine must exit without a panic.
	assert.NotPanics(t, func() {
		cancel()
		// Allow the goroutine a moment to react.
		time.Sleep(20 * time.Millisecond)
	})
}

// 6. purgeExpired does not delete rows that are not soft-deleted (deleted_at IS NULL).
func TestPurgeExpired_NullDeletedAt_NotPurged(t *testing.T) {
	rawDB := newTestDB(t)
	createPurgeTables(rawDB)

	// Active row — never soft-deleted.
	_, err := rawDB.Exec(
		`INSERT INTO secrets (id, deleted_at, purge_protection) VALUES (?, NULL, FALSE)`,
		"active-secret",
	)
	require.NoError(t, err)

	conn := newTestConn(t, rawDB)
	s := NewPurgeScheduler(conn, testConfig(), testLogger())
	s.Start(context.Background())
	time.Sleep(30 * time.Millisecond)
	s.Stop()

	var count int
	err = rawDB.QueryRow(`SELECT COUNT(*) FROM secrets WHERE id = 'active-secret'`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "active (non-soft-deleted) rows must not be purged")
}
