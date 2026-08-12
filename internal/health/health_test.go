package health

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDB opens an in-memory SQLite database and creates the users table
// that CheckDatabaseHealth queries via "SELECT COUNT(*) FROM users".
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY)")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
	return db
}

// ---------------------------------------------------------------------------
// TestNewHealthCollector
// ---------------------------------------------------------------------------

func TestNewHealthCollector(t *testing.T) {
	hc := NewHealthCollector(nil)
	assert.NotNil(t, hc, "NewHealthCollector should return a non-nil collector")
}

// ---------------------------------------------------------------------------
// TestCollectMetrics_NilDB
// ---------------------------------------------------------------------------

func TestCollectMetrics_NilDB(t *testing.T) {
	hc := NewHealthCollector(nil)
	metrics, err := hc.CollectMetrics(context.Background())
	require.NoError(t, err)
	require.NotNil(t, metrics)

	// Memory and CPU info must be populated
	assert.Greater(t, metrics.CPUStats.Goroutines, 0, "expected at least one goroutine")
	assert.NotEmpty(t, metrics.GoVersion)

	// Without a real DB, the database stats block is skipped, so the zero-value
	// DatabaseStats struct is returned.
	assert.Equal(t, 0, metrics.DatabaseStats.OpenConnections)
	assert.Empty(t, metrics.DatabaseStats.HealthStatus)
}

// ---------------------------------------------------------------------------
// TestCollectMetrics_WithDB
// ---------------------------------------------------------------------------

func TestCollectMetrics_WithDB(t *testing.T) {
	db := newTestDB(t)
	hc := NewHealthCollector(db)
	metrics, err := hc.CollectMetrics(context.Background())
	require.NoError(t, err)
	require.NotNil(t, metrics)

	// With a live DB we expect DatabaseStats to be filled in.
	assert.NotEmpty(t, metrics.DatabaseStats.HealthStatus)
	// Goroutines and Go version must still be present.
	assert.Greater(t, metrics.Goroutines, 0)
	assert.NotEmpty(t, metrics.GoVersion)
}

// ---------------------------------------------------------------------------
// TestRecordQuery_Fast
// ---------------------------------------------------------------------------

func TestRecordQuery_Fast(t *testing.T) {
	hc := NewHealthCollector(nil)
	hc.RecordQuery(50 * time.Millisecond) // below the 100 ms threshold

	m := hc.GetQueryMetrics()
	assert.Equal(t, int64(1), m.QueryCount)
	assert.Equal(t, int64(0), m.SlowQueries, "50 ms should not count as a slow query")
}

// ---------------------------------------------------------------------------
// TestRecordQuery_Slow
// ---------------------------------------------------------------------------

func TestRecordQuery_Slow(t *testing.T) {
	hc := NewHealthCollector(nil)
	hc.RecordQuery(150 * time.Millisecond) // above the 100 ms threshold

	m := hc.GetQueryMetrics()
	assert.Equal(t, int64(1), m.QueryCount)
	assert.Equal(t, int64(1), m.SlowQueries, "150 ms should count as a slow query")
}

// ---------------------------------------------------------------------------
// TestRecordQuery_Multiple
// ---------------------------------------------------------------------------

func TestRecordQuery_Multiple(t *testing.T) {
	hc := NewHealthCollector(nil)
	durations := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		300 * time.Millisecond,
	}
	for _, d := range durations {
		hc.RecordQuery(d)
	}

	m := hc.GetQueryMetrics()
	assert.Equal(t, int64(3), m.QueryCount)

	expectedTotal := 600 * time.Millisecond
	assert.Equal(t, expectedTotal, m.TotalDuration)

	expectedAvg := expectedTotal / 3
	assert.Equal(t, expectedAvg, m.AvgDuration, "average should be total/count")

	// All three durations are >= 100 ms; the boundary value (exactly 100 ms) does
	// NOT exceed the threshold (duration > 100ms), so only 200 ms and 300 ms are slow.
	assert.Equal(t, int64(2), m.SlowQueries)
}

// ---------------------------------------------------------------------------
// TestGetQueryMetrics
// ---------------------------------------------------------------------------

func TestGetQueryMetrics(t *testing.T) {
	hc := NewHealthCollector(nil)
	hc.RecordQuery(80 * time.Millisecond)
	hc.RecordQuery(200 * time.Millisecond)

	m := hc.GetQueryMetrics()
	// A copy is returned; mutating m must not affect the collector's state.
	m.QueryCount = 999

	m2 := hc.GetQueryMetrics()
	assert.Equal(t, int64(2), m2.QueryCount, "GetQueryMetrics should return a snapshot copy")
}

// ---------------------------------------------------------------------------
// FormatBytes
// ---------------------------------------------------------------------------

func TestFormatBytes_Bytes(t *testing.T) {
	result := FormatBytes(512)
	assert.Equal(t, "512 B", result)
}

func TestFormatBytes_KB(t *testing.T) {
	result := FormatBytes(1024)
	assert.Equal(t, "1.0 KB", result)
}

func TestFormatBytes_MB(t *testing.T) {
	result := FormatBytes(1024 * 1024)
	assert.Equal(t, "1.0 MB", result)
}

func TestFormatBytes_ZeroBytes(t *testing.T) {
	result := FormatBytes(0)
	assert.Equal(t, "0 B", result)
}

// ---------------------------------------------------------------------------
// FormatDuration
// ---------------------------------------------------------------------------

func TestFormatDuration_Microseconds(t *testing.T) {
	d := 500 * time.Microsecond // 0.5 ms — below 1 ms threshold
	result := FormatDuration(d)
	assert.Contains(t, result, "μs")
	assert.NotContains(t, result, "ms")
	assert.NotContains(t, result, " s")
}

func TestFormatDuration_Milliseconds(t *testing.T) {
	d := 250 * time.Millisecond
	result := FormatDuration(d)
	assert.Contains(t, result, "ms")
	assert.NotContains(t, result, "μs")
}

func TestFormatDuration_Seconds(t *testing.T) {
	d := 2 * time.Second
	result := FormatDuration(d)
	assert.Contains(t, result, " s")
	assert.NotContains(t, result, "ms")
	assert.NotContains(t, result, "μs")
}

func TestFormatDuration_ExactlyOneMillisecond(t *testing.T) {
	// 1 ms is NOT less than 1 ms, so the ms branch applies.
	d := time.Millisecond
	result := FormatDuration(d)
	assert.Contains(t, result, "ms")
}

func TestFormatDuration_ExactlyOneSecond(t *testing.T) {
	// 1 s is NOT less than 1 s, so the seconds branch applies.
	d := time.Second
	result := FormatDuration(d)
	assert.Contains(t, result, " s")
}

// ---------------------------------------------------------------------------
// TestLogHealthMetrics_NilDB
// ---------------------------------------------------------------------------

func TestLogHealthMetrics_NilDB(t *testing.T) {
	hc := NewHealthCollector(nil)
	err := hc.LogHealthMetrics(context.Background())
	// Logging should complete without error even when there is no DB.
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// TestCheckDatabaseHealth_NilDB
// ---------------------------------------------------------------------------

func TestCheckDatabaseHealth_NilDB(t *testing.T) {
	hc := NewHealthCollector(nil)
	result, err := hc.CheckDatabaseHealth(context.Background())
	require.Error(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "critical", result["status"])
}

// ---------------------------------------------------------------------------
// TestCheckDatabaseHealth_WithDB
// ---------------------------------------------------------------------------

func TestCheckDatabaseHealth_WithDB(t *testing.T) {
	db := newTestDB(t)
	hc := NewHealthCollector(db)
	result, err := hc.CheckDatabaseHealth(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)

	status, ok := result["status"].(string)
	require.True(t, ok, "status field should be a string")
	assert.Equal(t, "healthy", status)

	// The query_test map should indicate success.
	qt, ok := result["query_test"].(map[string]any)
	require.True(t, ok, "query_test field should be present")
	success, ok := qt["success"].(bool)
	assert.True(t, ok && success, "query_test should report success")
}

// ---------------------------------------------------------------------------
// Additional edge-case coverage
// ---------------------------------------------------------------------------

func TestCollectMetrics_UptimePositive(t *testing.T) {
	hc := NewHealthCollector(nil)
	// Sleep briefly so uptime is measurable.
	time.Sleep(2 * time.Millisecond)
	metrics, err := hc.CollectMetrics(context.Background())
	require.NoError(t, err)
	assert.Greater(t, metrics.Uptime, time.Duration(0), "uptime should be positive")
}

func TestCollectMetrics_TimestampRecent(t *testing.T) {
	before := time.Now()
	hc := NewHealthCollector(nil)
	metrics, err := hc.CollectMetrics(context.Background())
	require.NoError(t, err)
	after := time.Now()
	assert.True(t, !metrics.Timestamp.Before(before) && !metrics.Timestamp.After(after),
		"timestamp should be within the test window")
}

func TestFormatBytes_LargeValue(t *testing.T) {
	// 1 GB should produce a "GB" suffix.
	result := FormatBytes(1024 * 1024 * 1024)
	assert.Contains(t, result, "GB")
}

func TestRecordQuery_BoundaryNotSlow(t *testing.T) {
	// Exactly 100 ms must NOT be counted as slow (the condition is > 100ms, not >=).
	hc := NewHealthCollector(nil)
	hc.RecordQuery(100 * time.Millisecond)
	m := hc.GetQueryMetrics()
	assert.Equal(t, int64(0), m.SlowQueries)
}
