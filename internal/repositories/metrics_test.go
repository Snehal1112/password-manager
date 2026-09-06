package repositories_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

// TestSlowQueryThresholdIsConfigurable pins the F4 fix: the repository layer
// must read the same threshold db.RecordQueryExecution applies, not a
// hardcoded 100ms. Before this, tuning monitoring.slow_query_threshold moved
// the SlowQueryCount metric but left every repository's log warning at 100ms,
// so the metric and the logs disagreed about which queries were slow.
func TestSlowQueryThresholdIsConfigurable(t *testing.T) {
	original := rvdb.SlowQueryThreshold()
	t.Cleanup(func() { rvdb.SetSlowQueryThreshold(original) })

	require.Equal(t, 100*time.Millisecond, original,
		"the package default matches config.LoadMonitoringConfig's default")

	rvdb.SetSlowQueryThreshold(2 * time.Second)
	require.Equal(t, 2*time.Second, rvdb.SlowQueryThreshold(),
		"the exported accessor must observe SetSlowQueryThreshold")
}

// TestWithMetricsPropagatesTheError confirms the wrapper is transparent: it
// times and records the call but never swallows or rewrites its result.
func TestWithMetricsPropagatesTheError(t *testing.T) {
	sentinel := errors.New("boom")
	err := repositories.WithMetricsForTest("keys", "test_op", func() error { return sentinel })
	require.ErrorIs(t, err, sentinel)
}

// TestNoRepositoryHardcodesTheThreshold guards against a sixth copy of the
// metrics wrapper reappearing with its own literal cutoff. The five copies
// this replaced each hardcoded 100ms while db.RecordQueryExecution applied
// the configured monitoring.slow_query_threshold -- so once an operator tuned
// that setting, the SlowQueryCount metric and the slow-query log warnings
// disagreed about which queries were slow.
func TestNoRepositoryHardcodesTheThreshold(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(name)
		require.NoError(t, readErr, "read %s", name)
		require.NotContains(t, string(src), "100*time.Millisecond",
			"%s must take its slow-query cutoff from db.SlowQueryThreshold()", name)
		require.NotContains(t, string(src), "100 * time.Millisecond",
			"%s must take its slow-query cutoff from db.SlowQueryThreshold()", name)
	}
}
