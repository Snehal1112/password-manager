package repositories_test

import (
	"errors"
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
