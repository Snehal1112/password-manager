package metrics_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/metrics"
)

func TestDBMetrics_Update(t *testing.T) {
	m := metrics.NewDBMetrics()
	require.NotNil(t, m)

	m.Update(metrics.DBSnapshot{
		QueryCount:         42,
		SlowQueryCount:     3,
		AverageQueryTimeMS: 12.5,
		OpenConnections:    10,
		InUse:              4,
		Idle:               6,
	})

	assert.Equal(t, float64(42), testutil.ToFloat64(m.QueryCountGauge()))
	assert.Equal(t, float64(3), testutil.ToFloat64(m.SlowQueryCountGauge()))
	assert.Equal(t, 12.5, testutil.ToFloat64(m.AvgQueryTimeMSGauge()))
	assert.Equal(t, float64(10), testutil.ToFloat64(m.OpenConnectionsGauge()))
	assert.Equal(t, float64(4), testutil.ToFloat64(m.ConnectionsInUseGauge()))
	assert.Equal(t, float64(6), testutil.ToFloat64(m.ConnectionsIdleGauge()))
}

func TestNewDefaultDBMetrics_Idempotent(t *testing.T) {
	// Registering twice on the default registry must not panic — the second
	// call should return the already-registered collector.
	a := metrics.NewDefaultDBMetrics()
	b := metrics.NewDefaultDBMetrics()
	assert.Same(t, a, b)
}

func TestMetricsScheduler_RefreshesOnStart(t *testing.T) {
	m := metrics.NewDBMetrics()
	calls := make(chan struct{}, 1)
	snapshot := func() metrics.DBSnapshot {
		select {
		case calls <- struct{}{}:
		default:
		}
		return metrics.DBSnapshot{QueryCount: 7}
	}

	s := metrics.NewMetricsScheduler(m, snapshot, time.Hour)
	s.Start(t.Context())
	defer s.Stop()

	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("expected snapshot to be called once on Start")
	}

	assert.Equal(t, float64(7), testutil.ToFloat64(m.QueryCountGauge()))
}

func TestMetricsScheduler_StopDoesNotPanic(t *testing.T) {
	m := metrics.NewDBMetrics()
	s := metrics.NewMetricsScheduler(m, func() metrics.DBSnapshot { return metrics.DBSnapshot{} }, time.Hour)
	s.Start(t.Context())
	s.Stop()
}
