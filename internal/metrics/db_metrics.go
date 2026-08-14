package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// DBSnapshot is the subset of database performance data DBMetrics exposes as gauges.
type DBSnapshot struct {
	QueryCount         int64
	SlowQueryCount     int64
	AverageQueryTimeMS float64
	OpenConnections    int
	InUse              int
	Idle               int
}

// DBMetrics exposes database performance data as Prometheus gauges.
type DBMetrics struct {
	queryCount       prometheus.Gauge
	slowQueryCount   prometheus.Gauge
	avgQueryTimeMS   prometheus.Gauge
	openConnections  prometheus.Gauge
	connectionsInUse prometheus.Gauge
	connectionsIdle  prometheus.Gauge
}

func newDBMetrics(reg prometheus.Registerer) *DBMetrics {
	m := &DBMetrics{
		queryCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "rocketvault_db_query_count",
			Help: "Total database queries recorded since the last reset.",
		}),
		slowQueryCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "rocketvault_db_slow_query_count",
			Help: "Total slow database queries recorded since the last reset.",
		}),
		avgQueryTimeMS: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "rocketvault_db_avg_query_time_ms",
			Help: "Average database query duration in milliseconds.",
		}),
		openConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "rocketvault_db_open_connections",
			Help: "Open database connections.",
		}),
		connectionsInUse: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "rocketvault_db_connections_in_use",
			Help: "Database connections currently in use.",
		}),
		connectionsIdle: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "rocketvault_db_connections_idle",
			Help: "Idle database connections.",
		}),
	}
	reg.MustRegister(m.queryCount, m.slowQueryCount, m.avgQueryTimeMS,
		m.openConnections, m.connectionsInUse, m.connectionsIdle)
	return m
}

// NewDBMetrics creates a DBMetrics using a new (non-default) Prometheus
// registry so tests do not conflict.
func NewDBMetrics() *DBMetrics {
	return newDBMetrics(prometheus.NewRegistry())
}

var (
	defaultDBMetrics     *DBMetrics
	defaultDBMetricsOnce sync.Once
)

// NewDefaultDBMetrics registers the DB gauges on the default Prometheus
// registry. Safe to call more than once — returns the existing collector
// (e.g. in integration tests that construct the DI container multiple times).
func NewDefaultDBMetrics() *DBMetrics {
	defaultDBMetricsOnce.Do(func() {
		defaultDBMetrics = newDBMetrics(prometheus.DefaultRegisterer)
	})
	return defaultDBMetrics
}

// Update sets the gauges from a snapshot.
func (m *DBMetrics) Update(s DBSnapshot) {
	m.queryCount.Set(float64(s.QueryCount))
	m.slowQueryCount.Set(float64(s.SlowQueryCount))
	m.avgQueryTimeMS.Set(s.AverageQueryTimeMS)
	m.openConnections.Set(float64(s.OpenConnections))
	m.connectionsInUse.Set(float64(s.InUse))
	m.connectionsIdle.Set(float64(s.Idle))
}

// QueryCountGauge returns the underlying query-count gauge, for tests.
func (m *DBMetrics) QueryCountGauge() prometheus.Gauge { return m.queryCount }

// SlowQueryCountGauge returns the underlying slow-query-count gauge, for tests.
func (m *DBMetrics) SlowQueryCountGauge() prometheus.Gauge { return m.slowQueryCount }

// AvgQueryTimeMSGauge returns the underlying average-query-time gauge, for tests.
func (m *DBMetrics) AvgQueryTimeMSGauge() prometheus.Gauge { return m.avgQueryTimeMS }

// OpenConnectionsGauge returns the underlying open-connections gauge, for tests.
func (m *DBMetrics) OpenConnectionsGauge() prometheus.Gauge { return m.openConnections }

// ConnectionsInUseGauge returns the underlying connections-in-use gauge, for tests.
func (m *DBMetrics) ConnectionsInUseGauge() prometheus.Gauge { return m.connectionsInUse }

// ConnectionsIdleGauge returns the underlying connections-idle gauge, for tests.
func (m *DBMetrics) ConnectionsIdleGauge() prometheus.Gauge { return m.connectionsIdle }

// MetricsScheduler periodically refreshes DB performance gauges from a
// snapshot function. Mirrors the softdelete.PurgeScheduler ticker pattern.
type MetricsScheduler struct {
	metrics  *DBMetrics
	snapshot func() DBSnapshot
	interval time.Duration
	done     chan struct{}
}

// NewMetricsScheduler creates a new MetricsScheduler.
func NewMetricsScheduler(m *DBMetrics, snapshot func() DBSnapshot, interval time.Duration) *MetricsScheduler {
	return &MetricsScheduler{metrics: m, snapshot: snapshot, interval: interval, done: make(chan struct{})}
}

// Start launches the scheduler in a background goroutine.
func (s *MetricsScheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop signals the scheduler to stop.
func (s *MetricsScheduler) Stop() {
	close(s.done)
}

func (s *MetricsScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run once immediately on startup.
	s.refresh()

	for {
		select {
		case <-ticker.C:
			s.refresh()
		case <-s.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *MetricsScheduler) refresh() {
	s.metrics.Update(s.snapshot())
}
