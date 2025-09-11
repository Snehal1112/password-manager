/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package health

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HealthMetrics represents the system health metrics
type HealthMetrics struct {
	MemoryUsage   MemoryStats   `json:"memory_usage"`
	CPUStats      CPUStats      `json:"cpu_stats"`
	DatabaseStats DatabaseStats `json:"database_stats"`
	Uptime        time.Duration `json:"uptime"`
	GoVersion     string        `json:"go_version"`
	Goroutines    int           `json:"goroutines"`
	Timestamp     time.Time     `json:"timestamp"`
}

// MemoryStats contains memory usage information
type MemoryStats struct {
	Alloc        uint64 `json:"alloc_bytes"`
	TotalAlloc   uint64 `json:"total_alloc_bytes"`
	Sys          uint64 `json:"sys_bytes"`
	Lookups      uint64 `json:"lookups"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	HeapAlloc    uint64 `json:"heap_alloc_bytes"`
	HeapSys      uint64 `json:"heap_sys_bytes"`
	HeapIdle     uint64 `json:"heap_idle_bytes"`
	HeapInuse    uint64 `json:"heap_inuse_bytes"`
	HeapReleased uint64 `json:"heap_released_bytes"`
	HeapObjects  uint64 `json:"heap_objects"`
	StackInuse   uint64 `json:"stack_inuse_bytes"`
	StackSys     uint64 `json:"stack_sys_bytes"`
	GCSys        uint64 `json:"gc_sys_bytes"`
	NextGC       uint64 `json:"next_gc_bytes"`
	LastGC       uint64 `json:"last_gc_timestamp"`
	NumGC        uint32 `json:"num_gc"`
}

// CPUStats contains CPU usage information
type CPUStats struct {
	Goroutines int   `json:"goroutines"`
	CgoCalls   int64 `json:"cgo_calls"`
}

// DatabaseStats contains database connection information
type DatabaseStats struct {
	OpenConnections   int           `json:"open_connections"`
	InUse             int           `json:"in_use"`
	Idle              int           `json:"idle"`
	WaitCount         int64         `json:"wait_count"`
	WaitDuration      time.Duration `json:"wait_duration"`
	MaxIdleClosed     int64         `json:"max_idle_closed"`
	MaxLifetimeClosed int64         `json:"max_lifetime_closed"`
}

// HealthCollector manages health metrics collection
type HealthCollector struct {
	db           *sql.DB
	startTime    time.Time
	queryMetrics *QueryMetrics
	mu           sync.RWMutex
}

// QueryMetrics tracks database query performance
type QueryMetrics struct {
	QueryCount    int64         `json:"query_count"`
	TotalDuration time.Duration `json:"total_duration"`
	AvgDuration   time.Duration `json:"avg_duration"`
	SlowQueries   int64         `json:"slow_queries"`
	mu            sync.RWMutex
}

// NewHealthCollector creates a new health metrics collector
func NewHealthCollector(db *sql.DB) *HealthCollector {
	return &HealthCollector{
		db:           db,
		startTime:    time.Now(),
		queryMetrics: &QueryMetrics{},
	}
}

// CollectMetrics gathers all system health metrics
func (hc *HealthCollector) CollectMetrics(ctx context.Context) (*HealthMetrics, error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics := &HealthMetrics{
		MemoryUsage: MemoryStats{
			Alloc:        m.Alloc,
			TotalAlloc:   m.TotalAlloc,
			Sys:          m.Sys,
			Lookups:      m.Lookups,
			Mallocs:      m.Mallocs,
			Frees:        m.Frees,
			HeapAlloc:    m.HeapAlloc,
			HeapSys:      m.HeapSys,
			HeapIdle:     m.HeapIdle,
			HeapInuse:    m.HeapInuse,
			HeapReleased: m.HeapReleased,
			HeapObjects:  m.HeapObjects,
			StackInuse:   m.StackInuse,
			StackSys:     m.StackSys,
			GCSys:        m.GCSys,
			NextGC:       m.NextGC,
			LastGC:       m.LastGC,
			NumGC:        m.NumGC,
		},
		CPUStats: CPUStats{
			Goroutines: runtime.NumGoroutine(),
			CgoCalls:   runtime.NumCgoCall(),
		},
		Uptime:     time.Since(hc.startTime),
		GoVersion:  runtime.Version(),
		Goroutines: runtime.NumGoroutine(),
		Timestamp:  time.Now(),
	}

	// Collect database stats
	if hc.db != nil {
		dbStats := hc.db.Stats()
		metrics.DatabaseStats = DatabaseStats{
			OpenConnections:   dbStats.OpenConnections,
			InUse:             dbStats.InUse,
			Idle:              dbStats.Idle,
			WaitCount:         dbStats.WaitCount,
			WaitDuration:      dbStats.WaitDuration,
			MaxIdleClosed:     dbStats.MaxIdleClosed,
			MaxLifetimeClosed: dbStats.MaxLifetimeClosed,
		}
	}

	return metrics, nil
}

// RecordQuery records a database query for performance tracking
func (hc *HealthCollector) RecordQuery(duration time.Duration) {
	hc.queryMetrics.mu.Lock()
	defer hc.queryMetrics.mu.Unlock()

	hc.queryMetrics.QueryCount++
	hc.queryMetrics.TotalDuration += duration

	if hc.queryMetrics.QueryCount > 0 {
		hc.queryMetrics.AvgDuration = hc.queryMetrics.TotalDuration / time.Duration(hc.queryMetrics.QueryCount)
	}

	// Consider queries over 100ms as slow
	if duration > 100*time.Millisecond {
		hc.queryMetrics.SlowQueries++
	}
}

// GetQueryMetrics returns current query performance metrics
func (hc *HealthCollector) GetQueryMetrics() QueryMetrics {
	hc.queryMetrics.mu.RLock()
	defer hc.queryMetrics.mu.RUnlock()

	return QueryMetrics{
		QueryCount:    hc.queryMetrics.QueryCount,
		TotalDuration: hc.queryMetrics.TotalDuration,
		AvgDuration:   hc.queryMetrics.AvgDuration,
		SlowQueries:   hc.queryMetrics.SlowQueries,
	}
}

// FormatBytes formats bytes into human readable format
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats duration into human readable format
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2f μs", float64(d.Nanoseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%.2f ms", float64(d.Nanoseconds())/1000000)
	}
	return fmt.Sprintf("%.2f s", d.Seconds())
}

// LogHealthMetrics logs the current health metrics
func (hc *HealthCollector) LogHealthMetrics(ctx context.Context) error {
	metrics, err := hc.CollectMetrics(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect metrics: %w", err)
	}

	queryMetrics := hc.GetQueryMetrics()

	logrus.WithFields(logrus.Fields{
		"memory_alloc":   FormatBytes(metrics.MemoryUsage.Alloc),
		"memory_heap":    FormatBytes(metrics.MemoryUsage.HeapAlloc),
		"memory_sys":     FormatBytes(metrics.MemoryUsage.Sys),
		"goroutines":     metrics.CPUStats.Goroutines,
		"uptime":         FormatDuration(metrics.Uptime),
		"db_connections": metrics.DatabaseStats.OpenConnections,
		"db_in_use":      metrics.DatabaseStats.InUse,
		"db_idle":        metrics.DatabaseStats.Idle,
		"query_count":    queryMetrics.QueryCount,
		"avg_query_time": FormatDuration(queryMetrics.AvgDuration),
		"slow_queries":   queryMetrics.SlowQueries,
		"gc_cycles":      metrics.MemoryUsage.NumGC,
	}).Info("System health metrics collected")

	return nil
}
