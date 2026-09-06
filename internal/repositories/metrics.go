package repositories

import (
	"time"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
)

// withMetrics times fn, records it against the package-wide query metrics, and
// warns when it exceeds the configured slow-query threshold. It is transparent:
// fn's error is returned unchanged.
//
// A package-level function rather than a method or a struct field, deliberately.
// Repository structs are built via struct literals in tests, where a
// constructor-set field would zero-value -- the same hazard that keeps
// itemLifecycleConfig behind a crud() method instead of a stored field.
//
// table names the SQL table for the log field; pass "" to omit it, which
// preserves the shape of the two repositories whose copy of this wrapper never
// logged one.
func withMetrics(table, operation string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	db.RecordQueryExecution(duration)

	// The same threshold RecordQueryExecution just applied to SlowQueryCount,
	// so the metric and this warning can never disagree.
	if duration > db.SlowQueryThreshold() {
		fields := logrus.Fields{
			"operation": operation,
			"duration":  duration.Milliseconds(),
		}
		if table != "" {
			fields["table"] = table
		}
		logrus.WithFields(fields).Warn("Slow database query detected")
	}

	return err
}
