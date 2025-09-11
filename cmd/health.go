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

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"database/sql"

	"github.com/spf13/cobra"

	"password-manager/common"
	"password-manager/internal/health"
	"password-manager/internal/logging"
)

// healthCmd represents the health command
var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Display system health metrics",
	Long: `Display comprehensive system health metrics including memory usage,
CPU statistics, database connection status, and query performance metrics.`,
	Example: `password-manager health`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		db := ctx.Value(common.DBKey).(*sql.DB)
		logger := ctx.Value(common.LogKey).(*logging.Logger)

		collector := health.NewHealthCollector(db)

		metrics, err := collector.CollectMetrics(ctx)
		if err != nil {
			logger.LogAuditError("", "health_check", "failed", fmt.Sprintf("Failed to collect health metrics: %s", err), err)
			return fmt.Errorf("failed to collect health metrics: %w", err)
		}

		queryMetrics := collector.GetQueryMetrics()

		// Display metrics in a formatted table
		displayHealthMetrics(metrics, &queryMetrics)

		logger.LogAuditInfo("", "health_check", "success", "Health metrics displayed successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(healthCmd)
}

// displayHealthMetrics formats and displays health metrics
func displayHealthMetrics(metrics *health.HealthMetrics, queryMetrics *health.QueryMetrics) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "SYSTEM HEALTH METRICS")
	fmt.Fprintln(w, "====================")
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "MEMORY USAGE:")
	fmt.Fprintf(w, "  Allocated Memory:\t%s\n", health.FormatBytes(metrics.MemoryUsage.Alloc))
	fmt.Fprintf(w, "  Heap Allocated:\t%s\n", health.FormatBytes(metrics.MemoryUsage.HeapAlloc))
	fmt.Fprintf(w, "  System Memory:\t%s\n", health.FormatBytes(metrics.MemoryUsage.Sys))
	fmt.Fprintf(w, "  Heap System:\t%s\n", health.FormatBytes(metrics.MemoryUsage.HeapSys))
	fmt.Fprintf(w, "  Heap Idle:\t%s\n", health.FormatBytes(metrics.MemoryUsage.HeapIdle))
	fmt.Fprintf(w, "  Heap In Use:\t%s\n", health.FormatBytes(metrics.MemoryUsage.HeapInuse))
	fmt.Fprintf(w, "  Heap Objects:\t%d\n", metrics.MemoryUsage.HeapObjects)
	fmt.Fprintf(w, "  GC Cycles:\t%d\n", metrics.MemoryUsage.NumGC)
	fmt.Fprintf(w, "  Next GC:\t%s\n", health.FormatBytes(metrics.MemoryUsage.NextGC))
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "CPU STATISTICS:")
	fmt.Fprintf(w, "  Goroutines:\t%d\n", metrics.CPUStats.Goroutines)
	fmt.Fprintf(w, "  CGO Calls:\t%d\n", metrics.CPUStats.CgoCalls)
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "DATABASE STATISTICS:")
	fmt.Fprintf(w, "  Open Connections:\t%d\n", metrics.DatabaseStats.OpenConnections)
	fmt.Fprintf(w, "  In Use:\t%d\n", metrics.DatabaseStats.InUse)
	fmt.Fprintf(w, "  Idle:\t%d\n", metrics.DatabaseStats.Idle)
	fmt.Fprintf(w, "  Wait Count:\t%d\n", metrics.DatabaseStats.WaitCount)
	fmt.Fprintf(w, "  Wait Duration:\t%s\n", health.FormatDuration(metrics.DatabaseStats.WaitDuration))
	fmt.Fprintf(w, "  Max Idle Closed:\t%d\n", metrics.DatabaseStats.MaxIdleClosed)
	fmt.Fprintf(w, "  Max Lifetime Closed:\t%d\n", metrics.DatabaseStats.MaxLifetimeClosed)
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "QUERY PERFORMANCE:")
	fmt.Fprintf(w, "  Total Queries:\t%d\n", queryMetrics.QueryCount)
	fmt.Fprintf(w, "  Average Query Time:\t%s\n", health.FormatDuration(queryMetrics.AvgDuration))
	fmt.Fprintf(w, "  Slow Queries (>100ms):\t%d\n", queryMetrics.SlowQueries)
	fmt.Fprintf(w, "  Total Query Time:\t%s\n", health.FormatDuration(queryMetrics.TotalDuration))
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "SYSTEM INFORMATION:")
	fmt.Fprintf(w, "  Uptime:\t%s\n", health.FormatDuration(metrics.Uptime))
	fmt.Fprintf(w, "  Go Version:\t%s\n", metrics.GoVersion)
	fmt.Fprintf(w, "  Timestamp:\t%s\n", metrics.Timestamp.Format("2006-01-02 15:04:05"))

	w.Flush()
}
