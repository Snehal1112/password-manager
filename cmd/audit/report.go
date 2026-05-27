package audit

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// reportCmd generates SOC 2 or GDPR compliance reports.
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a compliance report",
	Long:  "Generate a SOC 2 or GDPR compliance report for the specified time range.",
	Example: `rocketvault audit report --type soc2 --from 2026-01-01 --to 2026-03-31
rocketvault audit report --type gdpr --from 2026-01-01 --to 2026-03-31 --subject-id user123 --output csv`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		reportType, _ := cmd.Flags().GetString("type")
		fromStr, _ := cmd.Flags().GetString("from")
		toStr, _ := cmd.Flags().GetString("to")
		subjectID, _ := cmd.Flags().GetString("subject-id")
		outputFmt, _ := cmd.Flags().GetString("output")

		if reportType == "" {
			return fmt.Errorf("--type is required (soc2 or gdpr)")
		}
		if fromStr == "" {
			return fmt.Errorf("--from is required")
		}
		if toStr == "" {
			return fmt.Errorf("--to is required")
		}

		from, err := parseDate(fromStr)
		if err != nil {
			return fmt.Errorf("invalid --from value %q: %w", fromStr, err)
		}
		to, err := parseDate(toStr)
		if err != nil {
			return fmt.Errorf("invalid --to value %q: %w", toStr, err)
		}

		svc := sc.GetComplianceReportService()

		switch reportType {
		case "soc2":
			if outputFmt == "csv" {
				csv, err := svc.GenerateSOC2CSV(ctx, from, to)
				if err != nil {
					return fmt.Errorf("failed to generate SOC 2 CSV: %w", err)
				}
				fmt.Fprint(os.Stdout, csv)
			} else {
				report, err := svc.GenerateSOC2Report(ctx, from, to)
				if err != nil {
					return fmt.Errorf("failed to generate SOC 2 report: %w", err)
				}
				fmt.Fprintf(os.Stdout, "SOC 2 Report: %s to %s\n", report.From.Format("2006-01-02"), report.To.Format("2006-01-02"))
				fmt.Fprintf(os.Stdout, "  Total events:       %d\n", report.TotalEvents)
				fmt.Fprintf(os.Stdout, "  Unique users:       %d\n", report.UniqueUsers)
				fmt.Fprintf(os.Stdout, "  Auth successes:     %d\n", report.AuthSuccesses)
				fmt.Fprintf(os.Stdout, "  Auth failures:      %d\n", report.AuthFailures)
				fmt.Fprintf(os.Stdout, "  Data access events: %d\n", report.DataAccessEvents)
				fmt.Fprintf(os.Stdout, "  Admin actions:      %d\n", report.AdminActions)
				fmt.Fprintf(os.Stdout, "  Key operations:     %d\n", report.KeyOperations)
				if len(report.TopActions) > 0 {
					fmt.Fprintln(os.Stdout, "  Top actions:")
					for _, ac := range report.TopActions {
						fmt.Fprintf(os.Stdout, "    %-30s %d\n", ac.Action, ac.Count)
					}
				}
			}

		case "gdpr":
			if subjectID == "" {
				return fmt.Errorf("--subject-id is required for GDPR reports")
			}
			if outputFmt == "csv" {
				csv, err := svc.GenerateGDPRCSV(ctx, from, to, subjectID)
				if err != nil {
					return fmt.Errorf("failed to generate GDPR CSV: %w", err)
				}
				fmt.Fprint(os.Stdout, csv)
			} else {
				report, err := svc.GenerateGDPRReport(ctx, from, to, subjectID)
				if err != nil {
					return fmt.Errorf("failed to generate GDPR report: %w", err)
				}
				fmt.Fprintf(os.Stdout, "GDPR Report for subject: %s\n", report.SubjectID)
				fmt.Fprintf(os.Stdout, "  Period:        %s to %s\n", report.From.Format("2006-01-02"), report.To.Format("2006-01-02"))
				fmt.Fprintf(os.Stdout, "  Total events:  %d\n", report.TotalEvents)
				fmt.Fprintf(os.Stdout, "  Data access:   %d\n", report.DataAccess)
				fmt.Fprintf(os.Stdout, "  Deletions:     %d\n", report.Deletions)
				fmt.Fprintf(os.Stdout, "  Auth events:   %d\n", report.AuthEvents)
			}

		default:
			return fmt.Errorf("unknown report type %q: must be soc2 or gdpr", reportType)
		}

		return nil
	},
}

func init() {
	reportCmd.Flags().String("type", "", "Report type: soc2 or gdpr (required)")
	reportCmd.Flags().String("from", "", "Start of time range (RFC3339 or YYYY-MM-DD, required)")
	reportCmd.Flags().String("to", "", "End of time range (RFC3339 or YYYY-MM-DD, required)")
	reportCmd.Flags().String("subject-id", "", "Data subject ID (required for gdpr)")
	reportCmd.Flags().String("output", "json", "Output format: json|csv")
}
