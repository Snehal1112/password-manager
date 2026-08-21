package audit

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// reportCmd generates SOC 2 or GDPR compliance reports.
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a compliance report",
	Long: `Generate a SOC 2 or GDPR compliance report for a time range: a
human-readable summary by default, or the raw records with --format csv.

--type is required and must be soc2 or gdpr. --from and --to are required
and accept RFC3339 timestamps or YYYY-MM-DD dates. --subject-id is
required for gdpr reports, to scope the report to one data subject; it is
ignored for soc2.

Requires the global admin role. Audit data spans every vault, so there is
no --vault scoping.`,
	Example: `  # Generate a SOC 2 compliance report
  rocketvault audit report --type soc2 --from 2026-01-01 --to 2026-03-31

  # Generate the same report as CSV
  rocketvault audit report --type soc2 --from 2026-01-01 --to 2026-03-31 \
    --format csv

  # Generate a GDPR report for one data subject
  rocketvault audit report --type gdpr --from 2026-01-01 --to 2026-03-31 \
    --subject-id <user-id>`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		if _, err := requireAuditAdmin(cmd); err != nil {
			return err
		}

		reportType, _ := cmd.Flags().GetString("type")
		fromStr, _ := cmd.Flags().GetString("from")
		toStr, _ := cmd.Flags().GetString("to")
		subjectID, _ := cmd.Flags().GetString("subject-id")
		outputFmt, _ := cmd.Flags().GetString("format")

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
				fmt.Fprint(cmd.OutOrStdout(), csv) //nolint:errcheck
			} else {
				report, err := svc.GenerateSOC2Report(ctx, from, to)
				if err != nil {
					return fmt.Errorf("failed to generate SOC 2 report: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "SOC 2 Report: %s to %s\n", report.From.Format("2006-01-02"), report.To.Format("2006-01-02")) //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Total events:       %d\n", report.TotalEvents)                                             //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Unique users:       %d\n", report.UniqueUsers)                                             //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Auth successes:     %d\n", report.AuthSuccesses)                                           //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Auth failures:      %d\n", report.AuthFailures)                                            //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Data access events: %d\n", report.DataAccessEvents)                                        //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Admin actions:      %d\n", report.AdminActions)                                            //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Key operations:     %d\n", report.KeyOperations)                                           //nolint:errcheck
				if len(report.TopActions) > 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "  Top actions:") //nolint:errcheck
					for _, ac := range report.TopActions {
						fmt.Fprintf(cmd.OutOrStdout(), "    %-30s %d\n", ac.Action, ac.Count) //nolint:errcheck
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
				fmt.Fprint(cmd.OutOrStdout(), csv) //nolint:errcheck
			} else {
				report, err := svc.GenerateGDPRReport(ctx, from, to, subjectID)
				if err != nil {
					return fmt.Errorf("failed to generate GDPR report: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "GDPR Report for subject: %s\n", report.SubjectID)                                               //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Period:        %s to %s\n", report.From.Format("2006-01-02"), report.To.Format("2006-01-02")) //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Total events:  %d\n", report.TotalEvents)                                                     //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Data access:   %d\n", report.DataAccess)                                                      //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Deletions:     %d\n", report.Deletions)                                                       //nolint:errcheck
				fmt.Fprintf(cmd.OutOrStdout(), "  Auth events:   %d\n", report.AuthEvents)                                                      //nolint:errcheck
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
	reportCmd.Flags().String("format", "json", "Output format: json|csv")
}
