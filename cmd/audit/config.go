package audit

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// configCmd manages audit log configuration settings.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View or update audit log configuration",
	Long:  "View or update audit log configuration. Pass --retention-days to set a new value; omit it to show the current value.",
	Example: `  # Show current audit log retention policy
  rocketvault audit config \
    --username admin --password admin123 --totp-code <code>

  # Update audit log retention to 90 days
  rocketvault audit config --retention-days 90 \
    --username admin --password admin123 --totp-code <code>`,
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

		retentionDays, _ := cmd.Flags().GetInt("retention-days")
		svc := sc.GetComplianceReportService()

		if retentionDays > 0 {
			if err := svc.SetRetentionDays(ctx, retentionDays); err != nil {
				return fmt.Errorf("failed to update retention policy: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Retention policy updated: %d days\n", retentionDays) //nolint:errcheck
		} else {
			days, err := svc.GetRetentionDays(ctx)
			if err != nil {
				return fmt.Errorf("failed to get retention policy: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Current audit log retention: %d days\n", days) //nolint:errcheck
		}

		return nil
	},
}

func init() {
	configCmd.Flags().Int("retention-days", 0, "Set retention period in days (0 = show current value)")
}
