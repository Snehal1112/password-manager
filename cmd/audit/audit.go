// Package audit provides CLI commands for querying audit logs and generating
// compliance reports.
package audit

import "github.com/spf13/cobra"

// AuditCmd is the top-level audit subcommand.
var AuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log and compliance reporting commands",
	Long:  "Query audit logs and generate SOC 2 / GDPR compliance reports.",
	Example: `  # View recent audit log entries
  rocketvault audit logs \
    --username admin --password admin123 --totp-code <code>

  # Generate a SOC 2 compliance report
  rocketvault audit report --type soc2 --from 2026-01-01 --to 2026-03-31 \
    --username admin --password admin123 --totp-code <code>

  # Show audit retention configuration
  rocketvault audit config \
    --username admin --password admin123 --totp-code <code>`,
}

func init() {
	AuditCmd.AddCommand(logsCmd)
	AuditCmd.AddCommand(reportCmd)
	AuditCmd.AddCommand(configCmd)
}
