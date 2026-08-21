// Package audit provides CLI commands for querying audit logs and generating
// compliance reports.
package audit

import "github.com/spf13/cobra"

// AuditCmd is the top-level audit subcommand.
var AuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log and compliance reporting commands",
	Long: `Query audit logs, generate SOC 2 or GDPR compliance reports, and view or
update the audit log retention policy.

Every audit command requires the global admin role. Audit data spans every
vault, so there is no --vault scoping and no data-action check — the same
restriction the HTTP audit routes enforce.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # View recent audit log entries
  rocketvault audit logs

  # Generate a SOC 2 compliance report
  rocketvault audit report --type soc2 --from 2026-01-01 --to 2026-03-31

  # Show audit log retention configuration
  rocketvault audit config`,
}

func init() {
	AuditCmd.AddCommand(logsCmd)
	AuditCmd.AddCommand(reportCmd)
	AuditCmd.AddCommand(configCmd)
}
