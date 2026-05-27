// Package audit provides CLI commands for querying audit logs and generating
// compliance reports.
package audit

import "github.com/spf13/cobra"

// AuditCmd is the top-level audit subcommand.
var AuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log and compliance reporting commands",
	Long:  "Query audit logs and generate SOC 2 / GDPR compliance reports.",
}

func init() {
	AuditCmd.AddCommand(logsCmd)
	AuditCmd.AddCommand(reportCmd)
	AuditCmd.AddCommand(configCmd)
}
