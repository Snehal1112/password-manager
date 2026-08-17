package cmd

import (
	"github.com/spf13/cobra"

	contextcli "rocketvault/cmd/context"
)

// contextCmd is the command group for named remote-server contexts.
var contextCmd = &cobra.Command{
	Use:   "context",
	Short: "Manage named remote RocketVault server contexts",
	Example: `  # Save and switch to a context
  rocketvault context add prod --server https://vault.prod.example.com --default-username admin
  rocketvault context use prod

  # See what's saved / active
  rocketvault context list
  rocketvault context current`,
}

func init() {
	rootCmd.AddCommand(contextCmd)
	contextcli.InitContextAdd(contextCmd)
	contextcli.InitContextList(contextCmd)
	contextcli.InitContextUse(contextCmd)
	contextcli.InitContextCurrent(contextCmd)
	contextcli.InitContextRemove(contextCmd)
}
