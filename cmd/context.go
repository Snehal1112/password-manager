package cmd

import (
	"github.com/spf13/cobra"

	contextcli "rocketvault/cmd/context"
)

// contextCmd is the command group for named remote-server contexts.
var contextCmd = &cobra.Command{
	Use:   "context",
	Short: "Manage named remote RocketVault server contexts",
	Long: `Save, inspect, and switch between named remote RocketVault servers. A
context records a server URL plus an optional default username and vault in
~/.rocketvault/contexts.json; 'context use' marks one active, 'context
current' prints it, 'context unset' clears the active one without deleting
it, and 'context remove' deletes it outright.

This group touches only that local file. It needs no session, no
.rocketvault.yaml, and no database, so it works on a machine that has never
run a RocketVault server. It is also the only resource group exempt from the
remote-target guard: remote mode is not implemented for every other group
yet (the secrets group is, as of 2026-08), so while a context is active — or
--server or ROCKETVAULT_ADDR is set — a command with no remote adapter fails
with "remote mode ... is not yet supported" rather than quietly acting on
the local instance. 'context unset' and 'context remove' of the current
context both clear it and put the CLI back in local mode; unset keeps the
saved context around to switch back to later, remove deletes it.

--server names the target when adding a context. --ca-cert and
--insecure-skip-verify configure TLS trust for the remote connections
themselves, and take effect once a command group gains remote support; they
are not stored in a context.`,
	Example: `  # Save a context and make it current
  rocketvault context add prod --server https://vault.prod.example.com \
    --default-username admin --default-vault payments
  rocketvault context use prod

  # See what is saved and which one is active
  rocketvault context list
  rocketvault context current

  # Switch back to local mode, keeping the context saved
  rocketvault context unset

  # Stop targeting a remote server for good
  rocketvault context remove prod`,
}

func init() {
	rootCmd.AddCommand(contextCmd)
	contextcli.InitContextAdd(contextCmd)
	contextcli.InitContextList(contextCmd)
	contextcli.InitContextUse(contextCmd)
	contextcli.InitContextCurrent(contextCmd)
	contextcli.InitContextUnset(contextCmd)
	contextcli.InitContextRemove(contextCmd)
}
