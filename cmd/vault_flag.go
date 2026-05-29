package cmd

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

// resolveVault determines the target vault for a resource command.
// Precedence: --vault flag > ROCKETVAULT_VAULT env > config "vault" key > "default".
// It delegates to common.ResolveVaultName so the precedence logic has a single
// source of truth shared with the resource subpackages.
func resolveVault(cmd *cobra.Command) string {
	return common.ResolveVaultName(cmd)
}
