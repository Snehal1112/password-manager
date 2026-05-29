package common

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/model"
)

// ResolveVaultName determines the target vault name for a resource command.
// Precedence: --vault flag > ROCKETVAULT_VAULT env > config "vault" key > "default".
// It is the single source of truth for the --vault precedence logic.
func ResolveVaultName(cmd *cobra.Command) string {
	if cmd != nil && cmd.Flags().Changed("vault") {
		if v, _ := cmd.Flags().GetString("vault"); v != "" {
			return v
		}
	}
	if v := os.Getenv("ROCKETVAULT_VAULT"); v != "" {
		return v
	}
	if v := viper.GetString("vault"); v != "" {
		return v
	}
	return model.DefaultVaultName
}
