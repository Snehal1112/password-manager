package cliclient

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/model"
)

// ResolveRemoteVault picks the vault a remote command operates on:
//
//	--vault flag > ROCKETVAULT_VAULT > the current context's default vault >
//	config "vault" key > "default"
//
// This is common.ResolveVaultName's precedence (common/vault_selector.go:15-28)
// with the context's default vault inserted after the environment variable. An
// exported variable is a narrower, more intentional statement than a default
// saved into a context months earlier, so it wins; the config file is a
// machine-wide default and loses to both.
//
// Remote commands previously resolved --vault then the context default and
// skipped the environment variable entirely, so the same command could address
// different vaults in the two modes.
//
// The flag test is Flags().Changed, matching ResolveVaultName: a flag left at a
// non-empty *default* must not outrank an explicitly exported variable.
func ResolveRemoteVault(cmd *cobra.Command, target *Target) string {
	if cmd != nil && cmd.Flags().Changed("vault") {
		if v, _ := cmd.Flags().GetString("vault"); v != "" {
			return v
		}
	}
	if v := os.Getenv("ROCKETVAULT_VAULT"); v != "" {
		return v
	}
	if target != nil && target.Vault != "" {
		return target.Vault
	}
	if v := viper.GetString("vault"); v != "" {
		return v
	}
	return model.DefaultVaultName
}
