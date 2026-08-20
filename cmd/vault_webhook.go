package cmd

import (
	"github.com/spf13/cobra"

	vaultwebhook "rocketvault/cmd/vault-webhook"
)

// vaultWebhookCmd is the command group for per-vault webhook configuration.
var vaultWebhookCmd = &cobra.Command{
	Use:   "vault-webhook",
	Short: "Manage per-vault webhook configuration",
	Long: `Configure the webhook RocketVault will use to notify a vault's operators.

Examples:
  rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault
  rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault --rotate-secret
  rocketvault vault-webhook get --vault prod
  rocketvault vault-webhook delete --vault prod`,
}

func init() {
	rootCmd.AddCommand(vaultWebhookCmd)
	vaultwebhook.InitVaultWebhookSet(vaultWebhookCmd)
	vaultwebhook.InitVaultWebhookGet(vaultWebhookCmd)
	vaultwebhook.InitVaultWebhookDelete(vaultWebhookCmd)
}
