package cmd

import (
	"github.com/spf13/cobra"

	vaultwebhook "rocketvault/cmd/vault-webhook"
)

// vaultWebhookCmd is the command group for per-vault webhook configuration.
var vaultWebhookCmd = &cobra.Command{
	Use:   "vault-webhook",
	Short: "Manage per-vault webhook configuration",
	Long: `Configure the webhook RocketVault will use to notify a vault's operators:
set or update its endpoint, show the current configuration, and delete it.
Each vault holds at most one webhook configuration.

All three commands require the admin role or a vaults/manage grant on the
target vault, and act on the vault named by --vault, defaulting to "default".

The URL must be an absolute https URL and must not embed credentials; a
receiver authenticates deliveries with the vault's signing secret instead.
That secret is minted when the webhook is first created, and again whenever
you pass --rotate-secret. It is printed once, at that moment, and never
again — get deliberately does not show it — so store it before moving on.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Point a vault's webhook at a receiver
  rocketvault vault-webhook set --vault prod \
    --url https://hooks.example/rocketvault

  # Rotate the signing secret; the new one is printed once
  rocketvault vault-webhook set --vault prod \
    --url https://hooks.example/rocketvault --rotate-secret

  # Show the configuration, then remove it
  rocketvault vault-webhook get --vault prod
  rocketvault vault-webhook delete --vault prod`,
}

func init() {
	rootCmd.AddCommand(vaultWebhookCmd)
	vaultwebhook.InitVaultWebhookSet(vaultWebhookCmd)
	vaultwebhook.InitVaultWebhookGet(vaultWebhookCmd)
	vaultwebhook.InitVaultWebhookDelete(vaultWebhookCmd)
}
