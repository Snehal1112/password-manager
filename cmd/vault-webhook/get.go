package vaultwebhook

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	vaultServices "rocketvault/internal/services/vaults"
)

// InitVaultWebhookGet registers the get command, which prints a vault's
// webhook configuration. It never prints or decrypts the signing secret: the
// service returns only ciphertext, and the CLI has no business decrypting it.
func InitVaultWebhookGet(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Show a vault's webhook configuration",
		Long: `Show a vault's webhook configuration: URL, enabled state, and created and
updated timestamps. The signing secret is never shown here — it is
printed once, only on creation or rotation, and cannot be retrieved
afterward.

Fails if the vault has no webhook configured.

Requires the admin role, or an access-policy grant of manage on vaults
scoped to this vault (or granted globally). Acts on the vault named by
--vault, defaulting to "default".`,
		Example: `  # Show the webhook configuration for the default vault
  rocketvault vault-webhook get

  # Show it for a named vault
  rocketvault vault-webhook get --vault prod`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultName := common.ResolveVaultName(cmd)
			vaultID, err := resolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			// Reads are not audited, so the principal id is not needed here.
			if _, err := requireCanManageVault(ctx, sc, vaultID, vaultName); err != nil {
				return err
			}

			cfg, err := sc.GetVaultWebhookService().Get(ctx, vaultID)
			if err != nil {
				if errors.Is(err, vaultServices.ErrWebhookNotFound) {
					return fmt.Errorf("no webhook configured for vault %q", vaultName)
				}
				return fmt.Errorf("get webhook failed: %w", err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Webhook for vault %q:\n", vaultName)                                 //nolint:errcheck
			fmt.Fprintf(out, "  URL: %s\n", cfg.URL)                                               //nolint:errcheck
			fmt.Fprintf(out, "  Enabled: %t\n", cfg.Enabled)                                       //nolint:errcheck
			fmt.Fprintf(out, "  Created: %s\n", cfg.CreatedAt.Format("2006-01-02T15:04:05Z07:00")) //nolint:errcheck
			fmt.Fprintf(out, "  Updated: %s\n", cfg.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")) //nolint:errcheck
			return nil
		},
	}
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
