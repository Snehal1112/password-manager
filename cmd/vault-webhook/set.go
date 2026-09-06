package vaultwebhook

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	vaultServices "rocketvault/internal/services/vaults"
)

// InitVaultWebhookSet registers the set command, which creates or updates a
// vault's webhook configuration.
func InitVaultWebhookSet(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Create or update a vault's webhook configuration",
		Long: `Create or update the webhook configuration for a vault. The first call for
a vault creates the config and mints a signing secret; later calls update
the existing config in place.

--url is required and must be an absolute https URL with a host, and must
not embed credentials. --rotate-secret replaces the current signing secret
with a newly minted one; without it, an update leaves the existing secret
untouched. --enabled toggles the webhook without changing its URL; omit it
to leave the current value alone (a newly created webhook is enabled by
default).

The signing secret is printed once, immediately after this command mints
one (on creation or with --rotate-secret), and is not retrievable
afterward — store it before moving on.

Requires the admin role, or an access-policy grant of manage on vaults
scoped to this vault. Acts on the vault named by
--vault, defaulting to "default".`,
		Example: `  # Point a vault's webhook at a receiver
  rocketvault vault-webhook set --vault prod \
    --url https://hooks.example/rocketvault

  # Rotate the signing secret
  rocketvault vault-webhook set --vault prod \
    --url https://hooks.example/rocketvault --rotate-secret

  # Disable the webhook without changing its URL
  rocketvault vault-webhook set --vault prod \
    --url https://hooks.example/rocketvault --enabled=false`,
		RunE: func(cmd *cobra.Command, args []string) error {
			url, _ := cmd.Flags().GetString("url")
			if url == "" {
				return fmt.Errorf("--url is required")
			}
			rotateSecret, _ := cmd.Flags().GetBool("rotate-secret")

			// --enabled must reach the service as *bool, nil when the user did
			// not pass the flag. A bare false for an unset flag would silently
			// disable the webhook on a URL-only update.
			var enabled *bool
			if cmd.Flags().Changed("enabled") {
				v, err := cmd.Flags().GetBool("enabled")
				if err != nil {
					return err
				}
				enabled = &v
			}

			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultName := common.ResolveVaultName(cmd)
			vaultID, err := vaultcli.ResolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			actor, err := requireCanManageVault(ctx, sc, vaultID, vaultName)
			if err != nil {
				return err
			}

			resp, plaintextSecret, err := sc.GetVaultWebhookService().Upsert(ctx, vaultID, vaultServices.UpsertWebhookRequest{
				URL:          url,
				RotateSecret: rotateSecret,
				Enabled:      enabled,
			}, actor)
			if err != nil {
				return fmt.Errorf("set webhook failed: %w", err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Webhook configured for vault %q:\n", vaultName) //nolint:errcheck
			fmt.Fprintf(out, "  URL: %s\n", resp.URL)                         //nolint:errcheck
			fmt.Fprintf(out, "  Enabled: %t\n", resp.Enabled)                 //nolint:errcheck
			if plaintextSecret != "" {
				fmt.Fprintf(out, "  Signing Secret: %s\n", plaintextSecret)                              //nolint:errcheck
				fmt.Fprintf(out, "\nStore the signing secret now — it is not retrievable after this.\n") //nolint:errcheck
			}
			return nil
		},
	}
	cmd.Flags().String("url", "", "webhook URL (absolute https URL, required)")
	cmd.Flags().Bool("rotate-secret", false, "replace the current signing secret with a new one")
	cmd.Flags().Bool("enabled", false, "enable or disable the webhook (default: keep current value, true on create)")
	vaultcli.AddVaultFlag(cmd)
	parent.AddCommand(cmd)
}
