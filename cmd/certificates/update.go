/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update certificate metadata",
	Long: `Change a certificate's metadata in place: its name, its tag set, its
auto-renewal settings and its purge protection. The certificate itself is
never re-signed here — use 'rocketvault certificate renew' for that.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/update data action in the target
vault.

Acts on the vault named by --vault, defaulting to "default". Only the flags
you actually pass take effect: --auto-renew, --renewal-days and
--purge-protection are read only when given explicitly, and an omitted or
empty --name or --tags leaves the stored value untouched. --tags replaces
the whole tag set rather than adding to it, and passing an empty value
cannot clear it.`,
	Example: `  # Rename a certificate
  rocketvault certificate update <id> --name <name>

  # Replace the tag set
  rocketvault certificate update <id> --tags prod,tls

  # Arm auto-renewal 45 days before expiry
  rocketvault certificate update <id> --auto-renew --renewal-days 45

  # Protect a certificate from purge, in a named vault
  rocketvault certificate update <id> --purge-protection --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "update_certificate", Action: model.ActionCertificatesUpdate, Policy: model.OpSet,
			Roles:        []string{model.RoleAdmin, model.RoleCertificateManager},
			AuthzFailMsg: "failed to update certificate",
		})
		if err != nil {
			return err
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}

		name, _ := cmd.Flags().GetString("name")
		tagsStr, _ := cmd.Flags().GetString("tags")

		// Only pass auto-renew if the flag was explicitly set by the caller.
		var autoRenewPtr *bool
		if cmd.Flags().Changed("auto-renew") {
			v, _ := cmd.Flags().GetBool("auto-renew")
			autoRenewPtr = &v
		}

		// Only pass renewal-days if the flag was explicitly set by the caller.
		var renewalDaysPtr *int
		if cmd.Flags().Changed("renewal-days") {
			v, _ := cmd.Flags().GetInt("renewal-days")
			renewalDaysPtr = &v
		}

		// Only change purge protection when the flag was explicitly passed.
		var purgeProtectionPtr *bool
		if cmd.Flags().Changed("purge-protection") {
			v, _ := cmd.Flags().GetBool("purge-protection")
			purgeProtectionPtr = &v
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		var namePtr *string
		if name != "" {
			namePtr = &name
		}

		req := certServices.UpdateCertificateRequest{
			CertID:          certID,
			Scope:           s.Scope,
			Name:            namePtr,
			Tags:            tags,
			AutoRenew:       autoRenewPtr,
			RenewalDays:     renewalDaysPtr,
			PurgeProtection: purgeProtectionPtr,
		}

		err = certService.UpdateCertificate(s.Ctx, req)
		if err != nil {
			return s.Fail("failed to update certificate", err)
		}

		s.OK(fmt.Sprintf("certificate updated: %s", certID))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate updated successfully: %s\n", certID)
		return nil
	},
}

// InitCertificatesUpdate initializes the update command for certificates.
func InitCertificatesUpdate(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(updateCmd)

	updateCmd.Flags().String("name", "", "Updated name for the certificate")
	updateCmd.Flags().String("tags", "", "Comma-separated tags for the certificate")
	updateCmd.Flags().Bool("auto-renew", false, "Enable or disable auto-renewal")
	updateCmd.Flags().Int("renewal-days", 0, "Days before expiry to trigger renewal")
	updateCmd.Flags().Bool("purge-protection", false, "Protect the certificate from being purged")
}
