/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// renewCmd represents the renew command
var renewCmd = &cobra.Command{
	Use:   "renew <id>",
	Short: "Renew a certificate",
	Long: `Re-issue an X.509 certificate over its existing key with a fresh validity
period counted from now. The renewal is written in place: the certificate
keeps its ID, name, tags and vault, and only its body and expiry change.
There is no new certificate ID to record.

A certificate originally signed by a CA is re-issued through that same CA,
so its issuer and chain are preserved; a self-signed certificate is
re-issued self-signed. The signing CA must still exist in the vault, be
enabled, and be within its own validity window, or the renewal is refused
rather than quietly downgraded to self-signed.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/create data action in the target
vault — not certificates/update. The certificate's key must still exist in
that vault and be owned by the calling user.

Acts on the vault named by --vault, defaulting to "default".
--validity-days must be positive. A certificate that is disabled, not yet
valid or already expired reads as inaccessible and cannot be renewed, so
renew before it lapses rather than after.`,
	Example: `  # Renew for the default 365 days
  rocketvault certificate renew <id>

  # Renew for a shorter period
  rocketvault certificate renew <id> --validity-days 90

  # Renew a certificate in a named vault
  rocketvault certificate renew <id> --validity-days 365 --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "renew_certificate", Action: model.ActionCertificatesCreate, Policy: model.OpRenew,
			Roles:        []string{model.RoleAdmin, model.RoleCertificateManager},
			AuthzFailMsg: "failed to renew certificate",
		})
		if err != nil {
			return err
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}

		validityDays, _ := cmd.Flags().GetInt("validity-days")
		if validityDays <= 0 {
			return s.Fail("validity-days must be greater than 0", nil)
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		result, err := certService.RenewCertificate(s.Ctx, certID, s.Scope, validityDays)
		if err != nil {
			return s.Fail("failed to renew certificate", err)
		}

		s.OK(fmt.Sprintf("certificate renewed: %s", result.CertID))
		// Renewal updates the row in place, so there is one ID, not two.
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate renewed successfully!\nCertificate ID: %s\nValidity: %d days\n",
			result.CertID, validityDays)
		return nil
	},
}

// InitCertificatesRenew initializes the renew command for certificates.
func InitCertificatesRenew(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(renewCmd)

	renewCmd.Flags().Int("validity-days", 365, "Certificate validity period in days")
}
