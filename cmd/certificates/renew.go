/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
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
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		validityDays := viper.GetInt("cert-renew-validity-days")
		if validityDays <= 0 {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", "validity-days must be greater than 0", nil)
			return fmt.Errorf("validity-days must be greater than 0")
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesCreate, model.OpRenew)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to renew certificate: %w", err)
		}

		result, err := certService.RenewCertificate(ctx, certID, model.NewVaultScope(vaultID, claims.UserID), validityDays)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", fmt.Sprintf("failed to renew certificate: %s", err), err)
			return fmt.Errorf("failed to renew certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "renew_certificate", "success", fmt.Sprintf("certificate renewed: %s", result.CertID))
		// Renewal updates the row in place, so there is one ID, not two.
		fmt.Printf("Certificate renewed successfully!\nCertificate ID: %s\nValidity: %d days\n",
			result.CertID, validityDays)
		return nil
	},
}

// InitCertificatesRenew initializes the renew command for certificates.
func InitCertificatesRenew(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(renewCmd)

	renewCmd.Flags().Int("validity-days", 365, "Certificate validity period in days")
	viper.BindPFlag("cert-renew-validity-days", renewCmd.Flags().Lookup("validity-days")) //nolint:errcheck,gosec

	return certificatesCmd
}
