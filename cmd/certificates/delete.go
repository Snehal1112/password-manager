/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a certificate",
	Long: `Soft-delete an X.509 certificate by its UUID. The row is stamped with a
deletion time rather than removed, so the certificate disappears from
'rocketvault certificate list' but survives until the retention window ends
and the background purge scheduler destroys it. Recovering or purging it
before then is possible only over the REST soft-delete endpoints; the CLI
has no recover or purge subcommand for certificates.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/delete data action in the target
vault.

Acts on the vault named by --vault, defaulting to "default". A certificate
in another vault is invisible to this command and reports as not found.`,
	Example: `  # Delete a certificate in the default vault
  rocketvault certificate delete <id>

  # Delete a certificate in a named vault
  rocketvault certificate delete <id> --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesDelete, model.OpDelete)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to delete certificate: %w", err)
		}

		err = certService.DeleteCertificate(ctx, certID, model.NewVaultScope(vaultID, claims.UserID))
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", fmt.Sprintf("failed to delete certificate: %s", err), err)
			return fmt.Errorf("failed to delete certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "delete_certificate", "success", fmt.Sprintf("certificate deleted: %s", certID))
		fmt.Printf("Certificate deleted successfully: %s\n", certID)
		return nil
	},
}

// InitCertificatesDelete initializes the delete command for certificates.
func InitCertificatesDelete(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(deleteCmd)
	return certificatesCmd
}
