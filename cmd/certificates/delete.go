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
	Long:  `Delete an X.509 certificate by its UUID. Requires admin or certificate_manager role.`,
	Example: `  # Delete a certificate
  rocketvault certificate delete <cert-id> \
    --username admin --password admin123 --totp-code <code>`,
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
