/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"password-manager/common"
	"password-manager/internal/container"
	"password-manager/internal/domain"
	"password-manager/internal/logging"
	certServices "password-manager/internal/services/certificates"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:     "update <id>",
	Short:   "Update certificate metadata",
	Long:    `Update metadata for an X.509 certificate (name, tags). Requires admin or certificate_manager role.`,
	Example: `password-manager certs update <cert-id> --username admin --password admin123 --totp-code <code> --name "Updated name" --tags prod,secure`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*domain.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasRequiredRole(claims.Role, domain.RoleAdmin, domain.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		name := viper.GetString("cert-update-name")
		tagsStr := viper.GetString("cert-update-tags")

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		var namePtr *string
		if name != "" {
			namePtr = &name
		}

		req := certServices.UpdateCertificateRequest{
			CertID: certID,
			UserID: claims.UserID,
			Name:   namePtr,
			Tags:   tags,
		}

		err = certService.UpdateCertificate(ctx, req)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", fmt.Sprintf("failed to update certificate: %s", err), err)
			return fmt.Errorf("failed to update certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "update_certificate", "success", fmt.Sprintf("certificate updated: %s", certID))
		fmt.Printf("Certificate updated successfully: %s\n", certID)
		return nil
	},
}

// InitCertificatesUpdate initializes the update command for certificates.
func InitCertificatesUpdate(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(updateCmd)

	updateCmd.Flags().String("name", "", "Updated name for the certificate")
	updateCmd.Flags().String("tags", "", "Comma-separated tags for the certificate")
	viper.BindPFlag("cert-update-name", updateCmd.Flags().Lookup("name"))
	viper.BindPFlag("cert-update-tags", updateCmd.Flags().Lookup("tags"))

	return certificatesCmd
}
