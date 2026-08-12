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

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update certificate metadata",
	Long:  `Update metadata for an X.509 certificate (name, tags). Requires admin or certificate_manager role.`,
	Example: `  # Update certificate metadata
  rocketvault certificate update <cert-id> --name "Updated name" \
    --tags prod,secure \
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

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesUpdate, model.OpSet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to update certificate: %w", err)
		}

		var namePtr *string
		if name != "" {
			namePtr = &name
		}

		req := certServices.UpdateCertificateRequest{
			CertID:      certID,
			Scope:       model.NewVaultScope(vaultID, claims.UserID),
			Name:        namePtr,
			Tags:        tags,
			AutoRenew:   autoRenewPtr,
			RenewalDays: renewalDaysPtr,
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
	updateCmd.Flags().Bool("auto-renew", false, "Enable or disable auto-renewal")
	updateCmd.Flags().Int("renewal-days", 0, "Days before expiry to trigger renewal")
	viper.BindPFlag("cert-update-name", updateCmd.Flags().Lookup("name")) //nolint:errcheck,gosec
	viper.BindPFlag("cert-update-tags", updateCmd.Flags().Lookup("tags")) //nolint:errcheck,gosec

	return certificatesCmd
}
