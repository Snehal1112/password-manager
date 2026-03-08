/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List certificates",
	Long:    `List all X.509 certificates for the authenticated user. Admins can list all certificates.`,
	Example: `rocketvault certs list --username admin --password admin123 --totp-code <code>`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*domain.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "list_certificates", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		certs, err := certService.ListCertificates(ctx, claims.UserID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_certificates", "failed", fmt.Sprintf("failed to list certificates: %s", err), err)
			return fmt.Errorf("failed to list certificates: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "list_certificates", "success", fmt.Sprintf("listed %d certificates", len(certs)))
		if len(certs) == 0 {
			fmt.Println("No certificates found.")
			return nil
		}

		fmt.Println("Certificates:")
		for _, cert := range certs {
			fmt.Printf("- ID=%s, Name=%s, CreatedAt=%s, Tags=[%s]\n",
				cert.ID, cert.Name, cert.CreatedAt.Format(time.RFC3339), strings.Join(cert.Tags, ", "))
		}
		return nil
	},
}

// InitCertificatesList initializes the list command for certificates.
func InitCertificatesList(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(listCmd)
	return certificatesCmd
}
