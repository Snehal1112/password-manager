/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/domain"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:     "get <id>",
	Short:   "Retrieve a certificate",
	Long:    `Retrieve details of an X.509 certificate by its UUID. Accessible by the certificate's owner or users with the admin role.`,
	Example: `rocketvault certs get <cert-id> --username admin --password admin123 --totp-code <code>`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*domain.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		cert, err := certService.GetCertificate(ctx, certID, claims.UserID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate", "failed", fmt.Sprintf("failed to get certificate: %s", err), err)
			return fmt.Errorf("failed to get certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "get_certificate", "success", fmt.Sprintf("certificate retrieved: %s", cert.Name))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Tags", "Expires", "AutoRenew", "Created"}
		row := []string{
			cert.ID.String(),
			cert.Name,
			strings.Join(cert.Tags, ","),
			formatOptionalTime(cert.ExpiresAt),
			strconv.FormatBool(cert.AutoRenew),
			cert.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(os.Stdout, headers, [][]string{row})
	},
}

// InitCertificatesGet initializes the get command for certificates.
func InitCertificatesGet(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(getCmd)
	return certificatesCmd
}
