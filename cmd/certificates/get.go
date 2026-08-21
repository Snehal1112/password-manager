/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Retrieve a certificate",
	Long: `Print one certificate's metadata by UUID: its ID, name, tags, expiry,
auto-renew flag and creation time. Neither the certificate PEM nor its
private key is printed.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault. There is no role check on this command — the vault role
assignment is the whole gate, and it is deny-by-default.

Acts on the vault named by --vault, defaulting to "default", and finds only
certificates in that vault. A certificate that is disabled, not yet valid or
already expired is refused as inaccessible rather than printed.`,
	Example: `  # Show a certificate in the default vault
  rocketvault certificate get <id>

  # Show a certificate in a named vault
  rocketvault certificate get <id> --vault payments

  # Machine-readable output
  rocketvault certificate get <id> --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
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

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to get certificate: %w", err)
		}

		cert, err := certService.GetCertificate(ctx, certID, model.NewVaultScope(vaultID, claims.UserID))
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
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitCertificatesGet initializes the get command for certificates.
func InitCertificatesGet(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(getCmd)
	return certificatesCmd
}
