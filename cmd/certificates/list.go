/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List certificates",
	Long: `List the X.509 certificates held in the target vault, one row each with
ID, name, tags, expiry, auto-renew flag and creation time. The listing is
vault-wide rather than filtered to the certificates the caller created, and
soft-deleted certificates are left out.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault. There is no role check on this command — the vault role
assignment is the whole gate, and it is deny-by-default.

Acts on the vault named by --vault, defaulting to "default". Certificates in
other vaults are never included; list them one vault at a time.`,
	Example: `  # List the certificates in the default vault
  rocketvault certificate list

  # List the certificates in a named vault
  rocketvault certificate list --vault payments

  # Machine-readable output
  rocketvault certificate list --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
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

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_certificates", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to list certificates: %w", err)
		}

		certs, err := certService.ListCertificates(ctx, model.NewVaultScope(vaultID, claims.UserID), model.CertificateFilter{})
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_certificates", "failed", fmt.Sprintf("failed to list certificates: %s", err), err)
			return fmt.Errorf("failed to list certificates: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "list_certificates", "success", fmt.Sprintf("listed %d certificates", len(certs)))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Tags", "Expires", "AutoRenew", "Created"}
		rows := make([][]string, len(certs))
		for i, c := range certs {
			rows[i] = []string{
				c.ID.String(),
				c.Name,
				strings.Join(c.Tags, ","),
				formatOptionalTime(c.ExpiresAt),
				strconv.FormatBool(c.AutoRenew),
				c.CreatedAt.Format(time.RFC3339),
			}
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
	},
}

// formatOptionalTime formats a pointer to time.Time as RFC3339, returning empty string for nil.
func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// InitCertificatesList initializes the list command for certificates.
func InitCertificatesList(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(listCmd)
	return certificatesCmd
}
