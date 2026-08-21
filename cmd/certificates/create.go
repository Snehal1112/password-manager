/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// createCmd represents the create command
// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new X.509 certificate",
	Long: `Issue an X.509 certificate over a key that already exists in the target
vault, and store the certificate in that same vault. Without --ca-cert-id
the certificate is self-signed; with --ca-cert-id it is signed by that CA
certificate, which must live in the same vault.

The certificate is an ordinary leaf unless you pass --is-ca, which marks it
as a Certificate Authority so it can sign later certificates. Ask for that
only when you mean it: anything holding a CA's private key can issue
certificates for any name. --is-ca cannot be combined with --ca-cert-id.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/create data action in the target
vault. The key named by --key-id must also be owned by the calling user, as
must the certificate named by --ca-cert-id.

Acts on the vault named by --vault, defaulting to "default". --name and
--key-id are required and --validity-days must be positive. --auto-renew and
--renewal-days only arm the background renewal scheduler for later; they
change nothing about the certificate being issued now. --purge-protection is
sent only when the flag is passed explicitly.`,
	Example: `  # Self-signed certificate over an existing key
  rocketvault certificate create --name <name> --key-id <key-id> \
    --validity-days 365

  # Self-signed CA that can sign later certificates
  rocketvault certificate create --name <name> --key-id <key-id> \
    --is-ca --validity-days 3650

  # Certificate signed by a CA certificate in the same vault
  rocketvault certificate create --name <name> --key-id <key-id> \
    --ca-cert-id <ca-cert-id> --validity-days 90

  # Tagged, auto-renewing certificate in a named vault
  rocketvault certificate create --name <name> --key-id <key-id> \
    --tags prod,tls --auto-renew --renewal-days 45 --vault payments`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		name := viper.GetString("cert-name")
		keyIDStr := viper.GetString("cert-key-id")
		validityDays := viper.GetInt("cert-validity-days")
		tagsStr := viper.GetString("cert-tags")
		caCertIDStr := viper.GetString("cert-ca-cert-id")
		autoRenew, _ := cmd.Flags().GetBool("auto-renew")
		renewalDays, _ := cmd.Flags().GetInt("renewal-days")
		isCA, _ := cmd.Flags().GetBool("is-ca")

		if name == "" || keyIDStr == "" || validityDays <= 0 {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", "name, key-id, and validity-days are required", nil)
			return fmt.Errorf("name, key-id, and validity-days are required")
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
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
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesCreate, model.OpCreate)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		// Create certificate request
		req := certServices.CreateCertificateRequest{
			Name:         name,
			KeyID:        keyID,
			ValidityDays: validityDays,
			Tags:         tags,
			UserID:       claims.UserID,
			VaultID:      vaultID,
			AutoRenew:    autoRenew,
			RenewalDays:  renewalDays,
			IsCA:         isCA,
		}
		// Only send purge protection when the flag was explicitly passed.
		if cmd.Flags().Changed("purge-protection") {
			purgeProtection, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &purgeProtection
		}

		var result *certServices.CreateCertificateResult
		if caCertIDStr != "" {
			// CA-signed certificate
			caCertID, parseErr := uuid.Parse(caCertIDStr)
			if parseErr != nil {
				log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", fmt.Sprintf("invalid CA certificate ID: %s", parseErr), parseErr)
				return fmt.Errorf("invalid CA certificate ID: %w", parseErr)
			}
			req.CACertID = &caCertID
			log.WithField("ca_cert_id", caCertID).Info("Creating CA-signed certificate")
			result, err = certService.CreateCASignedCertificate(ctx, req)
		} else {
			// Self-signed certificate
			result, err = certService.CreateSelfSignedCertificate(ctx, req)
		}

		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", fmt.Sprintf("failed to create certificate: %s", err), err)
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "create_certificate", "success", fmt.Sprintf("certificate created: %s, ID: %s", result.Name, result.CertID))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Created"}
		row := []string{
			result.CertID.String(),
			result.Name,
			result.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitCertificatesCreate initializes the create command for certificates.
func InitCertificatesCreate(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(createCmd)

	createCmd.Flags().String("name", "", "Name (Common Name) for the new certificate")
	createCmd.Flags().String("key-id", "", "UUID of the key to use for the certificate")
	createCmd.Flags().Int("validity-days", 365, "Certificate validity period in days")
	createCmd.Flags().String("tags", "", "Comma-separated tags for the certificate")
	createCmd.Flags().String("ca-cert-id", "", "UUID of the CA certificate for CA-signed certificates (optional)")
	createCmd.Flags().Bool("auto-renew", false, "Automatically renew certificate before expiry")
	createCmd.Flags().Int("renewal-days", 30, "Days before expiry to trigger renewal")
	createCmd.Flags().Bool("purge-protection", false, "Protect the certificate from being purged")
	createCmd.Flags().Bool("is-ca", false, "Issue the certificate as a Certificate Authority that can sign other certificates")
	viper.BindPFlag("cert-name", createCmd.Flags().Lookup("name"))                   //nolint:errcheck,gosec
	viper.BindPFlag("cert-key-id", createCmd.Flags().Lookup("key-id"))               //nolint:errcheck,gosec
	viper.BindPFlag("cert-validity-days", createCmd.Flags().Lookup("validity-days")) //nolint:errcheck,gosec
	viper.BindPFlag("cert-tags", createCmd.Flags().Lookup("tags"))                   //nolint:errcheck,gosec
	viper.BindPFlag("cert-ca-cert-id", createCmd.Flags().Lookup("ca-cert-id"))       //nolint:errcheck,gosec

	return certificatesCmd
}
