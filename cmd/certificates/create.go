/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/certificates"
	"password-manager/internal/keys"
	"password-manager/internal/logging"
)

// createCmd represents the create command
// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:     "create",
	Short:   "Create a new X.509 certificate",
	Long:    `Create a self-signed or CA-signed X.509 certificate using an existing key. Requires admin or certificate_manager role.`,
	Example: `password-manager certs create --username admin --password admin123 --totp-code <code> --name mycert --key-id <key-id> --validity-days 365 --tags prod,secure [--ca-cert-id <ca-cert-id>]`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if claims.Role != auth.RoleAdmin && claims.Role != auth.RoleCertificateManager {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		name := viper.GetString("cert-name")
		keyIDStr := viper.GetString("cert-key-id")
		validityDays := viper.GetInt("cert-validity-days")
		tagsStr := viper.GetString("cert-tags")
		caCertIDStr := viper.GetString("cert-ca-cert-id")

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

		// Verify key ownership
		keyRepo := keys.NewKeyRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		key, err := keyRepo.Read(ctx, keyID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", fmt.Sprintf("failed to read key: %s", err), err)
			return fmt.Errorf("failed to read key: %w", err)
		}
		if key.UserID != claims.UserID && claims.Role != auth.RoleAdmin {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", "forbidden: cannot use other users' keys", nil)
			return fmt.Errorf("forbidden: cannot use other users' keys")
		}

		certRepo := certificates.NewCertificateRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		var cert *certificates.Certificate
		if caCertIDStr != "" {
			// CA-signed certificate
			caCertID, parseErr := uuid.Parse(caCertIDStr)
			if parseErr != nil {
				log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", fmt.Sprintf("invalid CA certificate ID: %s", parseErr), parseErr)
				return fmt.Errorf("invalid CA certificate ID: %w", parseErr)
			}
			log.WithField("ca_cert_id", caCertID).Info("Creating CA-signed certificate")
			cert, err = certRepo.CreateCASigned(ctx, claims.UserID, name, keyID, caCertID, validityDays, tags)
		} else {
			// Self-signed certificate
			cert, err = certRepo.CreateSelfSigned(ctx, claims.UserID, name, keyID, validityDays, tags)
		}

		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_certificate", "failed", fmt.Sprintf("failed to create certificate: %s", err), err)
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "create_certificate", "success", fmt.Sprintf("certificate created: %s, ID: %s", cert.Name, cert.ID))
		fmt.Printf("Certificate created successfully, ID: %s\n", cert.ID)
		return nil
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
	viper.BindPFlag("cert-name", createCmd.Flags().Lookup("name"))
	viper.BindPFlag("cert-key-id", createCmd.Flags().Lookup("key-id"))
	viper.BindPFlag("cert-validity-days", createCmd.Flags().Lookup("validity-days"))
	viper.BindPFlag("cert-tags", createCmd.Flags().Lookup("tags"))
	viper.BindPFlag("cert-ca-cert-id", createCmd.Flags().Lookup("ca-cert-id"))

	return certificatesCmd
}
