/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
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

// rotationPolicyCmd represents the parent "rotation-policy" command.
var rotationPolicyCmd = &cobra.Command{
	Use:   "rotation-policy",
	Short: "Manage a certificate's issuance and renewal policy",
	Long: `Get, set or delete the policy attached to a certificate: the validity
period, key type and subject/SAN template used when the certificate is
(re)issued, and the auto-renewal window. Azure Key Vault has no separate data
action for this policy -- it is treated as part of updating the certificate
itself, and this command mirrors that.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help() //nolint:errcheck,gosec
	},
}

// rotationPolicyGetCmd represents the "rotation-policy get" command.
var rotationPolicyGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Show a certificate's issuance and renewal policy",
	Long: `Print the policy attached to a certificate by its UUID: the validity
period, key type/size/curve, subject and SANs, and the auto-renew window.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault, which defaults to "default". No global role is checked here.
A certificate with no policy set is reported, not treated as an error.`,
	Example: `  # Show a certificate's policy in the default vault
  rocketvault certificates rotation-policy get <cert-id>

  # Show a certificate's policy in a named vault
  rocketvault certificates rotation-policy get <cert-id> --vault payments`,
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
			log.LogAuditError(claims.UserID.String(), "get_certificate_rotation_policy", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate_rotation_policy", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate_rotation_policy", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		policy, err := certService.GetCertificatePolicy(ctx, certID, model.NewVaultScope(vaultID, claims.UserID))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.LogAuditInfo(claims.UserID.String(), "get_certificate_rotation_policy", "success", fmt.Sprintf("no rotation policy for certificate: %s", certID))
				fmt.Fprintf(cmd.OutOrStdout(), "No rotation policy set for certificate %s\n", certID) //nolint:errcheck,gosec
				return nil
			}
			log.LogAuditError(claims.UserID.String(), "get_certificate_rotation_policy", "failed", fmt.Sprintf("failed to get rotation policy: %s", err), err)
			return fmt.Errorf("failed to get rotation policy: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "get_certificate_rotation_policy", "success", fmt.Sprintf("rotation policy retrieved for certificate: %s", certID))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"Validity-Months", "Key-Type", "Key-Size", "Curve", "Subject", "SANs", "Auto-Renew", "Days-Before-Expiry", "Issuer-Name", "Updated"}
		row := []string{
			strconv.Itoa(policy.ValidityMonths),
			policy.KeyType,
			strconv.Itoa(policy.KeySize),
			policy.Curve,
			policy.Subject,
			policy.SANs,
			strconv.FormatBool(policy.AutoRenew),
			strconv.Itoa(policy.DaysBeforeExpiry),
			policy.IssuerName,
			policy.UpdatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// rotationPolicySetCmd represents the "rotation-policy set" command.
var rotationPolicySetCmd = &cobra.Command{
	Use:   "set <id>",
	Short: "Create or replace a certificate's renewal policy",
	Long: `Create or replace the policy attached to a certificate by its UUID. This is
a full replace, not a partial merge: --validity-months and --subject must
both be supplied on every call, since they are the only two fields with no
safe empty default -- read the current policy first with "rotation-policy
get" if you only mean to change one field. Every other flag defaults to its
zero value (empty string, 0, or false) when omitted, which is meaningful on
its own (e.g. --auto-renew unset means auto-renewal stays off).

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/update data action in the target
vault, which defaults to "default" -- Azure Key Vault has no separate policy
data action, so writing or clearing a policy is treated as an update of the
certificate itself.`,
	Example: `  # Set a policy requesting a 12-month RSA certificate
  rocketvault certificates rotation-policy set <cert-id> \
    --validity-months 12 --subject "CN=example.com" --key-type RSA --key-size 2048

  # Also request SANs and auto-renewal 30 days before expiry
  rocketvault certificates rotation-policy set <cert-id> \
    --validity-months 12 --subject "CN=example.com" \
    --sans "DNS:example.com,DNS:www.example.com" \
    --auto-renew --days-before-expiry 30

  # Set a policy in a named vault
  rocketvault certificates rotation-policy set <cert-id> \
    --validity-months 12 --subject "CN=example.com" --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "set_certificate_rotation_policy", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "set_certificate_rotation_policy", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		if !cmd.Flags().Changed("validity-months") || !cmd.Flags().Changed("subject") {
			log.LogAuditError(claims.UserID.String(), "set_certificate_rotation_policy", "failed", "missing required flags: --validity-months and --subject", nil)
			return fmt.Errorf("--validity-months and --subject are required: this replaces the whole policy, so every field must be supplied")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "set_certificate_rotation_policy", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}

		validityMonths, _ := cmd.Flags().GetInt("validity-months")
		keyType, _ := cmd.Flags().GetString("key-type")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		subject, _ := cmd.Flags().GetString("subject")
		sans, _ := cmd.Flags().GetString("sans")
		autoRenew, _ := cmd.Flags().GetBool("auto-renew")
		daysBeforeExpiry, _ := cmd.Flags().GetInt("days-before-expiry")
		issuerName, _ := cmd.Flags().GetString("issuer-name")

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesUpdate, model.OpSet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "set_certificate_rotation_policy", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		req := model.UpsertCertificatePolicyRequest{
			ValidityMonths:   validityMonths,
			KeyType:          keyType,
			KeySize:          keySize,
			Curve:            curve,
			Subject:          subject,
			SANs:             sans,
			AutoRenew:        autoRenew,
			DaysBeforeExpiry: daysBeforeExpiry,
			IssuerName:       issuerName,
		}
		policy, err := serviceContainer.GetCertificateService().UpsertCertificatePolicy(ctx, certID, model.NewVaultScope(vaultID, claims.UserID), req)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "set_certificate_rotation_policy", "failed", fmt.Sprintf("failed to set rotation policy: %s", err), err)
			return fmt.Errorf("failed to set rotation policy: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "set_certificate_rotation_policy", "success", fmt.Sprintf("rotation policy set for certificate: %s", certID))
		fmt.Fprintf(cmd.OutOrStdout(), "Rotation policy set for certificate %s: validity %d months, subject %q\n", //nolint:errcheck,gosec
			certID, policy.ValidityMonths, policy.Subject)
		return nil
	},
}

// rotationPolicyDeleteCmd represents the "rotation-policy delete" command.
var rotationPolicyDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a certificate's issuance and renewal policy",
	Long: `Delete the policy attached to a certificate by its UUID. The certificate
itself is unaffected; only the stored policy is removed. A later re-issuance
or renewal falls back to whatever parameters are passed explicitly at that
time.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/update data action in the target
vault, which defaults to "default" -- Azure Key Vault has no separate policy
data action, so writing or clearing a policy is treated as an update of the
certificate itself.`,
	Example: `  # Delete a certificate's policy in the default vault
  rocketvault certificates rotation-policy delete <cert-id>

  # Delete a certificate's policy in a named vault
  rocketvault certificates rotation-policy delete <cert-id> --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "delete_certificate_rotation_policy", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate_rotation_policy", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate_rotation_policy", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesUpdate, model.OpDelete)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate_rotation_policy", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		if err := serviceContainer.GetCertificateService().DeleteCertificatePolicy(ctx, certID, model.NewVaultScope(vaultID, claims.UserID)); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.LogAuditError(claims.UserID.String(), "delete_certificate_rotation_policy", "failed", fmt.Sprintf("no rotation policy for certificate: %s", certID), err)
				return fmt.Errorf("no rotation policy exists for certificate %s", certID)
			}
			log.LogAuditError(claims.UserID.String(), "delete_certificate_rotation_policy", "failed", fmt.Sprintf("failed to delete rotation policy: %s", err), err)
			return fmt.Errorf("failed to delete rotation policy: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "delete_certificate_rotation_policy", "success", fmt.Sprintf("rotation policy deleted for certificate: %s", certID))
		fmt.Fprintf(cmd.OutOrStdout(), "Rotation policy for certificate %s deleted successfully\n", certID) //nolint:errcheck,gosec
		return nil
	},
}

// rotationPolicyListCmd represents the "rotation-policy list" command.
var rotationPolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every certificate with a policy set in a vault",
	Long: `List every certificate in the target vault that currently has an issuance
and renewal policy set: certificate ID, certificate name, validity months,
auto-renew, and days-before-expiry. Certificates with no policy set are
simply absent from the list -- this lists policies, not all certificates.

The Auto-Renew and Days-Before-Expiry columns here come from the policy
record itself, not from the certificate row's own auto_renew/renewal_days
fields -- see "rotation-policy status" for why the two can disagree.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault, which defaults to "default". No global role is checked here.`,
	Example: `  # List certificate policies in the default vault
  rocketvault certificates rotation-policy list

  # List certificate policies in a named vault
  rocketvault certificates rotation-policy list --vault payments`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "list_certificate_rotation_policies", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_certificate_rotation_policies", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		policies, err := certService.ListCertificatePolicies(ctx, model.NewVaultScope(vaultID, claims.UserID))
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_certificate_rotation_policies", "failed", fmt.Sprintf("failed to list certificate policies: %s", err), err)
			return fmt.Errorf("failed to list certificate policies: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "list_certificate_rotation_policies", "success", fmt.Sprintf("listed %d certificate policies", len(policies)))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"Certificate-ID", "Certificate-Name", "Validity-Months", "Auto-Renew", "Days-Before-Expiry"}
		rows := make([][]string, len(policies))
		for i, p := range policies {
			rows[i] = []string{
				p.CertificateID.String(),
				p.CertificateName,
				strconv.Itoa(p.ValidityMonths),
				strconv.FormatBool(p.AutoRenew),
				strconv.Itoa(p.DaysBeforeExpiry),
			}
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
	},
}

// rotationPolicyStatusCmd represents the "rotation-policy status" command.
var rotationPolicyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "View certificate renewal status and active policies",
	Long: `Summarise certificate renewal for the target vault in two parts, drawn from
two genuinely different signals that this installation does NOT keep in
sync with each other:

  - "Certificates due for renewal" reads each certificate's own auto_renew,
    renewal_days and expires_at columns -- the exact fields the real
    auto-renewal scheduler (CertificateRenewalService, running inside
    "rocketvault serve") acts on. A certificate is listed here when it is
    not yet expired, its own auto_renew is on, and it has entered its
    renewal window.
  - "Active certificate policies" reads the separate policy records this
    command's own "get"/"set" subcommands manage, filtered to those with
    their own auto-renew flag on. A policy's auto-renew and
    days-before-expiry describe what a future (re)issuance should request;
    they are never read by the scheduler above. A certificate and its policy
    can disagree about auto-renewal, so this report keeps the two sections
    separate rather than conflating them into one.

Requires the Microsoft.KeyVault/vaults/certificates/read data action in the
target vault, which defaults to "default". No global role is checked here.

This is a read-only report: nothing is renewed by running it. Automatic
renewal is carried out by the scheduler inside a running "rocketvault serve"
process; "certificates renew" is the only way to renew from the CLI.`,
	Example: `  # Show certificate renewal status for the default vault
  rocketvault certificates rotation-policy status

  # Show certificate renewal status for a named vault
  rocketvault certificates rotation-policy status --vault payments`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "certificate_rotation_policy_status", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "certificate_rotation_policy_status", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}
		scope := model.NewVaultScope(vaultID, claims.UserID)

		due, err := certService.ListCertificatesDueForRenewal(ctx, scope)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "certificate_rotation_policy_status", "failed", fmt.Sprintf("failed to get due renewals: %s", err), err)
			return fmt.Errorf("failed to get due certificate renewals: %w", err)
		}
		policies, err := certService.ListCertificatePolicies(ctx, scope)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "certificate_rotation_policy_status", "failed", fmt.Sprintf("failed to list policies: %s", err), err)
			return fmt.Errorf("failed to list certificate policies: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "certificate_rotation_policy_status", "success", fmt.Sprintf("%d due, %d policies", len(due), len(policies)))

		fmt.Fprintln(cmd.OutOrStdout(), "Certificate Renewal Status")               //nolint:errcheck
		fmt.Fprintln(cmd.OutOrStdout(), "────────────────────────────────────────") //nolint:errcheck
		if len(due) > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "Certificates due for renewal (certificate row's own auto_renew/renewal_days):") //nolint:errcheck
			for _, c := range due {
				expiry := "-"
				if c.ExpiresAt != nil {
					expiry = c.ExpiresAt.Format("2006-01-02")
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s (%s) (expires: %s)\n", //nolint:errcheck
					c.Name, c.ID.String()[:8]+"...", expiry)
			}
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "No certificates are currently due for renewal.") //nolint:errcheck
		}
		if len(policies) > 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "\nActive certificate policies (policy-level auto-renew; may disagree with the certificate row above):") //nolint:errcheck
			foundAutoRenew := false
			for _, p := range policies {
				if p.AutoRenew {
					foundAutoRenew = true
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s: renew %d days before expiry\n", p.CertificateName, p.DaysBeforeExpiry) //nolint:errcheck
				}
			}
			if !foundAutoRenew {
				fmt.Fprintln(cmd.OutOrStdout(), "  (none with policy-level auto-renew enabled)") //nolint:errcheck
			}
		}
		return nil
	},
}

// InitCertificatesRotationPolicy adds the "rotation-policy" command, and its
// get, set, delete, list and status subcommands, to the certificates command.
func InitCertificatesRotationPolicy(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(rotationPolicyCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyGetCmd)
	rotationPolicyCmd.AddCommand(rotationPolicySetCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyDeleteCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyListCmd)
	rotationPolicyCmd.AddCommand(rotationPolicyStatusCmd)

	rotationPolicySetCmd.Flags().Int("validity-months", 0, "Validity period in months for (re)issuance (required)")
	rotationPolicySetCmd.Flags().String("key-type", "", "Key type requested at (re)issuance, e.g. RSA or EC")
	rotationPolicySetCmd.Flags().Int("key-size", 0, "Key size in bits requested at (re)issuance, when applicable")
	rotationPolicySetCmd.Flags().String("curve", "", "Elliptic curve requested at (re)issuance, when applicable")
	rotationPolicySetCmd.Flags().String("subject", "", "X.509 subject, e.g. CN=example.com (required)")
	rotationPolicySetCmd.Flags().String("sans", "", "Comma-separated Subject Alternative Names, e.g. DNS:example.com")
	rotationPolicySetCmd.Flags().Bool("auto-renew", false, "Whether to automatically renew before expiry")
	rotationPolicySetCmd.Flags().Int("days-before-expiry", 0, "Days before expiry to trigger auto-renewal")
	rotationPolicySetCmd.Flags().String("issuer-name", "", "Issuer to request the certificate from")

	return certificatesCmd
}
