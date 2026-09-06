/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "get_certificate_rotation_policy", Action: model.ActionCertificatesRead, Policy: model.OpGet,
		})
		if err != nil {
			return err
		}
		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetCertificateService()

		policy, err := svc.GetCertificatePolicy(s.Ctx, certID, s.Scope)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				s.OK(fmt.Sprintf("no rotation policy for certificate: %s", certID))
				fmt.Fprintf(cmd.OutOrStdout(), "No rotation policy set for certificate %s\n", certID) //nolint:errcheck,gosec
				return nil
			}
			return s.Fail("failed to get rotation policy", err)
		}

		s.OK(fmt.Sprintf("rotation policy retrieved for certificate: %s", certID))
		return vaultcli.Print(s, certPolicyColumns, policy)
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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "set_certificate_rotation_policy", Action: model.ActionCertificatesUpdate, Policy: model.OpSet,
			Roles: []string{model.RoleAdmin, model.RoleCertificateManager},
		})
		if err != nil {
			return err
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}

		if !cmd.Flags().Changed("validity-months") || !cmd.Flags().Changed("subject") {
			return s.Fail("--validity-months and --subject are required: this replaces the whole policy, so every field must be supplied", nil)
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

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetCertificateService()

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
		policy, err := svc.UpsertCertificatePolicy(s.Ctx, certID, s.Scope, req)
		if err != nil {
			return s.Fail("failed to set rotation policy", err)
		}

		s.OK(fmt.Sprintf("rotation policy set for certificate: %s", certID))
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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "delete_certificate_rotation_policy", Action: model.ActionCertificatesUpdate, Policy: model.OpDelete,
			Roles: []string{model.RoleAdmin, model.RoleCertificateManager},
		})
		if err != nil {
			return err
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			return s.Fail("invalid certificate ID", err)
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetCertificateService()

		if err := svc.DeleteCertificatePolicy(s.Ctx, certID, s.Scope); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return s.Fail(fmt.Sprintf("no rotation policy exists for certificate %s", certID), nil)
			}
			return s.Fail("failed to delete rotation policy", err)
		}

		s.OK(fmt.Sprintf("rotation policy deleted for certificate: %s", certID))
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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "list_certificate_rotation_policies", Action: model.ActionCertificatesRead, Policy: model.OpGet,
		})
		if err != nil {
			return err
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetCertificateService()

		policies, err := svc.ListCertificatePolicies(s.Ctx, s.Scope)
		if err != nil {
			return s.Fail("failed to list certificate policies", err)
		}

		s.OK(fmt.Sprintf("listed %d certificate policies", len(policies)))
		return vaultcli.Print(s, certPolicyListColumns, policies...)
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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "certificate_rotation_policy_status", Action: model.ActionCertificatesRead, Policy: model.OpGet,
		})
		if err != nil {
			return err
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		svc := s.Container.GetCertificateService()

		due, err := svc.ListCertificatesDueForRenewal(s.Ctx, s.Scope)
		if err != nil {
			return s.Fail("failed to get due certificate renewals", err)
		}
		policies, err := svc.ListCertificatePolicies(s.Ctx, s.Scope)
		if err != nil {
			return s.Fail("failed to list certificate policies", err)
		}

		s.OK(fmt.Sprintf("%d due, %d policies", len(due), len(policies)))

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
func InitCertificatesRotationPolicy(certificatesCmd *cobra.Command) {
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
}
