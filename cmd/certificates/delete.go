/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a certificate",
	Long: `Soft-delete an X.509 certificate by its UUID. The row is stamped with a
deletion time rather than removed, so the certificate disappears from
'rocketvault certificate list' but survives until the retention window ends
and the background purge scheduler destroys it. Recovering or purging it
before then is possible only over the REST soft-delete endpoints; the CLI
has no recover or purge subcommand for certificates.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/delete data action in the target
vault.

Acts on the vault named by --vault, defaulting to "default". A certificate
in another vault is invisible to this command and reports as not found.`,
	Example: `  # Delete a certificate in the default vault
  rocketvault certificate delete <id>

  # Delete a certificate in a named vault
  rocketvault certificate delete <id> --vault payments`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "delete_certificate", Action: model.ActionCertificatesDelete, Policy: model.OpDelete,
			Roles:        []string{model.RoleAdmin, model.RoleCertificateManager},
			AuthzFailMsg: "failed to delete certificate",
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
		certService := s.Container.GetCertificateService()

		err = certService.DeleteCertificate(s.Ctx, certID, s.Scope)
		if err != nil {
			return s.Fail("failed to delete certificate", err)
		}

		s.OK(fmt.Sprintf("certificate deleted: %s", certID))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate deleted successfully: %s\n", certID)
		return nil
	},
}

// InitCertificatesDelete initializes the delete command for certificates.
func InitCertificatesDelete(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(deleteCmd)
}
