/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "list_certificates", Action: model.ActionCertificatesRead, Policy: model.OpGet,
			AuthzFailMsg: "failed to list certificates",
		})
		if err != nil {
			return err
		}

		if err := s.Authorize(); err != nil {
			return err
		}
		certService := s.Container.GetCertificateService()

		certs, err := certService.ListCertificates(s.Ctx, s.Scope, model.CertificateFilter{})
		if err != nil {
			return s.Fail("failed to list certificates", err)
		}

		s.OK(fmt.Sprintf("listed %d certificates", len(certs)))
		return vaultcli.Print(s, certColumns, certs...)
	},
}

// InitCertificatesList initializes the list command for certificates.
func InitCertificatesList(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(listCmd)
}
