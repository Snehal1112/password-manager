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
		s, err := vaultcli.Caller(cmd, vaultcli.Op{
			Audit: "get_certificate", Action: model.ActionCertificatesRead, Policy: model.OpGet,
			AuthzFailMsg: "failed to get certificate",
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

		cert, err := certService.GetCertificate(s.Ctx, certID, s.Scope)
		if err != nil {
			return s.Fail("failed to get certificate", err)
		}

		s.OK(fmt.Sprintf("certificate retrieved: %s", cert.Name))
		return vaultcli.Print(s, certColumns, *cert)
	},
}

// InitCertificatesGet initializes the get command for certificates.
func InitCertificatesGet(certificatesCmd *cobra.Command) {
	certificatesCmd.AddCommand(getCmd)
}
