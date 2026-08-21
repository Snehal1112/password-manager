/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"github.com/spf13/cobra"

	"rocketvault/cmd/secrets"
)

// secretsCmd represents the secrets command
var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage secrets in the password manager",
	Long: `Manage the secrets held in a vault: create a secret, read it back, update
it into a new version, list and filter by tag, delete it, and bulk import or
export a vault's secrets. The group also generates random passwords, which are
returned to you and not stored. Two subgroups sit under it: 'secrets version'
walks a secret's version history, and 'secrets rotation' manages the policies
that rotate secrets on a schedule.

Creating, updating, deleting, importing, and exporting require the admin or
secrets_manager role plus the matching data action (secrets/set,
secrets/delete, secrets/get) in the target vault. get and list require only
their data action. Vault access is deny-by-default, so a role assignment must
exist for the target vault — see 'rocketvault vault-access'.

Every command here acts on the vault named by --vault, defaulting to
"default". Secret values are encrypted at rest, but export writes their
plaintext values to the file you name, so treat that file as a secret itself.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Create a tagged secret and read it back
  rocketvault secrets create <name> <value> --tags prod
  rocketvault secrets get <id>

  # List the secrets in a named vault
  rocketvault secrets list --vault payments

  # Export a vault's secrets to a file
  rocketvault secrets export --file <path> --format json --vault payments`,
}

func init() {
	rootCmd.AddCommand(secretsCmd)

	secrets.InitSecretsCreate(secretsCmd)
	secrets.InitSecretsDelete(secretsCmd)
	secrets.InitSecretsExport(secretsCmd)
	secrets.InitSecretsGenerate(secretsCmd)
	secrets.InitSecretsGet(secretsCmd)
	secrets.InitSecretsImport(secretsCmd)
	secrets.InitSecretsList(secretsCmd)
	secrets.InitSecretsUpdate(secretsCmd)

	secretsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
