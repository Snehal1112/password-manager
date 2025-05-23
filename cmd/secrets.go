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

	"password-manager/cmd/secrets"
)

// secretsCmd represents the secrets command
var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage secrets in the password manager",
	Long: `A command group for creating, retrieving, updating, listing, and deleting secrets,
as well as generating random passwords.`,
	Example: `secrets create --name <name> --value <value>`,
	Args:    cobra.ExactArgs(1),
}

func init() {
	rootCmd.AddCommand(secretsCmd)

	secrets.InitSecretsCreate(secretsCmd)
	secrets.InitSecretsDelete(secretsCmd)
	secrets.InitSecretsGenerate(secretsCmd)
	secrets.InitSecretsGet(secretsCmd)
	secrets.InitSecretsList(secretsCmd)
	secrets.InitSecretsUpdate(secretsCmd)

	secretsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
