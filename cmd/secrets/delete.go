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

package secrets

import (
	"os"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a secret by ID",
	Long:  `Delete a secret by its ID for the authenticated user.`,
	Example: `  # Soft-delete a secret by id
  rocketvault secrets delete <id> \
    --username admin --password admin123 --totp-code <code>`,
	Run: func(cmd *cobra.Command, args []string) {
		secretID := uuid.MustParse(args[0])

		ctx := cmd.Context()

		// Get service container and secret service
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			logrus.Error("Service container not available in context")
			os.Exit(1)
			return
		}
		secretService := serviceContainer.GetSecretService()

		// Resolve the target vault by name.
		vaultID, err := resolveVaultID(ctx, cmd, serviceContainer)
		if err != nil {
			logrus.WithError(err).Error("Failed to resolve vault")
			os.Exit(1)
			return
		}

		// Delete secret via service (includes access control).
		err = secretService.DeleteSecretInVault(ctx, secretID, vaultID)
		if err != nil {
			logrus.WithError(err).Error("Failed to delete secret")
			os.Exit(1)
			return
		}

		logrus.WithFields(logrus.Fields{
			"secret_id": secretID.String(),
			"vault_id":  vaultID.String(),
		}).Info("Secret deleted successfully")
	},
}

// InitSecretsDelete initializes the delete command for secrets
// and adds it to the secrets command.
// It also sets up the necessary flags and configuration settings.
// This function is called in the main package to set up the command.
// It returns the modified secrets command.
// Parameters:
// - secretsCmd: The parent command to which the delete command will be added.
// Returns:
// - *cobra.Command: The modified secrets command with the delete command added.
func InitSecretsDelete(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(deleteCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deleteCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// deleteCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	return secretsCmd
}
