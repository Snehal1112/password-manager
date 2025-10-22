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

	"password-manager/common"
	"password-manager/internal/container"
	"password-manager/internal/services/secrets"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:     "create <name> <value>",
	Aliases: []string{"add"},
	Short:   "Create a new secret",
	Long:    `Create a new secret in the password manager. You can specify the secret name, value, and optional tags.`,
	Example: `password-manager secrets create my-secret my-value`,
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		value := args[1]
		tags, _ := cmd.Flags().GetStringSlice("tags")
		userID := cmd.Context().Value(common.UserIDKey).(uuid.UUID)

		// Get service container and secret service
		serviceContainer, ok := cmd.Context().Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			logrus.Error("Service container not available in context")
			os.Exit(1)
			return
		}
		secretService := serviceContainer.GetSecretService()

		// Create secret request
		req := secrets.CreateSecretRequest{
			UserID: userID,
			Name:   name,
			Value:  value,
			Tags:   tags,
		}

		// Create secret via service
		secret, err := secretService.CreateSecret(cmd.Context(), req)
		if err != nil {
			logrus.WithError(err).Error("Failed to create secret")
			os.Exit(1)
			return
		}

		// Log success
		logrus.WithFields(logrus.Fields{
			"user_id":   userID.String(),
			"secret_id": secret.ID.String(),
			"name":      name,
		}).Info("Secret created successfully")
	},
}

// InitSecretsCreate initializes the create command for secrets.
// It sets up the command with flags and adds it to the secrets command group.
// The create command allows users to create a new secret with a name, value, and optional tags.
// It also sets up the command to use the database and logger from the context.
// Parameters:
//   - secretsCmd: *cobra.Command - the parent command to which the create command will be added
//
// Return type: *cobra.Command - the initialized create command
// Example usage:
//
//	secretsCmd := &cobra.Command{Use: "secrets"}
//	createCmd := InitSecretsCreate(secretsCmd)
//	createCmd.Execute()
func InitSecretsCreate(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(createCmd)

	createCmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")

	return secretsCmd
}
