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
	"encoding/json"
	"log"
	"os"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"password-manager/common"
	"password-manager/internal/container"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get [id]",
	Short: "Retrieve a secret by ID",
	Long:  `Retrieve a secret by its ID for the authenticated user.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		secretID := uuid.MustParse(args[0])

		ctx := cmd.Context()
		userID := ctx.Value(common.UserIDKey).(uuid.UUID)

		// Get service container and secret service
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			logrus.Error("Service container not available in context")
			os.Exit(1)
			return
		}
		secretService := serviceContainer.GetSecretService()

		// Get secret via service (includes access control)
		secret, err := secretService.GetSecret(ctx, secretID, userID)
		if err != nil {
			logrus.WithError(err).Error("Failed to retrieve secret")
			os.Exit(1)
			return
		}

		// Log success
		logrus.WithFields(logrus.Fields{
			"secret_id": secret.ID.String(),
			"user_id":   userID.String(),
		}).Info("Secret retrieved successfully")

		jsonData, _ := json.MarshalIndent(secret, "", "  ")
		log.Println(string(jsonData))
	},
}

// InitSecretsGet initializes the get command for secrets
// It sets up the command flags and adds it to the secrets command tree.
// This function is called in the main function of the application to set up the command structure.
// It returns the modified secrets command.
// Parameters:
//
//	secretsCmd: The parent command under which the get command will be added.
//
// Returns:
//
//	The modified secrets command with the get command added.
func InitSecretsGet(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(getCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	return secretsCmd
}
