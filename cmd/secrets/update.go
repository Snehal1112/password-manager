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
	"database/sql"
	"os"
	"password-manager/internal/logging"
	"password-manager/internal/secrets"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update [id] [value]",
	Short: "Update a secret",
	Long:  `Update a secret’s value and tags by its ID for the authenticated user.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		secretID := uuid.MustParse(args[0])
		value := args[1]
		tags, _ := cmd.Flags().GetStringSlice("tags")

		ctx := cmd.Context()
		userID := ctx.Value("userID").(uuid.UUID)
		db := ctx.Value("db").(*sql.DB)
		logger := ctx.Value("log").(*logging.Logger)

		repo := secrets.NewSecretRepository(db, logger)
		secret, err := repo.Read(cmd.Context(), secretID)
		if err != nil {
			logger.Error("Failed to read secret: ", err)
			os.Exit(0)
			return
		}
		if secret.UserID != userID {
			logger.Warn("Unauthorized access attempt to secret")
			os.Exit(0)
			return
		}

		secret.Value = value
		secret.Tags = tags
		secret.Version++
		secret.CreatedAt = time.Now()
		if err := repo.Update(cmd.Context(), secret); err != nil {
			logger.Error("Failed to update secret: ", err)
			os.Exit(0)
			return
		}

		logger.WithFields(logrus.Fields{
			"secret_id": secretID.String(),
			"user_id":   userID.String(),
		}).Info("Secret updated successfully")
	},
}

func InitSecretsUpdate(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(updateCmd)

	updateCmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")

	return secretsCmd
}
