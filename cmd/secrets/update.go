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

// InitSecretsUpdate initializes the update command for secrets
// and adds it to the secrets command.
// It also sets up the necessary flags and configuration settings.
// This function is called in the main function of the application to set up the command structure.
// It returns the modified secrets command.
// Parameters:
//
//	secretsCmd: The parent command under which the update command will be added.
//
// Returns:
//
//	*cobra.Command: The modified secrets command with the update command added.
//
// Example usage:
//
//	secretsCmd := &cobra.Command{Use: "secrets"}
//	secretsCmd = InitSecretsUpdate(secretsCmd)
//	secretsCmd.Execute()
//
// Example output:
//
//	Secret updated successfully
//
// Example error handling:
//
//	if err := secretsCmd.Execute(); err != nil {
//		fmt.Println("Error executing command:", err)
//		os.Exit(1)
//	}
//
// Example context usage:
//
//	ctx := context.Background()
//	ctx = context.WithValue(ctx, "userID", uuid.New())
//	secretsCmd.SetContext(ctx)
//	secretsCmd.Execute()
//
// Example command usage:
//
//	password-manager secrets update 123e4567-e89b-12d3-a456-426614174000 new-value --tags tag1,tag2
//
// Example command output:
//
//	Secret updated successfully
//
// Example command error handling:
//
//	if err := updateCmd.Execute(); err != nil {
//		fmt.Println("Error executing command:", err)
//		os.Exit(1)
//	}
//
// Example command context usage:
//
//	ctx := context.Background()
//	ctx = context.WithValue(ctx, "userID", uuid.New())
//	secretsCmd.SetContext(ctx)
//	secretsCmd.Execute()
//
// Example command database usage:
//
//	db, err := sql.Open("postgres", "user=foo dbname=bar sslmode=disable")
//	if err != nil {
//		log.Fatal(err)
//	}
//	ctx := context.WithValue(context.Background(), "db", db)
//	secretsCmd.SetContext(ctx)
//	secretsCmd.Execute()
//
// Example command logger usage:
//
//	logger := logging.NewLogger()
//	ctx := context.WithValue(context.Background(), "log", logger)
//	secretsCmd.SetContext(ctx)
//	secretsCmd.Execute()
//
// Example command flags usage:
//
//	updateCmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")
//
// Example command flag output:
//
//	Tags for the secret (comma-separated): tag1,tag2
//
// Example command flag error handling:
//
//	if err := updateCmd.Execute(); err != nil {
//		fmt.Println("Error executing command:", err)
//		os.Exit(1)
//	}
//
// Example command flag context usage:
//
//	ctx := context.Background()
//	ctx = context.WithValue(ctx, "tags", []string{"tag1", "tag2"})
//	secretsCmd.SetContext(ctx)
//	secretsCmd.Execute()
func InitSecretsUpdate(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(updateCmd)

	updateCmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")

	return secretsCmd
}
