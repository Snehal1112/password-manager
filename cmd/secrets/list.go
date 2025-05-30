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
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"password-manager/common"
	"password-manager/internal/logging"
	"password-manager/internal/secrets"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	Long:  `List all secrets for the authenticated user, optionally filtered by tags.`,
	Run: func(cmd *cobra.Command, args []string) {
		tags, _ := cmd.Flags().GetStringSlice("tags")

		ctx := cmd.Context()
		userID := ctx.Value(common.UserIDKey).(uuid.UUID)
		db := ctx.Value(common.DBKey).(*sql.DB)
		logger := ctx.Value(common.LogKey).(*logging.Logger)

		repo := secrets.NewSecretRepository(db, logger)
		secretsList, err := repo.ListByUser(cmd.Context(), userID, tags)
		if err != nil {
			logger.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to list secrets", err)
			os.Exit(0)
			return
		}

		t, _ := json.MarshalIndent(secretsList, "", "  ")
		fmt.Println(string(t))
	},
}

// InitSecretsList initializes the list command for secrets
// It sets up the command flags and adds it to the secrets command tree.
// This function is called in the main function of the application to set up the command structure.
// It returns the modified secrets command.
// Parameters:
//
//	secretsCmd: The parent command under which the list command will be added.
//
// Returns:
//
//	*cobra.Command: The modified secrets command with the list command added.
//
// Example usage:
//
//	secretsCmd := &cobra.Command{Use: "secrets"}
//	secretsCmd = InitSecretsList(secretsCmd)
//	secretsCmd.Execute()
//
// Example output:
//
//	[
//		{
//			"id": "123e4567-e89b-12d3-a456-426614174000",
//			"name": "My Secret",
//			"tags": ["tag1", "tag2"]
//		}
//	]
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
// Example database usage:
//
//	db, err := sql.Open("postgres", "user=foo dbname=bar sslmode=disable")
//	if err != nil {
//		log.Fatal(err)
//	}
//	ctx := context.WithValue(context.Background(), "db", db)
//	secretsCmd.SetContext(ctx)
//	secretsCmd.Execute()
func InitSecretsList(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(listCmd)

	listCmd.Flags().StringSlice("tags", []string{}, "Tags to filter secrets (comma-separated)")
	return secretsCmd
}
