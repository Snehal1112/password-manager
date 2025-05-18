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
	"password-manager/internal/logging"
	"password-manager/internal/secrets"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	Long:  `List all secrets for the authenticated user, optionally filtered by tags.`,
	Run: func(cmd *cobra.Command, args []string) {
		tags, _ := cmd.Flags().GetStringSlice("tags")

		ctx := cmd.Context()
		userID := ctx.Value("userID").(uuid.UUID)
		db := ctx.Value("db").(*sql.DB)
		logger := ctx.Value("log").(*logging.Logger)

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

func InitSecretsList(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(listCmd)

	listCmd.Flags().StringSlice("tags", []string{}, "Tags to filter secrets (comma-separated)")
	return secretsCmd
}
