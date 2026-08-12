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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	Long:  `List all secrets for the authenticated user, optionally filtered by tags.`,
	Example: `  # List all secrets
  rocketvault secrets list \
    --username admin --password admin123 --totp-code <code>

  # List secrets filtered by tags, as JSON
  rocketvault secrets list --tags prod,db --output json \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		tags, _ := cmd.Flags().GetStringSlice("tags")

		ctx := cmd.Context()

		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user ID not available in context")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		secretService := serviceContainer.GetSecretService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, userID, model.ActionSecretsReadMetadata, model.OpGet)
		if err != nil {
			return err
		}

		secretsList, err := secretService.ListSecrets(ctx, model.NewVaultScope(vaultID, userID), tags)
		if err != nil {
			return fmt.Errorf("failed to list secrets: %w", err)
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Version", "Enabled", "Tags", "Created"}
		rows := make([][]string, len(secretsList))
		for i, s := range secretsList {
			rows[i] = []string{
				s.ID.String(),
				s.Name,
				strconv.Itoa(s.Version),
				strconv.FormatBool(s.Enabled),
				strings.Join(s.Tags, ","),
				s.CreatedAt.Format(time.RFC3339),
			}
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
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
