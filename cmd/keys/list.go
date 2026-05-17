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

package keys

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/model"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List cryptographic keys",
	Long:    `List all cryptographic keys for the authenticated user. Admins can list all keys. Supports filtering by type and tags.`,
	Example: `rocketvault keys list --username admin --password admin123 --totp-code <code> --type RSA --tags prod,secure`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		keyType := viper.GetString("type")
		tagsStr := viper.GetString("tags")

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "list_keys", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		keyService := serviceContainer.GetKeyService()

		var keys []model.Key
		var err error

		if claims.Role == model.RoleAdmin {
			// Admins list all keys with filters - use repository directly for admin functionality
			keyRepo := serviceContainer.GetKeyRepository()
			keys, err = keyRepo.ListByUser(ctx, nil, keyType, tags)
		} else {
			// Non-admins list only their keys through service layer
			keys, err = keyService.ListKeys(ctx, claims.UserID)
		}

		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_keys", "failed", fmt.Sprintf("failed to list keys: %s", err), err)
			return fmt.Errorf("failed to list keys: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "list_keys", "success", fmt.Sprintf("listed %d keys", len(keys)))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Type", "Revoked", "Tags", "Created"}
		rows := make([][]string, len(keys))
		for i, k := range keys {
			rows[i] = []string{
				k.ID.String(),
				k.Name,
				k.Type,
				strconv.FormatBool(k.Revoked),
				strings.Join(k.Tags, ","),
				k.CreatedAt.Format(time.RFC3339),
			}
		}
		return fmtr.Write(os.Stdout, headers, rows)
	},
}

// InitKeysList initializes the list command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The list command allows users to retrieve
// a list of all keys in the system. It does not require any additional parameters.
//
// parameters:
//
// - keysCmd: The parent command under which the list command will be added.
//
// returns:
//
// - *cobra.Command: The initialized list command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The list command is a subcommand of the keys command and is used to retrieve a list of all keys.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysList(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(listCmd)

	listCmd.Flags().String("type", "", "Filter by key type (RSA, ECDSA)")
	listCmd.Flags().String("tags", "", "Comma-separated tags to filter keys")
	viper.BindPFlag("type", listCmd.Flags().Lookup("type"))
	viper.BindPFlag("tags", listCmd.Flags().Lookup("tags"))

	return keysCmd
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
