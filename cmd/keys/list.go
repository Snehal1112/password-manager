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
	"database/sql"
	"fmt"
	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/keys"
	"password-manager/internal/logging"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List cryptographic keys",
	Long:    `List all cryptographic keys for the authenticated user. Admins can list all keys. Supports filtering by type and tags.`,
	Example: `password-manager keys list --username admin --password admin123 --totp-code <code> --type RSA --tags prod,secure`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
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

		keyRepo := keys.NewKeyRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		var keys []keys.Key
		var err error

		if claims.Role == auth.RoleAdmin {
			// Admins list all keys with filters
			keys, err = keyRepo.ListByUser(ctx, nil, keyType, tags)
		} else {
			// Non-admins list only their keys
			keys, err = keyRepo.ListByUser(ctx, &claims.UserID, keyType, tags)
		}

		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_keys", "failed", fmt.Sprintf("failed to list keys: %s", err), err)
			return fmt.Errorf("failed to list keys: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "list_keys", "success", fmt.Sprintf("listed %d keys", len(keys)))
		if len(keys) == 0 {
			fmt.Println("No keys found.")
			return nil
		}

		fmt.Println("Keys:")
		for _, key := range keys {
			fmt.Printf("- ID=%s, Name=%s, Type=%s, Revoked=%t, CreatedAt=%s, Tags=[%s]\n",
				key.ID, key.Name, key.Type, key.Revoked, key.CreatedAt.Format(time.RFC3339), strings.Join(key.Tags, ", "))
		}
		return nil
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
