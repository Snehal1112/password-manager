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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/db"
	"password-manager/internal/keys"
	"password-manager/internal/logging"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:     "update <id>",
	Short:   "Update a cryptographic key",
	Long:    `Update a cryptographic key's name, revocation status, or tags by its UUID. Accessible by the key's owner or users with the admin role.`,
	Example: `password-manager keys update <key-id> --username admin --password admin123 --totp-code <code> --name newkey --revoked true --tags tag1,tag2`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		keyID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		// Read key to check ownership
		keyRepo := keys.NewKeyRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		key, err := keyRepo.Read(ctx, keyID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_key", "failed", fmt.Sprintf("failed to read key: %s", err), err)
			return fmt.Errorf("failed to read key: %w", err)
		}

		if claims.UserID != key.UserID && claims.Role != auth.RoleAdmin {
			log.LogAuditError(claims.UserID.String(), "update_key", "failed", "forbidden: cannot update other users' keys", nil)
			return fmt.Errorf("forbidden: cannot update other users' keys")
		}

		// Get update parameters
		newName := viper.GetString("name")
		revoked := viper.GetBool("revoked")
		tagsStr := viper.GetString("tags")
		updateRequired := false

		if newName != "" {
			key.Name = newName
			updateRequired = true
		}
		if viper.IsSet("revoked") {
			key.Revoked = revoked
			updateRequired = true
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
			key.Tags = tags
			updateRequired = true
		}

		if !updateRequired {
			log.LogAuditError(claims.UserID.String(), "update_key", "failed", "at least one update field (name, revoked, tags) must be provided", nil)
			return fmt.Errorf("at least one update field (name, revoked, tags) must be provided")
		}

		// Update the key
		err = keyRepo.Update(ctx, key)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_key", "failed", fmt.Sprintf("failed to update key: %s", err), err)
			return fmt.Errorf("failed to update key: %w", err)
		}

		// Update tags if provided
		if tagsStr != "" {
			tagRepo := db.NewTagRepository[keys.Key](ctx.Value(common.DBKey).(*sql.DB), "key_tags", "key_id")
			if err := tagRepo.ReplaceTags(ctx, keyID, tags); err != nil {
				log.LogAuditError(claims.UserID.String(), "update_key", "failed", fmt.Sprintf("failed to update tags: %s", err), err)
				return fmt.Errorf("failed to update tags: %w", err)
			}
		}

		log.LogAuditInfo(claims.UserID.String(), "update_key", "success", fmt.Sprintf("key updated: %s, ID: %s", key.Name, key.ID))
		fmt.Printf("Key updated successfully: ID=%s, Name=%s, Type=%s, Revoked=%t, CreatedAt=%s, Tags=[%s]\n",
			key.ID, key.Name, key.Type, key.Revoked, key.CreatedAt.Format(time.RFC3339), strings.Join(key.Tags, ", "))
		return nil
	},
}

// InitKeysUpdate initializes the update command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The update command allows users to update
// information about a specific key by its ID. It requires the key ID
// to be specified.
//
// parameters:
//
// - keysCmd: The parent command under which the update command will be added.
//
// returns:
//
// - *cobra.Command: The initialized update command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The update command is a subcommand of the keys command and is used to update information about a specific key.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysUpdate(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(updateCmd)

	updateCmd.Flags().String("name", "", "New name for the key")
	updateCmd.Flags().Bool("revoked", false, "Set key revocation status (true/false)")
	updateCmd.Flags().String("tags", "", "Comma-separated tags to replace existing tags")
	viper.BindPFlag("name", updateCmd.Flags().Lookup("name"))
	viper.BindPFlag("revoked", updateCmd.Flags().Lookup("revoked"))
	viper.BindPFlag("tags", updateCmd.Flags().Lookup("tags"))

	return keysCmd
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// updateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// updateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
