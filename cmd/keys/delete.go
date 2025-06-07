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

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/keys"
	"password-manager/internal/logging"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:     "delete <id>",
	Short:   "Delete a cryptographic key",
	Long:    `Delete a cryptographic key by its UUID, including associated tags. Accessible by the key's owner or users with the admin role.`,
	Example: `password-manager keys delete <key-id> --username admin --password admin123 --totp-code <code>`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		keyID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		keyRepo := keys.NewKeyRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		// Read key to check ownership
		key, err := keyRepo.Read(ctx, keyID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_key", "failed", fmt.Sprintf("failed to read key: %s", err), err)
			return fmt.Errorf("failed to read key: %w", err)
		}

		if claims.UserID != key.UserID && claims.Role != auth.RoleAdmin {
			log.LogAuditError(claims.UserID.String(), "delete_key", "failed", "forbidden: cannot delete other users' keys", nil)
			return fmt.Errorf("forbidden: cannot delete other users' keys")
		}

		// Delete the key
		err = keyRepo.Delete(ctx, keyID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_key", "failed", fmt.Sprintf("failed to delete key: %s", err), err)
			return fmt.Errorf("failed to delete key: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "delete_key", "success", fmt.Sprintf("key deleted: %s", key.Name))
		fmt.Printf("Key %s deleted successfully\n", keyID)
		return nil
	},
}

// InitKeysDelete initializes the delete command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The delete command allows users to delete
// a specific key by its ID. It requires the key ID to be specified.
//
// parameters:
//
// - keysCmd: The parent command under which the delete command will be added.
//
// returns:
//
// - *cobra.Command: The initialized delete command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The delete command is a subcommand of the keys command and is used to delete a specific key.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysDelete(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(deleteCmd)

	return keysCmd
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deleteCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// deleteCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
