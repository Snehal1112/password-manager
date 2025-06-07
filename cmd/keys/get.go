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

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/keys"
	"password-manager/internal/logging"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:     "get <id>",
	Short:   "Retrieve a cryptographic key",
	Long:    `Retrieve details of a cryptographic key by its UUID. Accessible by the key's owner or users with the admin role.`,
	Example: `password-manager keys get <key-id> --username admin --password admin123 --totp-code <code>`,
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
			log.LogAuditError(claims.UserID.String(), "get_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		keyRepo := keys.NewKeyRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		key, err := keyRepo.Read(ctx, keyID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_key", "failed", fmt.Sprintf("failed to get key: %s", err), err)
			return fmt.Errorf("failed to get key: %w", err)
		}

		if claims.UserID != key.UserID && claims.Role != auth.RoleAdmin {
			log.LogAuditError(claims.UserID.String(), "get_key", "failed", "forbidden: cannot access other users' keys", nil)
			return fmt.Errorf("forbidden: cannot access other users' keys")
		}

		log.LogAuditInfo(claims.UserID.String(), "get_key", "success", fmt.Sprintf("key retrieved: %s", key.Name))
		fmt.Printf("Key: ID=%s, Name=%s, Type=%s, Revoked=%t, CreatedAt=%s, Tags=[%s]\n",
			key.ID, key.Name, key.Type, key.Revoked, key.CreatedAt.Format(time.RFC3339), strings.Join(key.Tags, ", "))
		return nil
	},
}

// InitKeysGet initializes the get command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The get command allows users to retrieve
// information about a specific key by its ID. It requires the key ID
// to be specified.
//
// parameters:
//
// - keysCmd: The parent command under which the get command will be added.
//
// returns:
//
// - *cobra.Command: The initialized get command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The get command is a subcommand of the keys command and is used to retrieve information about a specific key.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysGet(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(getCmd)

	return keysCmd
}
