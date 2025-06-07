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

// rotateCmd represents the rotate command
var rotateCmd = &cobra.Command{
	Use:     "rotate <id>",
	Short:   "Rotate a cryptographic key",
	Long:    `Rotate a cryptographic key by generating a new key pair and revoking the old key. Accessible by the key's owner or users with the admin role.`,
	Example: `password-manager keys rotate <key-id> --username admin --password admin123 --totp-code <code>`,
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
			log.LogAuditError(claims.UserID.String(), "rotate_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		keyRepo := keys.NewKeyRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		// Read key to check ownership
		key, err := keyRepo.Read(ctx, keyID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "rotate_key", "failed", fmt.Sprintf("failed to read key: %s", err), err)
			return fmt.Errorf("failed to read key: %w", err)
		}

		if claims.UserID != key.UserID && claims.Role != auth.RoleAdmin {
			log.LogAuditError(claims.UserID.String(), "rotate_key", "failed", "forbidden: cannot rotate other users' keys", nil)
			return fmt.Errorf("forbidden: cannot rotate other users' keys")
		}

		// Rotate the key
		newKey, err := keyRepo.Rotate(ctx, keyID)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "rotate_key", "failed", fmt.Sprintf("failed to rotate key: %s", err), err)
			return fmt.Errorf("failed to rotate key: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "rotate_key", "success", fmt.Sprintf("key rotated: %s, new ID: %s", key.Name, newKey.ID))
		fmt.Printf("Key rotated successfully, New Key: ID=%s, Name=%s, Type=%s, Revoked=%t, CreatedAt=%s, Tags=[%s]\n",
			newKey.ID, newKey.Name, newKey.Type, newKey.Revoked, newKey.CreatedAt.Format(time.RFC3339), strings.Join(newKey.Tags, ", "))
		return nil
	},
}

// InitKeysRotate initializes the rotate command for keys.
// It adds the rotate command to the keys command. Authentication flags are inherited from the root command.
func InitKeysRotate(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(rotateCmd)
	return keysCmd
}
