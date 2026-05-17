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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/model"
	keyServices "rocketvault/internal/services/keys"
)

// updateCmd represents the update command for cryptographic keys.
var updateCmd = &cobra.Command{
	Use:     "update <id>",
	Short:   "Update a cryptographic key",
	Long:    `Update a cryptographic key's name, revocation status, or tags by its UUID.`,
	Example: `rocketvault keys update <key-id> --username admin --password admin123 --totp-code <code> --name newkey --revoked true`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		keyID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid key ID: %w", err)
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		newName, _ := cmd.Flags().GetString("name")
		tagsStr, _ := cmd.Flags().GetString("tags")

		req := keyServices.UpdateKeyRequest{
			KeyID:  keyID,
			UserID: claims.UserID,
		}

		hasUpdate := false

		if newName != "" {
			req.Name = &newName
			hasUpdate = true
		}
		if tagsStr != "" {
			tags := strings.Split(tagsStr, ",")
			for i, t := range tags {
				tags[i] = strings.TrimSpace(t)
			}
			req.Tags = tags
			hasUpdate = true
		}
		if cmd.Flags().Changed("revoked") {
			revoked, _ := cmd.Flags().GetBool("revoked")
			req.Revoked = &revoked
			hasUpdate = true
		}

		if !hasUpdate {
			return fmt.Errorf("at least one update field (name, revoked, tags) must be provided")
		}

		if err := sc.GetKeyService().UpdateKey(ctx, req); err != nil {
			return fmt.Errorf("failed to update key: %w", err)
		}

		fmt.Printf("Key %s updated successfully at %s\n", keyID, time.Now().Format(time.RFC3339))
		return nil
	},
}

// InitKeysUpdate adds the update subcommand to the keys command.
func InitKeysUpdate(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(updateCmd)
	updateCmd.Flags().String("name", "", "New name for the key")
	updateCmd.Flags().Bool("revoked", false, "Set key revocation status")
	updateCmd.Flags().String("tags", "", "Comma-separated tags to replace existing tags")
	viper.BindPFlag("name", updateCmd.Flags().Lookup("name"))
	viper.BindPFlag("revoked", updateCmd.Flags().Lookup("revoked"))
	viper.BindPFlag("tags", updateCmd.Flags().Lookup("tags"))
	return keysCmd
}
