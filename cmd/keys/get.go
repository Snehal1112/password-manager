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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Retrieve a cryptographic key",
	Long: `Print the metadata of one cryptographic key by its UUID: ID, name, type,
revocation status, tags and creation time. Key material is never printed.

Requires the Microsoft.KeyVault/vaults/keys/read data action in the target
vault. No global role is checked here, so any principal holding a role
assignment that grants that action can read key metadata.

The lookup is scoped to the vault named by --vault, defaulting to
"default"; a key that lives in another vault is reported as not found. A
key that is disabled, or outside its not-before/expiry window, is refused
even though it exists.`,
	Example: `  # Show a key in the default vault
  rocketvault keys get <key-id>

  # Show a key in a named vault
  rocketvault keys get <key-id> --vault payments

  # Machine-readable output
  rocketvault keys get <key-id> --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		keyID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_key", "failed", fmt.Sprintf("invalid key ID: %s", err), err)
			return fmt.Errorf("invalid key ID: %w", err)
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "get_key", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		keyService := serviceContainer.GetKeyService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionKeysRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_key", "failed", fmt.Sprintf("vault authorization failed: %s", err), err)
			return fmt.Errorf("vault authorization failed: %w", err)
		}

		key, err := keyService.GetKey(ctx, keyID, model.NewVaultScope(vaultID, claims.UserID))
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_key", "failed", fmt.Sprintf("failed to get key: %s", err), err)
			return fmt.Errorf("failed to get key: %w", err)
		}

		// Access control is now handled by the service layer

		log.LogAuditInfo(claims.UserID.String(), "get_key", "success", fmt.Sprintf("key retrieved: %s", key.Name))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Type", "Revoked", "Tags", "Created"}
		row := []string{
			key.ID.String(),
			key.Name,
			key.Type,
			strconv.FormatBool(key.Revoked),
			strings.Join(key.Tags, ","),
			key.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
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
