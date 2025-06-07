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

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/keys"
	"password-manager/internal/logging"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:     "create",
	Short:   "Create a new key",
	Long:    `Create a new key with the specified details.`,
	Example: `keys create --name <name> --type <type>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*auth.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if claims.Role != auth.RoleAdmin && claims.Role != auth.RoleSecretsManager {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", "forbidden: requires admin or secrets_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or secrets_manager role")
		}

		name := viper.GetString("name")
		keyType := viper.GetString("type")
		bits := viper.GetInt("bits")
		curve := viper.GetString("curve")
		tagsStr := viper.GetString("tags")

		if name == "" || keyType == "" {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", "name and type are required", nil)
			return fmt.Errorf("name and type are required")
		}

		keyType = strings.ToUpper(keyType)
		if keyType != "RSA" && keyType != "ECDSA" {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", "invalid key type: must be RSA or ECDSA", nil)
			return fmt.Errorf("invalid key type: must be RSA or ECDSA")
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		keyRepo := keys.NewKeyRepository(ctx.Value(common.DBKey).(*sql.DB), log)
		var key *keys.Key
		var err error

		if keyType == "RSA" {
			if bits != 2048 && bits != 4096 {
				log.LogAuditError(claims.UserID.String(), "create_key", "failed", "invalid RSA key size: must be 2048 or 4096", nil)
				return fmt.Errorf("invalid RSA key size: must be 2048 or 4096")
			}
			key, err = keyRepo.GenerateRSA(ctx, claims.UserID, name, bits, tags)
		} else {
			if curve != "P-256" && curve != "P-384" && curve != "P-521" {
				log.LogAuditError(claims.UserID.String(), "create_key", "failed", "invalid ECDSA curve: must be P-256, P-384, or P-521", nil)
				return fmt.Errorf("invalid ECDSA curve: must be P-256, P-384, or P-521")
			}
			log.Println("Creating ECDSA key with curve:", claims.UserID.String())
			key, err = keyRepo.GenerateECDSA(ctx, claims.UserID, name, curve, tags)
		}

		if err != nil {
			log.LogAuditError(claims.UserID.String(), "create_key", "failed", fmt.Sprintf("failed to create key: %s", err), err)
			return fmt.Errorf("failed to create key: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "create_key", "success", fmt.Sprintf("key created: %s, ID: %s", name, key.ID))
		fmt.Printf("Key created successfully, ID: %s\n", key.ID)
		return nil
	},
}

// InitKeysCreate initializes the create command for keys
// and adds it to the keys command. It also sets up the necessary flags
// and configuration settings. The create command allows users to create
// a new key. It requires the key details to be specified.
//
// parameters:
//
// - keysCmd: The parent command under which the create command will be added.
//
// returns:
//
// - *cobra.Command: The initialized create command.
//
// This function is called in the main function of the application to set up the command structure.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
// The create command is a subcommand of the keys command and is used to create a new key.
// It is part of the Cobra library, which is used for creating command-line applications in Go.
func InitKeysCreate(keysCmd *cobra.Command) *cobra.Command {
	keysCmd.AddCommand(createCmd)

	createCmd.Flags().String("name", "", "Name for the new key")
	createCmd.Flags().String("type", "", "Key type (RSA, ECDSA)")
	createCmd.Flags().Int("bits", 2048, "RSA key size in bits (2048 or 4096)")
	createCmd.Flags().String("curve", "P-256", "ECDSA curve (P-256, P-384, P-521)")
	createCmd.Flags().String("tags", "", "Comma-separated tags for the key")
	viper.BindPFlag("name", createCmd.Flags().Lookup("name"))
	viper.BindPFlag("type", createCmd.Flags().Lookup("type"))
	viper.BindPFlag("bits", createCmd.Flags().Lookup("bits"))
	viper.BindPFlag("curve", createCmd.Flags().Lookup("curve"))
	viper.BindPFlag("tags", createCmd.Flags().Lookup("tags"))

	return keysCmd

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
