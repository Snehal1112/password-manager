// Package main provides CLI commands for cryptographic key management in the password manager.
// It implements commands for generating, retrieving, listing, rotating, and deleting keys,
// using Cobra and integrating with authentication and logging.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/keys"
)

// keysCmd represents the keys command group for managing cryptographic keys.
func keysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage cryptographic keys in the password manager",
		Long: `A command group for generating, retrieving, listing, rotating, and deleting 
cryptographic keys (RSA/ECDSA) for the authenticated user.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Require authentication for all keys commands.
			username, _ := cmd.Flags().GetString("username")
			password, _ := cmd.Flags().GetString("password")
			totpCode, _ := cmd.Flags().GetString("totp-code")
			if username == "" || password == "" {
				Logger.LogAuditError(0, "keys_auth", "failed", "Username and password are required", nil)
				os.Exit(1)
			}
			token, err := auth.Login(cmd.Context(), username, password, totpCode)
			if err != nil {
				Logger.LogAuditError(0, "keys_auth", "failed", "Authentication failed", err)
				os.Exit(1)
			}
			// Parse JWT to extract userID and role.
			claims, err := auth.ParseJWT(token)
			if err != nil || claims == nil {
				Logger.LogAuditError(0, "keys_auth", "failed", "Failed to parse JWT or invalid claims", err)
				os.Exit(1)
			}

			// Enforce RBAC: only crypto_manager role allowed.
			if claims.Role != auth.RoleCryptoManager {
				Logger.LogAuditError(claims.UserID, "keys_auth", "failed", "Insufficient permissions: crypto_manager role required", nil)
				fmt.Println("Error: insufficient permissions")
				os.Exit(1)
			}

			// Add userID to context.
			ctx := context.WithValue(cmd.Context(), "userID", claims.UserID)
			cmd.SetContext(ctx)
		},
	}

	// Persistent flags for authentication.
	cmd.PersistentFlags().String("username", "", "Username for authentication")
	cmd.PersistentFlags().String("password", "", "Password for authentication")
	cmd.PersistentFlags().String("totp-code", "", "TOTP code for MFA")

	// Add subcommands.
	cmd.AddCommand(generateKeyCmd())
	cmd.AddCommand(getKeyCmd())
	cmd.AddCommand(listKeysCmd())
	cmd.AddCommand(rotateKeyCmd())
	cmd.AddCommand(deleteKeyCmd())

	return cmd
}

func generateKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new cryptographic key",
		Long: `Generate a new RSA or ECDSA key pair with configurable parameters 
(e.g., key type, bit size, curve) for the authenticated user.`,
		Run: func(cmd *cobra.Command, args []string) {
			keyType, _ := cmd.Flags().GetString("type")
			bitSize, _ := cmd.Flags().GetInt("bits")
			curve, _ := cmd.Flags().GetString("curve")
			useHSM, _ := cmd.Flags().GetBool("hsm")
			name, _ := cmd.Flags().GetString("name")
			tags, _ := cmd.Flags().GetStringSlice("tags")
			userID, _ := cmd.Context().Value("userID").(int)

			// Validate key name.
			if name == "" {
				name = fmt.Sprintf("key-%d", userID)
				Logger.LogAuditInfo(userID, "generate_key", "info", "Key name not provided, using default")
			}

			// Validate key type.
			if keyType != "rsa" && keyType != "ecdsa" {
				Logger.LogAuditError(userID, "generate_key", "failed", "Invalid key type: must be rsa or ecdsa", nil)
				os.Exit(1)
				return
			}

			// Validate RSA bit size.
			if keyType == "rsa" && bitSize != 2048 && bitSize != 4096 {
				Logger.LogAuditError(userID, "generate_key", "failed", "Invalid bit size: must be 2048 or 4096 for RSA", nil)
				os.Exit(1)
				return
			}

			// Validate ECDSA curve.
			if keyType == "ecdsa" && !contains([]string{"P256", "P384", "P521"}, curve) {
				Logger.LogAuditError(userID, "generate_key", "failed", "Invalid curve: must be P256, P384, or P521 for ECDSA", nil)
				os.Exit(1)
				return
			}

			repo := keys.NewKeyRepository(db.DB, Logger)
			var key *keys.Key
			var err error
			if keyType == "rsa" {
				key, err = repo.GenerateRSA(cmd.Context(), userID, name, bitSize, tags)
			} else {
				key, err = repo.GenerateECDSA(cmd.Context(), userID, name, curve, tags)
			}
			if err != nil {
				Logger.LogAuditError(userID, "generate_key", "failed", fmt.Sprintf("Failed to generate %s key", keyType), err)
				os.Exit(1)
				return
			}

			key.Tags = tags
			if err := repo.Create(cmd.Context(), *key); err != nil {
				Logger.LogAuditError(userID, "generate_key", "failed", fmt.Sprintf("Failed to store %s key", keyType), err)
				os.Exit(1)
				return
			}

			logMsg := fmt.Sprintf("%s key generated successfully: id=%d, bits=%d, curve=%s, hsm=%v", strings.ToUpper(keyType), key.ID, bitSize, curve, useHSM)
			Logger.LogAuditInfo(userID, "generate_key", "success", logMsg)
			fmt.Printf("%s key generated successfully: ID=%d\n", strings.ToUpper(keyType), key.ID)
		},
	}

	cmd.Flags().String("type", "", "Key type (rsa or ecdsa)")
	cmd.Flags().String("name", "", "Name for the key (optional)")
	cmd.Flags().Int("bits", 0, "Bit size for RSA keys (2048 or 4096)")
	cmd.Flags().String("curve", "", "Curve for ECDSA keys (P256, P384, P521)")
	cmd.Flags().Bool("hsm", false, "Use HSM for key generation (placeholder)")
	cmd.Flags().StringSlice("tags", []string{}, "Tags for the key (comma-separated)")

	return cmd
}

// getKeyCmd represents the keys get command.
func getKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Retrieve a key by ID",
		Long:  `Retrieve a cryptographic key by its ID for the authenticated user.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id := parseID(args[0])
			userID, _ := cmd.Context().Value("userID").(int)

			repo := keys.NewKeyRepository(db.DB, Logger)
			key, err := repo.Read(cmd.Context(), id)
			if err != nil {
				Logger.LogAuditError(userID, "get_key", "failed", "Failed to retrieve key", err)
				os.Exit(1)
				return
			}

			if key.UserID != userID {
				Logger.LogAuditError(userID, "get_key", "failed", "Unauthorized access attempt to key", nil)
				os.Exit(1)
				return
			}

			Logger.LogAuditInfo(userID, "get_key", "success", fmt.Sprintf("Key retrieved successfully: id=%d", key.ID))
		},
	}
	return cmd
}

// listKeysCmd represents the keys list command.
func listKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all keys",
		Long:  `List all cryptographic keys for the authenticated user, optionally filtered by type or tags.`,
		Run: func(cmd *cobra.Command, args []string) {
			keyType, _ := cmd.Flags().GetString("type")
			tags, _ := cmd.Flags().GetStringSlice("tags")
			userID, _ := cmd.Context().Value("userID").(int)

			log.Println("Listing keys for user:", userID)
			log.Println("Key type:", keyType)
			log.Println("Tags:", tags)

			repo := keys.NewKeyRepository(db.DB, Logger)
			keysList, err := repo.ListByUser(cmd.Context(), userID, keyType, tags)
			if err != nil {
				Logger.LogAuditError(userID, "list_keys", "failed", "Failed to list keys", err)
				os.Exit(1)
				return
			}

			Logger.LogAuditInfo(userID, "list_keys", "success", fmt.Sprintf("Keys listed successfully: %d keys", len(keysList)))
			tt, _ := json.MarshalIndent(keysList, "", "  ")
			log.Println("Keys list:", string(tt))
		},
	}
	cmd.Flags().String("type", "", "Filter keys by type (rsa or ecdsa)")
	cmd.Flags().StringSlice("tags", []string{}, "Filter keys by tags (comma-separated)")
	return cmd
}

// rotateKeyCmd represents the keys rotate command.
func rotateKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate [id]",
		Short: "Rotate a key by ID",
		Long: `Rotate a cryptographic key by ID, marking the old key as revoked and generating a new one 
for the authenticated user.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id := parseID(args[0])
			userID, _ := cmd.Context().Value("userID").(int)

			repo := keys.NewKeyRepository(db.DB, Logger)
			key, err := repo.Read(cmd.Context(), id)
			if err != nil {
				Logger.LogAuditError(userID, "rotate_key", "failed", "Failed to read key", err)
				os.Exit(1)
				return
			}
			if key.UserID != userID {
				Logger.LogAuditError(userID, "rotate_key", "failed", "Unauthorized access attempt to key", nil)
				os.Exit(1)
				return
			}
			if key.Revoked {
				Logger.LogAuditError(userID, "rotate_key", "failed", "Key is already revoked", nil)
				os.Exit(1)
				return
			}

			newKey, err := repo.Rotate(cmd.Context(), id)
			if err != nil {
				Logger.LogAuditError(userID, "rotate_key", "failed", "Failed to rotate key", err)
				os.Exit(1)
				return
			}

			Logger.LogAuditInfo(userID, "rotate_key", "success", fmt.Sprintf("Key rotated successfully: old_id=%d, new_id=%d", id, newKey.ID))
			fmt.Printf("Key rotated successfully: New ID=%d\n", newKey.ID)
		},
	}
	return cmd
}

// deleteKeyCmd represents the keys delete command.
func deleteKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [id]",
		Short: "Delete a key by ID",
		Long:  `Delete a cryptographic key by its ID for the authenticated user.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id := parseID(args[0])
			userID, _ := cmd.Context().Value("userID").(int)

			repo := keys.NewKeyRepository(db.DB, Logger)
			key, err := repo.Read(cmd.Context(), id)
			if err != nil {
				Logger.LogAuditError(userID, "delete_key", "failed", "Failed to read key", err)
				os.Exit(1)
				return
			}
			if key.UserID != userID {
				Logger.LogAuditError(userID, "delete_key", "failed", "Unauthorized access attempt to key", nil)
				os.Exit(1)
				return
			}
			if key.Revoked {
				Logger.LogAuditError(userID, "delete_key", "failed", "Key is already revoked", nil)
				os.Exit(1)
				return
			}

			if err := repo.Delete(cmd.Context(), id); err != nil {
				Logger.LogAuditError(userID, "delete_key", "failed", "Failed to delete key", err)
				os.Exit(1)
				return
			}

			Logger.LogAuditInfo(userID, "delete_key", "success", fmt.Sprintf("Key deleted successfully: id=%d", id))
			fmt.Println("Key deleted successfully")
		},
	}
	return cmd
}

// init initializes the keys command group and its subcommands.
func init() {
	rootCmd.AddCommand(keysCmd())
}

// contains checks if a string slice contains a specific value.
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
