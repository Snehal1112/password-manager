// Package main provides CLI commands for secrets management in the password manager.
// It implements commands for creating, retrieving, updating, listing, and deleting secrets,
// along with a password generator, using Cobra.
package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/secrets"
)

// secretsCmd represents the secrets command group for managing secrets.
func secretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage secrets in the password manager",
		Long: `A command group for creating, retrieving, updating, listing, and deleting secrets,
as well as generating random passwords.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Ensure database is initialized.
			db.InitializeDB()
			// Require authentication for all secrets commands except generate-password.
			if cmd.Name() == "generate-password" {
				return
			}
			username, _ := cmd.Flags().GetString("username")
			password, _ := cmd.Flags().GetString("password")
			totpCode, _ := cmd.Flags().GetString("totp-code")
			if username == "" || password == "" {
				logrus.Fatal("Username and password are required")
			}
			token, err := auth.Login(cmd.Context(), username, password, totpCode)
			if err != nil {
				logrus.Fatal("Authentication failed: ", err)
			}
			// Parse JWT to extract userID.
			claims, err := auth.ParseJWT(token)
			if err != nil {
				logrus.Fatal("Failed to parse JWT: ", err)
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
	cmd.AddCommand(createSecretCmd())
	cmd.AddCommand(getSecretCmd())
	cmd.AddCommand(listSecretsCmd())
	cmd.AddCommand(updateSecretCmd())
	cmd.AddCommand(deleteSecretCmd())
	cmd.AddCommand(generatePasswordCmd())

	return cmd
}

// createSecretCmd represents the secrets create command.
func createSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [name] [value]",
		Short: "Create a new secret",
		Long:  `Create a new secret with the specified name, value, and optional tags.`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			value := args[1]
			tags, _ := cmd.Flags().GetStringSlice("tags")
			userID, _ := cmd.Context().Value("userID").(int)

			repo := secrets.NewSecretRepository(db.DB, Logger)
			secret := secrets.Secret{
				UserID:    userID,
				Name:      name,
				Value:     value,
				Version:   1,
				Tags:      tags,
				CreatedAt: time.Now(),
			}
			log.Println("secreat", secret, secret.Tags)
			if err := repo.Create(cmd.Context(), secret); err != nil {
				logrus.Error("Failed to create secret: ", err)
				fmt.Println("Error creating secret:", err)
				return
			}

			logrus.WithFields(logrus.Fields{
				"user_id": userID,
				"name":    name,
			}).Info("Secret created successfully")
			fmt.Println("Secret created successfully")
		},
	}
	cmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")
	return cmd
}

// getSecretCmd represents the secrets get command.
func getSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Retrieve a secret by ID",
		Long:  `Retrieve a secret by its ID for the authenticated user.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id := parseID(args[0])
			userID, _ := cmd.Context().Value("userID").(int)

			repo := secrets.NewSecretRepository(db.DB, Logger)
			secret, err := repo.Read(cmd.Context(), id)
			if err != nil {
				logrus.Error("Failed to retrieve secret: ", err)
				fmt.Println("Error retrieving secret:", err)
				return
			}
			if secret.UserID != userID {
				logrus.Warn("Unauthorized access attempt to secret")
				fmt.Println("Error: unauthorized access")
				return
			}

			logrus.WithFields(logrus.Fields{
				"secret_id": id,
				"user_id":   userID,
			}).Info("Secret retrieved successfully")
			fmt.Printf("Secret: %+v\n", secret)
		},
	}
	return cmd
}

// listSecretsCmd represents the secrets list command.
func listSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all secrets",
		Long:  `List all secrets for the authenticated user, optionally filtered by tags.`,
		Run: func(cmd *cobra.Command, args []string) {
			tags, _ := cmd.Flags().GetStringSlice("tags")
			userID, _ := cmd.Context().Value("userID").(int)

			repo := secrets.NewSecretRepository(db.DB, Logger)
			secretsList, err := repo.ListByUser(cmd.Context(), userID, tags)
			if err != nil {
				logrus.Error("Failed to list secrets: ", err)
				fmt.Println("Error listing secrets:", err)
				return
			}

			logrus.WithFields(logrus.Fields{
				"user_id": userID,
				"count":   len(secretsList),
			}).Info("Secrets listed successfully")
			for _, secret := range secretsList {
				fmt.Printf("Secret: %+v\n", secret)
			}
		},
	}
	cmd.Flags().StringSlice("tags", []string{}, "Tags to filter secrets (comma-separated)")
	return cmd
}

// updateSecretCmd represents the secrets update command.
func updateSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [id] [value]",
		Short: "Update a secret",
		Long:  `Update a secret’s value and tags by its ID for the authenticated user.`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			id := parseID(args[0])
			value := args[1]
			tags, _ := cmd.Flags().GetStringSlice("tags")
			userID, _ := cmd.Context().Value("userID").(int)

			repo := secrets.NewSecretRepository(db.DB, Logger)
			secret, err := repo.Read(cmd.Context(), id)
			if err != nil {
				logrus.Error("Failed to read secret: ", err)
				fmt.Println("Error reading secret:", err)
				return
			}
			if secret.UserID != userID {
				logrus.Warn("Unauthorized access attempt to secret")
				fmt.Println("Error: unauthorized access")
				return
			}

			secret.Value = value
			secret.Tags = tags
			secret.Version++
			secret.CreatedAt = time.Now()
			if err := repo.Update(cmd.Context(), secret); err != nil {
				logrus.Error("Failed to update secret: ", err)
				fmt.Println("Error updating secret:", err)
				return
			}

			logrus.WithFields(logrus.Fields{
				"secret_id": id,
				"user_id":   userID,
			}).Info("Secret updated successfully")
			fmt.Println("Secret updated successfully")
		},
	}
	cmd.Flags().StringSlice("tags", []string{}, "Tags for the secret (comma-separated)")
	return cmd
}

// deleteSecretCmd represents the secrets delete command.
func deleteSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [id]",
		Short: "Delete a secret by ID",
		Long:  `Delete a secret by its ID for the authenticated user.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id := parseID(args[0])
			userID, _ := cmd.Context().Value("userID").(int)

			repo := secrets.NewSecretRepository(db.DB, Logger)
			secret, err := repo.Read(cmd.Context(), id)
			if err != nil {
				logrus.Error("Failed to read secret: ", err)
				fmt.Println("Error reading secret:", err)
				return
			}
			if secret.UserID != userID {
				logrus.Warn("Unauthorized access attempt to secret")
				fmt.Println("Error: unauthorized access")
				return
			}

			if err := repo.Delete(cmd.Context(), id); err != nil {
				logrus.Error("Failed to delete secret: ", err)
				fmt.Println("Error deleting secret:", err)
				return
			}

			logrus.WithFields(logrus.Fields{
				"secret_id": id,
				"user_id":   userID,
			}).Info("Secret deleted successfully")
			fmt.Println("Secret deleted successfully")
		},
	}
	return cmd
}

// generatePasswordCmd represents the secrets generate-password command.
func generatePasswordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate-password",
		Short: "Generate a random password",
		Long:  `Generate a random password with configurable length and character types.`,
		Run: func(cmd *cobra.Command, args []string) {
			length, _ := cmd.Flags().GetInt("length")
			useUpper, _ := cmd.Flags().GetBool("uppercase")
			useLower, _ := cmd.Flags().GetBool("lowercase")
			useNumbers, _ := cmd.Flags().GetBool("numbers")
			useSpecial, _ := cmd.Flags().GetBool("special")

			password, err := generatePassword(length, useUpper, useLower, useNumbers, useSpecial)
			if err != nil {
				logrus.Error("Failed to generate password: ", err)
				fmt.Println("Error generating password:", err)
				return
			}

			logrus.WithFields(logrus.Fields{
				"length": length,
			}).Info("Password generated successfully")
			fmt.Println("Generated password:", password)
		},
	}
	cmd.Flags().Int("length", 16, "Length of the generated password")
	cmd.Flags().Bool("uppercase", true, "Include uppercase letters")
	cmd.Flags().Bool("lowercase", true, "Include lowercase letters")
	cmd.Flags().Bool("numbers", true, "Include numbers")
	cmd.Flags().Bool("special", true, "Include special characters")
	return cmd
}

// init initializes the secrets command group and its subcommands.
func init() {
	rootCmd.AddCommand(secretsCmd())
}

// parseID converts a string ID to an integer.
// It returns the parsed ID or panics if conversion fails.
//
// Parameters:
//
//	id: The string ID.
//
// Returns:
//
//	The integer ID.
func parseID(id string) int {
	var n int
	fmt.Sscanf(id, "%d", &n)
	return n
}

// generatePassword generates a random password with the specified parameters.
// It includes configurable character types and ensures at least one character from each enabled type.
//
// Parameters:
//
//	length: The length of the password.
//	useUpper: Include uppercase letters.
//	useLower: Include lowercase letters.
//	useNumbers: Include numbers.
//	useSpecial: Include special characters.
//
// Returns:
//
//	The generated password and an error if generation fails.
func generatePassword(length int, useUpper, useLower, useNumbers, useSpecial bool) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("password length must be at least 1")
	}

	// Define character sets.
	const (
		upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowerChars   = "abcdefghijklmnopqrstuvwxyz"
		numberChars  = "0123456789"
		specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	)

	// Build the character pool.
	var chars []rune
	if useUpper {
		chars = append(chars, []rune(upperChars)...)
	}
	if useLower {
		chars = append(chars, []rune(lowerChars)...)
	}
	if useNumbers {
		chars = append(chars, []rune(numberChars)...)
	}
	if useSpecial {
		chars = append(chars, []rune(specialChars)...)
	}

	if len(chars) == 0 {
		return "", fmt.Errorf("at least one character type must be enabled")
	}

	// Generate the password.
	password := make([]rune, length)
	for i := 0; i < length; i++ {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		n := r.Intn(len(chars))
		password[i] = chars[n]
	}

	// Ensure at least one character from each enabled type.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	if useUpper {
		password[0] = []rune(upperChars)[r.Intn(len(upperChars))]
	}
	if useLower {
		password[1%length] = []rune(lowerChars)[r.Intn(len(lowerChars))]
	}
	if useNumbers {
		password[2%length] = []rune(numberChars)[r.Intn(len(numberChars))]
	}
	if useSpecial {
		password[3%length] = []rune(specialChars)[r.Intn(len(specialChars))]
	}

	return string(password), nil
}
