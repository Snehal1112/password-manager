// Package main provides the register CLI command for the password manager.
// It implements user registration with username, password, and role, including TOTP secret generation.
package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/snehal1112/password-manager/internal/auth"
)

// registerCmd represents the register command for creating a new user.
func registerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new user",
		Long:  `Register a new user with a username, password, and role, generating a TOTP secret for MFA.`,
		Run: func(cmd *cobra.Command, args []string) {
			username, _ := cmd.Flags().GetString("username")
			password, _ := cmd.Flags().GetString("password")
			role, _ := cmd.Flags().GetString("role")
			if username == "" || password == "" || role == "" {
				logrus.Fatal("Username, password, and role are required")
				os.Exit(1)
			}

			// Register the user.
			totpSecret, err := auth.Register(cmd.Context(), username, password, role)
			if err != nil {
				logrus.Error("Failed to register user: ", err)
				os.Exit(1)
				return
			}

			logrus.WithFields(logrus.Fields{
				"username": username,
			}).Info("User registered successfully")
			fmt.Printf("User registered successfully\nTOTP Secret: %s\n", totpSecret)
			fmt.Println("Configure this secret in a TOTP app (e.g., Google Authenticator) for MFA.")
		},
	}

	// Flags for registration.
	cmd.Flags().String("username", "", "Username for the new user")
	cmd.Flags().String("password", "", "Password for the new user")
	cmd.Flags().String("role", "", "Role for the new user (e.g., secrets_manager, crypto_manager, certificate_manager)")

	return cmd
}

// init initializes the register command.
func init() {
	rootCmd.AddCommand(registerCmd())
}
