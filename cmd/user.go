package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/db"
	"github.com/spf13/cobra"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users",
}

var registerCmd = &cobra.Command{
	Use:   "register [username] [password] [role]",
	Short: "Register a new user",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		if err := db.InitializeDB(); err != nil {
			logrus.Fatal("Failed to initialize database: ", err)
		}
		defer db.CloseDB()

		username, password, role := args[0], args[1], args[2]
		totpURL, err := auth.Register(username, password, role)
		if err != nil {
			logrus.Fatal("Failed to register user: ", err)
		}

		fmt.Printf("User registered successfully. Scan this TOTP URL with an authenticator app:\n%s\n", totpURL)
	},
}

func init() {
	userCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(userCmd)
}
