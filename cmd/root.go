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

package cmd

import (
	"context"
	"log"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/db"
	"password-manager/internal/logging"
)

// restrictedCmds defines commands that are restricted to certain parents.
var restrictedCmds = map[string]map[string]string{
	"serve": {
		"parent": "password-manager",
	},
	"create": {
		"parent": "users",
	},
}

// cfgFile is the config file name
var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "password-manager",
	Short: "A secure password manager for secrets, keys, and certificates",
	Long: `The password manager is a standalone application for securely managing
secrets, cryptographic keys, and certificates. It provides a CLI for user interaction
and a RESTful API for programmatic access, with features like MFA and secret rotation.`,
	PersistentPreRun:   persistentPreRun,
	PersistentPostRunE: persistentPostRun,
	// Run: func(cmd *cobra.Command, args []string) {},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	ctx := context.Background()
	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		os.Exit(0)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.password-manager.yaml)")

	// Persistent flags for authentication.
	rootCmd.PersistentFlags().String("username", "", "Username for authentication")
	rootCmd.PersistentFlags().String("password", "", "Password for authentication")
	rootCmd.PersistentFlags().String("totp-code", "", "TOTP code for MFA")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		// home, err := os.UserHomeDir()
		// cobra.CheckErr(err)

		// Search config in home directory with name ".password-manager" (without extension).
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".password-manager")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		log.Panicf("Error reading config file: %v (%s)", err, viper.ConfigFileUsed())
	}
}

// persistentPreRun is a Cobra persistent pre-run function that initializes logging,
// database connection, and authentication context for the command execution.
// It checks for restricted commands, initializes the logger and database, and
// sets up the context with database, logger, and user authentication information.
// If username or password flags are missing, or authentication fails, it logs
// an audit error and exits the application.
//
// Parameters:
//   - cmd: *cobra.Command - the command being executed
//   - args: []string - the command-line arguments
//
// Return type: none
func persistentPreRun(cmd *cobra.Command, args []string) {
	logrus.Info("Persistent PreRun called for command:", cmd.Name())
	// TODO: I think not below check is not required.
	if restrictedCmds[cmd.Name()] != nil && restrictedCmds[cmd.Name()]["parent"] == cmd.Parent().Name() {
		return
	}

	// Initialize the logger.
	log := logging.InitLogger()

	// Ensure database is initialized.
	database := db.NewRepository(log)
	database.InitializeDB()

	ctx := context.WithValue(cmd.Context(), common.DBKey, database.GetDB())
	ctx = context.WithValue(ctx, common.DBClassKey, database)
	ctx = context.WithValue(ctx, common.LogKey, log)

	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	totpCode, _ := cmd.Flags().GetString("totp-code")

	if username == "" || password == "" {
		log.LogAuditError("", "secrets", "failed", "Username and password are required for authentication", nil)
		os.Exit(0)
		return
	}

	authRepo := auth.NewUserRepository(database.GetDB(), log)
	token, err := authRepo.Login(ctx, username, password, totpCode)
	if err != nil {
		log.LogAuditError("", "secrets", "failed", "Authentication failed", err)
		os.Exit(0)
		return
	}

	// Parse JWT to extract userID.
	claims, err := auth.ParseJWT(token)
	if err != nil {
		log.LogAuditError("", "secrets", "failed", "Failed to parse JWT", err)
		os.Exit(0)
		return
	}

	// Log successful authentication.
	ctx = context.WithValue(ctx, common.TokenKey, token)
	// Add userID to context.
	ctx = context.WithValue(ctx, common.UserIDKey, claims.UserID)
	// Add claims to context for further use in the command.
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	cmd.SetContext(ctx)

	log.WithFields(logrus.Fields{
		"command":  cmd.Short,
		"jwt":      token[:10] + "...",
		"userID":   claims.UserID,
		"username": username,
	}).Info("User authenticated successfully")
}

// persistentPostRun is a Cobra persistent post-run function that closes the database connection
// after the command execution. It checks if the command is restricted and if so,
// it skips closing the database connection. Otherwise, it safely closes the database
// connection to ensure no resources are leaked.
// Parameters:
//   - cmd: *cobra.Command - the command that was executed
//   - args: []string - the command-line arguments
//
// Return type: error - returns nil if successful, or an error if closing the database fails.
func persistentPostRun(cmd *cobra.Command, args []string) error {
	// TODO: I think not below check is not required.
	if restrictedCmds[cmd.Name()] != nil && restrictedCmds[cmd.Name()]["parent"] == cmd.Parent().Name() {
		return nil
	}

	cmd.Context().Value(common.DBClassKey).(*db.DBRepository).CloseDB()
	return nil
}
