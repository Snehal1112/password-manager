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
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/db"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)

// cfgFile is the config file name
var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rocketvault",
	Short: "A secure password manager for secrets, keys, and certificates",
	Long: `The password manager is a standalone application for securely managing
secrets, cryptographic keys, and certificates. It provides a CLI for user interaction
and a RESTful API for programmatic access, with features like MFA and secret rotation.`,
	Example: `  # Log in
  rocketvault users login --username admin --password admin123 --totp-code <code>

  # Create and read a secret
  rocketvault secrets create <name> <value> --username admin --password admin123 --totp-code <code>
  rocketvault secrets get <id> --username admin --password admin123 --totp-code <code>

  # Start the API server
  rocketvault serve`,
	PersistentPreRunE:  persistentPreRun,
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
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.rocketvault.yaml)")

	// Persistent flags for authentication.
	rootCmd.PersistentFlags().String("username", "", "Username for authentication")
	rootCmd.PersistentFlags().String("password", "", "Password for authentication")
	rootCmd.PersistentFlags().String("totp-code", "", "TOTP code for MFA")
	rootCmd.PersistentFlags().String("output", "table", "Output format: table, json, yaml")

	// Persistent flag selecting the target vault for resource commands.
	rootCmd.PersistentFlags().String("vault", "", "Target vault name (default: \"default\")")
	_ = viper.BindPFlag("vault", rootCmd.PersistentFlags().Lookup("vault"))

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

		// Search config in home directory with name ".rocketvault" (without extension).
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".rocketvault")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		log.Panicf("Error reading config file: %v (%s)", err, viper.ConfigFileUsed())
	}
}

// resolveAuthentication determines the CLI caller's identity for a command
// that requires authentication. It tries, in order:
//  1. --username + --password (+ --totp-code): fresh password/TOTP login,
//     cached to disk on success.
//  2. --username alone (no --password): load that user's cached session.
//  3. no flags at all: load whichever session ~/.rocketvault/sessions/current
//     currently points at.
//
// A cached session past its ExpiresAt is refreshed transparently via its
// refresh token (and the cache updated) before being returned.
func resolveAuthentication(cmd *cobra.Command, authSvc authServices.AuthenticationService) (*authServices.AuthenticationResult, error) {
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	totpCode, _ := cmd.Flags().GetString("totp-code")

	if username != "" && password != "" {
		result, err := authSvc.AuthenticateUser(cmd.Context(), username, password, totpCode)
		if err != nil {
			return nil, err
		}
		if saveErr := common.SaveSession(&common.SessionCache{
			Token:        result.Token,
			RefreshToken: result.RefreshToken,
			UserID:       result.UserID,
			Username:     result.Username,
			Role:         result.Role,
			ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
		}); saveErr != nil {
			logrus.WithError(saveErr).Warn("failed to cache CLI session")
		}
		return result, nil
	}

	var cached *common.SessionCache
	var err error
	if username != "" {
		cached, err = common.LoadSession(username)
	} else {
		cached, err = common.LoadCurrentSession()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read cached session: %w", err)
	}
	if cached == nil {
		return nil, errors.New("no credentials provided and no cached session found")
	}

	if time.Now().Before(cached.ExpiresAt) {
		return &authServices.AuthenticationResult{
			Token:        cached.Token,
			RefreshToken: cached.RefreshToken,
			UserID:       cached.UserID,
			Username:     cached.Username,
			Role:         cached.Role,
		}, nil
	}

	refreshed, err := authSvc.RefreshAccessToken(cmd.Context(), cached.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("cached session expired and refresh failed: %w", err)
	}

	if saveErr := common.SaveSession(&common.SessionCache{
		Token:        refreshed.Token,
		RefreshToken: refreshed.RefreshToken,
		UserID:       refreshed.UserID,
		Username:     refreshed.Username,
		Role:         refreshed.Role,
		ExpiresAt:    refreshed.ExpiresAt,
	}); saveErr != nil {
		logrus.WithError(saveErr).Warn("failed to cache refreshed CLI session")
	}

	return &authServices.AuthenticationResult{
		Token:        refreshed.Token,
		RefreshToken: refreshed.RefreshToken,
		UserID:       refreshed.UserID,
		Username:     refreshed.Username,
		Role:         refreshed.Role,
	}, nil
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
func persistentPreRun(cmd *cobra.Command, args []string) error {
	logrus.Info("Persistent PreRun called for command:", cmd.Name())

	// System commands that don't require authentication
	systemCmds := map[string]bool{
		"health":            true,
		"serve":             true, // Server startup doesn't require prior authentication
		"admin":             true, // Allow admin registration without prior authentication
		"migrate":           true, // Database migrations don't require authentication
		"migrate:status":    true, // Migration status check
		"migrate:to":        true, // Targeted migrations
		"migrate:create":    true, // Migration file creation
		"roles":             true, // Lists built-in vault roles; pure client-side, no auth needed
		"preview-migration": true, // Reads ownership to plan role assignments; no auth, no writes
		"login":             true, // Bootstraps a session (password or --oidc); cannot itself require one
		"logout":            true, // Clears a cached session; must work even if that session is broken
	}

	// Check if this is a system command (either the command itself or its parent)
	isSystemCmd := systemCmds[cmd.Name()]
	if !isSystemCmd && cmd.Parent() != nil {
		isSystemCmd = systemCmds[cmd.Parent().Name()]
	}

	// Initialize the logger.
	log := logging.InitLogger()
	// Start log rotation goroutine
	go log.StartPeriodicRotation()

	// Ensure database is initialized.
	database := db.NewRepository(log)
	database.InitializeDB() //nolint:errcheck,gosec

	// Create service container
	serviceContainer, err := container.NewServiceContainer(container.Config{
		Database: database.GetDB(),
		Logger:   log,
	})
	if err != nil {
		log.LogAuditError("", "init_services", "failed", "Failed to initialize service container", err)
		return errors.New("failed to initialize services")
	}

	ctx := context.WithValue(cmd.Context(), common.DBKey, database.GetDB())
	ctx = context.WithValue(ctx, common.DBClassKey, database)
	ctx = context.WithValue(ctx, common.LogKey, log)
	ctx = context.WithValue(ctx, common.ServiceContainerKey, serviceContainer)

	outputFlag, _ := cmd.Flags().GetString("output")
	fmtr, fmtrErr := formatter.New(formatter.Format(outputFlag))
	if fmtrErr != nil {
		return fmt.Errorf("invalid --output value %q: must be table, json, or yaml", outputFlag)
	}
	ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
	cmd.SetContext(ctx)

	// Skip authentication for system commands
	if isSystemCmd {
		log.WithField("command", cmd.Name()).Info("System command executed without authentication")
		return nil
	}

	authService := serviceContainer.GetAuthenticationService()
	authResult, err := resolveAuthentication(cmd, authService)
	if err != nil {
		log.LogAuditError("", "secrets", "failed", "Authentication failed", err)
		cmd.PrintErrln("Error: Authentication failed -", err.Error())
		cmd.PrintErrln("Run 'rocketvault users login' or 'rocketvault users login --oidc' first, or pass --username/--password/--totp-code.")
		return errors.New("authentication failed")
	}

	// Create claims from authentication result (no need to parse JWT)
	claims := &model.Claims{
		UserID:   authResult.UserID,
		Username: authResult.Username,
		Role:     authResult.Role,
	}

	// Log successful authentication.
	ctx = context.WithValue(ctx, common.TokenKey, authResult.Token)
	// Add userID to context.
	ctx = context.WithValue(ctx, common.UserIDKey, claims.UserID)
	// Add claims to context for further use in the command.
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	cmd.SetContext(ctx)

	log.WithFields(logrus.Fields{
		"command":  cmd.Short,
		"jwt":      authResult.Token[:10] + "...",
		"userID":   claims.UserID,
		"username": authResult.Username,
	}).Info("User authenticated successfully")
	return nil
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
	if dbRepo, ok := cmd.Context().Value(common.DBClassKey).(*db.DBRepository); ok {
		return dbRepo.CloseDB()
	}
	return nil
}
