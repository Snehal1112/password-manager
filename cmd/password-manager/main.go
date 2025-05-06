// Package main provides the entry point for the password manager application.
// It initializes configuration, logging, database, and CLI commands using Cobra,
// and supports starting an API server for programmatic access.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/api"
	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Logger is the global logger instance for the application.
var Logger *logging.Logger

// rootCmd is the root CLI command for the password manager.
// It serves as the entry point for all subcommands, such as secrets and server.
var rootCmd = &cobra.Command{
	Use:   "password-manager",
	Short: "A secure password manager for secrets, keys, and certificates",
	Long: `The password manager is a standalone application for securely managing
secrets, cryptographic keys, and certificates. It provides a CLI for user interaction
and a RESTful API for programmatic access, with features like MFA and secret rotation.`,
}

// serverCmd starts the API server.
// It will be implemented to run the Gorilla Mux router for HTTP requests.
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the API server",
	Run: func(cmd *cobra.Command, args []string) {
		server, err := api.NewServer(Logger)
		if err != nil {
			Logger.LogAuditError(0, "server_init", "failed", "Failed to initialize server", err)
			os.Exit(1)
		}

		go func() {
			if err := server.Start(); err != nil {
				Logger.LogAuditError(0, "server_run", "failed", "Server failed", err)
			}
		}()

		// Wait for shutdown signal.
		<-cmd.Context().Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Stop(ctx); err != nil {
			Logger.LogAuditError(0, "server_stop", "failed", "Failed to stop server", err)
		}
	},
}

// init initializes the CLI commands and flags.
func init() {
	rootCmd.AddCommand(serverCmd)
}

// main is the entry point for the password manager application.
// It initializes configuration, logging, database, and CLI commands, then executes
// the Cobra CLI to process user input or start the API server.
//
// Parameters:
//
//	none
//
// Returns:
//
//	none
//
// The function sets up and runs the entire application.
func main() {
	// Initialize configuration.
	if err := initConfig(); err != nil {
		logrus.Fatal("Failed to initialize configuration: ", err)
	}

	// Initialize the database.
	if err := db.InitializeDB(); err != nil {
		logrus.Fatal("Failed to initialize database: ", err)
	}
	defer db.CloseDB()

	// Execute the CLI.
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal("CLI execution failed: ", err)
		os.Exit(1)
	}
}

// initConfig initializes the application configuration.
// It loads settings from a config file or environment variables using Viper.
//
// Parameters:
//
//	none
//
// Returns:
//
//	An error if configuration loading fails.
//
// The function is called at startup to set up application settings.
func initConfig() error {
	// Set configuration file details.
	viper.SetConfigName("config")
	viper.AddConfigPath(".")

	// Set default configuration values.
	viper.SetDefault("database.connection", "./password_manager.db")
	viper.SetDefault("log.level", "debug")
	viper.SetDefault("api.port", "8080")
	viper.SetDefault("master_key", "dGhpcy1pcy1hLXNlY3VyZS1rZXktZm9yLWF1dGgtMTIzNDU2Nzg5MA==")
	viper.SetDefault("jwt_secret", "your-jwt-secret")

	// Bind environment variables to config keys.
	viper.BindEnv("database.connection", "DATABASE_CONNECTION")
	viper.BindEnv("log.level", "LOG_LEVEL")
	viper.BindEnv("api.port", "API_PORT")
	viper.BindEnv("master_key", "MASTER_KEY")
	viper.BindEnv("jwt_secret", "JWT_SECRET")

	// Enable automatic environment variable binding.
	viper.AutomaticEnv()

	// Read the configuration file.
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			Logger.LogAuditError(0, "config_init", "failed", "Failed to read config file", err)
			return fmt.Errorf("failed to read config file: %w", err)
		}
		Logger.LogAuditError(0, "config_init", "failed", "Failed to read config file", err)
		os.Exit(1)
	}

	// Initialize logger
	Logger = logging.InitLogger()

	Logger.LogAuditInfo(0, "config_init", "success", "Configuration file loaded successfully", nil)
	return nil
}
