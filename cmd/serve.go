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
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"password-manager/bootstrap"
	"password-manager/common"
	"password-manager/config"
	"password-manager/internal/db"
	"password-manager/internal/logging"
)

const (
	// defaultListenAddr is the default address the server listens on.
	defaultListenAddr = "127.0.0.1:8774"

	// basePath is the base path for the API.
	basePath = "/api/v1"

	// defaultDBURI is the default MongoDB URI.
	defaultDBURI = "mongodb://0.0.0.0:27017/?retryWrites=false"

	// defaultDatabase is the default database name.
	defaultDatabase = "vault"

	rateLimit = "10-M" // Default rate limit for the API
)

// bootstrapConfig is the configuration for the bootstrap process.
var bootstrapConfig = &bootstrap.Config{}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logrus.Info("Persistent PreRun called from serve for command:", cmd.Name())
		// Initialize the logger.
		log := logging.InitLogger()
		// Start log rotation goroutine
		go rotateLogsPeriodically(log)

		// Ensure database is initialized.
		database := db.NewRepository(log)
		database.InitializeDB()

		ctx := context.WithValue(cmd.Context(), common.DBKey, database.GetDB())
		ctx = context.WithValue(ctx, common.DBClassKey, database)
		ctx = context.WithValue(ctx, common.LogKey, log)
		cmd.SetContext(ctx)

	},
	Run: func(cmd *cobra.Command, args []string) {
		if err := serve(cmd); err != nil {
			fmt.Printf("Error: %v\n\n", err)
			os.Exit(1)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		logrus.Info("Persistent PostRun called from serve for command:", cmd.Name())
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	cfg := bootstrapConfig
	serveCmd.Flags().StringVar(&cfg.Listen, "listen", getEnv("PASSWORD_MANAGER_LISTEN", defaultListenAddr), fmt.Sprintf("TCP listen address (default \"%s\").", "8774"))
	serveCmd.Flags().StringVar(&cfg.BasePath, "api_base", getEnv("PASSWORD_MANAGER_BASE_API", basePath), "Base api path for the password manager service.")
	serveCmd.Flags().StringVar(&cfg.BackendEndPoint, "backend_url", getEnv("PASSWORD_MANAGER_BACKEND_ENDPOINT", defaultDBURI), "Backend end point of password manager service.")
	serveCmd.Flags().StringVar(&cfg.DatabaseName, "database_name", getEnv("PASSWORD_MANAGER_DATABASE", defaultDatabase), "Database name which used by the password manager service.")
	serveCmd.Flags().Bool("log-timestamp", true, "Prefix each log line with timestamp")
	serveCmd.Flags().String("log-level", "info", "Log level (one of panic, fatal, error, warn, info or debug)")
}

// serve initializes and starts the server with the provided command.
// It sets up the logging configuration based on the command flags and
// then calls the bootstrap function to start the application.
//
// Parameters:
//   - cmd: The cobra command that contains the flags for configuration.
//
// Returns:
//   - error: An error if the server fails to start or if there is an issue
//     with the logger configuration.
func serve(cmd *cobra.Command) error {
	ctx := cmd.Context()

	log := ctx.Value(common.LogKey).(*logging.Logger)

	return bootstrap.Boot(ctx, bootstrapConfig, &config.Config{
		Logger: log,
	})
}
