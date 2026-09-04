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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/bootstrap"
	"rocketvault/common"
	"rocketvault/config"
	"rocketvault/internal/logging"
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
)

// bootstrapConfig is the configuration for the bootstrap process.
var bootstrapConfig = &bootstrap.Config{}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	Long: `Start the RocketVault API server: open the database connection, build the
service container (JWT signing-key provider, key provider, and OIDC when
enabled), and begin serving the HTTP API on the configured listen address.

.rocketvault.yaml is the only config file loaded at runtime. Startup aborts if
master_key is not usable or if the configured JWT signing-key provider cannot
be constructed. jwt.expiry is optional and defaults to 1h.

--listen overrides server.listen_addr from the config file, which in turn
overrides the PASSWORD_MANAGER_LISTEN environment variable and the built-in
default of 127.0.0.1:8774.`,
	Example: `  # Start the API server on the default address
  rocketvault serve

  # Start on a custom listen address with debug logging
  rocketvault serve --listen :9000 --log-level debug`,
	// Replace the root PersistentPreRunE. The root pre-run opens a database
	// connection and builds a full ServiceContainer (JWT signing key, OIDC,
	// key provider) purely to discard them for "serve" — bootstrap.Boot below
	// does that same initialization for real. See cmd/vaults/preview_migration.go
	// for the same pattern used for the same reason.
	PersistentPreRunE: servePreRun,
	RunE: func(cmd *cobra.Command, args []string) error {
		return serve(cmd)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	cfg := bootstrapConfig

	// The flag's own default can only be the env var or hardcoded fallback:
	// init() runs at package-load time, before cobra.OnInitialize(initConfig)
	// has parsed --config and loaded server.listen_addr into viper. The
	// config file's value is applied later, in servePreRun, once it's
	// actually available -- see the comment there.
	listenAddr := getEnv("PASSWORD_MANAGER_LISTEN", defaultListenAddr)

	serveCmd.Flags().StringVar(&cfg.Listen, "listen", listenAddr, fmt.Sprintf("TCP listen address (default \"%s\").", "8774"))
	serveCmd.Flags().StringVar(&cfg.BasePath, "api_base", getEnv("PASSWORD_MANAGER_BASE_API", basePath), "Base api path for the password manager service.")
	serveCmd.Flags().StringVar(&cfg.BackendEndPoint, "backend_url", getEnv("PASSWORD_MANAGER_BACKEND_ENDPOINT", defaultDBURI), "Backend end point of password manager service.")
	serveCmd.Flags().StringVar(&cfg.DatabaseName, "database_name", getEnv("PASSWORD_MANAGER_DATABASE", defaultDatabase), "Database name which used by the password manager service.")
	serveCmd.Flags().Bool("log-timestamp", true, "Prefix each log line with timestamp")
	serveCmd.Flags().String("log-level", "info", "Log level (one of panic, fatal, error, warn, info or debug)")
}

// servePreRun installs the logger without duplicating the DB connection and
// ServiceContainer that bootstrap.Boot builds for real inside serve(). It
// intentionally skips the root pre-run's authentication check too, since
// "serve" starting up requires no prior login.
func servePreRun(cmd *cobra.Command, _ []string) error {
	// Apply server.listen_addr from the config file, now that
	// cobra.OnInitialize(initConfig) has actually loaded it into viper --
	// init() above runs too early to see it. An explicit --listen flag still
	// wins over the config file, which still wins over the env var/hardcoded
	// default baked into the flag's own default.
	if !cmd.Flags().Changed("listen") {
		if v := viper.GetString("server.listen_addr"); v != "" {
			bootstrapConfig.Listen = v
		}
	}

	log := logging.InitLogger()
	go log.StartPeriodicRotation()

	ctx := context.WithValue(cmd.Context(), common.LogKey, log)
	cmd.SetContext(ctx)

	log.WithField("command", cmd.Name()).Info("System command executed without authentication")
	return nil
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

	// Set up logging configuration based on command flags.
	bootstrapConfig.Logger = log

	// Set up the HTTP transport for the server.
	shutdown, err := bootstrap.Boot(ctx, bootstrapConfig, &config.Config{
		Logger: log,
	})
	if err != nil {
		return err
	}
	defer shutdown(ctx) //nolint:errcheck
	return nil
}
