package bootstrap

import (
	"context"

	"github.com/sirupsen/logrus"

	"password-manager/api"
	"password-manager/app"
	"password-manager/config"
	"password-manager/server"
)

// Config holds the configuration settings for the vault service application.
// It includes the base path for the application, the address to listen on,
// the backend endpoint, the database name, and the logger instance.
type Config struct {
	BasePath        string
	Listen          string
	BackendEndPoint string
	DatabaseName    string
	Logger          logrus.FieldLogger
}

// bootstrap is a struct that holds the configuration and application implementation
// required to initialize and start the application.
//
// Fields:
// - cfg: A pointer to the application's configuration settings.
// - app: An implementation of the application logic.
type bootstrap struct {
	cfg *config.Config
	app app.Impl
}

// Config returns the configuration settings for the bootstrap instance.
// It provides access to the configuration object which contains all the necessary
// settings and parameters required for the application to run.
func (b *bootstrap) Config() *config.Config {
	return b.cfg
}

// Boot initializes and sets up the application using the provided context and configuration.
// It creates a bootstrap instance with the server configuration and calls its setup method.
//
// Parameters:
//   - ctx: The context for controlling cancellation and deadlines.
//   - cfg: The configuration for the application.
//   - serverCfg: The server configuration.
//
// Returns:
//   - error: An error if the setup fails, otherwise nil.
func Boot(ctx context.Context, cfg *Config, serverCfg *config.Config) error {
	bs := &bootstrap{
		cfg: serverCfg,
	}

	if err := bs.setup(ctx, cfg); err != nil {
		return err
	}

	return nil
}

// setup initializes the application with the provided configuration and context.
// It creates a new application instance with the specified database name, base path,
// backend endpoint, logger, and server configuration. It then initializes the API
// with the application instance, base path, router, and logger. Finally, it initializes
// the application's store and starts the server.
//
// Parameters:
//   - ctx: The context for controlling the setup process.
//   - cfg: The configuration settings for the application.
//
// Returns:
//   - error: An error if the setup process fails, otherwise nil.
func (b *bootstrap) setup(ctx context.Context, cfg *Config) error {
	app := app.NewApp(
		app.WithDBName(cfg.DatabaseName),
		app.WithBasePath(cfg.BasePath),
		app.WithBackendEndPoint(cfg.BackendEndPoint),
		app.WithLogger(b.cfg.Logger),
		app.WithServer(server.NewServer(b.cfg.Logger, cfg.Listen)),
	).(*app.App)

	api.Init(
		api.WithAPP(app),
		api.WithBasePath(cfg.BasePath),
		api.WithRouter(app.GetRouter()),
		api.WithLogger(b.cfg.Logger),
	)

	app.StartServer(ctx)
	return nil
}
