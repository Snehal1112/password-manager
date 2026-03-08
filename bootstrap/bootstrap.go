// Package bootstrap provides application initialization with proper separation of concerns.
// This refactored version follows SRP by delegating specific concerns to dedicated
// initializers while maintaining a clean orchestration layer.
package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"rocketvault/api"
	"rocketvault/app"
	"rocketvault/config"
	"rocketvault/internal/container"
	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/softdelete"
	"rocketvault/server"
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

// DatabaseInitializer handles database setup and initialization.
// It follows SRP by focusing only on database-related concerns.
type DatabaseInitializer struct {
	logger *logging.Logger
}

// NewDatabaseInitializer creates a new database initializer.
func NewDatabaseInitializer(logger *logging.Logger) *DatabaseInitializer {
	return &DatabaseInitializer{logger: logger}
}

// Initialize sets up the database connection and schema.
func (d *DatabaseInitializer) Initialize(cfg *config.Config) (*db.DBRepository, error) {
	d.logger.Info("Initializing database")

	database := db.NewRepository(cfg.Logger)
	if err := database.InitializeDB(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	d.logger.Info("Database initialized successfully")
	return database, nil
}

// ServerStarter handles server lifecycle management.
// It follows SRP by focusing only on server startup concerns.
type ServerStarter struct {
	logger *logging.Logger
}

// NewServerStarter creates a new server starter.
func NewServerStarter(logger *logging.Logger) *ServerStarter {
	return &ServerStarter{logger: logger}
}

// Start initializes and starts the HTTP server.
func (s *ServerStarter) Start(ctx context.Context, app *app.App) error {
	s.logger.Info("Starting HTTP server")
	app.StartServer(ctx)
	s.logger.Info("HTTP server started successfully")
	return nil
}

// ConfigurationValidator handles configuration validation.
// It follows SRP by focusing only on configuration validation concerns.
type ConfigurationValidator struct {
	logger *logging.Logger
}

// NewConfigurationValidator creates a new configuration validator.
func NewConfigurationValidator(logger *logging.Logger) *ConfigurationValidator {
	return &ConfigurationValidator{logger: logger}
}

// Validate checks that all required configuration is present and valid.
func (c *ConfigurationValidator) Validate(cfg *Config, serverCfg *config.Config) error {
	c.logger.Info("Validating configuration")

	if cfg.DatabaseName == "" {
		return fmt.Errorf("database name is required")
	}
	if cfg.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/"
	}
	if cfg.Logger == nil {
		return fmt.Errorf("logger is required")
	}
	if serverCfg.Logger == nil {
		return fmt.Errorf("server logger is required")
	}

	c.logger.Info("Configuration validation successful")
	return nil
}

// bootstrap provides orchestration for application startup following SRP.
// It coordinates different initializers while maintaining single responsibility.
type bootstrap struct {
	dbInitializer    *DatabaseInitializer
	serverStarter    *ServerStarter
	configValidator  *ConfigurationValidator
	serviceContainer *container.ServiceContainer
	cfg              *config.Config
	purgeScheduler   *softdelete.PurgeScheduler
}

// newBootstrap creates a new bootstrap orchestrator with SRP-compliant design.
func newBootstrap(serverCfg *config.Config) *bootstrap {
	return &bootstrap{
		cfg:             serverCfg,
		dbInitializer:   NewDatabaseInitializer(serverCfg.Logger),
		serverStarter:   NewServerStarter(serverCfg.Logger),
		configValidator: NewConfigurationValidator(serverCfg.Logger),
	}
}

// Config returns the configuration settings for the bootstrap instance.
func (b *bootstrap) Config() *config.Config {
	return b.cfg
}

// GetServiceContainer returns the service container for external access.
func (b *bootstrap) GetServiceContainer() *container.ServiceContainer {
	return b.serviceContainer
}

// Boot initialises the application and returns a shutdown function and any setup error.
// Call the returned shutdown function after the HTTP server has stopped to release resources.
func Boot(ctx context.Context, cfg *Config, serverCfg *config.Config) (func(context.Context) error, error) {
	bs := newBootstrap(serverCfg)
	if err := bs.setup(ctx, cfg); err != nil {
		return nil, err
	}
	return bs.Shutdown, nil
}

// setup orchestrates the complete application startup process following SRP.
// It coordinates initialization steps while delegating specific tasks to specialized initializers.
//
// Parameters:
//   - ctx: The context for controlling the setup process.
//   - cfg: The configuration settings for the application.
//
// Returns:
//   - error: An error if the setup process fails, otherwise nil.
func (b *bootstrap) setup(ctx context.Context, cfg *Config) error {
	logrus.Info("Starting application bootstrap")

	// Step 1: Validate configuration (SRP: dedicated validator)
	if err := b.configValidator.Validate(cfg, b.cfg); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Step 2: Initialize database (SRP: dedicated initializer)
	database, err := b.dbInitializer.Initialize(b.cfg)
	if err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}

	// Step 2b: Start background purge scheduler when soft-delete is enabled.
	softDeleteCfg := config.LoadSoftDeleteConfig()
	if softDeleteCfg.Enabled {
		b.purgeScheduler = softdelete.NewPurgeScheduler(database.GetDB(), softDeleteCfg, b.cfg.Logger)
		b.purgeScheduler.Start(ctx)
		b.cfg.Logger.Info("Soft-delete purge scheduler started")
	}

	// Step 3: Initialize service container (SRP: dependency injection)
	serviceContainer, err := container.NewServiceContainer(container.Config{
		Database: database.GetDB(),
		Logger:   b.cfg.Logger,
	})
	if err != nil {
		return fmt.Errorf("service container initialization failed: %w", err)
	}
	b.serviceContainer = serviceContainer

	// Step 4: Create application with dependency injection
	app, err := b.createApplication(cfg)
	if err != nil {
		return fmt.Errorf("application creation failed: %w", err)
	}

	// Step 6: Initialize API with dependencies
	if err := b.initializeAPI(cfg, app); err != nil {
		return fmt.Errorf("API initialization failed: %w", err)
	}

	// Step 7: Start server (SRP: dedicated starter)
	if err := b.serverStarter.Start(ctx, app); err != nil {
		return fmt.Errorf("server startup failed: %w", err)
	}

	logrus.Info("Application bootstrap completed successfully")
	return nil
}


// createApplication creates the main application instance with injected dependencies.
// This method follows SRP by handling only application instance creation.
func (b *bootstrap) createApplication(cfg *Config) (*app.App, error) {
	logrus.Info("Creating application instance")

	app := app.NewApp(
		app.WithDBName(cfg.DatabaseName),
		app.WithBasePath(cfg.BasePath),
		app.WithBackendEndPoint(cfg.BackendEndPoint),
		app.WithLogger(b.cfg.Logger),
		app.WithServer(server.NewDefaultServer(b.cfg.Logger, cfg.Listen)),
		app.WithServiceContainer(b.serviceContainer),
		app.WithSchedulerEnabled(true, 1*time.Hour), // Enable scheduler with 1-hour interval
	).(*app.App)

	logrus.Info("Application instance created successfully")
	return app, nil
}

// initializeAPI sets up the API layer with proper dependency injection.
// This method follows SRP by handling only API initialization concerns.
func (b *bootstrap) initializeAPI(cfg *Config, app *app.App) error {
	logrus.Info("Initializing API layer")

	api.Init(
		api.WithAPP(app),
		api.WithBasePath(cfg.BasePath),
		api.WithRouter(app.GetRouter()),
		api.WithLogger(b.cfg.Logger),
	)

	logrus.Info("API layer initialized successfully")
	return nil
}

// Shutdown performs graceful application shutdown.
// This method follows SRP by handling only shutdown concerns.
func (b *bootstrap) Shutdown(ctx context.Context) error {
	logrus.Info("Starting application shutdown")

	if b.purgeScheduler != nil {
		b.purgeScheduler.Stop()
		logrus.Info("Soft-delete purge scheduler stopped")
	}

	if b.serviceContainer != nil {
		if err := b.serviceContainer.Close(); err != nil {
			logrus.WithError(err).Error("Error closing service container")
			return fmt.Errorf("service container shutdown failed: %w", err)
		}
	}

	logrus.Info("Application shutdown completed")
	return nil
}
