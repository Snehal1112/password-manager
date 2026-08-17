package app

import (
	"context"
	"time"

	"github.com/gorilla/mux"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/server"
)

// Impl defines the interface for initializing the store and starting the server.
// It contains the following methods:
//
// InitStore initializes the store with the given context.
//
// StartServer starts the server with the given context and returns an error if any occurs.
type Impl interface {
	StartServer(ctx context.Context) error
}

// FrontendConfig holds non-sensitive config values safe to expose to web frontends.
// Populated at startup. Never contains passwords, keys, or tokens.
type FrontendConfig struct {
	FeatureFlags map[string]bool `json:"feature_flags"`
	PublicAPIURL string          `json:"public_api_url"`
	SentryDSN    string          `json:"sentry_dsn"`
}

// App represents the main application structure.
// It holds the server instance, store, configuration details,
// and logger for the vault service application.
type App struct {
	srv               *server.Server
	basePath          string
	databaseName      string
	backendEndPoint   string
	schedulerEnabled  bool
	schedulerInterval time.Duration

	ServiceContainer container.ServiceContainerInterface
	Logger           *logging.Logger
	FrontendConfig   *FrontendConfig
}

// NewApp creates a new instance of the application with the provided options.
// It returns an implementation of the application interface.
//
// Parameters:
//
//	optios - A variadic list of Option types to configure the application.
//
// Returns:
//
//	Impl - An implementation of the application interface.
func NewApp(optios ...Option) Impl {
	return newApp(optios...)
}

// newApp creates a new instance of App and applies the given options to it.
// It also initializes translations and logs an error if the initialization fails.
//
// Parameters:
//
//	options - A variadic list of Option functions to configure the App instance.
//
// Returns:
//
//	A pointer to the newly created App instance.
func newApp(options ...Option) *App {
	a := &App{}
	for _, option := range options {
		option(a)
	}

	if err := common.TranslationsPreInit(); err != nil {
		a.Logger.Errorln("Unable to initialize the localization.")
	}

	return a
}

// NewTestApp creates a minimal App for use in tests.
func NewTestApp(opts ...Option) *App {
	a := &App{}
	for _, o := range opts {
		o(a)
	}
	return a
}

// GetRouter returns the router instance associated with the App.
// It provides access to the underlying mux.Router used by the service.
func (a *App) GetRouter() *mux.Router {
	return a.srv.Router
}

// InitStore initializes the store for the application using the provided context.
// It sets up a new layered store with the backend endpoint and database name
// specified in the App struct. Additionally, it logs the database configuration
// using the application's logger.
//
// Parameters:
//
//	ctx - The context to use for initializing the store.
// func (a *App) InitStore(ctx context.Context) {
// 	a.store = store.NewLayered(
// 		store.WithBackendEndPoint(a.backendEndPoint),
// 		store.WithDatabaseName(a.databaseName),
// 	)
// 	a.logger.WithField("databaseName", a.databaseName).Infoln("database configured")
// }

// StartServer starts the server using the provided context.
// It delegates the server start operation to the srv field of the App struct.
// The context can be used to control the server's lifecycle, such as shutting it down gracefully.
// Returns an error if the server fails to start.
func (a *App) StartServer(ctx context.Context) error {
	// Start the rotation scheduler if enabled and configured
	if a.schedulerEnabled && a.ServiceContainer != nil {
		scheduler := a.ServiceContainer.GetSchedulerService()
		if scheduler != nil {
			interval := a.schedulerInterval
			if interval <= 0 {
				interval = 1 * time.Hour // Default to 1 hour if not specified, or if a config value was invalid (e.g. negative).
			}

			// scheduler.Start already logs its own success line; only log here on failure.
			if err := scheduler.Start(ctx, interval); err != nil {
				a.Logger.WithError(err).WithField("interval", interval).Error("Failed to start rotation scheduler")
			}

			// Handle graceful shutdown of scheduler
			go func() {
				<-ctx.Done()
				a.Logger.Info("Shutting down rotation scheduler")
				err := scheduler.Stop()
				if err != nil {
					a.Logger.WithError(err).Error("Error stopping rotation scheduler")
				}
			}()
		}
	}

	return a.srv.StartServer(ctx)
}
