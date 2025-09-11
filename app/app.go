package app

import (
	"context"
	"time"

	"github.com/gorilla/mux"

	"password-manager/common"
	"password-manager/internal/logging"
	"password-manager/internal/secrets"
	"password-manager/server"
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

// App represents the main application structure.
// It holds the server instance, store, configuration details,
// and logger for the vault service application.
type App struct {
	srv             *server.Server
	basePath        string
	databaseName    string
	backendEndPoint string
	Logger          *logging.Logger
	scheduler       *secrets.RotationScheduler
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
	// Start the rotation scheduler if configured
	if a.scheduler != nil {
		a.scheduler.Start(1 * time.Hour) // Check every hour
		a.Logger.Info("Rotation scheduler started")

		// Handle graceful shutdown of scheduler
		go func() {
			<-ctx.Done()
			a.Logger.Info("Shutting down rotation scheduler")
			a.scheduler.Stop()
		}()
	}

	return a.srv.StartServer(ctx)
}

// RotationScheduler is responsible for managing the rotation of secrets
// in the application. It defines the schedule and the method to execute
// for rotating the secrets.
//
// Parameters:
//
//	interval - The duration between each rotation execution.
//	factory  - A function that creates a new instance of the secret to be rotated.
//	exec     - A function that performs the rotation of the secret.
type RotationScheduler struct {
	interval time.Duration
	factory  func() secrets.Secret
	exec     func(secrets.Secret) error
}

// NewRotationScheduler creates a new instance of RotationScheduler with the
// specified interval, factory, and execution function.
//
// Parameters:
//
//	interval - The duration between each rotation execution.
//	factory  - A function that creates a new instance of the secret to be rotated.
//	exec     - A function that performs the rotation of the secret.
//
// Returns:
//
//	A pointer to the newly created RotationScheduler instance.
func NewRotationScheduler(interval time.Duration, factory func() secrets.Secret, exec func(secrets.Secret) error) *RotationScheduler {
	return &RotationScheduler{
		interval: interval,
		factory:  factory,
		exec:     exec,
	}
}

// Start initiates the secret rotation process. It runs the rotation execution
// function at the specified interval, creating a new secret instance using the
// factory function for each rotation.
//
// This method will block until the context is done.
//
// Parameters:
//
//	ctx - The context to control the lifecycle of the rotation process.
func (rs *RotationScheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(rs.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			secret := rs.factory()
			if err := rs.exec(secret); err != nil {
				// Handle rotation execution error
			}
		}
	}
}
