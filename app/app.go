package app

import (
	"context"

	"github.com/gorilla/mux"

	"password-manager/internal/logging"
	"password-manager/model"
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

	if err := model.TranslationsPreInit(); err != nil {
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
	return a.srv.StartServer(ctx)
}
