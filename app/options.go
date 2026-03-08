package app

import (
	"time"

	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/server"
)

// Option represents a function that modifies the configuration or behavior of an App instance.
// It is used to apply various settings or options to an App during its initialization or setup.
type Option func(a *App)

// WithBasePath sets the base path for the App.
//
// Parameters:
//   - basePath: The base path to be set.
//
// Returns:
//   - Option: A function that sets the base path of the App.
func WithBasePath(basePath string) Option {
	return func(a *App) {
		a.basePath = basePath
	}
}

// WithDBName sets the database name for the App instance.
// It returns an Option that applies the given database name to the App.
//
// Parameters:
//   - databaseName: The name of the database to be set.
//
// Returns:
//   - Option: A function that sets the database name in the App instance.
func WithDBName(databaseName string) Option {
	return func(a *App) {
		a.databaseName = databaseName
	}
}

// WithBackendEndPoint sets the backend endpoint for the App.
// It takes a string parameter backendEndPoint which specifies the endpoint URL.
// It returns an Option which is a function that modifies the App instance.
func WithBackendEndPoint(backendEndPoint string) Option {
	return func(a *App) {
		a.backendEndPoint = backendEndPoint
	}
}

// WithServer returns an Option that sets the server for the App.
// It takes a pointer to a server.Server and assigns it to the App's srv field.
func WithServer(server *server.Server) Option {
	return func(a *App) {
		a.srv = server
	}
}

// WithLogger sets the logger for the App instance.
// It takes a logrus.FieldLogger as an argument and returns an Option.
// The logger will be used for logging within the App.
//
// Example usage:
//
//	logger := logrus.New()
//	app := NewApp(WithLogger(logger))
func WithLogger(logger *logging.Logger) Option {
	return func(a *App) {
		a.Logger = logger
	}
}

// WithSchedulerEnabled enables or disables the rotation scheduler.
// When enabled, the scheduler will automatically process rotations and reminders
// according to the configured policies.
//
// Parameters:
//   - enabled: Whether to enable the rotation scheduler.
//   - interval: The interval at which the scheduler runs (e.g., 1 hour).
//
// Returns:
//   - Option: A function that configures the scheduler settings.
func WithSchedulerEnabled(enabled bool, interval time.Duration) Option {
	return func(a *App) {
		a.schedulerEnabled = enabled
		a.schedulerInterval = interval
	}
}

// WithServiceContainer sets the service container for the API.
// It provides access to all refactored services following the dependency injection pattern.
// This enables proper integration between the API layer and the SRP-compliant service layer.
//
// Parameters:
//
//	container (*container.ServiceContainer): The service container with all initialized services.
//
// Returns:
//
//	Options: A function that sets the service container for the API.
func WithServiceContainer(container *container.ServiceContainer) Option {
	return func(a *App) {
		a.ServiceContainer = container
	}
}
