package api

import (
	"strings"

	"github.com/gorilla/mux"

	"password-manager/app"
	"password-manager/internal/health"
	"password-manager/internal/logging"
	"password-manager/internal/middleware"
)

// router is a type alias for a map where the keys are strings and the values are pointers to mux.Router.
// This type alias is used to simplify the declaration and usage of maps that store mux.Router instances.
type router = map[string]*mux.Router

// API represents the main API structure for the vault service application.
// It contains references to the application instance, base routes, base path,
// root router, service container, and a logger.
//
// Fields:
// - App: A pointer to the main application instance.
// - BaseRoutes: The base routes for the API.
// - basePath: The base path for the API endpoints.
// - rootRouter: The root router for handling HTTP requests.
// - ServiceContainer: The service container providing access to all services.
// - Logger: The logger used for logging API-related information.
type API struct {
	App        *app.App
	BaseRoutes router
	basePath   string
	rootRouter *mux.Router
	Logger     *logging.Logger
}

// Init initializes the API with the provided options and sets up the base routes.
// It configures the logger with the base path and initializes the Vault routes.
//
// Parameters:
//
//	options - A variadic list of Option functions to configure the API.
//
// Returns:
//
//	*API - A pointer to the initialized API instance.
func Init(options ...Options) *API {
	api := &API{
		BaseRoutes: make(router),
	}

	for _, option := range options {
		option(api)
	}

	middleware := middleware.NewMiddleware(api.App.ServiceContainer)
	api.Logger.WithField("basePath", api.basePath).Infoln("Api configured with")
	api.BaseRoutes["ApiRoot"] = api.rootRouter.PathPrefix(api.basePath).Subrouter()

	api.BaseRoutes["ApiRoot"].Use(
		middleware.RateLimitMiddleware,
	)
	api.BaseRoutes["Vault"] = api.BaseRoutes["ApiRoot"].PathPrefix("/vault").Subrouter()
	api.BaseRoutes["Secrets"] = api.BaseRoutes["ApiRoot"].PathPrefix("/secrets").Subrouter()
	api.BaseRoutes["Users"] = api.BaseRoutes["ApiRoot"].PathPrefix("/users").Subrouter()
	api.BaseRoutes["Keys"] = api.BaseRoutes["ApiRoot"].PathPrefix("/keys").Subrouter()
	api.BaseRoutes["Health"] = api.BaseRoutes["ApiRoot"].PathPrefix("/health").Subrouter()

	api.InitVault(api.BaseRoutes["Vault"])
	api.InitSecrets(api.BaseRoutes["Secrets"])
	api.InitUsers(api.BaseRoutes["Users"])
	api.InitKeys(api.BaseRoutes["Keys"])
	api.InitHealth(api.BaseRoutes["Health"])

	var apiNames []string
	for s := range api.BaseRoutes {
		if s != "ApiRoot" {
			apiNames = append(apiNames, s)
		}
	}
	api.Logger.WithField("api", strings.Join(apiNames, ",")).Infoln("Initialized api")
	return api
}

// InitHealth initializes the routes for the health service API.
// It sets up the following endpoints:
// - GET /health: Returns comprehensive health metrics
// - GET /health/ready: Returns readiness status
// - GET /health/live: Returns liveness status
//
// Parameters:
// - healthRouter (*mux.Router): The router to which the routes will be added.
func (api *API) InitHealth(healthRouter *mux.Router) {
	// Create health collector with service container database connection
	collector := health.NewHealthCollector(api.App.ServiceContainer.GetDatabase())

	// Create health handler
	handler := NewHealthHandler(collector, api.Logger)

	// Register routes
	healthRouter.HandleFunc("", handler.HealthCheck).Methods("GET")
	healthRouter.HandleFunc("/ready", handler.ReadinessCheck).Methods("GET")
	healthRouter.HandleFunc("/live", handler.LivenessCheck).Methods("GET")

	api.Logger.Infoln("Health API routes initialized")
}
