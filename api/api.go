package api

import (
	"strings"

	"github.com/gorilla/mux"

	"rocketvault/app"
	"rocketvault/internal/health"
	"rocketvault/internal/logging"
	"rocketvault/internal/middleware"
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
		middleware.AuthenticationMiddleware,
		middleware.AuthorizationMiddleware,
	)
	api.BaseRoutes["Vault"] = api.BaseRoutes["ApiRoot"].PathPrefix("/vault").Subrouter()
	api.BaseRoutes["Secrets"] = api.BaseRoutes["ApiRoot"].PathPrefix("/secrets").Subrouter()
	api.BaseRoutes["Users"] = api.BaseRoutes["ApiRoot"].PathPrefix("/users").Subrouter()
	api.BaseRoutes["Keys"] = api.BaseRoutes["ApiRoot"].PathPrefix("/keys").Subrouter()
	api.BaseRoutes["Health"] = api.BaseRoutes["ApiRoot"].PathPrefix("/health").Subrouter()
	api.BaseRoutes["Deleted"] = api.BaseRoutes["ApiRoot"].PathPrefix("/deleted").Subrouter()

	api.InitVault(api.BaseRoutes["Vault"])
	api.InitSecrets(api.BaseRoutes["Secrets"])
	api.InitUsers(api.BaseRoutes["Users"])
	api.InitKeys(api.BaseRoutes["Keys"])
	api.InitHealth(api.BaseRoutes["Health"])
	api.InitDeleted(api.BaseRoutes["Deleted"])

	var apiNames []string
	for s := range api.BaseRoutes {
		if s != "ApiRoot" {
			apiNames = append(apiNames, s)
		}
	}
	api.Logger.WithField("api", strings.Join(apiNames, ",")).Infoln("Initialized api")
	return api
}

// InitDeleted initializes the routes for soft-delete recovery and purge operations.
// It sets up the following endpoints:
// - GET    /deleted/secrets                   — List soft-deleted secrets.
// - POST   /deleted/secrets/{id}/recover      — Recover a soft-deleted secret.
// - DELETE /deleted/secrets/{id}              — Permanently purge a soft-deleted secret.
// - GET    /deleted/keys                      — List soft-deleted keys.
// - POST   /deleted/keys/{id}/recover         — Recover a soft-deleted key.
// - DELETE /deleted/keys/{id}                 — Permanently purge a soft-deleted key.
// - GET    /deleted/certificates              — List soft-deleted certificates.
// - POST   /deleted/certificates/{id}/recover — Recover a soft-deleted certificate.
// - DELETE /deleted/certificates/{id}         — Permanently purge a soft-deleted certificate.
//
// Parameters:
// - deletedRouter (*mux.Router): The router to which the routes will be added.
func (api *API) InitDeleted(deletedRouter *mux.Router) {
	// Soft-deleted secrets.
	deletedRouter.Handle("/secrets", SessionRequired(api.App, listDeletedSecrets)).Methods("GET")
	deletedRouter.Handle("/secrets/{id:[A-Fa-f0-9-]+}/recover", SessionRequired(api.App, recoverSecret)).Methods("POST")
	deletedRouter.Handle("/secrets/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, purgeSecret)).Methods("DELETE")

	// Soft-deleted keys.
	deletedRouter.Handle("/keys", SessionRequired(api.App, listDeletedKeys)).Methods("GET")
	deletedRouter.Handle("/keys/{id:[A-Fa-f0-9-]+}/recover", SessionRequired(api.App, recoverKey)).Methods("POST")
	deletedRouter.Handle("/keys/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, purgeKey)).Methods("DELETE")

	// Soft-deleted certificates.
	deletedRouter.Handle("/certificates", SessionRequired(api.App, listDeletedCertificates)).Methods("GET")
	deletedRouter.Handle("/certificates/{id:[A-Fa-f0-9-]+}/recover", SessionRequired(api.App, recoverCertificate)).Methods("POST")
	deletedRouter.Handle("/certificates/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, purgeCertificate)).Methods("DELETE")

	api.Logger.Infoln("Deleted resources API routes initialized")
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
