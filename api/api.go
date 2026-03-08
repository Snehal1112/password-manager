package api

import (
	"strings"

	"github.com/gorilla/mux"

	"rocketvault/app"
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
		middleware.PolicyMiddleware,
		middleware.AuthorizationMiddleware,
	)
	api.BaseRoutes["Vault"] = api.BaseRoutes["ApiRoot"].PathPrefix("/vault").Subrouter()
	api.BaseRoutes["Secrets"] = api.BaseRoutes["ApiRoot"].PathPrefix("/secrets").Subrouter()
	api.BaseRoutes["Users"] = api.BaseRoutes["ApiRoot"].PathPrefix("/users").Subrouter()
	api.BaseRoutes["Keys"] = api.BaseRoutes["ApiRoot"].PathPrefix("/keys").Subrouter()
	api.BaseRoutes["Health"] = api.BaseRoutes["ApiRoot"].PathPrefix("/health").Subrouter()
	api.BaseRoutes["Deleted"] = api.BaseRoutes["ApiRoot"].PathPrefix("/deleted").Subrouter()
	api.BaseRoutes["AccessPolicies"] = api.BaseRoutes["ApiRoot"].PathPrefix("/access-policies").Subrouter()
	api.BaseRoutes["ServiceAccounts"] = api.BaseRoutes["ApiRoot"].PathPrefix("/service-accounts").Subrouter()

	api.InitVault(api.BaseRoutes["Vault"])
	api.InitSecrets(api.BaseRoutes["Secrets"])
	api.InitUsers(api.BaseRoutes["Users"])
	api.InitKeys(api.BaseRoutes["Keys"])
	api.InitHealth(api.BaseRoutes["Health"])
	api.InitDeleted(api.BaseRoutes["Deleted"])
	api.InitAccessPolicies(api.BaseRoutes["AccessPolicies"])
	api.InitServiceAccounts(api.BaseRoutes["ServiceAccounts"])
	// OAuth2 token endpoint is public — register directly on rootRouter so the
	// AuthenticationMiddleware chain (on ApiRoot) is bypassed entirely.
	api.BaseRoutes["OAuth2"] = api.rootRouter.PathPrefix(api.basePath).Subrouter()
	api.InitOAuth2(api.BaseRoutes["OAuth2"])

	var apiNames []string
	for s := range api.BaseRoutes {
		if s != "ApiRoot" {
			apiNames = append(apiNames, s)
		}
	}
	api.Logger.WithField("api", strings.Join(apiNames, ",")).Infoln("Initialized api")
	return api
}
