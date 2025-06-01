package api

import (
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"password-manager/app"
)

// router is a type alias for a map where the keys are strings and the values are pointers to mux.Router.
// This type alias is used to simplify the declaration and usage of maps that store mux.Router instances.
type router = map[string]*mux.Router

// API represents the main API structure for the vault service application.
// It contains references to the application instance, base routes, base path,
// root router, and a logger.
//
// Fields:
// - App: A pointer to the main application instance.
// - BaseRoutes: The base routes for the API.
// - basePath: The base path for the API endpoints.
// - rootRouter: The root router for handling HTTP requests.
// - logger: The logger used for logging API-related information.
type API struct {
	App        *app.App
	BaseRoutes router
	basePath   string
	rootRouter *mux.Router
	logger     logrus.FieldLogger
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

	api.logger.WithField("basePath", api.basePath).Infoln("Api configured with")

	api.BaseRoutes["ApiRoot"] = api.rootRouter.PathPrefix(api.basePath).Subrouter()
	api.BaseRoutes["Vault"] = api.BaseRoutes["ApiRoot"].PathPrefix("/vault").Subrouter()

	api.InitVault(api.BaseRoutes["Vault"])

	var apiNames []string
	for s := range api.BaseRoutes {
		if s != "ApiRoot" {
			apiNames = append(apiNames, s)
		}
	}
	api.logger.WithField("api", strings.Join(apiNames, ",")).Infoln("Initialized api")
	return api
}
