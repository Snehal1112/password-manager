package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"rocketvault/app"
	"rocketvault/internal/logging"
	"rocketvault/internal/middleware"
)

// Routes holds all subrouters for the API — typed for compile-time safety.
type Routes struct {
	ApiRoot         *mux.Router // /api/v1
	Vault           *mux.Router // /api/v1/vault
	Secrets         *mux.Router // /api/v1/secrets
	Secret          *mux.Router // /api/v1/secrets/{secret_id}
	Users           *mux.Router // /api/v1/users
	User            *mux.Router // /api/v1/users/{user_id}
	Keys            *mux.Router // /api/v1/keys
	Key             *mux.Router // /api/v1/keys/{key_id}
	Certificates    *mux.Router // /api/v1/certificates
	Certificate     *mux.Router // /api/v1/certificates/{certificate_id}
	Health          *mux.Router // /api/v1/health
	Deleted         *mux.Router // /api/v1/deleted
	AccessPolicies  *mux.Router // /api/v1/access-policies
	AccessPolicy    *mux.Router // /api/v1/access-policies/{policy_id}
	ServiceAccounts *mux.Router // /api/v1/service-accounts
	ServiceAccount  *mux.Router // /api/v1/service-accounts/{service_account_id}
	OAuth2          *mux.Router // /api/v1/oauth2 (public — no auth middleware)
}

// API is the main API structure for the vault service.
type API struct {
	App        *app.App
	BaseRoutes *Routes
	basePath   string
	rootRouter *mux.Router
	Logger     *logging.Logger
}

// Init initializes the API, wires middleware, and registers all route handlers.
func Init(options ...Options) *API {
	api := &API{
		BaseRoutes: &Routes{},
	}

	for _, option := range options {
		option(api)
	}

	mw := middleware.NewMiddleware(api.App.ServiceContainer)
	api.Logger.WithField("basePath", api.basePath).Infoln("Api configured with")

	r := api.BaseRoutes
	r.ApiRoot = api.rootRouter.PathPrefix(api.basePath).Subrouter()
	r.ApiRoot.Use(
		mw.RateLimitMiddleware,
		mw.AuthenticationMiddleware,
		mw.PolicyMiddleware,
		mw.AuthorizationMiddleware,
	)

	r.Vault = r.ApiRoot.PathPrefix("/vault").Subrouter()

	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	r.Secret = r.Secrets.PathPrefix("/{secret_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Users = r.ApiRoot.PathPrefix("/users").Subrouter()
	r.User = r.Users.PathPrefix("/{user_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	r.Key = r.Keys.PathPrefix("/{key_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	r.Certificate = r.Certificates.PathPrefix("/{certificate_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Health = r.ApiRoot.PathPrefix("/health").Subrouter()
	r.Deleted = r.ApiRoot.PathPrefix("/deleted").Subrouter()

	r.AccessPolicies = r.ApiRoot.PathPrefix("/access-policies").Subrouter()
	r.AccessPolicy = r.AccessPolicies.PathPrefix("/{policy_id:[A-Fa-f0-9-]+}").Subrouter()

	r.ServiceAccounts = r.ApiRoot.PathPrefix("/service-accounts").Subrouter()
	r.ServiceAccount = r.ServiceAccounts.PathPrefix("/{service_account_id:[A-Fa-f0-9-]+}").Subrouter()

	// OAuth2 is public — registered on rootRouter to bypass auth middleware.
	r.OAuth2 = api.rootRouter.PathPrefix(api.basePath).Subrouter()

	api.InitVault()
	api.InitSecrets()
	api.InitUsers()
	api.InitKeys()
	api.InitCertificates()
	api.InitHealth()
	api.InitConfig()
	api.InitDeleted()
	api.InitAccessPolicies()
	api.InitOAuth2()

	// Catch-all 404 for unmatched routes.
	api.rootRouter.NotFoundHandler = http.HandlerFunc(Handle404)

	names := []string{"Vault", "Secrets", "Users", "Keys", "Certificates",
		"Health", "Config", "Deleted", "AccessPolicies", "ServiceAccounts", "OAuth2"}
	api.Logger.WithField("api", strings.Join(names, ",")).Infoln("Initialized api")
	return api
}

// InitForTest wires a minimal API onto router for unit tests (no middleware, no auth).
func InitForTest(application *app.App, router *mux.Router) *API {
	a := &API{
		App:        application,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
	}
	a.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	// Register config handler without auth for testing.
	a.BaseRoutes.ApiRoot.Handle("/config",
		ApiHandler(application, getConfig),
	).Methods("GET")
	return a
}

// Handle404 returns a structured JSON 404 response for unmatched routes.
func Handle404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]any{
		"id":          "api.not_found",
		"message":     "Not found",
		"status_code": http.StatusNotFound,
	})
}

// ReturnStatusOK writes a standard {"status":"OK"} response.
func ReturnStatusOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
}
