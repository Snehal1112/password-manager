package api

import (
	"encoding/json"
	"net/http"
)

// InitConfig registers the GET /api/v1/config route as a public endpoint.
func (api *API) InitConfig() {
	api.BaseRoutes.Config.Handle("/config",
		ApiHandler(api.App, getConfig),
	).Methods("GET")
}

// getConfig returns the non-sensitive FrontendConfig to authenticated callers.
// No RocketVault call is made at request time — values are populated at startup.
func getConfig(c *Context, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if c.App.FrontendConfig == nil {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec
			"feature_flags":  map[string]bool{},
			"public_api_url": "",
			"sentry_dsn":     "",
		})
		return
	}
	json.NewEncoder(w).Encode(c.App.FrontendConfig) //nolint:errcheck,gosec
}
