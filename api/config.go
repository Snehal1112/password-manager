package api

import (
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
	if c.App.FrontendConfig == nil {
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"feature_flags":  map[string]bool{},
			"public_api_url": "",
			"sentry_dsn":     "",
		})
		return
	}
	writeJSONStatus(w, http.StatusOK, c.App.FrontendConfig)
}
