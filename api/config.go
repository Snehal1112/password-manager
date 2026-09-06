package api

import (
	"net/http"

	"rocketvault/app"
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
		// The zero FrontendConfig encodes byte-identically to the map this
		// replaces, because its fields are already in alphabetical json-tag
		// order. FeatureFlags is set explicitly so it encodes as {}, not null.
		writeJSONStatus(w, http.StatusOK, app.FrontendConfig{FeatureFlags: map[string]bool{}})
		return
	}
	writeJSONStatus(w, http.StatusOK, c.App.FrontendConfig)
}
