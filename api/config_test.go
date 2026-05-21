package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/api"
	"rocketvault/app"
)

func TestGetConfig_ReturnsFeatureFlags(t *testing.T) {
	fc := &app.FrontendConfig{
		FeatureFlags: map[string]bool{"new_ui": true},
		PublicAPIURL: "https://api.example.com",
		SentryDSN:    "https://sentry.example.com/123",
	}
	application := app.NewTestApp(app.WithFrontendConfig(fc))
	router := mux.NewRouter()
	api.InitForTest(application, router)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, true, body["feature_flags"].(map[string]any)["new_ui"])
	assert.Equal(t, "https://api.example.com", body["public_api_url"])
}

func TestGetConfig_NilFrontendConfig_ReturnsEmptyDefaults(t *testing.T) {
	application := app.NewTestApp() // no FrontendConfig set
	router := mux.NewRouter()
	api.InitForTest(application, router)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	// Should not panic and should return empty defaults.
	assert.NotNil(t, body)
}

func TestGetConfig_NeverExposesPasswords(t *testing.T) {
	fc := &app.FrontendConfig{
		PublicAPIURL: "https://api.example.com",
	}
	application := app.NewTestApp(app.WithFrontendConfig(fc))
	router := mux.NewRouter()
	api.InitForTest(application, router)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.NotContains(t, body, "password")
	assert.NotContains(t, body, "secret")
	assert.NotContains(t, body, "jwt")
}
