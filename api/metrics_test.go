// Package api — unit tests for the Prometheus /metrics route.
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
)

// newMetricsTestAPI constructs a minimal API with the metrics subrouter wired
// for testing, mirroring newHealthTestAPI in health_test.go.
func newMetricsTestAPI(t *testing.T) (*API, *mux.Router) {
	t.Helper()
	router := mux.NewRouter()
	a := app.NewTestApp()

	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     newTestLogger(),
	}
	api.BaseRoutes.Metrics = router.NewRoute().Subrouter()
	router.NotFoundHandler = http.HandlerFunc(Handle404)

	return api, router
}

func TestInitMetrics_Enabled_ServesPrometheusText(t *testing.T) {
	api, router := newMetricsTestAPI(t)
	api.InitMetrics(true)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "# HELP")
}

func TestInitMetrics_Disabled_RouteNotRegistered(t *testing.T) {
	api, router := newMetricsTestAPI(t)
	api.InitMetrics(false)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	assert.True(t, strings.Contains(w.Body.String(), "not_found"))
}
