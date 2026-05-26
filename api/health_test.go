/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Package api — unit tests for health handler routing.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/logging"
)

// newTestLogger returns a minimal Logger backed by a discarding logrus instance.
func newTestLogger() *logging.Logger {
	l := logrus.New()
	l.SetOutput(httptest.NewRecorder()) // discard log output in tests
	return logging.WrapLogrus(l)
}

// newHealthTestAPI constructs a minimal API with health subrouter wired for testing.
// No auth middleware is applied — health routes are registered directly.
func newHealthTestAPI(t *testing.T) (*API, *mux.Router) {
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
	api.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	api.BaseRoutes.Health = api.BaseRoutes.ApiRoot.PathPrefix("/health").Subrouter()

	api.InitHealth()
	return api, router
}

func TestInitHealth_LiveEndpoint(t *testing.T) {
	_, router := newHealthTestAPI(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/live", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "alive", body["status"])
}

func TestInitHealth_ReadyEndpoint(t *testing.T) {
	_, router := newHealthTestAPI(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "ready", body["status"])
}

func TestInitHealth_DatabaseEndpoint_NilDB(t *testing.T) {
	_, router := newHealthTestAPI(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/database", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "critical", body["status"])
}
