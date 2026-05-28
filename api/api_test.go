// Package api_test — external tests for exported api functions.
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

// TestHandle404_Returns404WithJSON verifies that Handle404 writes a structured
// JSON response with the correct status code and expected fields.
func TestHandle404_Returns404WithJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)

	api.Handle404(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "api.not_found", body["id"])
	assert.Equal(t, "Not found", body["message"])
	assert.Equal(t, float64(http.StatusNotFound), body["status_code"])
}

// TestReturnStatusOK_Returns200WithStatusOK verifies that ReturnStatusOK writes
// a 200 response with {"status":"OK"} body.
func TestReturnStatusOK_Returns200WithStatusOK(t *testing.T) {
	w := httptest.NewRecorder()

	api.ReturnStatusOK(w)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "OK", body["status"])
}

// TestInitForTest_ConfigRoute_Returns200 verifies that InitForTest registers
// the /api/v1/config route and it responds with 200.
func TestInitForTest_ConfigRoute_Returns200(t *testing.T) {
	application := app.NewTestApp()
	router := mux.NewRouter()
	api.InitForTest(application, router)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
