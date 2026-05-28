// Package api — additional health handler unit tests.
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/health"
	"rocketvault/internal/logging"
)

// healthTestLog creates a no-op logger for health tests.
func healthTestLog() *logging.Logger {
	l := logrus.New()
	l.SetOutput(httptest.NewRecorder())
	return logging.WrapLogrus(l)
}

// TestHealthCheck_NilDB_Returns200OrError verifies that HealthCheck handles a
// nil DB gracefully — it may return 200 or 500 but must not panic.
func TestHealthCheck_NilDB_Returns200OrError(t *testing.T) {
	collector := health.NewHealthCollector(nil)
	handler := NewHealthHandler(collector, healthTestLog())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	handler.HealthCheck(w, r)

	// Either succeeds (200) or fails gracefully — the important thing is no panic.
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusInternalServerError)
}

// TestReadinessCheck_NilDB_Returns200OrUnavailable verifies that ReadinessCheck
// handles a nil DB without panicking.
func TestReadinessCheck_NilDB_Returns200OrUnavailable(t *testing.T) {
	collector := health.NewHealthCollector(nil)
	handler := NewHealthHandler(collector, healthTestLog())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil)
	handler.ReadinessCheck(w, r)

	// Either ready or not — must not panic.
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusServiceUnavailable)
}

// TestLivenessCheck_Returns200 verifies that LivenessCheck always returns 200
// with {"status":"alive"} since it only checks if the process is running.
func TestLivenessCheck_Returns200(t *testing.T) {
	collector := health.NewHealthCollector(nil)
	handler := NewHealthHandler(collector, healthTestLog())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/health/live", nil)
	handler.LivenessCheck(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestDatabaseCheck_NilDB_Returns503 verifies that DatabaseCheck with no DB
// reports a non-OK status.
func TestDatabaseCheck_NilDB_Returns503(t *testing.T) {
	collector := health.NewHealthCollector(nil)
	handler := NewHealthHandler(collector, healthTestLog())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/health/database", nil)
	handler.DatabaseCheck(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// TestNewHealthHandler_ReturnsNonNil verifies that NewHealthHandler never returns nil.
func TestNewHealthHandler_ReturnsNonNil(t *testing.T) {
	collector := health.NewHealthCollector(nil)
	handler := NewHealthHandler(collector, healthTestLog())
	assert.NotNil(t, handler)
}
