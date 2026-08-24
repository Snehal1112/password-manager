// Package api — proves SecurityHeadersMiddleware is actually attached to the
// real production router, not just implemented and never used.
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
)

// assertSecurityHeaders fails the test if any of the headers
// SecurityHeadersMiddleware sets are missing.
func assertSecurityHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
}

// TestSecurityHeadersMiddleware_WiredOnPublicRoute walks the REAL router
// built by api.Init — the same construction production uses, with the full
// middleware chain — and hits the public /config route, asserting the
// security headers are present. A future accidental removal of
// SecurityHeadersMiddleware's ".Use" registration would fail this, not just
// pass silently the way it did before that middleware was wired in.
func TestSecurityHeadersMiddleware_WiredOnPublicRoute(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}

	router := mux.NewRouter()
	built := Init(
		WithAPP(a),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(userTestLog()),
	)
	require.NotNil(t, built)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assertSecurityHeaders(t, w)
}

// TestSecurityHeadersMiddleware_WiredOnRejectedRequest hits a real vault
// data-plane route with no Authorization header, which AuthenticationMiddleware
// rejects with 401 before touching the container (so routerWalkContainer's
// "panic if called" stub methods are never reached). SecurityHeadersMiddleware
// runs before AuthenticationMiddleware in the chain, so the rejected response
// should still carry the security headers.
func TestSecurityHeadersMiddleware_WiredOnRejectedRequest(t *testing.T) {
	container := &routerWalkContainer{policyContainer: &policyContainer{}, logger: userTestLog()}
	a := &app.App{ServiceContainer: container, Logger: userTestLog()}

	router := mux.NewRouter()
	built := Init(
		WithAPP(a),
		WithRouter(router),
		WithBasePath("/api/v1"),
		WithLogger(userTestLog()),
	)
	require.NotNil(t, built)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil) // no auth token
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	assertSecurityHeaders(t, w)
}
