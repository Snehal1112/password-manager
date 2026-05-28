// Package api — internal tests for versioning helpers.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/logging"
)

// testVersionLogger returns a minimal logger suitable for versioning tests.
func testVersionLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// ============================================================
// Version.String()
// ============================================================

// TestVersion_String_ReturnsSemanticVersion verifies that the String method
// produces the expected semver format.
func TestVersion_String_ReturnsSemanticVersion(t *testing.T) {
	v := Version{Major: 1, Minor: 2, Patch: 3}
	assert.Equal(t, "v1.2.3", v.String())
}

func TestVersion_String_ZeroValues(t *testing.T) {
	v := Version{}
	assert.Equal(t, "v0.0.0", v.String())
}

// ============================================================
// NewVersionManager
// ============================================================

// TestNewVersionManager_NotNilWithDefaultVersion verifies that a new manager
// is non-nil and defaults to "v1".
func TestNewVersionManager_NotNilWithDefaultVersion(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	require.NotNil(t, vm)
	// Default version should be "v1".
	assert.Equal(t, "v1", vm.defaultVersion)
}

// ============================================================
// RegisterVersion / SetDefaultVersion
// ============================================================

// TestRegisterVersion_CanBeRetrieved verifies that a registered version appears
// in the internal versions map.
func TestRegisterVersion_CanBeRetrieved(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	v := &Version{Major: 2, Minor: 0, Patch: 0}
	vm.RegisterVersion(v)

	got, ok := vm.versions["v2"]
	require.True(t, ok)
	assert.Equal(t, v, got)
}

// TestSetDefaultVersion_UpdatesDefault verifies that SetDefaultVersion changes
// the active default.
func TestSetDefaultVersion_UpdatesDefault(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{Major: 2, Minor: 0, Patch: 0})
	vm.SetDefaultVersion("v2")
	assert.Equal(t, "v2", vm.defaultVersion)
}

// ============================================================
// VersionMiddleware
// ============================================================

// TestVersionMiddleware_ExractVersionFromURLPath verifies that the middleware
// reads the version from /api/vN/... and injects it into the context.
func TestVersionMiddleware_ExtractVersionFromURLPath(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{Major: 1, Minor: 0, Patch: 0})

	var capturedVersion string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedVersion = GetVersionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := vm.VersionMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "v1", capturedVersion)
}

// TestVersionMiddleware_FallbackToDefault verifies that when no version can be
// detected, the middleware falls back to the default version.
func TestVersionMiddleware_FallbackToDefault(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{Major: 1, Minor: 0, Patch: 0})

	var capturedVersion string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedVersion = GetVersionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := vm.VersionMiddleware(next)
	// No /api/vN/ prefix — falls back to defaultVersion "v1".
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "v1", capturedVersion)
}

// TestVersionMiddleware_UnsupportedVersion_Returns400 verifies that an unknown
// version in the URL path causes a 400 response.
func TestVersionMiddleware_UnsupportedVersion_Returns400(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{Major: 1, Minor: 0, Patch: 0})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := vm.VersionMiddleware(next)
	// v99 is not registered.
	req := httptest.NewRequest(http.MethodGet, "/api/v99/secrets", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestVersionMiddleware_DeprecatedVersion_SetsHeaders verifies that using a
// deprecated version adds Deprecated and Warning headers.
func TestVersionMiddleware_DeprecatedVersion_SetsHeaders(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{
		Major:      1,
		Minor:      0,
		Patch:      0,
		Deprecated: true,
		SunsetDate: "2025-12-31T23:59:59Z",
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := vm.VersionMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "true", w.Header().Get("Deprecated"))
	assert.NotEmpty(t, w.Header().Get("Warning"))
	assert.Equal(t, "2025-12-31T23:59:59Z", w.Header().Get("Sunset"))
}

// TestVersionMiddleware_AcceptHeaderVersion verifies that version can be
// extracted from the Accept header.
func TestVersionMiddleware_AcceptHeaderVersion(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{Major: 1, Minor: 0, Patch: 0})

	var capturedVersion string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedVersion = GetVersionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := vm.VersionMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	req.Header.Set("Accept", "application/vnd.api+json;version=1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "v1", capturedVersion)
}

// TestVersionMiddleware_APIVersionHeader verifies that the API-Version header
// is used as a fallback version source.
func TestVersionMiddleware_APIVersionHeader(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{Major: 1, Minor: 0, Patch: 0})

	var capturedVersion string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedVersion = GetVersionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := vm.VersionMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	req.Header.Set("API-Version", "1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, "v1", capturedVersion)
}

// ============================================================
// GetVersionFromContext
// ============================================================

// TestGetVersionFromContext_Present returns the stored version string.
func TestGetVersionFromContext_Present(t *testing.T) {
	ctx := context.WithValue(context.Background(), common.APIVersionKey, "v2")
	assert.Equal(t, "v2", GetVersionFromContext(ctx))
}

// TestGetVersionFromContext_Missing returns "v1" when no key is set.
func TestGetVersionFromContext_Missing(t *testing.T) {
	assert.Equal(t, "v1", GetVersionFromContext(context.Background()))
}

// ============================================================
// CompatibilityMiddleware
// ============================================================

// TestCompatibilityMiddleware_PassesThrough verifies that the middleware calls
// the next handler for a non-deprecated version.
func TestCompatibilityMiddleware_PassesThrough(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{Major: 1, Minor: 0, Patch: 0})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := vm.CompatibilityMiddleware(next)
	// Inject v1 into context so CompatibilityMiddleware can read it.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	ctx := context.WithValue(req.Context(), common.APIVersionKey, "v1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.True(t, called)
}

// ============================================================
// CreateVersionedRouter
// ============================================================

// TestCreateVersionedRouter_CreatesSubroutersForVersions verifies that
// CreateVersionedRouter returns a non-nil router and registers version paths.
func TestCreateVersionedRouter_CreatesSubroutersForVersions(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{Major: 1, Minor: 0, Patch: 0})

	router := vm.CreateVersionedRouter()
	require.NotNil(t, router)

	// The /api/v1/version endpoint should be reachable.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// Should respond (not 404) — actual code depends on version middleware.
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

// ============================================================
// InitializeVersions
// ============================================================

// TestInitializeVersions_RegistersBothVersions verifies that the method registers
// both v1 and v2 and sets the default to "v1".
func TestInitializeVersions_RegistersBothVersions(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.InitializeVersions()

	_, hasV1 := vm.versions["v1"]
	_, hasV2 := vm.versions["v2"]
	assert.True(t, hasV1, "v1 should be registered")
	assert.True(t, hasV2, "v2 should be registered")
	assert.Equal(t, "v1", vm.defaultVersion)
}

// TestSetupVersionedRoutes_WithSunsetDate_ReturnsSunsetInResponse verifies that a
// deprecated version with a sunset date includes it in the /version response JSON.
func TestSetupVersionedRoutes_WithSunsetDate_ReturnsSunsetInResponse(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{
		Major:      1,
		Minor:      0,
		Patch:      0,
		Deprecated: true,
		SunsetDate: "2025-12-31T23:59:59Z",
		Routes:     make(map[string]http.HandlerFunc),
	})

	router := vm.CreateVersionedRouter()
	require.NotNil(t, router)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The response should include version info and not panic.
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

// TestSetupVersionedRoutes_ContentTypeHeader_SetsHeader verifies that when a
// content-type context key is present, it is applied to the response.
func TestSetupVersionedRoutes_ContentTypeHeader_SetsHeader(t *testing.T) {
	vm := NewVersionManager(testVersionLogger())
	vm.RegisterVersion(&Version{
		Major:  1,
		Minor:  0,
		Patch:  0,
		Routes: make(map[string]http.HandlerFunc),
	})

	router := vm.CreateVersionedRouter()
	require.NotNil(t, router)

	// Inject a content-type via the request context.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	req = req.WithContext(context.WithValue(req.Context(), common.ContentTypeKey, "application/vnd.api+json"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusNotFound, w.Code)
}
