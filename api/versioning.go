package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/logging"
)

// Version represents an API version configuration.
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Deprecated bool
	SunsetDate string // RFC3339 format
	Routes     map[string]http.HandlerFunc
}

// String returns the version string in semver format.
func (v Version) String() string {
	return "v" + strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// VersionManager manages API versioning and routing.
type VersionManager struct {
	versions         map[string]*Version
	defaultVersion   string
	logger           *logging.Logger
	deprecatedLogger logrus.FieldLogger
}

// NewVersionManager creates a new version manager.
func NewVersionManager(logger *logging.Logger) *VersionManager {
	return &VersionManager{
		versions:         make(map[string]*Version),
		defaultVersion:   "v1",
		logger:           logger,
		deprecatedLogger: logger.WithField("component", "api_deprecation"),
	}
}

// RegisterVersion registers a new API version.
func (vm *VersionManager) RegisterVersion(version *Version) {
	versionKey := "v" + strconv.Itoa(version.Major)
	vm.versions[versionKey] = version

	vm.logger.WithFields(logrus.Fields{
		"version":    version.String(),
		"deprecated": version.Deprecated,
	}).Info("API version registered")
}

// SetDefaultVersion sets the default API version.
func (vm *VersionManager) SetDefaultVersion(version string) {
	vm.defaultVersion = version
	vm.logger.WithField("default_version", version).Info("Default API version set")
}

// VersionMiddleware extracts version information from the request.
func (vm *VersionManager) VersionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var version string

		// Try to get version from URL path first (e.g., /api/v1/secrets)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
			if len(pathParts) > 0 && strings.HasPrefix(pathParts[0], "v") {
				version = pathParts[0]
			}
		}

		// Try to get version from Accept header (e.g., application/vnd.api+json;version=1)
		if version == "" {
			acceptHeader := r.Header.Get("Accept")
			if strings.Contains(acceptHeader, "version=") {
				parts := strings.Split(acceptHeader, "version=")
				if len(parts) > 1 {
					versionPart := strings.Split(parts[1], ",")[0]
					versionPart = strings.Split(versionPart, ";")[0]
					if v, err := strconv.Atoi(strings.TrimSpace(versionPart)); err == nil {
						version = "v" + strconv.Itoa(v)
					}
				}
			}
		}

		// Try to get version from custom header
		if version == "" {
			version = r.Header.Get("API-Version")
			if version != "" && !strings.HasPrefix(version, "v") {
				version = "v" + version
			}
		}

		// Fall back to default version
		if version == "" {
			version = vm.defaultVersion
		}

		// Validate version exists
		if _, exists := vm.versions[version]; !exists {
			http.Error(w, "Unsupported API version: "+version, http.StatusBadRequest)
			return
		}

		// Check if version is deprecated
		if apiVersion := vm.versions[version]; apiVersion.Deprecated {
			w.Header().Set("Deprecated", "true")
			if apiVersion.SunsetDate != "" {
				w.Header().Set("Sunset", apiVersion.SunsetDate)
			}
			w.Header().Set("Warning", "299 - \"Deprecated API version "+version+"\"")

			vm.deprecatedLogger.WithFields(logrus.Fields{
				"version":     version,
				"path":        r.URL.Path,
				"user_agent":  r.Header.Get("User-Agent"),
				"client_ip":   r.RemoteAddr,
				"sunset_date": apiVersion.SunsetDate,
			}).Warn("Deprecated API version used")
		}

		// Add version to response headers
		w.Header().Set("API-Version", version)

		// Add version to context
		ctx := context.WithValue(r.Context(), common.APIVersionKey, version)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetVersionFromContext extracts the API version from request context.
func GetVersionFromContext(ctx context.Context) string {
	if version, ok := ctx.Value(common.APIVersionKey).(string); ok {
		return version
	}
	return "v1" // Default fallback
}

// CompatibilityMiddleware handles backwards compatibility between versions.
func (vm *VersionManager) CompatibilityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := GetVersionFromContext(r.Context())

		// Handle version-specific request transformations
		switch version {
		case "v1":
			// Legacy v1 compatibility transformations
			vm.handleV1Compatibility(w, r)
		case "v2":
			// v2 specific handling
			vm.handleV2Compatibility(w, r)
		}

		next.ServeHTTP(w, r)
	})
}

// handleV1Compatibility handles v1 specific compatibility issues.
func (vm *VersionManager) handleV1Compatibility(_ http.ResponseWriter, r *http.Request) {
	// Transform legacy field names, date formats, etc.
	// Example: Convert old field names to new ones
	if r.Header.Get("Content-Type") == "application/json" {
		// Could implement request body transformation here
		vm.logger.Debug("Applying v1 compatibility transformations")
	}
}

// handleV2Compatibility handles v2 specific compatibility issues.
func (vm *VersionManager) handleV2Compatibility(_ http.ResponseWriter, _ *http.Request) {
	// v2 specific transformations
	vm.logger.Debug("Applying v2 compatibility transformations")
}

// CreateVersionedRouter creates a router with versioning support.
func (vm *VersionManager) CreateVersionedRouter() *mux.Router {
	router := mux.NewRouter()

	// Apply version middleware
	router.Use(vm.VersionMiddleware)
	router.Use(vm.CompatibilityMiddleware)

	// Create version-specific subrouters
	for versionKey := range vm.versions {
		versionRouter := router.PathPrefix("/api/" + versionKey).Subrouter()
		vm.logger.WithField("version", versionKey).Info("Created version-specific router")

		// Add version-specific routes here
		// This would be called by the main API initialization
		vm.setupVersionedRoutes(versionRouter, versionKey)
	}

	return router
}

// setupVersionedRoutes sets up routes for a specific version.
func (vm *VersionManager) setupVersionedRoutes(router *mux.Router, version string) {
	// This method would be implemented to set up version-specific routes
	// For now, we'll add a basic version info endpoint
	router.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		apiVersion := vm.versions[version]
		response := map[string]any{
			"version":    apiVersion.String(),
			"deprecated": apiVersion.Deprecated,
		}
		if apiVersion.SunsetDate != "" {
			response["sunset_date"] = apiVersion.SunsetDate
		}

		// Use the response encoder from context if available
		if contentType := r.Context().Value(common.ContentTypeKey); contentType != nil {
			// Would use the enhanced middleware's response encoder here
			w.Header().Set("Content-Type", contentType.(string))
		}

		w.WriteHeader(http.StatusOK)
		// Simple JSON response for now
		w.Write([]byte(`{"version": "` + apiVersion.String() + `", "deprecated": ` + strconv.FormatBool(apiVersion.Deprecated) + `}`))
	}).Methods("GET")
}

// InitializeVersions sets up the initial API versions.
func (vm *VersionManager) InitializeVersions() {
	// Register v1 (legacy, deprecated)
	v1 := &Version{
		Major:      1,
		Minor:      0,
		Patch:      0,
		Deprecated: true,
		SunsetDate: "2025-12-31T23:59:59Z",
		Routes:     make(map[string]http.HandlerFunc),
	}
	vm.RegisterVersion(v1)

	// Register v2 (current stable)
	v2 := &Version{
		Major:      2,
		Minor:      0,
		Patch:      0,
		Deprecated: false,
		Routes:     make(map[string]http.HandlerFunc),
	}
	vm.RegisterVersion(v2)

	// Set v1 as default for backwards compatibility
	vm.SetDefaultVersion("v1")
}
