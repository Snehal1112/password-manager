// Package middleware provides HTTP middleware with proper separation of concerns.
// This refactored version focuses only on HTTP concerns while delegating
// authentication and authorization logic to dedicated services.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"rocketvault/common"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
)

// ResponseWriter is a custom http.ResponseWriter that captures the status code.
// It embeds the original ResponseWriter and adds a statusCode field.
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
	log        *logging.Logger
}

// WriteHeader captures the response body and status code.
// It logs the response body and status code.
func (rw *ResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Container defines the interface for service container dependencies.
// This allows for easier testing with mock implementations.
type Container interface {
	GetLogger() *logging.Logger
	GetAuthenticationService() authServices.AuthenticationService
	GetRBACService() authzServices.RBACService
	GetAccessPolicyService() authzServices.AccessPolicyService
}

// Middleware provides HTTP middleware with single responsibilities.
// It delegates authentication and authorization to dedicated services,
// following the Single Responsibility Principle.
type Middleware struct {
	container     Container
	logger        *logging.Logger
	defaultLimiter *limiter.Limiter
	authLimiter    *limiter.Limiter
}

// NewMiddleware creates a new middleware with service dependencies.
// It uses dependency injection instead of global state access.
// Rate limiter stores are created once here and shared across requests.
//
// Parameters:
//
//	container: Service container for dependency access.
//
// Returns:
//
//	A Middleware instance with injected dependencies.
func NewMiddleware(container Container) *Middleware {
	store := memory.NewStore()

	defaultLimiter := limiter.New(store, limiter.Rate{
		Period: time.Minute,
		Limit:  60,
	})
	authLimiter := limiter.New(store, limiter.Rate{
		Period: time.Minute,
		Limit:  5,
	})

	return &Middleware{
		container:      container,
		logger:         container.GetLogger(),
		defaultLimiter: defaultLimiter,
		authLimiter:    authLimiter,
	}
}

// LoggingMiddleware logs HTTP request and response details.
// It focuses only on logging concerns without mixing other responsibilities.
func (m *Middleware) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		userID, _ := r.Context().Value(common.UserIDKey).(string)

		// Create response writer to capture status code
		rw := &ResponseWriter{ResponseWriter: w, statusCode: http.StatusOK, log: m.logger}
		next.ServeHTTP(rw, r)

		// Log request details
		duration := time.Since(start)
		operation := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		status := "success"
		if rw.statusCode >= 400 {
			status = "failed"
		}

		requestID, _ := r.Context().Value(requestIDKey).(string)
		logFields := logrus.Fields{
			"method":      r.Method,
			"path":        r.URL.Path,
			"client_ip":   r.RemoteAddr,
			"status_code": rw.statusCode,
			"duration_ms": duration.Milliseconds(),
			"request_id":  requestID,
		}

		logEntry := m.logger.WithAuditFields(userID, operation, status).WithFields(logFields)
		if status == "success" {
			logEntry.Info("HTTP request processed")
		} else {
			logEntry.Error("HTTP request failed")
		}
	})
}

// RateLimitMiddleware applies rate limiting to HTTP requests.
// It focuses solely on rate limiting without mixing other concerns.
// Default: 60 requests/minute, Auth endpoints: 5 requests/minute.
func (m *Middleware) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use client IP as the key for rate limiting
		key := r.RemoteAddr

		// Select appropriate limiter based on endpoint
		selectedLimiter := m.defaultLimiter
		isAuthEndpoint := false

		// Apply stricter limits to authentication endpoints
		if strings.HasPrefix(r.URL.Path, "/api/auth/login") ||
			strings.HasPrefix(r.URL.Path, "/api/auth/register") ||
			strings.HasPrefix(r.URL.Path, "/api/auth/refresh") {
			selectedLimiter = m.authLimiter
			isAuthEndpoint = true
		}

		context, err := selectedLimiter.Get(r.Context(), key)
		if err != nil {
			m.logger.LogAuditError("", "rate_limit", "failed", "Rate limiter error", err)
			logrus.WithError(err).Error("Rate limiter error")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", context.Limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", context.Remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", context.Reset))

		if context.Reached {
			endpoint := "default"
			if isAuthEndpoint {
				endpoint = "auth"
			}

			m.logger.LogAuditError("", "rate_limit", "failed",
				fmt.Sprintf("Rate limit exceeded for %s endpoint", endpoint), nil)
			logrus.WithFields(logrus.Fields{
				"client_ip": key,
				"endpoint":  r.URL.Path,
				"limit":     context.Limit,
			}).Warn("Rate limit exceeded")

			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AuthenticationMiddleware handles JWT token validation and user context.
// It delegates authentication logic to the AuthenticationService.
func (m *Middleware) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for public endpoints (health checks and auth endpoints)
		if strings.HasSuffix(r.URL.Path, "/health") ||
			strings.HasSuffix(r.URL.Path, "/health/ready") ||
			strings.HasSuffix(r.URL.Path, "/health/live") ||
			strings.HasSuffix(r.URL.Path, "/login") ||
			strings.HasSuffix(r.URL.Path, "/register") ||
			strings.HasSuffix(r.URL.Path, "/refresh") ||
			strings.Contains(r.URL.Path, "/auth/login") ||
			strings.Contains(r.URL.Path, "/auth/register") ||
			strings.Contains(r.URL.Path, "/auth/refresh") {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.logger.LogAuditError("", "auth", "failed", "Missing Authorization header", nil)
			http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
			return
		}

		// Validate Bearer token format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.logger.LogAuditError("", "auth", "failed", "Invalid token format", nil)
			http.Error(w, "Unauthorized: invalid token format", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token using authentication service
		claims, err := m.container.GetAuthenticationService().ValidateSession(r.Context(), tokenString)
		if err != nil {
			m.logger.LogAuditError("", "auth", "failed", "Token validation failed", err)
			logrus.WithError(err).Warn("Token validation failed")
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		// Add user information to request context
		ctx := context.WithValue(r.Context(), common.UserIDKey, claims.UserID.String())
		ctx = context.WithValue(ctx, common.UsernameKey, claims.Username)
		ctx = context.WithValue(ctx, common.RoleKey, claims.Role)

		m.logger.LogAuditInfo(claims.UserID.String(), "auth", "success", "Authentication successful")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthorizationMiddleware checks if the authenticated user has permission for the endpoint.
// It delegates authorization logic to the RBACService.
func (m *Middleware) AuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user role from context (set by authentication middleware)
		role, ok := r.Context().Value(common.RoleKey).(string)
		if !ok {
			m.logger.LogAuditError("", "authz", "failed", "Missing role in context", nil)
			http.Error(w, "Forbidden: missing role", http.StatusForbidden)
			return
		}

		// Check endpoint access using RBAC service
		if err := m.container.GetRBACService().ValidateEndpointAccess(role, r.Method, r.URL.Path); err != nil {
			m.logger.LogAuditError("", "authz", "failed", "Access denied", err)
			logrus.WithFields(logrus.Fields{
				"role":   role,
				"method": r.Method,
				"path":   r.URL.Path,
			}).Warn("Authorization failed")
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		m.logger.LogAuditInfo("", "authz", "success", "Authorization successful")
		next.ServeHTTP(w, r)
	})
}

// resolvePolicy maps an HTTP request's method and URL path to the
// PolicyResourceType and PolicyOperation used for access-policy evaluation.
// Returns ("", "") when the route does not correspond to a managed resource.
func resolvePolicy(method, path string) (domain.PolicyResourceType, domain.PolicyOperation) {
	// Determine resource type from path segments.
	var resourceType domain.PolicyResourceType
	switch {
	case strings.Contains(path, "/secrets"):
		resourceType = domain.PolicyResourceSecrets
	case strings.Contains(path, "/keys"):
		resourceType = domain.PolicyResourceKeys
	case strings.Contains(path, "/certificates"):
		resourceType = domain.PolicyResourceCertificates
	default:
		return "", ""
	}

	// Map HTTP method (and special sub-paths) to an operation.
	var op domain.PolicyOperation
	switch {
	case strings.HasSuffix(path, "/purge") && method == http.MethodDelete:
		op = domain.OpPurge
	case strings.HasSuffix(path, "/restore") && method == http.MethodPost:
		op = domain.OpRecover
	case strings.HasSuffix(path, "/rotate") && method == http.MethodPost:
		op = domain.OpRotate
	case strings.HasSuffix(path, "/import") && method == http.MethodPost:
		op = domain.OpImport
	case strings.HasSuffix(path, "/renew") && method == http.MethodPost:
		op = domain.OpRenew
	case method == http.MethodGet:
		op = domain.OpGet
	case method == http.MethodPost:
		op = domain.OpCreate
	case method == http.MethodPut:
		op = domain.OpSet
	case method == http.MethodDelete:
		op = domain.OpDelete
	default:
		return resourceType, ""
	}

	return resourceType, op
}

// PolicyMiddleware enforces per-operation access policies for authenticated users.
// It must run after AuthenticationMiddleware so that common.UserIDKey is set.
// The middleware uses AccessFallback-by-default semantics: if no explicit policy
// exists the request continues to the next handler unchanged. Only AccessDenied
// halts the request.
func (m *Middleware) PolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Resolve route — skip policy check for unmanaged routes (health, etc.)
		resourceType, op := resolvePolicy(r.Method, r.URL.Path)
		if resourceType == "" || op == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract caller identity set by AuthenticationMiddleware.
		userIDStr, ok := r.Context().Value(common.UserIDKey).(string)
		if !ok || userIDStr == "" {
			m.logger.LogAuditError("", "policy", "failed", "Missing user ID in context for policy check", nil)
			http.Error(w, "Forbidden: missing identity", http.StatusForbidden)
			return
		}

		principalID, err := uuid.Parse(userIDStr)
		if err != nil {
			m.logger.LogAuditError(userIDStr, "policy", "failed", "Invalid user ID format", err)
			http.Error(w, "Forbidden: invalid identity", http.StatusForbidden)
			return
		}

		// Evaluate access policy.
		policySvc := m.container.GetAccessPolicyService()
		decision, err := policySvc.CheckAccess(r.Context(), principalID, resourceType, op)
		if err != nil {
			// Log but don't block on evaluation errors — fail open via fallback.
			logrus.WithError(err).Warn("PolicyMiddleware: access policy check error, allowing request")
			next.ServeHTTP(w, r)
			return
		}

		// Use the route template for richer audit logs when available.
		routeTemplate := r.URL.Path
		if route := mux.CurrentRoute(r); route != nil {
			if tmpl, err2 := route.GetPathTemplate(); err2 == nil {
				routeTemplate = tmpl
			}
		}

		switch decision {
		case authzServices.AccessDenied:
			m.logger.LogAuditError(userIDStr, "policy", "denied",
				fmt.Sprintf("Access denied: %s %s (resource=%s op=%s)", r.Method, routeTemplate, resourceType, op), nil)
			http.Error(w, "Forbidden: access policy denied", http.StatusForbidden)
			return
		case authzServices.AccessAllowed:
			m.logger.LogAuditInfo(userIDStr, "policy", "allowed",
				fmt.Sprintf("Access allowed: %s %s (resource=%s op=%s)", r.Method, routeTemplate, resourceType, op))
		default: // AccessFallback — no explicit policy; continue
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeadersMiddleware adds security headers to responses.
// It focuses solely on HTTP security headers.
func (m *Middleware) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Only send HSTS when the connection is TLS.
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware handles Cross-Origin Resource Sharing headers.
// It focuses solely on CORS concerns.
func (m *Middleware) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequestIDMiddleware adds a unique request ID to each request.
// It focuses solely on request tracking.
// contextKey is a custom type for context keys in this package.
type contextKey string

const (
	requestIDKey contextKey = "request_id"
)

// RequestIDMiddleware adds a unique request ID to each HTTP request for tracking purposes.
func (m *Middleware) RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := generateRequestID()
		w.Header().Set("X-Request-ID", requestID)

		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// generateRequestID creates a unique request identifier.
func generateRequestID() string {
	// Simple implementation - in production, use a more robust UUID library
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// RequestBodySizeLimitMiddleware rejects requests that exceed the allowed body size.
// Default endpoints are limited to 10 MB; import endpoints allow up to 50 MB.
func (m *Middleware) RequestBodySizeLimitMiddleware(next http.Handler) http.Handler {
	const (
		defaultLimit int64 = 10 << 20 // 10 MB.
		importLimit  int64 = 50 << 20 // 50 MB for import operations.
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := defaultLimit
		if strings.HasSuffix(r.URL.Path, "/import") {
			limit = importLimit
		}

		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware is deprecated. Use AuthenticationMiddleware and AuthorizationMiddleware instead.
//
// Deprecated: AuthMiddleware is deprecated, use AuthenticationMiddleware and AuthorizationMiddleware instead.
func (m *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	logrus.Warn("AuthMiddleware is deprecated, use AuthenticationMiddleware and AuthorizationMiddleware instead")
	return m.AuthenticationMiddleware(m.AuthorizationMiddleware(next))
}
