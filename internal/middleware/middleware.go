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

	"github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"password-manager/common"
	"password-manager/internal/container"
	"password-manager/internal/logging"
	authServices "password-manager/internal/services/auth"
	authzServices "password-manager/internal/services/authorization"
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

// MiddlewareContainer defines the interface for service container dependencies.
// This allows for easier testing with mock implementations.
type MiddlewareContainer interface {
	GetLogger() *logging.Logger
	GetAuthenticationService() authServices.AuthenticationService
	GetRBACService() authzServices.RBACService
}

// Middleware provides HTTP middleware with single responsibilities.
// It delegates authentication and authorization to dedicated services,
// following the Single Responsibility Principle.
type Middleware struct {
	container MiddlewareContainer
	logger    *logging.Logger
}

// NewMiddleware creates a new middleware with service dependencies.
// It uses dependency injection instead of global state access.
//
// Parameters:
//   container: Service container for dependency access.
//
// Returns:
//   A Middleware instance with injected dependencies.
func NewMiddleware(container *container.ServiceContainer) *Middleware {
	return &Middleware{
		container: container,
		logger:    container.GetLogger(),
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

		logFields := logrus.Fields{
			"method":      r.Method,
			"path":        r.URL.Path,
			"client_ip":   r.RemoteAddr,
			"status_code": rw.statusCode,
			"duration_ms": duration.Milliseconds(),
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
	// Create rate limiters with in-memory store
	store := memory.NewStore()

	// Default rate limiter: 60 requests/minute
	defaultRate := limiter.Rate{
		Period: time.Minute,
		Limit:  60,
	}
	defaultLimiter := limiter.New(store, defaultRate)

	// Strict rate limiter for auth endpoints: 5 requests/minute
	authRate := limiter.Rate{
		Period: time.Minute,
		Limit:  5,
	}
	authLimiter := limiter.New(store, authRate)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use client IP as the key for rate limiting
		key := r.RemoteAddr

		// Select appropriate limiter based on endpoint
		selectedLimiter := defaultLimiter
		isAuthEndpoint := false

		// Apply stricter limits to authentication endpoints
		if strings.HasPrefix(r.URL.Path, "/api/auth/login") ||
		   strings.HasPrefix(r.URL.Path, "/api/auth/register") ||
		   strings.HasPrefix(r.URL.Path, "/api/auth/refresh") {
			selectedLimiter = authLimiter
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
		// Skip authentication for public endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/login" {
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
		ctx = context.WithValue(ctx, "username", claims.Username)
		ctx = context.WithValue(ctx, "role", claims.Role)

		m.logger.LogAuditInfo(claims.UserID.String(), "auth", "success", "Authentication successful")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthorizationMiddleware checks if the authenticated user has permission for the endpoint.
// It delegates authorization logic to the RBACService.
func (m *Middleware) AuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user role from context (set by authentication middleware)
		role, ok := r.Context().Value("role").(string)
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

// SecurityHeadersMiddleware adds security headers to responses.
// It focuses solely on HTTP security headers.
func (m *Middleware) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

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
func (m *Middleware) RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := generateRequestID()
		w.Header().Set("X-Request-ID", requestID)

		ctx := context.WithValue(r.Context(), "request_id", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// generateRequestID creates a unique request identifier.
func generateRequestID() string {
	// Simple implementation - in production, use a more robust UUID library
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// Deprecated: AuthMiddleware is deprecated, use AuthenticationMiddleware and AuthorizationMiddleware instead.
func (m *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	logrus.Warn("AuthMiddleware is deprecated, use AuthenticationMiddleware and AuthorizationMiddleware instead")
	return m.AuthenticationMiddleware(m.AuthorizationMiddleware(next))
}
