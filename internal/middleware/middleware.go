// Package middleware provides HTTP middleware for the password manager API.
// It includes logging, rate limiting, and authentication middleware.
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

	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/logging"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
	log        *logging.Logger
}

func (rw *ResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

type Middleware struct {
	log *logging.Logger
}

// NewMiddleware initializes a new Middleware instance with the provided logger.
// It sets up the middleware for logging, rate limiting, and authentication.
// The logger is used for structured logging with audit fields.
func NewMiddleware(logger *logging.Logger) *Middleware {
	return &Middleware{
		log: logger,
	}
}

// LoggingMiddleware logs request and response details with audit fields.
func (m *Middleware) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		userID, _ := r.Context().Value("user_id").(int) // May be 0 if unauthenticated.

		// Create a response writer to capture status code.
		rw := &ResponseWriter{ResponseWriter: w, statusCode: http.StatusOK, log: m.log}
		next.ServeHTTP(rw, r)

		// Log request details.
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

		logEntry := m.log.WithAuditFields(userID, operation, status).WithFields(logFields)
		if status == "success" {
			logEntry.Info("API request processed")
		} else {
			logEntry.Error("API request failed")
		}
	})
}

func (m *Middleware) RateLimitMiddleware(next http.Handler) http.Handler {
	store := memory.NewStore()
	rate, _ := limiter.NewRateFromFormatted("10-M") // 10 requests per minute
	limiterInstance := limiter.New(store, rate)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if _, err := limiterInstance.Get(ctx, r.RemoteAddr); err != nil {
			logrus.Warn("Rate limit exceeded for ", r.RemoteAddr)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware authenticates requests using JWT and enforces RBAC.
func (m *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for public endpoints.
		if r.URL.Path == "/health" || r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract JWT from Authorization header.
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.log.LogAuditError(0, "auth", "failed", "Missing or invalid Authorization header", nil)
			http.Error(w, "Unauthorized: missing or invalid token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse JWT.
		claims, err := auth.ParseJWT(token)
		if err != nil {
			m.log.LogAuditError(0, "auth", "failed", "Invalid JWT", err)
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		// Enforce RBAC based on endpoint and role.
		if strings.HasPrefix(r.URL.Path, "/secrets") && claims.Role != auth.RoleSecretsManager {
			m.log.LogAuditError(claims.UserID, "auth", "failed", "Insufficient permissions for secrets endpoint", nil)
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		// Add user_id to context.
		type contextKey string
		const userIDKey contextKey = "user_id"
		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		m.log.LogAuditInfo(claims.UserID, "auth", "success", "Authenticated successfully", nil)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
