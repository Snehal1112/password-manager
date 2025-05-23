// Package middleware provides HTTP middleware for the password manager API.
// It includes logging, rate limiting, and authentication middleware.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"password-manager/common"
	"password-manager/internal/auth"
	"password-manager/internal/logging"
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

// Middleware provides HTTP middleware for the password manager API.
// It includes logging, rate limiting, and authentication middleware.
// The middleware is designed to be used with the net/http package.
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
		userID, _ := r.Context().Value(common.UserIDKey.String()).(string) // May be 0 if unauthenticated.

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

// RateLimitMiddleware limits the number of requests from a single IP address.
// It uses the ulule/limiter library to enforce rate limits.
// The rate limit is set to 10 requests per minute.
// parameters:
//
// - next: the next http.Handler in the chain.
//
// returns:
//
// - http.Handler: the wrapped handler with rate limiting applied.
// The rate limit is enforced using an in-memory store.
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
			m.log.LogAuditError("", "auth", "failed", "Missing or invalid Authorization header", nil)
			http.Error(w, "Unauthorized: missing or invalid token", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &auth.Claims{}

		// Parse the JWT token and validate its claims.
		// Use jwt.ParseWithClaims to parse the token and validate the claims.
		// The claims struct should match the structure of the JWT claims.
		// The function will return an error if the token is invalid or expired.
		// The claims struct should include the user ID and role.
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate the token signing method.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				m.log.LogAuditError("", "auth", "failed", "Unexpected signing method", nil)
				logrus.Warn("Unexpected signing method: ", token.Header["alg"])
				return nil, jwt.ErrSignatureInvalid
			}

			// Retrieve the JWT secret from the configuration.
			var jwtSecret = viper.GetString("jwt_secret")
			if jwtSecret == "" {
				m.log.LogAuditError("", "auth", "failed", "JWT secret is not set", nil)
				logrus.Warn("JWT secret is not set")
				return nil, jwt.ErrInvalidKey
			}

			// Validate the token expiration.
			if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
				m.log.LogAuditError("", "auth", "failed", "Token has expired", nil)
				logrus.Warn("Token has expired")
				return nil, jwt.ErrTokenExpired
			}

			return []byte(viper.GetString("jwt_secret")), nil
		})

		if err != nil {
			m.log.LogAuditError("", "auth", "failed", "Invalid JWT token", nil)
			logrus.Warn("Invalid JWT token: ", err)
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			m.log.LogAuditError("", "auth", "failed", "Token is invalid", nil)
			logrus.Warn("Invalid JWT: token is invalid")
			http.Error(w, "Unauthorized: invalid claims", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*auth.Claims)
		if !ok {
			m.log.LogAuditError("", "auth", "failed", "Invalid JWT claims", nil)
			logrus.Warn("Invalid JWT claims")
			http.Error(w, "Unauthorized: invalid claims", http.StatusUnauthorized)
			return
		}

		// Enforce RBAC based on endpoint and role.
		if strings.HasPrefix(r.URL.Path, "/secrets") && claims.Role != auth.RoleSecretsManager {
			m.log.LogAuditError(claims.UserID.String(), "auth", "failed", "Insufficient permissions for secrets endpoint", nil)
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		// Add user_id to context.
		type contextKey string
		const userIDKey contextKey = "user_id"
		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		m.log.LogAuditInfo(claims.UserID.String(), "auth", "success", "Authenticated successfully")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
