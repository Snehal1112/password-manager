package middleware

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"password-manager/internal/auth"
	"password-manager/internal/logging"
)

func setupLogger() *logging.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard) // Suppress log output during tests
	return &logging.Logger{Logger: log}
}

func TestLoggingMiddleware(t *testing.T) {
	mw := NewMiddleware(setupLogger())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()

	mw.LoggingMiddleware(handler).ServeHTTP(rr, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "OK", rr.Body.String())
}

func TestRateLimitMiddleware(t *testing.T) {
	mw := NewMiddleware(setupLogger())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()

	// Test single request (within limit)
	mw.RateLimitMiddleware(handler).ServeHTTP(rr, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "OK", rr.Body.String())
}

func TestAuthMiddleware(t *testing.T) {
	mw := NewMiddleware(setupLogger())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	viper.Set("jwt_secret", "test_secret")

	// Create a valid JWT token for testing
	validToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &auth.Claims{
		UserID:   uuid.New(),
		Username: "testuser",
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	validTokenString, err := validToken.SignedString([]byte(viper.GetString("jwt_secret")))
	if err != nil {
		t.Fatalf("Failed to create valid test token: %v", err)
	}

	// Create an expired JWT token for testing
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &auth.Claims{
		UserID:   uuid.New(),
		Username: "testuser",
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	})
	expiredTokenString, err := expiredToken.SignedString([]byte(viper.GetString("jwt_secret")))
	if err != nil {
		t.Fatalf("Failed to create expired test token: %v", err)
	}

	// Create a token for secrets endpoint with insufficient role
	invalidRoleToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &auth.Claims{
		UserID:   uuid.New(),
		Username: "testuser",
		Role:     "user", // Not RoleSecretsManager
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	// Create a token string for the invalid role
	invalidRoleTokenString, err := invalidRoleToken.SignedString([]byte(viper.GetString("jwt_secret")))
	if err != nil {
		t.Fatalf("Failed to create invalid role test token: %v", err)
	}

	tests := []struct {
		name         string
		path         string
		authHeader   string
		expectedCode int
		expectedBody string
	}{
		{
			name:         "Public endpoint",
			path:         "/health",
			authHeader:   "",
			expectedCode: http.StatusOK,
			expectedBody: "OK",
		},
		{
			name:         "Missing Authorization header",
			path:         "/api/test",
			authHeader:   "",
			expectedCode: http.StatusUnauthorized,
			expectedBody: "Unauthorized: missing or invalid token",
		},
		{
			name:         "Invalid JWT",
			path:         "/api/test",
			authHeader:   "Bearer invalid",
			expectedCode: http.StatusUnauthorized,
			expectedBody: "Unauthorized: invalid token",
		},
		{
			name:         "Valid JWT",
			path:         "/api/test",
			authHeader:   "Bearer " + validTokenString,
			expectedCode: http.StatusOK,
			expectedBody: "OK",
		},
		{
			name:         "Expired JWT",
			path:         "/api/test",
			authHeader:   "Bearer " + expiredTokenString,
			expectedCode: http.StatusUnauthorized,
			expectedBody: "Unauthorized: invalid token",
		},
		{
			name:         "Secrets endpoint with insufficient role",
			path:         "/secrets",
			authHeader:   "Bearer " + invalidRoleTokenString,
			expectedCode: http.StatusForbidden,
			expectedBody: "Forbidden: insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()

			mw.AuthMiddleware(handler).ServeHTTP(rr, req)

			// Verify response
			assert.Equal(t, tt.expectedCode, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}
