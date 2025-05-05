// Package api contains unit tests for the RESTful API endpoints.
// It verifies authentication, secrets management, and health check functionality.
package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/logging"
	"github.com/snehal1112/password-manager/internal/secrets"
)

// setupTestDB initializes an in-memory SQLite database for testing.
func setupTestDB(t *testing.T) func() {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	assert.NoError(t, err, "opening in-memory database should succeed")

	_, err = sqlDB.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL,
			totp_secret TEXT
		);
		CREATE TABLE secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE secret_tags (
			secret_id INTEGER NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (secret_id, tag),
			FOREIGN KEY (secret_id) REFERENCES secrets(id)
		)
	`)
	assert.NoError(t, err, "creating tables should succeed")

	db.DB = sqlDB
	return func() {
		db.DB.Close()
		db.DB = nil
	}
}

// generateMasterKey generates a valid 32-byte base64-encoded master key for testing.
//
// Parameters:
//
//	tb: The testing context (supports *testing.T or *testing.B).
//
// Returns:
//
//	A base64-encoded 32-byte key.
func generateMasterKey(tb testing.TB) string {
	tb.Helper()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		tb.Fatalf("generating random key failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// TestCreateSecretHandler tests the create secret endpoint with middleware.
func TestCreateSecretHandler(t *testing.T) {
	// Set up test database.
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	log := logging.InitLogger()
	defer os.Remove("test.log")

	viper.Set("master_key", generateMasterKey(t))

	// Insert test user.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	totpSecret := "TOTPSECRET"
	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
		1, "testuser", string(hashedPassword), auth.RoleSecretsManager, totpSecret,
	)
	assert.NoError(t, err, "inserting user should succeed")

	// Generate valid TOTP code and token.
	totpCode, err := auth.GenerateTOTPCode(totpSecret, time.Now())
	assert.NoError(t, err, "generating TOTP code should succeed")
	token, err := auth.Login(context.Background(), "testuser", "password123", totpCode)
	assert.NoError(t, err, "login should succeed")

	// Create request.
	reqBody := `{"name":"test-secret","value":"my-secret-value","tags":["prod"]}`
	req := httptest.NewRequest("POST", "/secrets", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	// Create server with middleware.
	server, err := NewServer(log)
	assert.NoError(t, err, "creating server should succeed")
	server.router.ServeHTTP(rr, req)

	// Verify response.
	assert.Equal(t, http.StatusCreated, rr.Code, "should return 201 Created")
	var secret secrets.Secret
	err = json.NewDecoder(rr.Body).Decode(&secret)
	assert.NoError(t, err, "decoding response should succeed")
	assert.Equal(t, "test-secret", secret.Name, "secret name should match")
	assert.Equal(t, 1, secret.Version, "secret version should match")

	// Verify log file.
	logContent, err := os.ReadFile("test.log")
	assert.NoError(t, err, "log file should exist")
	assert.Contains(t, string(logContent), `"operation":"POST /secrets"`, "log should contain create_secret operation")
	assert.Contains(t, string(logContent), `"status":"success"`, "log should contain success status")
}

// TestLoginHandler tests the login endpoint without middleware.
func TestLoginHandler(t *testing.T) {
	// Set up test database.
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	Logger := logging.InitLogger()
	defer os.Remove("test.log")

	// Insert test user.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	totpSecret := "TOTPSECRET"
	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
		1, "testuser", string(hashedPassword), auth.RoleSecretsManager, totpSecret,
	)
	assert.NoError(t, err, "inserting user should succeed")

	// Generate valid TOTP code.
	totpCode, err := auth.GenerateTOTPCode(totpSecret, time.Now())
	assert.NoError(t, err, "generating TOTP code should succeed")

	// Create request.
	reqBody := fmt.Sprintf(`{"username":"testuser","password":"password123","totp_code":"%s"}`, totpCode)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	// Create server and call login handler.
	server, err := NewServer(Logger)
	assert.NoError(t, err, "creating server should succeed")
	server.router.ServeHTTP(rr, req)

	// Verify response.
	assert.Equal(t, http.StatusOK, rr.Code, "should return 200 OK")
	var response map[string]string
	err = json.NewDecoder(rr.Body).Decode(&response)
	assert.NoError(t, err, "decoding response should succeed")
	assert.NotEmpty(t, response["token"], "should return a token")

	// Verify log file.
	logContent, err := os.ReadFile("test.log")
	assert.NoError(t, err, "log file should exist")
	assert.Contains(t, string(logContent), `"operation":"login"`, "log should contain login operation")
	assert.Contains(t, string(logContent), `"status":"success"`, "log should contain success status")
}
