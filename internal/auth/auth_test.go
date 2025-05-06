// Package auth_test contains unit tests for the auth package.
// It verifies user registration, login, and JWT generation with TOTP MFA.
package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"github.com/snehal1112/password-manager/internal/db"
)

// setupTestDB initializes an in-memory SQLite database for testing.
// It sets up the users table and assigns the connection to db.DB.
//
// Parameters:
//
//	t: The testing context.
//
// Returns:
//
//	A function to clean up the database after the test.
func setupTestDB(t *testing.T) func() {
	t.Helper()

	// Open an in-memory SQLite database.
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	assert.NoError(t, err, "opening in-memory database should succeed")

	// Create users table.
	_, err = sqlDB.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	assert.NoError(t, err, "creating users table should succeed")

	// Assign to global db.DB.
	db.DB = sqlDB

	// Return cleanup function.
	return func() {
		db.DB.Close()
		db.DB = nil
	}
}

// TestRegister tests the Register function to ensure it creates a user with a TOTP secret.
func TestRegister(t *testing.T) {
	// Set up test database.
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")

	// Test registration.
	ctx := context.Background()
	totpURL, err := Register(ctx, "testuser", "password123", RoleSecretsManager)
	assert.NoError(t, err, "registration should succeed")
	assert.NotEmpty(t, totpURL, "TOTP URL should be returned")

	// Verify user in database.
	var username, role string
	var totpSecret sql.NullString
	err = db.DB.QueryRow("SELECT username, totp_secret, role FROM users WHERE username = ?", "testuser").
		Scan(&username, &totpSecret, &role)
	assert.NoError(t, err, "querying user should succeed")
	assert.Equal(t, "testuser", username, "username should match")
	assert.True(t, totpSecret.Valid, "TOTP secret should be set")
	assert.Equal(t, RoleSecretsManager, role, "role should match")
}

// TestLogin tests the Login function to ensure it authenticates users and issues JWTs.
func TestLogin(t *testing.T) {
	// Set up mock database.
	sqlDB, mock, err := sqlmock.New()
	assert.NoError(t, err, "creating mock database should succeed")
	defer sqlDB.Close()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")

	// Mock user query.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	rows := sqlmock.NewRows([]string{"id", "username", "password_hash", "role", "totp_secret"}).
		AddRow(1, "testuser", string(hashedPassword), RoleSecretsManager, "TOTPSECRET")
	mock.ExpectQuery("SELECT id, username, password_hash, role, totp_secret FROM users WHERE username = ?").
		WithArgs("testuser").
		WillReturnRows(rows)

	// Generate TOTP code.
	totpCode, err := GenerateTOTPCode("TOTPSECRET", time.Now())
	assert.NoError(t, err, "generating TOTP code should succeed")

	// Set mock database for auth package.
	db.DB = sqlDB

	// Test login.
	ctx := context.Background()
	token, err := Login(ctx, "testuser", "password123", totpCode)
	assert.NoError(t, err, "login should succeed")
	assert.NotEmpty(t, token, "JWT token should be returned")

	// Verify mock expectations.
	assert.NoError(t, mock.ExpectationsWereMet(), "all mock expectations should be met")
}

// TestLoginInvalidCredentials tests Login with invalid credentials.
func TestLoginInvalidCredentials(t *testing.T) {
	// Set up mock database.
	sqlDB, mock, err := sqlmock.New()
	assert.NoError(t, err, "creating mock database should succeed")
	defer sqlDB.Close()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")

	// Mock user query with no rows.
	mock.ExpectQuery("SELECT id, username, password_hash, role, totp_secret FROM users WHERE username = ?").
		WithArgs("testuser").
		WillReturnError(sql.ErrNoRows)

	// Set mock database for auth package.
	db.DB = sqlDB

	// Test login with invalid username.
	ctx := context.Background()
	_, err = Login(ctx, "testuser", "password123", "123456")
	assert.Error(t, err, "login should fail with invalid credentials")
	assert.Contains(t, err.Error(), "invalid credentials", "error should indicate invalid credentials")

	// Verify mock expectations.
	assert.NoError(t, mock.ExpectationsWereMet(), "all mock expectations should be met")
}

// BenchmarkLogin measures the performance of the Login function.
func BenchmarkLogin(b *testing.B) {
	// Set up mock database.
	sqlDB, mock, err := sqlmock.New()
	assert.NoError(b, err, "creating mock database should succeed")
	defer sqlDB.Close()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")

	// Mock user query.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	rows := sqlmock.NewRows([]string{"id", "username", "password_hash", "role", "totp_secret"}).
		AddRow(1, "testuser", string(hashedPassword), RoleSecretsManager, "TOTPSECRET")
	mock.ExpectQuery("SELECT id, username, password_hash, role, totp_secret FROM users WHERE username = ?").
		WithArgs("testuser").
		WillReturnRows(rows)

	// Generate TOTP code.
	totpCode, err := GenerateTOTPCode("TOTPSECRET", time.Now())
	assert.NoError(b, err, "generating TOTP code should succeed")

	// Set mock database for auth package.
	db.DB = sqlDB

	// Run benchmark.
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		_, _ = Login(ctx, "testuser", "password123", totpCode)
	}

	// Verify mock expectations.
	assert.NoError(b, mock.ExpectationsWereMet(), "all mock expectations should be met")
}
