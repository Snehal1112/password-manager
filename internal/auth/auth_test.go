// Package auth_test contains unit tests for the auth package.
// It verifies user registration, login, and JWT generation with TOTP MFA.
package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"password-manager/internal/db"
	"password-manager/internal/logging"
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
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
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

// generateMasterKey generates a valid 32-byte base64-encoded master key for testing.
//
// Parameters:
// - tb: The testing context (supports *testing.T or *testing.B).
// Returns: A base64-encoded 32-byte key.
func generateMasterKey(tb testing.TB) string {
	tb.Helper()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		tb.Fatalf("generating random key failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// TestRegister tests the Register function to ensure it creates a user with a TOTP secret.
func TestRegister(t *testing.T) {
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	log := logging.InitLogger()
	defer os.Remove("test.log")

	// Set up test database.
	cleanup := setupTestDB(t)
	defer cleanup()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")

	// Test registration.
	ctx := context.Background()
	authRepo := NewUserRepository(db.DB, log)
	user := User{
		Username:     "testuser",
		PasswordHash: "password123",
		Role:         RoleSecretsManager,
	}
	err := authRepo.Create(ctx, &user)
	log.Println(user)

	assert.NoError(t, err, "registration should succeed")
	assert.NotEmpty(t, &user.TOTPSecret, "TOTP URL should be returned")

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

	id := uuid.New()
	// Mock user query.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	rows := sqlmock.NewRows([]string{"id", "username", "password_hash", "role", "totp_secret"}).
		AddRow(id.String(), "testuser", string(hashedPassword), RoleSecretsManager, "TOTPSECRET")

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
	authRepo := NewUserRepository(db.DB, nil)
	token, err := authRepo.Login(ctx, "testuser", "password123", totpCode)
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
	authRepo := NewUserRepository(db.DB, nil)
	_, err = authRepo.Login(ctx, "testuser", "password123", "123456")
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

	// Set mock database for auth package.
	db.DB = sqlDB

	log := logrus.New()
	log.SetLevel(logrus.InfoLevel)
	b.ResetTimer()
	authRepo := NewUserRepository(db.DB, nil)
	// Run benchmark
	for i := 0; i < b.N; i++ {
		// Mock user query.
		userID := uuid.New().String()
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
		rows := sqlmock.NewRows([]string{"id", "username", "password_hash", "role", "totp_secret"}).
			AddRow(userID, "testuser", string(hashedPassword), RoleSecretsManager, "TOTPSECRET")

		// Set up the query expectation to handle multiple calls
		query := "SELECT id, username, password_hash, role, totp_secret FROM users WHERE username = \\?"
		mock.ExpectQuery(query).
			WithArgs("testuser").
			WillReturnRows(rows).
			RowsWillBeClosed()

		// Generate TOTP code.
		totpCode, err := GenerateTOTPCode("TOTPSECRET", time.Now())
		assert.NoError(b, err, "generating TOTP code should succeed")

		ctx := context.Background()
		_, err = authRepo.Login(ctx, "testuser", "password123", totpCode)
		if err != nil {
			b.Fatalf("login failed: %v", err)
		}

		// Optionally log success (remove in production benchmarks to avoid overhead)
		log.Infof("User logged in successfully, user_id=%s, username=%s", userID, "testuser")
	}

	// Verify mock expectations.
	assert.NoError(b, mock.ExpectationsWereMet(), "all mock expectations should be met")
}
