// Package main contains unit tests for the keys CLI commands.
// It verifies the functionality of cryptographic key management commands using an in-memory SQLite database.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"log"
	"math/rand"
	"os"
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
// It sets up the users and keys tables and assigns the connection to db.DB.
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
		CREATE TABLE keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			revoked BOOLEAN NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE key_tags (
			key_id INTEGER NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag),
			FOREIGN KEY (key_id) REFERENCES keys(id)
		)
	`)
	assert.NoError(t, err, "creating tables should succeed")

	db.DB = sqlDB
	return func() {
		sqlDB.Close()
		db.DB = nil
	}
}

// generateMasterKey generates a valid 32-byte base64-encoded master key for testing.
func generateMasterKey(t *testing.T) string {
	t.Helper()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("generating random key failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// TestGenerateKeyCmd tests the keys generate command with a specified name.
func TestGenerateKeyCmd(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("master_key", generateMasterKey(t))

	Logger = logging.InitLogger()
	defer os.Remove("test.log")

	// Insert test user.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
		1, "testuser", string(hashedPassword), auth.RoleCryptoManager, "TOTPSECRET",
	)
	assert.NoError(t, err, "inserting user should succeed")

	cmd := generateKeyCmd()
	cmd.Flags().String("username", "testuser", "")
	cmd.Flags().String("password", "password123", "")
	cmd.Flags().String("totp-code", "123456", "")
	cmd.Flags().Set("name", "test-key")
	cmd.Flags().Set("type", "rsa")
	cmd.Flags().Set("bits", "2048")
	cmd.Flags().Set("curve", "P256")
	cmd.Flags().Set("hsm", "false")
	cmd.Flags().Set("tags", "prod") // Set the flag to a comma-separated string for slice

	ctx := context.WithValue(context.Background(), "userID", 1)
	cmd.SetContext(ctx)
	var output bytes.Buffer
	cmd.SetOut(&output)

	cmd.Run(cmd, []string{})

	// Verify key in database.
	var id int
	var name, keyType string
	var revoked bool
	err = db.DB.QueryRow("SELECT id, name, type, revoked FROM keys WHERE user_id = ?", 1).
		Scan(&id, &name, &keyType, &revoked)
	assert.NoError(t, err, "querying key should succeed")
	assert.Equal(t, "test-key", name, "key name should match")
	assert.Equal(t, "RSA", keyType, "key type should match")
	assert.False(t, revoked, "key should not be revoked")

	// Verify tags in database.
	var tag string
	err = db.DB.QueryRow("SELECT tag FROM key_tags WHERE key_id = ?", id).
		Scan(&tag)
	assert.NoError(t, err, "querying tag should succeed")
	assert.Equal(t, "prod", tag, "tag should match")

	logContent, err := os.ReadFile("test.log")
	assert.NoError(t, err, "log file should exist")
	assert.Contains(t, string(logContent), `"operation":"generate_key"`, "log should contain generate_key operation")
}

// TestGenerateKeyCmdDefaultName tests the generate command with a default name.
func TestGenerateKeyCmdDefaultName(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("master_key", generateMasterKey(t))

	Logger = logging.InitLogger()
	defer os.Remove("test.log")

	// Insert test user.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
		1, "testuser", string(hashedPassword), auth.RoleCryptoManager, "TOTPSECRET",
	)
	assert.NoError(t, err, "inserting user should succeed")

	cmd := generateKeyCmd()
	cmd.Flags().String("username", "testuser", "")
	cmd.Flags().String("password", "password123", "")
	cmd.Flags().String("totp-code", "123456", "")

	cmd.Flags().Set("type", "rsa")
	cmd.Flags().Set("bits", "2048")
	cmd.Flags().Set("curve", "P256")
	cmd.Flags().Set("hsm", "false")

	ctx := context.WithValue(context.Background(), "userID", 1)
	cmd.SetContext(ctx)
	var output bytes.Buffer
	cmd.SetOut(&output)

	cmd.Run(cmd, []string{})

	// Verify key in database.
	var id int
	var name, keyType string
	var revoked bool
	err = db.DB.QueryRow("SELECT id, name, type, revoked FROM keys WHERE user_id = ?", 1).
		Scan(&id, &name, &keyType, &revoked)
	assert.NoError(t, err, "querying key should succeed")
	assert.Equal(t, "key-1", name, "key name should match default")
	assert.Equal(t, "RSA", keyType, "key type should match")
	assert.False(t, revoked, "key should not be revoked")

	logContent, err := os.ReadFile("test.log")
	assert.NoError(t, err, "log file should exist")
	assert.Contains(t, string(logContent), "Key name not provided, using default", "log should contain default name message")
}

// TestGenerateKeyCmdInvalidParams tests the generate command with invalid parameters.
func TestGenerateKeyCmdInvalidParams(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("master_key", generateMasterKey(t))

	Logger = logging.InitLogger()
	defer os.Remove("test.log")

	// Insert test user.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
		1, "testuser", string(hashedPassword), auth.RoleCryptoManager, "TOTPSECRET",
	)
	assert.NoError(t, err, "inserting user should succeed")

	// Test invalid key type.
	cmd := generateKeyCmd()
	cmd.Flags().String("username", "testuser", "")
	cmd.Flags().String("password", "password123", "")
	cmd.Flags().String("totp-code", "123456", "")
	cmd.Flags().Set("type", "rsaa")
	ctx := context.WithValue(context.Background(), "userID", 1)
	cmd.SetContext(ctx)

	cmd.Run(cmd, []string{})
	logContent, err := os.ReadFile("test.log")

	assert.Contains(t, string(logContent), `"msg":"Invalid key type: must be rsa or ecdsa"`, "should output error for invalid key type")

	// Test invalid RSA bit size.
	cmd = generateKeyCmd()
	cmd.Flags().String("username", "testuser", "")
	cmd.Flags().String("password", "password123", "")
	cmd.Flags().String("totp-code", "123456", "")
	cmd.Flags().Set("type", "rsa")
	cmd.Flags().Set("bits", "1024")
	cmd.SetContext(ctx)

	cmd.Run(cmd, []string{})
	logContent, err = os.ReadFile("test.log")
	assert.Contains(t, string(logContent), `"msg":"Invalid bit size: must be 2048 or 4096 for RSA"`, "should output error for invalid bit size")

	//Test invalid ECDSA curve.
	cmd = generateKeyCmd()
	cmd.Flags().String("username", "testuser", "")
	cmd.Flags().String("password", "password123", "")
	cmd.Flags().String("totp-code", "123456", "")
	cmd.Flags().Set("type", "ecdsa")
	cmd.Flags().Set("curve", "invalid")
	cmd.SetContext(ctx)

	cmd.Run(cmd, []string{})
	logContent, err = os.ReadFile("test.log")
	assert.Contains(t, string(logContent), `"msg":"Invalid curve: must be P256, P384, or P521 for ECDSA"`, "should output error for invalid curve")
}

// TestGetKeyCmd tests the keys get command.
func TestGetKeyCmd(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("master_key", generateMasterKey(t))

	Logger = logging.InitLogger()
	defer os.Remove("test.log")

	// Insert test user.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
		1, "testuser", string(hashedPassword), auth.RoleCryptoManager, "TOTPSECRET",
	)
	assert.NoError(t, err, "inserting user should succeed")

	// Insert test key.
	encryptedValue, err := secrets.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----")
	assert.NoError(t, err, "encrypting key should succeed")
	createdAt := time.Now()
	_, err = db.DB.Exec(
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		1, 1, "test-key", encryptedValue, "RSA", false, createdAt,
	)
	assert.NoError(t, err, "inserting key should succeed")

	cmd := getKeyCmd()
	cmd.Flags().String("username", "testuser", "")
	cmd.Flags().String("password", "password123", "")
	cmd.Flags().String("totp-code", "123456", "")
	ctx := context.WithValue(context.Background(), "userID", 1)
	cmd.SetContext(ctx)

	cmd.Run(cmd, []string{"1"})
	logContent, err := os.ReadFile("test.log")
	assert.Contains(t, string(logContent), `"msg":"Key retrieved successfully: id=1"`, "should output key details")
	assert.Contains(t, string(logContent), `"status":"success"`, "should output key details")

	logContent, err = os.ReadFile("test.log")
	assert.NoError(t, err, "log file should exist")
	assert.Contains(t, string(logContent), `"operation":"get_key"`, "log should contain get_key operation")
}

// TestListKeysCmd tests the keys list command (currently debug logs only).
func TestListKeysCmd(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("master_key", generateMasterKey(t))

	Logger = logging.InitLogger()
	defer os.Remove("test.log")

	// Insert test user.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
		1, "testuser", string(hashedPassword), auth.RoleCryptoManager, "TOTPSECRET",
	)
	assert.NoError(t, err, "inserting user should succeed")

	var logOutput bytes.Buffer
	log.SetOutput(&logOutput)

	cmd := listKeysCmd()
	cmd.Flags().String("username", "testuser", "")
	cmd.Flags().String("password", "password123", "")
	cmd.Flags().String("totp-code", "123456", "")
	cmd.Flags().Set("type", "rsa")

	// Set tags
	cmd.Flags().Set("tags", "prod,dev") // Set the flag to a comma-separated string for slice
	ctx := context.WithValue(context.Background(), "userID", 1)
	cmd.SetContext(ctx)
	var output bytes.Buffer
	cmd.SetOut(&output)

	cmd.Run(cmd, []string{})

	logContent := logOutput.String()
	t.Logf("Log content: %s", logContent)

	assert.Contains(t, logContent, "Listing keys for user: 1", "should log user ID")
	assert.Contains(t, logContent, "Key type: rsa", "should log key type")
	assert.Contains(t, logContent, "Tags: [prod dev]", "should log tags")
}

// TestRotateKeyCmd tests the keys rotate command.
func TestRotateKeyCmd(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("master_key", generateMasterKey(t))

	Logger = logging.InitLogger()
	//	defer os.Remove("test.log")

	// Insert test user.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := db.DB.Exec(
		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
		1, "testuser", string(hashedPassword), auth.RoleCryptoManager, "TOTPSECRET",
	)
	assert.NoError(t, err, "inserting user should succeed")

	// Insert test key.
	encryptedValue, err := secrets.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----")
	assert.NoError(t, err, "encrypting key should succeed")
	createdAt := time.Now()
	_, err = db.DB.Exec(
		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		1, 1, "test-key", encryptedValue, "RSA", false, createdAt,
	)
	assert.NoError(t, err, "inserting key should succeed")

	cmd := rotateKeyCmd()
	cmd.Flags().String("username", "testuser", "")
	cmd.Flags().String("password", "password123", "")
	cmd.Flags().String("totp-code", "123456", "")
	ctx := context.WithValue(context.Background(), "userID", 1)
	cmd.SetContext(ctx)
	cmd.Run(cmd, []string{"1"})

	// Verify old key is revoked.
	var revoked bool
	err = db.DB.QueryRow("SELECT revoked FROM keys WHERE id = ?", 1).Scan(&revoked)
	assert.NoError(t, err, "querying old key should succeed")
	assert.True(t, revoked, "old key should be revoked")

	// Verify new key exists.
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM keys WHERE user_id = ? AND name = ? AND id != ?", 1, "test-key", 1).Scan(&count)
	assert.NoError(t, err, "querying new key should succeed")
	assert.Equal(t, 1, count, "new key should exist")

	logContent, err := os.ReadFile("test.log")
	assert.NoError(t, err, "log file should exist")
	assert.Contains(t, string(logContent), `"operation":"rotate_key"`, "log should contain rotate_key operation")
}

// // TestDeleteKeyCmd tests the keys delete command.
// func TestDeleteKeyCmd(t *testing.T) {
// 	cleanup := setupTestDB(t)
// 	defer cleanup()

// 	viper.Set("jwt_secret", "test-jwt-secret")
// 	viper.Set("log.file", "test.log")
// 	viper.Set("master_key", generateMasterKey(t))

// 	logger := logging.InitLogger()
// 	defer os.Remove("test.log")

// 	// Insert test user.
// 	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
// 	_, err := db.DB.Exec(
// 		"INSERT INTO users (id, username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?, ?)",
// 		1, "testuser", string(hashedPassword), auth.RoleCryptoManager, "TOTPSECRET",
// 	)
// 	assert.NoError(t, err, "inserting user should succeed")

// 	// Insert test key.
// 	encryptedValue, err := secrets.EncryptSecret("-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----")
// 	assert.NoError(t, err, "encrypting key should succeed")
// 	createdAt := time.Now()
// 	_, err = db.DB.Exec(
// 		"INSERT INTO keys (id, user_id, name, value, type, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
// 		1, 1, "test-key", encryptedValue, "RSA", false, createdAt,
// 	)
// 	assert.NoError(t, err, "inserting key should succeed")

// 	cmd := deleteKeyCmd()
// 	cmd.Flags().String("username", "testuser", "")
// 	cmd.Flags().String("password", "password123", "")
// 	cmd.Flags().String("totp-code", "123456", "")
// 	ctx := context.WithValue(context.Background(), "userID", 1)
// 	cmd.SetContext(ctx)
// 	var output bytes.Buffer
// 	cmd.SetOut(&output)

// 	mockAuth(t, cmd, auth.RoleCryptoManager)
// 	cmd.Run(cmd, []string{"1"})

// 	assert.Contains(t, output.String(), "Key deleted successfully", "should output success message")

// 	// Verify key is deleted.
// 	var count int
// 	err = db.DB.QueryRow("SELECT COUNT(*) FROM keys WHERE id = ?", 1).Scan(&count)
// 	assert.NoError(t, err, "querying key should succeed")
// 	assert.Equal(t, 0, count, "key should be deleted")

// 	logContent, err := os.ReadFile("test.log")
// 	assert.NoError(t, err, "log file should exist")
// 	assert.Contains(t, string(logContent), `"operation":"delete_key"`, "log should contain delete_key operation")
// }

// // TestRBACEnforcement tests RBAC enforcement for keys commands.
// func TestRBACEnforcement(t *testing.T) {
// 	cleanup := setupTestDB(t)
// 	defer cleanup()

// 	viper.Set("jwt_secret", "test-jwt-secret")
// 	viper.Set("log.file", "test.log")
// 	viper.Set("master_key", generateMasterKey(t))

// 	logger := logging.InitLogger()
// 	defer os.Remove("test.log")

// 	cmd := generateKeyCmd()
// 	cmd.Flags().String("username", "testuser", "")
// 	cmd.Flags().String("password", "password123", "")
// 	cmd.Flags().String("totp-code", "123456", "")
// 	ctx := context.WithValue(context.Background(), "userID", 1)
// 	cmd.SetContext(ctx)
// 	var output bytes.Buffer
// 	cmd.SetOut(&output)

// 	mockAuth(t, cmd, auth.RoleSecretsManager)
// 	cmd.Run(cmd, []string{})

// 	assert.Contains(t, output.String(), "Error: insufficient permissions", "should output RBAC error")

// 	logContent, err := os.ReadFile("test.log")
// 	assert.NoError(t, err, "log file should exist")
// 	assert.Contains(t, string(logContent), `"operation":"keys_auth"`, "log should contain keys_auth operation")
// }
