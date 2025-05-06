// Package certificates_test contains unit tests for the certificates package.
// It verifies certificate creation, CRUD operations, revocation, and encryption for X.509 certificates.
package certificates

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/keys"
	"github.com/snehal1112/password-manager/internal/logging"
	"github.com/snehal1112/password-manager/internal/secrets"
)

// setupTestDB initializes an in-memory SQLite database for testing.
// It sets up the ca_keys, crl, and keys tables and assigns the connection to db.DB.
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

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	assert.NoError(t, err, "opening in-memory database should succeed")

	_, err = sqlDB.Exec(`
		CREATE TABLE ca_keys (
			user_id INTEGER PRIMARY KEY,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE crl (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			serial_number TEXT NOT NULL,
			name TEXT NOT NULL,
			revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			revoked BOOLEAN NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

// TestCreateSelfSigned tests the CreateSelfSigned function to ensure it creates a self-signed certificate.
func TestCreateSelfSigned(t *testing.T) {
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

	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(t))

	// Create a test RSA key.
	keyRepo := keys.NewKeyRepository(db.DB, log)
	ctx := context.Background()
	_, err := keyRepo.GenerateRSA(ctx, 1, "test-key", 2048)
	assert.NoError(t, err, "generating RSA key should succeed")

	// Test self-signed certificate creation.
	repo := NewCertificateRepository(db.DB, log)
	err = repo.CreateSelfSigned(ctx, 1, "test-cert", 1, 365)
	assert.NoError(t, err, "creating self-signed certificate should succeed")

	// Verify certificate in database.
	var certPEM, privateKeyPEM string
	err = db.DB.QueryRow("SELECT certificate, private_key FROM ca_keys WHERE user_id = ?", 1).
		Scan(&certPEM, &privateKeyPEM)
	assert.NoError(t, err, "querying certificate should succeed")
	assert.Contains(t, certPEM, "-----BEGIN CERTIFICATE-----", "certificate should be PEM-encoded")

	// Decrypt and verify private key format.
	decryptedPrivateKey, err := secrets.DecryptSecret(privateKeyPEM)
	assert.NoError(t, err, "decrypting private key should succeed")
	assert.Contains(t, decryptedPrivateKey, "MII", "private key should be encrypted PEM")
}

// TestCreateCASigned tests the CreateCASigned function to ensure it creates a CA-signed certificate.
func TestCreateCASigned(t *testing.T) {
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

	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(t))

	// Create a CA key and certificate.
	keyRepo := keys.NewKeyRepository(db.DB, log)
	ctx := context.Background()
	_, err := keyRepo.GenerateRSA(ctx, 1, "ca-key", 2048)
	assert.NoError(t, err, "generating CA key should succeed")
	repo := NewCertificateRepository(db.DB, log)
	err = repo.CreateSelfSigned(ctx, 1, "ca-cert", 1, 365)
	assert.NoError(t, err, "creating CA certificate should succeed")

	// Create a client key.
	_, err = keyRepo.GenerateRSA(ctx, 2, "client-key", 2048)
	assert.NoError(t, err, "generating client key should succeed")

	// Test CA-signed certificate creation.
	err = repo.CreateCASigned(ctx, 2, "client-cert", 2, 1, 365)
	assert.NoError(t, err, "creating CA-signed certificate should succeed")

	// Verify certificate in database.
	var certPEM, privateKeyPEM string
	err = db.DB.QueryRow("SELECT certificate, private_key FROM ca_keys WHERE user_id = ?", 2).
		Scan(&certPEM, &privateKeyPEM)
	assert.NoError(t, err, "querying certificate should succeed")
	assert.Contains(t, certPEM, "-----BEGIN CERTIFICATE-----", "certificate should be PEM-encoded")

	// Decrypt and verify private key format.
	decryptedPrivateKey, err := secrets.DecryptSecret(privateKeyPEM)
	assert.NoError(t, err, "decrypting private key should succeed")
	assert.Contains(t, decryptedPrivateKey, "MII", "private key should be encrypted PEM")
}

// TestRevoke tests the Revoke function to ensure it adds a certificate to the CRL.
func TestRevoke(t *testing.T) {
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

	// Test revocation.
	ctx := context.Background()
	repo := NewCertificateRepository(db.DB, log)
	err := repo.Revoke(ctx, 1, "123456789", "test-cert")
	assert.NoError(t, err, "revoking certificate should succeed")

	// Verify CRL entry.
	var serialNumber, name string
	err = db.DB.QueryRow("SELECT serial_number, name FROM crl WHERE user_id = ?", 1).
		Scan(&serialNumber, &name)
	assert.NoError(t, err, "querying CRL should succeed")
	assert.Equal(t, "123456789", serialNumber, "serial number should match")
	assert.Equal(t, "test-cert", name, "certificate name should match")
}

// TestListRevoked tests the ListRevoked function to ensure it retrieves revoked certificates.
func TestListRevoked(t *testing.T) {
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

	// Insert test revoked certificate.
	_, err := db.DB.Exec(
		"INSERT INTO crl (user_id, serial_number, name, revoked_at) VALUES (?, ?, ?, ?)",
		1, "123456789", "test-cert", time.Now(),
	)
	assert.NoError(t, err, "inserting revoked certificate should succeed")

	// Test listing revoked certificates.
	ctx := context.Background()
	repo := NewCertificateRepository(db.DB, log)
	revokedCerts, err := repo.ListRevoked(ctx, 1)
	assert.NoError(t, err, "listing revoked certificates should succeed")
	assert.Len(t, revokedCerts, 1, "should return one revoked certificate")
	assert.Equal(t, "123456789", revokedCerts[0].SerialNumber, "serial number should match")
	assert.Equal(t, "test-cert", revokedCerts[0].Name, "certificate name should match")
}

// BenchmarkCreateSelfSigned measures the performance of the CreateSelfSigned function.
func BenchmarkCreateSelfSigned(b *testing.B) {
	// Set up mock database.
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		b.Fatalf("creating mock database failed: %v", err)
	}
	defer sqlDB.Close()

	// Set Viper configuration.
	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	log := logging.InitLogger()
	defer os.Remove("test.log")

	// Set Viper configuration.
	viper.Set("master_key", generateMasterKey(b))

	// Generate a valid RSA private key for the mock.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("generating RSA key failed: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	encryptedValue, err := secrets.EncryptSecret(string(privateKeyPEM))
	if err != nil {
		b.Fatalf("encrypting mock key failed: %v", err)
	}

	// Mock key query with encrypted key value.
	rows := sqlmock.NewRows([]string{"id", "user_id", "name", "value", "type", "revoked", "created_at"}).
		AddRow(1, 1, "test-key", encryptedValue, "RSA", false, time.Now())
	mock.ExpectQuery("SELECT id, user_id, name, value, type, revoked, created_at FROM keys WHERE id = ?").
		WithArgs(1).
		WillReturnRows(rows)

	// Mock certificate insertion.
	mock.ExpectExec("INSERT OR REPLACE INTO ca_keys \\(user_id, certificate, private_key, created_at\\) VALUES \\(\\?, \\?, \\?, \\?\\)").
		WithArgs(1, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Set mock database.
	db.DB = sqlDB

	// Run benchmark.
	ctx := context.Background()
	repo := NewCertificateRepository(db.DB, log)
	for i := 0; i < b.N; i++ {
		_ = repo.CreateSelfSigned(ctx, 1, "test-cert", 1, 365)
	}

	// Verify mock expectations.
	if err := mock.ExpectationsWereMet(); err != nil {
		b.Fatalf("mock expectations not met: %v", err)
	}
}
