// Package certificates_test contains unit tests for the certificates package.
// It verifies certificate creation, CRUD operations, revocation, listing, and tag management for X.509 certificates.
package certificates_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"password-manager/common"
	"password-manager/internal/certificates"
	"password-manager/internal/keys"
	"password-manager/internal/logging"
)

// setupTestDB initializes an in-memory SQLite database for testing.
// It creates the certificates, certificate_tags, crl, and keys tables.
//
// Parameters:
// - t: The testing context.
// Returns: The SQLite database connection and a cleanup function.
func setupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", "file:memdb1?mode=memory&cache=shared")

	assert.NoError(t, err, "opening in-memory database should succeed")

	_, err = sqlDB.Exec(`
		CREATE TABLE certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE certificate_tags (
			certificate_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag),
			FOREIGN KEY (certificate_id) REFERENCES certificates(id)
		);
		CREATE TABLE crl (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag),
			FOREIGN KEY (key_id) REFERENCES keys(id)
		);
	`)
	assert.NoError(t, err, "creating tables should succeed")

	return sqlDB, func() {
		sqlDB.Close()
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

// TestCreateSelfSignedRSA tests the CreateSelfSigned function with an RSA key.
func TestCreateSelfSignedRSA(t *testing.T) {
	sqlDB, cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	keyRepo := keys.NewKeyRepository(sqlDB, log)
	ctx := context.Background()
	userID := uuid.New()
	key, err := keyRepo.GenerateRSA(ctx, userID, "test-key", 2048, []string{"prod"})
	assert.NoError(t, err, "generating RSA key should succeed")

	repo := certificates.NewCertificateRepository(sqlDB, log)
	_, err = repo.CreateSelfSigned(ctx, userID, "test-cert", key.ID, 365, []string{"prod"})
	assert.NoError(t, err, "creating self-signed certificate should succeed")

	var id, userid, name string
	var certPEM, privateKeyPEM string
	err = sqlDB.QueryRow("SELECT id, user_id, name, certificate, private_key FROM certificates WHERE user_id = ?", userID.String()).
		Scan(&id, &userid, &name, &certPEM, &privateKeyPEM)
	assert.NoError(t, err, "querying certificate should succeed")
	assert.Contains(t, certPEM, "-----BEGIN CERTIFICATE-----", "certificate should be PEM-encoded")

	decryptedPrivateKey, err := common.DecryptSecret(privateKeyPEM)
	assert.NoError(t, err, "decrypting private key should succeed")
	assert.Contains(t, decryptedPrivateKey, "-----BEGIN RSA PRIVATE KEY-----", "private key should be PEM-encoded")

	var tag string
	err = sqlDB.QueryRow("SELECT tag FROM certificate_tags WHERE certificate_id = ?", id).Scan(&tag)
	assert.NoError(t, err, "querying tag should succeed")
	assert.Equal(t, "prod", tag, "tag should match")
}

// TestCreateSelfSignedECDSA tests the CreateSelfSigned function with an ECDSA key.
func TestCreateSelfSignedECDSA(t *testing.T) {
	sqlDB, cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	keyRepo := keys.NewKeyRepository(sqlDB, log)
	ctx := context.Background()
	userID := uuid.New()
	key, err := keyRepo.GenerateECDSA(ctx, userID, "test-key", "P-256", []string{"prod"})
	assert.NoError(t, err, "generating ECDSA key should succeed")

	repo := certificates.NewCertificateRepository(sqlDB, log)
	_, err = repo.CreateSelfSigned(ctx, userID, "test-cert", key.ID, 365, []string{"prod"})
	assert.NoError(t, err, "creating self-signed certificate should succeed")

	var id string
	var userid, name string
	var certPEM, privateKeyPEM string
	err = sqlDB.QueryRow("SELECT id, user_id, name, certificate, private_key FROM certificates WHERE user_id = ?", userID.String()).
		Scan(&id, &userid, &name, &certPEM, &privateKeyPEM)
	assert.NoError(t, err, "querying certificate should succeed")
	assert.Contains(t, certPEM, "-----BEGIN CERTIFICATE-----", "certificate should be PEM-encoded")

	decryptedPrivateKey, err := common.DecryptSecret(privateKeyPEM)
	assert.NoError(t, err, "decrypting private key should succeed")
	assert.Contains(t, decryptedPrivateKey, "-----BEGIN EC PRIVATE KEY-----", "private key should be PEM-encoded")

	var tag string
	err = sqlDB.QueryRow("SELECT tag FROM certificate_tags WHERE certificate_id = ?", id).Scan(&tag)
	assert.NoError(t, err, "querying tag should succeed")
	assert.Equal(t, "prod", tag, "tag should match")
}

// TestCreateCASigned tests the CreateCASigned function to ensure it creates a CA-signed certificate.
func TestCreateCASigned(t *testing.T) {
	sqlDB, cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	keyRepo := keys.NewKeyRepository(sqlDB, log)
	ctx := context.Background()
	userID := uuid.New()
	caKey, err := keyRepo.GenerateRSA(ctx, userID, "ca-key", 2048, []string{"prod"})
	assert.NoError(t, err, "generating CA key should succeed")

	repo := certificates.NewCertificateRepository(sqlDB, log)
	cert, err := repo.CreateSelfSigned(ctx, userID, "ca-cert", caKey.ID, 365, []string{"prod"})
	assert.NoError(t, err, "creating CA certificate should succeed")

	clientKey, err := keyRepo.GenerateRSA(ctx, userID, "client-key", 2048, []string{"prod"})
	assert.NoError(t, err, "generating client key should succeed")

	cert, err = repo.CreateCASigned(ctx, clientKey.UserID, "client-cert", clientKey.ID, cert.ID, 365, []string{"prod"})
	assert.NoError(t, err, "creating CA-signed certificate should succeed")

	var id string
	var userid, name string
	var certPEM, privateKeyPEM string
	err = sqlDB.QueryRow("SELECT id, user_id, name, certificate, private_key FROM certificates WHERE user_id = ?", userID.String()).
		Scan(&id, &userid, &name, &certPEM, &privateKeyPEM)
	assert.NoError(t, err, "querying certificate should succeed")
	assert.Contains(t, certPEM, "-----BEGIN CERTIFICATE-----", "certificate should be PEM-encoded")

	decryptedPrivateKey, err := common.DecryptSecret(privateKeyPEM)
	assert.NoError(t, err, "decrypting private key should succeed")
	assert.Contains(t, decryptedPrivateKey, "-----BEGIN RSA PRIVATE KEY-----", "private key should be PEM-encoded")

	var tag string
	err = sqlDB.QueryRow("SELECT tag FROM certificate_tags WHERE certificate_id = ?", id).Scan(&tag)
	assert.NoError(t, err, "querying tag should succeed")
	assert.Equal(t, "prod", tag, "tag should match")
}

// TestRevoke tests the Revoke function to ensure it adds a certificate to the CRL.
func TestRevoke(t *testing.T) {
	sqlDB, cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	keyRepo := keys.NewKeyRepository(sqlDB, log)
	ctx := context.Background()
	userID := uuid.New()
	key, err := keyRepo.GenerateRSA(ctx, userID, "test-key", 2048, []string{"prod"})
	assert.NoError(t, err, "generating RSA key should succeed")

	repo := certificates.NewCertificateRepository(sqlDB, log)
	_, err = repo.CreateSelfSigned(ctx, userID, "test-cert", key.ID, 365, []string{"prod"})
	assert.NoError(t, err, "creating self-signed certificate should succeed")

	var id string
	err = sqlDB.QueryRow("SELECT id FROM certificates WHERE user_id = ?", userID.String()).Scan(&id)
	assert.NoError(t, err, "querying certificate ID should succeed")

	err = repo.Revoke(ctx, uuid.MustParse(id), "123456789", "test-cert")
	assert.NoError(t, err, "revoking certificate should succeed")

	var serialNumber, name string
	err = sqlDB.QueryRow("SELECT serial_number, name FROM crl WHERE user_id = ?", userID.String()).
		Scan(&serialNumber, &name)
	assert.NoError(t, err, "querying CRL should succeed")
	assert.Equal(t, "123456789", serialNumber, "serial number should match")
	assert.Equal(t, "test-cert", name, "certificate name should match")
}

// TestListRevoked tests the ListRevoked function to ensure it retrieves revoked certificates.
func TestListRevoked(t *testing.T) {
	sqlDB, cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	userID := uuid.New()
	_, err := sqlDB.Exec(
		"INSERT INTO crl (user_id, serial_number, name, revoked_at) VALUES (?, ?, ?, ?)",
		userID.String(), "123456789", "test-cert", time.Now(),
	)
	assert.NoError(t, err, "inserting revoked certificate should succeed")

	ctx := context.Background()
	repo := certificates.NewCertificateRepository(sqlDB, log)
	revokedCerts, err := repo.ListRevoked(ctx, userID)
	assert.NoError(t, err, "listing revoked certificates should succeed")
	assert.Len(t, revokedCerts, 1, "should return one revoked certificate")
	assert.Equal(t, "123456789", revokedCerts[0].SerialNumber, "serial number should match")
	assert.Equal(t, "test-cert", revokedCerts[0].Name, "certificate name should match")
}

// TestListByUser tests the ListByUser function to ensure it lists certificates with filters.
func TestListByUser(t *testing.T) {
	sqlDB, cleanup := setupTestDB(t)
	defer cleanup()

	viper.Set("jwt_secret", "test-jwt-secret")
	viper.Set("log.file", "test.log")
	viper.Set("api.rate_limit", "10-M")
	viper.Set("log.level", "debug")
	viper.Set("master_key", generateMasterKey(t))

	log := logging.InitLogger()
	defer os.Remove("test.log")

	keyRepo := keys.NewKeyRepository(sqlDB, log)
	ctx := context.Background()
	userID := uuid.New()
	key, err := keyRepo.GenerateRSA(ctx, userID, "test-key", 2048, []string{"prod"})
	assert.NoError(t, err, "generating RSA key should succeed")

	repo := certificates.NewCertificateRepository(sqlDB, log)
	_, err = repo.CreateSelfSigned(ctx, userID, "test-cert", key.ID, 365, []string{"prod", "api"})
	assert.NoError(t, err, "creating self-signed certificate should succeed")

	encryptedValue2, err := common.EncryptSecret("-----BEGIN CERTIFICATE-----\ntest-cert2\n-----END CERTIFICATE-----")
	assert.NoError(t, err, "encrypting certificate should succeed")
	ID := uuid.New()
	_, err = sqlDB.Exec(
		"INSERT INTO certificates (id, user_id, name, certificate, private_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		ID.String(), userID.String(), "test-cert2", encryptedValue2, key.Value, time.Now(),
	)

	assert.NoError(t, err, "inserting second certificate should succeed")
	_, err = sqlDB.Exec(
		"INSERT INTO certificate_tags (certificate_id, tag) VALUES (?, ?)",
		ID.String(), "dev",
	)
	assert.NoError(t, err, "inserting tag for second certificate should succeed")

	certs, err := repo.ListByUser(ctx, userID, "", []string{"prod"})
	assert.NoError(t, err, "listing certificates should succeed")
	assert.Len(t, certs, 1, "should return one certificate")
	assert.Equal(t, "test-cert", certs[0].Name, "certificate name should match")
	assert.ElementsMatch(t, []string{"prod", "api"}, certs[0].Tags, "tags should match")
}

// BenchmarkCreateSelfSigned measures the performance of the CreateSelfSigned function.
// func BenchmarkCreateSelfSigned(b *testing.B) {
// 	sqlDB, mock, err := sqlmock.New()
// 	if err != nil {
// 		b.Fatalf("creating mock database failed: %v", err)
// 	}
// 	defer sqlDB.Close()

// 	viper.Set("jwt_secret", "test-jwt-secret")
// 	viper.Set("log.file", "test.log")
// 	viper.Set("api.rate_limit", "10-M")
// 	viper.Set("log.level", "debug")
// 	viper.Set("master_key", generateMasterKey(b))

// 	log := logging.InitLogger()
// 	defer os.Remove("test.log")

// 	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		b.Fatalf("generating RSA key failed: %v", err)
// 	}
// 	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
// 	})
// 	encryptedValue, err := secrets.EncryptSecret(string(privateKeyPEM))
// 	if err != nil {
// 		b.Fatalf("encrypting mock key failed: %v", err)
// 	}

// 	id := uuid.New()
// 	userID := uuid.New()
// 	// Mock key query
// 	rows := sqlmock.NewRows([]string{"id", "user_id", "name", "value", "type", "revoked", "created_at"}).
// 		AddRow(id.String(), userID.String(), "test-key", encryptedValue, "RSA", false, time.Now())

// 	mock.ExpectQuery("SELECT id, user_id, name, value, type, revoked, created_at FROM keys WHERE id = ?").
// 		WithArgs(id.String()).
// 		WillReturnRows(rows)

// 	// Mock tag query for key (from keyRepo.Read)
// 	tagRows := sqlmock.NewRows([]string{"tag"}).AddRow("prod")
// 	mock.ExpectQuery("SELECT tag FROM key_tags WHERE key_id = ?").
// 		WithArgs(id.String()).WillReturnRows(tagRows)

// 	certID := uuid.New()
// 	// Mock outer transaction for certificate insertion
// 	mock.ExpectBegin()
// 	mock.ExpectExec("INSERT INTO certificates \\(id, user_id, name, certificate, private_key, created_at\\) VALUES \\(\\?, \\?, \\?, \\?, \\?, \\?\\)").
// 		WithArgs(certID.String(), userID.String(), "test-cert", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
// 		WillReturnResult(sqlmock.NewResult(1, 1))

// 	// Mock inner transaction for tag insertion (from tags.AddTags)
// 	mock.ExpectBegin()
// 	mock.ExpectExec("INSERT INTO certificate_tags \\(certificate_id, tag\\) VALUES \\(\\?, \\?\\)").
// 		WithArgs(certID.String(), "prod").
// 		WillReturnResult(sqlmock.NewResult(1, 1))
// 	mock.ExpectCommit() // Inner transaction commit

// 	// Mock outer transaction commit
// 	mock.ExpectCommit()

// 	ctx := context.Background()
// 	repo := certificates.NewCertificateRepository(sqlDB, log)
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		b.Logf("Starting CreateSelfSigned iteration %d", i)
// 		_, err := repo.CreateSelfSigned(ctx, userID, "test-cert", id, 365, []string{"prod"})
// 		if err != nil {
// 			b.Logf("CreateSelfSigned error: %v", err)
// 			b.Fatalf("CreateSelfSigned failed: %v", err)
// 		}
// 	}

// 	if err := mock.ExpectationsWereMet(); err != nil {
// 		b.Logf("Mock expectations error: %v", err)
// 		b.Fatalf("mock expectations not met: %v", err)
// 	}
// }
