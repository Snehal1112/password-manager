package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// setupCertTestDB creates an in-memory SQLite database with the certificates table.
// The table includes the soft-delete columns required by the repository.
func setupCertTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "failed to open in-memory database")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP DEFAULT NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP DEFAULT NULL,
			expires_at DATETIME,
			auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days INTEGER NOT NULL DEFAULT 30
		);
		CREATE TABLE IF NOT EXISTS certificate_tags (
			certificate_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag)
		);
		CREATE TABLE IF NOT EXISTS crl (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			name TEXT NOT NULL,
			revoked_at TIMESTAMP NOT NULL
		);
	`)
	require.NoError(t, err, "failed to create certificate test schema")

	t.Cleanup(func() { db.Close() })

	return db
}

// newTestCert builds a minimal Certificate suitable for insertion via Create.
func newTestCert(userID uuid.UUID, name string) *domain.Certificate {
	return &domain.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		Name:        name,
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
		CreatedAt:   time.Now(),
	}
}

// TestCertificateSoftDelete verifies that SoftDelete hides the certificate from Read
// while making it visible through ListSoftDeleted.
func TestCertificateSoftDelete(t *testing.T) {
	t.Parallel()
	db := setupCertTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	cert := newTestCert(userID, "soft-delete-cert")
	require.NoError(t, repo.Create(ctx, cert))

	// SoftDelete sets deleted_at, leaves the row in the table.
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))

	// Normal Read should return an error because the cert is now soft-deleted.
	_, err := repo.Read(ctx, cert.ID)
	assert.Error(t, err, "Read should fail for a soft-deleted certificate")

	// ListSoftDeleted should include the certificate.
	deleted, err := repo.ListSoftDeleted(ctx, userID)
	require.NoError(t, err)
	require.Len(t, deleted, 1)
	assert.Equal(t, cert.ID, deleted[0].ID)
	assert.NotNil(t, deleted[0].DeletedAt)
}

// TestCertificatePurge verifies that PurgeCertificate permanently removes a soft-deleted certificate.
func TestCertificatePurge(t *testing.T) {
	t.Parallel()
	db := setupCertTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	cert := newTestCert(userID, "purge-cert")
	require.NoError(t, repo.Create(ctx, cert))
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))

	// PurgeCertificate should permanently remove the row.
	require.NoError(t, repo.PurgeCertificate(ctx, cert.ID))

	deleted, err := repo.ListSoftDeleted(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, deleted, "certificate should be permanently removed after purge")
}

// TestCertificatePurgeProtection verifies that PurgeCertificate fails when purge protection is enabled.
func TestCertificatePurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupCertTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(db, log)
	ctx := context.Background()
	userID := uuid.New()

	cert := newTestCert(userID, "protected-cert")
	require.NoError(t, repo.Create(ctx, cert))
	require.NoError(t, repo.SoftDelete(ctx, cert.ID))
	require.NoError(t, repo.SetPurgeProtection(ctx, cert.ID, true))

	// Purge must fail while purge_protection is true.
	err := repo.PurgeCertificate(ctx, cert.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "purge protection")
}
