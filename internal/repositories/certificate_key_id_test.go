package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func setupCertKeyIDTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		expires_at DATETIME,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30,
		key_id TEXT,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		not_before TIMESTAMP NULL
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificate_tags (
		certificate_id TEXT NOT NULL, tag TEXT NOT NULL,
		PRIMARY KEY (certificate_id, tag))`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// TestCertificateRepository_KeyID_Persisted verifies that a non-nil KeyID round-trips
// through Create and Read without corruption.
func TestCertificateRepository_KeyID_Persisted(t *testing.T) {
	db := setupCertKeyIDTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(db, log)

	keyID := uuid.New()
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		KeyID:       keyID,
		Name:        "key-id-test-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		AutoRenew:   false,
		RenewalDays: 30,
	}

	err := repo.Create(context.Background(), cert)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), cert.ID)
	require.NoError(t, err)
	assert.Equal(t, keyID, got.KeyID, "KeyID should round-trip through Create/Read")
}

// TestCertificateRepository_KeyID_NilUUID verifies that a zero-value KeyID (uuid.Nil) is
// stored as a valid UUID string and reads back as uuid.Nil.
func TestCertificateRepository_KeyID_NilUUID(t *testing.T) {
	db := setupCertKeyIDTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(db, log)

	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		KeyID:       uuid.Nil, // zero value
		Name:        "nil-key-id-cert",
		Certificate: "PEM",
		PrivateKey:  "ENCRYPTED",
		CreatedAt:   time.Now().UTC(),
		AutoRenew:   false,
		RenewalDays: 30,
	}

	err := repo.Create(context.Background(), cert)
	require.NoError(t, err)

	got, err := repo.Read(context.Background(), cert.ID)
	require.NoError(t, err)
	// uuid.Nil.String() == "00000000-0000-0000-0000-000000000000", which is valid — parses back to uuid.Nil
	assert.Equal(t, uuid.Nil, got.KeyID)
}
