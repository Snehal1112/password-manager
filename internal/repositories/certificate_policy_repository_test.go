package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupCertPolicyTestDB creates an in-memory SQLite DB for certificate policy tests.
func setupCertPolicyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	// Create minimal users table to satisfy foreign keys.
	// SQLite only enforces FK constraints when PRAGMA foreign_keys = ON,
	// so a minimal schema is enough for unit tests.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret TEXT,
		role TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificate_policies (
		id                TEXT PRIMARY KEY,
		certificate_id    TEXT NOT NULL UNIQUE,
		user_id           TEXT NOT NULL,
		validity_months   INTEGER NOT NULL DEFAULT 12,
		key_type          TEXT NOT NULL DEFAULT 'RSA',
		key_size          INTEGER NOT NULL DEFAULT 2048,
		curve             TEXT NOT NULL DEFAULT '',
		subject           TEXT NOT NULL DEFAULT '',
		sans              TEXT NOT NULL DEFAULT '',
		auto_renew        BOOLEAN NOT NULL DEFAULT FALSE,
		days_before_expiry INTEGER NOT NULL DEFAULT 30,
		issuer_name       TEXT NOT NULL DEFAULT '',
		created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// newCertPolicyTestLogger creates a logger for certificate policy repository tests.
func newCertPolicyTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// TestCertificatePolicy_UpsertAndGet verifies that a policy can be persisted and loaded.
func TestCertificatePolicy_UpsertAndGet(t *testing.T) {
	db := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(db, newCertPolicyTestLogger(t))

	certID := uuid.New()
	userID := uuid.New()

	policy := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           userID,
		ValidityMonths:   12,
		KeyType:          "RSA",
		KeySize:          2048,
		AutoRenew:        true,
		DaysBeforeExpiry: 30,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	require.NoError(t, repo.Upsert(context.Background(), policy))

	loaded, err := repo.GetByCertificateID(context.Background(), certID, userID)
	require.NoError(t, err)
	require.Equal(t, 12, loaded.ValidityMonths)
	require.True(t, loaded.AutoRenew)
}

// TestCertificatePolicy_UpsertUpdatesExisting verifies that a second Upsert replaces the policy.
func TestCertificatePolicy_UpsertUpdatesExisting(t *testing.T) {
	db := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(db, newCertPolicyTestLogger(t))

	certID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	first := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           userID,
		ValidityMonths:   12,
		KeyType:          "RSA",
		KeySize:          2048,
		AutoRenew:        false,
		DaysBeforeExpiry: 30,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	require.NoError(t, repo.Upsert(context.Background(), first))

	// Upsert again with different values; existing row must be updated.
	second := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           userID,
		ValidityMonths:   24,
		KeyType:          "EC",
		Curve:            "P-256",
		AutoRenew:        true,
		DaysBeforeExpiry: 60,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	require.NoError(t, repo.Upsert(context.Background(), second))

	loaded, err := repo.GetByCertificateID(context.Background(), certID, userID)
	require.NoError(t, err)
	require.Equal(t, 24, loaded.ValidityMonths)
	require.Equal(t, "EC", loaded.KeyType)
	require.Equal(t, "P-256", loaded.Curve)
	require.True(t, loaded.AutoRenew)
}

// TestCertificatePolicy_DeleteByCertificateID verifies that a policy can be deleted.
func TestCertificatePolicy_DeleteByCertificateID(t *testing.T) {
	db := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(db, newCertPolicyTestLogger(t))

	certID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	policy := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           userID,
		ValidityMonths:   12,
		KeyType:          "RSA",
		KeySize:          2048,
		AutoRenew:        false,
		DaysBeforeExpiry: 30,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	require.NoError(t, repo.Upsert(context.Background(), policy))
	require.NoError(t, repo.DeleteByCertificateID(context.Background(), certID, userID))

	// After deletion, GetByCertificateID must return an error.
	_, err := repo.GetByCertificateID(context.Background(), certID, userID)
	require.Error(t, err)
}
