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

	rvdb "rocketvault/internal/db"
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
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL
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
	t.Cleanup(func() { db.Close() }) //nolint:errcheck,gosec
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
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newCertPolicyTestLogger(t))

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
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newCertPolicyTestLogger(t))

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
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newCertPolicyTestLogger(t))

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

// TestCertificatePolicyRepository_GetByCertificateIDAny_IgnoresOwner verifies
// that GetByCertificateIDAny retrieves a policy regardless of which user owns
// it, unlike the owner-scoped GetByCertificateID.
func TestCertificatePolicyRepository_GetByCertificateIDAny_IgnoresOwner(t *testing.T) {
	db := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newCertPolicyTestLogger(t))
	ctx := context.Background()

	certID := uuid.New()
	ownerID := uuid.New()
	policy := &model.CertificatePolicy{
		ID: uuid.New(), CertificateID: certID, UserID: ownerID,
		ValidityMonths: 12, KeyType: "RSA", KeySize: 2048,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	got, err := repo.GetByCertificateIDAny(ctx, certID) // no ownerID passed
	require.NoError(t, err)
	require.Equal(t, certID, got.CertificateID)
}

// TestCertificatePolicyRepository_DeleteByCertificateIDAny_IgnoresOwner
// verifies that DeleteByCertificateIDAny removes a policy regardless of which
// user owns it, unlike the owner-scoped DeleteByCertificateID.
func TestCertificatePolicyRepository_DeleteByCertificateIDAny_IgnoresOwner(t *testing.T) {
	db := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newCertPolicyTestLogger(t))
	ctx := context.Background()

	certID := uuid.New()
	ownerID := uuid.New()
	policy := &model.CertificatePolicy{
		ID: uuid.New(), CertificateID: certID, UserID: ownerID,
		ValidityMonths: 12, KeyType: "RSA", KeySize: 2048,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	err := repo.DeleteByCertificateIDAny(ctx, certID) // no ownerID passed
	require.NoError(t, err)

	_, err = repo.GetByCertificateIDAny(ctx, certID)
	require.Error(t, err)
}

// insertCertPolicyTestCert inserts a minimal certificates row so ListByVault
// (and its certificates JOIN) has a name and vault_id to read.
func insertCertPolicyTestCert(t *testing.T, db *sql.DB, id, userID, vaultID uuid.UUID, name string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO certificates (id, user_id, vault_id, name, certificate, private_key) VALUES (?, ?, ?, ?, 'cert', 'key')`,
		id.String(), userID.String(), vaultID.String(), name,
	)
	require.NoError(t, err)
}

// TestCertificatePolicy_ListByVault_ScopedAndJoinsCertName verifies that
// ListByVault only returns policies for certificates in the requested vault,
// and that each result carries its parent certificate's name.
func TestCertificatePolicy_ListByVault_ScopedAndJoinsCertName(t *testing.T) {
	sqlDB := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), newCertPolicyTestLogger(t))
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	userA, userB := uuid.New(), uuid.New()
	certA, certB := uuid.New(), uuid.New()
	now := time.Now()

	insertCertPolicyTestCert(t, sqlDB, certA, userA, vaultA, "cert-a")
	insertCertPolicyTestCert(t, sqlDB, certB, userB, vaultB, "cert-b")

	require.NoError(t, repo.Upsert(ctx, &model.CertificatePolicy{
		ID: uuid.New(), CertificateID: certA, UserID: userA,
		ValidityMonths: 12, AutoRenew: true, DaysBeforeExpiry: 30,
		CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, repo.Upsert(ctx, &model.CertificatePolicy{
		ID: uuid.New(), CertificateID: certB, UserID: userB,
		ValidityMonths: 24, AutoRenew: false, DaysBeforeExpiry: 60,
		CreatedAt: now, UpdatedAt: now,
	}))

	got, err := repo.ListByVault(ctx, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Len(t, got, 1, "must only see vault A's policy, not vault B's")
	require.Equal(t, certA, got[0].CertificateID)
	require.Equal(t, "cert-a", got[0].CertificateName)
	require.Equal(t, 12, got[0].ValidityMonths)
	require.True(t, got[0].AutoRenew)
}

// TestCertificatePolicy_ListByVault_EmptyWhenNoPolicies verifies ListByVault
// returns an empty slice, not an error, for a vault with no policies set.
func TestCertificatePolicy_ListByVault_EmptyWhenNoPolicies(t *testing.T) {
	sqlDB := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), newCertPolicyTestLogger(t))

	got, err := repo.ListByVault(context.Background(), model.NewVaultScope(uuid.New(), uuid.New()))
	require.NoError(t, err)
	require.Empty(t, got)
}

// TestCertificatePolicy_ListByVault_ExcludesDeletedCertificate verifies that
// a policy whose parent certificate is soft-deleted is excluded from the
// report -- it lists policies for live certificates, not orphaned rows.
func TestCertificatePolicy_ListByVault_ExcludesDeletedCertificate(t *testing.T) {
	sqlDB := setupCertPolicyTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), newCertPolicyTestLogger(t))
	ctx := context.Background()

	vaultID, userID, certID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	insertCertPolicyTestCert(t, sqlDB, certID, userID, vaultID, "deleted-cert")
	_, err := sqlDB.Exec(`UPDATE certificates SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?`, certID.String())
	require.NoError(t, err)

	require.NoError(t, repo.Upsert(ctx, &model.CertificatePolicy{
		ID: uuid.New(), CertificateID: certID, UserID: userID,
		ValidityMonths: 12, CreatedAt: now, UpdatedAt: now,
	}))

	got, err := repo.ListByVault(ctx, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	require.Empty(t, got)
}
