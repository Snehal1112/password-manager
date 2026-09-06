package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// setupCertListAllTestDB creates an in-memory SQLite database with the
// certificates table. Named distinctly from the package-scope setupTestDB,
// setupRotationTestDB, setupSessionTestDB and setupCertLifecycleTestDB helpers
// that already exist in this test package.
func setupCertListAllTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "file:certlistall_" + uuid.NewString() + "?mode=memory&cache=shared"
	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err, "open in-memory database")
	t.Cleanup(func() { _ = raw.Close() })

	_, err = raw.Exec(`
		CREATE TABLE certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			name TEXT NOT NULL,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP,
			auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days INTEGER NOT NULL DEFAULT 30,
			key_id TEXT,
			ca_cert_id TEXT,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			not_before TIMESTAMP,
			deleted_at TIMESTAMP,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE
		);
		CREATE TABLE certificate_tags (
			certificate_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag)
		);
	`)
	require.NoError(t, err, "create certificates schema")

	return raw
}

// TestListAllPopulatesVaultID pins the F2 fix: ListAll must read through the
// canonical certificateColumns list, so vault_id survives the listing the
// renewal scheduler reads. Before the fix ListAll used its own SELECT list
// that omitted the column entirely, leaving VaultID zero on every row.
func TestListAllPopulatesVaultID(t *testing.T) {
	raw := setupCertListAllTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	vaultID := uuid.New()
	certID := uuid.New()

	_, err := raw.ExecContext(ctx,
		`INSERT INTO certificates
		 (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at,
		  auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before)
		 VALUES (?, ?, ?, 'web', 'PEM', 'KEY', ?, ?, TRUE, 30, ?, NULL, TRUE, NULL)`,
		certID.String(), uuid.New().String(), vaultID.String(),
		time.Now(), time.Now().Add(48*time.Hour), uuid.New().String())
	require.NoError(t, err, "insert certificate")

	certs, err := repo.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.Equal(t, vaultID, certs[0].VaultID, "vault_id must survive the ListAll read")
}

// TestListAllRejectsMalformedID pins the removal of uuid.MustParse: a corrupt
// id column must return an error, not panic the renewal scheduler's goroutine.
func TestListAllRejectsMalformedID(t *testing.T) {
	raw := setupCertListAllTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	_, err := raw.ExecContext(ctx,
		`INSERT INTO certificates
		 (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at,
		  auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before)
		 VALUES ('not-a-uuid', ?, ?, 'web', 'PEM', 'KEY', ?, ?, TRUE, 30, NULL, NULL, TRUE, NULL)`,
		uuid.New().String(), uuid.New().String(), time.Now(), time.Now().Add(48*time.Hour))
	require.NoError(t, err, "insert certificate with corrupt id")

	require.NotPanics(t, func() {
		_, err = repo.ListAll(ctx)
	}, "a corrupt id must not panic the renewal scheduler")
	require.Error(t, err, "a corrupt id must be reported as an error")
	require.Contains(t, err.Error(), "failed to parse certificate ID")
}

// TestListAllSkipsSoftDeleted confirms the WHERE clause is unchanged by the
// refactor -- the new column list adds deleted_at to the SELECT, and this
// guards against someone concluding it should therefore be returned.
func TestListAllSkipsSoftDeleted(t *testing.T) {
	raw := setupCertListAllTestDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(raw, rvdb.SQLite), logging.InitLogger())

	ctx := context.Background()
	_, err := raw.ExecContext(ctx,
		`INSERT INTO certificates
		 (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at,
		  auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, deleted_at)
		 VALUES (?, ?, ?, 'gone', 'PEM', 'KEY', ?, ?, TRUE, 30, NULL, NULL, TRUE, NULL, ?)`,
		uuid.New().String(), uuid.New().String(), uuid.New().String(),
		time.Now(), time.Now().Add(48*time.Hour), time.Now())
	require.NoError(t, err, "insert soft-deleted certificate")

	certs, err := repo.ListAll(ctx)
	require.NoError(t, err)
	require.Empty(t, certs, "soft-deleted certificates stay out of ListAll")
}
