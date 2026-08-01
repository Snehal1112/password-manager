package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newScopeTestCertRepo(t *testing.T) *CertificateRepository {
	t.Helper()
	dsn := "file:certscope_" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		expires_at DATETIME,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30,
		key_id TEXT NOT NULL DEFAULT '',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		not_before TIMESTAMP NULL
	);
	CREATE TABLE IF NOT EXISTS certificate_tags (
		certificate_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (certificate_id, tag)
	)`)
	require.NoError(t, err)

	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: &logging.Logger{Logger: l}}
}

func seedScopeCert(t *testing.T, repo *CertificateRepository, ownerID, vaultID uuid.UUID, name string) *model.Certificate {
	t.Helper()
	c := &model.Certificate{
		ID:          uuid.New(),
		UserID:      ownerID,
		VaultID:     vaultID,
		KeyID:       uuid.New(),
		Name:        name,
		Certificate: "PEM-" + name,
		PrivateKey:  "ENC-" + name,
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(context.Background(), c))
	return c
}

func TestCertificateRead(t *testing.T) {
	repo := newScopeTestCertRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	cert := seedScopeCert(t, repo, ownerID, vaultA, "cert-a")

	got, err := repo.Read(ctx, cert.ID, model.NewVaultScope(vaultA, otherUser))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)
	assert.Equal(t, vaultA, got.VaultID)

	_, err = repo.Read(ctx, cert.ID, model.NewVaultScope(vaultB, otherUser))
	assert.Error(t, err)

	_, err = repo.Read(ctx, cert.ID, model.NewOwnerScope(vaultA, otherUser))
	assert.Error(t, err)

	got, err = repo.Read(ctx, cert.ID, model.NewOwnerScope(vaultA, ownerID))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)

	got, err = repo.Read(ctx, cert.ID, model.NewAdminScope(otherUser))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)
}

func TestCertificateUpdate(t *testing.T) {
	repo := newScopeTestCertRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	cert := seedScopeCert(t, repo, ownerID, vaultA, "cert-b")

	updated := *cert
	updated.Name = "cert-b-renamed"
	require.NoError(t, repo.Update(ctx, &updated, model.NewVaultScope(vaultA, otherUser)))

	got, err := repo.Read(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "cert-b-renamed", got.Name)

	blocked := *cert
	blocked.Name = "should-not-land"
	assert.Error(t, repo.Update(ctx, &blocked, model.NewVaultScope(vaultB, otherUser)))
}

func TestCertificateList(t *testing.T) {
	repo := newScopeTestCertRepo(t)
	ctx := context.Background()

	ownerA, ownerB := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	seedScopeCert(t, repo, ownerA, vaultA, "cert-1")
	gone := seedScopeCert(t, repo, ownerA, vaultA, "cert-2")
	seedScopeCert(t, repo, ownerB, vaultB, "cert-3")
	require.NoError(t, repo.SoftDelete(ctx, gone.ID))

	live, err := repo.List(ctx, model.NewVaultScope(vaultA, ownerB), CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, live, 1)
	assert.Equal(t, vaultA, live[0].VaultID)

	deleted, err := repo.List(ctx, model.NewVaultScope(vaultA, ownerB), CertificateFilter{OnlyDeleted: true})
	require.NoError(t, err)
	require.Len(t, deleted, 1)
	assert.Equal(t, gone.ID, deleted[0].ID)

	byOwner, err := repo.List(ctx, model.NewOwnerScope(vaultB, ownerA), CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, byOwner, 1, "owner scope must not constrain vault_id")

	all, err := repo.List(ctx, model.NewAdminScope(uuid.Nil), CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 2)
}
