package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestCertificateRepositoryInterfaceExposesScopedMethods(t *testing.T) {
	db := setupFullCertDB(t)
	var repo repositories.CertificateRepositoryInterface = repositories.NewCertificateRepository(
		rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID, vaultID := uuid.New(), uuid.New()
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      ownerID,
		VaultID:     vaultID,
		KeyID:       uuid.New(),
		Name:        "iface-cert",
		Certificate: "PEM",
		PrivateKey:  "ENC",
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(ctx, cert))

	got, err := repo.ReadScoped(ctx, cert.ID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)

	got.Name = "iface-cert-renamed"
	require.NoError(t, repo.UpdateScoped(ctx, got, model.NewVaultScope(vaultID, ownerID)))

	list, err := repo.ListScoped(ctx, model.NewVaultScope(vaultID, ownerID), repositories.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "iface-cert-renamed", list[0].Name)
}
