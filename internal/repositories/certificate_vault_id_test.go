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

// TestCertificateRepository_ListByUser_PopulatesVaultID pins the fix for the
// copy-paste defect where ListByUser returned certificates with a zero VaultID.
func TestCertificateRepository_ListByUser_PopulatesVaultID(t *testing.T) {
	db := setupFullCertDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	userID := uuid.New()
	vaultID := uuid.New()
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		VaultID:     vaultID,
		Name:        "listed-cert",
		Certificate: "PEM",
		PrivateKey:  "ENC",
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(ctx, cert))

	certs, err := repo.ListByUser(ctx, userID, nil)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, vaultID, certs[0].VaultID, "ListByUser must populate VaultID from the row")
}

// TestCertificateRepository_ListInVault_NoTypeFilter pins that the dead
// certType parameter is gone; the certificates table has no type column.
func TestCertificateRepository_ListInVault_NoTypeFilter(t *testing.T) {
	db := setupFullCertDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	for _, name := range []string{"cert-a", "cert-b"} {
		require.NoError(t, repo.Create(ctx, &model.Certificate{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			VaultID:     vaultID,
			Name:        name,
			Certificate: "PEM",
			PrivateKey:  "ENC",
			CreatedAt:   time.Now().UTC(),
			Enabled:     true,
			RenewalDays: 30,
		}))
	}

	certs, err := repo.ListInVault(ctx, vaultID, nil)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}
