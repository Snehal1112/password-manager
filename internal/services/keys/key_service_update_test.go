package keys

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func boolPtr(b bool) *bool { return &b }

func TestUpdateKey_SetsRevoked(t *testing.T) {
	repo := &mockKeyRepository{}
	logger := &logging.Logger{Logger: logrus.New()}
	svc := &keyService{keyRepo: repo, logger: logger}

	ownerID := uuid.New()
	keyID := uuid.New()
	existing := &model.Key{ID: keyID, UserID: ownerID, Name: "old-name", Type: "RSA", Revoked: false, Enabled: true}

	repo.On("Read", mock.Anything, keyID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.Revoked == true
	})).Return(nil)

	err := svc.UpdateKey(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		UserID:  ownerID,
		Revoked: boolPtr(true),
	})

	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestUpdateKey_ClearsRevoked(t *testing.T) {
	repo := &mockKeyRepository{}
	logger := &logging.Logger{Logger: logrus.New()}
	svc := &keyService{keyRepo: repo, logger: logger}

	ownerID := uuid.New()
	keyID := uuid.New()
	existing := &model.Key{ID: keyID, UserID: ownerID, Name: "old-name", Type: "RSA", Revoked: true, Enabled: true}

	repo.On("Read", mock.Anything, keyID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *model.Key) bool {
		return k.Revoked == false
	})).Return(nil)

	err := svc.UpdateKey(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		UserID:  ownerID,
		Revoked: boolPtr(false),
	})

	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestUpdateKeyInVault_HappyPath(t *testing.T) {
	repo := &mockKeyRepository{}
	logger := &logging.Logger{Logger: logrus.New()}

	keyID := uuid.New()
	vaultID := uuid.New()
	ownerID := uuid.New()
	callerID := uuid.New() // a different vault member than the key's owner

	stored := &model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Name: "old"}
	repo.On("ReadInVault", mock.Anything, keyID, vaultID).Return(stored, nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key")).Return(nil)

	svc := &keyService{keyRepo: repo, logger: logger}

	newName := "new-name"
	err := svc.UpdateKeyInVault(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		UserID:  callerID,
		VaultID: vaultID,
		Name:    &newName,
	})

	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestUpdateKeyInVault_WrongVault(t *testing.T) {
	repo := &mockKeyRepository{}
	logger := &logging.Logger{Logger: logrus.New()}

	keyID := uuid.New()
	vaultID := uuid.New()

	repo.On("ReadInVault", mock.Anything, keyID, vaultID).Return(nil, errors.New("key not found or access denied"))

	svc := &keyService{keyRepo: repo, logger: logger}
	err := svc.UpdateKeyInVault(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		UserID:  uuid.New(),
		VaultID: vaultID,
	})

	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// fakeAuditPersister records every persisted audit event's actor (userID)
// for assertions. It implements logging.AuditPersister.
type fakeAuditPersister struct {
	actors []string
}

func (f *fakeAuditPersister) PersistAudit(userID, action, details string) error {
	f.actors = append(f.actors, userID)
	return nil
}

// TestUpdateKeyInVault_AuditRowsAttributeTheActor_NotTheOwner uses a real
// KeyRepository (not a mock) so both the service-layer and repository-layer
// audit calls actually fire, proving they no longer disagree.
func TestUpdateKeyInVault_AuditRowsAttributeTheActor_NotTheOwner(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer sqlDB.Close()
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL,
		bits INTEGER NOT NULL DEFAULT 0,
		curve TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NULL
	)`)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS key_tags (
		key_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (key_id, tag)
	)`)
	require.NoError(t, err)

	logger := &logging.Logger{Logger: logrus.New()}
	persister := &fakeAuditPersister{}
	logger.SetAuditPersister(persister)

	keyRepo := repositories.NewKeyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), logger)

	ownerID := uuid.New()
	callerID := uuid.New() // a different vault member than the key's owner
	vaultID := uuid.New()
	keyID := uuid.New()
	require.NoError(t, keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID, Name: "old", Type: "RSA", Value: "enc", Enabled: true,
	}))

	// Create() legitimately attributes its own audit row to the owner; reset
	// here so the assertions below only cover the update flow under test.
	persister.actors = nil

	svc := NewKeyService(KeyServiceConfig{KeyRepository: keyRepo, Logger: logger})

	newName := "new-name"
	err = svc.UpdateKeyInVault(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		UserID:  callerID,
		VaultID: vaultID,
		Name:    &newName,
	})
	require.NoError(t, err)

	require.NotEmpty(t, persister.actors)
	for _, actor := range persister.actors {
		assert.Equal(t, callerID.String(), actor,
			"every audit row for a vault-scoped key update must attribute the actor (caller), not the key's owner")
	}
}
