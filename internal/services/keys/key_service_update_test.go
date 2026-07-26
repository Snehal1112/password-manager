package keys

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/internal/logging"
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
