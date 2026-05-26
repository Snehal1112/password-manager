package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/model"
	"rocketvault/internal/logging"
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
