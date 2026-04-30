package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
)

func boolPtr(b bool) *bool { return &b }

type mockKeyRepoForUpdate struct{ mock.Mock }

func (m *mockKeyRepoForUpdate) Read(ctx context.Context, id uuid.UUID) (*domain.Key, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Key), args.Error(1)
}
func (m *mockKeyRepoForUpdate) Update(ctx context.Context, key *domain.Key) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}
func (m *mockKeyRepoForUpdate) Create(ctx context.Context, key *domain.Key) error { return nil }
func (m *mockKeyRepoForUpdate) Delete(ctx context.Context, id uuid.UUID) error    { return nil }
func (m *mockKeyRepoForUpdate) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]domain.Key, error) {
	return nil, nil
}
func (m *mockKeyRepoForUpdate) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return nil
}
func (m *mockKeyRepoForUpdate) SoftDelete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockKeyRepoForUpdate) RecoverKey(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockKeyRepoForUpdate) PurgeKey(ctx context.Context, id uuid.UUID) error   { return nil }
func (m *mockKeyRepoForUpdate) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return nil
}
func (m *mockKeyRepoForUpdate) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*domain.Key, error) {
	return nil, nil
}

func TestUpdateKey_SetsRevoked(t *testing.T) {
	repo := &mockKeyRepoForUpdate{}
	logger := &logging.Logger{Logger: logrus.New()}
	svc := &keyService{keyRepo: repo, logger: logger}

	ownerID := uuid.New()
	keyID := uuid.New()
	existing := &domain.Key{ID: keyID, UserID: ownerID, Name: "old-name", Type: "RSA", Revoked: false}

	repo.On("Read", mock.Anything, keyID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(k *domain.Key) bool {
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
