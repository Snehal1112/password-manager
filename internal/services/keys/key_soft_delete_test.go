package keys

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
)

// mockKeyRepository is a minimal testify mock for KeyRepositoryInterface.
type mockKeyRepository struct {
	mock.Mock
}

func (m *mockKeyRepository) Create(ctx context.Context, key *domain.Key) error {
	return m.Called(ctx, key).Error(0)
}

func (m *mockKeyRepository) Read(ctx context.Context, id uuid.UUID) (*domain.Key, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*domain.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) Update(ctx context.Context, key *domain.Key) error {
	return m.Called(ctx, key).Error(0)
}

func (m *mockKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepository) PurgeKey(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return m.Called(ctx, id, enabled).Error(0)
}

func (m *mockKeyRepository) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]domain.Key, error) {
	args := m.Called(ctx, userID, keyType, tags)
	if v := args.Get(0); v != nil {
		return v.([]domain.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return m.Called(ctx, id, revoked).Error(0)
}

func (m *mockKeyRepository) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*domain.Key, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]*domain.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

// TestDeleteKeySoftDeletes verifies that DeleteKey calls SoftDelete and not Delete.
func TestDeleteKeySoftDeletes(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()

	existingKey := &domain.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		Type:      domain.KeyTypeRSA,
		CreatedAt: time.Now(),
	}

	repo := &mockKeyRepository{}

	// GetKey calls Read internally — return the key so access check passes.
	repo.On("Read", mock.Anything, keyID).Return(existingKey, nil)

	// SoftDelete must be called once.
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)

	// Delete must NOT be called — we register no expectation, and AssertNotCalled
	// below will confirm this.

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		Logger:        logger,
	})

	err := svc.DeleteKey(context.Background(), keyID, userID)
	assert.NoError(t, err)

	repo.AssertCalled(t, "SoftDelete", mock.Anything, keyID)
	repo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	repo.AssertExpectations(t)
}
