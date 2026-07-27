package keys

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// mockKeyRepository is a minimal testify mock for KeyRepositoryInterface.
type mockKeyRepository struct {
	mock.Mock
}

func (m *mockKeyRepository) Create(ctx context.Context, key *model.Key) error {
	return m.Called(ctx, key).Error(0)
}

func (m *mockKeyRepository) Read(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) Update(ctx context.Context, key *model.Key) error {
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

func (m *mockKeyRepository) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	args := m.Called(ctx, userID, keyType, tags)
	if v := args.Get(0); v != nil {
		return v.([]model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return m.Called(ctx, id, revoked).Error(0)
}

func (m *mockKeyRepository) RecoverKey(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepository) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Key, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]*model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
	return m.Called(ctx, keyID, version, value).Error(0)
}

func (m *mockKeyRepository) ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error) {
	args := m.Called(ctx, keyID, userID)
	if v := args.Get(0); v != nil {
		return v.([]model.KeyVersion), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	args := m.Called(ctx, vaultID, keyType, tags)
	if v := args.Get(0); v != nil {
		return v.([]model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, id, vaultID)
	if v := args.Get(0); v != nil {
		return v.(*model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *mockKeyRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *mockKeyRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyRepository) UpdateScoped(ctx context.Context, key *model.Key, scope model.Scope) error {
	args := m.Called(ctx, key, scope)
	return args.Error(0)
}

func (m *mockKeyRepository) ListScoped(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}

// TestDeleteKeySoftDeletes verifies that DeleteKey calls SoftDelete and not Delete.
func TestDeleteKeySoftDeletes(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()

	now := time.Now()
	existingKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
	}
	deletedKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
		DeletedAt: &now,
	}

	repo := &mockKeyRepository{}

	// DeleteKey reads via the scoped read — return the key so access check passes.
	repo.On("ReadScoped", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(existingKey, nil)

	// SoftDelete must be called once.
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)

	// ReadDeleted is called after SoftDelete to fetch metadata.
	repo.On("ReadDeleted", mock.Anything, keyID).Return(deletedKey, nil)

	// Delete must NOT be called — we register no expectation, and AssertNotCalled
	// below will confirm this.

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		Logger:        logger,
	})

	result, err := svc.DeleteKey(context.Background(), keyID, userID)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	repo.AssertCalled(t, "SoftDelete", mock.Anything, keyID)
	repo.AssertCalled(t, "ReadDeleted", mock.Anything, keyID)
	repo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	repo.AssertExpectations(t)
}

// TestDeleteKey_ReturnsDeletedRecord verifies that DeleteKey returns a non-nil
// *model.Key with DeletedAt populated after a successful soft-delete.
func TestDeleteKey_ReturnsDeletedRecord(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()

	now := time.Now()
	existingKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "my-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
	}
	deletedKey := &model.Key{
		ID:        keyID,
		UserID:    userID,
		Name:      "my-key",
		Type:      model.KeyTypeRSA,
		CreatedAt: now,
		Enabled:   true,
		DeletedAt: &now,
	}

	repo := &mockKeyRepository{}
	repo.On("ReadScoped", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(existingKey, nil)
	repo.On("SoftDelete", mock.Anything, keyID).Return(nil)
	repo.On("ReadDeleted", mock.Anything, keyID).Return(deletedKey, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		Logger:        logger,
	})

	result, err := svc.DeleteKey(context.Background(), keyID, userID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.DeletedAt, "DeletedAt must be populated in the returned record")
	assert.Equal(t, keyID, result.ID)
	assert.Equal(t, "my-key", result.Name)

	repo.AssertExpectations(t)
}
