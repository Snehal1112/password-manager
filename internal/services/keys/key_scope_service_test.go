package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// newKeyScopeFixture builds a keyService over a mock repository.
func newKeyScopeFixture(t *testing.T) (*mockKeyRepository, *keyService) {
	t.Helper()
	repo := new(mockKeyRepository)
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return repo, &keyService{
		keyRepo:  repo,
		keyCache: nil,
		logger:   &logging.Logger{Logger: l},
	}
}

func TestGetKeyScopedPassesTheScopeToTheRepository(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil).Once()

	got, err := svc.GetKeyScoped(ctx, keyID, scope)
	require.NoError(t, err)
	assert.Equal(t, keyID, got.ID)
	repo.AssertExpectations(t)
}

func TestGetKeyScopedEnforcesLifecycle(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, Enabled: false}, nil).Once()

	_, err := svc.GetKeyScoped(ctx, keyID, scope)
	assert.ErrorIs(t, err, ErrKeyLifecycleDenied)
}

func TestListKeysScopedForwardsTheFilter(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	scope := model.NewVaultScope(uuid.New(), uuid.New())
	filter := repositories.KeyFilter{Type: model.KeyTypeRSA, Tags: []string{"prod"}}
	repo.On("ListScoped", ctx, scope, filter).Return([]model.Key{{ID: uuid.New()}}, nil).Once()

	got, err := svc.ListKeysScoped(ctx, scope, filter)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	repo.AssertExpectations(t)
}

func TestUpdateKeyScopedUsesTheSameScopeForReadAndWrite(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	name := "renamed"

	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Name: "original", Enabled: true}, nil).Once()
	repo.On("UpdateScoped", ctx, mock.MatchedBy(func(k *model.Key) bool {
		return k.Name == "renamed"
	}), scope).Return(nil).Once()

	require.NoError(t, svc.UpdateKeyScoped(ctx, UpdateKeyRequest{KeyID: keyID, Scope: scope, Name: &name}))
	repo.AssertExpectations(t)
}

func TestDeleteKeyScopedKeepsTheB6VaultConjunction(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID := uuid.New()
	ownerID := uuid.New()
	requestedVault, actualVault := uuid.New(), uuid.New()
	scope := model.NewOwnerScope(requestedVault, ownerID)

	// The owner predicate matches, but the key lives in another vault.
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: actualVault, Enabled: true}, nil).Once()

	_, err := svc.DeleteKeyScoped(ctx, keyID, scope)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	repo.AssertNotCalled(t, "SoftDelete", mock.Anything, mock.Anything)
}

func TestDeleteKeyScopedSoftDeletesInScope(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())

	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil).Once()
	repo.On("SoftDelete", ctx, keyID).Return(nil).Once()
	repo.On("ReadDeleted", ctx, keyID).Return(&model.Key{ID: keyID}, nil).Once()

	deleted, err := svc.DeleteKeyScoped(ctx, keyID, scope)
	require.NoError(t, err)
	assert.Equal(t, keyID, deleted.ID)
	repo.AssertExpectations(t)
}
