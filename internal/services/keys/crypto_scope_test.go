package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// newTestKeyLogger builds a logging.Logger suitable for tests: a real logrus
// logger silenced at PanicLevel so audit-log calls in loadAndAuthorize do not
// spam test output.
func newTestKeyLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &logging.Logger{Logger: l}
}

func newCryptoScopeFixture(t *testing.T) (*mockKeyRepository, *cryptoService) {
	t.Helper()
	repo := new(mockKeyRepository)
	return repo, &cryptoService{keyRepo: repo, logger: newTestKeyLogger(t)}
}

func TestLoadAndAuthorizeUsesTheScopedRead(t *testing.T) {
	repo, svc := newCryptoScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()
	scope := model.NewOwnerScope(vaultID, ownerID)
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Enabled: true}, nil).Once()

	key, err := svc.loadAndAuthorize(ctx, keyID, scope, "sign")
	require.NoError(t, err)
	assert.Equal(t, keyID, key.ID)
	repo.AssertExpectations(t)
}

func TestLoadAndAuthorizeKeepsTheB6VaultConjunction(t *testing.T) {
	repo, svc := newCryptoScopeFixture(t)
	ctx := context.Background()

	keyID, ownerID := uuid.New(), uuid.New()
	requestedVault, actualVault := uuid.New(), uuid.New()
	scope := model.NewOwnerScope(requestedVault, ownerID)
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: actualVault, Enabled: true}, nil).Once()

	_, err := svc.loadAndAuthorize(ctx, keyID, scope, "sign")
	assert.ErrorIs(t, err, ErrKeyForbidden)
}

func TestLoadAndAuthorizeRejectsRevokedAndInaccessibleKeys(t *testing.T) {
	ctx := context.Background()
	keyID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()
	scope := model.NewOwnerScope(vaultID, ownerID)

	repo, svc := newCryptoScopeFixture(t)
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Enabled: true, Revoked: true}, nil).Once()
	_, err := svc.loadAndAuthorize(ctx, keyID, scope, "sign")
	assert.ErrorIs(t, err, ErrKeyRevoked)

	repo2, svc2 := newCryptoScopeFixture(t)
	repo2.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Enabled: false}, nil).Once()
	_, err = svc2.loadAndAuthorize(ctx, keyID, scope, "sign")
	assert.ErrorIs(t, err, ErrKeyLifecycleDenied)
}

func TestLoadAndAuthorizeDeniesOutOfScope(t *testing.T) {
	repo, svc := newCryptoScopeFixture(t)
	ctx := context.Background()

	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, keyID, scope).Return(nil, assert.AnError).Once()

	_, err := svc.loadAndAuthorize(ctx, keyID, scope, "sign")
	assert.Error(t, err)
}
