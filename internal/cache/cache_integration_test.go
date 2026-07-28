package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// Mock SecretService
// ---------------------------------------------------------------------------

type mockSecretService struct {
	// per-call return values
	getSecretFn                     func(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error)
	getSecretScopedFn               func(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error)
	listSecretsScopedFn             func(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error)
	deleteSecretScopedFn            func(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	listDeletedSecretsScopedFn      func(ctx context.Context, scope model.Scope) ([]model.Secret, error)
	createSecretFn                  func(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error)
	updateSecretScopedFn            func(ctx context.Context, req secrets.UpdateSecretRequest) error
	updateSecretFn                  func(ctx context.Context, req secrets.UpdateSecretRequest) error
	updateSecretInVaultFn           func(ctx context.Context, req secrets.UpdateSecretRequest) error
	deleteSecretFn                  func(ctx context.Context, secretID, userID uuid.UUID) error
	listSecretsFn                   func(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error)
	getSecretInVaultFn              func(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error)
	listSecretsInVaultFn            func(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error)
	deleteSecretInVaultFn           func(ctx context.Context, secretID, vaultID uuid.UUID) error
	getSecretVersionsFn             func(ctx context.Context, secretID, userID uuid.UUID) ([]model.SecretVersion, error)
	getSecretVersionFn              func(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error)
	getLatestSecretVersionFn        func(ctx context.Context, secretID, userID uuid.UUID) (*model.SecretVersion, error)
	getSecretVersionsInVaultFn      func(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error)
	getSecretVersionInVaultFn       func(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error)
	getLatestSecretVersionInVaultFn func(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error)
	getSecretVersionsScopedFn       func(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)
	getSecretVersionScopedFn        func(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)
	getLatestSecretVersionScopedFn  func(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)
	generateSecretFn                func(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error)
	exportSecretsFn                 func(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error)
	importSecretsFn                 func(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error)
	recoverSecretScopedFn           func(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	purgeSecretScopedFn             func(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
}

// compile-time check
var _ secrets.SecretService = (*mockSecretService)(nil)

func (m *mockSecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	if m.getSecretFn != nil {
		return m.getSecretFn(ctx, secretID, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	if m.getSecretScopedFn != nil {
		return m.getSecretScopedFn(ctx, secretID, scope)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	if m.listSecretsScopedFn != nil {
		return m.listSecretsScopedFn(ctx, scope, tags)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if m.deleteSecretScopedFn != nil {
		return m.deleteSecretScopedFn(ctx, secretID, scope)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	if m.listDeletedSecretsScopedFn != nil {
		return m.listDeletedSecretsScopedFn(ctx, scope)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
	if m.createSecretFn != nil {
		return m.createSecretFn(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) UpdateSecretScoped(ctx context.Context, req secrets.UpdateSecretRequest) error {
	if m.updateSecretScopedFn != nil {
		return m.updateSecretScopedFn(ctx, req)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) UpdateSecret(ctx context.Context, req secrets.UpdateSecretRequest) error {
	if m.updateSecretFn != nil {
		return m.updateSecretFn(ctx, req)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) UpdateSecretInVault(ctx context.Context, req secrets.UpdateSecretRequest) error {
	if m.updateSecretInVaultFn != nil {
		return m.updateSecretInVaultFn(ctx, req)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, secretID, userID)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	if m.listSecretsFn != nil {
		return m.listSecretsFn(ctx, userID, tags)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	if m.getSecretInVaultFn != nil {
		return m.getSecretInVaultFn(ctx, secretID, vaultID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	if m.listSecretsInVaultFn != nil {
		return m.listSecretsInVaultFn(ctx, vaultID, tags)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error {
	if m.deleteSecretInVaultFn != nil {
		return m.deleteSecretInVaultFn(ctx, secretID, vaultID)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) GetSecretVersions(ctx context.Context, secretID, userID uuid.UUID) ([]model.SecretVersion, error) {
	if m.getSecretVersionsFn != nil {
		return m.getSecretVersionsFn(ctx, secretID, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
	if m.getSecretVersionFn != nil {
		return m.getSecretVersionFn(ctx, secretID, version, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetLatestSecretVersion(ctx context.Context, secretID, userID uuid.UUID) (*model.SecretVersion, error) {
	if m.getLatestSecretVersionFn != nil {
		return m.getLatestSecretVersionFn(ctx, secretID, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetSecretVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	if m.getSecretVersionsInVaultFn != nil {
		return m.getSecretVersionsInVaultFn(ctx, secretID, vaultID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetSecretVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	if m.getSecretVersionInVaultFn != nil {
		return m.getSecretVersionInVaultFn(ctx, secretID, version, vaultID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetLatestSecretVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	if m.getLatestSecretVersionInVaultFn != nil {
		return m.getLatestSecretVersionInVaultFn(ctx, secretID, vaultID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetSecretVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	if m.getSecretVersionsScopedFn != nil {
		return m.getSecretVersionsScopedFn(ctx, secretID, scope)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetSecretVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	if m.getSecretVersionScopedFn != nil {
		return m.getSecretVersionScopedFn(ctx, secretID, version, scope)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetLatestSecretVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	if m.getLatestSecretVersionScopedFn != nil {
		return m.getLatestSecretVersionScopedFn(ctx, secretID, scope)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GenerateSecret(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error) {
	if m.generateSecretFn != nil {
		return m.generateSecretFn(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) ExportSecrets(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error) {
	if m.exportSecretsFn != nil {
		return m.exportSecretsFn(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) ImportSecrets(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
	if m.importSecretsFn != nil {
		return m.importSecretsFn(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if m.recoverSecretScopedFn != nil {
		return m.recoverSecretScopedFn(ctx, secretID, scope)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if m.purgeSecretScopedFn != nil {
		return m.purgeSecretScopedFn(ctx, secretID, scope)
	}
	return errors.New("not implemented")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestCache(t *testing.T) *SecretCache {
	t.Helper()
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	return NewSecretCache(5*time.Minute, logger)
}

func newTestLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return l
}

func makeSecret(userID uuid.UUID) *model.Secret {
	return &model.Secret{
		ID:        uuid.New(),
		UserID:    userID,
		Name:      "test-secret",
		Value:     "encrypted-value",
		Version:   1,
		CreatedAt: time.Now(),
		Enabled:   true, // accessible by default; individual tests override as needed.
	}
}

// ---------------------------------------------------------------------------
// NewCachedSecretService
// ---------------------------------------------------------------------------

func TestNewCachedSecretService(t *testing.T) {
	svc := &mockSecretService{}
	c := newTestCache(t)
	logger := newTestLogger()

	cached := NewCachedSecretService(svc, c, logger)
	require.NotNil(t, cached)
}

// ---------------------------------------------------------------------------
// GetSecret
// ---------------------------------------------------------------------------

// Re-enabled in Phase 5: GetSecret is a shim over GetSecretScoped, which now
// caches. The first call delegates to the base service; the second is served
// from cache.
func TestCachedSecretService_GetSecret_CachesOnFirstCall(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)

	callCount := 0
	svc := &mockSecretService{
		getSecretScopedFn: func(_ context.Context, sid uuid.UUID, scope model.Scope) (*model.Secret, error) {
			callCount++
			assert.Equal(t, secret.ID, sid)
			ownerID, ok := scope.OwnerID()
			require.True(t, ok)
			assert.Equal(t, userID, ownerID)
			return secret, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	// First call — delegates to base service and populates the cache.
	got, err := cached.GetSecret(ctx, secret.ID, userID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)

	// Second call — served from cache; base service is not consulted again.
	got2, err := cached.GetSecret(ctx, secret.ID, userID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got2.ID)
	assert.Equal(t, 1, callCount, "GetSecret must serve the second call from cache")
}

// ---------------------------------------------------------------------------
// UpdateSecret
// ---------------------------------------------------------------------------

func TestCachedSecretService_UpdateSecretInVault_InvalidatesCache(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	// Pre-populate cache.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, scope))

	svc := &mockSecretService{
		updateSecretInVaultFn: func(_ context.Context, _ secrets.UpdateSecretRequest) error {
			return nil
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	req := secrets.UpdateSecretRequest{SecretID: secret.ID, VaultID: uuid.New()}
	err := cached.UpdateSecretInVault(ctx, req)
	require.NoError(t, err)

	// Cache should be invalidated, same as the owner-scoped UpdateSecret.
	_, found := c.Get(ctx, secret.ID, scope)
	assert.False(t, found, "vault-scoped update must invalidate the cache so GET does not serve stale plaintext")
}

func TestCachedSecretService_GetSecret_CacheHitWrongUser(t *testing.T) {
	ctx := context.Background()
	ownerID := uuid.New()
	otherID := uuid.New()
	secret := makeSecret(ownerID)

	// Pre-populate the cache under ownerID's owner scope.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, model.NewOwnerScope(uuid.Nil, ownerID)))

	fetchCount := 0
	svc := &mockSecretService{
		getSecretScopedFn: func(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
			fetchCount++
			return nil, errors.New("no access")
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	// Request from a different user — the compound key means the entry
	// cached under ownerID's scope does not satisfy otherID's scope, so the
	// service must fall through to the base service.
	_, err := cached.GetSecret(ctx, secret.ID, otherID)
	assert.Error(t, err)
	assert.Equal(t, 1, fetchCount, "base service should have been called for wrong-user cache hit")
}

func TestCachedSecretService_GetSecret_CacheHitInaccessible_FallsThrough(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)
	secret.Enabled = false // disabled while cached

	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, model.NewOwnerScope(uuid.Nil, userID)))

	fetchCount := 0
	svc := &mockSecretService{
		getSecretScopedFn: func(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
			fetchCount++
			return nil, errors.New("secret is disabled or outside its valid time window")
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.GetSecret(ctx, secret.ID, userID)
	assert.Error(t, err)
	assert.Equal(t, 1, fetchCount, "a disabled cached secret must fall through to the base service, not be served from cache")
}

func TestCachedSecretService_GetSecret_BaseServiceError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	svc := &mockSecretService{
		getSecretScopedFn: func(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
			return nil, errors.New("db error")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.GetSecret(ctx, secretID, userID)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// CreateSecret
// ---------------------------------------------------------------------------

func TestCachedSecretService_CreateSecret_Success(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)

	svc := &mockSecretService{
		createSecretFn: func(_ context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
			return secret, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	req := secrets.CreateSecretRequest{UserID: userID, Name: "test-secret", Value: "value"}
	got, err := cached.CreateSecret(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)

	// CreateSecret does not know the reading scope, so it must not populate
	// the cache; the first read does that instead.
	_, found := c.Get(ctx, secret.ID, model.NewOwnerScope(uuid.Nil, userID))
	assert.False(t, found, "CreateSecret must not cache on write")
}

func TestCachedSecretService_CreateSecret_BaseError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	svc := &mockSecretService{
		createSecretFn: func(_ context.Context, _ secrets.CreateSecretRequest) (*model.Secret, error) {
			return nil, errors.New("create failed")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.CreateSecret(ctx, secrets.CreateSecretRequest{UserID: userID})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// UpdateSecret
// ---------------------------------------------------------------------------

func TestCachedSecretService_UpdateSecret_InvalidatesCache(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	// Pre-populate cache.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, scope))

	svc := &mockSecretService{
		updateSecretFn: func(_ context.Context, _ secrets.UpdateSecretRequest) error {
			return nil
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	req := secrets.UpdateSecretRequest{SecretID: secret.ID, UserID: userID}
	err := cached.UpdateSecret(ctx, req)
	require.NoError(t, err)

	// Cache should be invalidated.
	_, found := c.Get(ctx, secret.ID, scope)
	assert.False(t, found)
}

func TestCachedSecretService_UpdateSecret_BaseError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	svc := &mockSecretService{
		updateSecretFn: func(_ context.Context, _ secrets.UpdateSecretRequest) error {
			return errors.New("update failed")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, UserID: userID})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// DeleteSecret
// ---------------------------------------------------------------------------

func TestCachedSecretService_DeleteSecret_RemovesFromCache(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	// Pre-populate cache.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, scope))

	svc := &mockSecretService{
		deleteSecretFn: func(_ context.Context, _, _ uuid.UUID) error {
			return nil
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.DeleteSecret(ctx, secret.ID, userID)
	require.NoError(t, err)

	_, found := c.Get(ctx, secret.ID, scope)
	assert.False(t, found)
}

func TestCachedSecretService_DeleteSecret_BaseError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	svc := &mockSecretService{
		deleteSecretFn: func(_ context.Context, _, _ uuid.UUID) error {
			return errors.New("delete failed")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.DeleteSecret(ctx, secretID, userID)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListSecrets
// ---------------------------------------------------------------------------

func TestCachedSecretService_ListSecrets_DelegatesToBase(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	expected := []model.Secret{{ID: uuid.New(), UserID: userID, Name: "s1"}}

	svc := &mockSecretService{
		listSecretsFn: func(_ context.Context, uid uuid.UUID, tags []string) ([]model.Secret, error) {
			assert.Equal(t, userID, uid)
			return expected, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.ListSecrets(ctx, userID, nil)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, expected[0].ID, got[0].ID)
}

func TestCachedSecretService_ListSecrets_BaseError(t *testing.T) {
	ctx := context.Background()

	svc := &mockSecretService{
		listSecretsFn: func(_ context.Context, _ uuid.UUID, _ []string) ([]model.Secret, error) {
			return nil, errors.New("list error")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.ListSecrets(ctx, uuid.New(), nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Vault-scoped methods
// ---------------------------------------------------------------------------

func TestCachedSecretService_GetSecretInVault_Delegates(t *testing.T) {
	ctx := context.Background()
	vaultID := uuid.New()
	secret := makeSecret(uuid.New())

	svc := &mockSecretService{
		getSecretInVaultFn: func(_ context.Context, sid, vid uuid.UUID) (*model.Secret, error) {
			assert.Equal(t, secret.ID, sid)
			assert.Equal(t, vaultID, vid)
			return secret, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.GetSecretInVault(ctx, secret.ID, vaultID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)
}

func TestCachedSecretService_ListSecretsInVault_Delegates(t *testing.T) {
	ctx := context.Background()
	vaultID := uuid.New()
	expected := []model.Secret{{ID: uuid.New(), Name: "vault-secret"}}

	svc := &mockSecretService{
		listSecretsInVaultFn: func(_ context.Context, vid uuid.UUID, tags []string) ([]model.Secret, error) {
			assert.Equal(t, vaultID, vid)
			return expected, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.ListSecretsInVault(ctx, vaultID, nil)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestCachedSecretService_DeleteSecretInVault_RemovesFromCache(t *testing.T) {
	ctx := context.Background()
	vaultID := uuid.New()
	secret := makeSecret(uuid.New())
	scope := model.NewVaultScope(vaultID, uuid.New())

	// Pre-populate cache.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, scope))

	svc := &mockSecretService{
		deleteSecretInVaultFn: func(_ context.Context, sid, vid uuid.UUID) error {
			assert.Equal(t, secret.ID, sid)
			assert.Equal(t, vaultID, vid)
			return nil
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.DeleteSecretInVault(ctx, secret.ID, vaultID)
	require.NoError(t, err)

	_, found := c.Get(ctx, secret.ID, scope)
	assert.False(t, found)
}

func TestCachedSecretService_DeleteSecretInVault_BaseError(t *testing.T) {
	ctx := context.Background()

	svc := &mockSecretService{
		deleteSecretInVaultFn: func(_ context.Context, _, _ uuid.UUID) error {
			return errors.New("vault delete error")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.DeleteSecretInVault(ctx, uuid.New(), uuid.New())
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Version methods
// ---------------------------------------------------------------------------

func TestCachedSecretService_GetSecretVersions_Delegates(t *testing.T) {
	ctx := context.Background()
	secretID := uuid.New()
	userID := uuid.New()
	versions := []model.SecretVersion{{SecretID: secretID, Version: 1}}

	svc := &mockSecretService{
		getSecretVersionsFn: func(_ context.Context, sid, uid uuid.UUID) ([]model.SecretVersion, error) {
			assert.Equal(t, secretID, sid)
			assert.Equal(t, userID, uid)
			return versions, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.GetSecretVersions(ctx, secretID, userID)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestCachedSecretService_GetSecretVersion_Delegates(t *testing.T) {
	ctx := context.Background()
	secretID := uuid.New()
	userID := uuid.New()
	sv := &model.SecretVersion{SecretID: secretID, Version: 2}

	svc := &mockSecretService{
		getSecretVersionFn: func(_ context.Context, sid uuid.UUID, ver int, uid uuid.UUID) (*model.SecretVersion, error) {
			assert.Equal(t, secretID, sid)
			assert.Equal(t, 2, ver)
			assert.Equal(t, userID, uid)
			return sv, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.GetSecretVersion(ctx, secretID, 2, userID)
	require.NoError(t, err)
	assert.Equal(t, 2, got.Version)
}

func TestCachedSecretService_GetLatestSecretVersion_Delegates(t *testing.T) {
	ctx := context.Background()
	secretID := uuid.New()
	userID := uuid.New()
	sv := &model.SecretVersion{SecretID: secretID, Version: 5}

	svc := &mockSecretService{
		getLatestSecretVersionFn: func(_ context.Context, sid, uid uuid.UUID) (*model.SecretVersion, error) {
			assert.Equal(t, secretID, sid)
			assert.Equal(t, userID, uid)
			return sv, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.GetLatestSecretVersion(ctx, secretID, userID)
	require.NoError(t, err)
	assert.Equal(t, 5, got.Version)
}

// ---------------------------------------------------------------------------
// GenerateSecret
// ---------------------------------------------------------------------------

func TestCachedSecretService_GenerateSecret_DoesNotCacheOnWrite(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)

	svc := &mockSecretService{
		generateSecretFn: func(_ context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error) {
			return secret, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	req := secrets.GenerateSecretRequest{UserID: userID, Name: "gen-secret", Length: 32}
	got, err := cached.GenerateSecret(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)

	// GenerateSecret does not know the reading scope, so it must not
	// populate the cache; the first read does that instead.
	_, found := c.Get(ctx, secret.ID, model.NewOwnerScope(uuid.Nil, userID))
	assert.False(t, found, "GenerateSecret must not cache on write")
}

func TestCachedSecretService_GenerateSecret_BaseError(t *testing.T) {
	ctx := context.Background()

	svc := &mockSecretService{
		generateSecretFn: func(_ context.Context, _ secrets.GenerateSecretRequest) (*model.Secret, error) {
			return nil, errors.New("gen failed")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.GenerateSecret(ctx, secrets.GenerateSecretRequest{})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ExportSecrets
// ---------------------------------------------------------------------------

func TestCachedSecretService_ExportSecrets_Delegates(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	payload := []byte(`{"secrets":[]}`)

	svc := &mockSecretService{
		exportSecretsFn: func(_ context.Context, req secrets.ExportSecretsRequest) ([]byte, error) {
			assert.Equal(t, userID, req.UserID)
			return payload, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	req := secrets.ExportSecretsRequest{UserID: userID}
	got, err := cached.ExportSecrets(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestCachedSecretService_ExportSecrets_BaseError(t *testing.T) {
	ctx := context.Background()

	svc := &mockSecretService{
		exportSecretsFn: func(_ context.Context, _ secrets.ExportSecretsRequest) ([]byte, error) {
			return nil, errors.New("export error")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.ExportSecrets(ctx, secrets.ExportSecretsRequest{})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ImportSecrets
// ---------------------------------------------------------------------------

func TestCachedSecretService_ImportSecrets_ClearsCache(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	// Pre-populate cache with a secret.
	secret := makeSecret(userID)
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, model.NewVaultScope(uuid.New(), uuid.New())))

	result := &secrets.ImportResult{ImportedCount: 3, TotalCount: 3}
	svc := &mockSecretService{
		importSecretsFn: func(_ context.Context, _ secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
			return result, nil
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	req := secrets.ImportSecretsRequest{UserID: userID}
	got, err := cached.ImportSecrets(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 3, got.ImportedCount)

	// ImportSecrets calls Flush (not Clear) to invalidate the cache; that
	// behavior is asserted separately in
	// TestCachedSecretService_ImportSecrets_FlushesLiveCacheEntries below.
	// This test only verifies the import result is returned correctly.
}

func TestCachedSecretService_ImportSecrets_FlushesLiveCacheEntries(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	// Pre-populate cache with a live (non-expired) secret.
	secret := makeSecret(userID)
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, scope))

	svc := &mockSecretService{
		importSecretsFn: func(_ context.Context, _ secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
			return &secrets.ImportResult{ImportedCount: 1, TotalCount: 1}, nil
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.ImportSecrets(ctx, secrets.ImportSecretsRequest{UserID: userID})
	require.NoError(t, err)

	// SecretCache.Clear only prunes expired entries, so a live entry
	// surviving import means "clear cache to ensure consistency" is a no-op
	// for anything still within its TTL. Flush must be used instead.
	_, found := c.Get(ctx, secret.ID, scope)
	assert.False(t, found, "ImportSecrets must flush live cache entries, not just expired ones")
}

func TestCachedSecretService_ImportSecrets_BaseError(t *testing.T) {
	ctx := context.Background()

	svc := &mockSecretService{
		importSecretsFn: func(_ context.Context, _ secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
			return nil, errors.New("import failed")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.ImportSecrets(ctx, secrets.ImportSecretsRequest{})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// GetCacheStats / ClearCache / StartCacheCleanup
// ---------------------------------------------------------------------------

func TestCachedSecretService_GetCacheStats(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)

	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret, model.NewVaultScope(uuid.New(), uuid.New())))

	svc := &mockSecretService{}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	stats := cached.GetCacheStats()
	require.NotNil(t, stats)
	assert.Equal(t, 1, stats["total_entries"])
}

func TestCachedSecretService_ClearCache(t *testing.T) {
	ctx := context.Background()

	c := newTestCache(t)
	svc := &mockSecretService{}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.ClearCache(ctx)
	assert.NoError(t, err)
}

func TestCachedSecretService_StartCacheCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := newTestCache(t)
	svc := &mockSecretService{}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	// StartCacheCleanup should not panic or block.
	cached.StartCacheCleanup(ctx, 50*time.Millisecond)

	// Give the goroutine a moment to start, then cancel to stop it.
	time.Sleep(10 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// countingSecretService: a minimal SecretService stub for the scoped-caching
// tests below. It counts GetSecretScoped calls and mirrors the real
// service's behavior of erroring once the secret is no longer accessible.
// ---------------------------------------------------------------------------

type countingSecretService struct {
	secrets.SecretService
	secret         *model.Secret
	getScopedCalls int
}

func (c *countingSecretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	c.getScopedCalls++
	if !c.secret.IsAccessible() {
		return nil, errors.New("secret is disabled or outside its valid time window")
	}
	return c.secret, nil
}

func (c *countingSecretService) ImportSecrets(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
	return &secrets.ImportResult{}, nil
}

func newQuietLogger(t *testing.T) *logrus.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

// ---------------------------------------------------------------------------
// GetSecretScoped caching (Task 31)
// ---------------------------------------------------------------------------

// TestCachedGetSecretScopedServesAHitUnderTheSameScope confirms caching is back
// on after Phase 3's deliberate pass-through.
func TestCachedGetSecretScopedServesAHitUnderTheSameScope(t *testing.T) {
	inner := &countingSecretService{secret: &model.Secret{
		ID: uuid.New(), Name: "s", Value: "plaintext", Enabled: true,
	}}
	svc := NewCachedSecretService(inner, newScopeCache(t, time.Minute), newQuietLogger(t))
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	_, err := svc.GetSecretScoped(ctx, inner.secret.ID, scope)
	require.NoError(t, err)
	_, err = svc.GetSecretScoped(ctx, inner.secret.ID, scope)
	require.NoError(t, err)

	assert.Equal(t, 1, inner.getScopedCalls, "the second read is served from cache")
}

func TestCachedGetSecretScopedDoesNotCrossScopes(t *testing.T) {
	inner := &countingSecretService{secret: &model.Secret{
		ID: uuid.New(), Name: "s", Value: "plaintext", Enabled: true,
	}}
	svc := NewCachedSecretService(inner, newScopeCache(t, time.Minute), newQuietLogger(t))
	ctx := context.Background()

	_, err := svc.GetSecretScoped(ctx, inner.secret.ID, model.NewVaultScope(uuid.New(), uuid.New()))
	require.NoError(t, err)
	_, err = svc.GetSecretScoped(ctx, inner.secret.ID, model.NewOwnerScope(uuid.Nil, uuid.New()))
	require.NoError(t, err)

	assert.Equal(t, 2, inner.getScopedCalls, "a different scope must miss")
}

// TestCachedHitRechecksIsAccessible pins the defect where a secret that expired
// or was disabled while cached was served anyway.
func TestCachedHitRechecksIsAccessible(t *testing.T) {
	expiry := time.Now().Add(50 * time.Millisecond)
	inner := &countingSecretService{secret: &model.Secret{
		ID: uuid.New(), Name: "s", Value: "plaintext", Enabled: true, ExpiresAt: &expiry,
	}}
	svc := NewCachedSecretService(inner, newScopeCache(t, time.Minute), newQuietLogger(t))
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	_, err := svc.GetSecretScoped(ctx, inner.secret.ID, scope)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	_, err = svc.GetSecretScoped(ctx, inner.secret.ID, scope)
	require.Error(t, err, "an expired secret must not be served from cache")
	assert.Equal(t, 2, inner.getScopedCalls, "the stale entry is dropped and the service re-consulted")
}

// TestImportSecretsFlushesRatherThanPrunes pins the defect where ImportSecrets'
// "clear cache to ensure consistency" was a no-op for live entries.
func TestImportSecretsFlushesRatherThanPrunes(t *testing.T) {
	inner := &countingSecretService{secret: &model.Secret{
		ID: uuid.New(), Name: "s", Value: "plaintext", Enabled: true,
	}}
	cache := newScopeCache(t, time.Minute)
	svc := NewCachedSecretService(inner, cache, newQuietLogger(t))
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	_, err := svc.GetSecretScoped(ctx, inner.secret.ID, scope)
	require.NoError(t, err)

	_, err = svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Format: "json", Data: []byte("[]")})
	require.NoError(t, err)

	_, found := cache.Get(ctx, inner.secret.ID, scope)
	assert.False(t, found, "ImportSecrets must flush live entries")
}
