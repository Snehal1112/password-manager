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
	createSecretFn                  func(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error)
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
	generateSecretFn                func(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error)
	exportSecretsFn                 func(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error)
	importSecretsFn                 func(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error)
}

// compile-time check
var _ secrets.SecretService = (*mockSecretService)(nil)

func (m *mockSecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	if m.getSecretFn != nil {
		return m.getSecretFn(ctx, secretID, userID)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) CreateSecret(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error) {
	if m.createSecretFn != nil {
		return m.createSecretFn(ctx, req)
	}
	return nil, errors.New("not implemented")
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

func TestCachedSecretService_GetSecret_CacheMiss_ThenHit(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)

	svc := &mockSecretService{
		getSecretFn: func(_ context.Context, sid, uid uuid.UUID) (*model.Secret, error) {
			assert.Equal(t, secret.ID, sid)
			assert.Equal(t, userID, uid)
			return secret, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	// First call — cache miss, delegates to base service.
	got, err := cached.GetSecret(ctx, secret.ID, userID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)

	// Second call — cache hit, base service NOT called again.
	callCount := 0
	svc.getSecretFn = func(_ context.Context, _, _ uuid.UUID) (*model.Secret, error) {
		callCount++
		return nil, errors.New("should not be called")
	}
	got2, err := cached.GetSecret(ctx, secret.ID, userID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got2.ID)
	assert.Equal(t, 0, callCount)
}

// ---------------------------------------------------------------------------
// UpdateSecret
// ---------------------------------------------------------------------------

func TestCachedSecretService_UpdateSecretInVault_InvalidatesCache(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)

	// Pre-populate cache.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret))

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
	_, found := c.Get(ctx, secret.ID)
	assert.False(t, found, "vault-scoped update must invalidate the cache so GET does not serve stale plaintext")
}

func TestCachedSecretService_GetSecret_CacheHitWrongUser(t *testing.T) {
	ctx := context.Background()
	ownerID := uuid.New()
	otherID := uuid.New()
	secret := makeSecret(ownerID)

	// Pre-populate the cache with a secret owned by ownerID.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret))

	fetchCount := 0
	svc := &mockSecretService{
		getSecretFn: func(_ context.Context, _, _ uuid.UUID) (*model.Secret, error) {
			fetchCount++
			return nil, errors.New("no access")
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	// Request from a different user — cache entry exists but belongs to ownerID,
	// so the service must fall through to the base service.
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
	require.NoError(t, c.Set(ctx, secret))

	fetchCount := 0
	svc := &mockSecretService{
		getSecretFn: func(_ context.Context, _, _ uuid.UUID) (*model.Secret, error) {
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
		getSecretFn: func(_ context.Context, _, _ uuid.UUID) (*model.Secret, error) {
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

	// The newly created secret should now be in the cache.
	cachedSec, found := c.Get(ctx, secret.ID)
	assert.True(t, found)
	assert.Equal(t, secret.ID, cachedSec.ID)
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

	// Pre-populate cache.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret))

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
	_, found := c.Get(ctx, secret.ID)
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

	// Pre-populate cache.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret))

	svc := &mockSecretService{
		deleteSecretFn: func(_ context.Context, _, _ uuid.UUID) error {
			return nil
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.DeleteSecret(ctx, secret.ID, userID)
	require.NoError(t, err)

	_, found := c.Get(ctx, secret.ID)
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

	// Pre-populate cache.
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret))

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

	_, found := c.Get(ctx, secret.ID)
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

func TestCachedSecretService_GenerateSecret_CachesResult(t *testing.T) {
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

	cachedSec, found := c.Get(ctx, secret.ID)
	assert.True(t, found)
	assert.Equal(t, secret.ID, cachedSec.ID)
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
	require.NoError(t, c.Set(ctx, secret))

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

	// The cache Clear only removes expired entries; the pre-populated entry with
	// 5-minute TTL should be cleared by the explicit cache clear on import.
	// Note: SecretCache.Clear() only removes *expired* entries; however the
	// implementation calls c.cache.Clear() which removes expired ones. To keep
	// the test deterministic we verify the import result was returned correctly.
}

func TestCachedSecretService_ImportSecrets_FlushesLiveCacheEntries(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	// Pre-populate cache with a live (non-expired) secret.
	secret := makeSecret(userID)
	c := newTestCache(t)
	require.NoError(t, c.Set(ctx, secret))

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
	_, found := c.Get(ctx, secret.ID)
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
	require.NoError(t, c.Set(ctx, secret))

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
