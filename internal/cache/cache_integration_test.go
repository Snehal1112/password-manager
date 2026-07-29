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
	getSecretFn              func(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error)
	listSecretsFn            func(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error)
	deleteSecretFn           func(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	listDeletedSecretsFn     func(ctx context.Context, scope model.Scope) ([]model.Secret, error)
	createSecretFn           func(ctx context.Context, req secrets.CreateSecretRequest) (*model.Secret, error)
	updateSecretFn           func(ctx context.Context, req secrets.UpdateSecretRequest) error
	getSecretVersionsFn      func(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)
	getSecretVersionFn       func(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)
	getLatestSecretVersionFn func(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)
	generateSecretFn         func(ctx context.Context, req secrets.GenerateSecretRequest) (*model.Secret, error)
	exportSecretsFn          func(ctx context.Context, req secrets.ExportSecretsRequest) ([]byte, error)
	importSecretsFn          func(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error)
	recoverSecretFn          func(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	purgeSecretFn            func(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
}

// compile-time check
var _ secrets.SecretService = (*mockSecretService)(nil)

func (m *mockSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	if m.getSecretFn != nil {
		return m.getSecretFn(ctx, secretID, scope)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) ListSecrets(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	if m.listSecretsFn != nil {
		return m.listSecretsFn(ctx, scope, tags)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, secretID, scope)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) ListDeletedSecrets(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	if m.listDeletedSecretsFn != nil {
		return m.listDeletedSecretsFn(ctx, scope)
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

func (m *mockSecretService) GetSecretVersions(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	if m.getSecretVersionsFn != nil {
		return m.getSecretVersionsFn(ctx, secretID, scope)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	if m.getSecretVersionFn != nil {
		return m.getSecretVersionFn(ctx, secretID, version, scope)
	}
	return nil, errors.New("not implemented")
}

func (m *mockSecretService) GetLatestSecretVersion(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	if m.getLatestSecretVersionFn != nil {
		return m.getLatestSecretVersionFn(ctx, secretID, scope)
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

func (m *mockSecretService) RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if m.recoverSecretFn != nil {
		return m.recoverSecretFn(ctx, secretID, scope)
	}
	return errors.New("not implemented")
}

func (m *mockSecretService) PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if m.purgeSecretFn != nil {
		return m.purgeSecretFn(ctx, secretID, scope)
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

// TestCachedSecretService_GetSecret_CachesOnFirstCall confirms the first call
// delegates to the base service and populates the cache, and the second call
// is served from cache.
func TestCachedSecretService_GetSecret_CachesOnFirstCall(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secret := makeSecret(userID)
	scope := model.NewOwnerScope(uuid.Nil, userID)

	callCount := 0
	svc := &mockSecretService{
		getSecretFn: func(_ context.Context, sid uuid.UUID, scope model.Scope) (*model.Secret, error) {
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
	got, err := cached.GetSecret(ctx, secret.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)

	// Second call — served from cache; base service is not consulted again.
	got2, err := cached.GetSecret(ctx, secret.ID, scope)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got2.ID)
	assert.Equal(t, 1, callCount, "GetSecret must serve the second call from cache")
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
		getSecretFn: func(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
			fetchCount++
			return nil, errors.New("no access")
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	// Request from a different user — the compound key means the entry
	// cached under ownerID's scope does not satisfy otherID's scope, so the
	// service must fall through to the base service.
	_, err := cached.GetSecret(ctx, secret.ID, model.NewOwnerScope(uuid.Nil, otherID))
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
		getSecretFn: func(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
			fetchCount++
			return nil, errors.New("secret is disabled or outside its valid time window")
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.GetSecret(ctx, secret.ID, model.NewOwnerScope(uuid.Nil, userID))
	assert.Error(t, err)
	assert.Equal(t, 1, fetchCount, "a disabled cached secret must fall through to the base service, not be served from cache")
}

func TestCachedSecretService_GetSecret_BaseServiceError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	svc := &mockSecretService{
		getSecretFn: func(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
			return nil, errors.New("db error")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.GetSecret(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
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

	req := secrets.UpdateSecretRequest{SecretID: secret.ID, Scope: scope}
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

	err := cached.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, Scope: model.NewOwnerScope(uuid.Nil, userID)})
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
		deleteSecretFn: func(_ context.Context, _ uuid.UUID, _ model.Scope) error {
			return nil
		},
	}
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.DeleteSecret(ctx, secret.ID, scope)
	require.NoError(t, err)

	_, found := c.Get(ctx, secret.ID, scope)
	assert.False(t, found)
}

func TestCachedSecretService_DeleteSecret_BaseError(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	svc := &mockSecretService{
		deleteSecretFn: func(_ context.Context, _ uuid.UUID, _ model.Scope) error {
			return errors.New("delete failed")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	err := cached.DeleteSecret(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListSecrets
// ---------------------------------------------------------------------------

func TestCachedSecretService_ListSecrets_DelegatesToBase(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)
	expected := []model.Secret{{ID: uuid.New(), UserID: userID, Name: "s1"}}

	svc := &mockSecretService{
		listSecretsFn: func(_ context.Context, gotScope model.Scope, tags []string) ([]model.Secret, error) {
			assert.Equal(t, scope, gotScope)
			return expected, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.ListSecrets(ctx, scope, nil)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, expected[0].ID, got[0].ID)
}

func TestCachedSecretService_ListSecrets_BaseError(t *testing.T) {
	ctx := context.Background()

	svc := &mockSecretService{
		listSecretsFn: func(_ context.Context, _ model.Scope, _ []string) ([]model.Secret, error) {
			return nil, errors.New("list error")
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	_, err := cached.ListSecrets(ctx, model.NewOwnerScope(uuid.Nil, uuid.New()), nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Version methods
// ---------------------------------------------------------------------------

func TestCachedSecretService_GetSecretVersions_Delegates(t *testing.T) {
	ctx := context.Background()
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	versions := []model.SecretVersion{{SecretID: secretID, Version: 1}}

	svc := &mockSecretService{
		getSecretVersionsFn: func(_ context.Context, sid uuid.UUID, gotScope model.Scope) ([]model.SecretVersion, error) {
			assert.Equal(t, secretID, sid)
			assert.Equal(t, scope, gotScope)
			return versions, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.GetSecretVersions(ctx, secretID, scope)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestCachedSecretService_GetSecretVersion_Delegates(t *testing.T) {
	ctx := context.Background()
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	sv := &model.SecretVersion{SecretID: secretID, Version: 2}

	svc := &mockSecretService{
		getSecretVersionFn: func(_ context.Context, sid uuid.UUID, ver int, gotScope model.Scope) (*model.SecretVersion, error) {
			assert.Equal(t, secretID, sid)
			assert.Equal(t, 2, ver)
			assert.Equal(t, scope, gotScope)
			return sv, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.GetSecretVersion(ctx, secretID, 2, scope)
	require.NoError(t, err)
	assert.Equal(t, 2, got.Version)
}

func TestCachedSecretService_GetLatestSecretVersion_Delegates(t *testing.T) {
	ctx := context.Background()
	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	sv := &model.SecretVersion{SecretID: secretID, Version: 5}

	svc := &mockSecretService{
		getLatestSecretVersionFn: func(_ context.Context, sid uuid.UUID, gotScope model.Scope) (*model.SecretVersion, error) {
			assert.Equal(t, secretID, sid)
			assert.Equal(t, scope, gotScope)
			return sv, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	got, err := cached.GetLatestSecretVersion(ctx, secretID, scope)
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
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	payload := []byte(`{"secrets":[]}`)

	svc := &mockSecretService{
		exportSecretsFn: func(_ context.Context, req secrets.ExportSecretsRequest) ([]byte, error) {
			assert.Equal(t, scope, req.Scope)
			return payload, nil
		},
	}
	c := newTestCache(t)
	logger := newTestLogger()
	cached := NewCachedSecretService(svc, c, logger)

	req := secrets.ExportSecretsRequest{Scope: scope}
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

	req := secrets.ImportSecretsRequest{Scope: model.NewOwnerScope(uuid.Nil, userID)}
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

	_, err := cached.ImportSecrets(ctx, secrets.ImportSecretsRequest{Scope: model.NewOwnerScope(uuid.Nil, userID)})
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
// tests below. It counts GetSecret calls and mirrors the real service's
// behavior of erroring once the secret is no longer accessible.
// ---------------------------------------------------------------------------

type countingSecretService struct {
	secrets.SecretService
	secret   *model.Secret
	getCalls int
}

func (c *countingSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	c.getCalls++
	if !c.secret.IsAccessible() {
		return nil, errors.New("secret is disabled or outside its valid time window")
	}
	return c.secret, nil
}

// The stubs below make countingSecretService a complete, always-succeeding
// SecretService for Task 32's mutator-invalidation table (internal/cache/
// mutator_invalidation_test.go): every mutating method the table invokes must
// return nil so the test can isolate cache-invalidation behavior from
// business-logic failures.

func (c *countingSecretService) UpdateSecret(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return nil
}

func (c *countingSecretService) DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return nil
}

func (c *countingSecretService) RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return nil
}

func (c *countingSecretService) PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return nil
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
// GetSecret caching (Task 31)
// ---------------------------------------------------------------------------

// TestCachedGetSecretServesAHitUnderTheSameScope confirms caching is back
// on after Phase 3's deliberate pass-through.
func TestCachedGetSecretServesAHitUnderTheSameScope(t *testing.T) {
	inner := &countingSecretService{secret: &model.Secret{
		ID: uuid.New(), Name: "s", Value: "plaintext", Enabled: true,
	}}
	svc := NewCachedSecretService(inner, newScopeCache(t, time.Minute), newQuietLogger(t))
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	_, err := svc.GetSecret(ctx, inner.secret.ID, scope)
	require.NoError(t, err)
	_, err = svc.GetSecret(ctx, inner.secret.ID, scope)
	require.NoError(t, err)

	assert.Equal(t, 1, inner.getCalls, "the second read is served from cache")
}

func TestCachedGetSecretDoesNotCrossScopes(t *testing.T) {
	inner := &countingSecretService{secret: &model.Secret{
		ID: uuid.New(), Name: "s", Value: "plaintext", Enabled: true,
	}}
	svc := NewCachedSecretService(inner, newScopeCache(t, time.Minute), newQuietLogger(t))
	ctx := context.Background()

	_, err := svc.GetSecret(ctx, inner.secret.ID, model.NewVaultScope(uuid.New(), uuid.New()))
	require.NoError(t, err)
	_, err = svc.GetSecret(ctx, inner.secret.ID, model.NewOwnerScope(uuid.Nil, uuid.New()))
	require.NoError(t, err)

	assert.Equal(t, 2, inner.getCalls, "a different scope must miss")
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

	_, err := svc.GetSecret(ctx, inner.secret.ID, scope)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	_, err = svc.GetSecret(ctx, inner.secret.ID, scope)
	require.Error(t, err, "an expired secret must not be served from cache")
	assert.Equal(t, 2, inner.getCalls, "the stale entry is dropped and the service re-consulted")
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

	_, err := svc.GetSecret(ctx, inner.secret.ID, scope)
	require.NoError(t, err)

	_, err = svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Format: "json", Data: []byte("[]")})
	require.NoError(t, err)

	_, found := cache.Get(ctx, inner.secret.ID, scope)
	assert.False(t, found, "ImportSecrets must flush live entries")
}
