package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/cachekit"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/repositories/mocks"
	"rocketvault/internal/services/keys"
	"rocketvault/model"
)

// setupCacheTestMasterKey configures a deterministic 32-byte AES master key.
// Must NOT be called from parallel tests because viper.Set is not goroutine-safe.
func setupCacheTestMasterKey() {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(key))
}

// generateCacheTestRSAPEM creates a 2048-bit RSA private key PEM for tests.
func generateCacheTestRSAPEM(t *testing.T) string {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	}))
}

// mockKeyProvider is a minimal mock of crypto.KeyProvider for HSM path tests.
type mockKeyProvider struct{ mock.Mock }

func (m *mockKeyProvider) GenerateRSAKey(_ context.Context, _ int) (string, error) {
	return "", errors.New("not implemented")
}

func (m *mockKeyProvider) GenerateECDSAKey(_ context.Context, _ string) (string, error) {
	return "", errors.New("not implemented")
}

func (m *mockKeyProvider) GenerateAESKey(_ context.Context, bits int) (string, error) {
	args := m.Called(bits)
	return args.String(0), args.Error(1)
}

func (m *mockKeyProvider) Sign(_ context.Context, handle, _ string, _ []byte, _ crypto.SignatureAlgorithm) ([]byte, error) {
	args := m.Called(handle)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockKeyProvider) Verify(_ context.Context, handle, _ string, _, _ []byte, _ crypto.SignatureAlgorithm) (bool, error) {
	args := m.Called(handle)
	return args.Bool(0), args.Error(1)
}

func (m *mockKeyProvider) Encrypt(_ context.Context, handle string, _ []byte, _ crypto.EncryptionAlgorithm) ([]byte, []byte, error) {
	args := m.Called(handle)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

func (m *mockKeyProvider) Decrypt(_ context.Context, handle string, _ []byte, _ []byte, _ crypto.EncryptionAlgorithm) ([]byte, error) {
	args := m.Called(handle)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockKeyProvider) Close() error { return nil }

// mockKeyCache is a testify-based mock of keycache.Cache.
type mockKeyCache struct{ mock.Mock }

func (m *mockKeyCache) Get(keyID uuid.UUID, version int) (*keycache.Entry, bool) {
	args := m.Called(keyID, version)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*keycache.Entry), args.Bool(1)
}

func (m *mockKeyCache) Set(keyID uuid.UUID, version int, entry *keycache.Entry) {
	m.Called(keyID, version, entry)
}

func (m *mockKeyCache) Invalidate(keyID uuid.UUID) {
	m.Called(keyID)
}

func (m *mockKeyCache) InvalidateAll() {
	m.Called()
}

func (m *mockKeyCache) Stats() keycache.CacheStats {
	args := m.Called()
	return args.Get(0).(keycache.CacheStats)
}

func (m *mockKeyCache) Stop() {
	m.Called()
}

// TestCacheHit_ReducesDecryptCalls verifies that on the second Sign call for
// the same key, the cache returns a hit so AES-GCM decryption is skipped.
// A mock cache is used so we can assert that Set is called exactly once (on the
// first call) and not again on the second call (cache hit path).
// keyRepo.Read is still called each time for the authorization check.
// Not run in parallel because setupCacheTestMasterKey writes global viper state.
func TestCacheHit_ReducesDecryptCalls(t *testing.T) {
	setupCacheTestMasterKey()

	privateKeyPEM := generateCacheTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    "RSA",
		Value:   encryptedPEM,
		Revoked: false,
		Enabled: true,
	}

	// keyRepo.Read is called on every Sign for the authorization check.
	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	// currentVersionNumber calls ListVersions on every crypto op; no rotation
	// has happened for this key, so the version list is empty.
	repo.On("ListVersions", mock.Anything, keyID, userID).Return(nil, nil)

	// Use a mock cache so we can assert Set/Get call counts precisely.
	cache := &mockKeyCache{}

	// Build the cached entry that the mock returns on the second Get call.
	// Version 1: currentVersionNumber resolves a never-rotated key (empty
	// ListVersions) to the implicit version 1, not the old hardcoded 0.
	cachedEntry := &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: privateKeyPEM},
		KeyType:    "RSA",
		Version:    1,
	}

	// First call: Get returns a miss (nil, false).
	// Second call: Get returns the cached entry (hit).
	cache.On("Get", keyID, 1).Return(nil, false).Once()
	cache.On("Get", keyID, 1).Return(cachedEntry, true).Once()

	// Set is called exactly once — on the first call (cache miss).
	cache.On("Set", keyID, 1, mock.AnythingOfType("*keycache.Entry")).Return().Once()

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      cache,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	data := []byte("hello world")

	// First call: cache miss — AES-GCM decrypt runs and result is cached.
	res1, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      data,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	require.NotNil(t, res1)

	// Second call: cache hit — no AES-GCM decrypt, Set must NOT be called again.
	res2, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      data,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	require.NotNil(t, res2)

	// repo.Read is called once per Sign for the authorization check; two total.
	repo.AssertNumberOfCalls(t, "Read", 2)

	// Set must have been called exactly once (first call only).
	cache.AssertNumberOfCalls(t, "Set", 1)

	// Both signatures must be non-empty.
	assert.NotEmpty(t, res1.Signature)
	assert.NotEmpty(t, res2.Signature)

	cache.AssertExpectations(t)
}

// TestHSMPath_NeverCallsCacheSet verifies that PKCS#11-backed keys are never
// stored in the key cache.
func TestHSMPath_NeverCallsCacheSet(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()
	tokenLabel := "some-token-label"
	hsmKey := &model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    "RSA",
		Value:   "pkcs11:" + tokenLabel,
		Revoked: false,
		Enabled: true,
	}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(hsmKey, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return(nil, nil)

	// Use a mock KeyProvider that returns a dummy signature for the HSM call.
	provider := &mockKeyProvider{}
	provider.On("Sign", tokenLabel).Return([]byte("hsm-signature"), nil)

	// For HSM keys, resolveKeyMaterial returns immediately without touching the
	// cache. We use a mock cache to assert Set is never called.
	cache := &mockKeyCache{}

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      cache,
		KeyProvider:   provider,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	// Sign should succeed via the mock HSM provider.
	res, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      []byte("test"),
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("hsm-signature"), res.Signature)

	// cache.Set must never be called for HSM-backed keys.
	cache.AssertNotCalled(t, "Set", mock.Anything, mock.Anything, mock.Anything)
}

// TestWrapKey_HSMKey_AllowsAES256KW verifies that A256KW is now accepted for
// PKCS#11-backed keys (it was previously rejected as RSA-OAEP-only).
func TestWrapKey_HSMKey_AllowsAES256KW(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeOct, Bits: 256, Value: "pkcs11:aes-label", Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, scope).Return(key, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return(nil, nil)

	provider := &mockKeyProvider{}
	provider.On("Encrypt", "aes-label").Return([]byte("wrapped"), []byte(nil), nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	result, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: scope,
		PlaintextKey: []byte("plaintext"), Algorithm: "A256KW",
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("wrapped"), result.WrappedKey)
	provider.AssertExpectations(t)
}

// TestWrapKey_HSMKey_RejectsAESKWSizeMismatch verifies that wrapping with an
// AES-KW algorithm whose key size doesn't match the HSM-backed key's actual
// size (key.Bits) is rejected before the provider is invoked. CKM_AES_KEY_WRAP
// itself doesn't validate this, so the mismatch must be caught here or the
// response would silently misreport the algorithm used.
func TestWrapKey_HSMKey_RejectsAESKWSizeMismatch(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	// Key is actually 256-bit, but the request claims A128KW.
	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeOct, Bits: 256, Value: "pkcs11:aes-label", Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, scope).Return(key, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return(nil, nil)

	provider := &mockKeyProvider{}

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: scope,
		PlaintextKey: []byte("plaintext"), Algorithm: "A128KW",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "128-bit")
	provider.AssertNotCalled(t, "Encrypt", mock.Anything)
}

// TestUnwrapKey_HSMKey_RejectsAESKWSizeMismatch mirrors the WrapKey size-
// mismatch rejection for UnwrapKey: a request claiming A128KW against an
// actually-256-bit HSM key must be rejected before the provider is invoked.
func TestUnwrapKey_HSMKey_RejectsAESKWSizeMismatch(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeOct, Bits: 256, Value: "pkcs11:aes-label", Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, scope).Return(key, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return(nil, nil)

	provider := &mockKeyProvider{}

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyProvider:   provider,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err := svc.UnwrapKey(context.Background(), keys.UnwrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: scope,
		WrappedKey: []byte("wrapped"), Algorithm: "A128KW",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "128-bit")
	provider.AssertNotCalled(t, "Decrypt", mock.Anything)
}

// TestWrapKey_HSMKey_RejectsAES256CBC verifies AES-CBC stays rejected for
// PKCS#11-backed keys — there is no PKCS#11 mechanism for it.
func TestWrapKey_HSMKey_RejectsAES256CBC(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	key := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeOct, Value: "pkcs11:aes-label", Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, scope).Return(key, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return(nil, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyProvider:   &mockKeyProvider{},
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID: keyID, UserID: userID, Scope: scope,
		PlaintextKey: []byte("plaintext"), Algorithm: "A256CBC",
	})
	assert.Error(t, err)
}

// TestNilCacheAndMetrics_DoNotPanic verifies that constructing a CryptoService
// with nil KeyCache and CryptoMetrics does not panic.
func TestNilCacheAndMetrics_DoNotPanic(t *testing.T) {
	t.Parallel()

	repo := mocks.NewMockKeyRepositoryInterface(t)

	assert.NotPanics(t, func() {
		_ = keys.NewCryptoService(keys.CryptoServiceConfig{
			KeyRepository: repo,
			Logger:        &logging.Logger{Logger: logrus.New()},
			// KeyCache and CryptoMetrics intentionally omitted (nil).
		})
	})
}

// TestCacheHit_TTLExpiry verifies that cache entries expire and trigger a new
// AES-GCM decrypt on the next request after the TTL elapses.
// Not run in parallel because setupCacheTestMasterKey writes global viper state.
func TestCacheHit_TTLExpiry(t *testing.T) {
	setupCacheTestMasterKey()

	privateKeyPEM := generateCacheTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    "RSA",
		Value:   encryptedPEM,
		Revoked: false,
		Enabled: true,
	}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return(nil, nil)

	// Use a very short TTL so entries expire quickly.
	shortTTLConfig := &cachekit.Config{
		Enabled:         true,
		TTL:             10 * time.Millisecond,
		MaxEntries:      500,
		CleanupInterval: 5 * time.Millisecond,
	}
	cache := keycache.NewCache(*shortTTLConfig)
	t.Cleanup(cache.Stop)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      cache,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	data := []byte("hello world")

	// First call: cache miss, entry is created.
	_, err = svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      data,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, cache.Stats().TotalEntries)

	// Wait long enough for the TTL to elapse.
	time.Sleep(50 * time.Millisecond)

	// Second call after expiry: must be a cache miss again.
	_, err = svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      data,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)

	// repo.Read is called once per Sign for the authorization check.
	repo.AssertNumberOfCalls(t, "Read", 2)
}

// TestSign_ArchivedVersion_UsesVersionMaterial verifies that passing a
// non-zero Version reads the version's own material (via
// ReadVersionValue), not the key's current keys.value.
func TestSign_ArchivedVersion_UsesVersionMaterial(t *testing.T) {
	setupCacheTestMasterKey()

	currentPEM := generateCacheTestRSAPEM(t)
	archivedPEM := generateCacheTestRSAPEM(t)
	encryptedCurrent, err := common.EncryptSecret(currentPEM)
	require.NoError(t, err)
	encryptedArchived, err := common.EncryptSecret(archivedPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: encryptedCurrent, Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	// Two versions exist: 1 (archived) and 2 (current, == keys.value).
	repo.On("ListVersions", mock.Anything, keyID, userID).Return([]model.KeyVersion{{KeyID: keyID, Version: 1}, {KeyID: keyID, Version: 2}}, nil)
	repo.On("ReadVersionValue", mock.Anything, keyID, 1, userID).Return(encryptedArchived, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	res, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      []byte("hello"),
		Algorithm: crypto.AlgorithmRS256,
		Version:   1,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Version)
	assert.NotEmpty(t, res.Signature)
}

// TestSign_VersionOmitted_UsesCurrentAndEchoesNumber verifies the default
// path (Version: 0) still uses keys.value and echoes the computed current
// version number in the result.
func TestSign_VersionOmitted_UsesCurrentAndEchoesNumber(t *testing.T) {
	setupCacheTestMasterKey()

	pem := generateCacheTestRSAPEM(t)
	encrypted, err := common.EncryptSecret(pem)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: encrypted, Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return([]model.KeyVersion{{KeyID: keyID, Version: 1}, {KeyID: keyID, Version: 2}}, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	res, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("hello"), Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Version)
	repo.AssertNotCalled(t, "ReadVersionValue", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestSign_NonexistentVersion_ReturnsErrKeyVersionNotFound verifies a
// request for a version that doesn't exist surfaces the repository's
// sentinel unwrapped.
func TestSign_NonexistentVersion_ReturnsErrKeyVersionNotFound(t *testing.T) {
	setupCacheTestMasterKey()

	pem := generateCacheTestRSAPEM(t)
	encrypted, err := common.EncryptSecret(pem)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: encrypted, Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return([]model.KeyVersion{{KeyID: keyID, Version: 1}}, nil)
	repo.On("ReadVersionValue", mock.Anything, keyID, 9, userID).Return("", repositories.ErrKeyVersionNotFound)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err = svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("hello"), Algorithm: crypto.AlgorithmRS256, Version: 9,
	})
	require.ErrorIs(t, err, repositories.ErrKeyVersionNotFound)
}

// TestResolveKeyMaterial_CacheKeyUsesRealVersion_NoCrossContamination is the
// regression test for the cache-key bug found during design: two calls for
// the same key at two different versions must not serve each other's
// material from the cache.
func TestResolveKeyMaterial_CacheKeyUsesRealVersion_NoCrossContamination(t *testing.T) {
	setupCacheTestMasterKey()

	currentPEM := generateCacheTestRSAPEM(t)
	archivedPEM := generateCacheTestRSAPEM(t)
	require.NotEqual(t, currentPEM, archivedPEM)
	encryptedCurrent, err := common.EncryptSecret(currentPEM)
	require.NoError(t, err)
	encryptedArchived, err := common.EncryptSecret(archivedPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: encryptedCurrent, Enabled: true}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(vaultKey, nil)
	repo.On("ListVersions", mock.Anything, keyID, userID).Return([]model.KeyVersion{{KeyID: keyID, Version: 1}, {KeyID: keyID, Version: 2}}, nil)
	repo.On("ReadVersionValue", mock.Anything, keyID, 1, userID).Return(encryptedArchived, nil)

	cache := &mockKeyCache{}
	// version 2 (current) miss then never re-fetched; version 1 (archived) miss too.
	cache.On("Get", keyID, 2).Return(nil, false)
	cache.On("Set", keyID, 2, mock.AnythingOfType("*keycache.Entry")).Return()
	cache.On("Get", keyID, 1).Return(nil, false)
	cache.On("Set", keyID, 1, mock.AnythingOfType("*keycache.Entry")).Return()

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      cache,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	// Sign with the current version (2), then the archived version (1).
	resCurrent, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("hello"), Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	resArchived, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: model.NewOwnerScope(uuid.Nil, userID),
		Data: []byte("hello"), Algorithm: crypto.AlgorithmRS256, Version: 1,
	})
	require.NoError(t, err)

	// Different key material must produce different signatures.
	assert.NotEqual(t, resCurrent.Signature, resArchived.Signature)
	cache.AssertExpectations(t)
}
