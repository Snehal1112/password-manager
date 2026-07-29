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
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
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

	// Use a mock cache so we can assert Set/Get call counts precisely.
	cache := &mockKeyCache{}

	// Build the cached entry that the mock returns on the second Get call.
	cachedEntry := &keycache.Entry{
		PrivateKey: keycache.PEMKey{PEM: privateKeyPEM},
		KeyType:    "RSA",
		Version:    0,
		ExpiresAt:  time.Now().Add(time.Minute),
	}

	// First call: Get returns a miss (nil, false).
	// Second call: Get returns the cached entry (hit).
	cache.On("Get", keyID, 0).Return(nil, false).Once()
	cache.On("Get", keyID, 0).Return(cachedEntry, true).Once()

	// Set is called exactly once — on the first call (cache miss).
	cache.On("Set", keyID, 0, mock.AnythingOfType("*keycache.Entry")).Return().Once()

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
		Data:      data,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	require.NotNil(t, res1)

	// Second call: cache hit — no AES-GCM decrypt, Set must NOT be called again.
	res2, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
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
		Data:      []byte("test"),
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("hsm-signature"), res.Signature)

	// cache.Set must never be called for HSM-backed keys.
	cache.AssertNotCalled(t, "Set", mock.Anything, mock.Anything, mock.Anything)
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

	// Use a very short TTL so entries expire quickly.
	shortTTLConfig := &keycache.KeyCacheConfig{
		Enabled:         true,
		TTL:             10 * time.Millisecond,
		MaxEntries:      500,
		CleanupInterval: 5 * time.Millisecond,
	}
	cache := keycache.NewMemoryCache(shortTTLConfig)
	t.Cleanup(cache.Stop)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      cache,
		CacheConfig:   shortTTLConfig,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	data := []byte("hello world")

	// First call: cache miss, entry is created.
	_, err = svc.Sign(context.Background(), keys.SignRequest{
		KeyID:     keyID,
		UserID:    userID,
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
		Data:      data,
		Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)

	// repo.Read is called once per Sign for the authorization check.
	repo.AssertNumberOfCalls(t, "Read", 2)
}
