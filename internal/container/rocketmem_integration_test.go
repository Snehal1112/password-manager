//go:build integration

// This file is the live end-to-end Rocket-mem integration suite. It proves
// the full Rocket-mem-backed TieredCache stack (Plans 01-08) works
// end-to-end for all four domains against a real, TLS+ACL-configured
// Rocket-mem instance -- specifically, that the L2 tier (Rocket-mem itself)
// is actually reachable and round-trips correctly, not merely that each
// domain cache's in-process L1 works (that's already covered by the
// existing unit suites). Every test below therefore uses two independent
// ServiceContainers, each with its own fresh L1, both pointed at the same
// Rocket-mem address/credentials: a write via container A and a read via
// container B can only succeed through the shared L2, since B's L1 has
// never seen A's write. Run with:
//
//	go test -tags=integration ./internal/container/... -run TestRocketMem -v
//
// Requires the environment described in this plan's Task 2 Step 1. The
// default `go test ./...` run skips this file.
//
// Deviation from the task brief: the brief's code declares
// `package container_test` and refers to the container types via a
// qualified `container.` import. The repo's actual helper this test needs
// (the silent-logger fixture in container_test.go, `newTestLogger`) is
// unexported and lives in `package container` (the internal test package
// for this directory, not an external `container_test` one -- no
// `container_test` package exists anywhere in this directory before this
// file). An external test file cannot see an unexported identifier in the
// internal package, so this file uses `package container` instead and
// refers to `ServiceContainer`/`Config`/`NewServiceContainer` unqualified,
// which is also why "rocketvault/internal/container" is not imported
// below. This is the same kind of brief-vs-repo naming mismatch flagged in
// a prior task in this feature; the fix here goes one step further because
// the mismatch here is a package boundary, not just a name.
package container

import (
	"context"
	gocrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/config"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories/mocks"
	"rocketvault/internal/services/keys"
	"rocketvault/model"
)

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set -- see Plan 09 Task 2 Step 1 for setup", key)
	}
	return v
}

func newRocketMemEnabledContainer(t *testing.T) *ServiceContainer {
	t.Helper()
	rmCfg := config.RocketMemConfig{
		Enabled:      true,
		Addr:         requireEnv(t, "ROCKETMEM_INTEGRATION_ADDR"),
		TLS:          true,
		Username:     requireEnv(t, "ROCKETMEM_INTEGRATION_USERNAME"),
		Password:     requireEnv(t, "ROCKETMEM_INTEGRATION_PASSWORD"),
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		PoolSize:     5,
	}
	cacheCfg, err := config.LoadCacheConfig()
	require.NoError(t, err)

	c, err := NewServiceContainer(Config{
		Logger:          newTestLogger(), // reuse this test package's existing logger fixture (container_test.go)
		CacheConfig:     &cacheCfg,
		RocketMemConfig: &rmCfg,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestRocketMem_SecretCache_RoundTripsThroughRealContainer proves a genuine
// cross-process cache hit: containerA and containerB are separate
// ServiceContainers, each with its own fresh, never-shared L1. Set goes
// through containerA (populating A's L1 and, via TieredCache, the shared
// Rocket-mem L2). Get goes through containerB, whose L1 has never seen this
// secret -- a hit there can only have come from the shared L2.
func TestRocketMem_SecretCache_RoundTripsThroughRealContainer(t *testing.T) {
	containerA := newRocketMemEnabledContainer(t)
	containerB := newRocketMemEnabledContainer(t)
	ctx := context.Background()
	vaultID, secretID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	secret := &model.Secret{ID: secretID, VaultID: vaultID, Name: "n", Value: "integration-secret-value", Version: 1, CreatedAt: time.Now(), Enabled: true}

	require.NoError(t, containerA.GetSecretCache().Set(ctx, secret, scope))
	got, ok := containerB.GetSecretCache().Get(ctx, secretID, scope)
	require.True(t, ok)
	require.Equal(t, "integration-secret-value", got.Value)
}

// TestRocketMem_KeyCache_RoundTripsThroughRealContainer proves a genuine
// cross-process cache hit through the real, shared Rocket-mem-backed
// KeyCache: svcA and svcB are two CryptoService instances wired to two
// separate ServiceContainers' KeyCaches (so separate, never-shared L1s) but
// sharing one mock KeyRepositoryInterface. The mock returns valid
// ciphertext on the first Read (svcA's cache miss, which decrypts it and
// populates svcA's L1 *and* the shared Rocket-mem L2) and deliberately
// corrupted ciphertext on the second Read (svcB's call). svcB's L1 has
// never seen this key, so it can only satisfy the lookup via the shared L2.
// If the second Sign still produces a signature that verifies against the
// original public key, the key material for it could only have come from
// the shared L2 (Rocket-mem) -- if svcB's L2 lookup had missed too, it would
// have fallen through to a fresh AES-GCM decrypt of the corrupted value,
// which either errors or produces a signature that fails verification.
// Mirrors the call-count assertion technique in
// internal/services/keys/crypto_service_cache_test.go's
// TestCacheHit_ReducesDecryptCalls, adapted to prove correctness against a
// real, shared cache instead of counting calls on a mock one.
func TestRocketMem_KeyCache_RoundTripsThroughRealContainer(t *testing.T) {
	containerA := newRocketMemEnabledContainer(t)
	containerB := newRocketMemEnabledContainer(t)

	origMasterKey := viper.GetString("master_key")
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(masterKey))
	t.Cleanup(func() { viper.Set("master_key", origMasterKey) })

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	validCiphertext, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)
	corruptedCiphertext, err := common.EncryptSecret("not-a-real-pem-anymore")
	require.NoError(t, err)

	userID, keyID := uuid.New(), uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	// One mock repository shared by both services -- it's a plain Go value,
	// not owned by either container.
	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("CurrentVersion", mock.Anything, keyID).Return(1, nil)
	repo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: validCiphertext, Enabled: true}, nil).Once()
	repo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: corruptedCiphertext, Enabled: true}, nil).Once()

	svcA := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      containerA.GetKeyCache(), // real, rocket-mem-backed cache -- container A's fresh L1
		Logger:        &logging.Logger{Logger: logrus.New()},
	})
	svcB := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      containerB.GetKeyCache(), // real, rocket-mem-backed cache -- container B's fresh, separate L1
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	data := []byte("integration test payload")

	// First Sign via svcA: cache miss on A's fresh L1, decrypts
	// validCiphertext (the repo's first Read), caches the result in A's L1
	// and, via TieredCache, in the shared Rocket-mem L2.
	res1, err := svcA.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: scope, Data: data, Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)

	// Second Sign via svcB: B's L1 has never seen this key, so this can
	// only be satisfied by the shared L2 (Rocket-mem). The repo's second
	// Read (used only on a total cache miss) now returns corrupted
	// ciphertext, so if this call reached the decrypt path at all it would
	// either error or produce a signature that fails verification. A
	// successful, valid signature proves the key material came from the
	// shared L2, not a fresh decrypt and not svcA's L1 (svcB never touches
	// svcA's L1 -- they're different CryptoService/KeyCache instances).
	res2, err := svcB.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: scope, Data: data, Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)

	digest := sha256.Sum256(data)
	require.NoError(t, rsa.VerifyPKCS1v15(&rsaKey.PublicKey, gocrypto.SHA256, digest[:], res2.Signature))
	assert.NotEmpty(t, res1.Signature)
}

// TestRocketMem_CertCache_RoundTripsThroughRealContainer proves a genuine
// cross-process cache hit: Set via containerA, Get via containerB, whose
// fresh L1 has never seen this certificate -- a hit there can only have
// come from the shared L2.
func TestRocketMem_CertCache_RoundTripsThroughRealContainer(t *testing.T) {
	containerA := newRocketMemEnabledContainer(t)
	containerB := newRocketMemEnabledContainer(t)
	ctx := context.Background()
	vaultID, certID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: certID, VaultID: vaultID, Name: "n", Certificate: "PUBLIC-PEM", PrivateKey: "encrypted-ciphertext", Enabled: true, CreatedAt: time.Now()}

	require.NoError(t, containerA.GetCertificateCache().Set(ctx, cert, scope))
	got, ok := containerB.GetCertificateCache().Get(ctx, certID, scope)
	require.True(t, ok)
	require.Equal(t, "PUBLIC-PEM", got.Certificate)
}

// TestRocketMem_VaultCache_RoundTripsThroughRealContainer proves a genuine
// cross-process cache hit: Set via containerA, Get via containerB, whose
// fresh L1 has never seen this vault -- a hit there can only have come from
// the shared L2.
func TestRocketMem_VaultCache_RoundTripsThroughRealContainer(t *testing.T) {
	containerA := newRocketMemEnabledContainer(t)
	containerB := newRocketMemEnabledContainer(t)
	containerA.GetVaultCache().Set("integration-vault", &model.Vault{Name: "integration-vault", Enabled: true})
	got, ok := containerB.GetVaultCache().Get("integration-vault")
	require.True(t, ok)
	require.Equal(t, "integration-vault", got.Name)
}
