# Rocket-mem Tiered Cache — Plan 09: Live Integration + Full Regression Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the full stack (Plans 01-08 together) works end-to-end against a real Rocket-mem instance for all four domains, and run one final whole-repo regression pass confirming the default (rocket-mem-disabled) path is byte-for-byte unaffected.

**Architecture:** A build-tagged (`//go:build integration`, matching this repo's existing convention) suite in `internal/container` that constructs a real `ServiceContainer` with `cache.rocket_mem` enabled and exercises `GetSecretCache`/`GetKeyCache`/`GetCertificateCache`/`GetVaultCache` against a live Rocket-mem instance. This is the last plan in the sequence — it depends on Plans 01-08 all being merged.

**Tech Stack:** Existing test tooling; a Rocket-mem instance configured with TLS and an ACL user (required by Plan 04's fail-closed startup guard — see Task 2's setup note, since this is stricter than the currently-running unauthenticated local instance).

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (Testing approach section)

## Global Constraints

- This plan depends on Plans 01-08 being complete.
- The default (`cache.rocket_mem` unset/disabled) `go test ./...` run must remain identical in outcome to before Plan 01 started — this is the plan that proves that claim for the whole feature, not just one file at a time.
- The `integration`-tagged suite requires a live Rocket-mem instance with TLS and an ACL user configured (not the plain/unauthenticated instance used ad hoc during Plan 03's development) — this is intentional: it proves the feature works under the same security posture Plan 04 forces in production, not a weakened test-only posture.

---

### Task 1: Whole-repo regression pass (default build, rocket-mem disabled)

**Files:**
- None modified — verification only.

- [ ] **Step 1: Run the full default test suite**

Run: `go build ./...`
Expected: clean, no errors.

Run: `go vet ./...`
Expected: clean, no warnings.

Run: `go test ./...`
Expected: every package `ok`, none skipped due to a compile error. Confirm specifically that `internal/cache`, `internal/keycache`, `internal/certcache`, `internal/vaultcache`, `internal/container`, and `config` all pass — these are the packages every prior plan in this sequence touched.

- [ ] **Step 2: Confirm zero behavioral drift on the disabled path**

Start the server against the committed `.rocketvault.yaml.example` (which has no `cache.rocket_mem` section, so it defaults disabled):

```bash
cp .rocketvault.yaml.example .rocketvault.yaml   # if not already present
go run main.go serve
```

Expected: starts exactly as it did before this feature existed — no new log line about Rocket-mem, no new startup delay, no new failure mode. Stop the server (Ctrl-C) once confirmed.

- [ ] **Step 3: Commit**

Nothing to commit for this task (verification only) — if Step 1 or Step 2 surfaced any regression, stop here and fix it in the plan (01-08) where it was introduced before proceeding to Task 2. Do not paper over a regression by patching it directly in this plan.

---

### Task 2: Live end-to-end integration suite (all four domains)

**Files:**
- Create: `internal/container/rocketmem_integration_test.go`

**Interfaces:**
- Consumes: `container.NewServiceContainer` (existing), every `NewCacheWithL2` constructor (Plans 05-08), `config.LoadRocketMemConfig` (Plan 04).

- [ ] **Step 1: Set up a TLS+ACL-configured Rocket-mem instance**

The instance already running locally (`127.0.0.1:6379`, no ACL user, no TLS) does **not** satisfy Plan 04's fail-closed guard — that's intentional, not a bug to route around. Before running this task's test, start a second instance (or reconfigure) with TLS and at least one ACL user, per rocket-mem's own docs (`../rocket-mem/docs/` and its `README.md` cover `tls_resp_addr`/`tls_cert_path`/`tls_key_path` config and `ACL SETUSER`/the bootstrap TOML's `[[acl.users]]`) — e.g. a `rocket-mem.test.toml` with:

```toml
tls_resp_addr = "127.0.0.1:6381"
tls_cert_path = "path/to/test-cert.pem"
tls_key_path  = "path/to/test-key.pem"

[[acl.users]]
username = "rocketvault_test"
password = "test-password-only"
```

(rocket-mem's own test fixtures at `crates/server/tests/fixtures/test-{cert,key}.pem`, referenced in the design spec, are reusable here for a local test cert/key pair.)

Set the following before running Step 2's test:

```bash
export ROCKETMEM_INTEGRATION_ADDR=127.0.0.1:6381
export ROCKETMEM_INTEGRATION_USERNAME=rocketvault_test
export ROCKETMEM_INTEGRATION_PASSWORD=test-password-only
```

- [ ] **Step 2: Write the test**

```go
// internal/container/rocketmem_integration_test.go
//go:build integration

// Package container integration suite proves the full Rocket-mem-backed
// TieredCache stack (Plans 01-08) works end-to-end for all four domains
// against a real, TLS+ACL-configured Rocket-mem instance. Run with:
//
//	go test -tags=integration ./internal/container/... -run TestRocketMem -v
//
// Requires the environment described in this plan's Task 2 Step 1. The
// default `go test ./...` run skips this file.
package container_test

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
	"rocketvault/internal/container"
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

func newRocketMemEnabledContainer(t *testing.T) *container.ServiceContainer {
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

	c, err := container.NewServiceContainer(container.Config{
		Logger:          testLogger(), // reuse this test package's existing logger fixture
		CacheConfig:     &cacheCfg,
		RocketMemConfig: &rmCfg,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRocketMem_SecretCache_RoundTripsThroughRealContainer(t *testing.T) {
	c := newRocketMemEnabledContainer(t)
	ctx := context.Background()
	vaultID, secretID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	secret := &model.Secret{ID: secretID, VaultID: vaultID, Name: "n", Value: "integration-secret-value", Version: 1, CreatedAt: time.Now(), Enabled: true}

	require.NoError(t, c.GetSecretCache().Set(ctx, secret, scope))
	got, ok := c.GetSecretCache().Get(ctx, secretID, scope)
	require.True(t, ok)
	require.Equal(t, "integration-secret-value", got.Value)
}

// TestRocketMem_KeyCache_RoundTripsThroughRealContainer proves a genuine
// cross-process cache hit through the real container's rocket-mem-backed
// KeyCache: the mock repository returns valid ciphertext on the first
// Read (populating the cache via a miss) and deliberately corrupted
// ciphertext on the second Read. If the second Sign still produces a
// signature that verifies against the original public key, the key
// material for it could only have come from the cache (Rocket-mem), not a
// fresh AES-GCM decrypt of the now-garbage value -- mirrors the call-count
// assertion technique in internal/services/keys/crypto_service_cache_test.go's
// TestCacheHit_ReducesDecryptCalls, adapted to prove correctness against a
// real cache instead of counting calls on a mock one.
func TestRocketMem_KeyCache_RoundTripsThroughRealContainer(t *testing.T) {
	c := newRocketMemEnabledContainer(t)

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(masterKey))

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	validCiphertext, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)
	corruptedCiphertext, err := common.EncryptSecret("not-a-real-pem-anymore")
	require.NoError(t, err)

	userID, keyID := uuid.New(), uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("CurrentVersion", mock.Anything, keyID).Return(1, nil)
	repo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: validCiphertext, Enabled: true}, nil).Once()
	repo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: userID, Type: "RSA", Value: corruptedCiphertext, Enabled: true}, nil).Once()

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		KeyCache:      c.GetKeyCache(), // the real, rocket-mem-backed cache -- not a mock
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	data := []byte("integration test payload")

	// First Sign: cache miss, decrypts validCiphertext, caches it (in L1 and,
	// via TieredCache, in the real Rocket-mem instance).
	res1, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: scope, Data: data, Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)

	// Second Sign: repo now returns corrupted ciphertext, so if this call
	// reached the decrypt path at all it would either error or produce a
	// signature that fails verification. A successful, valid signature
	// proves the key material came from the cache.
	res2, err := svc.Sign(context.Background(), keys.SignRequest{
		KeyID: keyID, UserID: userID, Scope: scope, Data: data, Algorithm: crypto.AlgorithmRS256,
	})
	require.NoError(t, err)

	digest := sha256.Sum256(data)
	require.NoError(t, rsa.VerifyPKCS1v15(&rsaKey.PublicKey, gocrypto.SHA256, digest[:], res2.Signature))
	assert.NotEmpty(t, res1.Signature)
}

func TestRocketMem_CertCache_RoundTripsThroughRealContainer(t *testing.T) {
	c := newRocketMemEnabledContainer(t)
	ctx := context.Background()
	vaultID, certID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	cert := &model.Certificate{ID: certID, VaultID: vaultID, Name: "n", Certificate: "PUBLIC-PEM", PrivateKey: "encrypted-ciphertext", Enabled: true, CreatedAt: time.Now()}

	require.NoError(t, c.GetCertificateCache().Set(ctx, cert, scope))
	got, ok := c.GetCertificateCache().Get(ctx, certID, scope)
	require.True(t, ok)
	require.Equal(t, "PUBLIC-PEM", got.Certificate)
}

func TestRocketMem_VaultCache_RoundTripsThroughRealContainer(t *testing.T) {
	c := newRocketMemEnabledContainer(t)
	c.GetVaultCache().Set("integration-vault", &model.Vault{Name: "integration-vault", Enabled: true})
	got, ok := c.GetVaultCache().Get("integration-vault")
	require.True(t, ok)
	require.Equal(t, "integration-vault", got.Name)
}
```

- [ ] **Step 3: Run test to verify it passes**

Run: `go test -tags=integration ./internal/container/... -run TestRocketMem -v`
Expected: all four domain tests PASS — `SecretCache`/`CertCache`/`VaultCache` via a direct round-trip, `KeyCache` via the corrupted-ciphertext-on-second-read technique above (the second `Sign` producing a signature that verifies proves the key material came from the real Rocket-mem-backed cache, not a fresh decrypt).

- [ ] **Step 4: Commit**

```bash
git add internal/container/rocketmem_integration_test.go
git commit -m "test(container): add live end-to-end Rocket-mem integration suite"
```
