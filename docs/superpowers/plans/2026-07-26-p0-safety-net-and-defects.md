# P0: Safety Net and Live Defect Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land permanent regression tests that pin RocketVault's current vault-scoping and B6 crypto-ownership behavior, fix eight live defects discovered while tracing that behavior, and replace five stale/duplicated hand-written mocks with `mockery`-generated ones — all without changing any intended behavior except where a defect fix requires it.

**Architecture:** Tests land first (B6 owner-gating pins, then cross-vault-denial proofs against real SQLite), so every subsequent defect fix has a regression test that would have caught it. Each defect fix is its own commit touching only the files named in the design spec's defect table. Mockery adoption lands last since it is orthogonal to behavior and only needs to compile cleanly against the interfaces the defect fixes already touched.

**Tech Stack:** Go 1.25, `testify` (`mock`, `assert`, `require`), `github.com/mattn/go-sqlite3` (in-memory), `gorilla/mux`, `mockery/v2` (new).

## Global Constraints

- Every commit is GPG-signed: `git commit -S`.
- Verification gates run `go build ./... && go test ./...`. `go vet ./...` alone is **not sufficient** — `cmd/testutils.MockServiceContainer` stores services as `interface{}` and type-asserts at runtime, so a missing mock method surfaces only as a `go test` panic, never a `go vet` or compile error.
- Nothing in this plan changes intended behavior except the eight defects in Task 9-16, each justified against the design spec's table.
- The real domain/model package is `model/` (`model.Secret`, `model.Key`, `model.Vault`, `model.DefaultVaultID`, `model.RoleAdmin`). `internal/domain/` does not exist despite `CLAUDE.md` describing it — do not create it. This plan is scoped to spec section 4 only; correcting `CLAUDE.md` is out of scope here.
- **SEQUENCING HAZARD — read before deploying anything from this plan:** Task 9's `CreateVersion` ownership-gate fix releases an accidental brake on cross-tenant secret writes. Today, `UpdateSecretInVault` fails closed (500) for any non-owner because of the very bug Task 9 fixes. Once fixed, "any vault member may update" is restored as intended — but P2's fail-closed RBAC (vault membership enforcement) has not shipped yet, so any principal holding a global secrets permission can overwrite another user's secret in any vault by name until P2 lands. **P0 must not be deployed to production alone — it ships together with P1 and P2, never incrementally to production.** If that is not possible, land P2's fail-closed `PolicyMiddleware` inversion before the `CreateVersion` fix, accepting the 500 in the interim.
- B6 regression tests (Tasks 2-3) pin a **temporary** invariant that P2 deliberately removes. Their eventual deletion must be its own commit alongside the P2 policy change — never bundled into a refactor commit. Nothing in this plan deletes them; noted here so implementers of later phases don't lose the context.

---

## File Structure

| File | Responsibility |
|---|---|
| `api/vault_test.go` | (Modify) `vaultSvcTestContainer` gains a `cryptoSvc` field so tests can inject a real `CryptoService`. |
| `api/vault_scoped_crypto_b6_test.go` | (Create) B6 regression tests: non-owner vault member gets 403 on sign/verify/encrypt/decrypt/wrap/unwrap and key delete via `/vaults/{name}/keys/...`. |
| `api/keys.go` | (Modify) `deleteKey` handler maps `ErrKeyForbidden` to 403 (missing case found while writing the B6 delete test). |
| `api/vault_cross_denial_test.go` | (Create, then append) Cross-vault denial tests against real SQLite for secrets, keys, certificates, certificate policy, and secret version endpoints. |
| `internal/services/secrets/secret_service.go` | (Modify) `UpdateSecretInVault` passes the secret's owner, not the caller, into `CreateVersion`. |
| `internal/services/secrets/secret_service_test.go` | (Modify) Regression test for the above. |
| `internal/cache/cache_integration.go` | (Modify) `UpdateSecretInVault` invalidates cache; `GetSecret` cache hit path rechecks `IsAccessible()`; `ImportSecrets` calls `Flush` instead of `Clear`. |
| `internal/cache/cache_integration_test.go` | (Modify) Regression tests for all three cache fixes. |
| `internal/cache/secret_cache.go` | (Modify) Adds `Flush`, which unconditionally empties the cache (distinct from `Clear`, which only prunes expired entries). |
| `internal/cache/secret_cache_test.go` | (Modify) Regression test for `Flush`. |
| `cmd/keys/wrap.go`, `cmd/keys/unwrap.go` | (Modify) Set `VaultID` to the default vault on `WrapKeyRequest`/`UnwrapKeyRequest`. |
| `cmd/keys/keys_cmd_test.go` | (Modify) Regression tests asserting `VaultID` is set. |
| `internal/repositories/secret_repository.go` | (Modify) `UpdateInVault` attributes audit rows to `secret.UserID`, not `secret.VaultID`. |
| `internal/repositories/secret_repository_test.go` | (Modify) Regression test using a fake `AuditPersister`. |
| `internal/repositories/key_repository.go` | (Modify) `Update` stops emitting its own (owner-attributed) audit rows, so it no longer contradicts the service layer's (actor-attributed) rows for `UpdateKeyInVault`. |
| `internal/services/keys/key_service_update_test.go` | (Modify) Regression test proving every audit row for a vault-scoped update attributes the actor. |
| `internal/services/secrets/rotation_service.go` | (Modify) `GetSecretPolicies` and `AcknowledgeReminder` gain ownership checks (skippable via `uuid.Nil` for system callers, matching `DeleteKeyInVault`'s existing convention). |
| `internal/services/secrets/rotation_service_test.go` | (Create) Regression tests for both methods. |
| `internal/services/secrets/scheduler_service.go` | (Modify) Passes `reminder.SecretID` and `uuid.Nil` (system caller) to the now-3-arg `AcknowledgeReminder`. |
| `cmd/rotation_service_test.go`, `cmd/rotation_security_test.go` | (Modify) Hand-written `RotationServiceInterface` mocks updated to the new 2-arg/3-arg signatures. |
| `.mockery.yaml` | (Create) Mockery v2 config targeting `SecretService`, `KeyService`, `CertificateService`, `VersioningServiceInterface`, `SecretRepositoryInterface`, `KeyRepositoryInterface`, `CertificateRepositoryInterface`. |
| `internal/services/keys/wrap_key_test.go` | (Modify) Replaces the hand-written `mockKeyRepoForWrap` (18 methods) with the generated `mocks.MockKeyRepositoryInterface`. |

---

### Task 1: Test harness — inject a real CryptoService into vaultSvcTestContainer

**Files:**
- Modify: `api/vault_test.go:160-169` (struct), `api/vault_test.go:264-266` (`GetCryptoService`)
- Test: `api/vault_test.go`

**Interfaces:**
- Consumes: `keyServices.CryptoService` (existing interface, `internal/services/keys/crypto_service.go:120-127`); `stubCryptoSvc` (existing type in `api/keys_crypto_test.go`, same package).
- Produces: `vaultSvcTestContainer.cryptoSvc` field and a working `GetCryptoService()` override that Tasks 2-3 depend on.

- [ ] **Step 1: Write the failing test**

Add to `api/vault_test.go`:

```go
// TestVaultSvcTestContainer_GetCryptoService_ReturnsConfiguredService proves
// the test container can inject a real CryptoService, which the B6
// regression tests (api/vault_scoped_crypto_b6_test.go) need in order to
// exercise the actual loadAndAuthorize ownership check instead of a stub.
func TestVaultSvcTestContainer_GetCryptoService_ReturnsConfiguredService(t *testing.T) {
	svc := &stubCryptoSvc{}
	c := &vaultSvcTestContainer{cryptoSvc: svc, logger: userTestLog()}
	if c.GetCryptoService() != svc {
		t.Fatalf("GetCryptoService() did not return the configured cryptoSvc")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestVaultSvcTestContainer_GetCryptoService_ReturnsConfiguredService -v`
Expected: FAIL to compile — `unknown field cryptoSvc in struct literal of type vaultSvcTestContainer`

- [ ] **Step 3: Add the field and wire GetCryptoService**

In `api/vault_test.go`, change the `vaultSvcTestContainer` struct (currently lines 160-169):

```go
type vaultSvcTestContainer struct {
	vaultSvc       vaultServices.VaultService
	secretSvc      secretServices.SecretService
	keySvc         keyServices.KeyService
	cryptoSvc      keyServices.CryptoService
	certSvc        certServices.CertificateService
	certPolicyRepo repositories.CertificatePolicyRepositoryInterface
	policySvc      authzServices.AccessPolicyService
	rbacSvc        authzServices.RBACService
	logger         *logging.Logger
}
```

And change `GetCryptoService` (currently lines 264-266):

```go
func (c *vaultSvcTestContainer) GetCryptoService() keyServices.CryptoService {
	if c.cryptoSvc != nil {
		return c.cryptoSvc
	}
	panic("unexpected call: GetCryptoService")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/... -run TestVaultSvcTestContainer_GetCryptoService_ReturnsConfiguredService -v`
Expected: PASS

Also run the full package to confirm nothing else broke: `go test ./api/... -v`
Expected: PASS (all existing vault tests still pass; `cryptoSvc` defaults to the zero value `nil`, and `GetCryptoService()` still panics for any existing test that never sets it, exactly as before)

- [ ] **Step 5: Commit**

```bash
git add api/vault_test.go
git commit -S -m "test(api): let vaultSvcTestContainer inject a real CryptoService"
```

---

### Task 2: B6 regression tests — crypto operations return 403 for a non-owner vault member

**Files:**
- Create: `api/vault_scoped_crypto_b6_test.go`
- Test: same file (this task is entirely test code; no production code changes)

**Interfaces:**
- Consumes: `vaultSvcTestContainer{cryptoSvc: ...}` (Task 1); `doVaultRequest`, `newVaultFakeRepo`, `vaultResolutionTestMiddleware`, `vaultNoopCascade{}`, `userTestLog()` (all existing, `api/vault_test.go` / `api/vault_scoped_routes_test.go` / `api/users_test.go`); `repositories.KeyRepositoryInterface` (`internal/repositories/key_repository.go:24-49`); `keyServices.NewCryptoService`, `keyServices.CryptoServiceConfig` (`internal/services/keys/crypto_service.go:141-173`); `keyServices.NewKeyService`, `keyServices.KeyServiceConfig` (`internal/services/keys/key_service.go:120-150`).
- Produces: `b6FakeKeyRepo`, `newB6FakeKeyRepo()`, `newB6TestAPI(repo *b6FakeKeyRepo) (*API, *vaultFakeRepo)` — Task 3 reuses both.

- [ ] **Step 1: Write the failing test**

Create `api/vault_scoped_crypto_b6_test.go`:

```go
// Package api — B6 regression tests (design spec 2026-07-26, section 4.1).
// B6 is the temporary invariant that crypto operations on a key remain
// gated by ownership even on vault-scoped routes, where listing/get/update
// already grant vault-wide "members see all" visibility. These tests pin
// that invariant so the P1 mechanical refactor cannot silently widen it.
// They are deliberately deleted (not adapted) in P2, in the same commit as
// the policy change that retires ownership as an authorization input.
package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// TestB6_CryptoOps_NonOwnerVaultMember_Returns403 asserts that a vault
// member who does not own a key is forbidden from using it for sign,
// verify, encrypt, decrypt, wrap, and unwrap, even via the vault-scoped
// route that grants vault-wide visibility for listing and get.
func TestB6_CryptoOps_NonOwnerVaultMember_Returns403(t *testing.T) {
	tests := []struct {
		name string
		path string
		body []byte
	}{
		{"sign", "/sign", []byte(`{"value":"aGVsbG8="}`)},
		{"verify", "/verify", []byte(`{"value":"aGVsbG8=","signature":"c2ln"}`)},
		{"encrypt", "/encrypt", []byte(`{"value":"aGVsbG8="}`)},
		{"decrypt", "/decrypt", []byte(`{"value":"Y3Q="}`)},
		{"wrap", "/wrap", []byte(`{"plaintext_key":"a2V5"}`)},
		{"unwrap", "/unwrap", []byte(`{"wrapped_key":"d3JhcHBlZA=="}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newB6FakeKeyRepo()
			ownerID := uuid.New()
			vaultID := uuid.New()
			keyID := uuid.New()
			repo.keys[keyID] = &model.Key{
				ID: keyID, UserID: ownerID, VaultID: vaultID,
				Name: "k1", Type: "RSA", Value: "irrelevant-before-authz-check",
				Enabled: true,
			}

			api, vrepo := newB6TestAPI(repo)
			vrepo.byName["prod"] = &model.Vault{ID: vaultID, Name: "prod", Enabled: true}
			vrepo.byID[vaultID.String()] = vrepo.byName["prod"]

			w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/keys/"+keyID.String()+tt.path, tt.body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s via vault route for non-owner key: expected 403, got %d (%s)", tt.name, w.Code, w.Body.String())
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestB6_CryptoOps_NonOwnerVaultMember_Returns403 -v`
Expected: FAIL to compile — `undefined: newB6FakeKeyRepo`, `undefined: newB6TestAPI`

- [ ] **Step 3: Add the fake repo and test-API helper**

Append to `api/vault_scoped_crypto_b6_test.go`:

```go
import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/app"
	keyServices "rocketvault/internal/services/keys"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// b6FakeKeyRepo is a minimal, deterministic KeyRepositoryInterface backed by
// an in-memory map. B6 tests need real ownership/vault data on the key
// (UserID, VaultID) rather than per-call expectations, so a plain map fits
// better here than a testify mock.
type b6FakeKeyRepo struct {
	keys map[uuid.UUID]*model.Key
}

func newB6FakeKeyRepo() *b6FakeKeyRepo {
	return &b6FakeKeyRepo{keys: map[uuid.UUID]*model.Key{}}
}

func (f *b6FakeKeyRepo) Create(ctx context.Context, k *model.Key) error {
	f.keys[k.ID] = k
	return nil
}
func (f *b6FakeKeyRepo) Read(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	if k, ok := f.keys[id]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}
func (f *b6FakeKeyRepo) Update(ctx context.Context, k *model.Key) error {
	f.keys[k.ID] = k
	return nil
}
func (f *b6FakeKeyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	delete(f.keys, id)
	return nil
}
func (f *b6FakeKeyRepo) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	return nil, nil
}
func (f *b6FakeKeyRepo) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return nil
}
func (f *b6FakeKeyRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	if k, ok := f.keys[id]; ok {
		now := time.Now()
		k.DeletedAt = &now
	}
	return nil
}
func (f *b6FakeKeyRepo) RecoverKey(ctx context.Context, id uuid.UUID) error { return nil }
func (f *b6FakeKeyRepo) PurgeKey(ctx context.Context, id uuid.UUID) error  { return nil }
func (f *b6FakeKeyRepo) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return nil
}
func (f *b6FakeKeyRepo) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Key, error) {
	return nil, nil
}
func (f *b6FakeKeyRepo) ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	if k, ok := f.keys[id]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}
func (f *b6FakeKeyRepo) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
	return nil
}
func (f *b6FakeKeyRepo) ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error) {
	return nil, nil
}
func (f *b6FakeKeyRepo) ListInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	return nil, nil
}
func (f *b6FakeKeyRepo) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Key, error) {
	k, ok := f.keys[id]
	if !ok || k.VaultID != vaultID {
		return nil, errors.New("key not found in vault")
	}
	return k, nil
}
func (f *b6FakeKeyRepo) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}
func (f *b6FakeKeyRepo) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}

// newB6TestAPI wires the vault-scoped key routes onto a real KeyService and
// real CryptoService backed by repo, so B6 tests exercise the actual
// loadAndAuthorize / DeleteKeyInVault ownership checks rather than a
// recording fake that always succeeds.
func newB6TestAPI(repo *b6FakeKeyRepo) (*API, *vaultFakeRepo) {
	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	keySvc := keyServices.NewKeyService(keyServices.KeyServiceConfig{
		KeyRepository: repo,
		Logger:        userTestLog(),
	})
	cryptoSvc := keyServices.NewCryptoService(keyServices.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        userTestLog(),
	})
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{
		vaultSvc: vsvc, keySvc: keySvc, cryptoSvc: cryptoSvc, logger: userTestLog(),
	}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	api.InitVault()
	api.InitKeys()
	return api, vrepo
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/... -run TestB6_CryptoOps_NonOwnerVaultMember_Returns403 -v`
Expected: PASS (all six subtests) — the crypto handlers in `api/keys.go` already map `keyservices.ErrKeyForbidden` to 403 via `c.SetPermissionError`, and `loadAndAuthorize` in `internal/services/keys/crypto_service.go:252-256` already rejects `key.UserID != userID`.

- [ ] **Step 5: Commit**

```bash
git add api/vault_scoped_crypto_b6_test.go
git commit -S -m "test(api): pin B6 — non-owner vault member gets 403 on crypto ops"
```

---

### Task 3: B6 regression test — key delete returns 403 for a non-owner, and fix the handler

**Files:**
- Modify: `api/vault_scoped_crypto_b6_test.go` (append test)
- Modify: `api/keys.go:622-631`
- Test: `api/vault_scoped_crypto_b6_test.go`

**Interfaces:**
- Consumes: `newB6FakeKeyRepo`, `newB6TestAPI` (Task 2); `keyservices.ErrKeyForbidden`, `keyservices.ErrKeyNotFound` (`internal/services/keys/key_service.go:25-33`).
- Produces: none new (this task closes out the B6 test file).

**Finding while writing this test:** `deleteKey` in `api/keys.go:622-631` calls `keyService.DeleteKeyInVault`, which already enforces ownership (`internal/services/keys/key_service.go:439-443`, returning `ErrKeyForbidden`) — but the handler's error switch only checks `ErrKeyNotFound`; every other error, including `ErrKeyForbidden`, falls into `c.SetInternalError(err)` and returns **500**, not 403. This is not one of the eight defects in spec section 4.2 (that table was traced from the audit-actor and cache-focused commits, not this handler), but it directly contradicts the B6 invariant the design spec asks P0 to pin for "key delete via `/vaults/{name}/keys/...`". Fixing it here, in the same commit as its own regression test, keeps the fix traceable to the test that found it rather than silently bundling it into an unrelated defect task.

- [ ] **Step 1: Write the failing test**

Append to `api/vault_scoped_crypto_b6_test.go`:

```go
// TestB6_KeyDelete_NonOwnerVaultMember_Returns403 asserts that DELETE on the
// vault-scoped key route is forbidden for a non-owner vault member, matching
// the crypto operations tested above.
func TestB6_KeyDelete_NonOwnerVaultMember_Returns403(t *testing.T) {
	repo := newB6FakeKeyRepo()
	ownerID := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()
	repo.keys[keyID] = &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID,
		Name: "k1", Type: "RSA", Value: "irrelevant", Enabled: true,
	}

	api, vrepo := newB6TestAPI(repo)
	vrepo.byName["prod"] = &model.Vault{ID: vaultID, Name: "prod", Enabled: true}
	vrepo.byID[vaultID.String()] = vrepo.byName["prod"]

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/keys/"+keyID.String(), nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("DELETE non-owner key via vault route: expected 403, got %d (%s)", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestB6_KeyDelete_NonOwnerVaultMember_Returns403 -v`
Expected: FAIL — `DELETE non-owner key via vault route: expected 403, got 500 (...)`

- [ ] **Step 3: Fix the handler's error mapping**

In `api/keys.go`, replace the `deleteKey` error handling (currently lines 623-631):

```go
	// Use service layer for deletion; userID enforces ownership within the vault.
	deleted, err := keyService.DeleteKeyInVault(r.Context(), keyID, vaultID, userID)
	if err != nil {
		switch {
		case errors.Is(err, keyservices.ErrKeyNotFound):
			c.SetNotFound("key")
		case errors.Is(err, keyservices.ErrKeyForbidden):
			c.SetPermissionError("key_access")
		default:
			c.SetInternalError(err)
		}
		return
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/... -run TestB6_KeyDelete_NonOwnerVaultMember_Returns403 -v`
Expected: PASS

Then run the whole B6 file and the whole `api` package:
Run: `go test ./api/... -v`
Expected: PASS (existing `TestDeleteKey*`-style tests, if any, are unaffected since they exercise the not-found and success paths, not forbidden)

- [ ] **Step 5: Commit**

```bash
git add api/vault_scoped_crypto_b6_test.go api/keys.go
git commit -S -m "fix(keys): map ErrKeyForbidden to 403 on vault-scoped key delete"
```

---

### Task 4: Cross-vault denial, real SQLite — secrets

**Files:**
- Create: `api/vault_cross_denial_test.go`
- Test: same file

**Interfaces:**
- Consumes: `repositories.NewSecretRepository` (`internal/repositories/secret_repository.go:89`); `secretServices.NewSecretService`, `secretServices.SecretServiceConfig` (`internal/services/secrets/secret_service.go:161-187`); `doVaultRequest`, `newVaultFakeRepo`, `vaultResolutionTestMiddleware`, `vaultNoopCascade{}`, `userTestLog()`, `vaultSvcTestContainer` (existing).
- Produces: `newCrossVaultSecretsTestAPI(t) (*API, *vaultFakeRepo, repositories.SecretRepositoryInterface)`, `seedCrossVaultPair(repo *vaultFakeRepo) (vaultAID, vaultBID uuid.UUID)` — Tasks 5-8 reuse `seedCrossVaultPair`.

- [ ] **Step 1: Write the failing test**

Create `api/vault_cross_denial_test.go`:

```go
// Package api — cross-vault denial regression tests backed by real SQLite
// repositories (design spec 2026-07-26, section 4.1 / 8). Unlike the
// hand-written fakes used elsewhere in this package, whose *InVault methods
// unconditionally succeed, these tests exercise the real repository SQL
// predicates (WHERE id = ? AND vault_id = ?) so a resource seeded in vault B
// is provably denied when requested via /vaults/{vault-a}/... . Permanent
// tests — not deleted by any later phase.
package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// TestCrossVaultDenial_Secret_RealSQLite seeds a secret in vault B and
// requests it via /vaults/vault-a/secrets/{id}, asserting 404. The real
// SecretRepository.ReadInVault predicate enforces the denial, not a fake.
func TestCrossVaultDenial_Secret_RealSQLite(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultBID,
		Name: "db-password", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET secret: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestCrossVaultDenial_Secret_RealSQLite -v`
Expected: FAIL to compile — `undefined: newCrossVaultSecretsTestAPI`, `undefined: seedCrossVaultPair`

- [ ] **Step 3: Add the shared helpers**

Append to `api/vault_cross_denial_test.go` (also extend the `import` block added in Step 1 with these entries):

```go
import (
	"context"
	"database/sql"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"

	"rocketvault/app"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	secretServices "rocketvault/internal/services/secrets"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// newCrossVaultSecretsTestAPI wires the vault-scoped secret routes onto a
// real SecretService backed by a real SecretRepository over an in-memory
// SQLite database. Only the SecretRepository needs to be real:
// GetSecretInVault's cross-vault-denial path returns before ever touching
// cryptoService or tagService, so both are left nil.
func newCrossVaultSecretsTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.SecretRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id               TEXT PRIMARY KEY,
		user_id          TEXT NOT NULL,
		vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name             TEXT NOT NULL,
		value            TEXT NOT NULL,
		version          INTEGER NOT NULL,
		created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at       TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type     TEXT NOT NULL DEFAULT '',
		enabled          BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at       TIMESTAMP NULL,
		not_before       TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create secrets schema: %v", err)
	}

	secretRepo := repositories.NewSecretRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	secretSvc := secretServices.NewSecretService(secretServices.SecretServiceConfig{
		SecretRepository: secretRepo,
		Logger:           userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, secretSvc: secretSvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	api.InitVault()
	api.InitSecrets()
	return api, vrepo, secretRepo
}

// seedCrossVaultPair seeds two enabled vaults ("vault-a", "vault-b") into
// repo and returns their IDs. Shared by every cross-vault-denial test.
func seedCrossVaultPair(repo *vaultFakeRepo) (vaultAID, vaultBID uuid.UUID) {
	vaultAID = uuid.New()
	repo.byName["vault-a"] = &model.Vault{ID: vaultAID, Name: "vault-a", Enabled: true}
	repo.byID[vaultAID.String()] = repo.byName["vault-a"]

	vaultBID = uuid.New()
	repo.byName["vault-b"] = &model.Vault{ID: vaultBID, Name: "vault-b", Enabled: true}
	repo.byID[vaultBID.String()] = repo.byName["vault-b"]
	return
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/... -run TestCrossVaultDenial_Secret_RealSQLite -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api/vault_cross_denial_test.go
git commit -S -m "test(api): cross-vault denial against real SQLite — secrets"
```

---

### Task 5: Cross-vault denial, real SQLite — keys

**Files:**
- Modify: `api/vault_cross_denial_test.go` (append)
- Test: same file

**Interfaces:**
- Consumes: `seedCrossVaultPair` (Task 4); `repositories.NewKeyRepository` (`internal/repositories/key_repository.go:90`); `keyServices.NewKeyService`, `keyServices.KeyServiceConfig` (Task 2).
- Produces: `newCrossVaultKeysTestAPI(t) (*API, *vaultFakeRepo, repositories.KeyRepositoryInterface)`.

- [ ] **Step 1: Write the failing test**

Append to `api/vault_cross_denial_test.go`:

```go
// TestCrossVaultDenial_Key_RealSQLite seeds a key in vault B and requests it
// via /vaults/vault-a/keys/{id}, asserting 404.
func TestCrossVaultDenial_Key_RealSQLite(t *testing.T) {
	api, vrepo, keyRepo := newCrossVaultKeysTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	keyID := uuid.New()
	if err := keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: uuid.New(), VaultID: vaultBID,
		Name: "signing-key", Type: "RSA", Value: "encrypted-pem", Enabled: true,
	}); err != nil {
		t.Fatalf("seed key in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/keys/"+keyID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET key: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestCrossVaultDenial_Key_RealSQLite -v`
Expected: FAIL to compile — `undefined: newCrossVaultKeysTestAPI`

- [ ] **Step 3: Add the helper**

Append to `api/vault_cross_denial_test.go`, and add `keyServices "rocketvault/internal/services/keys"` to the import block:

```go
// newCrossVaultKeysTestAPI wires the vault-scoped key routes onto a real
// KeyService backed by a real KeyRepository over an in-memory SQLite
// database. GetKeyInVault's cross-vault-denial path returns before
// touching keyProvider or keyCache, so both stay at their zero values.
func newCrossVaultKeysTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.KeyRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL,
		bits INTEGER NOT NULL DEFAULT 0,
		curve TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create keys schema: %v", err)
	}

	keyRepo := repositories.NewKeyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	keySvc := keyServices.NewKeyService(keyServices.KeyServiceConfig{
		KeyRepository: keyRepo,
		Logger:        userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, keySvc: keySvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	api.InitVault()
	api.InitKeys()
	return api, vrepo, keyRepo
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/... -run TestCrossVaultDenial_Key_RealSQLite -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api/vault_cross_denial_test.go
git commit -S -m "test(api): cross-vault denial against real SQLite — keys"
```

---

### Task 6: Cross-vault denial, real SQLite — certificates

**Files:**
- Modify: `api/vault_cross_denial_test.go` (append)
- Test: same file

**Interfaces:**
- Consumes: `seedCrossVaultPair` (Task 4); `repositories.NewCertificateRepository` (`internal/repositories/certificate_repository.go:87`); `certServices.NewCertificateService`, `certServices.CertificateServiceConfig` (`internal/services/certificates/certificate_service.go:107-129`).
- Produces: `newCrossVaultCertsTestAPI(t) (*API, *vaultFakeRepo, repositories.CertificateRepositoryInterface)`.

- [ ] **Step 1: Write the failing test**

Append to `api/vault_cross_denial_test.go`:

```go
// TestCrossVaultDenial_Certificate_RealSQLite seeds a certificate in vault B
// and requests it via /vaults/vault-a/certificates/{id}, asserting 404.
func TestCrossVaultDenial_Certificate_RealSQLite(t *testing.T) {
	api, vrepo, certRepo := newCrossVaultCertsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	certID := uuid.New()
	if err := certRepo.Create(context.Background(), &model.Certificate{
		ID: certID, UserID: uuid.New(), VaultID: vaultBID,
		Name:        "tls-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
	}); err != nil {
		t.Fatalf("seed certificate in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/certificates/"+certID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET certificate: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestCrossVaultDenial_Certificate_RealSQLite -v`
Expected: FAIL to compile — `undefined: newCrossVaultCertsTestAPI`

- [ ] **Step 3: Add the helper**

Append to `api/vault_cross_denial_test.go`, and add `certServices "rocketvault/internal/services/certificates"` to the import block:

```go
// newCrossVaultCertsTestAPI wires the vault-scoped certificate routes onto a
// real CertificateService backed by a real CertificateRepository over an
// in-memory SQLite database. GetCertificateInVault's cross-vault-denial path
// returns before touching keyRepo, so it stays nil.
func newCrossVaultCertsTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.CertificateRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		expires_at TIMESTAMP,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30,
		key_id TEXT,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		not_before TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create certificates schema: %v", err)
	}

	certRepo := repositories.NewCertificateRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	certSvc := certServices.NewCertificateService(certServices.CertificateServiceConfig{
		CertificateRepository: certRepo,
		Logger:                userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, certSvc: certSvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitCertificates()
	return api, vrepo, certRepo
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/... -run TestCrossVaultDenial_Certificate_RealSQLite -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api/vault_cross_denial_test.go
git commit -S -m "test(api): cross-vault denial against real SQLite — certificates"
```

---

### Task 7: Cross-vault denial, real SQLite — certificate policy

**Files:**
- Modify: `api/vault_cross_denial_test.go` (append)
- Test: same file

**Interfaces:**
- Consumes: `seedCrossVaultPair` (Task 4); real `CertificateRepository` schema (Task 6); `mockCertPolicyRepo` (existing, `api/certificate_policy_test.go:43-76`, same package).
- Produces: `TestCrossVaultDenial_CertificatePolicy_RealSQLite`.

The certificate policy get/upsert/delete handlers (`api/certificate_policy.go:29-42,100-115,170-183`) all gate on `certService.GetCertificateInVault` *before* ever touching the policy repository, and `certificate_policies` has no `vault_id` column of its own (deferred to P3 per spec section 10). So this test only needs the certificate repository to be real; the policy repository can stay the existing hand-written mock, asserted never called.

- [ ] **Step 1: Write the failing test**

Append to `api/vault_cross_denial_test.go`:

```go
// TestCrossVaultDenial_CertificatePolicy_RealSQLite seeds a certificate (with
// its policy sub-resource) in vault B and requests the policy via
// /vaults/vault-a/certificates/{id}/policy, asserting 404 and that the
// policy repository is never consulted.
func TestCrossVaultDenial_CertificatePolicy_RealSQLite(t *testing.T) {
	api, vrepo, certRepo, policyRepo := newCrossVaultCertPolicyTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	certID := uuid.New()
	if err := certRepo.Create(context.Background(), &model.Certificate{
		ID: certID, UserID: uuid.New(), VaultID: vaultBID,
		Name:        "tls-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
	}); err != nil {
		t.Fatalf("seed certificate in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/certificates/"+certID.String()+"/policy", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET .../policy: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
	policyRepo.AssertNotCalled(t, "GetByCertificateIDAny", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestCrossVaultDenial_CertificatePolicy_RealSQLite -v`
Expected: FAIL to compile — `undefined: newCrossVaultCertPolicyTestAPI`

- [ ] **Step 3: Add the helper**

Append to `api/vault_cross_denial_test.go`, and add `"github.com/stretchr/testify/mock"` to the import block:

```go
// newCrossVaultCertPolicyTestAPI wires the vault management routes and the
// vault-scoped certificate + policy routes onto a real CertificateService
// (real CertificateRepository over SQLite) and a mock certificate policy
// repository, so the test can assert the policy repository is never
// consulted once GetCertificateInVault denies the request.
func newCrossVaultCertPolicyTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.CertificateRepositoryInterface, *mockCertPolicyRepo) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		certificate TEXT NOT NULL,
		private_key TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		expires_at TIMESTAMP,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30,
		key_id TEXT,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		not_before TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create certificates schema: %v", err)
	}

	certRepo := repositories.NewCertificateRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	certSvc := certServices.NewCertificateService(certServices.CertificateServiceConfig{
		CertificateRepository: certRepo,
		Logger:                userTestLog(),
	})
	policyRepo := &mockCertPolicyRepo{}

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{
		vaultSvc: vsvc, certSvc: certSvc, certPolicyRepo: policyRepo, logger: userTestLog(),
	}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitCertificates()
	return api, vrepo, certRepo, policyRepo
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/... -run TestCrossVaultDenial_CertificatePolicy_RealSQLite -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api/vault_cross_denial_test.go
git commit -S -m "test(api): cross-vault denial against real SQLite — certificate policy"
```

---

### Task 8: Cross-vault denial, real SQLite — secret version endpoints

**Files:**
- Modify: `api/vault_cross_denial_test.go` (append)
- Test: same file

**Interfaces:**
- Consumes: `seedCrossVaultPair` (Task 4); real `secrets` schema (Task 4); `secretServices.NewVersioningService` (`internal/services/secrets/versioning_service.go:63-77`).
- Produces: `TestCrossVaultDenial_SecretVersions_RealSQLite`.

`GetSecretVersionsInVault`, `GetSecretVersionInVault`, and `GetLatestSecretVersionInVault` all delegate to `versioningService`, whose vault-scoped methods (`internal/services/secrets/versioning_service.go:238-303`) call `secretRepo.ReadInVault` first — this needs a *second*, dedicated helper because `SecretServiceConfig.VersionService` must be a real, working `VersioningServiceInterface` here (unlike Task 4, where it stays `nil` because `GetSecretInVault` never delegates to it).

- [ ] **Step 1: Write the failing test**

Append to `api/vault_cross_denial_test.go`:

```go
// TestCrossVaultDenial_SecretVersions_RealSQLite seeds a secret in vault B
// and requests its version endpoints via /vaults/vault-a/secrets/{id}/...,
// asserting denial on all three.
func TestCrossVaultDenial_SecretVersions_RealSQLite(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretVersionsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultBID,
		Name: "api-key", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in vault B: %v", err)
	}

	// listSecretVersionsHandler's vault-scoped branch (api/secrets.go:101-105)
	// maps every error to 500, not 404 -- a known, deliberately-deferred
	// defect (design spec 2026-07-26, section 5.3, P1 Phase 4: "the
	// listSecretVersionsHandler 500->404 correction"). P0 pins the current
	// behavior; fixing it is P1's job, not this plan's.
	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("cross-vault GET .../versions: expected 500 (pinned pending P1), got %d (%s)", w.Code, w.Body.String())
	}

	w = doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions/1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET .../versions/1: expected 404, got %d (%s)", w.Code, w.Body.String())
	}

	w = doVaultRequest(api, http.MethodGet, "/api/v1/vaults/vault-a/secrets/"+secretID.String()+"/versions/latest", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-vault GET .../versions/latest: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestCrossVaultDenial_SecretVersions_RealSQLite -v`
Expected: FAIL to compile — `undefined: newCrossVaultSecretVersionsTestAPI`

- [ ] **Step 3: Add the helper**

Append to `api/vault_cross_denial_test.go`:

```go
// newCrossVaultSecretVersionsTestAPI mirrors newCrossVaultSecretsTestAPI but
// wires a real VersioningService (backed by the same real SecretRepository)
// into SecretServiceConfig.VersionService, since the version-endpoint
// handlers delegate straight through to it. versionRepo/userRepo/cryptoSvc
// stay nil: every vault-scoped versioning method checks
// secretRepo.ReadInVault first and returns before touching them.
func newCrossVaultSecretVersionsTestAPI(t *testing.T) (*API, *vaultFakeRepo, repositories.SecretRepositoryInterface) {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id               TEXT PRIMARY KEY,
		user_id          TEXT NOT NULL,
		vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name             TEXT NOT NULL,
		value            TEXT NOT NULL,
		version          INTEGER NOT NULL,
		created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at       TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type     TEXT NOT NULL DEFAULT '',
		enabled          BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at       TIMESTAMP NULL,
		not_before       TIMESTAMP NULL
	)`)
	if err != nil {
		t.Fatalf("create secrets schema: %v", err)
	}

	secretRepo := repositories.NewSecretRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), userTestLog())
	versionSvc := secretServices.NewVersioningService(nil, secretRepo, nil, nil, userTestLog())
	secretSvc := secretServices.NewSecretService(secretServices.SecretServiceConfig{
		SecretRepository: secretRepo,
		VersionService:   versionSvc,
		Logger:           userTestLog(),
	})

	vrepo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(vrepo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, secretSvc: secretSvc, logger: userTestLog()}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{App: a, BaseRoutes: &Routes{}, basePath: "/api/v1", rootRouter: router, Logger: userTestLog()}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.VaultScoped.Use(vaultResolutionTestMiddleware(vrepo))
	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	api.InitVault()
	api.InitSecrets()
	return api, vrepo, secretRepo
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./api/... -run TestCrossVaultDenial_SecretVersions_RealSQLite -v`
Expected: PASS

Then run the whole cross-denial file and the whole `api` package:
Run: `go test ./api/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api/vault_cross_denial_test.go
git commit -S -m "test(api): cross-vault denial against real SQLite — secret versions"
```

---

### Task 9: Fix defect — CreateVersion ownership gate rejects legitimate vault-scoped updates

**Files:**
- Modify: `internal/services/secrets/secret_service.go:407-413`
- Test: `internal/services/secrets/secret_service_test.go`

**Interfaces:**
- Consumes: `testutils.MockSecretRepository`, `testutils.MockCryptographyService`, `testutils.MockVersioningService`, `testutils.MockTagService`, `newService(...)` (all existing, `internal/services/secrets/secret_service_test.go:18-33` and `internal/testutils/mocks.go`).
- Produces: none new.

**Defect (spec 4.2, row 1):** `UpdateSecretInVault` builds `CreateVersionRequest{UserID: req.UserID}` — `req.UserID` is the **caller**, not necessarily the secret's owner. `versioningService.CreateVersion` (`internal/services/secrets/versioning_service.go:88-97`) then rejects the call with `secret.UserID != req.UserID`, comparing the row's real owner against the caller. A vault member updating a secret they don't own gets HTTP 500 — the exact feature "any vault member may update" doesn't work.

- [ ] **Step 1: Write the failing test**

Append to `internal/services/secrets/secret_service_test.go`:

```go
// TestUpdateSecretInVault_NonOwnerVaultMember_CreateVersionUsesSecretOwner
// proves that a vault member who is not the secret's owner can still update
// it: CreateVersion must be invoked with the secret's actual owner, not the
// caller, or its internal ownership check rejects a legitimate update.
func TestUpdateSecretInVault_NonOwnerVaultMember_CreateVersionUsesSecretOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New() // vault member who does not own the secret
	vaultID := uuid.New()
	secretID := uuid.New()

	current := &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID,
		Name: "shared-secret", Value: "encrypted-current", Version: 1, Enabled: true,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("ReadInVault", ctx, secretID, vaultID).Return(current, nil)
	crypto.On("DecryptSecret", "encrypted-current").Return("plaintext-current", nil)
	crypto.On("EncryptSecret", "new-plaintext").Return("encrypted-new", nil)

	var gotVersionReq secrets.CreateVersionRequest
	ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).
		Run(func(args mock.Arguments) {
			gotVersionReq = args.Get(1).(secrets.CreateVersionRequest)
		}).
		Return(&model.SecretVersion{}, nil)
	repo.On("UpdateInVault", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	newValue := "new-plaintext"
	err := svc.UpdateSecretInVault(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		VaultID:  vaultID,
		UserID:   callerID,
		Value:    &newValue,
	})

	require.NoError(t, err, "a vault member updating a secret they do not own must succeed")
	assert.Equal(t, ownerID, gotVersionReq.UserID,
		"CreateVersion must be called with the secret's owner, not the caller, so its internal ownership gate does not reject a legitimate vault-scoped update")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run TestUpdateSecretInVault_NonOwnerVaultMember_CreateVersionUsesSecretOwner -v`
Expected: FAIL — `Error: Not equal: expected: <ownerID> actual: <callerID>` (assertion on `gotVersionReq.UserID`)

- [ ] **Step 3: Fix the versionReq construction**

In `internal/services/secrets/secret_service.go`, change the `versionReq` construction inside `UpdateSecretInVault` (currently lines 407-413):

```go
	// CreateVersion gates on secret.UserID == UserID; pass the secret's real
	// owner here, not the caller, so a legitimate vault-scoped update by a
	// non-owner member is not rejected by CreateVersion's internal check.
	versionReq := CreateVersionRequest{
		SecretID: currentSecret.ID,
		UserID:   currentSecret.UserID,
		Name:     currentSecret.Name,
		Value:    currentValue,
		Version:  currentSecret.Version,
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/secrets/... -run TestUpdateSecretInVault_NonOwnerVaultMember_CreateVersionUsesSecretOwner -v`
Expected: PASS

Then run the whole package: `go test ./internal/services/secrets/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_service_test.go
git commit -S -m "fix(secrets): CreateVersion uses the secret's owner, not the caller, on vault-scoped update"
```

---

### Task 10: Fix defect — CachedSecretService.UpdateSecretInVault does not invalidate cache

**Files:**
- Modify: `internal/cache/cache_integration.go:96-99`
- Test: `internal/cache/cache_integration_test.go`

**Interfaces:**
- Consumes: `mockSecretService`, `newTestCache(t)`, `newTestLogger()`, `makeSecret(userID)` (all existing, `internal/cache/cache_integration_test.go:22-240`).
- Produces: none new.

**Defect (spec 4.2, row 2):** `CachedSecretService.UpdateSecretInVault` (`internal/cache/cache_integration.go:97-99`) delegates without invalidating the cache, unlike `UpdateSecret` (lines 80-94). `GET /api/v1/secrets/{id}` serves stale plaintext for up to the TTL (5 min default) after a vault-scoped update.

- [ ] **Step 1: Write the failing test**

Append to `internal/cache/cache_integration_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/... -run TestCachedSecretService_UpdateSecretInVault_InvalidatesCache -v`
Expected: FAIL — `Error: Should be false` (the entry is still `found` in the cache)

- [ ] **Step 3: Invalidate cache on vault-scoped update**

In `internal/cache/cache_integration.go`, replace `UpdateSecretInVault` (currently lines 96-99):

```go
// UpdateSecretInVault updates a vault-scoped secret and invalidates cache.
func (s *CachedSecretService) UpdateSecretInVault(ctx context.Context, req secrets.UpdateSecretRequest) error {
	if err := s.secretService.UpdateSecretInVault(ctx, req); err != nil {
		return err
	}

	// Invalidate cache - the secret will be re-cached on next read.
	if err := s.cache.Delete(ctx, req.SecretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
		// Don't fail the operation if cache invalidation fails.
	}

	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cache/... -run TestCachedSecretService_UpdateSecretInVault_InvalidatesCache -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cache/cache_integration.go internal/cache/cache_integration_test.go
git commit -S -m "fix(cache): invalidate cache on vault-scoped secret update"
```

---

### Task 11: Fix defect — cache hit path skips IsAccessible()

**Files:**
- Modify: `internal/cache/cache_integration.go:34-45`
- Test: `internal/cache/cache_integration_test.go`

**Interfaces:**
- Consumes: `mockSecretService`, `newTestCache(t)`, `newTestLogger()`, `makeSecret(userID)` (existing).
- Produces: none new.

**Defect (spec 4.2, row 3):** `CachedSecretService.GetSecret`'s cache-hit path (`internal/cache/cache_integration.go:36-45`) only checks `cached.UserID == userID`. A secret that expires or is disabled while cached is still served from cache.

- [ ] **Step 1: Write the failing test**

Append to `internal/cache/cache_integration_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/... -run TestCachedSecretService_GetSecret_CacheHitInaccessible_FallsThrough -v`
Expected: FAIL — `Error: Not equal: expected: 1 actual: 0` (base service was never called; the disabled secret was served straight from cache)

- [ ] **Step 3: Recheck IsAccessible on the cache-hit path**

In `internal/cache/cache_integration.go`, change `GetSecret`'s cache-hit condition (currently lines 34-45):

```go
// GetSecret retrieves a secret, using cache when available.
func (s *CachedSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.Secret, error) {
	// Try cache first
	if cached, found := s.cache.Get(ctx, secretID); found {
		// Verify the cached secret belongs to the requesting user and is
		// still accessible (a secret can expire or be disabled while cached).
		if cached.UserID == userID && cached.IsAccessible() {
			s.logger.WithFields(logrus.Fields{
				"secret_id": secretID,
				"user_id":   userID,
			}).Debug("Cache hit for secret")
			return cached, nil
		}
	}
```

(The remainder of the function is unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cache/... -run TestCachedSecretService_GetSecret_CacheHitInaccessible_FallsThrough -v`
Expected: PASS

Then run the whole package: `go test ./internal/cache/... -v`
Expected: PASS (existing `TestCachedSecretService_GetSecret_CacheMiss_ThenHit` still passes: `makeSecret` defaults `Enabled` to Go's zero value `false`... verify this explicitly in Step 4's full-package run — if that test starts failing, it means `makeSecret` needs `Enabled: true`, which is a pre-existing test-data gap unrelated to this fix; if so, add `Enabled: true` to `makeSecret` in the same commit.)

- [ ] **Step 5: Commit**

```bash
git add internal/cache/cache_integration.go internal/cache/cache_integration_test.go
git commit -S -m "fix(cache): recheck IsAccessible on the cache-hit path"
```

---

### Task 12: Fix defect — SecretCache.Clear is a no-op for live entries; ImportSecrets needs Flush

**Files:**
- Modify: `internal/cache/secret_cache.go:99-115` (add `Flush`)
- Modify: `internal/cache/cache_integration.go:200-215` (`ImportSecrets` calls `Flush`)
- Test: `internal/cache/secret_cache_test.go`, `internal/cache/cache_integration_test.go`

**Interfaces:**
- Consumes: existing `SecretCache` test helpers (`internal/cache/secret_cache_test.go`); `mockSecretService`, `newTestCache(t)`, `newTestLogger()`, `makeSecret(userID)` (`internal/cache/cache_integration_test.go`).
- Produces: `(*SecretCache).Flush(ctx context.Context) error` — a new public method.

**Defect (spec 4.2, row 4):** `SecretCache.Clear` (`internal/cache/secret_cache.go:99-115`) only removes *expired* entries. `CachedSecretService.ImportSecrets`'s "clear cache to ensure consistency" comment (`internal/cache/cache_integration.go:208-211`) is therefore a no-op for any secret still within its 5-minute TTL. This exact gap is already documented as a workaround in the existing test `TestCachedSecretService_ImportSecrets_ClearsCache` (`internal/cache/cache_integration_test.go:787-791`): "SecretCache.Clear() only removes expired entries... To keep the test deterministic we verify the import result was returned correctly" — i.e. the existing test avoids asserting cache state specifically because of this bug.

- [ ] **Step 1: Write the failing tests**

Append to `internal/cache/secret_cache_test.go`:

```go
// TestSecretCacheFlush proves Flush empties the cache unconditionally,
// unlike Clear, which only prunes expired entries.
func TestSecretCacheFlush(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	cache := NewSecretCache(5*time.Minute, logger)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		secret := &model.Secret{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Name:      fmt.Sprintf("secret-%d", i),
			Value:     "encrypted-value",
			Version:   1,
			CreatedAt: time.Now(),
		}
		require.NoError(t, cache.Set(ctx, secret))
	}

	err := cache.Flush(ctx)
	assert.NoError(t, err)

	stats := cache.GetStats()
	assert.Equal(t, 0, stats["total_entries"], "Flush must remove all live entries, not just expired ones")
}
```

Append to `internal/cache/cache_integration_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/... -run TestSecretCacheFlush -v`
Expected: FAIL to compile — `cache.Flush undefined (type *SecretCache has no field or method Flush)`

Run: `go test ./internal/cache/... -run TestCachedSecretService_ImportSecrets_FlushesLiveCacheEntries -v`
Expected: FAIL to compile for the same reason, and (once `Flush` exists but before `ImportSecrets` calls it) FAIL with `Error: Should be false` — the live entry is still `found`.

- [ ] **Step 3: Add Flush and use it in ImportSecrets**

In `internal/cache/secret_cache.go`, add after `Clear` (currently ending at line 115):

```go
// Flush removes every entry from the cache unconditionally, live or
// expired. Unlike Clear, which only prunes expired entries, Flush is the
// correct primitive for callers that need a guaranteed-empty cache (e.g.
// bulk import, where secrets may change or be removed outside their TTL).
func (c *SecretCache) Flush(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := len(c.cache)
	c.cache = make(map[string]*CachedSecret)

	c.logger.WithField("removed_count", removed).Debug("Cache flushed")
	return nil
}
```

In `internal/cache/cache_integration.go`, change `ImportSecrets` (currently lines 200-215):

```go
// ImportSecrets imports secrets and flushes the cache to ensure consistency.
func (s *CachedSecretService) ImportSecrets(ctx context.Context, req secrets.ImportSecretsRequest) (*secrets.ImportResult, error) {
	// Import through underlying service
	result, err := s.secretService.ImportSecrets(ctx, req)
	if err != nil {
		return nil, err
	}

	// Flush (not Clear) so live, non-expired cache entries are also
	// removed -- a bulk import can change or delete secrets that are
	// still cached.
	if err := s.cache.Flush(ctx); err != nil {
		s.logger.WithError(err).Warn("Failed to flush cache after import")
		// Don't fail the operation if cache flush fails.
	}

	return result, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cache/... -run 'TestSecretCacheFlush|TestCachedSecretService_ImportSecrets_FlushesLiveCacheEntries' -v`
Expected: PASS

Then run the whole `cache` package: `go test ./internal/cache/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cache/secret_cache.go internal/cache/cache_integration.go internal/cache/secret_cache_test.go internal/cache/cache_integration_test.go
git commit -S -m "fix(cache): add Flush and use it for ImportSecrets' cache consistency"
```

---

### Task 13: Fix defect — CLI keys wrap/unwrap never set VaultID

**Files:**
- Modify: `cmd/keys/wrap.go:85-90`
- Modify: `cmd/keys/unwrap.go:85-90`
- Test: `cmd/keys/keys_cmd_test.go`

**Interfaces:**
- Consumes: `keyCmdCryptoService` (existing testify mock, `cmd/keys/keys_cmd_test.go:118`), `keysTestContainer` (existing, `cmd/keys/keys_cmd_test.go:197-211`), `newTestCmd`, `viperSet`, `newLogger` (existing helpers, same file).
- Produces: none new.

**Defect (spec 4.2, row 5):** `wrap.go:85-90` and `unwrap.go:85-90` build `WrapKeyRequest`/`UnwrapKeyRequest` without setting `VaultID`, which defaults to `uuid.Nil`. `loadAndAuthorize`'s `key.VaultID != vaultID` check (`internal/services/keys/crypto_service.go:246-250`) then always fails against a real key (whose `VaultID` is the default vault, never `uuid.Nil`). Both commands are broken today.

- [ ] **Step 1: Write the failing tests**

Append to `cmd/keys/keys_cmd_test.go`:

```go
func TestWrapCmd_SetsDefaultVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	plaintext := []byte("my-secret-key-material")
	wrapped := []byte("wrapped-bytes")
	cryptoSvc.On("WrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.WrapKeyRequest) bool {
		return r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.WrapKeyResult{WrappedKey: wrapped}, nil)

	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		cryptoSvc:             cryptoSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"wrap-key-id":       keyID.String(),
		"wrap-key-material": base64.StdEncoding.EncodeToString(plaintext),
	})
	defer cleanup()

	cmd, _ := newTestCmd(wrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}

func TestUnwrapCmd_SetsDefaultVaultID(t *testing.T) {
	cryptoSvc := &keyCmdCryptoService{}
	userID := uuid.New()
	keyID := uuid.New()
	wrapped := []byte("wrapped-bytes")
	plaintext := []byte("recovered-key-material")
	cryptoSvc.On("UnwrapKey", mock.Anything, mock.MatchedBy(func(r keyServices.UnwrapKeyRequest) bool {
		return r.VaultID == uuid.MustParse(model.DefaultVaultID)
	})).Return(&keyServices.UnwrapKeyResult{PlaintextKey: plaintext}, nil)

	sc := &keysTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		cryptoSvc:             cryptoSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSet(map[string]interface{}{
		"unwrap-key-id":      keyID.String(),
		"unwrap-wrapped-key": base64.StdEncoding.EncodeToString(wrapped),
	})
	defer cleanup()

	cmd, _ := newTestCmd(unwrapCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	cryptoSvc.AssertExpectations(t)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/keys/... -run 'TestWrapCmd_SetsDefaultVaultID|TestUnwrapCmd_SetsDefaultVaultID' -v`
Expected: FAIL — testify mock panic: `mock: I don't know what to return because the method call was unexpected.` (the actual `WrapKeyRequest`/`UnwrapKeyRequest` carries `VaultID: uuid.Nil`, which does not satisfy the `mock.MatchedBy` predicate, so there is no matching expectation)

- [ ] **Step 3: Set VaultID to the default vault**

In `cmd/keys/wrap.go`, change the `cryptoService.WrapKey` call (currently lines 85-90):

```go
		result, err := cryptoService.WrapKey(ctx, keyServices.WrapKeyRequest{
			KeyID:        keyID,
			UserID:       claims.UserID,
			VaultID:      uuid.MustParse(model.DefaultVaultID),
			PlaintextKey: plaintext,
			Algorithm:    "RSA-OAEP",
		})
```

In `cmd/keys/unwrap.go`, change the `cryptoService.UnwrapKey` call (currently lines 85-90):

```go
		result, err := cryptoService.UnwrapKey(ctx, keyServices.UnwrapKeyRequest{
			KeyID:      keyID,
			UserID:     claims.UserID,
			VaultID:    uuid.MustParse(model.DefaultVaultID),
			WrappedKey: wrappedKey,
			Algorithm:  "RSA-OAEP",
		})
```

Both files already import `github.com/google/uuid` and `rocketvault/model`; no import changes needed.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/keys/... -run 'TestWrapCmd_SetsDefaultVaultID|TestUnwrapCmd_SetsDefaultVaultID' -v`
Expected: PASS

Then run the whole package: `go test ./cmd/keys/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/keys/wrap.go cmd/keys/unwrap.go cmd/keys/keys_cmd_test.go
git commit -S -m "fix(keys): CLI wrap/unwrap set VaultID to the default vault"
```

---

### Task 14: Fix defect — audit actor is a vault UUID on vault-scoped secret update

**Files:**
- Modify: `internal/repositories/secret_repository.go:730,736,740,744`
- Test: `internal/repositories/secret_repository_test.go`

**Interfaces:**
- Consumes: `setupSecretTestDB(t)`, `newTestSecretLogger(t)` (existing, `internal/repositories/secret_repository_test.go:22-51`); `repositories.NewSecretRepository` (`internal/repositories/secret_repository.go:89`); `logging.AuditPersister` (`internal/logging/logging.go:35-37`).
- Produces: `fakeAuditPersister` (test-local type in `internal/repositories/secret_repository_test.go`).

**Defect (spec 4.2, row 6):** `SecretRepository.UpdateInVault` (`internal/repositories/secret_repository.go:717-752`) logs `secret.VaultID.String()` as the actor on all four `LogAuditError`/`LogAuditInfo` calls (lines 730, 736, 740, 744), writing a **vault UUID** into `audit_logs.user_id` — a column that is a queryable filter and feeds the hash chain. `Update` (the owner-scoped sibling, lines 251-286) correctly uses `secret.UserID.String()`.

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/secret_repository_test.go`:

```go
// fakeAuditPersister records every persisted audit event's actor (userID)
// for assertions. It implements logging.AuditPersister.
type fakeAuditPersister struct {
	actors []string
}

func (f *fakeAuditPersister) PersistAudit(userID, action, details string) error {
	f.actors = append(f.actors, userID)
	return nil
}

// TestSecretRepository_UpdateInVault_AttributesOwnerNotVaultID proves that
// UpdateInVault's audit rows are attributed to the secret's user, never the
// vault ID.
func TestSecretRepository_UpdateInVault_AttributesOwnerNotVaultID(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	logger := newTestSecretLogger(t)
	persister := &fakeAuditPersister{}
	logger.SetAuditPersister(persister)

	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), logger)
	ctx := context.Background()

	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID, Name: "s", Value: "enc", Version: 1,
	}))

	err := repo.UpdateInVault(ctx, &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID, Name: "s2", Value: "enc2", Version: 2,
	})
	require.NoError(t, err)

	require.NotEmpty(t, persister.actors)
	for _, actor := range persister.actors {
		assert.Equal(t, ownerID.String(), actor,
			"UpdateInVault must attribute audit rows to the secret's user, not the vault ID")
		assert.NotEqual(t, vaultID.String(), actor)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestSecretRepository_UpdateInVault_AttributesOwnerNotVaultID -v`
Expected: FAIL — `Error: Not equal: expected: "<ownerID>" actual: "<vaultID>"`

- [ ] **Step 3: Fix the audit actor**

In `internal/repositories/secret_repository.go`, change all four calls inside `UpdateInVault` (currently lines 724-744) from `secret.VaultID.String()` to `secret.UserID.String()`:

```go
	result, err := r.db.ExecContext(
		ctx,
		"UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ?, enabled = ?, expires_at = ?, not_before = ? WHERE id = ? AND vault_id = ?",
		secret.Name, secret.Value, secret.Version, secret.ContentType, secret.Enabled, secret.ExpiresAt, secret.NotBefore, secret.ID.String(), secret.VaultID.String(),
	)
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError(secret.UserID.String(), "update_secret", "failed", "Secret not found for update", nil)
		return fmt.Errorf("secret not found")
	}

	r.log.LogAuditInfo(secret.UserID.String(), "update_secret", "success", fmt.Sprintf("Secret updated: %s", secret.Name))
```

(The trailing `logrus.WithFields(...).Debug(...)` block, which legitimately logs `vault_id` as a structured field rather than an audit actor, is unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repositories/... -run TestSecretRepository_UpdateInVault_AttributesOwnerNotVaultID -v`
Expected: PASS

Then run the whole package: `go test ./internal/repositories/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/secret_repository.go internal/repositories/secret_repository_test.go
git commit -S -m "fix(secrets): UpdateInVault attributes audit rows to the owner, not the vault ID"
```

---

### Task 15: Fix defect — UpdateKeyInVault emits contradictory audit rows

**Files:**
- Modify: `internal/repositories/key_repository.go:302-317`
- Test: `internal/services/keys/key_service_update_test.go`

**Interfaces:**
- Consumes: `repositories.NewKeyRepository` (`internal/repositories/key_repository.go:90`); `keyService{keyRepo:..., logger:...}` (white-box, `internal/services/keys/key_service_update_test.go` is `package keys`); `logging.AuditPersister`.
- Produces: `fakeAuditPersister` (test-local type in `internal/services/keys/key_service_update_test.go`; distinct from the one in Task 14 — different package).

**Defect (spec 4.2, row 7):** After the `e38bd11` audit-attribution fix, `keyService.UpdateKeyInVault` (`internal/services/keys/key_service.go:620,628`) correctly logs `req.UserID.String()` (the actor). But `KeyRepository.Update` (`internal/repositories/key_repository.go:303,309,313,317`), which `UpdateKeyInVault` calls internally, *also* logs its own audit rows using `key.UserID.String()` — the key's **owner**, taken from the row read via `ReadInVault`, not the actor. When a non-owner vault member updates a key, this produces two audit rows for the same action attributing it to two different users.

- [ ] **Step 1: Write the failing test**

Append to `internal/services/keys/key_service_update_test.go`:

```go
import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
)

// fakeAuditPersister records every persisted audit event's actor (userID)
// for assertions. It implements logging.AuditPersister.
type fakeAuditPersister struct {
	actors []string
}

func (f *fakeAuditPersister) PersistAudit(userID, action, details string) error {
	f.actors = append(f.actors, userID)
	return nil
}

// TestUpdateKeyInVault_AuditRowsAttributeTheActor_NotTheOwner uses a real
// KeyRepository (not a mock) so both the service-layer and repository-layer
// audit calls actually fire, proving they no longer disagree.
func TestUpdateKeyInVault_AuditRowsAttributeTheActor_NotTheOwner(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer sqlDB.Close()
	_, err = sqlDB.Exec(`CREATE TABLE IF NOT EXISTS keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		revoked BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP DEFAULT NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP DEFAULT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL,
		bits INTEGER NOT NULL DEFAULT 0,
		curve TEXT NOT NULL DEFAULT '',
		updated_at TIMESTAMP NULL
	)`)
	require.NoError(t, err)

	logger := &logging.Logger{Logger: logrus.New()}
	persister := &fakeAuditPersister{}
	logger.SetAuditPersister(persister)

	keyRepo := repositories.NewKeyRepository(rvdb.NewConn(sqlDB, rvdb.SQLite), logger)

	ownerID := uuid.New()
	callerID := uuid.New() // a different vault member than the key's owner
	vaultID := uuid.New()
	keyID := uuid.New()
	require.NoError(t, keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: ownerID, VaultID: vaultID, Name: "old", Type: "RSA", Value: "enc", Enabled: true,
	}))

	svc := NewKeyService(KeyServiceConfig{KeyRepository: keyRepo, Logger: logger})

	newName := "new-name"
	err = svc.UpdateKeyInVault(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		UserID:  callerID,
		VaultID: vaultID,
		Name:    &newName,
	})
	require.NoError(t, err)

	for _, actor := range persister.actors {
		assert.Equal(t, callerID.String(), actor,
			"every audit row for a vault-scoped key update must attribute the actor (caller), not the key's owner")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/keys/... -run TestUpdateKeyInVault_AuditRowsAttributeTheActor_NotTheOwner -v`
Expected: FAIL — `Error: Not equal: expected: "<callerID>" actual: "<ownerID>"` (one of the two persisted rows is attributed to the owner, from `KeyRepository.Update`)

- [ ] **Step 3: Stop the repository from emitting its own audit rows**

In `internal/repositories/key_repository.go`, replace the body of `Update` (currently lines 297-325, inside the `executeWithMetrics` closure):

```go
		now := time.Now().UTC()
		key.UpdatedAt = &now
		result, err := r.db.ExecContext(
			ctx,
			"UPDATE keys SET name = ?, value = ?, revoked = ?, created_at = ?, enabled = ?, expires_at = ?, not_before = ?, bits = ?, curve = ?, updated_at = ? WHERE id = ?",
			key.Name, key.Value, key.Revoked, key.CreatedAt, key.Enabled, key.ExpiresAt, key.NotBefore, key.Bits, key.Curve, now, key.ID.String(),
		)
		if err != nil {
			return fmt.Errorf("failed to update key: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("key not found")
		}

		// Audit attribution belongs to the caller (service layer), which
		// knows the acting principal; this pure-CRUD method receives none,
		// and key.UserID is the row's owner, not necessarily the actor. Both
		// UpdateKey and UpdateKeyInVault already emit their own audit rows
		// after calling Update.
		logrus.WithFields(logrus.Fields{
			"key_id":  key.ID.String(),
			"user_id": key.UserID.String(),
			"name":    key.Name,
		}).Debug("Key updated successfully")

		return nil
	})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/keys/... -run TestUpdateKeyInVault_AuditRowsAttributeTheActor_NotTheOwner -v`
Expected: PASS

Then run both affected packages:
Run: `go test ./internal/services/keys/... ./internal/repositories/... -v`
Expected: PASS (existing `Update`/`UpdateKeyInVault` tests assert on returned errors and repository state, not on audit log content, so they are unaffected by removing the repo-level `LogAuditError`/`LogAuditInfo` calls)

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/key_repository.go internal/services/keys/key_service_update_test.go
git commit -S -m "fix(keys): KeyRepository.Update stops emitting owner-attributed audit rows"
```

---

### Task 16: Fix defect — RotationService.GetSecretPolicies and AcknowledgeReminder have no ownership check

**Files:**
- Modify: `internal/services/secrets/rotation_service.go:20-42,338-347,496-513`
- Modify: `internal/services/secrets/scheduler_service.go:309`
- Modify: `cmd/rotation_service_test.go:69-75,110-112`
- Modify: `cmd/rotation_security_test.go:61-64,89-91`
- Create: `internal/services/secrets/rotation_service_test.go`

**Interfaces:**
- Consumes: `testutils.MockSecretRepository`, `testutils.NewTestLogger(t)` (existing, `internal/testutils/mocks.go`); `repositories.RotationPolicyRepositoryInterface` (`internal/repositories/rotation_repository.go:21-50`).
- Produces: `mockRotationPolicyRepo` (test-local type in the new file); new signatures `GetSecretPolicies(ctx, secretID, userID uuid.UUID)` and `AcknowledgeReminder(ctx, reminderID, secretID, userID uuid.UUID)` on `RotationServiceInterface`.

**Defect (spec 4.2, row 8):** `GetSecretPolicies` (`internal/services/secrets/rotation_service.go:339`) and `AcknowledgeReminder` (`:497`) take no `userID` and perform no ownership check at all — any caller can view or acknowledge any secret's rotation state. `GetSecretPolicies` has zero non-test callers today; `AcknowledgeReminder`'s only caller is `schedulerService.sendReminder` (`internal/services/secrets/scheduler_service.go:309`), a trusted internal process that already has the full `model.RotationReminder` (including `SecretID`) in scope. Both methods gain a `userID` parameter that is skippable via `uuid.Nil`, mirroring the existing convention on `KeyService.DeleteKeyInVault` ("pass uuid.Nil to skip the check (admin/cascade ops)").

- [ ] **Step 1: Write the failing test**

Create `internal/services/secrets/rotation_service_test.go`:

```go
package secrets_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// mockRotationPolicyRepo is a testify mock of repositories.RotationPolicyRepositoryInterface.
type mockRotationPolicyRepo struct{ mock.Mock }

func (m *mockRotationPolicyRepo) Create(ctx context.Context, policy *model.RotationPolicy) error {
	return m.Called(ctx, policy).Error(0)
}
func (m *mockRotationPolicyRepo) Read(ctx context.Context, id uuid.UUID) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) Update(ctx context.Context, policy *model.RotationPolicy) error {
	return m.Called(ctx, policy).Error(0)
}
func (m *mockRotationPolicyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}
func (m *mockRotationPolicyRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) AssignToSecret(ctx context.Context, secretID, policyID uuid.UUID, assignedAt, nextRotationAt time.Time) error {
	return m.Called(ctx, secretID, policyID, assignedAt, nextRotationAt).Error(0)
}
func (m *mockRotationPolicyRepo) RemoveFromSecret(ctx context.Context, secretID, policyID uuid.UUID) error {
	return m.Called(ctx, secretID, policyID).Error(0)
}
func (m *mockRotationPolicyRepo) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) GetPoliciesForSecret(ctx context.Context, secretID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) UpdateSecretPolicyRotation(ctx context.Context, secretID, policyID uuid.UUID, lastRotatedAt, nextRotationAt time.Time) error {
	return m.Called(ctx, secretID, policyID, lastRotatedAt, nextRotationAt).Error(0)
}
func (m *mockRotationPolicyRepo) RecordRotation(ctx context.Context, history *model.RotationHistory) error {
	return m.Called(ctx, history).Error(0)
}
func (m *mockRotationPolicyRepo) GetRotationHistory(ctx context.Context, secretID uuid.UUID) ([]model.RotationHistory, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationHistory), args.Error(1)
}
func (m *mockRotationPolicyRepo) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]model.RotationReminder, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationReminder), args.Error(1)
}
func (m *mockRotationPolicyRepo) CreateReminder(ctx context.Context, reminder *model.RotationReminder) error {
	return m.Called(ctx, reminder).Error(0)
}
func (m *mockRotationPolicyRepo) UpdateReminder(ctx context.Context, reminder *model.RotationReminder) error {
	return m.Called(ctx, reminder).Error(0)
}
func (m *mockRotationPolicyRepo) GetReminderBySecret(ctx context.Context, secretID, policyID uuid.UUID, reminderType string) (*model.RotationReminder, error) {
	args := m.Called(ctx, secretID, policyID, reminderType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationReminder), args.Error(1)
}

func TestGetSecretPolicies_NonOwner_Forbidden(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	secretID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: ownerID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	_, err := svc.GetSecretPolicies(ctx, secretID, callerID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not own")
	rotationRepo.AssertNotCalled(t, "GetPoliciesForSecret", mock.Anything, mock.Anything)
}

func TestGetSecretPolicies_Owner_Succeeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	secretID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: ownerID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("GetPoliciesForSecret", ctx, secretID).Return([]model.RotationPolicy{{ID: uuid.New()}}, nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	policies, err := svc.GetSecretPolicies(ctx, secretID, ownerID)

	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

func TestGetSecretPolicies_NilUserID_SkipsOwnershipCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("GetPoliciesForSecret", ctx, secretID).Return([]model.RotationPolicy{}, nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	_, err := svc.GetSecretPolicies(ctx, secretID, uuid.Nil)

	require.NoError(t, err)
	secretRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything)
}

func TestAcknowledgeReminder_NonOwner_Forbidden(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	secretID := uuid.New()
	reminderID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: ownerID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	err := svc.AcknowledgeReminder(ctx, reminderID, secretID, callerID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not own")
	rotationRepo.AssertNotCalled(t, "UpdateReminder", mock.Anything, mock.Anything)
}

func TestAcknowledgeReminder_SystemCaller_SkipsOwnershipCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	reminderID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("UpdateReminder", ctx, mock.MatchedBy(func(r *model.RotationReminder) bool {
		return r.ID == reminderID && r.Acknowledged
	})).Return(nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	err := svc.AcknowledgeReminder(ctx, reminderID, secretID, uuid.Nil)

	require.NoError(t, err)
	secretRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything)
	rotationRepo.AssertExpectations(t)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run 'TestGetSecretPolicies_|TestAcknowledgeReminder_' -v`
Expected: FAIL to compile — `not enough arguments in call to svc.GetSecretPolicies` / `not enough arguments in call to svc.AcknowledgeReminder`

- [ ] **Step 3: Add the ownership checks**

In `internal/services/secrets/rotation_service.go`, change the interface (currently lines 31 and 41):

```go
	GetSecretPolicies(ctx context.Context, secretID, userID uuid.UUID) ([]model.RotationPolicy, error)
```

```go
	// AcknowledgeReminder marks a reminder as acknowledged. secretID
	// identifies the secret the reminder belongs to. userID enforces
	// ownership before the update; pass uuid.Nil to skip the check
	// (system/scheduler callers), mirroring KeyService.DeleteKeyInVault.
	AcknowledgeReminder(ctx context.Context, reminderID, secretID, userID uuid.UUID) error
```

Change `GetSecretPolicies` (currently lines 338-347):

```go
// GetSecretPolicies gets all rotation policies assigned to a secret. userID
// enforces ownership; pass uuid.Nil to skip the check (admin/system callers).
func (s *rotationService) GetSecretPolicies(ctx context.Context, secretID, userID uuid.UUID) ([]model.RotationPolicy, error) {
	if userID != uuid.Nil {
		secret, err := s.secretRepo.Read(ctx, secretID)
		if err != nil {
			return nil, fmt.Errorf("secret not found: %w", err)
		}
		if secret.UserID != userID {
			return nil, fmt.Errorf("user does not own this secret")
		}
	}

	policies, err := s.rotationRepo.GetPoliciesForSecret(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get secret policies")
		return nil, fmt.Errorf("failed to get secret policies: %w", err)
	}

	return policies, nil
}
```

Change `AcknowledgeReminder` (currently lines 496-513):

```go
// AcknowledgeReminder marks a reminder as acknowledged. secretID identifies
// the secret the reminder belongs to; userID enforces ownership before the
// update. Pass uuid.Nil for userID to skip the check (system/scheduler
// callers).
func (s *rotationService) AcknowledgeReminder(ctx context.Context, reminderID, secretID, userID uuid.UUID) error {
	if userID != uuid.Nil {
		secret, err := s.secretRepo.Read(ctx, secretID)
		if err != nil {
			return fmt.Errorf("secret not found: %w", err)
		}
		if secret.UserID != userID {
			return fmt.Errorf("user does not own this secret")
		}
	}

	// This would typically fetch the reminder first, then update it.
	// For simplicity, we'll create a reminder object with just the ID and
	// acknowledged status.
	reminder := &model.RotationReminder{
		ID:           reminderID,
		Acknowledged: true,
	}

	err := s.rotationRepo.UpdateReminder(ctx, reminder)
	if err != nil {
		s.log.WithError(err).WithField("reminder_id", reminderID).Error("Failed to acknowledge reminder")
		return fmt.Errorf("failed to acknowledge reminder: %w", err)
	}

	s.log.WithField("reminder_id", reminderID).Info("Reminder acknowledged successfully")
	return nil
}
```

Update the only production caller, `internal/services/secrets/scheduler_service.go` (currently line 309):

```go
	// Acknowledge the reminder through rotation service. uuid.Nil marks the
	// scheduler as a trusted system caller, skipping the ownership check --
	// it is acknowledging its own generated reminder, not acting on behalf
	// of a specific user.
	err := s.rotationSvc.AcknowledgeReminder(ctx, reminder.ID, reminder.SecretID, uuid.Nil)
```

(`uuid` is already imported in `scheduler_service.go` since `model.RotationReminder` fields are `uuid.UUID`.)

Update the two hand-written `RotationServiceInterface` mocks so the repository still compiles. In `cmd/rotation_service_test.go`, change `MockRotationSvc` (currently lines 69-75 and 110-112):

```go
func (m *MockRotationSvc) GetSecretPolicies(ctx context.Context, secretID, userID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}
```

```go
func (m *MockRotationSvc) AcknowledgeReminder(ctx context.Context, reminderID, secretID, userID uuid.UUID) error {
	return nil
}
```

In `cmd/rotation_security_test.go`, change `mockRotationService` (currently lines 61-64 and 89-91):

```go
func (m *mockRotationService) GetSecretPolicies(ctx context.Context, secretID, userID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID, userID)
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}
```

```go
func (m *mockRotationService) AcknowledgeReminder(ctx context.Context, reminderID, secretID, userID uuid.UUID) error {
	return m.Called(ctx, reminderID, secretID, userID).Error(0)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/secrets/... -run 'TestGetSecretPolicies_|TestAcknowledgeReminder_' -v`
Expected: PASS

Then run the full verification gate (this task touches a shared interface, `cmd/rotation.go`'s callers, and two other packages' mocks):
Run: `go build ./... && go test ./...`
Expected: PASS, zero failures

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/rotation_service.go internal/services/secrets/scheduler_service.go internal/services/secrets/rotation_service_test.go cmd/rotation_service_test.go cmd/rotation_security_test.go
git commit -S -m "fix(rotation): GetSecretPolicies and AcknowledgeReminder enforce ownership"
```

---

### Task 17: Adopt mockery for the generated-mock interfaces

**Files:**
- Create: `.mockery.yaml`
- Modify: `internal/services/keys/wrap_key_test.go:47-97` (delete `mockKeyRepoForWrap`; use the generated mock)
- Test: `internal/services/keys/wrap_key_test.go`

**Interfaces:**
- Consumes: `repositories.KeyRepositoryInterface` (`internal/repositories/key_repository.go:24-49`).
- Produces: `mocks.MockSecretService`, `mocks.MockKeyService`, `mocks.MockCertificateService`, `mocks.MockVersioningServiceInterface`, `mocks.MockSecretRepositoryInterface`, `mocks.MockKeyRepositoryInterface`, `mocks.MockCertificateRepositoryInterface` — generated packages, one per interface's own directory (`internal/services/secrets/mocks`, `internal/services/keys/mocks`, `internal/services/certificates/mocks`, `internal/repositories/mocks`).

**Scope note:** The design spec (section 4.3) names five hand-written mock files reimplementing ~115 methods across `SecretService`, `KeyService`, `CertificateService`, `VersioningServiceInterface`, and the secret/key/certificate repository interfaces. This task adds the `mockery` config and generation step covering all seven interfaces, and migrates one full example end-to-end (`KeyRepositoryInterface`'s hand-written mock in `wrap_key_test.go`) so the pattern is proven and the remaining four hand-written mocks (`cmd/testutils.MockSecretService`, `internal/testutils.MockSecretRepository`, `internal/testutils.MockVersioningService`, `internal/services/certificates/cert_soft_delete_test.go`'s `mockCertRepository`) can be migrated the same way in fast-follow commits without re-deriving the approach. Two additional partial, already-stale hand-written mocks (`cmd/keys/service_test.go`'s `MockKeyService`, 9/13 methods; `cmd/certificates/service_test.go`'s `MockCertificateService`, 9/12 methods) exercise a synthetic hand-rolled command body rather than the real CLI command and are a pre-existing test-quality gap independent of this task; replacing their type does not fix that gap, so they are left for the same fast-follow pass.

**P1 does not block on the fast-follow work.** Sized during plan review: the deferred migration spans 14 test files and ~208 hand-written mock methods (`cmd/testutils/test_utils.go` 93, `internal/testutils/mocks.go` 115). P1's plan is written to be resilient to it — each of its Phase 2 and Phase 3 mock steps runs `mockery`, gates on `go test ./...`, and supplies the exact hand-written methods for the 12 mock implementations it enumerates in case any survived P0. So Task 17 delivering config plus one worked migration is sufficient to unblock P1; completing the other four is an optimisation that reduces P1's hand-editing, not a prerequisite. Do not treat a partial Task 17 as a failed gate.

- [ ] **Step 1: Write the failing test**

`wrap_key_test.go`'s existing tests already assert the behavior this migration must preserve; there is no new behavior to pin. Instead, this step proves the *current* state — the hand-written `mockKeyRepoForWrap` compiles and passes — as the baseline the migration must not regress:

Run: `go test ./internal/services/keys/... -run 'TestWrapAndUnwrapKey|TestWrapKeyForbiddenForWrongUser|TestWrapKeyRejectsUnsupportedAlgorithm|TestWrapKey_AESKWAlgorithmNotRejectedByAllowlist' -v`
Expected: PASS (baseline, before any change)

- [ ] **Step 2: Run test to verify it fails**

Delete the `mockKeyRepoForWrap` type and its 17 methods from `internal/services/keys/wrap_key_test.go` (currently lines 47-97), leaving the five tests that construct `&mockKeyRepoForWrap{}` referencing an undefined type.

Run: `go test ./internal/services/keys/... -run 'TestWrapAndUnwrapKey|TestWrapKeyForbiddenForWrongUser|TestWrapKeyRejectsUnsupportedAlgorithm|TestWrapKey_AESKWAlgorithmNotRejectedByAllowlist' -v`
Expected: FAIL to compile — `undefined: mockKeyRepoForWrap`

- [ ] **Step 3: Add the mockery config, generate, and rewire the tests**

Create `.mockery.yaml` at the repository root:

```yaml
with-expecter: true
dir: "{{.InterfaceDir}}/mocks"
outpkg: mocks
filename: "mock_{{.InterfaceName}}.go"
mockname: "Mock{{.InterfaceName}}"
packages:
  rocketvault/internal/services/secrets:
    interfaces:
      SecretService:
      VersioningServiceInterface:
  rocketvault/internal/services/keys:
    interfaces:
      KeyService:
  rocketvault/internal/services/certificates:
    interfaces:
      CertificateService:
  rocketvault/internal/repositories:
    interfaces:
      SecretRepositoryInterface:
      KeyRepositoryInterface:
      CertificateRepositoryInterface:
```

Generate the mocks (run from the repository root):

```bash
go run github.com/vektra/mockery/v2@latest --config .mockery.yaml
```

This produces `internal/repositories/mocks/mock_KeyRepositoryInterface.go` (package `mocks`, type `MockKeyRepositoryInterface`), plus the equivalent files for the other six interfaces.

Update `internal/services/keys/wrap_key_test.go`: add the import and replace every `&mockKeyRepoForWrap{}` construction with the generated mock's constructor. The generated mock (`with-expecter: true`) exposes `mocks.NewMockKeyRepositoryInterface(t)` plus an `.EXPECT()` builder, but also still embeds `mock.Mock` so the existing `.On("Read", mock.Anything, keyID).Return(vaultKey, nil)` call style keeps working unchanged — only the constructor and type name change:

```go
import (
	"rocketvault/internal/repositories/mocks"
)
```

```go
	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID).Return(vaultKey, nil)
```

applied at each of the five call sites (`TestWrapAndUnwrapKey`, `TestWrapAndUnwrapKey_OAEP256`, `TestWrapKeyForbiddenForWrongUser`, `TestWrapKeyRejectsUnsupportedAlgorithm`, `TestWrapKey_AESKWAlgorithmNotRejectedByAllowlist`). `mocks.NewMockKeyRepositoryInterface(t)` registers `t.Cleanup` to call `AssertExpectations` automatically, so the explicit `repo.AssertExpectations(t)` calls in these tests may stay (harmless, redundant) or be removed.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/keys/... -run 'TestWrapAndUnwrapKey|TestWrapKeyForbiddenForWrongUser|TestWrapKeyRejectsUnsupportedAlgorithm|TestWrapKey_AESKWAlgorithmNotRejectedByAllowlist' -v`
Expected: PASS

Then run the full verification gate:
Run: `go build ./... && go test ./...`
Expected: PASS, zero failures

- [ ] **Step 5: Commit**

```bash
git add .mockery.yaml internal/repositories/mocks internal/services/secrets/mocks internal/services/keys/mocks internal/services/certificates/mocks internal/services/keys/wrap_key_test.go
git commit -S -m "chore(mocks): adopt mockery for SecretService, KeyService, CertificateService, VersioningServiceInterface, and repository interfaces"
```

---

## Self-review

**(a) Spec §4 coverage.** §4.1 B6 (sign/verify/encrypt/decrypt/wrap/unwrap + delete, non-owner → 403): Tasks 2-3. §4.1 cross-vault denial (secrets, keys, certificates, certificate policy, secret version endpoints), real SQLite: Tasks 4-8. §4.2 all eight defects: Task 9 (CreateVersion gate), Task 10 (cache invalidation), Task 11 (cache IsAccessible), Task 12 (Clear vs Flush), Task 13 (CLI wrap/unwrap VaultID), Task 14 (secret audit actor), Task 15 (key audit contradiction), Task 16 (rotation ownership). §4.3 mockery: Task 17, scoped per the note in that task (full config + generation for all seven interfaces; one full worked migration; four remaining hand-written mocks flagged for fast-follow with the pattern established).

**(b) Placeholder scan.** No task contains "TBD", "similar to Task N", or an undemonstrated code step; every step has a complete, real code block or a real shell command. Task 17's scope note is an explicit, justified exception documented in-line, not a placeholder.

**(c) Type/signature consistency across tasks.** `vaultSvcTestContainer.cryptoSvc` (Task 1) is consumed by `newB6TestAPI` (Task 2) exactly as produced. `newB6FakeKeyRepo`/`newB6TestAPI` (Task 2) are consumed unchanged by Task 3. `seedCrossVaultPair` (Task 4) is consumed identically by Tasks 5-8. `RotationServiceInterface.GetSecretPolicies(ctx, secretID, userID)` and `AcknowledgeReminder(ctx, reminderID, secretID, userID)` (Task 16) are used with matching argument order and count in the new test file, the scheduler call site, and both hand-written mocks updated in the same task. `SecretCache.Flush` (Task 12) is defined and consumed within the same task; Task 12's `ImportSecrets` change references it correctly.

## Spec requirement not fully planned

None of spec section 4's requirements are unplanned. The one partial item is disclosed in Task 17's scope note rather than silently dropped: full call-site migration for four of the five originally hand-written mock files (`cmd/testutils.MockSecretService`, `internal/testutils.MockSecretRepository`, `internal/testutils.MockVersioningService`, `internal/services/certificates/cert_soft_delete_test.go`'s `mockCertRepository`) is not written out task-by-task here, because doing so faithfully requires reading every call site across those files in full — which this pass did not do for all of them — and the plan's no-placeholder rule forbids writing that migration without having verified the exact content being replaced. Task 17 delivers the `.mockery.yaml` covering all seven interfaces (the mechanical generation step, which *is* fully specified) plus one complete worked example, so the remaining migrations are a mechanical repeat of an already-proven pattern rather than open design work.
