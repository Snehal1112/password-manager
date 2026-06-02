# Minor Bug Fixes (Issues 6–10) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix five minor issues identified in the architecture review: SQL migration indexes gap, vault-scope bypass in soft-delete restore/purge, DELETE→500 on not-found, GET→404 on all errors, and missing `VaultID` population in five repository methods.

**Architecture:** All fixes are contained within existing packages — no new packages required. Issues 8 and 9 share a common root cause (no sentinel error discrimination) and are fixed together by introducing per-service sentinel vars + handler-level `errors.Is` checks. All other fixes are surgical one-file edits.

**Tech Stack:** Go 1.24, Gorilla Mux, SQLite/PostgreSQL, `errors.Is`/`fmt.Errorf %w`

---

## File Map

| File | Change |
|---|---|
| `internal/db/migrations/20260529000001_add_vaults.sql` | Add three `CREATE UNIQUE INDEX IF NOT EXISTS` statements (Issue 6) |
| `api/soft_delete.go` | `recoverSecret`/`purgeSecret` — use vault scope instead of user ownership (Issue 7) |
| `internal/services/secrets/secret_service.go` | Introduce `ErrSecretNotFound`, `ErrSecretLifecycleDenied`; wrap in `DeleteSecretInVault` + `GetSecretInVault` (Issues 8, 9) |
| `internal/services/keys/key_service.go` | Introduce `ErrKeyNotFound`; wrap in `DeleteKeyInVault` + `GetKeyInVault` (Issues 8, 9) |
| `internal/services/certificates/certificate_service.go` | Introduce `ErrCertNotFound`; wrap in `DeleteCertificateInVault` + `GetCertificateInVault` (Issues 8, 9) |
| `api/secrets.go` | `deleteSecret` check `errors.Is(err, ErrSecretNotFound)` → 404; `getSecret` check sentinel → 404/403/500 (Issues 8, 9) |
| `api/keys.go` | `deleteKey` + `getKey` same pattern (Issues 8, 9) |
| `api/certificates.go` | `deleteCertificate` + `getCertificate` same pattern (Issues 8, 9) |
| `internal/repositories/secret_repository.go` | `ListInVault` + `ListInVaultIncludeDeleted`: set `secret.VaultID = vaultID` on each row (Issue 10) |
| `internal/repositories/key_repository.go` | `ListInVault` + `ReadInVault`: set `key.VaultID = vaultID` (Issue 10) |
| `internal/repositories/certificate_repository.go` | `ListInVault` + `ReadInVault`: set `cert.VaultID = vaultID` (Issue 10) |

---

## Task 1: Add vault-unique indexes to migration SQL (Issue 6)

**Files:**
- Modify: `internal/db/migrations/20260529000001_add_vaults.sql`
- Test: `internal/db/db_test.go` (or a new migration-specific test verifying the indexes exist after migration)

> Context: `internal/db/db.go:finalizeVaultIndexes` creates `UNIQUE INDEX` on `(vault_id, name)` for secrets/keys/certificates at server startup via Go code. The SQL migration file currently only creates the table and backfills `vault_id` but does NOT create these indexes, so a `migrate`-only operator never gets the uniqueness guarantee.  
> The Go collision resolver (`ResolveNameCollisions`) cannot be replicated in SQL. Add only the `CREATE UNIQUE INDEX IF NOT EXISTS` statements. On a database with pre-existing collisions the indexes will fail, but that is the same behavior as a fresh migration and a deploy-time `finalizeVaultIndexes` call. Document this in a SQL comment.

- [ ] **Step 1: Open the migration file and read it in full**

  Confirm it ends after the `vault_id` backfill UPDATEs and the `access_policies` ALTER TABLE.

- [ ] **Step 2: Append the three UNIQUE INDEX statements**

  Add to the end of `20260529000001_add_vaults.sql`:
  ```sql
  -- Create per-vault unique name indexes. These mirror the indexes created by
  -- finalizeVaultIndexes() on server startup. If name collisions exist the
  -- CREATE statements will fail; run `rocketvault serve` once first to resolve
  -- collisions via the Go-side collision resolver, then re-run migrations.
  CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_vault_name      ON secrets(vault_id, name);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_vault_name         ON keys(vault_id, name);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_vault_name ON certificates(vault_id, name);
  ```

- [ ] **Step 3: Verify the migration file parses correctly**

  Run:
  ```bash
  cd /home/numericlabs/data/rocket/rocketvault
  sqlite3 /tmp/test_migration.db < internal/db/migrations/20260529000001_add_vaults.sql 2>&1 || true
  ```
  
  Expect: The commands for the index creation will partially fail (because prerequisites like the `secrets` table aren't created by this file alone), but no syntax errors. If there's a syntax error, fix it.

- [ ] **Step 4: Run full test suite to confirm no regression**

  ```bash
  cd /home/numericlabs/data/rocket/rocketvault
  go test ./internal/db/... -count=1 -timeout 60s
  ```

- [ ] **Step 5: Commit**

  ```
  fix: add vault-unique indexes to add_vaults migration SQL
  
  Mirrors the CREATE UNIQUE INDEX statements that finalizeVaultIndexes()
  creates on server startup. Operators running migrate-only now get the
  uniqueness guarantee without a server start.
  ```

---

## Task 2: Fix vault-scope bypass in recoverSecret / purgeSecret (Issue 7)

**Files:**
- Modify: `api/soft_delete.go`
- Test: `api/soft_delete_test.go` or `api/soft_delete_extended_test.go`

> Context: `recoverSecret` and `purgeSecret` currently verify ownership by calling `repo.ListByUserIncludeDeleted(userID)` — checking the JWT's user_id. The soft-delete route is vault-scoped (`/vaults/{name}/deleted/secrets/{id}/restore`), so it must verify that the secret belongs to the resolved vault, not the current user. This contradicts the documented invariant that no vault-scoped route silently ignores its vault. The fix: resolve `vaultID` from the request context (identical to how `listDeletedSecrets` already does it), then use `repo.ListInVaultIncludeDeleted(vaultID)` to confirm the secret is in the vault before recovering/purging.  
> NOTE: This is a *behaviour change* on the vault-scoped route only. The legacy flat `/deleted/secrets/{id}/restore` route still goes through the same function (since `registerDeletedRoutes` calls `registerVaultScopedDeletedRoutes` which registers the same handler), so removing the user-ownership check could allow any vault member to restore another user's secret. The correct approach is to keep user-ownership verification as a fallback AND add vault verification when the route is vault-scoped.  
> REVISED FIX: When `isVaultScopedRoute(r)` is true, verify by vault (ListInVaultIncludeDeleted). When not vault-scoped, keep the existing user-ownership check. This matches the `getSecret`/`listSecrets` pattern.

- [ ] **Step 1: Write failing test**

  In `api/soft_delete_test.go` (or `api/soft_delete_extended_test.go`), add a test that calls `POST /vaults/myvault/deleted/secrets/{id}/restore` with a secret that belongs to the vault but to a different user. Expect 200 (vault membership is sufficient). Add a second test that calls the same route with a secret NOT in the vault — expect 404.

- [ ] **Step 2: Run the test to confirm it fails**

  ```bash
  go test ./api/... -run TestRecoverSecret -v -count=1 -timeout 60s
  ```

- [ ] **Step 3: Update recoverSecret in api/soft_delete.go**

  Replace the body of `recoverSecret` with:
  ```go
  func recoverSecret(c *Context, w http.ResponseWriter, r *http.Request) {
      secretID, err := uuid.Parse(c.Params.SecretID)
      if err != nil {
          c.SetInvalidParam("secret_id")
          return
      }
  
      repo := c.App.ServiceContainer.GetSecretRepository()
  
      if isVaultScopedRoute(r) {
          // Vault-scoped route: verify the secret belongs to this vault.
          vaultID, err := vaultIDFromRequest(r)
          if err != nil {
              c.SetInvalidParam("vault")
              return
          }
          secrets, err := repo.ListInVaultIncludeDeleted(r.Context(), vaultID, nil)
          if err != nil {
              c.SetInternalError(err)
              return
          }
          found := false
          for _, s := range secrets {
              if s.ID == secretID {
                  found = true
                  break
              }
          }
          if !found {
              c.SetNotFound("secret")
              return
          }
      } else {
          // Legacy flat route: verify user ownership (original behaviour).
          userID, ok := userIDFromClaims(c)
          if !ok {
              return
          }
          secrets, err := repo.ListByUserIncludeDeleted(r.Context(), userID, nil)
          if err != nil {
              c.SetInternalError(err)
              return
          }
          found := false
          for _, s := range secrets {
              if s.ID == secretID && s.UserID == userID {
                  found = true
                  break
              }
          }
          if !found {
              c.SetNotFound("secret")
              return
          }
      }
  
      if err := repo.RecoverSecret(r.Context(), secretID); err != nil {
          c.SetInternalError(err)
          return
      }
  
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(map[string]any{"message": "Secret recovered successfully", "id": secretID.String()})
  }
  ```

- [ ] **Step 4: Update purgeSecret with identical vault/user branching**

  Apply the same `isVaultScopedRoute` check to `purgeSecret`:
  ```go
  func purgeSecret(c *Context, w http.ResponseWriter, r *http.Request) {
      secretID, err := uuid.Parse(c.Params.SecretID)
      if err != nil {
          c.SetInvalidParam("secret_id")
          return
      }
  
      repo := c.App.ServiceContainer.GetSecretRepository()
  
      if isVaultScopedRoute(r) {
          vaultID, err := vaultIDFromRequest(r)
          if err != nil {
              c.SetInvalidParam("vault")
              return
          }
          secrets, err := repo.ListInVaultIncludeDeleted(r.Context(), vaultID, nil)
          if err != nil {
              c.SetInternalError(err)
              return
          }
          found := false
          for _, s := range secrets {
              if s.ID == secretID {
                  found = true
                  break
              }
          }
          if !found {
              c.SetNotFound("secret")
              return
          }
      } else {
          userID, ok := userIDFromClaims(c)
          if !ok {
              return
          }
          secrets, err := repo.ListByUserIncludeDeleted(r.Context(), userID, nil)
          if err != nil {
              c.SetInternalError(err)
              return
          }
          found := false
          for _, s := range secrets {
              if s.ID == secretID && s.UserID == userID {
                  found = true
                  break
              }
          }
          if !found {
              c.SetNotFound("secret")
              return
          }
      }
  
      if err := repo.PurgeSecret(r.Context(), secretID); err != nil {
          c.SetInternalError(err)
          return
      }
  
      ReturnStatusOK(w)
  }
  ```

- [ ] **Step 5: Run the tests**

  ```bash
  go test ./api/... -run TestRecoverSecret -v -count=1
  go test ./api/... -run TestPurgeSecret -v -count=1
  go test ./api/... -count=1 -timeout 120s
  ```

- [ ] **Step 6: Commit**

  ```
  fix: vault-scoped recover/purge now verify by vault, not user ownership
  
  recoverSecret and purgeSecret on vault-scoped routes (/vaults/{name}/…)
  now use ListInVaultIncludeDeleted to confirm the secret belongs to the
  resolved vault before recovering or purging it. Legacy flat routes
  retain the original per-user ownership check. Fixes the invariant
  violation: no vault-scoped route silently ignores its vault.
  ```

---

## Task 3: Sentinel errors for not-found + lifecycle denial; fix DELETE→500 and GET→404 (Issues 8 and 9)

**Files:**
- Modify: `internal/services/secrets/secret_service.go`
- Modify: `internal/services/keys/key_service.go`
- Modify: `internal/services/certificates/certificate_service.go`
- Modify: `api/secrets.go`
- Modify: `api/keys.go`
- Modify: `api/certificates.go`
- Test: `api/secrets_handlers_test.go`, `api/keys_crud_test.go`, `api/certificates_test.go`

> Context: Two separate bugs share the same root cause — no sentinel error discrimination between "resource not found" and "real server fault":
>
> **Issue 8 (DELETE → 500):** `deleteSecret`, `deleteKey`, `deleteCertificate` call the service's `Delete*InVault` method and on ANY error call `c.SetInternalError(err)` — including when the resource simply doesn't exist in the vault, which should be 404.
>
> **Issue 9 (GET → 404):** `getSecret`, `getKey`, `getCertificate` call the service's `Get*InVault` method and on ANY error call `c.SetNotFound(...)` — including when a decrypt operation fails (DB corruption, wrong key) or when the secret is disabled/expired, both of which should return 500 and 403 respectively, not 404.
>
> Fix strategy (Go idiomatic):  
> 1. Declare sentinel errors in each service package: `ErrSecretNotFound`, `ErrSecretLifecycleDenied`; `ErrKeyNotFound`, `ErrKeyLifecycleDenied`; `ErrCertNotFound`, `ErrCertLifecycleDenied`.  
> 2. Wrap them at the relevant service return sites using `fmt.Errorf("...: %w", Err...)`.  
> 3. In API handlers, branch on `errors.Is(err, Err...)` before falling through to `c.SetInternalError`.

**Sub-steps:**

### 3a — secrets service

- [ ] **Step 1: Write failing handler tests**

  In `api/secrets_handlers_test.go`, add:
  - A test for `deleteSecret` that mocks `DeleteSecretInVault` returning `secrets.ErrSecretNotFound` → expect 404.
  - A test for `getSecret` that mocks `GetSecretInVault` returning `secrets.ErrSecretLifecycleDenied` → expect 403.
  - A test for `getSecret` that mocks `GetSecretInVault` returning a generic `errors.New("disk I/O error")` → expect 500.

- [ ] **Step 2: Run to confirm they fail**

  ```bash
  go test ./api/... -run TestDeleteSecret -v -count=1
  go test ./api/... -run TestGetSecret -v -count=1
  ```

- [ ] **Step 3: Add sentinel vars to secret_service.go**

  Near the top of `internal/services/secrets/secret_service.go`, after imports:
  ```go
  // ErrSecretNotFound is returned when a secret does not exist or is not
  // accessible within the requested scope (vault or user ownership).
  var ErrSecretNotFound = errors.New("secret not found")
  
  // ErrSecretLifecycleDenied is returned when a secret exists but is disabled
  // or outside its valid time window (not_before / expires_at).
  var ErrSecretLifecycleDenied = errors.New("secret is disabled or outside its valid time window")
  ```

- [ ] **Step 4: Wrap ErrSecretNotFound in DeleteSecretInVault**

  In `DeleteSecretInVault`, change the first error return from:
  ```go
  return fmt.Errorf("secret not found: %w", err)
  ```
  to:
  ```go
  return fmt.Errorf("delete secret: %w: %w", ErrSecretNotFound, err)
  ```
  
  > Note: Go 1.20+ supports wrapping multiple errors with `%w: %w`. But since we want `errors.Is` to match, we can use `fmt.Errorf("%w", ErrSecretNotFound)` as the primary. Simple approach:
  ```go
  s.logger.LogAuditError("", "delete_secret", "failed", "Secret not found in vault", err)
  return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
  ```

- [ ] **Step 5: Wrap sentinels in GetSecretInVault**

  In `GetSecretInVault`:
  - First `return nil, fmt.Errorf("secret not found or access denied")` → wrap `ErrSecretNotFound`:
    ```go
    return nil, fmt.Errorf("%w", ErrSecretNotFound)
    ```
  - The decrypt error (`"failed to decrypt secret: %w"`) → leave as-is (no sentinel, caller gets 500).
  - The tags error → leave as-is (caller gets 500).
  - The lifecycle check at the end:
    ```go
    return nil, fmt.Errorf("secret is disabled or outside its valid time window")
    ```
    → wrap `ErrSecretLifecycleDenied`:
    ```go
    return nil, fmt.Errorf("%w", ErrSecretLifecycleDenied)
    ```

- [ ] **Step 6: Update deleteSecret handler in api/secrets.go**

  Change:
  ```go
  if err := secretService.DeleteSecretInVault(r.Context(), secretID, vaultID); err != nil {
      c.SetInternalError(err)
      return
  }
  ```
  to:
  ```go
  if err := secretService.DeleteSecretInVault(r.Context(), secretID, vaultID); err != nil {
      if errors.Is(err, secrets.ErrSecretNotFound) {
          c.SetNotFound("secret")
      } else {
          c.SetInternalError(err)
      }
      return
  }
  ```
  
  Import `"github.com/numericlabs/rocketvault/internal/services/secrets"` in `api/secrets.go` if not already present.

- [ ] **Step 7: Update getSecret handler in api/secrets.go**

  In `getSecret`, change both `c.SetNotFound("secret")` error returns (vault-scoped and user-scoped) to branch on the error type:
  ```go
  // vault-scoped:
  if err != nil {
      if errors.Is(err, secrets.ErrSecretLifecycleDenied) {
          http.Error(w, `{"message":"secret is disabled or outside its valid time window"}`, http.StatusForbidden)
      } else if errors.Is(err, secrets.ErrSecretNotFound) {
          c.SetNotFound("secret")
      } else {
          c.SetInternalError(err)
      }
      return
  }
  // user-scoped:
  if err != nil {
      if errors.Is(err, secrets.ErrSecretLifecycleDenied) {
          http.Error(w, `{"message":"secret is disabled or outside its valid time window"}`, http.StatusForbidden)
      } else if errors.Is(err, secrets.ErrSecretNotFound) {
          c.SetNotFound("secret")
      } else {
          c.SetInternalError(err)
      }
      return
  }
  ```
  
  > Note: The user-scoped path calls `secretService.GetSecret` (not `GetSecretInVault`). Check whether `GetSecret` also needs sentinel wrapping — look at its error returns and apply the same sentinel pattern if it doesn't already have them.

### 3b — keys service

- [ ] **Step 8: Add ErrKeyNotFound + ErrKeyLifecycleDenied to key_service.go**

  Same pattern as secrets. Near top of `internal/services/keys/key_service.go`:
  ```go
  var ErrKeyNotFound = errors.New("key not found")
  var ErrKeyLifecycleDenied = errors.New("key is disabled or outside its valid time window")
  ```

- [ ] **Step 9: Wrap ErrKeyNotFound in DeleteKeyInVault**

  `DeleteKeyInVault` currently:
  ```go
  key, err := s.keyRepo.ReadInVault(ctx, keyID, vaultID)
  if err != nil {
      return nil, fmt.Errorf("delete key: %w", err)
  }
  ```
  Change to:
  ```go
  key, err := s.keyRepo.ReadInVault(ctx, keyID, vaultID)
  if err != nil {
      return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
  }
  ```

- [ ] **Step 10: Wrap sentinels in GetKeyInVault**

  Find `GetKeyInVault` in `key_service.go` and wrap the not-found return with `ErrKeyNotFound` and the lifecycle denial with `ErrKeyLifecycleDenied`.

- [ ] **Step 11: Update deleteKey handler in api/keys.go**

  The current `deleteKey` returns 500 on any service error. Add:
  ```go
  deleted, err := keyService.DeleteKeyInVault(r.Context(), keyID, vaultID)
  if err != nil {
      if errors.Is(err, keys.ErrKeyNotFound) {
          c.SetNotFound("key")
      } else {
          c.SetInternalError(err)
      }
      return
  }
  ```

- [ ] **Step 12: Update getKey handler in api/keys.go**

  Same three-way branch as `getSecret` above.

### 3c — certificates service

- [ ] **Step 13: Add ErrCertNotFound + ErrCertLifecycleDenied to certificate_service.go**

  ```go
  var ErrCertNotFound = errors.New("certificate not found")
  var ErrCertLifecycleDenied = errors.New("certificate is disabled or outside its valid time window")
  ```

- [ ] **Step 14: Wrap ErrCertNotFound in DeleteCertificateInVault**

  `DeleteCertificateInVault` currently:
  ```go
  if _, err := s.certRepo.ReadInVault(ctx, certID, vaultID); err != nil {
      return fmt.Errorf("failed to read certificate: %w", err)
  }
  ```
  Change to:
  ```go
  if _, err := s.certRepo.ReadInVault(ctx, certID, vaultID); err != nil {
      return fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
  }
  ```

- [ ] **Step 15: Wrap sentinels in GetCertificateInVault**

  Find `GetCertificateInVault` in `certificate_service.go`. Apply the same sentinel wrapping.

- [ ] **Step 16: Update deleteCertificate + getCertificate handlers in api/certificates.go**

  Same pattern.

- [ ] **Step 17: Run the full test suite**

  ```bash
  cd /home/numericlabs/data/rocket/rocketvault
  go test ./... -count=1 -timeout 120s
  ```
  
  Fix any compilation or test failures.

- [ ] **Step 18: Commit**

  ```
  fix: distinguish not-found from server errors in DELETE and GET handlers
  
  Introduce ErrSecretNotFound/ErrSecretLifecycleDenied, ErrKeyNotFound/
  ErrKeyLifecycleDenied, ErrCertNotFound/ErrCertLifecycleDenied sentinel
  errors. Service methods wrap them at the appropriate return sites.
  
  API handlers now return:
  - 404 when the resource is not found (DELETE and GET)
  - 403 when the resource exists but is disabled/expired (GET only)
  - 500 for genuine server faults (decrypt failure, DB error)
  
  Fixes: DELETE maps not-found → 500; GET collapses all errors → 404
  ```

---

## Task 4: Populate model.VaultID in ReadInVault / ListInVault (Issue 10)

**Files:**
- Modify: `internal/repositories/secret_repository.go`
- Modify: `internal/repositories/key_repository.go`
- Modify: `internal/repositories/certificate_repository.go`
- Test: `internal/repositories/secret_repository_test.go`, `internal/repositories/key_repository_test.go` (or key_soft_delete_test.go), `internal/repositories/certificate_key_id_test.go`

> Context: `model.Secret`, `model.Key`, and `model.Certificate` all have a `VaultID uuid.UUID` field. When results are returned from vault-scoped queries (`ReadInVault`, `ListInVault`, `ListInVaultIncludeDeleted`) the `VaultID` should be set on each returned item. `SecretRepository.ReadInVault` already does this correctly; the other five methods do not. Isolation is enforced by the `WHERE vault_id = ?` clause, so this is cosmetic — but it makes callers' lives easier and removes the inconsistency.
>
> The fix is trivial: after scanning a row (or building the result), set `key.VaultID = vaultID` / `cert.VaultID = vaultID` / `secret.VaultID = vaultID`.

- [ ] **Step 1: Write failing tests**

  For each of the five methods, add a test asserting that every returned item has `VaultID` set to the vault that was queried. For example:

  ```go
  // secret_repository_test.go
  func TestListInVault_PopulatesVaultID(t *testing.T) {
      // arrange: create a secret in vault A
      // act: ListInVault(ctx, vaultA, nil)
      // assert: every returned secret has VaultID == vaultA
  }
  ```

  Target methods: `SecretRepository.ListInVault`, `SecretRepository.ListInVaultIncludeDeleted`, `KeyRepository.ReadInVault`, `KeyRepository.ListInVault`, `CertificateRepository.ReadInVault`, `CertificateRepository.ListInVault`.

- [ ] **Step 2: Run to confirm failure**

  ```bash
  go test ./internal/repositories/... -run TestListInVault_PopulatesVaultID -v -count=1
  ```

- [ ] **Step 3: Fix secret_repository.go — ListInVault**

  In the scanning loop of `SecretRepository.ListInVault`, after `secret.UserID, err = uuid.Parse(userIDStr)`, add:
  ```go
  secret.VaultID = vaultID
  ```

- [ ] **Step 4: Fix secret_repository.go — ListInVaultIncludeDeleted**

  Identical one-liner in the scanning loop of `ListInVaultIncludeDeleted`:
  ```go
  secret.VaultID = vaultID
  ```

- [ ] **Step 5: Fix key_repository.go — ReadInVault**

  After successful scan and UUID parsing in `KeyRepository.ReadInVault`, before `return &key, nil`, add:
  ```go
  key.VaultID = vaultID
  ```

- [ ] **Step 6: Fix key_repository.go — ListInVault**

  In the scanning loop of `KeyRepository.ListInVault`, after `key.UserID, err = uuid.Parse(userIDStr)`, add:
  ```go
  key.VaultID = vaultID
  ```

- [ ] **Step 7: Fix certificate_repository.go — ReadInVault**

  After UUID parsing in `CertificateRepository.ReadInVault`, before `return &cert, nil`, add:
  ```go
  cert.VaultID = vaultID
  ```

- [ ] **Step 8: Fix certificate_repository.go — ListInVault**

  In the scanning loop of `CertificateRepository.ListInVault`, after `cert.UserID, err = uuid.Parse(userIDStr)`, add:
  ```go
  cert.VaultID = vaultID
  ```

- [ ] **Step 9: Run the tests**

  ```bash
  go test ./internal/repositories/... -count=1 -timeout 60s
  ```

- [ ] **Step 10: Run the full test suite**

  ```bash
  go test ./... -count=1 -timeout 120s
  ```

- [ ] **Step 11: Commit**

  ```
  fix: populate VaultID on rows returned from ReadInVault/ListInVault
  
  Five of the six vault-scoped repository methods returned items with a
  zero VaultID. Add a one-liner assignment after scan in each of:
  SecretRepository.ListInVault, ListInVaultIncludeDeleted,
  KeyRepository.ReadInVault, KeyRepository.ListInVault,
  CertificateRepository.ReadInVault, CertificateRepository.ListInVault.
  SecretRepository.ReadInVault already populated VaultID correctly.
  Isolation is enforced by the WHERE clause; this is a consistency fix.
  ```

---

## Final Review

After all four tasks are committed, run the full test suite once more:

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./... && go test ./... -count=1 -timeout 180s
```

Then use `superpowers:finishing-a-development-branch`.
