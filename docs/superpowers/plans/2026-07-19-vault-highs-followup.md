# Vault High-Severity Follow-Ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two **High**-severity follow-up items named in `docs/superpowers/specs/2026-07-19-vault-management-authz-fix-design.md` §"Related Work / Follow-Up" (items 2 and 3):

1. Introduce a shared `repositories.ErrNotFound` sentinel and thread it through the vault read path (repository → service → API) so a genuine DB failure in `vault_service.go`'s `getByName` is no longer collapsed into the same `ErrVaultNotFound` used for an honest missing-vault 404 — a DB outage must surface as a 500, not a mass "vault not found" storm.
2. Make `DeleteVault`/`RecoverVault`'s cascade (vault row + secrets + keys + certificates) atomic, so a mid-cascade failure cannot leave the vault row soft-deleted/recovered while its contents are not (or vice versa).

**Architecture:**

*Part 1* is a narrow, vault-scoped fix: `VaultRepository.ReadByName`/`ReadByID` already distinguish `sql.ErrNoRows` internally but throw that information away by returning an unwrapped string error; a new `repositories.ErrNotFound` sentinel (`%w`-wrapped) fixes that, and `vaultService.getByName`/`PurgeVault` are updated to check `errors.Is(err, repositories.ErrNotFound)` before deciding whether to report `ErrVaultNotFound` (404) or propagate the real error (500). `api/vault.go`'s three management handlers get the matching `errors.Is`/`SetInternalError` split.

*Part 2* makes the vault delete/recover cascade transactional. The existing `db.WithTx` helper (`internal/db/txhelper.go`) operates on a raw `*sql.DB`/`*sql.Tx` pair that is **incompatible** with the dialect-aware `db.DB`/`db.Conn`/`db.Tx` abstraction every repository is actually built on (`*db.Tx` doesn't implement `db.DB`, and repositories store `db.DB`, not `*sql.DB`) — it also has zero production call sites today. Rather than force that dead helper into service, this plan adds new, purpose-built `*Tx`-suffixed sibling methods to `VaultRepository` and to the three vault-content repositories (`SecretRepository`, `KeyRepository`, `CertificateRepository`), each accepting an explicit `db.DBTX` executor instead of using the repo's own stored connection. `vaultService` gains an optional `TxBeginner` (satisfied by `*db.Conn`, wired in via a setter so every existing unit test — which uses in-memory fakes with no real database — keeps working unmodified against the pre-existing non-transactional code path). When a `TxBeginner` is configured (production wiring only), `DeleteVault`/`RecoverVault` begin one `*db.Tx`, and run the vault-row mutation plus every content repo's cascade call through that same `*db.Tx`, committing once at the end or rolling back everything on the first error. All new repository methods are strictly additive — no existing exported method signature changes — to keep the blast radius bounded to the vault cascade path.

**Tech Stack:** Go 1.24.2, `database/sql`, `github.com/mattn/go-sqlite3` (test-only), `rocketvault/internal/db` (`DB`/`DBTX`/`Conn`/`Tx`/`Dialect`), `rocketvault/internal/repositories`, `rocketvault/internal/services/vaults`, `github.com/google/uuid`, `github.com/stretchr/testify` (`require`/`assert`/`mock`).

**Spec:** `docs/superpowers/specs/2026-07-19-vault-management-authz-fix-design.md` §"Related Work / Follow-Up", items 2 and 3.

## Global Constraints

- Every not-found check added or touched by this plan must use `errors.Is` against an exported sentinel — never a string comparison (`err.Error() == "..."`). This plan does not fix the pre-existing string-comparison anti-pattern in `internal/repositories/role_assignment_repository.go:78`; that stays as a noted example, not an in-scope fix.
- No existing exported method signature may change. New transactional/DBTX-scoped capability is added as new, additively-named sibling methods (`*Tx` suffix) so retry wrappers, mocks, and every other existing call site keep compiling untouched.
- All repository code continues to go through `internal/db`'s dialect-aware `db.DB`/`db.DBTX` abstraction. Never call a raw `*sql.DB`/`*sql.Tx` method directly from a repository or service.
- Every task's commit must be GPG-signed (`git commit -S`), matching this repository's existing commit history.
- `go build ./...` must be clean and the packages touched by a task must pass (`go test ./<package>/...`) before that task's commit. The final task in each Part additionally runs the full suite: `go test ./...`.
- Preserve every existing test's behavior unless a task explicitly says to change it. Where a shared test fake (`fakeVaultRepo`, `vaultFakeRepo`, `noopCascade`, `recordingRepo`, `failingRepo`) must gain a new method purely for interface conformance, keep its existing behavior for all pre-existing call sites unchanged.

---

## File Structure

| File | Action | Part | Purpose |
|---|---|---|---|
| `internal/repositories/errors.go` | Create | 1 | `repositories.ErrNotFound` sentinel |
| `internal/repositories/vault_repository.go` | Modify | 1, 2 | Wrap `ErrNotFound`; add `SoftDeleteTx`/`ReadByIDTx`/`RecoverTx` |
| `internal/repositories/vault_repository_test.go` | Modify | 1, 2 | Sentinel tests; Tx-variant tests |
| `internal/services/vaults/vault_service.go` | Modify | 1, 2 | Fix `getByName`/`PurgeVault`; add `TxBeginner`/`withTx`; rewrite `DeleteVault`/`RecoverVault` |
| `internal/services/vaults/vault_service_test.go` | Modify | 1, 2 | Fake repo returns `ErrNotFound`; regression test; Tx-variant stub methods |
| `api/vault.go` | Modify | 1 | 404-vs-500 split in `getVault`/`updateVault`/`deleteVault` |
| `api/vault_test.go` | Modify | 1 | Fake repo returns `ErrNotFound`; `readErr` field; 500 regression tests |
| `internal/repositories/secret_repository.go` | Modify | 2 | Add `SoftDeleteVaultContentsTx`/`RecoverVaultContentsTx` |
| `internal/repositories/secret_repository_test.go` | Modify | 2 | Tx-variant commit/rollback tests |
| `internal/repositories/key_repository.go` | Modify | 2 | Add `SoftDeleteVaultContentsTx`/`RecoverVaultContentsTx` |
| `internal/repositories/certificate_repository.go` | Modify | 2 | Add `SoftDeleteVaultContentsTx`/`RecoverVaultContentsTx` |
| `internal/repositories/repositories_test.go` | Modify | 2 | Key/Certificate Tx-variant commit/rollback tests |
| `internal/services/retry/retry_repository_wrapper.go` | Modify | 2 | Passthrough (no-retry) `*Tx` methods |
| `internal/testutils/mocks.go` | Modify | 2 | `MockSecretRepository` `*Tx` stub methods |
| `internal/services/vaults/cascade_adapter.go` | Modify | 2 | `vaultContentRepo`/`cascadeAdapter` `*Tx` fan-out |
| `internal/services/vaults/cascade_adapter_test.go` | Modify | 2 | `recordingRepo`/`failingRepo` `*Tx` methods; new fan-out test |
| `internal/container/service_container.go` | Modify | 2 | Wire `vaultService.SetTxBeginner(c.conn)` |
| `internal/services/vaults/vault_service_tx_integration_test.go` | Create | 2 | Real-SQLite rollback/commit proof across vault+secret tables |

---

# Part 1 — `repositories.ErrNotFound` sentinel (vault-scoped)

## Task 1: Add `repositories.ErrNotFound` and wrap it in `VaultRepository`

**Files:**
- Create: `internal/repositories/errors.go`
- Modify: `internal/repositories/vault_repository.go` (`ReadByName` lines 121-129, `ReadByID` lines 131-139)
- Modify: `internal/repositories/vault_repository_test.go`

**Interfaces:**
- Produces: `var repositories.ErrNotFound error`, wrapped via `%w` in `VaultRepository.ReadByName`/`ReadByID` when the row is genuinely missing (`sql.ErrNoRows`). Any other error (e.g. a closed/unreachable DB) is returned unwrapped, exactly as today.

- [ ] **Step 1: Write the failing tests**

Append to `internal/repositories/vault_repository_test.go` (needs `errors` added to the import block):

```go
func TestVaultRepository_ReadByName_UnknownReturnsErrNotFound(t *testing.T) {
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), newTestVaultLogger(t))

	_, err := repo.ReadByName(context.Background(), "ghost")
	require.True(t, errors.Is(err, repositories.ErrNotFound), "expected ErrNotFound, got %v", err)
}

func TestVaultRepository_ReadByID_UnknownReturnsErrNotFound(t *testing.T) {
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), newTestVaultLogger(t))

	_, err := repo.ReadByID(context.Background(), uuid.New())
	require.True(t, errors.Is(err, repositories.ErrNotFound), "expected ErrNotFound, got %v", err)
}

// TestVaultRepository_ReadByName_NonNotFoundErrorIsNotErrNotFound proves a real
// DB failure (here: a closed connection) is NOT mistaken for a missing row.
func TestVaultRepository_ReadByName_NonNotFoundErrorIsNotErrNotFound(t *testing.T) {
	db := newVaultTestDB(t)
	repo := repositories.NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), newTestVaultLogger(t))
	require.NoError(t, db.Close())

	_, err := repo.ReadByName(context.Background(), "prod")
	require.Error(t, err)
	require.False(t, errors.Is(err, repositories.ErrNotFound), "a closed-DB error must not look like not-found")
}
```

- [ ] **Step 2: Run to confirm the sentinel tests fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./internal/repositories/... 2>&1
```

Expected: **build failure** — `repositories.ErrNotFound` doesn't exist yet.

- [ ] **Step 3: Add the sentinel**

Create `internal/repositories/errors.go`:

```go
package repositories

import "errors"

// ErrNotFound is returned (wrapped with %w) by repository Read/ReadBy*
// methods when no row matches the lookup. Callers must use errors.Is against
// this sentinel rather than comparing error strings — see
// role_assignment_repository.go's FindByTuple for the fragile pattern this
// sentinel replaces (not fixed by this change; kept as a documented example).
var ErrNotFound = errors.New("repository: not found")
```

- [ ] **Step 4: Wrap it in `VaultRepository`**

In `internal/repositories/vault_repository.go`, replace `ReadByName` (lines 121-129):

```go
func (r *VaultRepository) ReadByName(ctx context.Context, name string) (*model.Vault, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT "+vaultCols+" FROM vaults WHERE name = ? AND deleted_at IS NULL", name)
	v, err := scanVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault %q: %w", name, ErrNotFound)
	}
	return v, err
}
```

Replace `ReadByID` (lines 131-139):

```go
func (r *VaultRepository) ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT "+vaultCols+" FROM vaults WHERE id = ?", id.String())
	v, err := scanVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault %s: %w", id, ErrNotFound)
	}
	return v, err
}
```

- [ ] **Step 5: Build and run**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/repositories/... -run "TestVaultRepository" -v 2>&1 | tail -40
```

Expected: all `TestVaultRepository_*` PASS, including the three new ones.

- [ ] **Step 6: Commit**

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add internal/repositories/errors.go internal/repositories/vault_repository.go internal/repositories/vault_repository_test.go && git commit -S -m "feat(repositories): add ErrNotFound sentinel, wrap it in VaultRepository"
```

---

## Task 2: Propagate `ErrNotFound` correctly through `vault_service.go`

**Files:**
- Modify: `internal/services/vaults/vault_service.go` (`getByName` lines 99-105, `PurgeVault` lines 219-250)
- Modify: `internal/services/vaults/vault_service_test.go`

**Interfaces:**
- Consumes: `repositories.ErrNotFound` from Task 1.
- Produces: `getByName` now returns `ErrVaultNotFound` **only** when the underlying repo error is `repositories.ErrNotFound`; any other repo error is wrapped with context and returned as-is (no sentinel), so `errors.Is(err, ErrVaultNotFound)` at every caller (service and API) is `false` for a genuine failure.

### Step 1: Write the failing tests

`vault_service_test.go`'s `fakeVaultRepo.ReadByName`/`ReadByID` currently return a fake-local `errFakeNotFound = errors.New("not found")`, which is unrelated to `repositories.ErrNotFound`. After Step 3 below, `getByName` will stop recognizing that fake sentinel as "not found" and the four existing tests that assert `errors.Is(err, ErrVaultNotFound)` (`TestGetVault_UnknownReturnsSentinel`, `TestRecoverVault_UnknownReturnsSentinel`, `TestUpdateVault_NotFound`, `TestDeleteVault_NotFound`) would start failing. Fix the fake first, then add the new regression test.

In `internal/services/vaults/vault_service_test.go`, add `"rocketvault/internal/repositories"` to the import block, then replace the sentinel and add a `readErr` field (currently lines 17-26):

```go
// fakeVaultRepo is a hand-rolled in-memory VaultRepositoryInterface for tests.
type fakeVaultRepo struct {
	byName map[string]*model.Vault
	byID   map[string]*model.Vault
	// readErr, when set, is returned by ReadByName/ReadByID instead of the
	// normal not-found sentinel — simulates a real failure (e.g. DB outage)
	// distinct from an honest missing row.
	readErr error
}

func newFakeRepo() *fakeVaultRepo {
	return &fakeVaultRepo{byName: map[string]*model.Vault{}, byID: map[string]*model.Vault{}}
}

var errFakeNotFound = repositories.ErrNotFound
```

Replace `ReadByName`/`ReadByID` (currently lines 37-48):

```go
func (f *fakeVaultRepo) ReadByName(_ context.Context, n string) (*model.Vault, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if v, ok := f.byName[n]; ok && v.DeletedAt == nil {
		return v, nil
	}
	return nil, errFakeNotFound
}
func (f *fakeVaultRepo) ReadByID(_ context.Context, id uuid.UUID) (*model.Vault, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if v, ok := f.byID[id.String()]; ok {
		return v, nil
	}
	return nil, errFakeNotFound
}
```

Add the new regression test proving a real error is not masked:

```go
// TestGetVault_NonNotFoundRepoErrorIsNotMaskedAsSentinel proves a real repo
// failure (e.g. a DB outage) is NOT reported as ErrVaultNotFound.
func TestGetVault_NonNotFoundRepoErrorIsNotMaskedAsSentinel(t *testing.T) {
	repo := newFakeRepo()
	repo.readErr = errors.New("connection refused")
	svc := NewVaultService(repo, &noopCascade{}, nil)

	_, err := svc.GetVault(context.Background(), "prod")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("a DB-outage error must not be reported as ErrVaultNotFound, got %v", err)
	}
}
```

### Step 2: Run to confirm the new test fails (and the existing four still pass with the fake fixed)

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/vaults/... -run "TestGetVault_NonNotFoundRepoErrorIsNotMaskedAsSentinel|TestGetVault_UnknownReturnsSentinel|TestRecoverVault_UnknownReturnsSentinel|TestUpdateVault_NotFound|TestDeleteVault_NotFound" -v 2>&1 | tail -40
```

Expected: `TestGetVault_NonNotFoundRepoErrorIsNotMaskedAsSentinel` **FAILs** (current `getByName` still collapses every error into `ErrVaultNotFound`); the other four already pass (fake now returns `repositories.ErrNotFound`, which `getByName`'s current unconditional wrap still turns into `ErrVaultNotFound` regardless of cause).

### Step 3: Fix `getByName` and `PurgeVault`

In `internal/services/vaults/vault_service.go`, replace `getByName` (currently lines 99-105):

```go
// getByName reads a vault by name, normalizing a genuine not-found into
// ErrVaultNotFound while propagating any other repository error (e.g. a DB
// outage) unchanged, so callers can tell "vault doesn't exist" (404) apart
// from "the lookup itself failed" (500).
func (s *vaultService) getByName(ctx context.Context, name string) (*model.Vault, error) {
	v, err := s.repo.ReadByName(ctx, name)
	if err != nil {
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("vault %q: %w", name, ErrVaultNotFound)
		}
		return nil, fmt.Errorf("get vault %q: %w", name, err)
	}
	return v, nil
}
```

Replace `PurgeVault` (currently lines 219-250) so its fallback lookup goes through the now-fixed `getByName` instead of a raw `s.repo.ReadByName` call, and so a `findDeleted` failure that is NOT "no match" (e.g. the underlying `ListDeleted` hit a DB error) is not masked by a second lookup:

```go
// PurgeVault permanently removes a vault, refusing the default and purge-protected vaults.
func (s *vaultService) PurgeVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be purged")
	}

	// Normally a vault is purged after a soft-delete, so check there first.
	v, err := s.findDeleted(ctx, name)
	if err != nil {
		if !errors.Is(err, ErrVaultNotFound) {
			// findDeleted failed for a reason other than "no match" (e.g. the
			// underlying ListDeleted call hit a DB error) -- don't mask it by
			// falling through to a second lookup.
			return err
		}
		// Fall back to an active vault when no soft-deleted match exists.
		v, err = s.getByName(ctx, name)
		if err != nil {
			return err
		}
	}
	if v.PurgeProtection {
		return fmt.Errorf("vault %q is protected from purge", name)
	}
	if err := s.repo.Purge(ctx, v.ID); err != nil {
		return err
	}
	// access_policies has no FK to vaults, so vault-scoped policy rows must be
	// removed explicitly to avoid orphaning them after the vault is purged.
	if s.policies != nil {
		if err := s.policies.DeleteByVault(ctx, v.ID); err != nil {
			return fmt.Errorf("delete vault policies: %w", err)
		}
	}
	if s.log != nil {
		s.log.LogAuditInfo("", "purge_vault", "success", fmt.Sprintf("Vault purged: %s", name))
	}
	return nil
}
```

`repositories` is already imported in this file (used for `repositories.VaultRepositoryInterface`); no new import needed.

### Step 4: Build and re-run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/vaults/... -v 2>&1 | tail -60
```

Expected: every test in the package PASSes, including the new regression test.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add internal/services/vaults/vault_service.go internal/services/vaults/vault_service_test.go && git commit -S -m "fix(vault): stop collapsing every repo error into ErrVaultNotFound"
```

---

## Task 3: Distinguish 404 from 500 in the vault API handlers

**Files:**
- Modify: `api/vault.go` (`getVault` lines 118-130, `updateVault` lines 146-167, `deleteVault` lines 205-224)
- Modify: `api/vault_test.go`

**Interfaces:**
- Consumes: `vaultServices.ErrVaultNotFound` (unchanged), `c.SetInternalError(err error)` (`api/context.go`, existing).

### Step 1: Write the failing tests

`api/vault_test.go`'s `vaultFakeRepo.ReadByName`/`ReadByID` (currently lines 54, 65-76) have the same masking problem as Task 2's fake: `errVaultFakeNotFound = errors.New("not found")` is unrelated to `repositories.ErrNotFound`, so after Task 2 shipped, `vaultService.getByName` (backed by this fake, via the real `vaultServices.NewVaultService` used in `newVaultTestAPI`) now treats every lookup miss in these API tests as a **non**-not-found error. Fix the fake the same way, then add the 500-vs-404 regression tests.

Replace lines 45-76 in `api/vault_test.go`:

```go
type vaultFakeRepo struct {
	byName map[string]*model.Vault
	byID   map[string]*model.Vault
	// readErr, when set, is returned by ReadByName/ReadByID instead of the
	// normal not-found sentinel -- simulates a real failure (e.g. DB outage).
	readErr error
}

func newVaultFakeRepo() *vaultFakeRepo {
	return &vaultFakeRepo{byName: map[string]*model.Vault{}, byID: map[string]*model.Vault{}}
}

var errVaultFakeNotFound = repositories.ErrNotFound

func (f *vaultFakeRepo) Create(_ context.Context, v *model.Vault) error {
	if _, ok := f.byName[v.Name]; ok {
		return errors.New("duplicate vault name")
	}
	cp := *v
	f.byName[v.Name] = &cp
	f.byID[v.ID.String()] = &cp
	return nil
}
func (f *vaultFakeRepo) ReadByName(_ context.Context, n string) (*model.Vault, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if v, ok := f.byName[n]; ok && v.DeletedAt == nil {
		return v, nil
	}
	return nil, errVaultFakeNotFound
}
func (f *vaultFakeRepo) ReadByID(_ context.Context, id uuid.UUID) (*model.Vault, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if v, ok := f.byID[id.String()]; ok {
		return v, nil
	}
	return nil, errVaultFakeNotFound
}
```

(`"rocketvault/internal/repositories"` is already imported in `api/vault_test.go`.)

Append new tests near the existing `TestGetVault_NotFound`/`TestDeleteVault_RefusesDefault` tests:

```go
// TestGetVault_InternalErrorIsNotReportedAsNotFound proves a genuine repository
// failure (e.g. a DB outage) surfaces as 500, not a misleading 404.
func TestGetVault_InternalErrorIsNotReportedAsNotFound(t *testing.T) {
	api, repo := newVaultTestAPI()
	repo.readErr = errors.New("connection refused")

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/anything", nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateVault_InternalErrorIsNotReportedAsNotFound(t *testing.T) {
	api, repo := newVaultTestAPI()
	repo.readErr = errors.New("connection refused")

	body := []byte(`{"enabled":false}`)
	w := doVaultRequest(api, http.MethodPatch, "/api/v1/vaults/anything", body)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteVault_InternalErrorIsNotReportedAsNotFound(t *testing.T) {
	api, repo := newVaultTestAPI()
	repo.readErr = errors.New("connection refused")

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/anything", nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
```

### Step 2: Run to confirm the three new tests fail

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestGetVault_InternalError|TestUpdateVault_InternalError|TestDeleteVault_InternalError" -v 2>&1 | tail -30
```

Expected: all three **FAIL** with 404, since the handlers currently do a blanket `c.SetNotFound("vault")` on any error.

### Step 3: Add the 404-vs-500 split

In `api/vault.go`, replace `getVault`'s lookup (currently lines 126-130):

```go
	vault, err := svc.GetVault(r.Context(), name)
	if err != nil {
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInternalError(err)
		return
	}
```

Replace `updateVault`'s precheck (currently lines 159-163):

```go
	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInternalError(err)
		return
	}
```

Replace `deleteVault`'s precheck (currently lines 216-220):

```go
	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInternalError(err)
		return
	}
```

The post-mutation `errors.Is(err, vaultServices.ErrVaultNotFound)` checks in `updateVault`/`deleteVault` (after `svc.UpdateVault`/`svc.DeleteVault`) are unchanged — they already distinguish not-found from other errors and are out of scope for this fix.

### Step 4: Build and run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "Vault" -v 2>&1 | tail -60
```

Expected: all vault handler tests PASS, including the three new ones, with every pre-existing test (`TestGetVault_NotFound`, `TestDeleteVault_RefusesDefault`, `TestDeleteVault_Success`, `TestCreateVault_AndList`, the authz tests, etc.) still green.

### Step 5: Run the full suite and commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|^ok" | tail -40
```

Expected: all packages `ok`, no `FAIL`.

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add api/vault.go api/vault_test.go && git commit -S -m "fix(vault): report internal errors as 500 instead of a misleading 404"
```

**Part 1 is independently shippable here** — the sentinel now flows repository → service → API.

---

# Part 2 — Transactional vault delete/recover cascade

## Task 4: Add Tx-scoped methods to `VaultRepository`

**Files:**
- Modify: `internal/repositories/vault_repository.go` (`VaultRepositoryInterface` lines 19-29, `ReadByID` lines 131-139, `SoftDelete` lines 186-193, `Recover` lines 195-202)
- Modify: `internal/repositories/vault_repository_test.go`

**Interfaces:**
- Produces: `VaultRepositoryInterface` gains `ReadByIDTx(ctx, ex db.DBTX, id) (*model.Vault, error)`, `SoftDeleteTx(ctx, ex db.DBTX, id) error`, `RecoverTx(ctx, ex db.DBTX, id) error`. The existing `ReadByID`/`SoftDelete`/`Recover` are unchanged (they now delegate to a shared private helper using `r.db` as the executor).

### Step 1: Write the failing tests

Add `"rocketvault/internal/db"` is already imported in this file as `db.DB`; append to `internal/repositories/vault_repository_test.go`:

```go
func TestVaultRepository_SoftDeleteTx_CommitsWithSharedTx(t *testing.T) {
	sqlDB := newVaultTestDB(t)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	repo := repositories.NewVaultRepository(conn, newTestVaultLogger(t))
	ctx := context.Background()

	id := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Vault{ID: id, Name: "txc", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteTx(ctx, tx, id))
	got, err := repo.ReadByIDTx(ctx, tx, id)
	require.NoError(t, err)
	require.NotNil(t, got.DeletedAt)
	require.NoError(t, tx.Commit())

	_, err = repo.ReadByName(ctx, "txc")
	require.Error(t, err, "vault must be hidden after commit")
}

func TestVaultRepository_SoftDeleteTx_RollsBackWithSharedTx(t *testing.T) {
	sqlDB := newVaultTestDB(t)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	repo := repositories.NewVaultRepository(conn, newTestVaultLogger(t))
	ctx := context.Background()

	id := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Vault{ID: id, Name: "txr", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New()}))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteTx(ctx, tx, id))
	require.NoError(t, tx.Rollback())

	got, err := repo.ReadByName(ctx, "txr")
	require.NoError(t, err, "vault must still be active after rollback")
	require.Nil(t, got.DeletedAt)
}
```

### Step 2: Run to confirm the tests fail

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./internal/repositories/... 2>&1
```

Expected: **build failure** — `SoftDeleteTx`/`ReadByIDTx` don't exist yet.

### Step 3: Add the Tx-scoped methods

In `internal/repositories/vault_repository.go`, add the three new methods to `VaultRepositoryInterface` (currently lines 19-29):

```go
// VaultRepositoryInterface defines pure CRUD data access for vaults.
type VaultRepositoryInterface interface {
	Create(ctx context.Context, v *model.Vault) error
	ReadByName(ctx context.Context, name string) (*model.Vault, error)
	ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error)
	// ReadByIDTx is ReadByID scoped to an explicit executor (e.g. a shared
	// transaction), used by the vault delete/recover cascade.
	ReadByIDTx(ctx context.Context, ex db.DBTX, id uuid.UUID) (*model.Vault, error)
	List(ctx context.Context) ([]model.Vault, error)
	ListDeleted(ctx context.Context) ([]model.Vault, error)
	Update(ctx context.Context, v *model.Vault) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	// SoftDeleteTx is SoftDelete scoped to an explicit executor.
	SoftDeleteTx(ctx context.Context, ex db.DBTX, id uuid.UUID) error
	Recover(ctx context.Context, id uuid.UUID) error
	// RecoverTx is Recover scoped to an explicit executor.
	RecoverTx(ctx context.Context, ex db.DBTX, id uuid.UUID) error
	Purge(ctx context.Context, id uuid.UUID) error
}
```

Replace `ReadByID` (currently lines 131-139):

```go
func (r *VaultRepository) ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error) {
	return r.readByID(ctx, r.db, id)
}

func (r *VaultRepository) ReadByIDTx(ctx context.Context, ex db.DBTX, id uuid.UUID) (*model.Vault, error) {
	return r.readByID(ctx, ex, id)
}

func (r *VaultRepository) readByID(ctx context.Context, ex db.DBTX, id uuid.UUID) (*model.Vault, error) {
	row := ex.QueryRowContext(ctx,
		"SELECT "+vaultCols+" FROM vaults WHERE id = ?", id.String())
	v, err := scanVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault %s: %w", id, ErrNotFound)
	}
	return v, err
}
```

Replace `SoftDelete` (currently lines 186-193):

```go
func (r *VaultRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return r.softDelete(ctx, r.db, id)
}

func (r *VaultRepository) SoftDeleteTx(ctx context.Context, ex db.DBTX, id uuid.UUID) error {
	return r.softDelete(ctx, ex, id)
}

func (r *VaultRepository) softDelete(ctx context.Context, ex db.DBTX, id uuid.UUID) error {
	_, err := ex.ExecContext(ctx,
		"UPDATE vaults SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL", time.Now(), id.String())
	if err != nil {
		return fmt.Errorf("failed to soft-delete vault: %w", err)
	}
	return nil
}
```

Replace `Recover` (currently lines 195-202):

```go
func (r *VaultRepository) Recover(ctx context.Context, id uuid.UUID) error {
	return r.recover(ctx, r.db, id)
}

func (r *VaultRepository) RecoverTx(ctx context.Context, ex db.DBTX, id uuid.UUID) error {
	return r.recover(ctx, ex, id)
}

func (r *VaultRepository) recover(ctx context.Context, ex db.DBTX, id uuid.UUID) error {
	_, err := ex.ExecContext(ctx,
		"UPDATE vaults SET deleted_at = NULL, scheduled_purge_at = NULL WHERE id = ? AND deleted_at IS NOT NULL", id.String())
	if err != nil {
		return fmt.Errorf("failed to recover vault: %w", err)
	}
	return nil
}
```

### Step 4: Build and run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build. (`fakeVaultRepo` in `vault_service_test.go` and `vaultFakeRepo` in `api/vault_test.go` will now fail to compile because they no longer satisfy `VaultRepositoryInterface` — this is expected and fixed in Task 7, which touches those same fakes for the `TxBeginner` wiring. Do not fix them in this task; `go build ./internal/repositories/...` and its own test package are what must pass here.)

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/repositories/... -run "TestVaultRepository" -v 2>&1 | tail -50
```

Expected: all `TestVaultRepository_*` PASS.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add internal/repositories/vault_repository.go internal/repositories/vault_repository_test.go && git commit -S -m "feat(vault): add Tx-scoped ReadByID/SoftDelete/Recover to VaultRepository"
```

---

## Task 5: Add Tx-scoped cascade methods to Secret/Key/Certificate repositories

**Files:**
- Modify: `internal/repositories/secret_repository.go` (`SecretRepositoryInterface` lines 18-43, cascade methods ~lines 886-926)
- Modify: `internal/repositories/key_repository.go` (`KeyRepositoryInterface` lines 22-49, cascade methods ~lines 996-1036)
- Modify: `internal/repositories/certificate_repository.go` (`CertificateRepositoryInterface` lines 22-45, cascade methods ~lines 1043-1083)
- Modify: `internal/services/retry/retry_repository_wrapper.go` (append after line 237)
- Modify: `internal/testutils/mocks.go` (append after line 244)
- Modify: `internal/repositories/secret_repository_test.go`
- Modify: `internal/repositories/repositories_test.go`

**Interfaces:**
- Produces: `SecretRepositoryInterface`/`KeyRepositoryInterface`/`CertificateRepositoryInterface` each gain `SoftDeleteVaultContentsTx(ctx, ex db.DBTX, vaultID, deletedAt) error` and `RecoverVaultContentsTx(ctx, ex db.DBTX, vaultID, deletedAt) error`. Existing `SoftDeleteVaultContents`/`RecoverVaultContents` are unchanged (delegate to a shared private helper using `r.db`).

### Step 1: Write the failing tests

Append to `internal/repositories/secret_repository_test.go`:

```go
func TestSecretRepository_SoftDeleteVaultContentsTx_CommitsWithSharedTx(t *testing.T) {
	db := setupSecretTestDB(t)
	conn := rvdb.NewConn(db, rvdb.SQLite)
	repo := repositories.NewSecretRepository(conn, newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	secret := &model.Secret{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, Name: "s", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Commit())

	_, err = repo.Read(ctx, secret.ID)
	require.Error(t, err, "secret must be hidden after commit")
}

func TestSecretRepository_SoftDeleteVaultContentsTx_RollsBackWithSharedTx(t *testing.T) {
	db := setupSecretTestDB(t)
	conn := rvdb.NewConn(db, rvdb.SQLite)
	repo := repositories.NewSecretRepository(conn, newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	secret := &model.Secret{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, Name: "s", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Rollback())

	_, err = repo.Read(ctx, secret.ID)
	require.NoError(t, err, "secret must still be active after rollback")
}
```

Append to `internal/repositories/repositories_test.go` (reuses the existing `setupFullKeyDB`/`setupFullCertDB`/`newKey`/`newCert` helpers):

```go
// ---------------------------------------------------------------------------
// KeyRepository / CertificateRepository -- vault-cascade Tx-scoped methods
// ---------------------------------------------------------------------------

func TestKeyRepository_SoftDeleteVaultContentsTx_CommitsWithSharedTx(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	conn := rvdb.NewConn(db, rvdb.SQLite)
	repo := repositories.NewKeyRepository(conn, log)
	ctx := context.Background()

	vaultID := uuid.New()
	k := newKey(uuid.New(), vaultID, "tx-key")
	require.NoError(t, repo.Create(ctx, k))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Commit())

	_, err = repo.Read(ctx, k.ID)
	assert.Error(t, err, "key must be hidden after the transaction commits")
}

func TestKeyRepository_SoftDeleteVaultContentsTx_RollsBackWithSharedTx(t *testing.T) {
	t.Parallel()
	db := setupFullKeyDB(t)
	log := logging.InitLogger()
	conn := rvdb.NewConn(db, rvdb.SQLite)
	repo := repositories.NewKeyRepository(conn, log)
	ctx := context.Background()

	vaultID := uuid.New()
	k := newKey(uuid.New(), vaultID, "tx-key-rb")
	require.NoError(t, repo.Create(ctx, k))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Rollback())

	_, err = repo.Read(ctx, k.ID)
	require.NoError(t, err, "key must still be active after rollback")
}

func TestCertificateRepository_SoftDeleteVaultContentsTx_CommitsWithSharedTx(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	conn := rvdb.NewConn(db, rvdb.SQLite)
	repo := repositories.NewCertificateRepository(conn, log)
	ctx := context.Background()

	vaultID := uuid.New()
	c := newCert(uuid.New(), vaultID, "tx-cert")
	require.NoError(t, repo.Create(ctx, c))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Commit())

	_, err = repo.Read(ctx, c.ID)
	assert.Error(t, err, "certificate must be hidden after the transaction commits")
}

func TestCertificateRepository_SoftDeleteVaultContentsTx_RollsBackWithSharedTx(t *testing.T) {
	t.Parallel()
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	conn := rvdb.NewConn(db, rvdb.SQLite)
	repo := repositories.NewCertificateRepository(conn, log)
	ctx := context.Background()

	vaultID := uuid.New()
	c := newCert(uuid.New(), vaultID, "tx-cert-rb")
	require.NoError(t, repo.Create(ctx, c))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Rollback())

	_, err = repo.Read(ctx, c.ID)
	require.NoError(t, err, "certificate must still be active after rollback")
}
```

### Step 2: Run to confirm the tests fail

```bash
cd /home/numericlabs/data/rocket/rocketvault && go vet ./internal/repositories/... 2>&1
```

Expected: **vet/build failure** — `SoftDeleteVaultContentsTx` doesn't exist yet on any of the three repos.

### Step 3: Add the Tx-scoped methods

In `internal/repositories/secret_repository.go`, add to `SecretRepositoryInterface` (after the existing `RecoverVaultContents` line, currently line 39):

```go
	// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an
	// explicit executor (e.g. a transaction shared with the vault row's own
	// soft-delete), used by the vault delete cascade.
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
```

Replace `SoftDeleteVaultContents`/`RecoverVaultContents` (currently ~lines 886-926):

```go
func (r *SecretRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.softDeleteVaultContents(ctx, r.db, vaultID, deletedAt)
}

func (r *SecretRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.softDeleteVaultContents(ctx, ex, vaultID, deletedAt)
}

func (r *SecretRepository) softDeleteVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Soft deleting all secrets in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE secrets SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
		deletedAt, vaultID.String())
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "soft_delete_vault_secrets", "failed", "Failed to soft delete vault secrets", err)
		return fmt.Errorf("failed to soft delete vault secrets: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "soft_delete_vault_secrets", "success", "Vault secrets soft deleted successfully")
	return nil
}

func (r *SecretRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.recoverVaultContents(ctx, r.db, vaultID, deletedAt)
}

func (r *SecretRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.recoverVaultContents(ctx, ex, vaultID, deletedAt)
}

func (r *SecretRepository) recoverVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Recovering cascade soft-deleted secrets in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE secrets SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at = ?",
		vaultID.String(), deletedAt)
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "recover_vault_secrets", "failed", "Failed to recover vault secrets", err)
		return fmt.Errorf("failed to recover vault secrets: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "recover_vault_secrets", "success", "Vault secrets recovered successfully")
	return nil
}
```

In `internal/repositories/key_repository.go`, add to `KeyRepositoryInterface` (after the existing `RecoverVaultContents` line):

```go
	// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
```

Replace `SoftDeleteVaultContents`/`RecoverVaultContents` (currently ~lines 996-1036):

```go
func (r *KeyRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("soft_delete_vault_keys", func() error {
		return r.softDeleteVaultContents(ctx, r.db, vaultID, deletedAt)
	})
}

func (r *KeyRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("soft_delete_vault_keys", func() error {
		return r.softDeleteVaultContents(ctx, ex, vaultID, deletedAt)
	})
}

func (r *KeyRepository) softDeleteVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Soft deleting all keys in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE keys SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
		deletedAt, vaultID.String())
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "soft_delete_vault_keys", "failed", "Failed to soft delete vault keys", err)
		return fmt.Errorf("failed to soft delete vault keys: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "soft_delete_vault_keys", "success", "Vault keys soft deleted successfully")
	return nil
}

func (r *KeyRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("recover_vault_keys", func() error {
		return r.recoverVaultContents(ctx, r.db, vaultID, deletedAt)
	})
}

func (r *KeyRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("recover_vault_keys", func() error {
		return r.recoverVaultContents(ctx, ex, vaultID, deletedAt)
	})
}

func (r *KeyRepository) recoverVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Recovering cascade soft-deleted keys in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE keys SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at = ?",
		vaultID.String(), deletedAt)
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "recover_vault_keys", "failed", "Failed to recover vault keys", err)
		return fmt.Errorf("failed to recover vault keys: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "recover_vault_keys", "success", "Vault keys recovered successfully")
	return nil
}
```

In `internal/repositories/certificate_repository.go`, add to `CertificateRepositoryInterface` (after the existing `RecoverVaultContents` line):

```go
	// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
```

Replace `SoftDeleteVaultContents`/`RecoverVaultContents` (currently ~lines 1043-1083):

```go
func (r *CertificateRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("soft_delete_vault_certificates", func() error {
		return r.softDeleteVaultContents(ctx, r.db, vaultID, deletedAt)
	})
}

func (r *CertificateRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("soft_delete_vault_certificates", func() error {
		return r.softDeleteVaultContents(ctx, ex, vaultID, deletedAt)
	})
}

func (r *CertificateRepository) softDeleteVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Soft deleting all certificates in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE certificates SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
		deletedAt, vaultID.String())
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "soft_delete_vault_certificates", "failed", "Failed to soft delete vault certificates", err)
		return fmt.Errorf("failed to soft delete vault certificates: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "soft_delete_vault_certificates", "success", "Vault certificates soft deleted successfully")
	return nil
}

func (r *CertificateRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("recover_vault_certificates", func() error {
		return r.recoverVaultContents(ctx, r.db, vaultID, deletedAt)
	})
}

func (r *CertificateRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("recover_vault_certificates", func() error {
		return r.recoverVaultContents(ctx, ex, vaultID, deletedAt)
	})
}

func (r *CertificateRepository) recoverVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Recovering cascade soft-deleted certificates in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE certificates SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at = ?",
		vaultID.String(), deletedAt)
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "recover_vault_certificates", "failed", "Failed to recover vault certificates", err)
		return fmt.Errorf("failed to recover vault certificates: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "recover_vault_certificates", "success", "Vault certificates recovered successfully")
	return nil
}
```

`db` (for `db.DBTX`) is already imported in all three files (used for the `db db.DB` struct field); no new imports needed there.

Now fix the two compile breaks this interface change causes. In `internal/services/retry/retry_repository_wrapper.go`, add `"rocketvault/internal/db"` to the import block, then append after the existing `RecoverVaultContents` method (currently ending at line 237):

```go

// SoftDeleteVaultContentsTx passes through to the base repository without
// retry wrapping: it always runs inside a caller-owned transaction, and
// retrying a statement after a mid-transaction failure would retry against a
// transaction that may already need to roll back.
func (r *RetryRepositoryWrapper) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.baseRepo.SoftDeleteVaultContentsTx(ctx, ex, vaultID, deletedAt)
}

// RecoverVaultContentsTx passes through to the base repository without retry
// wrapping, for the same reason as SoftDeleteVaultContentsTx.
func (r *RetryRepositoryWrapper) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.baseRepo.RecoverVaultContentsTx(ctx, ex, vaultID, deletedAt)
}
```

In `internal/testutils/mocks.go`, add `"rocketvault/internal/db"` to the import block, then append after the existing `RecoverVaultContents` mock (currently ending at line 244):

```go

func (m *MockSecretRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, ex, vaultID, deletedAt)
	return args.Error(0)
}

func (m *MockSecretRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, ex, vaultID, deletedAt)
	return args.Error(0)
}
```

### Step 4: Build and run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build (aside from the two vault-package fakes noted in Task 4, still fixed in Task 7).

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/repositories/... -run "SoftDeleteVaultContentsTx" -v 2>&1 | tail -60
```

Expected: all six new tests PASS.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/retry/... ./internal/testutils/... 2>&1 | tail -20
```

Expected: both packages build and pass (no behavior change to existing retry/mock tests).

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add internal/repositories/secret_repository.go internal/repositories/key_repository.go internal/repositories/certificate_repository.go internal/repositories/secret_repository_test.go internal/repositories/repositories_test.go internal/services/retry/retry_repository_wrapper.go internal/testutils/mocks.go && git commit -S -m "feat(vault): add Tx-scoped vault-content cascade methods to Secret/Key/Certificate repositories"
```

---

## Task 6: Thread the Tx-scoped methods through the cascade adapter

**Files:**
- Modify: `internal/services/vaults/cascade_adapter.go`
- Modify: `internal/services/vaults/cascade_adapter_test.go`
- Modify: `internal/services/vaults/vault_service.go` (`CascadeRepository` interface, currently lines 24-27)

**Interfaces:**
- Consumes: `SoftDeleteVaultContentsTx`/`RecoverVaultContentsTx` from Task 5 (on the three content repos) and `db.DBTX`.
- Produces: `vaultService.CascadeRepository` and the internal `vaultContentRepo` interface both gain `SoftDeleteVaultContentsTx(ctx, ex db.DBTX, vaultID, deletedAt) error` / `RecoverVaultContentsTx(...)`; `cascadeAdapter` fans both out the same way its existing non-Tx methods do (stop at first error).

### Step 1: Write the failing test

Append to `internal/services/vaults/cascade_adapter_test.go`, and give `recordingRepo`/`failingRepo` the new methods (replace the whole file's repo-double definitions):

```go
package vaults

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
)

type recordingRepo struct{ softCalls, recoverCalls int }

func (r *recordingRepo) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	r.softCalls++
	return nil
}
func (r *recordingRepo) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	r.recoverCalls++
	return nil
}
func (r *recordingRepo) SoftDeleteVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	r.softCalls++
	return nil
}
func (r *recordingRepo) RecoverVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	r.recoverCalls++
	return nil
}

func TestCascadeAdapter_FansOutToAllRepos(t *testing.T) {
	s, k, c := &recordingRepo{}, &recordingRepo{}, &recordingRepo{}
	ad := NewCascadeAdapter(s, k, c)
	if err := ad.SoftDeleteVaultContents(context.Background(), uuid.New(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.softCalls != 1 || k.softCalls != 1 || c.softCalls != 1 {
		t.Fatalf("soft-delete must fan out to all three repos: s=%d k=%d c=%d", s.softCalls, k.softCalls, c.softCalls)
	}
	if err := ad.RecoverVaultContents(context.Background(), uuid.New(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.recoverCalls != 1 || k.recoverCalls != 1 || c.recoverCalls != 1 {
		t.Fatalf("recover must fan out to all three repos")
	}
}

// failingRepo fails its soft-delete to exercise the adapter's error path.
type failingRepo struct{ err error }

func (f *failingRepo) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingRepo) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error { return f.err }
func (f *failingRepo) SoftDeleteVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingRepo) RecoverVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	return f.err
}

func TestCascadeAdapter_ReturnsFirstError(t *testing.T) {
	boom := errors.New("boom")
	failing := &failingRepo{err: boom}
	later := &recordingRepo{}
	ad := NewCascadeAdapter(failing, later)

	err := ad.SoftDeleteVaultContents(context.Background(), uuid.New(), time.Now())
	if !errors.Is(err, boom) {
		t.Fatalf("expected the first repo's error, got %v", err)
	}
	if later.softCalls != 0 {
		t.Fatalf("expected later repo not to be called after an error, got %d", later.softCalls)
	}
}

// TestCascadeAdapter_TxFansOutToAllRepos proves the Tx-scoped fan-out behaves
// exactly like the non-Tx fan-out, threading the same executor to every repo.
func TestCascadeAdapter_TxFansOutToAllRepos(t *testing.T) {
	s, k, c := &recordingRepo{}, &recordingRepo{}, &recordingRepo{}
	ad := NewCascadeAdapter(s, k, c)
	if err := ad.SoftDeleteVaultContentsTx(context.Background(), nil, uuid.New(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.softCalls != 1 || k.softCalls != 1 || c.softCalls != 1 {
		t.Fatalf("Tx soft-delete must fan out to all three repos: s=%d k=%d c=%d", s.softCalls, k.softCalls, c.softCalls)
	}
}

func TestCascadeAdapter_TxReturnsFirstError(t *testing.T) {
	boom := errors.New("boom")
	failing := &failingRepo{err: boom}
	later := &recordingRepo{}
	ad := NewCascadeAdapter(failing, later)

	err := ad.SoftDeleteVaultContentsTx(context.Background(), nil, uuid.New(), time.Now())
	if !errors.Is(err, boom) {
		t.Fatalf("expected the first repo's error, got %v", err)
	}
	if later.softCalls != 0 {
		t.Fatalf("expected later repo not to be called after an error, got %d", later.softCalls)
	}
}
```

(`db.DBTX` accepts `nil` as an interface value here since `recordingRepo`/`failingRepo` never dereference it — these two tests exercise only the adapter's fan-out/stop-on-error logic, not real query execution.)

### Step 2: Run to confirm the tests fail

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./internal/services/vaults/... 2>&1
```

Expected: **build failure** — `SoftDeleteVaultContentsTx` doesn't exist on `CascadeRepository`/`vaultContentRepo` yet.

### Step 3: Update `cascade_adapter.go` and `CascadeRepository`

Replace `internal/services/vaults/cascade_adapter.go` in full:

```go
package vaults

import (
	"context"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
)

// vaultContentRepo is the subset of a resource repository the cascade needs.
type vaultContentRepo interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
}

// cascadeAdapter fans cascade operations out to the secret, key, and cert repos.
type cascadeAdapter struct {
	repos []vaultContentRepo
}

// NewCascadeAdapter builds a CascadeRepository over the given content repos.
func NewCascadeAdapter(repos ...vaultContentRepo) CascadeRepository {
	return &cascadeAdapter{repos: repos}
}

func (a *cascadeAdapter) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	for _, r := range a.repos {
		if err := r.SoftDeleteVaultContents(ctx, vaultID, deletedAt); err != nil {
			return err
		}
	}
	return nil
}

func (a *cascadeAdapter) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	for _, r := range a.repos {
		if err := r.RecoverVaultContents(ctx, vaultID, deletedAt); err != nil {
			return err
		}
	}
	return nil
}

func (a *cascadeAdapter) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	for _, r := range a.repos {
		if err := r.SoftDeleteVaultContentsTx(ctx, ex, vaultID, deletedAt); err != nil {
			return err
		}
	}
	return nil
}

func (a *cascadeAdapter) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	for _, r := range a.repos {
		if err := r.RecoverVaultContentsTx(ctx, ex, vaultID, deletedAt); err != nil {
			return err
		}
	}
	return nil
}
```

In `internal/services/vaults/vault_service.go`, replace the `CascadeRepository` interface (currently lines 24-27) and add the `db` import:

```go
// CascadeRepository soft-deletes or recovers all resources belonging to a vault.
type CascadeRepository interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
}
```

Add `"rocketvault/internal/db"` to `vault_service.go`'s import block (needed here and again in Task 7).

Also update `internal/services/vaults/vault_service_test.go`'s `noopCascade` (currently lines 93-102) so it keeps satisfying `CascadeRepository`:

```go
type noopCascade struct{ soft, recover int }

func (n *noopCascade) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	n.soft++
	return nil
}
func (n *noopCascade) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	n.recover++
	return nil
}
func (n *noopCascade) SoftDeleteVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	n.soft++
	return nil
}
func (n *noopCascade) RecoverVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	n.recover++
	return nil
}
```

Add `"rocketvault/internal/db"` to `vault_service_test.go`'s import block.

### Step 4: Build and run

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build (aside from the two vault-package fakes still pending Task 7 — `fakeVaultRepo`/`vaultFakeRepo` are missing `ReadByIDTx`/`SoftDeleteTx`/`RecoverTx` from Task 4).

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/vaults/... -run "TestCascadeAdapter" -v 2>&1 | tail -40
```

Expected: all `TestCascadeAdapter_*` PASS, including the two new Tx tests.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add internal/services/vaults/cascade_adapter.go internal/services/vaults/cascade_adapter_test.go internal/services/vaults/vault_service.go internal/services/vaults/vault_service_test.go && git commit -S -m "feat(vault): thread Tx-scoped cascade methods through cascadeAdapter and CascadeRepository"
```

---

## Task 7: Wire `TxBeginner` into `vaultService` and make `DeleteVault`/`RecoverVault` transactional

**Files:**
- Modify: `internal/services/vaults/vault_service.go` (`VaultService` interface lines 35-44, `vaultService` struct lines 46-52, `NewVaultService` line 54-56, `DeleteVault` lines 162-192, `RecoverVault` lines 194-217)
- Modify: `internal/services/vaults/vault_service_test.go` (`fakeVaultRepo` Tx stub methods)
- Modify: `api/vault_test.go` (`vaultFakeRepo` Tx stub methods)
- Modify: `internal/container/service_container.go` (lines 279-280)

**Interfaces:**
- Produces: `VaultService` gains `SetTxBeginner(tb TxBeginner)` (mirrors the existing `SetPolicyCleaner` pattern). `TxBeginner` is a new exported interface in the `vaults` package: `BeginTx(ctx context.Context, opts *sql.TxOptions) (*db.Tx, error)`, satisfied by `*db.Conn`. When unset (every existing unit test), `DeleteVault`/`RecoverVault` run the pre-existing non-transactional sequence unchanged. When set (production wiring), they run inside one `*db.Tx`.

### Step 1: Fix the two fakes so the package builds again (from Tasks 4 and 6)

In `internal/services/vaults/vault_service_test.go`, add these methods to `fakeVaultRepo` (after the existing `Purge` method):

```go
func (f *fakeVaultRepo) ReadByIDTx(_ context.Context, _ db.DBTX, id uuid.UUID) (*model.Vault, error) {
	return f.ReadByID(context.Background(), id)
}
func (f *fakeVaultRepo) SoftDeleteTx(_ context.Context, _ db.DBTX, id uuid.UUID) error {
	return f.SoftDelete(context.Background(), id)
}
func (f *fakeVaultRepo) RecoverTx(_ context.Context, _ db.DBTX, id uuid.UUID) error {
	return f.Recover(context.Background(), id)
}
```

In `api/vault_test.go`, add the same three methods to `vaultFakeRepo` (after its existing `Purge` method):

```go
func (f *vaultFakeRepo) ReadByIDTx(_ context.Context, _ db.DBTX, id uuid.UUID) (*model.Vault, error) {
	return f.ReadByID(context.Background(), id)
}
func (f *vaultFakeRepo) SoftDeleteTx(_ context.Context, _ db.DBTX, id uuid.UUID) error {
	return f.SoftDelete(context.Background(), id)
}
func (f *vaultFakeRepo) RecoverTx(_ context.Context, _ db.DBTX, id uuid.UUID) error {
	return f.Recover(context.Background(), id)
}
```

Add `"rocketvault/internal/db"` to `api/vault_test.go`'s import block.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build. All existing tests in both packages still pass unchanged (verify below in Step 4).

### Step 2: Write the failing test for the setter

`*db.Tx`'s fields are unexported by design, so no test double outside the `db` package can construct a usable one — the real proof that the transactional branch works end-to-end, including atomic rollback, is Task 8's integration test against a real SQLite database. This step only proves `SetTxBeginner`/`TxBeginner` exist and are part of the exported `VaultService` interface, which is a precondition for Task 8 to compile at all.

Append to `internal/services/vaults/vault_service_test.go`:

```go
func TestVaultService_SetTxBeginnerIsPartOfTheInterface(t *testing.T) {
	svc := NewVaultService(newFakeRepo(), &noopCascade{}, nil)
	var _ interface {
		SetTxBeginner(tb TxBeginner)
	} = svc
}
```

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./internal/services/vaults/... 2>&1
```

Expected: **build failure** — `SetTxBeginner`/`TxBeginner` don't exist yet.

### Step 3: Implement `TxBeginner`, `SetTxBeginner`, `withTx`, and the transactional `DeleteVault`/`RecoverVault`

In `internal/services/vaults/vault_service.go`, add the `TxBeginner` interface near `PolicyCleaner` (after line 33's closing brace):

```go
// TxBeginner begins a transaction usable by the Tx-scoped repository/cascade
// methods. Satisfied by *db.Conn. Injected via SetTxBeginner so unit tests
// that construct a vaultService without a real database (every existing test
// in this package) keep exercising the pre-existing non-transactional path.
type TxBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*db.Tx, error)
}
```

Add `"database/sql"` and `"rocketvault/internal/db"` to the import block (the latter may already be present from Task 6).

Add `SetTxBeginner` to the `VaultService` interface (currently lines 35-44), alongside `SetPolicyCleaner`:

```go
	SetPolicyCleaner(p PolicyCleaner)
	SetTxBeginner(tb TxBeginner)
```

Add the field to `vaultService` (currently lines 46-52):

```go
type vaultService struct {
	repo       repositories.VaultRepositoryInterface
	cascade    CascadeRepository
	policies   PolicyCleaner
	txBeginner TxBeginner
	log        *logging.Logger
}
```

Add the setter next to `SetPolicyCleaner` (currently line 59):

```go
// SetTxBeginner attaches an optional transaction beginner. When set,
// DeleteVault/RecoverVault run their cascade atomically inside one
// transaction; when unset, they run the pre-existing non-transactional
// sequence.
func (s *vaultService) SetTxBeginner(tb TxBeginner) { s.txBeginner = tb }
```

Add the `withTx` helper right after `SetTxBeginner`:

```go
// withTx runs fn inside a transaction begun via txBeginner, committing on
// success and rolling back on error. Mirrors db.WithTx's commit/rollback
// semantics but operates on the dialect-aware db.Tx the repository layer
// uses, rather than a raw *sql.Tx.
func (s *vaultService) withTx(ctx context.Context, fn func(tx *db.Tx) error) error {
	tx, err := s.txBeginner.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %w (original: %v)", rbErr, err)
		}
		return err
	}
	return tx.Commit()
}
```

Replace `DeleteVault` (currently lines 162-192):

```go
// DeleteVault soft-deletes a vault and cascades the soft-delete to its contents.
func (s *vaultService) DeleteVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be deleted")
	}
	v, err := s.getByName(ctx, name)
	if err != nil {
		return err
	}

	if s.txBeginner == nil {
		// No transaction support configured (e.g. unit tests against fakes);
		// fall back to the pre-existing non-transactional sequence.
		if err := s.repo.SoftDelete(ctx, v.ID); err != nil {
			return err
		}
		deleted, err := s.repo.ReadByID(ctx, v.ID)
		if err != nil {
			return fmt.Errorf("read vault after soft-delete: %w", err)
		}
		if deleted.DeletedAt == nil {
			return fmt.Errorf("vault %q missing deleted_at after soft-delete", name)
		}
		if err := s.cascade.SoftDeleteVaultContents(ctx, v.ID, *deleted.DeletedAt); err != nil {
			return fmt.Errorf("cascade soft-delete vault contents: %w", err)
		}
	} else {
		// Soft-delete the vault row and cascade its contents atomically: if the
		// cascade fails partway, the whole transaction rolls back and the vault
		// row itself is never left soft-deleted without its contents following.
		if err := s.withTx(ctx, func(tx *db.Tx) error {
			if err := s.repo.SoftDeleteTx(ctx, tx, v.ID); err != nil {
				return err
			}
			deleted, err := s.repo.ReadByIDTx(ctx, tx, v.ID)
			if err != nil {
				return fmt.Errorf("read vault after soft-delete: %w", err)
			}
			if deleted.DeletedAt == nil {
				return fmt.Errorf("vault %q missing deleted_at after soft-delete", name)
			}
			if err := s.cascade.SoftDeleteVaultContentsTx(ctx, tx, v.ID, *deleted.DeletedAt); err != nil {
				return fmt.Errorf("cascade soft-delete vault contents: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	if s.log != nil {
		s.log.LogAuditInfo("", "delete_vault", "success", fmt.Sprintf("Vault deleted: %s", name))
	}
	return nil
}
```

Replace `RecoverVault` (currently lines 194-217):

```go
// RecoverVault restores a soft-deleted vault and cascades the recovery to its contents.
func (s *vaultService) RecoverVault(ctx context.Context, name string) error {
	v, err := s.findDeleted(ctx, name)
	if err != nil {
		return err
	}
	if v.DeletedAt == nil {
		return fmt.Errorf("vault %q missing deleted_at", name)
	}
	// Capture the vault's deletion timestamp before recovery clears it. The cascade
	// restores only the contents stamped with this exact timestamp, leaving rows the
	// user deleted individually (different deleted_at) untouched.
	deletedAt := *v.DeletedAt

	if s.txBeginner == nil {
		if err := s.repo.Recover(ctx, v.ID); err != nil {
			return fmt.Errorf("recover vault: %w", err)
		}
		if err := s.cascade.RecoverVaultContents(ctx, v.ID, deletedAt); err != nil {
			return fmt.Errorf("cascade recover vault contents: %w", err)
		}
	} else if err := s.withTx(ctx, func(tx *db.Tx) error {
		if err := s.repo.RecoverTx(ctx, tx, v.ID); err != nil {
			return fmt.Errorf("recover vault: %w", err)
		}
		if err := s.cascade.RecoverVaultContentsTx(ctx, tx, v.ID, deletedAt); err != nil {
			return fmt.Errorf("cascade recover vault contents: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if s.log != nil {
		s.log.LogAuditInfo("", "recover_vault", "success", fmt.Sprintf("Vault recovered: %s", name))
	}
	return nil
}
```

The `TestVaultService_SetTxBeginnerIsPartOfTheInterface` test added in Step 2 now compiles as-is against this interface change.

Finally, wire it in production. In `internal/container/service_container.go`, replace lines 279-280:

```go
	vaultCascade := vaultServices.NewCascadeAdapter(c.secretRepository, c.keyRepository, c.certificateRepository)
	c.vaultService = vaultServices.NewVaultService(c.vaultRepository, vaultCascade, c.logger)
	c.vaultService.SetTxBeginner(c.conn)
```

### Step 4: Build and run the full existing suite

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/vaults/... ./api/... ./internal/container/... -v 2>&1 | grep -E "FAIL|--- PASS" | tail -100
```

Expected: every pre-existing test in these three packages still PASSes unchanged (confirms the `s.txBeginner == nil` fallback in `DeleteVault`/`RecoverVault` behaves identically to the old code for every test that doesn't call `SetTxBeginner`), plus the new interface-shape test.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|^ok" | tail -40
```

Expected: all packages `ok`, no `FAIL`.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add internal/services/vaults/vault_service.go internal/services/vaults/vault_service_test.go api/vault_test.go internal/container/service_container.go && git commit -S -m "feat(vault): make DeleteVault/RecoverVault transactional when a TxBeginner is configured"
```

---

## Task 8: Prove atomicity with a real-database rollback/commit test

**Files:**
- Create: `internal/services/vaults/vault_service_tx_integration_test.go`

**Interfaces:**
- Consumes: `vaultServices.NewVaultService`, `vaultServices.NewCascadeAdapter`, `VaultService.SetTxBeginner` (all exported, from Task 7); `repositories.NewVaultRepository`/`NewSecretRepository` (real, from Tasks 4-5); `db.NewConn`/`db.DBTX` (from `internal/db`).

This is the task that actually proves the point of Part 2: a mid-cascade failure rolls back the vault row too, and a successful cascade commits every table together.

### Step 1: Write the tests

Create `internal/services/vaults/vault_service_tx_integration_test.go`:

```go
package vaults_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

func newTxTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// newTxTestDB creates an in-memory SQLite database with just enough schema
// (vaults + secrets) to prove a transaction shared between VaultRepository
// and SecretRepository rolls back or commits both tables together.
func newTxTestDB(t *testing.T) *sql.DB {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = sqlDB.Exec(`
		CREATE TABLE vaults (
			id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT 1,
			purge_protection BOOLEAN NOT NULL DEFAULT 0,
			retention_days INTEGER NOT NULL DEFAULT 90,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL,
			tags TEXT NOT NULL DEFAULT '{}',
			updated_at TIMESTAMP NULL,
			updated_by TEXT NULL
		);
		CREATE TABLE secrets (
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
		);`)
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	return sqlDB
}

// explodingContentRepo stands in for a cascade participant (e.g.
// certificates) that fails mid-cascade, proving the transaction rolls back
// every repo's writes, not just its own.
type explodingContentRepo struct{ err error }

func (e *explodingContentRepo) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	return e.err
}
func (e *explodingContentRepo) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	return e.err
}
func (e *explodingContentRepo) SoftDeleteVaultContentsTx(context.Context, rvdb.DBTX, uuid.UUID, time.Time) error {
	return e.err
}
func (e *explodingContentRepo) RecoverVaultContentsTx(context.Context, rvdb.DBTX, uuid.UUID, time.Time) error {
	return e.err
}

func deletedAtColumn(t *testing.T, sqlDB *sql.DB, table string, id uuid.UUID) *time.Time {
	t.Helper()
	var deletedAt sql.NullTime
	require.NoError(t, sqlDB.QueryRow("SELECT deleted_at FROM "+table+" WHERE id = ?", id.String()).Scan(&deletedAt))
	if !deletedAt.Valid {
		return nil
	}
	return &deletedAt.Time
}

func TestDeleteVault_CascadeFailureRollsBackEverything(t *testing.T) {
	sqlDB := newTxTestDB(t)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	log := newTxTestLogger(t)
	ctx := context.Background()

	vaultRepo := repositories.NewVaultRepository(conn, log)
	secretRepo := repositories.NewSecretRepository(conn, log)

	vaultID := uuid.New()
	require.NoError(t, vaultRepo.Create(ctx, &model.Vault{
		ID: vaultID, Name: "prod", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New(),
	}))
	secretID := uuid.New()
	require.NoError(t, secretRepo.Create(ctx, &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}))

	boom := errors.New("cert cascade boom")
	cascade := vaultServices.NewCascadeAdapter(secretRepo, &explodingContentRepo{err: boom})
	svc := vaultServices.NewVaultService(vaultRepo, cascade, log)
	svc.SetTxBeginner(conn)

	err := svc.DeleteVault(ctx, "prod")
	require.Error(t, err)
	require.ErrorIs(t, err, boom)

	require.Nil(t, deletedAtColumn(t, sqlDB, "vaults", vaultID), "vault soft-delete must have rolled back")
	require.Nil(t, deletedAtColumn(t, sqlDB, "secrets", secretID), "secret soft-delete must have rolled back with it")
}

func TestDeleteVault_CascadeSuccessCommitsEverything(t *testing.T) {
	sqlDB := newTxTestDB(t)
	conn := rvdb.NewConn(sqlDB, rvdb.SQLite)
	log := newTxTestLogger(t)
	ctx := context.Background()

	vaultRepo := repositories.NewVaultRepository(conn, log)
	secretRepo := repositories.NewSecretRepository(conn, log)

	vaultID := uuid.New()
	require.NoError(t, vaultRepo.Create(ctx, &model.Vault{
		ID: vaultID, Name: "prod", Enabled: true, RetentionDays: 90, CreatedBy: uuid.New(),
	}))
	secretID := uuid.New()
	require.NoError(t, secretRepo.Create(ctx, &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}))

	cascade := vaultServices.NewCascadeAdapter(secretRepo)
	svc := vaultServices.NewVaultService(vaultRepo, cascade, log)
	svc.SetTxBeginner(conn)

	require.NoError(t, svc.DeleteVault(ctx, "prod"))

	require.NotNil(t, deletedAtColumn(t, sqlDB, "vaults", vaultID), "vault must be soft-deleted after commit")
	require.NotNil(t, deletedAtColumn(t, sqlDB, "secrets", secretID), "secret must be soft-deleted after commit")
}
```

### Step 2: Run to confirm the rollback test fails without the fix

To confirm this test genuinely guards the regression, temporarily revert Task 7's `DeleteVault` to always take the `s.txBeginner == nil` branch (e.g. comment out the `else` branch's body and call the non-transactional sequence unconditionally), then run:

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/vaults/... -run "TestDeleteVault_CascadeFailureRollsBackEverything" -v 2>&1 | tail -20
```

Expected without the transactional path: **FAIL** — the vault row would show a non-nil `deleted_at` even though the cascade failed, because the non-transactional sequence commits the vault's own soft-delete before ever calling the cascade. Restore Task 7's code afterward.

### Step 3: Run for real

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1
```

Expected: clean build.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/services/vaults/... -run "TestDeleteVault_Cascade" -v 2>&1 | tail -30
```

Expected: both new tests PASS.

### Step 4: Run the full suite

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|^ok" | tail -40
```

Expected: all packages `ok`, no `FAIL`.

### Step 5: Commit

```bash
cd /home/numericlabs/data/rocket/rocketvault && git add internal/services/vaults/vault_service_tx_integration_test.go && git commit -S -m "test(vault): prove DeleteVault rolls back the vault row when its cascade fails"
```

**Part 2 is complete here** — `DeleteVault`/`RecoverVault` are now atomic across the vault row and its secrets/keys/certificates in production.

---

## Self-Review

**Spec coverage:**
- Follow-up item 2 ("introduce a shared `repositories.ErrNotFound` sentinel and thread it end-to-end … so a DB outage doesn't present as a mass 'vault not found' 404 storm") → Tasks 1-3: sentinel added, `getByName`/`PurgeVault` fixed, `api/vault.go`'s three handlers split 404 from 500. Scoped to the vault path named as root cause in the spec; extending the same sentinel to the other 13 repositories is explicitly deferred (see Follow-Up below), not silently out of scope. ✅
- Follow-up item 3 ("wrap the vault delete/recover cascade … in a `WithTx` transaction so a mid-cascade failure cannot leave the vault row and its contents in inconsistent soft-delete states") → Tasks 4-8. The literal `db.WithTx` helper is not reusable as-is (documented architecture mismatch in the plan's Architecture section); the same commit/rollback semantics are achieved via a dialect-aware equivalent (`vaultService.withTx` + `*db.Tx`-scoped repository methods), which is the substantive requirement. Task 8 proves atomicity with a real database, not mocks. ✅
- "No existing exported method signature may change" (Global Constraint) → every new capability in Tasks 4-6 is an additively-named `*Tx` sibling method; `RetryRepositoryWrapper`/`MockSecretRepository` get passthrough/stub additions, not signature edits. ✅
- "Every existing test's behavior [preserved] unless explicitly changed" → Task 7's `s.txBeginner == nil` branch is verbatim the pre-existing `DeleteVault`/`RecoverVault` code; Step 4 of that task explicitly re-runs the full pre-existing test suite in the touched packages to confirm this. ✅

**Placeholder scan:** No `TODO`/`FIXME`/`TBD`/"add appropriate error handling" placeholders. Every new method has a concrete body; every new test has concrete assertions (`errors.Is`, `require.Nil`/`NotNil` on a real queried column, exact HTTP status codes). ✅

**Type consistency (verified by reading the code before writing each task):**
- `VaultRepositoryInterface`/`SecretRepositoryInterface`/`KeyRepositoryInterface`/`CertificateRepositoryInterface` field/method names match their concrete implementations exactly (`db db.DB`, `log *logging.Logger`), confirmed by reading each file in full before drafting its task. ✅
- `db.DBTX` (`ExecContext`/`QueryContext`/`QueryRowContext`) is satisfied by both `*db.Conn` and `*db.Tx` already, with no changes needed to `internal/db/conn.go` — confirmed by reading that file in full; this plan deliberately avoids modifying it. ✅
- `TxBeginner.BeginTx(ctx, opts) (*db.Tx, error)` matches `*db.Conn.BeginTx`'s exact existing signature (`internal/db/conn.go:56`) — no adapter needed for production wiring. ✅
- `ServiceContainer.secretRepository`/`.keyRepository`/`.certificateRepository`/`.vaultRepository` are all interface-typed (`repositories.XRepositoryInterface`), confirmed by reading `service_container.go:140-147` — this is exactly why Tasks 5-6 add the new methods to the exported interfaces rather than only the concrete structs (an interface-to-interface `vaultContentRepo` assignment requires the source interface to already declare the methods). ✅
- `RetryRepositoryWrapper` and `MockSecretRepository` both implement `SecretRepositoryInterface` by explicit method list (no embedding), confirmed by reading both files — this is why Task 5 must add passthrough/stub methods to both, not just the concrete `SecretRepository`. ✅
- `VaultRepository.ReadByID`/`SoftDelete`/`Recover` have exactly one caller file (`vault_service.go`), confirmed via `grep -rn "\.ReadByID(\|\.SoftDelete(\|\.Recover("` across `internal/`, `api/`, `cmd/` — this is why Task 4 is safe as an additive-only change with no other ripple. ✅
- `model.Secret`'s field set used in Task 8's seed data (`ID`, `UserID`, `VaultID`, `Name`, `Value`, `Version`, `CreatedAt`, `Enabled`) matches `model/secret.go`'s struct exactly, and mirrors the exact seeding pattern already used in `internal/repositories/secret_repository_test.go`. ✅

---

## Follow-Up

Deferred to their own spec+plan pairs, in order of priority:

- **[Medium]** Extend `repositories.ErrNotFound` beyond `VaultRepository` to the other 13 repositories currently using ad-hoc `fmt.Errorf("<noun> not found")` strings (`secret_repository.go`, `key_repository.go`, `certificate_repository.go`, `user_repository.go`, `session_repository.go`, `rotation_repository.go`, `versioning_repository.go`, `audit_repository.go`, `oauth2_client_repository.go`). Also fix `role_assignment_repository.go`'s `FindByTuple` string-comparison anti-pattern (`err.Error() == "role assignment not found"`) and `access_policy_repository.go`'s `err == sql.ErrNoRows` (should be `errors.Is`).
- **[Medium]** (already noted in the source spec) Add a `pg_advisory_lock` around `SetupSchema`/`finalizeVaultIndexes` to prevent a multi-instance startup race, and consolidate the two divergent migration systems (`cmd/migrate.go`'s `MigrationRunner` vs. `internal/db/db.go`'s `migrateSchema()`).
- **[Low]** `PurgeVault` still calls `s.repo.Purge`/`s.policies.DeleteByVault` non-transactionally; the same atomicity gap Part 2 closed for delete/recover exists for purge, but purge is a hard, irreversible deletion with a narrower blast radius (nothing to "roll back to") and was intentionally left out of this plan's scope, which named only delete/recover per the spec.
