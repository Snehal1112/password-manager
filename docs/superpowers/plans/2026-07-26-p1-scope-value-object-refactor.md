# P1: model.Scope Value Object Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the duplicated `*InVault` / `*ByOwner` / plain method triples across the repository, service, handler, CLI and cache layers onto a single explicit `model.Scope` value object whose zero value fails closed.

**Architecture:** A new dependency-free value object in `model/` carries the authorization scope of one operation (vault, owner, or admin). `internal/repositories/scope_predicate.go` turns that value into one of three compile-time-constant SQL fragments plus bind arguments, so the scoped read *is* the authorization check and the scoped write repeats the same predicate. Migration is bottom-up in seven phases: the new API lands first as the canonical implementation, every old method becomes a three-line shim, and the untouched existing test suite is the equivalence proof until the shims are deleted in Phase 6.

**Tech Stack:** Go 1.25, SQLite/PostgreSQL via `internal/db`, `github.com/google/uuid`, `gorilla/mux`, `testify` (assert/require/mock), `mockery` for generated mocks, GPG-signed commits.

## Global Constraints

- All new domain types go in `model/`. `internal/domain/` does not exist; do not create it.
- Composite literals of `model.Scope{}` are forbidden outside `model/scope_test.go`.
- Every repository entry point calls `Validate()` before building a query.
- The predicate is always built from the explicit `Scope` argument, never from the entity.
- No caller-supplied value is ever interpolated; every value travels as a `?` placeholder.
- `ScopeOwner` deliberately does **not** constrain `vault_id`; tightening it would smuggle a behavioral change into a refactor.
- Caching stays disabled on the unified `GetSecret` through Phase 3.
- New mutators must be added to the `TestEveryMutatorInvalidates` table in the same commit.
- One resource per commit in Phases 3 and 4.
- Verification gates run `go build ./... && go test ./...`. `go vet` alone is insufficient — `cmd/testutils.MockServiceContainer` stores services as `interface{}` and type-asserts at runtime, so a missing mock method surfaces only as a `go test` panic.
- Every commit is GPG-signed: `git commit -S`.
- P0, P1 and P2 ship as **one release**. Never deploy P1 alone to production.

### Plan-level naming decision (not spelled out in the spec)

Go has no method overloading, so a scope-aware `Read(ctx, id, scope)` cannot coexist with the legacy `Read(ctx, id)` it replaces. Phases 1–5 therefore introduce the canonical bodies under a transitional `…Scoped` suffix, and **Phase 6 renames them to the final names in the same commit that deletes the shims**:

| Transitional (Phases 1–5) | Final (Phase 6) |
|---|---|
| `ReadScoped` | `Read` |
| `UpdateScoped` | `Update` |
| `ListScoped` | `List` |
| `GetSecretScoped` / `GetKeyScoped` / `GetCertificateScoped` | `GetSecret` / `GetKey` / `GetCertificate` |
| `ListSecretsScoped` / `ListKeysScoped` / `ListCertificatesScoped` | `ListSecrets` / `ListKeys` / `ListCertificates` |
| `DeleteSecretScoped` / `DeleteKeyScoped` / `DeleteCertificateScoped` | `DeleteSecret` / `DeleteKey` / `DeleteCertificate` |
| `UpdateSecretScoped` / `UpdateKeyScoped` / `UpdateCertificateScoped` | `UpdateSecret` / `UpdateKey` / `UpdateCertificate` |
| `RecoverSecretScoped` / `PurgeSecretScoped` | `RecoverSecret` / `PurgeSecret` |

### Corrections to the spec found while verifying against the repo

1. §5.3 says `isVaultScopedRoute` has "8 call sites". The verified count is **17** across five files: `api/secrets.go` (8: lines 95, 142, 188, 261, 352, 490, 560, 677), `api/keys.go` (3: 381, 439, 527), `api/certificate_policy.go` (3: 29, 100, 170), `api/certificates.go` (2: 256, 312), `api/soft_delete.go` (1: 61). The spec's "8" matches `api/secrets.go` alone. All 17 must go before the symbol can be deleted.
2. §9's certificate `type`-column risk is confirmed: the `certificates` table has no `type` column in `internal/db/db.go` (`CREATE TABLE` at 434-452, no `ALTER TABLE … type` anywhere in `migrateSchema()` at 691+), `model.Certificate` has no `Type` field, and both non-test callers pass `""`. Resolution chosen: **drop the dead filter** (Task 3), not add the column.
3. `CertificateRepository.ListByUser` neither selects `vault_id` nor back-fills `cert.VaultID` — the same defect family as the secret `Read`/`ReadByOwner` gap called out in §5.3. Fixed in Task 3.
4. §5.4 Phase 2 says "update the retry wrapper" (singular). Verified: retry decorators exist **only** for secrets and users — `internal/services/retry/retry_repository_wrapper.go` (wraps `SecretRepositoryInterface`) and `retry_secret_service.go` (wraps `secrets.SecretService`). There is no retry wrapper for `KeyRepositoryInterface`, `CertificateRepositoryInterface`, `KeyService`, or `CertificateService`, so Tasks 12 and 13 have no wrapper work. Note `NewRetryRepositoryWrapper` is never called outside tests but must still satisfy the interface and compile.
5. `api/context.go` has no user-ID extractor. Two near-duplicates exist: `getUserID(c *Context)` at `api/backup_item.go:51` and `userIDFromClaims(c *Context)` at `api/soft_delete.go:418`. The scope helpers in Task 22 reuse `userIDFromClaims`; do not add a third.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `model/scope.go` | Create | `ScopeKind`, `Scope`, constructors, accessors, `Validate`, `String`, `ResolvedVaultID`. |
| `model/scope_test.go` | Create | Unit tests for the value object, incl. the only permitted `model.Scope{}` literals. |
| `internal/repositories/scope_predicate.go` | Create | `ErrInvalidScope`, `scopePredicate(model.Scope) (string, []any, error)`. |
| `internal/repositories/scope_predicate_test.go` | Create | `TestScopePredicateBindArity` and per-kind fragment assertions. |
| `internal/repositories/secret_repository.go` | Modify | Scope-aware `ReadScoped`/`UpdateScoped`/`ListScoped`, `SecretFilter`, `vault_id` SELECT fix, shims. |
| `internal/repositories/key_repository.go` | Modify | Scope-aware trio, `KeyFilter`, shims. |
| `internal/repositories/certificate_repository.go` | Modify | Drop dead `type` filter, `vault_id` SELECT fix, scope-aware trio, `CertificateFilter`, shims. |
| `internal/repositories/scope_rejection_test.go` | Create | `model.Scope{}` rejection test per scope-aware repository method (all three repositories). |
| `internal/services/retry/retry_repository_wrapper.go` | Modify | Wrap the three new secret-repository methods. |
| `internal/services/retry/retry_secret_service.go` | Modify | Generic `retried[T]` helper; wrap the new service methods. |
| `internal/services/retry/retried.go` | Create | `retried[T]` generic helper removing var/closure/return boilerplate. |
| `internal/services/secrets/secret_update.go` | Create | Pure `applySecretUpdate`. |
| `internal/services/secrets/secret_update_test.go` | Create | Unit tests for `applySecretUpdate` — no database. |
| `internal/services/secrets/secret_service.go` | Modify | Scope-aware service methods, `Scope` field on request structs, shims. |
| `internal/services/secrets/versioning_service.go` | Modify | Scope-aware version getters, shims. |
| `internal/services/keys/key_update.go` | Create | Pure `applyKeyUpdate`. |
| `internal/services/keys/key_update_test.go` | Create | Unit tests for `applyKeyUpdate`. |
| `internal/services/keys/key_service.go` | Modify | Scope-aware service methods, drop `ListKeysWithFilters`' `isAdmin` re-derivation, shims. |
| `internal/services/certificates/certificate_service.go` | Modify | Scope-aware service methods, shims. |
| `api/context.go` | Modify | Add `scopeFromRequest`, `ownerScopeFromRequest`; delete `isVaultScopedRoute`. |
| `api/errors_secret.go` | Create | Shared `writeSecretError`. |
| `api/secrets.go` | Modify | 8 handlers onto scopes; `listSecretVersionsHandler` 500→404 fix. |
| `api/soft_delete.go` | Modify | Scope-aware soft-delete handlers; drop the `IsSecretSoftDeleted*` TOCTOU pre-check. |
| `api/keys.go` | Modify | 3 branch sites onto scopes; B6 handlers use `ownerScopeFromRequest`. |
| `api/certificates.go` | Modify | 2 branch sites onto scopes. |
| `api/certificate_policy.go` | Modify | 3 branch sites onto scopes. |
| `cmd/secrets/get.go`, `list.go`, `delete.go` | Modify | CLI onto scopes. |
| `cmd/keys/list.go` | Modify | Admin listing via `model.NewAdminScope`. |
| `internal/cache/secret_cache.go` | Modify | `scopeCacheKey`, `byID` reverse index, `DeleteByID`, `Flush` vs `Clear`. |
| `internal/cache/cache_integration.go` | Modify | Compound-key caching, `IsAccessible()` recheck, invalidation on every mutator. |
| `internal/cache/mutator_invalidation_test.go` | Create | `TestEveryMutatorInvalidates`. |
| `internal/db/db.go` | Read-only | Consulted to confirm the `certificates` table has no `type` column. |
| `.github/workflows/go.yml` | Modify | Phase 6 CI grep gate. |
| `CLAUDE.md` | Modify | Remove the `internal/domain/` fiction; document `model/`. |
| `.claude/multi-vault.md` | Modify | Correct the "no vault-scoped route silently ignores its vault" claim. |

---

## Phase 0 — The value object (additive; nothing consumes it)

### Task 1: model.Scope value object

**Files:**
- Create: `model/scope.go`
- Test: `model/scope_test.go`

**Interfaces:**
- Consumes: `model.DefaultVaultID` (`model/vault.go:18`), `github.com/google/uuid`.
- Produces:
  - `type ScopeKind uint8` with `ScopeInvalid ScopeKind = 0`, `ScopeVault`, `ScopeOwner`, `ScopeAdmin`
  - `var ErrScopeInvalid error`
  - `type Scope struct{ ... }` (all fields unexported)
  - `func NewVaultScope(vaultID, actorID uuid.UUID) Scope`
  - `func NewOwnerScope(vaultID, ownerID uuid.UUID) Scope`
  - `func NewAdminScope(actorID uuid.UUID) Scope`
  - `func (s Scope) Kind() ScopeKind`
  - `func (s Scope) VaultID() uuid.UUID`
  - `func (s Scope) ActorID() uuid.UUID`
  - `func (s Scope) OwnerID() (uuid.UUID, bool)`
  - `func (s Scope) ResolvedVaultID() uuid.UUID`
  - `func (s Scope) Validate() error`
  - `func (s Scope) String() string`

- [ ] **Step 1: Write the failing test**

Create `model/scope_test.go`:

```go
package model

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVaultScope(t *testing.T) {
	vaultID := uuid.New()
	actorID := uuid.New()
	s := NewVaultScope(vaultID, actorID)

	assert.Equal(t, ScopeVault, s.Kind())
	assert.Equal(t, vaultID, s.VaultID())
	assert.Equal(t, actorID, s.ActorID())
	assert.NoError(t, s.Validate())

	owner, ok := s.OwnerID()
	assert.False(t, ok, "a vault scope has no owner")
	assert.Equal(t, uuid.Nil, owner)
}

func TestNewOwnerScope(t *testing.T) {
	vaultID := uuid.New()
	ownerID := uuid.New()
	s := NewOwnerScope(vaultID, ownerID)

	assert.Equal(t, ScopeOwner, s.Kind())
	assert.Equal(t, vaultID, s.VaultID(), "vault id is advisory on an owner scope")
	assert.Equal(t, ownerID, s.ActorID(), "the owner is the actor")
	assert.NoError(t, s.Validate())

	owner, ok := s.OwnerID()
	require.True(t, ok)
	assert.Equal(t, ownerID, owner)
}

func TestNewAdminScope(t *testing.T) {
	actorID := uuid.New()
	s := NewAdminScope(actorID)

	assert.Equal(t, ScopeAdmin, s.Kind())
	assert.Equal(t, actorID, s.ActorID())
	assert.Equal(t, uuid.Nil, s.VaultID())
	assert.NoError(t, s.Validate())

	_, ok := s.OwnerID()
	assert.False(t, ok)
}

func TestScopeResolvedVaultIDFallsBackToDefault(t *testing.T) {
	vaultID := uuid.New()
	assert.Equal(t, vaultID, NewVaultScope(vaultID, uuid.New()).ResolvedVaultID())
	assert.Equal(t, uuid.MustParse(DefaultVaultID), NewAdminScope(uuid.New()).ResolvedVaultID())
	assert.Equal(t, uuid.MustParse(DefaultVaultID), NewOwnerScope(uuid.Nil, uuid.New()).ResolvedVaultID())
}

func TestScopeStringNeverLeaksSecretMaterial(t *testing.T) {
	vaultID := uuid.New()
	ownerID := uuid.New()
	actorID := uuid.New()

	assert.Equal(t, "vault("+vaultID.String()+")", NewVaultScope(vaultID, actorID).String())
	assert.Equal(t, "owner("+ownerID.String()+")", NewOwnerScope(vaultID, ownerID).String())
	assert.Equal(t, "admin("+actorID.String()+")", NewAdminScope(actorID).String())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/... -run 'TestNewVaultScope|TestNewOwnerScope|TestNewAdminScope|TestScopeResolvedVaultIDFallsBackToDefault|TestScopeStringNeverLeaksSecretMaterial' -v`

Expected: FAIL to build — `model/scope_test.go:…: undefined: NewVaultScope`, `undefined: ScopeVault`, `undefined: NewOwnerScope`, `undefined: ScopeOwner`, `undefined: NewAdminScope`, `undefined: ScopeAdmin`.

- [ ] **Step 3: Implement the value object**

Create `model/scope.go`:

```go
package model

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ScopeKind identifies how a resource operation is authorized. Its zero value
// is deliberately invalid so an uninitialised Scope fails closed.
type ScopeKind uint8

const (
	ScopeInvalid ScopeKind = iota // Zero value. Repositories reject it.
	ScopeVault                    // Any member of the vault may act.
	ScopeOwner                    // Restricted to the owner. P1 only; retired in P2.
	ScopeAdmin                    // No predicate. Trusted internal callers only.
)

// ErrScopeInvalid is returned by Validate when a scope cannot authorize an
// operation. Reaching it from a request path is a programming error.
var ErrScopeInvalid = errors.New("model: invalid authorization scope")

// Scope is the authorization scope of a single resource operation. It replaces
// the *InVault and *ByOwner method pairs: the scope travels as a value instead
// of being encoded in the method name. Every field is unexported so the only
// way to build one is through a constructor that sets a valid kind.
type Scope struct {
	kind    ScopeKind
	vaultID uuid.UUID // Set for ScopeVault; advisory for ScopeOwner.
	ownerID uuid.UUID // Set for ScopeOwner only.
	actorID uuid.UUID // The acting principal, for audit. Never an access predicate.
}

// NewVaultScope authorizes an operation for any member of vaultID, acted on by
// actorID. The actor is recorded for audit and is never an access predicate.
func NewVaultScope(vaultID, actorID uuid.UUID) Scope {
	return Scope{kind: ScopeVault, vaultID: vaultID, actorID: actorID}
}

// NewOwnerScope restricts an operation to the resource owner. vaultID is
// advisory: owner-scoped queries never constrain vault_id, matching the
// pre-refactor behaviour of ReadByOwner and ListByUser.
func NewOwnerScope(vaultID, ownerID uuid.UUID) Scope {
	return Scope{kind: ScopeOwner, vaultID: vaultID, ownerID: ownerID, actorID: ownerID}
}

// NewAdminScope authorizes an operation with no access predicate. It is for
// trusted internal callers only: the vault cascade, backup/restore, and the
// rotation scheduler.
func NewAdminScope(actorID uuid.UUID) Scope {
	return Scope{kind: ScopeAdmin, actorID: actorID}
}

// Kind returns the scope kind.
func (s Scope) Kind() ScopeKind { return s.kind }

// VaultID returns the vault the scope refers to, or uuid.Nil when it has none.
func (s Scope) VaultID() uuid.UUID { return s.vaultID }

// ActorID returns the acting principal, for audit attribution.
func (s Scope) ActorID() uuid.UUID { return s.actorID }

// OwnerID returns the owner and true only when the scope is owner-scoped.
// It never overloads uuid.Nil as "no check".
func (s Scope) OwnerID() (uuid.UUID, bool) {
	if s.kind != ScopeOwner {
		return uuid.Nil, false
	}
	return s.ownerID, true
}

// ResolvedVaultID returns the scope's vault, falling back to the well-known
// default vault so legacy flat routes keep targeting it.
func (s Scope) ResolvedVaultID() uuid.UUID {
	if s.vaultID == uuid.Nil {
		return uuid.MustParse(DefaultVaultID)
	}
	return s.vaultID
}

// Validate reports whether the scope can authorize an operation. Every
// repository entry point calls it before building a query.
func (s Scope) Validate() error {
	switch s.kind {
	case ScopeVault:
		if s.vaultID == uuid.Nil {
			return fmt.Errorf("%w: vault scope requires a vault id", ErrScopeInvalid)
		}
		return nil
	case ScopeOwner:
		if s.ownerID == uuid.Nil {
			return fmt.Errorf("%w: owner scope requires an owner id", ErrScopeInvalid)
		}
		return nil
	case ScopeAdmin:
		return nil
	default:
		return fmt.Errorf("%w: uninitialised scope", ErrScopeInvalid)
	}
}

// String renders the scope for logs. It never contains secret material.
func (s Scope) String() string {
	switch s.kind {
	case ScopeVault:
		return "vault(" + s.vaultID.String() + ")"
	case ScopeOwner:
		return "owner(" + s.ownerID.String() + ")"
	case ScopeAdmin:
		return "admin(" + s.actorID.String() + ")"
	default:
		return "invalid"
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./model/... -v`

Expected: PASS — all `TestNewVaultScope`, `TestNewOwnerScope`, `TestNewAdminScope`, `TestScopeResolvedVaultIDFallsBackToDefault`, `TestScopeStringNeverLeaksSecretMaterial` pass, and the pre-existing `model` tests stay green.

- [ ] **Step 5: Commit**

```bash
git add model/scope.go model/scope_test.go
git commit -S -m "feat(model): add fail-closed Scope authorization value object"
```

---

### Task 2: Fail-closed regression tests for the zero value

**Files:**
- Modify: `model/scope_test.go` (append)

**Interfaces:**
- Consumes: `model.Scope`, `model.ScopeInvalid`, `model.ErrScopeInvalid`, `Scope.Validate`, `Scope.OwnerID` from Task 1.
- Produces: no new production symbols. Establishes `model/scope_test.go` as the **only** file permitted to write `model.Scope{}` composite literals.

- [ ] **Step 1: Write the failing test**

Append to `model/scope_test.go`:

```go
// TestScopeZeroValueFailsClosed pins the highest-severity invariant in the
// refactor: an uninitialised Scope must never be mistaken for admin. This file
// is the only place a Scope composite literal is permitted.
func TestScopeZeroValueFailsClosed(t *testing.T) {
	var zero Scope

	assert.Equal(t, ScopeInvalid, zero.Kind())
	assert.Equal(t, ScopeKind(0), ScopeInvalid, "ScopeInvalid must be the zero value")
	assert.NotEqual(t, ScopeAdmin, zero.Kind(), "the zero value must not be admin")

	err := zero.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScopeInvalid)
	assert.Equal(t, "invalid", zero.String())

	_, ok := zero.OwnerID()
	assert.False(t, ok)
}

func TestScopeStructLiteralWithoutKindFailsClosed(t *testing.T) {
	// A partially-populated literal — the exact shape a half-migrated call site
	// or a zero-valued mock return produces.
	s := Scope{vaultID: uuid.New(), actorID: uuid.New()}

	assert.Equal(t, ScopeInvalid, s.Kind())
	assert.ErrorIs(t, s.Validate(), ErrScopeInvalid)
}

func TestScopeValidateRejectsIncompleteConstructions(t *testing.T) {
	cases := []struct {
		name    string
		scope   Scope
		wantErr bool
	}{
		{"vault scope without vault id", NewVaultScope(uuid.Nil, uuid.New()), true},
		{"vault scope with vault id", NewVaultScope(uuid.New(), uuid.New()), false},
		{"owner scope without owner id", NewOwnerScope(uuid.New(), uuid.Nil), true},
		{"owner scope with owner id", NewOwnerScope(uuid.New(), uuid.New()), false},
		{"admin scope with nil actor", NewAdminScope(uuid.Nil), false},
		{"unknown kind", Scope{kind: ScopeKind(99)}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.scope.Validate()
			if c.wantErr {
				assert.ErrorIs(t, err, ErrScopeInvalid)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestScopeOwnerIDNeverOverloadsNil(t *testing.T) {
	// Regression pin for DeleteKeyInVault's documented "pass uuid.Nil to skip
	// the check". A vault or admin scope reports ok=false, not a Nil owner that
	// a caller could misread as "no check needed".
	for _, s := range []Scope{
		NewVaultScope(uuid.New(), uuid.New()),
		NewAdminScope(uuid.New()),
	} {
		id, ok := s.OwnerID()
		assert.False(t, ok, "scope %s must not report an owner", s)
		assert.Equal(t, uuid.Nil, id)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/... -run 'TestScopeZeroValueFailsClosed|TestScopeStructLiteralWithoutKindFailsClosed|TestScopeValidateRejectsIncompleteConstructions|TestScopeOwnerIDNeverOverloadsNil' -v`

Expected: PASS immediately if Task 1 was implemented correctly. If any subtest FAILs — in particular `ScopeInvalid must be the zero value` or `assert.ErrorIs(err, ErrScopeInvalid)` for `unknown kind` — Task 1's `Validate` is missing its `default:` branch or the `iota` block does not start at `ScopeInvalid`. Fix `model/scope.go` before proceeding; these tests must not be weakened.

- [ ] **Step 3: Verify the composite-literal ban holds repo-wide**

Run:

```bash
grep -rn "model\.Scope{" --include="*.go" . | grep -v "^./model/scope_test.go"
```

Expected: zero matches. (Inside `model/scope_test.go` the literals are written as `Scope{...}` without the package qualifier, so this grep is the correct repo-wide gate for every other package.)

- [ ] **Step 4: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS. Phase 0 is purely additive; nothing else in the tree references `model.Scope` yet.

- [ ] **Step 5: Commit**

```bash
git add model/scope_test.go
git commit -S -m "test(model): pin fail-closed behaviour of the zero-value Scope"
```

---

## Phase 1 — Predicate helper and scope-aware repository bodies (no interface changes)

### Task 3: Resolve the certificate `type`-column latent bug

The `certificates` table has no `type` column. `internal/db/db.go:434-452` defines it without one and `migrateSchema()` (line 691 onward) never adds it; `model.Certificate` (`model/certificate.go:12-30`) has no `Type` field and no API surface exposes one. Both non-test callers pass `""` (`internal/services/certificates/certificate_service.go:444` and `:553`), so the branch is dead code that would fail with `no such column: type` the moment it ran. **Resolution: drop the dead filter and the dead parameter.** While the column lists are open, also fix `ListByUser`, which neither selects `vault_id` nor sets `cert.VaultID`.

**Files:**
- Modify: `internal/repositories/certificate_repository.go:30` (interface `ListByUser`), `:38-39` (interface `ListInVault` + doc), `:393-399` (`ListByUser` doc), `:405-415` (`ListByUser` signature and filter), `:864-870` (`ListInVault` doc), `:876-886` (`ListInVault` signature and filter)
- Modify: `internal/services/certificates/certificate_service.go:444`, `:553`
- Test: `internal/repositories/certificate_vault_id_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `CertificateRepositoryInterface.ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Certificate, error)` — `certType` removed
  - `CertificateRepositoryInterface.ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Certificate, error)` — `certType` removed
  - `ListByUser` now populates `Certificate.VaultID` on every returned row.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/certificate_vault_id_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// TestCertificateRepository_ListByUser_PopulatesVaultID pins the fix for the
// copy-paste defect where ListByUser returned certificates with a zero VaultID.
func TestCertificateRepository_ListByUser_PopulatesVaultID(t *testing.T) {
	db := setupFullCertDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	userID := uuid.New()
	vaultID := uuid.New()
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      userID,
		VaultID:     vaultID,
		Name:        "listed-cert",
		Certificate: "PEM",
		PrivateKey:  "ENC",
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(ctx, cert))

	certs, err := repo.ListByUser(ctx, userID, nil)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, vaultID, certs[0].VaultID, "ListByUser must populate VaultID from the row")
}

// TestCertificateRepository_ListInVault_NoTypeFilter pins that the dead
// certType parameter is gone; the certificates table has no type column.
func TestCertificateRepository_ListInVault_NoTypeFilter(t *testing.T) {
	db := setupFullCertDB(t)
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	for _, name := range []string{"cert-a", "cert-b"} {
		require.NoError(t, repo.Create(ctx, &model.Certificate{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			VaultID:     vaultID,
			Name:        name,
			Certificate: "PEM",
			PrivateKey:  "ENC",
			CreatedAt:   time.Now().UTC(),
			Enabled:     true,
			RenewalDays: 30,
		}))
	}

	certs, err := repo.ListInVault(ctx, vaultID, nil)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run 'TestCertificateRepository_ListByUser_PopulatesVaultID|TestCertificateRepository_ListInVault_NoTypeFilter' -v`

Expected: FAIL to build — `not enough arguments in call to repo.ListByUser` / `repo.ListInVault` (the current signatures still take `certType string` between the id and `tags`).

- [ ] **Step 3: Drop the dead filter and fix the VaultID gap**

In `internal/repositories/certificate_repository.go`, change the two interface lines (30 and 39):

```go
	ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Certificate, error)
```

```go
	// ListInVault lists certificates scoped to a vault, optionally filtered by tags.
	ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Certificate, error)
```

Change `ListByUser` (declared at line 405). Replace its signature and the query/filter block — the current code is:

```go
func (r *CertificateRepository) ListByUser(ctx context.Context, userID uuid.UUID, certType string, tags []string) ([]model.Certificate, error) {
	...
		query := "SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before FROM certificates WHERE user_id = ? AND deleted_at IS NULL"
		args := []interface{}{userID.String()}

		if certType != "" {
			query += " AND type = ?"
			args = append(args, certType)
		}
```

with:

```go
func (r *CertificateRepository) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Certificate, error) {
	...
		query := "SELECT id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before FROM certificates WHERE user_id = ? AND deleted_at IS NULL"
		args := []interface{}{userID.String()}
```

Then update the row scan in `ListByUser` to read the new column: declare `var vaultIDStr string` alongside the existing `idStr, userIDStr` declarations, add `&vaultIDStr` to the `rows.Scan(...)` argument list immediately after `&userIDStr`, and after the existing `cert.UserID, err = uuid.Parse(userIDStr)` block add:

```go
			cert.VaultID, err = uuid.Parse(vaultIDStr)
			if err != nil {
				return fmt.Errorf("failed to parse vault ID: %w", err)
			}
```

Change `ListInVault` (declared at line 876) the same way — signature loses `certType string`, and delete its filter block:

```go
func (r *CertificateRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Certificate, error) {
	...
		query := "SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before FROM certificates WHERE vault_id = ? AND deleted_at IS NULL"
		args := []interface{}{vaultID.String()}
```

(`ListInVault` already back-fills `cert.VaultID = vaultID`; leave that line in place.) Remove the `certType` mentions from the doc comments at lines 38, 393, 399, 864 and 870.

Update both service call sites in `internal/services/certificates/certificate_service.go`:

```go
	return s.certRepo.ListByUser(ctx, userID, nil)     // line 444, ListCertificates
```

```go
	return s.certRepo.ListInVault(ctx, vaultID, nil)   // line 553, ListCertificatesInVault
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS for the two new tests. Test-only mocks and stubs that still declare the three-argument form will fail to compile — update each to the new signature: `internal/services/certificates/cert_soft_delete_test.go:51,99`, `internal/services/certificates/renewal_service_test.go:46,94`, `internal/services/certificates/certificate_service_extended_test.go:77,91,327,341`, `internal/repositories/certificate_key_id_test.go:138,141,172`, `internal/repositories/missing_coverage_test.go:1509-1525`, `internal/backup/backup_edge_test.go:58,68`, `api/soft_delete_extended_test.go:132,144`, `api/backup_item_test.go:653,667`. Re-run until the whole suite is green.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/certificate_repository.go internal/repositories/certificate_vault_id_test.go internal/services/certificates/certificate_service.go internal/services/certificates/cert_soft_delete_test.go internal/services/certificates/renewal_service_test.go internal/services/certificates/certificate_service_extended_test.go internal/repositories/certificate_key_id_test.go internal/repositories/missing_coverage_test.go internal/backup/backup_edge_test.go api/soft_delete_extended_test.go api/backup_item_test.go
git commit -S -m "fix(certificates): drop filter on nonexistent type column and populate VaultID in ListByUser"
```

---

### Task 4: scopePredicate helper

**Files:**
- Create: `internal/repositories/scope_predicate.go`
- Test: `internal/repositories/scope_predicate_test.go`

**Interfaces:**
- Consumes: `model.Scope`, `model.ScopeVault`, `model.ScopeOwner`, `model.ScopeAdmin`, `Scope.Validate`, `Scope.VaultID`, `Scope.OwnerID` (Task 1).
- Produces:
  - `var ErrInvalidScope = errors.New("invalid authorization scope")` in package `repositories`
  - `func scopePredicate(scope model.Scope) (string, []any, error)` — unexported; `ScopeVault` → `"vault_id = ?"`, `ScopeOwner` → `"user_id = ?"`, `ScopeAdmin` → `"1 = 1"` with no args.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/scope_predicate_test.go` (internal test — package `repositories`, because `scopePredicate` is unexported):

```go
package repositories

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestScopePredicateBindArity asserts every scope kind produces exactly as many
// "?" placeholders as bind arguments. A mismatch is a SQL injection or a
// runtime "sql: expected N arguments" panic waiting to happen.
func TestScopePredicateBindArity(t *testing.T) {
	cases := []struct {
		name  string
		scope model.Scope
	}{
		{"vault", model.NewVaultScope(uuid.New(), uuid.New())},
		{"owner", model.NewOwnerScope(uuid.New(), uuid.New())},
		{"admin", model.NewAdminScope(uuid.New())},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fragment, args, err := scopePredicate(c.scope)
			require.NoError(t, err)
			assert.Equal(t, strings.Count(fragment, "?"), len(args),
				"fragment %q has %d placeholders but %d bind args", fragment, strings.Count(fragment, "?"), len(args))
		})
	}
}

func TestScopePredicateFragments(t *testing.T) {
	vaultID := uuid.New()
	ownerID := uuid.New()

	fragment, args, err := scopePredicate(model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, "vault_id = ?", fragment)
	assert.Equal(t, []any{vaultID.String()}, args)

	fragment, args, err = scopePredicate(model.NewOwnerScope(uuid.New(), ownerID))
	require.NoError(t, err)
	assert.Equal(t, "user_id = ?", fragment)
	assert.Equal(t, []any{ownerID.String()}, args)

	fragment, args, err = scopePredicate(model.NewAdminScope(uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, "1 = 1", fragment)
	assert.Empty(t, args)
}

func TestScopePredicateRejectsInvalidScope(t *testing.T) {
	var zero model.Scope

	fragment, args, err := scopePredicate(zero)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidScope)
	assert.Empty(t, fragment, "no fragment may be returned for an invalid scope")
	assert.Nil(t, args)
}

func TestScopePredicateRejectsIncompleteVaultScope(t *testing.T) {
	_, _, err := scopePredicate(model.NewVaultScope(uuid.Nil, uuid.New()))
	assert.ErrorIs(t, err, ErrInvalidScope)
}

// TestScopePredicateNeverInterpolates guards the rule that no caller-supplied
// value is ever concatenated into the fragment.
func TestScopePredicateNeverInterpolates(t *testing.T) {
	vaultID := uuid.New()
	fragment, _, err := scopePredicate(model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.NotContains(t, fragment, vaultID.String())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run 'TestScopePredicate' -v`

Expected: FAIL to build — `internal/repositories/scope_predicate_test.go:…: undefined: scopePredicate` and `undefined: ErrInvalidScope`.

- [ ] **Step 3: Implement the predicate helper**

Create `internal/repositories/scope_predicate.go`:

```go
package repositories

import (
	"errors"
	"fmt"

	"rocketvault/model"
)

// ErrInvalidScope is returned when a repository receives a scope it cannot
// turn into a SQL predicate. It is a programming error, never reachable from a
// well-formed request, and surfaces to clients as a 500.
var ErrInvalidScope = errors.New("invalid authorization scope")

// scopePredicate turns an authorization scope into a SQL fragment plus its bind
// arguments. Each fragment is a compile-time constant; every caller-supplied
// value travels as a "?" placeholder, so nothing is ever interpolated.
//
// ScopeOwner deliberately does not constrain vault_id: ReadByOwner and
// ListByUser have never filtered by vault, and tightening that here would be a
// behavioral change smuggled into a refactor. P2 retires ScopeOwner entirely.
func scopePredicate(scope model.Scope) (string, []any, error) {
	if err := scope.Validate(); err != nil {
		return "", nil, fmt.Errorf("%w: %s", ErrInvalidScope, err.Error())
	}

	switch scope.Kind() {
	case model.ScopeVault:
		return "vault_id = ?", []any{scope.VaultID().String()}, nil
	case model.ScopeOwner:
		ownerID, ok := scope.OwnerID()
		if !ok {
			return "", nil, fmt.Errorf("%w: owner scope without an owner", ErrInvalidScope)
		}
		return "user_id = ?", []any{ownerID.String()}, nil
	case model.ScopeAdmin:
		return "1 = 1", nil, nil
	default:
		return "", nil, fmt.Errorf("%w: unknown scope kind %d", ErrInvalidScope, scope.Kind())
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./internal/repositories/... -run 'TestScopePredicate' -v && go test ./...`

Expected: PASS for all six `TestScopePredicate*` tests and the full suite.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/scope_predicate.go internal/repositories/scope_predicate_test.go
git commit -S -m "feat(repositories): add scopePredicate with bind-arity test"
```

---

### Task 5: Fix the missing vault_id in the secret Read and ReadByOwner SELECT lists

`SecretRepository.Read` (`internal/repositories/secret_repository.go:155-189`) and `ReadByOwner` (`:203-238`) do not select `vault_id`, so a secret fetched through `UpdateSecret` carries `VaultID == uuid.Nil`. Only the `*InVault` variants back-fill it from the query argument. Fix the SELECT lists **before** any scope-aware write exists.

**Files:**
- Modify: `internal/repositories/secret_repository.go:155-189` (`Read`), `:203-238` (`ReadByOwner`)
- Test: `internal/repositories/secret_repository_test.go` (append)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no signature changes. `Read` and `ReadByOwner` now populate `model.Secret.VaultID` from the row.

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/secret_repository_test.go`:

```go
// TestSecretRepository_Read_PopulatesVaultID pins the prerequisite fix from the
// P1 spec: Read and ReadByOwner must select vault_id, so a scope-aware write can
// never be handed an entity with a zero VaultID.
func TestSecretRepository_Read_PopulatesVaultID(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	vaultID := uuid.New()
	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      "vault-scoped-secret",
		Value:     "encrypted-data",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	byID, err := repo.Read(ctx, secret.ID)
	require.NoError(t, err)
	assert.Equal(t, vaultID, byID.VaultID, "Read must populate VaultID")

	byOwner, err := repo.ReadByOwner(ctx, secret.ID, ownerID)
	require.NoError(t, err)
	assert.Equal(t, vaultID, byOwner.VaultID, "ReadByOwner must populate VaultID")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestSecretRepository_Read_PopulatesVaultID -v`

Expected: FAIL — `Error: Not equal: expected: <the generated vault uuid>, actual: 00000000-0000-0000-0000-000000000000` with message `Read must populate VaultID`.

- [ ] **Step 3: Add vault_id to both SELECT lists**

In `internal/repositories/secret_repository.go`, `Read` currently reads:

```go
	var secret model.Secret
	var idStr, userIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE id = ? AND deleted_at IS NULL",
		id.String(),
	).Scan(&idStr, &userIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)
```

Replace with:

```go
	var secret model.Secret
	var idStr, userIDStr, vaultIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, vault_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE id = ? AND deleted_at IS NULL",
		id.String(),
	).Scan(&idStr, &userIDStr, &vaultIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)
```

and after the existing `secret.UserID, err = uuid.Parse(userIDStr)` block add:

```go
	secret.VaultID, err = uuid.Parse(vaultIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault ID: %w", err)
	}
```

Apply the identical three edits to `ReadByOwner` (line 203 onward), whose scan block uses `parseErr` rather than `err`:

```go
	var secret model.Secret
	var idStr, userIDStr, vaultIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, vault_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before FROM secrets WHERE id = ? AND user_id = ? AND deleted_at IS NULL",
		id.String(), userID.String(),
	).Scan(&idStr, &userIDStr, &vaultIDStr, &secret.Name, &secret.Value, &secret.Version, &secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled, &secret.ExpiresAt, &secret.NotBefore)
```

and after the existing `secret.UserID, parseErr = uuid.Parse(userIDStr)` block add:

```go
	secret.VaultID, parseErr = uuid.Parse(vaultIDStr)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse vault ID: %w", parseErr)
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS. Any test whose in-memory schema lacks `vault_id` on `secrets` will fail with `no such column: vault_id` — the shared helpers (`setupSecretTestDB` in `secret_repository_test.go:26`, `setupTagDB` in `missing_coverage_test.go:122`, `internal_coverage_test.go:47`, `setupContentTypeTestDB` in `secret_repository_content_type_test.go:26`) already declare it; add `vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'` to any that do not.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/secret_repository.go internal/repositories/secret_repository_test.go
git commit -S -m "fix(secrets): select vault_id in Read and ReadByOwner"
```

---
### Task 6: Scope-aware SecretRepository bodies with the old methods as shims

**Files:**
- Modify: `internal/repositories/secret_repository.go` — add `SecretFilter` + `ReadScoped`/`UpdateScoped`/`ListScoped`; rewrite `Read` (`:155-189`), `ReadByOwner` (`:203-238`), `Update` (`:251-286`), `ListByUser` (`:473-543`), `ListByUserIncludeDeleted` (`:557-626`), `ReadInVault` (`:665-703`), `UpdateInVault` (`:717-752`), `ListInVault` (`:766-839`), `ListInVaultIncludeDeleted` (`:853-925`) as shims
- Test: `internal/repositories/secret_scope_test.go`

**Interfaces:**
- Consumes: `scopePredicate(model.Scope) (string, []any, error)`, `ErrInvalidScope` (Task 4); `model.NewVaultScope`, `model.NewOwnerScope`, `model.NewAdminScope`, `Scope.Kind`, `Scope.ActorID` (Task 1); `Read`/`ReadByOwner` now select `vault_id` (Task 5).
- Produces, on the concrete `*SecretRepository` (**not** on the interface yet):
  - `type SecretFilter struct { Tags []string; IncludeDeleted bool; OnlyDeleted bool }`
  - `func (r *SecretRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error)`
  - `func (r *SecretRepository) UpdateScoped(ctx context.Context, secret *model.Secret, scope model.Scope) error`
  - `func (r *SecretRepository) ListScoped(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/secret_scope_test.go` (internal test — package `repositories` — because the new methods are not on the interface until Phase 2):

```go
package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// newScopeTestSecretRepo builds a concrete *SecretRepository over an in-memory
// SQLite database carrying the full secrets schema.
func newScopeTestSecretRepo(t *testing.T) *SecretRepository {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
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
	);
	CREATE TABLE IF NOT EXISTS secret_tags (
		secret_id TEXT NOT NULL,
		tag       TEXT NOT NULL,
		PRIMARY KEY (secret_id, tag)
	)`)
	require.NoError(t, err)

	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &SecretRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: &logging.Logger{Logger: l}}
}

func seedScopeSecret(t *testing.T, repo *SecretRepository, ownerID, vaultID uuid.UUID, name string) *model.Secret {
	t.Helper()
	s := &model.Secret{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      name,
		Value:     "encrypted-" + name,
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
	}
	require.NoError(t, repo.Create(context.Background(), s))
	return s
}

func TestSecretReadScoped(t *testing.T) {
	repo := newScopeTestSecretRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	secret := seedScopeSecret(t, repo, ownerID, vaultA, "alpha")

	t.Run("vault scope matches", func(t *testing.T) {
		got, err := repo.ReadScoped(ctx, secret.ID, model.NewVaultScope(vaultA, otherUser))
		require.NoError(t, err)
		assert.Equal(t, secret.ID, got.ID)
		assert.Equal(t, vaultA, got.VaultID)
	})
	t.Run("wrong vault denies", func(t *testing.T) {
		_, err := repo.ReadScoped(ctx, secret.ID, model.NewVaultScope(vaultB, otherUser))
		assert.Error(t, err)
	})
	t.Run("owner scope matches", func(t *testing.T) {
		got, err := repo.ReadScoped(ctx, secret.ID, model.NewOwnerScope(vaultA, ownerID))
		require.NoError(t, err)
		assert.Equal(t, secret.ID, got.ID)
	})
	t.Run("wrong owner denies", func(t *testing.T) {
		_, err := repo.ReadScoped(ctx, secret.ID, model.NewOwnerScope(vaultA, otherUser))
		assert.Error(t, err)
	})
	t.Run("admin scope sees everything", func(t *testing.T) {
		got, err := repo.ReadScoped(ctx, secret.ID, model.NewAdminScope(otherUser))
		require.NoError(t, err)
		assert.Equal(t, secret.ID, got.ID)
	})
}

func TestSecretUpdateScoped(t *testing.T) {
	repo := newScopeTestSecretRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	secret := seedScopeSecret(t, repo, ownerID, vaultA, "beta")

	t.Run("vault member may write", func(t *testing.T) {
		updated := *secret
		updated.Name = "beta-renamed"
		updated.Version = 2
		require.NoError(t, repo.UpdateScoped(ctx, &updated, model.NewVaultScope(vaultA, otherUser)))

		got, err := repo.ReadScoped(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
		require.NoError(t, err)
		assert.Equal(t, "beta-renamed", got.Name)
	})
	t.Run("wrong vault write is rejected", func(t *testing.T) {
		updated := *secret
		updated.Name = "should-not-land"
		err := repo.UpdateScoped(ctx, &updated, model.NewVaultScope(vaultB, otherUser))
		require.Error(t, err)

		got, readErr := repo.ReadScoped(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
		require.NoError(t, readErr)
		assert.NotEqual(t, "should-not-land", got.Name)
	})
	t.Run("predicate comes from the scope not the entity", func(t *testing.T) {
		// The entity claims vaultA, but the scope says vaultB: the write must fail.
		updated := *secret
		updated.VaultID = vaultA
		updated.Name = "entity-wins"
		assert.Error(t, repo.UpdateScoped(ctx, &updated, model.NewVaultScope(vaultB, otherUser)))
	})
}

func TestSecretListScoped(t *testing.T) {
	repo := newScopeTestSecretRepo(t)
	ctx := context.Background()

	ownerA, ownerB := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	live := seedScopeSecret(t, repo, ownerA, vaultA, "live")
	gone := seedScopeSecret(t, repo, ownerA, vaultA, "gone")
	seedScopeSecret(t, repo, ownerB, vaultB, "other-vault")
	require.NoError(t, repo.SoftDelete(ctx, gone.ID))

	t.Run("vault scope excludes deleted by default", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), SecretFilter{})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, live.ID, got[0].ID)
		assert.Equal(t, vaultA, got[0].VaultID)
	})
	t.Run("include deleted", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), SecretFilter{IncludeDeleted: true})
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})
	t.Run("only deleted filters in SQL", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), SecretFilter{OnlyDeleted: true})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, gone.ID, got[0].ID)
		assert.NotNil(t, got[0].DeletedAt)
	})
	t.Run("owner scope ignores vault", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewOwnerScope(vaultB, ownerA), SecretFilter{})
		require.NoError(t, err)
		assert.Len(t, got, 1, "owner scope must not constrain vault_id")
	})
	t.Run("admin scope sees every vault", func(t *testing.T) {
		got, err := repo.ListScoped(ctx, model.NewAdminScope(uuid.Nil), SecretFilter{})
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run 'TestSecretReadScoped|TestSecretUpdateScoped|TestSecretListScoped' -v`

Expected: FAIL to build — `repo.ReadScoped undefined (type *SecretRepository has no field or method ReadScoped)`, likewise `UpdateScoped`, `ListScoped`, and `undefined: SecretFilter`.

- [ ] **Step 3: Add the canonical bodies and rewrite the old methods as shims**

Add `"strings"` to the import block of `internal/repositories/secret_repository.go` (it is not imported today).

Add, directly below the `SecretRepositoryInterface` declaration:

```go
// SecretFilter narrows a scoped secret listing. Tags is accepted for
// compatibility; tag filtering lives in TagService.
type SecretFilter struct {
	Tags           []string
	IncludeDeleted bool
	OnlyDeleted    bool
}

// scanSecretRow scans one secrets row in the canonical column order used by
// every scope-aware query.
func scanSecretRow(scan func(dest ...any) error) (model.Secret, error) {
	var secret model.Secret
	var idStr, userIDStr, vaultIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	if err := scan(&idStr, &userIDStr, &vaultIDStr, &secret.Name, &secret.Value, &secret.Version,
		&secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled,
		&secret.ExpiresAt, &secret.NotBefore); err != nil {
		return secret, err
	}

	var err error
	if secret.ID, err = uuid.Parse(idStr); err != nil {
		return secret, fmt.Errorf("failed to parse secret ID: %w", err)
	}
	if secret.UserID, err = uuid.Parse(userIDStr); err != nil {
		return secret, fmt.Errorf("failed to parse user ID: %w", err)
	}
	if secret.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return secret, fmt.Errorf("failed to parse vault ID: %w", err)
	}

	secret.DeletedAt = deletedAt
	secret.PurgeProtection = purgeProtection
	return secret, nil
}

// secretColumns is the canonical SELECT list shared by every scoped query.
const secretColumns = "id, user_id, vault_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before"
```

Add the three canonical bodies:

```go
// ReadScoped retrieves a secret by ID, authorized by scope. The scoped read is
// the access check: a row outside the scope is indistinguishable from a row
// that does not exist.
func (r *SecretRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	query := "SELECT " + secretColumns + " FROM secrets WHERE id = ? AND " + predicate + " AND deleted_at IS NULL"
	queryArgs := append([]any{id.String()}, args...)

	secret, err := scanSecretRow(r.db.QueryRowContext(ctx, query, queryArgs...).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		if scope.Kind() == model.ScopeAdmin {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("secret not found or access denied")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}
	return &secret, nil
}

// UpdateScoped updates a secret, authorized by scope. The predicate is built
// from the scope argument, never from the entity, so a caller cannot widen its
// own authorization by mutating secret.VaultID or secret.UserID.
//
// This method does not emit audit rows: audit attribution belongs to the
// caller (service layer), which knows the acting principal from the request,
// not just the scope it was handed. UpdateSecretScoped already logs its own
// audit row after calling this, for every error path and on success — logging
// here too would duplicate every scoped update into two audit_logs rows.
func (r *SecretRepository) UpdateScoped(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"scope":     scope.String(),
		"version":   secret.Version,
	}).Debug("Updating secret in database")

	query := "UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ?, enabled = ?, expires_at = ?, not_before = ? WHERE id = ? AND " + predicate
	execArgs := append([]any{
		secret.Name, secret.Value, secret.Version, secret.ContentType,
		secret.Enabled, secret.ExpiresAt, secret.NotBefore, secret.ID.String(),
	}, args...)

	result, err := r.db.ExecContext(ctx, query, execArgs...)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("secret not found")
	}

	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"scope":     scope.String(),
		"version":   secret.Version,
	}).Debug("Secret updated successfully")
	return nil
}

// ListScoped lists secrets authorized by scope and narrowed by filter. The
// soft-delete predicate is applied in SQL rather than by discarding rows in Go.
func (r *SecretRepository) ListScoped(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	conditions := []string{predicate}
	switch {
	case filter.OnlyDeleted:
		conditions = append(conditions, "deleted_at IS NOT NULL")
	case filter.IncludeDeleted:
		// No deleted_at constraint.
	default:
		conditions = append(conditions, "deleted_at IS NULL")
	}

	query := "SELECT " + secretColumns + " FROM secrets WHERE " +
		strings.Join(conditions, " AND ") + " ORDER BY name ASC"

	var secretList []model.Secret
	err = r.executeWithMetrics("list_secrets_scoped", func() error {
		rows, queryErr := r.db.QueryContext(ctx, query, args...)
		if queryErr != nil {
			return fmt.Errorf("failed to query secrets: %w", queryErr)
		}
		defer rows.Close()

		secretList = make([]model.Secret, 0, 50)
		for rows.Next() {
			secret, scanErr := scanSecretRow(rows.Scan)
			if scanErr != nil {
				return fmt.Errorf("failed to scan secret: %w", scanErr)
			}
			secretList = append(secretList, secret)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return fmt.Errorf("row iteration error: %w", rowsErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"scope":        scope.String(),
		"secret_count": len(secretList),
	}).Debug("Secrets listed successfully")

	return secretList, nil
}
```

Replace the nine old method bodies with shims (keep the existing doc comments, add a `// Deprecated: shim over …Scoped; removed in Phase 6.` line to each):

```go
func (r *SecretRepository) Read(ctx context.Context, id uuid.UUID) (*model.Secret, error) {
	return r.ReadScoped(ctx, id, model.NewAdminScope(uuid.Nil))
}

func (r *SecretRepository) ReadByOwner(ctx context.Context, id, userID uuid.UUID) (*model.Secret, error) {
	return r.ReadScoped(ctx, id, model.NewOwnerScope(uuid.Nil, userID))
}

func (r *SecretRepository) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Secret, error) {
	return r.ReadScoped(ctx, id, model.NewVaultScope(vaultID, uuid.Nil))
}

func (r *SecretRepository) Update(ctx context.Context, secret *model.Secret) error {
	return r.UpdateScoped(ctx, secret, model.NewOwnerScope(secret.VaultID, secret.UserID))
}

func (r *SecretRepository) UpdateInVault(ctx context.Context, secret *model.Secret) error {
	return r.UpdateScoped(ctx, secret, model.NewVaultScope(secret.VaultID, secret.UserID))
}

func (r *SecretRepository) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	return r.ListScoped(ctx, model.NewOwnerScope(uuid.Nil, userID), SecretFilter{Tags: tags})
}

func (r *SecretRepository) ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	return r.ListScoped(ctx, model.NewOwnerScope(uuid.Nil, userID), SecretFilter{Tags: tags, IncludeDeleted: true})
}

func (r *SecretRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	return r.ListScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), SecretFilter{Tags: tags})
}

func (r *SecretRepository) ListInVaultIncludeDeleted(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	return r.ListScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), SecretFilter{Tags: tags, IncludeDeleted: true})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS. The three new tests pass and the entire pre-existing suite stays green — that is the equivalence proof for this phase. Two behavioural notes to check if something fails: `Read` via the admin shim keeps the message `"secret not found"` while the owner/vault shims keep `"secret not found or access denied"`; and `UpdateScoped`/`ListScoped` no longer call `r.log.LogAuditError`/`LogAuditInfo` at all — any pre-existing test that asserted on a repository-level audit call for `Update` or `UpdateInVault` (e.g. via a fake `AuditPersister`) must be updated to assert **no** audit call from the repository, since attribution now lives solely in the service layer that calls it (matching the pattern already established for `KeyRepository.Update` — see `internal/repositories/secret_repository.go`'s current `UpdateInVault`, which has no audit calls for the same reason).

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/secret_repository.go internal/repositories/secret_scope_test.go
git commit -S -m "refactor(secrets): make scope-aware Read/Update/List the canonical repository bodies"
```

---

### Task 7: Scope-aware KeyRepository bodies with the old methods as shims

**Files:**
- Modify: `internal/repositories/key_repository.go` — add `KeyFilter` + `ReadScoped`/`UpdateScoped`/`ListScoped`; rewrite `Read` (`:174-217`), `Update` (`:287-326`), `ListByUser` (`:397-485`), `ListInVault` (`:845-930`), `ReadInVault` (`:943-984`) as shims
- Test: `internal/repositories/key_scope_test.go`

**Interfaces:**
- Consumes: `scopePredicate`, `ErrInvalidScope` (Task 4); `model.NewVaultScope`, `model.NewOwnerScope`, `model.NewAdminScope` (Task 1).
- Produces, on the concrete `*KeyRepository`:
  - `type KeyFilter struct { Type string; Tags []string; IncludeDeleted bool; OnlyDeleted bool }`
  - `func (r *KeyRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error)`
  - `func (r *KeyRepository) UpdateScoped(ctx context.Context, key *model.Key, scope model.Scope) error`
  - `func (r *KeyRepository) ListScoped(ctx context.Context, scope model.Scope, filter KeyFilter) ([]model.Key, error)`

Unlike secrets, `KeyFilter` keeps `Type`: the `keys` table really does have a `type` column (`internal/db/db.go:397`).

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/key_scope_test.go` (internal test, package `repositories`):

```go
package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newScopeTestKeyRepo(t *testing.T) *KeyRepository {
	t.Helper()
	dsn := "file:keyscope_" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
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
	);
	CREATE TABLE IF NOT EXISTS key_tags (
		key_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (key_id, tag)
	)`)
	require.NoError(t, err)

	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &KeyRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: &logging.Logger{Logger: l}}
}

func seedScopeKey(t *testing.T, repo *KeyRepository, ownerID, vaultID uuid.UUID, name, keyType string) *model.Key {
	t.Helper()
	k := &model.Key{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      name,
		Type:      keyType,
		Value:     "encrypted-" + name,
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
		Bits:      2048,
	}
	require.NoError(t, repo.Create(context.Background(), k))
	return k
}

func TestKeyReadScoped(t *testing.T) {
	repo := newScopeTestKeyRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	key := seedScopeKey(t, repo, ownerID, vaultA, "rsa-a", model.KeyTypeRSA)

	got, err := repo.ReadScoped(ctx, key.ID, model.NewVaultScope(vaultA, otherUser))
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
	assert.Equal(t, vaultA, got.VaultID)

	_, err = repo.ReadScoped(ctx, key.ID, model.NewVaultScope(vaultB, otherUser))
	assert.Error(t, err)

	_, err = repo.ReadScoped(ctx, key.ID, model.NewOwnerScope(vaultA, otherUser))
	assert.Error(t, err)

	got, err = repo.ReadScoped(ctx, key.ID, model.NewAdminScope(otherUser))
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
}

func TestKeyUpdateScoped(t *testing.T) {
	repo := newScopeTestKeyRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	key := seedScopeKey(t, repo, ownerID, vaultA, "rsa-b", model.KeyTypeRSA)

	updated := *key
	updated.Name = "rsa-b-renamed"
	require.NoError(t, repo.UpdateScoped(ctx, &updated, model.NewVaultScope(vaultA, otherUser)))

	got, err := repo.ReadScoped(ctx, key.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "rsa-b-renamed", got.Name)

	blocked := *key
	blocked.Name = "should-not-land"
	assert.Error(t, repo.UpdateScoped(ctx, &blocked, model.NewVaultScope(vaultB, otherUser)))
}

func TestKeyListScoped(t *testing.T) {
	repo := newScopeTestKeyRepo(t)
	ctx := context.Background()

	ownerA, ownerB := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	seedScopeKey(t, repo, ownerA, vaultA, "rsa-1", model.KeyTypeRSA)
	seedScopeKey(t, repo, ownerA, vaultA, "ec-1", model.KeyTypeECDSA)
	seedScopeKey(t, repo, ownerB, vaultB, "rsa-2", model.KeyTypeRSA)

	inVault, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, inVault, 2)

	typed, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), KeyFilter{Type: model.KeyTypeRSA})
	require.NoError(t, err)
	require.Len(t, typed, 1)
	assert.Equal(t, model.KeyTypeRSA, typed[0].Type)

	byOwner, err := repo.ListScoped(ctx, model.NewOwnerScope(vaultB, ownerA), KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, byOwner, 2, "owner scope must not constrain vault_id")

	all, err := repo.ListScoped(ctx, model.NewAdminScope(uuid.Nil), KeyFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 3)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run 'TestKeyReadScoped|TestKeyUpdateScoped|TestKeyListScoped' -v`

Expected: FAIL to build — `repo.ReadScoped undefined (type *KeyRepository has no field or method ReadScoped)`, likewise `UpdateScoped`, `ListScoped`, and `undefined: KeyFilter`.

- [ ] **Step 3: Add the canonical bodies and rewrite the old methods as shims**

Add to `internal/repositories/key_repository.go`, below the `KeyRepositoryInterface` declaration:

```go
// KeyFilter narrows a scoped key listing.
type KeyFilter struct {
	Type           string // Empty means every type. The keys table really has this column.
	Tags           []string
	IncludeDeleted bool
	OnlyDeleted    bool
}

// keyColumns is the canonical SELECT list shared by every scoped key query.
const keyColumns = "id, user_id, vault_id, name, value, type, revoked, created_at, enabled, expires_at, not_before, bits, curve, updated_at"

// scanKeyRow scans one keys row in the canonical column order.
func scanKeyRow(scan func(dest ...any) error) (model.Key, error) {
	var key model.Key
	var idStr, userIDStr, vaultIDStr string

	if err := scan(&idStr, &userIDStr, &vaultIDStr, &key.Name, &key.Value, &key.Type, &key.Revoked,
		&key.CreatedAt, &key.Enabled, &key.ExpiresAt, &key.NotBefore, &key.Bits, &key.Curve, &key.UpdatedAt); err != nil {
		return key, err
	}

	var err error
	if key.ID, err = uuid.Parse(idStr); err != nil {
		return key, fmt.Errorf("failed to parse key ID: %w", err)
	}
	if key.UserID, err = uuid.Parse(userIDStr); err != nil {
		return key, fmt.Errorf("failed to parse user ID: %w", err)
	}
	if key.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return key, fmt.Errorf("failed to parse vault ID: %w", err)
	}
	return key, nil
}
```

Add the three canonical bodies:

```go
// ReadScoped retrieves a key by ID, authorized by scope. Tags are loaded via
// TagRepository, matching the behaviour of the methods it replaces.
func (r *KeyRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	query := "SELECT " + keyColumns + " FROM keys WHERE id = ? AND " + predicate + " AND deleted_at IS NULL"
	queryArgs := append([]any{id.String()}, args...)

	key, err := scanKeyRow(r.db.QueryRowContext(ctx, query, queryArgs...).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		if scope.Kind() == model.ScopeAdmin {
			return nil, fmt.Errorf("key not found")
		}
		return nil, fmt.Errorf("key not found or access denied")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query key: %w", err)
	}

	tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
	key.Tags, err = tagRepo.GetTags(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}
	return &key, nil
}

// UpdateScoped updates a key, authorized by scope. The predicate is built from
// the scope argument, never from the entity.
//
// This method does not emit audit rows: audit attribution belongs to the
// caller (service layer), which knows the acting principal from the request.
// UpdateKeyScoped already logs its own audit row after calling this, for
// every error path and on success — logging here too would duplicate every
// scoped update into two audit_logs rows.
func (r *KeyRepository) UpdateScoped(ctx context.Context, key *model.Key, scope model.Scope) error {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return err
	}

	return r.executeWithMetrics("update_key_scoped", func() error {
		now := time.Now().UTC()
		key.UpdatedAt = &now

		query := "UPDATE keys SET name = ?, value = ?, revoked = ?, created_at = ?, enabled = ?, expires_at = ?, not_before = ?, bits = ?, curve = ?, updated_at = ? WHERE id = ? AND " + predicate
		execArgs := append([]any{
			key.Name, key.Value, key.Revoked, key.CreatedAt, key.Enabled,
			key.ExpiresAt, key.NotBefore, key.Bits, key.Curve, now, key.ID.String(),
		}, args...)

		result, execErr := r.db.ExecContext(ctx, query, execArgs...)
		if execErr != nil {
			return fmt.Errorf("failed to update key: %w", execErr)
		}

		rowsAffected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("failed to get rows affected: %w", rowsErr)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("key not found")
		}

		logrus.WithFields(logrus.Fields{
			"key_id": key.ID.String(),
			"scope":  scope.String(),
		}).Debug("Key updated successfully")
		return nil
	})
}

// ListScoped lists keys authorized by scope and narrowed by filter.
func (r *KeyRepository) ListScoped(ctx context.Context, scope model.Scope, filter KeyFilter) ([]model.Key, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	conditions := []string{predicate}
	switch {
	case filter.OnlyDeleted:
		conditions = append(conditions, "deleted_at IS NOT NULL")
	case filter.IncludeDeleted:
		// No deleted_at constraint.
	default:
		conditions = append(conditions, "deleted_at IS NULL")
	}

	if filter.Type != "" {
		conditions = append(conditions, "type = ?")
		args = append(args, filter.Type)
	}
	if len(filter.Tags) > 0 {
		placeholders := strings.Repeat(",?", len(filter.Tags))[1:]
		conditions = append(conditions, fmt.Sprintf("id IN (SELECT key_id FROM key_tags WHERE tag IN (%s))", placeholders))
		for _, tag := range filter.Tags {
			args = append(args, tag)
		}
	}

	query := "SELECT " + keyColumns + " FROM keys WHERE " +
		strings.Join(conditions, " AND ") + " ORDER BY created_at DESC"

	var keyList []model.Key
	err = r.executeWithMetrics("list_keys_scoped", func() error {
		rows, queryErr := r.db.QueryContext(ctx, query, args...)
		if queryErr != nil {
			return fmt.Errorf("failed to query keys: %w", queryErr)
		}
		defer rows.Close()

		tagRepo := db.NewTagRepository[model.Key](r.db, "key_tags", "key_id")
		keyList = make([]model.Key, 0, 50)
		for rows.Next() {
			key, scanErr := scanKeyRow(rows.Scan)
			if scanErr != nil {
				return fmt.Errorf("failed to scan key: %w", scanErr)
			}
			key.Tags, scanErr = tagRepo.GetTags(ctx, key.ID)
			if scanErr != nil {
				return fmt.Errorf("failed to read tags for key: %w", scanErr)
			}
			keyList = append(keyList, key)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return fmt.Errorf("row iteration error: %w", rowsErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithField("count", len(keyList)).Debug("Keys listed successfully")
	return keyList, nil
}
```

Replace the five old bodies with shims (keep their doc comments, add `// Deprecated: shim over …Scoped; removed in Phase 6.`):

```go
func (r *KeyRepository) Read(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	return r.ReadScoped(ctx, id, model.NewAdminScope(uuid.Nil))
}

func (r *KeyRepository) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Key, error) {
	return r.ReadScoped(ctx, id, model.NewVaultScope(vaultID, uuid.Nil))
}

func (r *KeyRepository) Update(ctx context.Context, key *model.Key) error {
	return r.UpdateScoped(ctx, key, model.NewAdminScope(key.UserID))
}

func (r *KeyRepository) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	scope := model.NewAdminScope(uuid.Nil)
	if userID != nil {
		scope = model.NewOwnerScope(uuid.Nil, *userID)
	}
	return r.ListScoped(ctx, scope, KeyFilter{Type: keyType, Tags: tags})
}

func (r *KeyRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	return r.ListScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), KeyFilter{Type: keyType, Tags: tags})
}
```

`Update`'s shim uses an admin scope because the legacy `UPDATE keys … WHERE id = ?` had no ownership predicate at all; using an owner scope here would tighten behaviour mid-refactor. Ownership for the legacy path is still enforced in `keyService.UpdateKey` (`internal/services/keys/key_service.go:535`).

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS, including the three new tests and the whole existing suite. Note `ReadScoped` now selects `vault_id` and populates `key.VaultID` on the plain `Read` path too, which previously already parsed it (`key_repository.go:203-206`) — behaviour is unchanged there. Also: `ReadScoped`/`UpdateScoped`/`ListScoped` call no `r.log.LogAuditError`/`LogAuditInfo` at all, matching the existing `KeyRepository.Update` convention (P0 already removed its own audit calls for the identical reason — the repository cannot know the acting principal, only the row's owner). Any pre-existing test asserting a repository-level audit call for these methods must be updated to assert none; attribution lives solely in the service-layer callers added in Task 19.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/key_repository.go internal/repositories/key_scope_test.go
git commit -S -m "refactor(keys): make scope-aware Read/Update/List the canonical repository bodies"
```

---
### Task 8: Scope-aware CertificateRepository bodies with the old methods as shims

**Files:**
- Modify: `internal/repositories/certificate_repository.go` — add `CertificateFilter` + `ReadScoped`/`UpdateScoped`/`ListScoped`; rewrite `Read` (`:169-214`), `Update` (`:226-293`), `ListByUser` (`:405`), `ListInVault` (`:876`), `ReadInVault` (`:982`) as shims
- Test: `internal/repositories/certificate_scope_test.go`

**Interfaces:**
- Consumes: `scopePredicate`, `ErrInvalidScope` (Task 4); `model.NewVaultScope`, `model.NewOwnerScope`, `model.NewAdminScope` (Task 1); the `certType`-free `ListByUser`/`ListInVault` signatures (Task 3).
- Produces, on the concrete `*CertificateRepository`:
  - `type CertificateFilter struct { Tags []string; IncludeDeleted bool; OnlyDeleted bool }`
  - `func (r *CertificateRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error)`
  - `func (r *CertificateRepository) UpdateScoped(ctx context.Context, cert *model.Certificate, scope model.Scope) error`
  - `func (r *CertificateRepository) ListScoped(ctx context.Context, scope model.Scope, filter CertificateFilter) ([]model.Certificate, error)`

`CertificateFilter` has no `Type` field: Task 3 established that the `certificates` table has no `type` column.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/certificate_scope_test.go` (internal test, package `repositories`):

```go
package repositories

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newScopeTestCertRepo(t *testing.T) *CertificateRepository {
	t.Helper()
	dsn := "file:certscope_" + uuid.NewString() + "?mode=memory&cache=shared"
	db, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS certificates (
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
		expires_at DATETIME,
		auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
		renewal_days INTEGER NOT NULL DEFAULT 30,
		key_id TEXT NOT NULL DEFAULT '',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		not_before TIMESTAMP NULL
	);
	CREATE TABLE IF NOT EXISTS certificate_tags (
		certificate_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (certificate_id, tag)
	)`)
	require.NoError(t, err)

	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &CertificateRepository{db: rvdb.NewConn(db, rvdb.SQLite), log: &logging.Logger{Logger: l}}
}

func seedScopeCert(t *testing.T, repo *CertificateRepository, ownerID, vaultID uuid.UUID, name string) *model.Certificate {
	t.Helper()
	c := &model.Certificate{
		ID:          uuid.New(),
		UserID:      ownerID,
		VaultID:     vaultID,
		KeyID:       uuid.New(),
		Name:        name,
		Certificate: "PEM-" + name,
		PrivateKey:  "ENC-" + name,
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(context.Background(), c))
	return c
}

func TestCertificateReadScoped(t *testing.T) {
	repo := newScopeTestCertRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	cert := seedScopeCert(t, repo, ownerID, vaultA, "cert-a")

	got, err := repo.ReadScoped(ctx, cert.ID, model.NewVaultScope(vaultA, otherUser))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)
	assert.Equal(t, vaultA, got.VaultID)

	_, err = repo.ReadScoped(ctx, cert.ID, model.NewVaultScope(vaultB, otherUser))
	assert.Error(t, err)

	_, err = repo.ReadScoped(ctx, cert.ID, model.NewOwnerScope(vaultA, otherUser))
	assert.Error(t, err)

	got, err = repo.ReadScoped(ctx, cert.ID, model.NewOwnerScope(vaultA, ownerID))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)

	got, err = repo.ReadScoped(ctx, cert.ID, model.NewAdminScope(otherUser))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)
}

func TestCertificateUpdateScoped(t *testing.T) {
	repo := newScopeTestCertRepo(t)
	ctx := context.Background()

	ownerID, otherUser := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	cert := seedScopeCert(t, repo, ownerID, vaultA, "cert-b")

	updated := *cert
	updated.Name = "cert-b-renamed"
	require.NoError(t, repo.UpdateScoped(ctx, &updated, model.NewVaultScope(vaultA, otherUser)))

	got, err := repo.ReadScoped(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "cert-b-renamed", got.Name)

	blocked := *cert
	blocked.Name = "should-not-land"
	assert.Error(t, repo.UpdateScoped(ctx, &blocked, model.NewVaultScope(vaultB, otherUser)))
}

func TestCertificateListScoped(t *testing.T) {
	repo := newScopeTestCertRepo(t)
	ctx := context.Background()

	ownerA, ownerB := uuid.New(), uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()
	seedScopeCert(t, repo, ownerA, vaultA, "cert-1")
	gone := seedScopeCert(t, repo, ownerA, vaultA, "cert-2")
	seedScopeCert(t, repo, ownerB, vaultB, "cert-3")
	require.NoError(t, repo.SoftDelete(ctx, gone.ID))

	live, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, live, 1)
	assert.Equal(t, vaultA, live[0].VaultID)

	deleted, err := repo.ListScoped(ctx, model.NewVaultScope(vaultA, ownerB), CertificateFilter{OnlyDeleted: true})
	require.NoError(t, err)
	require.Len(t, deleted, 1)
	assert.Equal(t, gone.ID, deleted[0].ID)

	byOwner, err := repo.ListScoped(ctx, model.NewOwnerScope(vaultB, ownerA), CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, byOwner, 1, "owner scope must not constrain vault_id")

	all, err := repo.ListScoped(ctx, model.NewAdminScope(uuid.Nil), CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 2)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run 'TestCertificateReadScoped|TestCertificateUpdateScoped|TestCertificateListScoped' -v`

Expected: FAIL to build — `repo.ReadScoped undefined (type *CertificateRepository has no field or method ReadScoped)`, likewise `UpdateScoped`, `ListScoped`, and `undefined: CertificateFilter`.

- [ ] **Step 3: Add the canonical bodies and rewrite the old methods as shims**

Add to `internal/repositories/certificate_repository.go`, below the `CertificateRepositoryInterface` declaration:

```go
// CertificateFilter narrows a scoped certificate listing. There is no Type
// field: the certificates table has no type column.
type CertificateFilter struct {
	Tags           []string
	IncludeDeleted bool
	OnlyDeleted    bool
}

// certificateColumns is the canonical SELECT list shared by every scoped query.
const certificateColumns = "id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before"

// scanCertificateRow scans one certificates row in the canonical column order.
func scanCertificateRow(scan func(dest ...any) error) (model.Certificate, error) {
	var cert model.Certificate
	var idStr, userIDStr, vaultIDStr string
	var keyIDStr sql.NullString

	if err := scan(&idStr, &userIDStr, &vaultIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey,
		&cert.CreatedAt, &cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr,
		&cert.Enabled, &cert.NotBefore); err != nil {
		return cert, err
	}

	var err error
	if cert.ID, err = uuid.Parse(idStr); err != nil {
		return cert, fmt.Errorf("failed to parse certificate ID: %w", err)
	}
	if cert.UserID, err = uuid.Parse(userIDStr); err != nil {
		return cert, fmt.Errorf("failed to parse user ID: %w", err)
	}
	if cert.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return cert, fmt.Errorf("failed to parse vault ID: %w", err)
	}
	if keyIDStr.Valid && keyIDStr.String != "" {
		if cert.KeyID, err = uuid.Parse(keyIDStr.String); err != nil {
			return cert, fmt.Errorf("failed to parse key ID: %w", err)
		}
	}
	return cert, nil
}
```

Add the three canonical bodies:

```go
// ReadScoped retrieves a certificate by ID, authorized by scope.
func (r *CertificateRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	query := "SELECT " + certificateColumns + " FROM certificates WHERE id = ? AND " + predicate + " AND deleted_at IS NULL"
	queryArgs := append([]any{id.String()}, args...)

	cert, err := scanCertificateRow(r.db.QueryRowContext(ctx, query, queryArgs...).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		if scope.Kind() == model.ScopeAdmin {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("certificate not found or access denied")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate: %w", err)
	}

	tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
	cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}
	return &cert, nil
}

// UpdateScoped updates a certificate, authorized by scope. The predicate is
// built from the scope argument, never from the entity.
//
// This method does not emit audit rows: audit attribution belongs to the
// caller (service layer), which knows the acting principal from the request.
// UpdateCertificateScoped already logs its own audit row after calling this,
// for every error path and on success — logging here too would duplicate
// every scoped update into two audit_logs rows.
func (r *CertificateRepository) UpdateScoped(ctx context.Context, cert *model.Certificate, scope model.Scope) error {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return err
	}

	return r.executeWithMetrics("update_certificate_scoped", func() error {
		tx, txErr := r.db.BeginTx(ctx, nil)
		if txErr != nil {
			return fmt.Errorf("failed to begin transaction: %w", txErr)
		}
		defer tx.Rollback()

		query := "UPDATE certificates SET name = ?, certificate = ?, private_key = ?, created_at = ?, expires_at = ?, auto_renew = ?, renewal_days = ?, enabled = ?, not_before = ? WHERE id = ? AND " + predicate
		execArgs := append([]any{
			cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt, cert.ExpiresAt,
			cert.AutoRenew, cert.RenewalDays, cert.Enabled, cert.NotBefore, cert.ID.String(),
		}, args...)

		result, execErr := tx.ExecContext(ctx, query, execArgs...)
		if execErr != nil {
			return fmt.Errorf("failed to update certificate: %w", execErr)
		}

		rowsAffected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("failed to get rows affected: %w", rowsErr)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("certificate not found")
		}

		if len(cert.Tags) > 0 {
			if _, delErr := tx.ExecContext(ctx, "DELETE FROM certificate_tags WHERE certificate_id = ?", cert.ID.String()); delErr != nil {
				return fmt.Errorf("failed to delete existing tags: %w", delErr)
			}
			tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
			if tagErr := tagRepo.AddTags(ctx, cert.ID, cert.Tags); tagErr != nil {
				return fmt.Errorf("failed to add tags: %w", tagErr)
			}
		}

		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("failed to commit transaction: %w", commitErr)
		}

		logrus.WithFields(logrus.Fields{
			"certificate_id": cert.ID.String(),
			"scope":          scope.String(),
		}).Debug("Certificate updated successfully")
		return nil
	})
}

// ListScoped lists certificates authorized by scope and narrowed by filter.
func (r *CertificateRepository) ListScoped(ctx context.Context, scope model.Scope, filter CertificateFilter) ([]model.Certificate, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	conditions := []string{predicate}
	switch {
	case filter.OnlyDeleted:
		conditions = append(conditions, "deleted_at IS NOT NULL")
	case filter.IncludeDeleted:
		// No deleted_at constraint.
	default:
		conditions = append(conditions, "deleted_at IS NULL")
	}

	if len(filter.Tags) > 0 {
		placeholders := strings.Repeat(",?", len(filter.Tags))[1:]
		conditions = append(conditions, fmt.Sprintf("id IN (SELECT certificate_id FROM certificate_tags WHERE tag IN (%s))", placeholders))
		for _, tag := range filter.Tags {
			args = append(args, tag)
		}
	}

	query := "SELECT " + certificateColumns + " FROM certificates WHERE " +
		strings.Join(conditions, " AND ") + " ORDER BY created_at DESC"

	var certList []model.Certificate
	err = r.executeWithMetrics("list_certificates_scoped", func() error {
		rows, queryErr := r.db.QueryContext(ctx, query, args...)
		if queryErr != nil {
			return fmt.Errorf("failed to query certificates: %w", queryErr)
		}
		defer rows.Close()

		tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
		certList = make([]model.Certificate, 0, 50)
		for rows.Next() {
			cert, scanErr := scanCertificateRow(rows.Scan)
			if scanErr != nil {
				return fmt.Errorf("failed to scan certificate: %w", scanErr)
			}
			cert.Tags, scanErr = tagRepo.GetTags(ctx, cert.ID)
			if scanErr != nil {
				return fmt.Errorf("failed to read tags for certificate: %w", scanErr)
			}
			certList = append(certList, cert)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return fmt.Errorf("row iteration error: %w", rowsErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithField("count", len(certList)).Debug("Certificates listed successfully")
	return certList, nil
}
```

Replace the five old bodies with shims (keep their doc comments, add `// Deprecated: shim over …Scoped; removed in Phase 6.`):

```go
func (r *CertificateRepository) Read(ctx context.Context, id uuid.UUID) (*model.Certificate, error) {
	return r.ReadScoped(ctx, id, model.NewAdminScope(uuid.Nil))
}

func (r *CertificateRepository) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Certificate, error) {
	return r.ReadScoped(ctx, id, model.NewVaultScope(vaultID, uuid.Nil))
}

func (r *CertificateRepository) Update(ctx context.Context, cert *model.Certificate) error {
	return r.UpdateScoped(ctx, cert, model.NewAdminScope(cert.UserID))
}

func (r *CertificateRepository) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Certificate, error) {
	return r.ListScoped(ctx, model.NewOwnerScope(uuid.Nil, userID), CertificateFilter{Tags: tags})
}

func (r *CertificateRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Certificate, error) {
	return r.ListScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), CertificateFilter{Tags: tags})
}
```

`Update`'s shim uses an admin scope because the legacy `UPDATE certificates … WHERE id = ?` had no ownership predicate; ownership for the legacy path stays in `certificateService.UpdateCertificate`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS, including the three new tests and the whole existing suite. `ReadScoped`/`UpdateScoped`/`ListScoped` call no `r.log.LogAuditError`/`LogAuditInfo` at all, matching the same convention established for `SecretRepository` (Task 6) and `KeyRepository` (Task 7) — attribution lives solely in the service-layer callers added in Task 21.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/certificate_repository.go internal/repositories/certificate_scope_test.go
git commit -S -m "refactor(certificates): make scope-aware Read/Update/List the canonical repository bodies"
```

---

### Task 9: model.Scope{} rejection test per scope-aware repository method

Spec §8 and §9 require a rejection test for **every** repository method that takes a scope: nine methods across three repositories. Assert `ErrInvalidScope`, not rows.

**Files:**
- Create: `internal/repositories/scope_rejection_test.go`

**Interfaces:**
- Consumes: `ErrInvalidScope`, `scopePredicate` (Task 4); `newScopeTestSecretRepo`, `seedScopeSecret`, `SecretFilter` (Task 6); `newScopeTestKeyRepo`, `seedScopeKey`, `KeyFilter` (Task 7); `newScopeTestCertRepo`, `seedScopeCert`, `CertificateFilter` (Task 8).
- Produces: no production symbols.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/scope_rejection_test.go` (internal test, package `repositories`):

```go
package repositories

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestZeroScopeRejectedByEveryRepositoryMethod is the fail-closed gate for the
// refactor's highest-severity risk: a partially-migrated call site or a
// zero-valued mock return producing model.Scope{} must never read or write a
// row. Every scope-aware repository method belongs in this test.
func TestZeroScopeRejectedByEveryRepositoryMethod(t *testing.T) {
	ctx := context.Background()
	var zero model.Scope

	t.Run("SecretRepository", func(t *testing.T) {
		repo := newScopeTestSecretRepo(t)
		secret := seedScopeSecret(t, repo, uuid.New(), uuid.New(), "zero-scope")

		t.Run("ReadScoped", func(t *testing.T) {
			got, err := repo.ReadScoped(ctx, secret.ID, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Nil(t, got, "no row may be returned for an invalid scope")
		})
		t.Run("UpdateScoped", func(t *testing.T) {
			mutated := *secret
			mutated.Name = "zero-scope-write"
			err := repo.UpdateScoped(ctx, &mutated, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)

			after, readErr := repo.ReadScoped(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
			require.NoError(t, readErr)
			assert.Equal(t, "zero-scope", after.Name, "the row must be untouched")
		})
		t.Run("ListScoped", func(t *testing.T) {
			rows, err := repo.ListScoped(ctx, zero, SecretFilter{})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Empty(t, rows)
		})
	})

	t.Run("KeyRepository", func(t *testing.T) {
		repo := newScopeTestKeyRepo(t)
		key := seedScopeKey(t, repo, uuid.New(), uuid.New(), "zero-scope-key", model.KeyTypeRSA)

		t.Run("ReadScoped", func(t *testing.T) {
			got, err := repo.ReadScoped(ctx, key.ID, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Nil(t, got)
		})
		t.Run("UpdateScoped", func(t *testing.T) {
			mutated := *key
			mutated.Name = "zero-scope-write"
			err := repo.UpdateScoped(ctx, &mutated, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)

			after, readErr := repo.ReadScoped(ctx, key.ID, model.NewAdminScope(uuid.Nil))
			require.NoError(t, readErr)
			assert.Equal(t, "zero-scope-key", after.Name)
		})
		t.Run("ListScoped", func(t *testing.T) {
			rows, err := repo.ListScoped(ctx, zero, KeyFilter{})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Empty(t, rows)
		})
	})

	t.Run("CertificateRepository", func(t *testing.T) {
		repo := newScopeTestCertRepo(t)
		cert := seedScopeCert(t, repo, uuid.New(), uuid.New(), "zero-scope-cert")

		t.Run("ReadScoped", func(t *testing.T) {
			got, err := repo.ReadScoped(ctx, cert.ID, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Nil(t, got)
		})
		t.Run("UpdateScoped", func(t *testing.T) {
			mutated := *cert
			mutated.Name = "zero-scope-write"
			err := repo.UpdateScoped(ctx, &mutated, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)

			after, readErr := repo.ReadScoped(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
			require.NoError(t, readErr)
			assert.Equal(t, "zero-scope-cert", after.Name)
		})
		t.Run("ListScoped", func(t *testing.T) {
			rows, err := repo.ListScoped(ctx, zero, CertificateFilter{})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Empty(t, rows)
		})
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestZeroScopeRejectedByEveryRepositoryMethod -v`

Expected: PASS immediately if Tasks 6-8 call `scopePredicate` first in every method. Any subtest that FAILs identifies a method that builds its query before validating — most likely one that forgot `if err != nil { return … }` after the `scopePredicate` call, or one that wraps the predicate call inside `executeWithMetrics` so the error is swallowed. Fix the repository, not the test.

- [ ] **Step 3: Verify the ban on entity-derived predicates**

Run:

```bash
grep -n "scopePredicate" internal/repositories/*.go
```

Expected: exactly ten matches — the definition in `scope_predicate.go` plus one call at the top of each of the nine scope-aware methods. Confirm by eye that no `…Scoped` body reads `secret.VaultID`, `key.UserID`, `cert.VaultID` or similar to build a WHERE clause; the entity is only ever a SET-clause source.

- [ ] **Step 4: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/scope_rejection_test.go
git commit -S -m "test(repositories): reject the zero-value Scope in every scope-aware method"
```

---
## Phase 2 — Publish the new methods on the repository interfaces (additive)

### Task 10: SecretRepositoryInterface gains the scope-aware trio

**Files:**
- Modify: `internal/repositories/secret_repository.go:19-49` (interface)
- Modify: `internal/services/retry/retry_repository_wrapper.go` (append three wrapped methods)
- Test: `internal/repositories/secret_scope_iface_test.go`

**Interfaces:**
- Consumes: `(*SecretRepository).ReadScoped/UpdateScoped/ListScoped`, `SecretFilter` (Task 6).
- Produces, on `repositories.SecretRepositoryInterface`:
  - `ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error)`
  - `UpdateScoped(ctx context.Context, secret *model.Secret, scope model.Scope) error`
  - `ListScoped(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error)`
- Also produces the same three methods on `*retry.RetryRepositoryWrapper`.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/secret_scope_iface_test.go` (external test — package `repositories_test` — so it exercises the interface exactly as service callers will):

```go
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// TestSecretRepositoryInterfaceExposesScopedMethods pins that service callers
// can reach the scope-aware API through the interface, not just the struct.
func TestSecretRepositoryInterfaceExposesScopedMethods(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	var repo repositories.SecretRepositoryInterface = repositories.NewSecretRepository(
		rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID, vaultID := uuid.New(), uuid.New()
	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      "iface-secret",
		Value:     "encrypted",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	got, err := repo.ReadScoped(ctx, secret.ID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)

	got.Name = "iface-secret-renamed"
	got.Version = 2
	require.NoError(t, repo.UpdateScoped(ctx, got, model.NewVaultScope(vaultID, ownerID)))

	list, err := repo.ListScoped(ctx, model.NewVaultScope(vaultID, ownerID), repositories.SecretFilter{})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "iface-secret-renamed", list[0].Name)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestSecretRepositoryInterfaceExposesScopedMethods -v`

Expected: FAIL to build — `repo.ReadScoped undefined (type repositories.SecretRepositoryInterface has no field or method ReadScoped)`.

- [ ] **Step 3: Add the methods to the interface and the retry wrapper**

In `internal/repositories/secret_repository.go`, add to `SecretRepositoryInterface` (immediately after the `Create` line, before the deprecated `Read`):

```go
	// ReadScoped fetches a secret authorized by scope. Canonical; the Read,
	// ReadByOwner and ReadInVault methods below are shims over it.
	ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error)
	// UpdateScoped updates a secret authorized by scope. The predicate comes
	// from the scope argument, never from the entity.
	UpdateScoped(ctx context.Context, secret *model.Secret, scope model.Scope) error
	// ListScoped lists secrets authorized by scope and narrowed by filter.
	ListScoped(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error)
```

Append to `internal/services/retry/retry_repository_wrapper.go` (it already imports `repositories` and `model`; no new imports needed):

```go
// ReadScoped wraps the ReadScoped operation with retry logic.
func (r *RetryRepositoryWrapper) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	var result *model.Secret
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ReadScoped(ctx, id, scope)
		return err
	})

	return result, retryErr
}

// UpdateScoped wraps the UpdateScoped operation with retry logic.
func (r *RetryRepositoryWrapper) UpdateScoped(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	return r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return r.baseRepo.UpdateScoped(ctx, secret, scope)
	})
}

// ListScoped wraps the ListScoped operation with retry logic.
func (r *RetryRepositoryWrapper) ListScoped(ctx context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	var result []model.Secret
	var err error

	retryErr := r.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = r.baseRepo.ListScoped(ctx, scope, filter)
		return err
	})

	return result, retryErr
}
```

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. `mockery` (config landed in P0) regenerates the `SecretRepositoryInterface` mock with the three new methods. Any mock still hand-written will fail to compile with `cannot use … (variable of type *MockX) as repositories.SecretRepositoryInterface value … missing method ReadScoped`. The known hand-written implementations of this interface are `internal/testutils/mocks.go:109` (`MockSecretRepository`), `internal/services/retry/retry_wrappers_test.go:318` (`MockSecretRepo`, with a compile-time assertion at `:461`) and `api/backup_item_test.go:288` (`mockSecretRepo`, func-field stub). For any that survived P0, add:

```go
func (m *MockSecretRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepository) UpdateScoped(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	args := m.Called(ctx, secret, scope)
	return args.Error(0)
}

func (m *MockSecretRepository) ListScoped(ctx context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}
```

Run `go test ./...` — not `go vet` — until green: `cmd/testutils.MockServiceContainer` type-asserts at runtime, so a missing method shows up only as a test panic.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/secret_repository.go internal/repositories/secret_scope_iface_test.go internal/services/retry/retry_repository_wrapper.go
git commit -S -m "feat(repositories): publish scope-aware secret methods on the interface"
```

---

### Task 11: KeyRepositoryInterface gains the scope-aware trio

**Files:**
- Modify: `internal/repositories/key_repository.go:24-49` (interface)
- Test: `internal/repositories/key_scope_iface_test.go`

**Interfaces:**
- Consumes: `(*KeyRepository).ReadScoped/UpdateScoped/ListScoped`, `KeyFilter` (Task 7).
- Produces, on `repositories.KeyRepositoryInterface`:
  - `ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error)`
  - `UpdateScoped(ctx context.Context, key *model.Key, scope model.Scope) error`
  - `ListScoped(ctx context.Context, scope model.Scope, filter KeyFilter) ([]model.Key, error)`

There is no retry wrapper for `KeyRepositoryInterface`, so this task has no decorator work.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/key_scope_iface_test.go` (external test, package `repositories_test`):

```go
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestKeyRepositoryInterfaceExposesScopedMethods(t *testing.T) {
	db := setupFullKeyDB(t)
	var repo repositories.KeyRepositoryInterface = repositories.NewKeyRepository(
		rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID, vaultID := uuid.New(), uuid.New()
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      "iface-key",
		Type:      model.KeyTypeRSA,
		Value:     "encrypted",
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
		Bits:      2048,
	}
	require.NoError(t, repo.Create(ctx, key))

	got, err := repo.ReadScoped(ctx, key.ID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)

	got.Name = "iface-key-renamed"
	require.NoError(t, repo.UpdateScoped(ctx, got, model.NewVaultScope(vaultID, ownerID)))

	list, err := repo.ListScoped(ctx, model.NewVaultScope(vaultID, ownerID), repositories.KeyFilter{Type: model.KeyTypeRSA})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "iface-key-renamed", list[0].Name)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestKeyRepositoryInterfaceExposesScopedMethods -v`

Expected: FAIL to build — `repo.ReadScoped undefined (type repositories.KeyRepositoryInterface has no field or method ReadScoped)`.

- [ ] **Step 3: Add the methods to the interface**

In `internal/repositories/key_repository.go`, add to `KeyRepositoryInterface` immediately after the embedded `db.Repository[model.Key]` line:

```go
	// ReadScoped fetches a key authorized by scope. Canonical; Read and
	// ReadInVault are shims over it.
	ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error)
	// UpdateScoped updates a key authorized by scope. The predicate comes from
	// the scope argument, never from the entity.
	UpdateScoped(ctx context.Context, key *model.Key, scope model.Scope) error
	// ListScoped lists keys authorized by scope and narrowed by filter.
	ListScoped(ctx context.Context, scope model.Scope, filter KeyFilter) ([]model.Key, error)
```

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Six hand-written implementations of this interface exist if P0's mockery adoption did not replace them: `internal/services/keys/key_soft_delete_test.go:18` (`mockKeyRepository`), `internal/services/keys/wrap_key_test.go:47` (`mockKeyRepoForWrap`), `internal/services/keys/key_service_extended_test.go:1075` (`mockKeyRepoForExtendedCrypto`), `internal/services/certificates/cert_soft_delete_test.go:127` (`mockKeyRepo`), `internal/signing/signing_test.go:58` (`mockKeyRepo`, plain stub), `api/backup_item_test.go:574` (`mockKeyRepo`, func-field stub). For each testify-style mock that survived, add:

```go
func (m *mockKeyRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *mockKeyRepository) UpdateScoped(ctx context.Context, key *model.Key, scope model.Scope) error {
	args := m.Called(ctx, key, scope)
	return args.Error(0)
}

func (m *mockKeyRepository) ListScoped(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}
```

For the two plain-stub mocks (`internal/signing/signing_test.go:58`, `api/backup_item_test.go:574`), return zero values matching their existing style rather than introducing testify.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/key_repository.go internal/repositories/key_scope_iface_test.go
git commit -S -m "feat(repositories): publish scope-aware key methods on the interface"
```

---

### Task 12: CertificateRepositoryInterface gains the scope-aware trio

**Files:**
- Modify: `internal/repositories/certificate_repository.go:24-45` (interface)
- Test: `internal/repositories/certificate_scope_iface_test.go`

**Interfaces:**
- Consumes: `(*CertificateRepository).ReadScoped/UpdateScoped/ListScoped`, `CertificateFilter` (Task 8).
- Produces, on `repositories.CertificateRepositoryInterface`:
  - `ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error)`
  - `UpdateScoped(ctx context.Context, cert *model.Certificate, scope model.Scope) error`
  - `ListScoped(ctx context.Context, scope model.Scope, filter CertificateFilter) ([]model.Certificate, error)`

There is no retry wrapper for `CertificateRepositoryInterface`, so this task has no decorator work.

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/certificate_scope_iface_test.go` (external test, package `repositories_test`):

```go
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestCertificateRepositoryInterfaceExposesScopedMethods(t *testing.T) {
	db := setupFullCertDB(t)
	var repo repositories.CertificateRepositoryInterface = repositories.NewCertificateRepository(
		rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID, vaultID := uuid.New(), uuid.New()
	cert := &model.Certificate{
		ID:          uuid.New(),
		UserID:      ownerID,
		VaultID:     vaultID,
		KeyID:       uuid.New(),
		Name:        "iface-cert",
		Certificate: "PEM",
		PrivateKey:  "ENC",
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
		RenewalDays: 30,
	}
	require.NoError(t, repo.Create(ctx, cert))

	got, err := repo.ReadScoped(ctx, cert.ID, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, cert.ID, got.ID)

	got.Name = "iface-cert-renamed"
	require.NoError(t, repo.UpdateScoped(ctx, got, model.NewVaultScope(vaultID, ownerID)))

	list, err := repo.ListScoped(ctx, model.NewVaultScope(vaultID, ownerID), repositories.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "iface-cert-renamed", list[0].Name)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestCertificateRepositoryInterfaceExposesScopedMethods -v`

Expected: FAIL to build — `repo.ReadScoped undefined (type repositories.CertificateRepositoryInterface has no field or method ReadScoped)`.

- [ ] **Step 3: Add the methods to the interface**

In `internal/repositories/certificate_repository.go`, add to `CertificateRepositoryInterface` immediately after the `Create` line:

```go
	// ReadScoped fetches a certificate authorized by scope. Canonical; Read and
	// ReadInVault are shims over it.
	ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error)
	// UpdateScoped updates a certificate authorized by scope. The predicate
	// comes from the scope argument, never from the entity.
	UpdateScoped(ctx context.Context, cert *model.Certificate, scope model.Scope) error
	// ListScoped lists certificates authorized by scope and narrowed by filter.
	ListScoped(ctx context.Context, scope model.Scope, filter CertificateFilter) ([]model.Certificate, error)
```

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Three hand-written implementations exist if P0 did not replace them: `internal/services/certificates/cert_soft_delete_test.go:23` (`mockCertRepository`), `internal/services/certificates/renewal_service_test.go:20` (`mockCertRepoForRenewal`), `api/backup_item_test.go:631` (`mockCertRepo`, func-field stub). For each testify-style mock that survived, add:

```go
func (m *mockCertRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Certificate), args.Error(1)
}

func (m *mockCertRepository) UpdateScoped(ctx context.Context, cert *model.Certificate, scope model.Scope) error {
	args := m.Called(ctx, cert, scope)
	return args.Error(0)
}

func (m *mockCertRepository) ListScoped(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}
```

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/certificate_repository.go internal/repositories/certificate_scope_iface_test.go
git commit -S -m "feat(repositories): publish scope-aware certificate methods on the interface"
```

---
## Phase 3 — Services, one resource per commit

### Task 13: applySecretUpdate pure function

The ~70 lines of field-merge logic are duplicated between `UpdateSecret` (`internal/services/secrets/secret_service.go:316-352`) and `UpdateSecretInVault` (`:419-447`). Extract them into a function that performs no I/O and no authorization, so it is unit-testable without a database — neither original was.

**Files:**
- Create: `internal/services/secrets/secret_update.go`
- Test: `internal/services/secrets/secret_update_test.go`

**Interfaces:**
- Consumes: `model.Secret`, `UpdateSecretRequest`, `validateContentType` (`secret_service.go:67`).
- Produces: `func applySecretUpdate(current *model.Secret, req UpdateSecretRequest, encrypt func(string) (string, error)) (*model.Secret, error)` — unexported, package `secrets`.

- [ ] **Step 1: Write the failing test**

Create `internal/services/secrets/secret_update_test.go`:

```go
package secrets

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func baseSecret() *model.Secret {
	return &model.Secret{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		VaultID:     uuid.New(),
		Name:        "original",
		Value:       "ENC(original)",
		Version:     3,
		ContentType: "text/plain",
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
	}
}

func passthroughEncrypt(v string) (string, error) { return "ENC(" + v + ")", nil }

func TestApplySecretUpdateIncrementsVersionAndLeavesOriginalUntouched(t *testing.T) {
	current := baseSecret()
	snapshot := *current

	updated, err := applySecretUpdate(current, UpdateSecretRequest{}, passthroughEncrypt)
	require.NoError(t, err)

	assert.Equal(t, snapshot.Version+1, updated.Version)
	assert.Equal(t, snapshot, *current, "applySecretUpdate must not mutate its input")
	assert.NotSame(t, current, updated)
}

func TestApplySecretUpdateAppliesEveryOptionalField(t *testing.T) {
	current := baseSecret()
	name := "renamed"
	value := "fresh"
	contentType := "application/json"
	enabled := false
	expires := time.Now().Add(24 * time.Hour).UTC()
	notBefore := time.Now().Add(time.Hour).UTC()

	updated, err := applySecretUpdate(current, UpdateSecretRequest{
		Name:        &name,
		Value:       &value,
		ContentType: &contentType,
		Enabled:     &enabled,
		ExpiresAt:   &expires,
		NotBefore:   &notBefore,
	}, passthroughEncrypt)
	require.NoError(t, err)

	assert.Equal(t, "renamed", updated.Name)
	assert.Equal(t, "ENC(fresh)", updated.Value)
	assert.Equal(t, "application/json", updated.ContentType)
	assert.False(t, updated.Enabled)
	assert.Equal(t, expires, *updated.ExpiresAt)
	assert.Equal(t, notBefore, *updated.NotBefore)
}

func TestApplySecretUpdateNilFieldsMeanNoChange(t *testing.T) {
	current := baseSecret()

	updated, err := applySecretUpdate(current, UpdateSecretRequest{}, passthroughEncrypt)
	require.NoError(t, err)

	assert.Equal(t, current.Name, updated.Name)
	assert.Equal(t, current.Value, updated.Value)
	assert.Equal(t, current.ContentType, updated.ContentType)
	assert.Equal(t, current.Enabled, updated.Enabled)
	assert.Nil(t, updated.ExpiresAt)
	assert.Nil(t, updated.NotBefore)
}

func TestApplySecretUpdateRejectsUnsupportedContentType(t *testing.T) {
	current := baseSecret()
	bad := "application/x-not-allowed"

	_, err := applySecretUpdate(current, UpdateSecretRequest{ContentType: &bad}, passthroughEncrypt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported content type")
}

func TestApplySecretUpdatePropagatesEncryptionFailure(t *testing.T) {
	current := baseSecret()
	value := "fresh"
	boom := errors.New("cipher unavailable")

	_, err := applySecretUpdate(current, UpdateSecretRequest{Value: &value},
		func(string) (string, error) { return "", boom })
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

func TestApplySecretUpdateRejectsNilSecret(t *testing.T) {
	_, err := applySecretUpdate(nil, UpdateSecretRequest{}, passthroughEncrypt)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run TestApplySecretUpdate -v`

Expected: FAIL to build — `internal/services/secrets/secret_update_test.go:…: undefined: applySecretUpdate`.

- [ ] **Step 3: Implement the pure function**

Create `internal/services/secrets/secret_update.go`:

```go
package secrets

import (
	"fmt"

	"rocketvault/model"
)

// applySecretUpdate merges an update request onto the current secret and
// returns a new entity. It performs no I/O and no authorization: authorization
// lives entirely in the scope passed to the repository, and encryption is
// injected so the function is unit-testable without a database.
//
// The returned secret always carries an incremented version. Nil request
// fields mean "no change".
func applySecretUpdate(current *model.Secret, req UpdateSecretRequest,
	encrypt func(string) (string, error)) (*model.Secret, error) {
	if current == nil {
		return nil, fmt.Errorf("cannot apply an update to a nil secret")
	}

	updated := *current
	updated.Version++

	if req.ContentType != nil {
		if err := validateContentType(*req.ContentType); err != nil {
			return nil, err
		}
		updated.ContentType = *req.ContentType
	}
	if req.Name != nil {
		updated.Name = *req.Name
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		updated.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		updated.NotBefore = req.NotBefore
	}
	if req.Value != nil {
		encrypted, err := encrypt(*req.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt updated secret: %w", err)
		}
		updated.Value = encrypted
	}

	return &updated, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./internal/services/secrets/... -run TestApplySecretUpdate -v && go test ./...`

Expected: PASS for all six `TestApplySecretUpdate*` tests and the full suite.

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/secret_update.go internal/services/secrets/secret_update_test.go
git commit -S -m "refactor(secrets): extract applySecretUpdate as a pure function"
```

---

### Task 14: SecretService read/list/delete on a scope

**Files:**
- Modify: `internal/services/secrets/secret_service.go:115-149` (interface), `:488-519` (`GetSecret`), `:532-567` (`ListSecrets`), `:580-613` (`DeleteSecret`), `:618-648` (`GetSecretInVault`), `:652-683` (`ListSecretsInVault`), `:687-714` (`DeleteSecretInVault`), `:718-732` (`ListDeletedSecretsInVault`)
- Modify: `internal/cache/cache_integration.go` (add pass-through decorators — **caching stays disabled** on the unified read)
- Modify: `internal/services/retry/retry_secret_service.go` (add wrapped methods)
- Test: `internal/services/secrets/secret_scope_service_test.go`

**Interfaces:**
- Consumes: `repositories.SecretRepositoryInterface.ReadScoped/ListScoped`, `repositories.SecretFilter` (Task 10); `model.NewVaultScope`, `model.NewOwnerScope`, `Scope.ActorID` (Task 1).
- Produces, on `secrets.SecretService`:
  - `GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error)`
  - `ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error)`
  - `DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error`
  - `ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/services/secrets/secret_scope_service_test.go`:

```go
package secrets

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestGetSecretScopedPassesTheScopeStraightToTheRepository(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	vaultID := uuid.New()
	actorID := uuid.New()
	scope := model.NewVaultScope(vaultID, actorID)

	repo.On("ReadScoped", ctx, secretID, scope).Return(&model.Secret{
		ID: secretID, VaultID: vaultID, Name: "s", Value: "ENC(v)", Enabled: true,
	}, nil).Once()

	got, err := svc.GetSecretScoped(ctx, secretID, scope)
	require.NoError(t, err)
	assert.Equal(t, secretID, got.ID)
	assert.Equal(t, "v", got.Value, "the service decrypts before returning")
	repo.AssertExpectations(t)
}

func TestGetSecretScopedMapsNotFoundToErrSecretNotFound(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("ReadScoped", ctx, mock.Anything, scope).
		Return(nil, assert.AnError).Once()

	_, err := svc.GetSecretScoped(ctx, uuid.New(), scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestListDeletedSecretsScopedFiltersInSQLNotInGo(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("ListScoped", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: uuid.New()}}, nil).Once()

	got, err := svc.ListDeletedSecretsScoped(ctx, scope)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	repo.AssertExpectations(t)
}

func TestDeleteSecretScopedChecksScopeBeforeSoftDeleting(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("ReadScoped", ctx, secretID, scope).Return(nil, assert.AnError).Once()

	err := svc.DeleteSecretScoped(ctx, secretID, scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "SoftDelete", mock.Anything, mock.Anything)
}

func TestLegacyShimsBuildTheRightScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()

	repo.On("ReadScoped", ctx, secretID, model.NewOwnerScope(uuid.Nil, userID)).
		Return(&model.Secret{ID: secretID, Value: "ENC(v)", Enabled: true}, nil).Once()
	_, err := svc.GetSecret(ctx, secretID, userID)
	require.NoError(t, err)

	repo.On("ReadScoped", ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil)).
		Return(&model.Secret{ID: secretID, Value: "ENC(v)", Enabled: true}, nil).Once()
	_, err = svc.GetSecretInVault(ctx, secretID, vaultID)
	require.NoError(t, err)

	repo.AssertExpectations(t)
}
```

Add the fixture helper to the same file. It reuses the mocks already present in the package's test files; if `newScopeServiceFixture` collides with an existing helper name, rename it rather than editing the existing one:

```go
// newScopeServiceFixture builds a secretService over mock collaborators.
// The crypto mock is a reversible ENC(...) wrapper so tests can assert on the
// plaintext the service returns.
func newScopeServiceFixture(t *testing.T) (*MockSecretRepository, *secretService) {
	t.Helper()
	repo := new(MockSecretRepository)
	tags := new(MockTagService)
	tags.On("GetTags", mock.Anything, mock.Anything).Return([]string{}, nil).Maybe()
	tags.On("RemoveAllTags", mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := &secretService{
		secretRepo:     repo,
		cryptoService:  fakeCrypto{},
		versionService: new(MockVersioningService),
		tagService:     tags,
		logger:         newTestLogger(t),
	}
	return repo, svc
}
```

Reuse the package's existing mock and logger helpers — `MockSecretRepository`, `MockTagService`, `MockVersioningService` and a logger constructor already exist in `internal/services/secrets/secret_service_test.go` and `coverage_boost_test.go`. If a reversible `fakeCrypto` does not exist there, add:

```go
type fakeCrypto struct{}

func (fakeCrypto) EncryptSecret(v string) (string, error) { return "ENC(" + v + ")", nil }
func (fakeCrypto) DecryptSecret(v string) (string, error) {
	if len(v) > 5 && v[:4] == "ENC(" && v[len(v)-1] == ')' {
		return v[4 : len(v)-1], nil
	}
	return v, nil
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run 'Scoped|TestLegacyShimsBuildTheRightScope' -v`

Expected: FAIL to build — `svc.GetSecretScoped undefined (type *secretService has no field or method GetSecretScoped)`, likewise `ListDeletedSecretsScoped` and `DeleteSecretScoped`.

- [ ] **Step 3: Implement the scoped service methods and turn the old ones into shims**

In `internal/services/secrets/secret_service.go`, add to the `SecretService` interface (directly under `CreateSecret`):

```go
	// GetSecretScoped retrieves a decrypted secret authorized by scope.
	// Canonical; GetSecret and GetSecretInVault are shims over it.
	GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error)
	// ListSecretsScoped lists decrypted secrets authorized by scope.
	ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error)
	// DeleteSecretScoped soft-deletes a secret authorized by scope.
	DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	// ListDeletedSecretsScoped lists soft-deleted secrets authorized by scope.
	ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error)
```

Add the canonical implementations:

```go
// GetSecretScoped retrieves a secret authorized by scope, decrypts it, loads
// its tags, and enforces the lifecycle policy. The scoped read is the access
// check — there is no separate in-Go ownership comparison.
func (s *secretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	actor := scope.ActorID().String()

	secret, err := s.secretRepo.ReadScoped(ctx, secretID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Secret not found or access denied", err)
		return nil, fmt.Errorf("%w", ErrSecretNotFound)
	}

	decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Failed to decrypt secret", err)
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	secret.Value = decryptedValue

	tags, err := s.tagService.GetTags(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(actor, "get_secret", "failed", "Failed to load tags", err)
		return nil, fmt.Errorf("failed to load tags: %w", err)
	}
	secret.Tags = tags

	if !secret.IsAccessible() {
		s.logger.LogAuditError(actor, "get_secret", "denied", "Secret is disabled or outside its valid time window", nil)
		return nil, fmt.Errorf("%w", ErrSecretLifecycleDenied)
	}

	return secret, nil
}

// ListSecretsScoped lists secrets authorized by scope, decrypting values and
// loading tags for each.
func (s *secretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	actor := scope.ActorID().String()

	secretList, err := s.secretRepo.ListScoped(ctx, scope, repositories.SecretFilter{Tags: tags})
	if err != nil {
		s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to list secrets", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for i := range secretList {
		secret := &secretList[i]

		decryptedValue, decErr := s.cryptoService.DecryptSecret(secret.Value)
		if decErr != nil {
			s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to decrypt secret", decErr)
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", secret.ID.String(), decErr)
		}
		secret.Value = decryptedValue

		secretTags, tagErr := s.tagService.GetTags(ctx, secret.ID)
		if tagErr != nil {
			s.logger.LogAuditError(actor, "list_secrets", "failed", "Failed to load tags", tagErr)
			return nil, fmt.Errorf("failed to load tags for secret %s: %w", secret.ID.String(), tagErr)
		}
		secret.Tags = secretTags
	}

	logrus.WithFields(logrus.Fields{
		"scope":        scope.String(),
		"secret_count": len(secretList),
	}).Debug("Listed secrets")

	return secretList, nil
}

// DeleteSecretScoped soft-deletes a secret authorized by scope. The scoped read
// is the access check.
func (s *secretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	actor := scope.ActorID().String()

	secret, err := s.secretRepo.ReadScoped(ctx, secretID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Secret not found or access denied", err)
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}

	if err := s.tagService.RemoveAllTags(ctx, secretID); err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Failed to remove tags", err)
		return fmt.Errorf("failed to remove tags: %w", err)
	}

	if err := s.secretRepo.SoftDelete(ctx, secretID); err != nil {
		s.logger.LogAuditError(actor, "delete_secret", "failed", "Failed to soft delete secret", err)
		return fmt.Errorf("failed to soft delete secret: %w", err)
	}

	s.logger.LogAuditInfo(actor, "delete_secret", "success", fmt.Sprintf("Secret soft deleted: %s", secret.Name))
	return nil
}

// ListDeletedSecretsScoped lists soft-deleted secrets authorized by scope. The
// filter runs in SQL rather than pulling every secret into memory to discard
// most of them.
func (s *secretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	secretList, err := s.secretRepo.ListScoped(ctx, scope, repositories.SecretFilter{OnlyDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted secrets: %w", err)
	}
	return secretList, nil
}
```

Replace the six old bodies with shims (keep the doc comments, add `// Deprecated: shim over …Scoped; removed in Phase 6.`):

```go
func (s *secretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	return s.GetSecretScoped(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
}

func (s *secretService) GetSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	return s.GetSecretScoped(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
}

func (s *secretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]model.Secret, error) {
	return s.ListSecretsScoped(ctx, model.NewOwnerScope(uuid.Nil, userID), tags)
}

func (s *secretService) ListSecretsInVault(ctx context.Context, vaultID uuid.UUID, tags []string) ([]model.Secret, error) {
	return s.ListSecretsScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), tags)
}

func (s *secretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
	return s.DeleteSecretScoped(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
}

func (s *secretService) DeleteSecretInVault(ctx context.Context, secretID, vaultID uuid.UUID) error {
	return s.DeleteSecretScoped(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
}

func (s *secretService) ListDeletedSecretsInVault(ctx context.Context, vaultID uuid.UUID) ([]model.Secret, error) {
	return s.ListDeletedSecretsScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil))
}
```

Add pass-through decorators to `internal/cache/cache_integration.go` — **caching stays disabled on the unified read through Phase 3**, so a vault-scoped entry can never be admitted to an owner-scoped caller:

```go
// GetSecretScoped retrieves a scoped secret. Caching is deliberately disabled
// here until Phase 5 introduces the compound scopeCacheKey: an ID-keyed cache
// would serve an owner-scoped caller a value admitted under a vault scope.
func (s *CachedSecretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	return s.secretService.GetSecretScoped(ctx, secretID, scope)
}

// ListSecretsScoped lists scoped secrets (not cached).
func (s *CachedSecretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	return s.secretService.ListSecretsScoped(ctx, scope, tags)
}

// DeleteSecretScoped soft-deletes a scoped secret and evicts it from cache.
func (s *CachedSecretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.DeleteSecretScoped(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove deleted secret from cache")
	}
	return nil
}

// ListDeletedSecretsScoped lists scoped soft-deleted secrets (not cached).
func (s *CachedSecretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	return s.secretService.ListDeletedSecretsScoped(ctx, scope)
}
```

Also change `CachedSecretService.GetSecret` (`internal/cache/cache_integration.go:34-60`) to a pass-through for the duration of Phase 3; Phase 5 restores caching under the compound key:

```go
// GetSecret retrieves a secret. Caching is disabled here from Phase 3 until
// Phase 5 lands the compound scopeCacheKey.
func (s *CachedSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.Secret, error) {
	return s.secretService.GetSecret(ctx, secretID, userID)
}
```

Add the matching retry decorators to `internal/services/retry/retry_secret_service.go`:

```go
// GetSecretScoped retrieves a scoped secret with retry logic.
func (s *retrySecretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	var result *model.Secret
	var err error
	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.GetSecretScoped(ctx, secretID, scope)
		return err
	})
	return result, retryErr
}

// ListSecretsScoped lists scoped secrets with retry logic.
func (s *retrySecretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	var result []model.Secret
	var err error
	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ListSecretsScoped(ctx, scope, tags)
		return err
	})
	return result, retryErr
}

// DeleteSecretScoped deletes a scoped secret with retry logic.
func (s *retrySecretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.DeleteSecretScoped(ctx, secretID, scope)
	})
}

// ListDeletedSecretsScoped lists scoped deleted secrets with retry logic.
func (s *retrySecretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	var result []model.Secret
	var err error
	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.ListDeletedSecretsScoped(ctx, scope)
		return err
	})
	return result, retryErr
}
```

`internal/services/retry/retry_secret_service.go` must now import `rocketvault/model` (already imported) — no new imports needed.

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. `SecretService` implementors that are still hand-written need the four methods — the known ones are `cmd/testutils/test_utils.go:379` (`MockSecretService`) and any per-package stub. Add, matching the file's existing testify style:

```go
func (m *MockSecretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, secretID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretService) ListSecretsScoped(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error) {
	args := m.Called(ctx, scope, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretService) DeleteSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

func (m *MockSecretService) ListDeletedSecretsScoped(ctx context.Context, scope model.Scope) ([]model.Secret, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}
```

Cache tests asserting a hit on `GetSecret` will now fail because caching is deliberately off for this phase — update them to assert the pass-through and add a `// Re-enabled in Phase 5.` comment rather than restoring the old behaviour.

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_scope_service_test.go internal/cache/cache_integration.go internal/cache/cache_integration_test.go internal/services/retry/retry_secret_service.go cmd/testutils/test_utils.go
git commit -S -m "refactor(secrets): scope-aware read, list and delete on SecretService"
```

---
### Task 15: SecretService update on a scope, via applySecretUpdate

**Files:**
- Modify: `internal/services/secrets/secret_service.go:42-53` (`UpdateSecretRequest`), `:115-149` (interface), `:279-384` (`UpdateSecret`), `:389-475` (`UpdateSecretInVault`)
- Modify: `internal/cache/cache_integration.go` (add `UpdateSecretScoped` decorator that invalidates)
- Modify: `internal/services/retry/retry_secret_service.go` (add `UpdateSecretScoped`)
- Test: `internal/services/secrets/secret_scope_service_test.go` (append)

**Interfaces:**
- Consumes: `applySecretUpdate` (Task 13); `repositories.SecretRepositoryInterface.ReadScoped/UpdateScoped` (Task 10); `GetSecretScoped` fixture helpers (Task 14).
- Produces:
  - `UpdateSecretRequest` gains `Scope model.Scope` (the legacy `UserID`/`VaultID` fields stay until Phase 6)
  - `SecretService.UpdateSecretScoped(ctx context.Context, req UpdateSecretRequest) error`

- [ ] **Step 1: Write the failing test**

Append to `internal/services/secrets/secret_scope_service_test.go`:

```go
func TestUpdateSecretScopedUsesTheSameScopeForReadAndWrite(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	vaultID := uuid.New()
	actorID := uuid.New()
	scope := model.NewVaultScope(vaultID, actorID)
	newName := "renamed"

	current := &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultID,
		Name: "original", Value: "ENC(v1)", Version: 1, Enabled: true,
	}

	repo.On("ReadScoped", ctx, secretID, scope).Return(current, nil).Once()
	repo.On("UpdateScoped", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.Name == "renamed" && s.Version == 2
	}), scope).Return(nil).Once()

	err := svc.UpdateSecretScoped(ctx, UpdateSecretRequest{
		SecretID: secretID,
		Scope:    scope,
		Name:     &newName,
	})
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestUpdateSecretScopedDeniesOutOfScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("ReadScoped", ctx, secretID, scope).Return(nil, assert.AnError).Once()

	err := svc.UpdateSecretScoped(ctx, UpdateSecretRequest{SecretID: secretID, Scope: scope})
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "UpdateScoped", mock.Anything, mock.Anything, mock.Anything)
}

func TestUpdateSecretScopedRejectsAnInvalidScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	// A half-migrated caller that forgot to set Scope must not reach the repo
	// with an admin-equivalent predicate.
	var zero model.Scope
	repo.On("ReadScoped", mock.Anything, mock.Anything, zero).
		Return(nil, repositories.ErrInvalidScope).Once()

	err := svc.UpdateSecretScoped(ctx, UpdateSecretRequest{SecretID: uuid.New()})
	require.Error(t, err)
	repo.AssertNotCalled(t, "UpdateScoped", mock.Anything, mock.Anything, mock.Anything)
}

func TestUpdateSecretLegacyShimsBuildTheRightScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()
	current := &model.Secret{ID: secretID, UserID: userID, VaultID: vaultID, Value: "ENC(v)", Version: 1, Enabled: true}

	ownerScope := model.NewOwnerScope(uuid.Nil, userID)
	repo.On("ReadScoped", ctx, secretID, ownerScope).Return(current, nil).Once()
	repo.On("UpdateScoped", ctx, mock.Anything, ownerScope).Return(nil).Once()
	require.NoError(t, svc.UpdateSecret(ctx, UpdateSecretRequest{SecretID: secretID, UserID: userID}))

	vaultScope := model.NewVaultScope(vaultID, userID)
	repo.On("ReadScoped", ctx, secretID, vaultScope).Return(current, nil).Once()
	repo.On("UpdateScoped", ctx, mock.Anything, vaultScope).Return(nil).Once()
	require.NoError(t, svc.UpdateSecretInVault(ctx, UpdateSecretRequest{SecretID: secretID, UserID: userID, VaultID: vaultID}))

	repo.AssertExpectations(t)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run 'TestUpdateSecretScoped|TestUpdateSecretLegacyShims' -v`

Expected: FAIL to build — `unknown field Scope in struct literal of type UpdateSecretRequest` and `svc.UpdateSecretScoped undefined (type *secretService has no field or method UpdateSecretScoped)`.

- [ ] **Step 3: Implement the scoped update and turn the old ones into shims**

In `internal/services/secrets/secret_service.go`, add the field to `UpdateSecretRequest` and mark the legacy fields:

```go
// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	SecretID    uuid.UUID
	Scope       model.Scope // Authorization scope for the read and the write.
	UserID      uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	VaultID     uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	Name        *string     // Optional - nil means no change.
	Value       *string     // Optional - nil means no change.
	Tags        *[]string   // Optional - nil means no change.
	ContentType *string     // Optional - nil means no change.
	Enabled     *bool       // Optional - nil means no change.
	ExpiresAt   *time.Time  // Optional - nil means no change.
	NotBefore   *time.Time  // Optional - nil means no change.
}
```

Add to the `SecretService` interface:

```go
	// UpdateSecretScoped updates a secret authorized by req.Scope. The scoped
	// read is the check and the write repeats the same predicate, so there is
	// no TOCTOU window even if the row's vault changes between them.
	UpdateSecretScoped(ctx context.Context, req UpdateSecretRequest) error
```

Add the canonical implementation:

```go
// UpdateSecretScoped updates a secret with versioning support, authorized by
// req.Scope. Authorization lives entirely in the scope: the scoped read is the
// check, and the write repeats the same predicate.
func (s *secretService) UpdateSecretScoped(ctx context.Context, req UpdateSecretRequest) error {
	actor := req.Scope.ActorID().String()
	logrus.WithFields(logrus.Fields{
		"secret_id": req.SecretID.String(),
		"scope":     req.Scope.String(),
	}).Info("Updating secret")

	currentSecret, err := s.secretRepo.ReadScoped(ctx, req.SecretID, req.Scope)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Secret not found or access denied", err)
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}

	currentValue, err := s.cryptoService.DecryptSecret(currentSecret.Value)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to decrypt current secret", err)
		return fmt.Errorf("failed to decrypt current secret: %w", err)
	}

	if _, err = s.versionService.CreateVersion(ctx, CreateVersionRequest{
		SecretID: currentSecret.ID,
		UserID:   req.Scope.ActorID(),
		Name:     currentSecret.Name,
		Value:    currentValue,
		Version:  currentSecret.Version,
	}); err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to create version", err)
		return fmt.Errorf("failed to create version: %w", err)
	}

	updatedSecret, err := applySecretUpdate(currentSecret, req, s.cryptoService.EncryptSecret)
	if err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to apply update", err)
		return err
	}

	if err := s.secretRepo.UpdateScoped(ctx, updatedSecret, req.Scope); err != nil {
		s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	if req.Tags != nil {
		if err := s.tagService.RemoveAllTags(ctx, req.SecretID); err != nil {
			s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to remove old tags", err)
			return fmt.Errorf("failed to remove old tags: %w", err)
		}
		if len(*req.Tags) > 0 {
			if err := s.tagService.AddTags(ctx, req.SecretID, *req.Tags); err != nil {
				s.logger.LogAuditError(actor, "update_secret", "failed", "Failed to add new tags", err)
				return fmt.Errorf("failed to add new tags: %w", err)
			}
		}
	}

	s.logger.LogAuditInfo(actor, "update_secret", "success", fmt.Sprintf("Secret updated: %s", updatedSecret.Name))
	return nil
}
```

Replace both old bodies with shims:

```go
// Deprecated: shim over UpdateSecretScoped; removed in Phase 6.
func (s *secretService) UpdateSecret(ctx context.Context, req UpdateSecretRequest) error {
	req.Scope = model.NewOwnerScope(uuid.Nil, req.UserID)
	return s.UpdateSecretScoped(ctx, req)
}

// Deprecated: shim over UpdateSecretScoped; removed in Phase 6.
func (s *secretService) UpdateSecretInVault(ctx context.Context, req UpdateSecretRequest) error {
	req.Scope = model.NewVaultScope(req.VaultID, req.UserID)
	return s.UpdateSecretScoped(ctx, req)
}
```

Add to `internal/cache/cache_integration.go`:

```go
// UpdateSecretScoped updates a scoped secret and invalidates the cache entry.
func (s *CachedSecretService) UpdateSecretScoped(ctx context.Context, req secrets.UpdateSecretRequest) error {
	if err := s.secretService.UpdateSecretScoped(ctx, req); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, req.SecretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
	}
	return nil
}
```

Add to `internal/services/retry/retry_secret_service.go`:

```go
// UpdateSecretScoped updates a scoped secret with retry logic.
func (s *retrySecretService) UpdateSecretScoped(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateSecretScoped(ctx, req)
	})
}
```

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Hand-written `SecretService` mocks need:

```go
func (m *MockSecretService) UpdateSecretScoped(ctx context.Context, req secretServices.UpdateSecretRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
```

`UpdateSecret`'s legacy path now returns `ErrSecretNotFound` (wrapped) where it previously returned the bare strings `"secret not found: …"` and `"access denied"`; update any test asserting on those strings to `assert.ErrorIs(t, err, secrets.ErrSecretNotFound)`. This is the deliberate consolidation of the three disagreeing mechanisms described in spec §5.3.

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_scope_service_test.go internal/cache/cache_integration.go internal/services/retry/retry_secret_service.go cmd/testutils/test_utils.go
git commit -S -m "refactor(secrets): scope-aware UpdateSecret built on applySecretUpdate"
```

---

### Task 16: Scope RecoverSecret and PurgeSecret

Today `RecoverSecret` (`internal/services/secrets/secret_service.go:769-774`) and `PurgeSecret` (`:777-782`) take a bare `secretID` with **no authorization check at all**; the handlers gate them with a separate `IsSecretSoftDeleted*` pre-check (`api/soft_delete.go:59-91`), which is a TOCTOU window because the pre-check and the mutation use different scopes. Move the check inside, under one scope value.

**Files:**
- Modify: `internal/services/secrets/secret_service.go:115-149` (interface), `:736-749` (`IsSecretSoftDeletedInVault`), `:753-766` (`IsSecretSoftDeletedForUser`), `:769-782` (`RecoverSecret`, `PurgeSecret`)
- Modify: `internal/cache/cache_integration.go:249-280` (add scoped decorators)
- Modify: `internal/services/retry/retry_secret_service.go:280-292` (add scoped decorators)
- Test: `internal/services/secrets/secret_scope_service_test.go` (append)

**Interfaces:**
- Consumes: `repositories.SecretRepositoryInterface.ListScoped`, `repositories.SecretFilter{OnlyDeleted: true}` (Task 10); `secretRepo.RecoverSecret`/`PurgeSecret` (unchanged).
- Produces, on `secrets.SecretService`:
  - `RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error`
  - `PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error`

Note: `SecretRepositoryInterface.RecoverSecret`/`PurgeSecret` keep their unscoped signatures. The scope check is a scoped `ListScoped(OnlyDeleted)` membership test performed inside the service under the *same* scope value the mutation runs with, which closes the handler-level TOCTOU. The repository's own `deleted_at IS NOT NULL` / purge-protection predicates still guard the mutation. A fully atomic scoped recover/purge needs new repository predicates and is deferred to P3.

- [ ] **Step 1: Write the failing test**

Append to `internal/services/secrets/secret_scope_service_test.go`:

```go
func TestRecoverSecretScopedRequiresTheSecretToBeInScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("ListScoped", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{}, nil).Once()

	err := svc.RecoverSecretScoped(ctx, secretID, scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "RecoverSecret", mock.Anything, mock.Anything)
}

func TestRecoverSecretScopedRecoversWhenInScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	deletedAt := time.Now().UTC()

	repo.On("ListScoped", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, DeletedAt: &deletedAt}}, nil).Once()
	repo.On("RecoverSecret", ctx, secretID).Return(nil).Once()

	require.NoError(t, svc.RecoverSecretScoped(ctx, secretID, scope))
	repo.AssertExpectations(t)
}

func TestPurgeSecretScopedRequiresTheSecretToBeInScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	repo.On("ListScoped", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{}, nil).Once()

	err := svc.PurgeSecretScoped(ctx, uuid.New(), scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "PurgeSecret", mock.Anything, mock.Anything)
}

func TestPurgeSecretScopedPurgesWhenInScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	deletedAt := time.Now().UTC()

	repo.On("ListScoped", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, DeletedAt: &deletedAt}}, nil).Once()
	repo.On("PurgeSecret", ctx, secretID).Return(nil).Once()

	require.NoError(t, svc.PurgeSecretScoped(ctx, secretID, scope))
	repo.AssertExpectations(t)
}
```

Add `"time"` to the test file's import block if it is not already there.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run 'TestRecoverSecretScoped|TestPurgeSecretScoped' -v`

Expected: FAIL to build — `svc.RecoverSecretScoped undefined (type *secretService has no field or method RecoverSecretScoped)` and the same for `PurgeSecretScoped`.

- [ ] **Step 3: Implement the scoped recover and purge**

In `internal/services/secrets/secret_service.go`, add to the `SecretService` interface:

```go
	// RecoverSecretScoped restores a soft-deleted secret authorized by scope.
	RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
	// PurgeSecretScoped permanently deletes a soft-deleted secret authorized by scope.
	PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error
```

Add the implementations plus a shared helper:

```go
// softDeletedInScope reports whether secretID names a soft-deleted secret the
// scope authorizes. It replaces the handler-level IsSecretSoftDeleted* checks,
// which used a different scope from the mutation that followed them.
func (s *secretService) softDeletedInScope(ctx context.Context, secretID uuid.UUID, scope model.Scope) (bool, error) {
	deleted, err := s.secretRepo.ListScoped(ctx, scope, repositories.SecretFilter{OnlyDeleted: true})
	if err != nil {
		return false, fmt.Errorf("failed to list deleted secrets: %w", err)
	}
	for _, secret := range deleted {
		if secret.ID == secretID {
			return true, nil
		}
	}
	return false, nil
}

// RecoverSecretScoped restores a soft-deleted secret authorized by scope.
func (s *secretService) RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	inScope, err := s.softDeletedInScope(ctx, secretID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "recover_secret", "failed",
			"Secret not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrSecretNotFound)
	}
	if err := s.secretRepo.RecoverSecret(ctx, secretID); err != nil {
		return fmt.Errorf("failed to recover secret: %w", err)
	}
	return nil
}

// PurgeSecretScoped permanently deletes a soft-deleted secret authorized by scope.
func (s *secretService) PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	inScope, err := s.softDeletedInScope(ctx, secretID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_secret", "failed",
			"Secret not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrSecretNotFound)
	}
	if err := s.secretRepo.PurgeSecret(ctx, secretID); err != nil {
		return fmt.Errorf("failed to purge secret: %w", err)
	}
	return nil
}
```

Rewrite the two `IsSecretSoftDeleted*` methods over the helper (they lose their in-Go `ListInVaultIncludeDeleted` loops), keeping them as shims until Phase 6:

```go
// Deprecated: shim over softDeletedInScope; removed in Phase 6.
func (s *secretService) IsSecretSoftDeletedInVault(ctx context.Context, secretID, vaultID uuid.UUID) (bool, error) {
	return s.softDeletedInScope(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
}

// Deprecated: shim over softDeletedInScope; removed in Phase 6.
func (s *secretService) IsSecretSoftDeletedForUser(ctx context.Context, secretID, userID uuid.UUID) (bool, error) {
	return s.softDeletedInScope(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
}
```

Keep the unscoped `RecoverSecret`/`PurgeSecret` as admin-scoped shims:

```go
// Deprecated: shim over RecoverSecretScoped; removed in Phase 6.
func (s *secretService) RecoverSecret(ctx context.Context, secretID uuid.UUID) error {
	return s.RecoverSecretScoped(ctx, secretID, model.NewAdminScope(uuid.Nil))
}

// Deprecated: shim over PurgeSecretScoped; removed in Phase 6.
func (s *secretService) PurgeSecret(ctx context.Context, secretID uuid.UUID) error {
	return s.PurgeSecretScoped(ctx, secretID, model.NewAdminScope(uuid.Nil))
}
```

Add to `internal/cache/cache_integration.go`:

```go
// RecoverSecretScoped recovers a scoped soft-deleted secret and evicts it from cache.
func (s *CachedSecretService) RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.RecoverSecretScoped(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
	}
	return nil
}

// PurgeSecretScoped purges a scoped soft-deleted secret and evicts it from cache.
func (s *CachedSecretService) PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	if err := s.secretService.PurgeSecretScoped(ctx, secretID, scope); err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to remove purged secret from cache")
	}
	return nil
}
```

Add to `internal/services/retry/retry_secret_service.go`:

```go
// RecoverSecretScoped recovers a scoped soft-deleted secret with retry logic.
func (s *retrySecretService) RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.RecoverSecretScoped(ctx, secretID, scope)
	})
}

// PurgeSecretScoped purges a scoped soft-deleted secret with retry logic.
func (s *retrySecretService) PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.PurgeSecretScoped(ctx, secretID, scope)
	})
}
```

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Hand-written `SecretService` mocks need:

```go
func (m *MockSecretService) RecoverSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}

func (m *MockSecretService) PurgeSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) error {
	args := m.Called(ctx, secretID, scope)
	return args.Error(0)
}
```

Tests that previously expected `RecoverSecret` to succeed on a secret that is not soft-deleted will now get `ErrSecretNotFound` — that is the intended new authorization, not a regression.

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_scope_service_test.go internal/cache/cache_integration.go internal/services/retry/retry_secret_service.go cmd/testutils/test_utils.go
git commit -S -m "feat(secrets): authorize RecoverSecret and PurgeSecret with a scope"
```

---

### Task 17: VersioningService version getters on a scope

The three vault-scoped getters (`GetVersionsInVault` at `internal/services/secrets/versioning_service.go:238`, `GetVersionInVault` at `:267`, `GetLatestVersionInVault` at `:294`) duplicate their owner-scoped siblings (`:137`, `:173`, `:206`) with only the guard clause differing.

**Files:**
- Modify: `internal/services/secrets/versioning_service.go:20-34` (interface), `:137-233` (owner getters), `:238-313` (vault getters)
- Modify: `internal/services/secrets/secret_service.go:794-840` (the six delegating `Get*Version*` methods) — add three scoped delegates
- Test: `internal/services/secrets/versioning_scope_test.go`

**Interfaces:**
- Consumes: `repositories.SecretRepositoryInterface.ReadScoped` (Task 10).
- Produces:
  - `VersioningServiceInterface.GetVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)`
  - `VersioningServiceInterface.GetVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)`
  - `VersioningServiceInterface.GetLatestVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)`
  - `SecretService.GetSecretVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)`
  - `SecretService.GetSecretVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)`
  - `SecretService.GetLatestSecretVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/services/secrets/versioning_scope_test.go`:

```go
package secrets

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func newVersioningScopeFixture(t *testing.T) (*MockSecretRepository, *MockSecretVersionRepository, *versioningService) {
	t.Helper()
	secretRepo := new(MockSecretRepository)
	versionRepo := new(MockSecretVersionRepository)
	return secretRepo, versionRepo, &versioningService{
		versionRepo: versionRepo,
		secretRepo:  secretRepo,
		userRepo:    new(MockUserRepository),
		cryptoSvc:   fakeCrypto{},
		log:         newTestLogger(t),
	}
}

func TestGetVersionsScopedDeniesOutOfScope(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("ReadScoped", ctx, secretID, scope).Return(nil, assert.AnError).Once()

	_, err := svc.GetVersionsScoped(ctx, secretID, scope)
	require.Error(t, err)
	versionRepo.AssertNotCalled(t, "GetVersions", mock.Anything, mock.Anything)
}

func TestGetVersionsScopedDecryptsInScope(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	secretRepo.On("ReadScoped", ctx, secretID, scope).Return(&model.Secret{ID: secretID}, nil).Once()
	versionRepo.On("GetVersions", ctx, secretID).Return([]model.SecretVersion{
		{ID: uuid.New(), SecretID: secretID, Version: 1, Value: "ENC(v1)", CreatedAt: time.Now().UTC()},
	}, nil).Once()

	versions, err := svc.GetVersionsScoped(ctx, secretID, scope)
	require.NoError(t, err)
	require.Len(t, versions, 1)
	assert.Equal(t, "v1", versions[0].Value)
}

func TestGetVersionScopedAndLatestVersionScoped(t *testing.T) {
	secretRepo, versionRepo, svc := newVersioningScopeFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	secretRepo.On("ReadScoped", ctx, secretID, scope).Return(&model.Secret{ID: secretID}, nil).Twice()
	versionRepo.On("GetVersion", ctx, secretID, 2).
		Return(&model.SecretVersion{SecretID: secretID, Version: 2, Value: "ENC(v2)"}, nil).Once()
	versionRepo.On("GetLatestVersion", ctx, secretID).
		Return(&model.SecretVersion{SecretID: secretID, Version: 3, Value: "ENC(v3)"}, nil).Once()

	v, err := svc.GetVersionScoped(ctx, secretID, 2, scope)
	require.NoError(t, err)
	assert.Equal(t, "v2", v.Value)

	latest, err := svc.GetLatestVersionScoped(ctx, secretID, scope)
	require.NoError(t, err)
	assert.Equal(t, "v3", latest.Value)
	secretRepo.AssertExpectations(t)
}
```

Reuse the package's existing `MockSecretVersionRepository`, `MockUserRepository` and `newTestLogger` helpers; if the version-repository mock has a different name in this package, use that name instead of adding a second one.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run 'TestGetVersionsScoped|TestGetVersionScopedAndLatestVersionScoped' -v`

Expected: FAIL to build — `svc.GetVersionsScoped undefined (type *versioningService has no field or method GetVersionsScoped)`, likewise `GetVersionScoped` and `GetLatestVersionScoped`.

- [ ] **Step 3: Implement the scoped getters and shim the six old ones**

In `internal/services/secrets/versioning_service.go`, add to `VersioningServiceInterface`:

```go
	// GetVersionsScoped returns every decrypted version of a secret the scope
	// authorizes. Canonical; GetVersions and GetVersionsInVault are shims.
	GetVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)
	// GetVersionScoped returns one decrypted version the scope authorizes.
	GetVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)
	// GetLatestVersionScoped returns the newest decrypted version the scope authorizes.
	GetLatestVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)
```

Add the canonical implementations:

```go
// GetVersionsScoped retrieves all versions of a secret the scope authorizes.
// The scoped read on the parent secret is the access check.
func (s *versioningService) GetVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	if _, err := s.secretRepo.ReadScoped(ctx, secretID, scope); err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	encryptedVersions, err := s.versionRepo.GetVersions(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get secret versions")
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}

	var versions []model.SecretVersion
	for _, encVersion := range encryptedVersions {
		decryptedValue, decErr := s.cryptoSvc.DecryptSecret(encVersion.Value)
		if decErr != nil {
			s.log.WithError(decErr).WithField("version_id", encVersion.ID).Error("Failed to decrypt secret version")
			return nil, fmt.Errorf("failed to decrypt secret version: %w", decErr)
		}
		decVersion := encVersion
		decVersion.Value = decryptedValue
		versions = append(versions, decVersion)
	}
	return versions, nil
}

// GetVersionScoped retrieves one version of a secret the scope authorizes.
func (s *versioningService) GetVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	if _, err := s.secretRepo.ReadScoped(ctx, secretID, scope); err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	encryptedVersion, err := s.versionRepo.GetVersion(ctx, secretID, version)
	if err != nil {
		s.log.WithError(err).WithFields(map[string]any{"secret_id": secretID, "version": version}).
			Error("Failed to get secret version")
		return nil, fmt.Errorf("failed to get secret version: %w", err)
	}

	decryptedValue, err := s.cryptoSvc.DecryptSecret(encryptedVersion.Value)
	if err != nil {
		s.log.WithError(err).WithField("version_id", encryptedVersion.ID).Error("Failed to decrypt secret version")
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}
	encryptedVersion.Value = decryptedValue
	return encryptedVersion, nil
}

// GetLatestVersionScoped retrieves the newest version the scope authorizes.
func (s *versioningService) GetLatestVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	if _, err := s.secretRepo.ReadScoped(ctx, secretID, scope); err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	encryptedVersion, err := s.versionRepo.GetLatestVersion(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get latest secret version")
		return nil, fmt.Errorf("failed to get latest secret version: %w", err)
	}

	decryptedValue, err := s.cryptoSvc.DecryptSecret(encryptedVersion.Value)
	if err != nil {
		s.log.WithError(err).WithField("version_id", encryptedVersion.ID).Error("Failed to decrypt secret version")
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}
	encryptedVersion.Value = decryptedValue
	return encryptedVersion, nil
}
```

Replace the six old bodies with shims:

```go
// Deprecated: shim over GetVersionsScoped; removed in Phase 6.
func (s *versioningService) GetVersions(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) ([]model.SecretVersion, error) {
	return s.GetVersionsScoped(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over GetVersionScoped; removed in Phase 6.
func (s *versioningService) GetVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*model.SecretVersion, error) {
	return s.GetVersionScoped(ctx, secretID, version, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over GetLatestVersionScoped; removed in Phase 6.
func (s *versioningService) GetLatestVersion(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.SecretVersion, error) {
	return s.GetLatestVersionScoped(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over GetVersionsScoped; removed in Phase 6.
func (s *versioningService) GetVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	return s.GetVersionsScoped(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
}

// Deprecated: shim over GetVersionScoped; removed in Phase 6.
func (s *versioningService) GetVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return s.GetVersionScoped(ctx, secretID, version, model.NewVaultScope(vaultID, uuid.Nil))
}

// Deprecated: shim over GetLatestVersionScoped; removed in Phase 6.
func (s *versioningService) GetLatestVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return s.GetLatestVersionScoped(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
}
```

In `internal/services/secrets/secret_service.go`, add to the `SecretService` interface and implement three delegates:

```go
	// GetSecretVersionsScoped returns every version of a secret the scope authorizes.
	GetSecretVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error)
	// GetSecretVersionScoped returns one version the scope authorizes.
	GetSecretVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error)
	// GetLatestSecretVersionScoped returns the newest version the scope authorizes.
	GetLatestSecretVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error)
```

```go
func (s *secretService) GetSecretVersionsScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	return s.versionService.GetVersionsScoped(ctx, secretID, scope)
}

func (s *secretService) GetSecretVersionScoped(ctx context.Context, secretID uuid.UUID, version int, scope model.Scope) (*model.SecretVersion, error) {
	return s.versionService.GetVersionScoped(ctx, secretID, version, scope)
}

func (s *secretService) GetLatestSecretVersionScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.SecretVersion, error) {
	return s.versionService.GetLatestVersionScoped(ctx, secretID, scope)
}
```

Add matching pass-through decorators to `internal/cache/cache_integration.go` (versions are never cached) and to `internal/services/retry/retry_secret_service.go` (wrapped in `ExecuteDatabaseOperation`, following the shape of the existing `GetSecretVersionsInVault` decorator at `:164`).

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Hand-written `VersioningServiceInterface` and `SecretService` mocks need the three methods each, in the same testify style as their neighbours. `internal/services/secrets/versioning_service_vault_test.go` exercises the `*InVault` shims and must stay green unchanged — that is this task's equivalence proof.

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/versioning_service.go internal/services/secrets/versioning_scope_test.go internal/services/secrets/secret_service.go internal/cache/cache_integration.go internal/services/retry/retry_secret_service.go cmd/testutils/test_utils.go
git commit -S -m "refactor(secrets): scope-aware secret version getters"
```

---
### Task 18: applyKeyUpdate pure function

The field-merge logic is duplicated between `UpdateKey` (`internal/services/keys/key_service.go:540-567`) and `UpdateKeyInVault` (`:598-617`). Extract it, mirroring `applySecretUpdate`. Keys carry no encrypted-value update path, so no `encrypt` parameter is needed.

**Files:**
- Create: `internal/services/keys/key_update.go`
- Test: `internal/services/keys/key_update_test.go`

**Interfaces:**
- Consumes: `model.Key`, `UpdateKeyRequest` (`key_service.go:74-84`).
- Produces: `func applyKeyUpdate(current *model.Key, req UpdateKeyRequest) (*model.Key, error)` — unexported, package `keys`.

- [ ] **Step 1: Write the failing test**

Create `internal/services/keys/key_update_test.go`:

```go
package keys

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func baseKey() *model.Key {
	return &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "original",
		Type:      model.KeyTypeRSA,
		Value:     "ENC(pem)",
		Tags:      []string{"a"},
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
		Bits:      2048,
	}
}

func TestApplyKeyUpdateLeavesTheInputUntouched(t *testing.T) {
	current := baseKey()
	name := "renamed"

	updated, err := applyKeyUpdate(current, UpdateKeyRequest{Name: &name})
	require.NoError(t, err)

	assert.Equal(t, "renamed", updated.Name)
	assert.Equal(t, "original", current.Name, "applyKeyUpdate must not mutate its input")
	assert.NotSame(t, current, updated)
}

func TestApplyKeyUpdateAppliesEveryOptionalField(t *testing.T) {
	current := baseKey()
	name := "renamed"
	revoked := true
	enabled := false
	expires := time.Now().Add(48 * time.Hour).UTC()
	notBefore := time.Now().Add(time.Hour).UTC()

	updated, err := applyKeyUpdate(current, UpdateKeyRequest{
		Name:      &name,
		Tags:      []string{"x", "y"},
		Revoked:   &revoked,
		Enabled:   &enabled,
		ExpiresAt: &expires,
		NotBefore: &notBefore,
	})
	require.NoError(t, err)

	assert.Equal(t, "renamed", updated.Name)
	assert.Equal(t, []string{"x", "y"}, updated.Tags)
	assert.True(t, updated.Revoked)
	assert.False(t, updated.Enabled)
	assert.Equal(t, expires, *updated.ExpiresAt)
	assert.Equal(t, notBefore, *updated.NotBefore)
}

func TestApplyKeyUpdateNilFieldsMeanNoChange(t *testing.T) {
	current := baseKey()

	updated, err := applyKeyUpdate(current, UpdateKeyRequest{})
	require.NoError(t, err)

	assert.Equal(t, current.Name, updated.Name)
	assert.Equal(t, current.Tags, updated.Tags)
	assert.Equal(t, current.Revoked, updated.Revoked)
	assert.Equal(t, current.Enabled, updated.Enabled)
}

func TestApplyKeyUpdateNonNilEmptyTagsClearsTags(t *testing.T) {
	current := baseKey()

	updated, err := applyKeyUpdate(current, UpdateKeyRequest{Tags: []string{}})
	require.NoError(t, err)
	assert.Empty(t, updated.Tags, "a non-nil empty slice clears all tags")
}

func TestApplyKeyUpdateRejectsNilKey(t *testing.T) {
	_, err := applyKeyUpdate(nil, UpdateKeyRequest{})
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/keys/... -run TestApplyKeyUpdate -v`

Expected: FAIL to build — `internal/services/keys/key_update_test.go:…: undefined: applyKeyUpdate`.

- [ ] **Step 3: Implement the pure function**

Create `internal/services/keys/key_update.go`:

```go
package keys

import (
	"fmt"

	"rocketvault/model"
)

// applyKeyUpdate merges an update request onto the current key and returns a
// new entity. It performs no I/O and no authorization: authorization lives
// entirely in the scope passed to the repository.
//
// Nil request fields mean "no change". A non-nil empty Tags slice clears all
// tags, matching the pre-refactor behaviour of UpdateKey.
func applyKeyUpdate(current *model.Key, req UpdateKeyRequest) (*model.Key, error) {
	if current == nil {
		return nil, fmt.Errorf("cannot apply an update to a nil key")
	}

	updated := *current

	if req.Name != nil {
		updated.Name = *req.Name
	}
	if req.Tags != nil {
		updated.Tags = req.Tags
	}
	if req.Revoked != nil {
		updated.Revoked = *req.Revoked
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		updated.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		updated.NotBefore = req.NotBefore
	}

	return &updated, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./internal/services/keys/... -run TestApplyKeyUpdate -v && go test ./...`

Expected: PASS for all five `TestApplyKeyUpdate*` tests and the full suite.

- [ ] **Step 5: Commit**

```bash
git add internal/services/keys/key_update.go internal/services/keys/key_update_test.go
git commit -S -m "refactor(keys): extract applyKeyUpdate as a pure function"
```

---

### Task 19: KeyService read, list, update and delete on a scope

**Files:**
- Modify: `internal/services/keys/key_service.go:74-84` (`UpdateKeyRequest`), `:89-109` (interface), `:347-389` (`GetKey`), `:401-403` (`ListKeys`), `:408-423` (`GetKeyInVault`), `:427-429` (`ListKeysInVault`), `:433-462` (`DeleteKeyInVault`), `:478-515` (`ListKeysWithFilters`), `:527-582` (`UpdateKey`), `:587-630` (`UpdateKeyInVault`), `:645-672` (`DeleteKey`)
- Test: `internal/services/keys/key_scope_service_test.go`

**Interfaces:**
- Consumes: `applyKeyUpdate` (Task 18); `repositories.KeyRepositoryInterface.ReadScoped/UpdateScoped/ListScoped`, `repositories.KeyFilter` (Task 11).
- Produces, on `keys.KeyService`:
  - `GetKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)`
  - `ListKeysScoped(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error)`
  - `UpdateKeyScoped(ctx context.Context, req UpdateKeyRequest) error` — `UpdateKeyRequest` gains `Scope model.Scope`
  - `DeleteKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)`

**B6 note.** `DeleteKeyInVault` today applies a *conjunction*: vault scope from `ReadInVault` **and** ownership from `key.UserID != userID` (`key_service.go:440`). A single `Scope` cannot express AND. `DeleteKeyScoped` therefore keeps one explicitly-temporary in-Go check: when the scope is owner-scoped and carries an advisory vault id, the key's vault must match. That check is deleted in P2 together with `ScopeOwner`, and it is what the P0 B6 tests pin.

- [ ] **Step 1: Write the failing test**

Create `internal/services/keys/key_scope_service_test.go`:

```go
package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestGetKeyScopedPassesTheScopeToTheRepository(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil).Once()

	got, err := svc.GetKeyScoped(ctx, keyID, scope)
	require.NoError(t, err)
	assert.Equal(t, keyID, got.ID)
	repo.AssertExpectations(t)
}

func TestGetKeyScopedEnforcesLifecycle(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, Enabled: false}, nil).Once()

	_, err := svc.GetKeyScoped(ctx, keyID, scope)
	assert.ErrorIs(t, err, ErrKeyLifecycleDenied)
}

func TestListKeysScopedForwardsTheFilter(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	scope := model.NewVaultScope(uuid.New(), uuid.New())
	filter := repositories.KeyFilter{Type: model.KeyTypeRSA, Tags: []string{"prod"}}
	repo.On("ListScoped", ctx, scope, filter).Return([]model.Key{{ID: uuid.New()}}, nil).Once()

	got, err := svc.ListKeysScoped(ctx, scope, filter)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	repo.AssertExpectations(t)
}

func TestUpdateKeyScopedUsesTheSameScopeForReadAndWrite(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	name := "renamed"

	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Name: "original", Enabled: true}, nil).Once()
	repo.On("UpdateScoped", ctx, mock.MatchedBy(func(k *model.Key) bool {
		return k.Name == "renamed"
	}), scope).Return(nil).Once()

	require.NoError(t, svc.UpdateKeyScoped(ctx, UpdateKeyRequest{KeyID: keyID, Scope: scope, Name: &name}))
	repo.AssertExpectations(t)
}

func TestDeleteKeyScopedKeepsTheB6VaultConjunction(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID := uuid.New()
	ownerID := uuid.New()
	requestedVault, actualVault := uuid.New(), uuid.New()
	scope := model.NewOwnerScope(requestedVault, ownerID)

	// The owner predicate matches, but the key lives in another vault.
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: actualVault, Enabled: true}, nil).Once()

	_, err := svc.DeleteKeyScoped(ctx, keyID, scope)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	repo.AssertNotCalled(t, "SoftDelete", mock.Anything, mock.Anything)
}

func TestDeleteKeyScopedSoftDeletesInScope(t *testing.T) {
	repo, svc := newKeyScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())

	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil).Once()
	repo.On("SoftDelete", ctx, keyID).Return(nil).Once()
	repo.On("ReadDeleted", ctx, keyID).Return(&model.Key{ID: keyID}, nil).Once()

	deleted, err := svc.DeleteKeyScoped(ctx, keyID, scope)
	require.NoError(t, err)
	assert.Equal(t, keyID, deleted.ID)
	repo.AssertExpectations(t)
}
```

Add the fixture to the same file, reusing the package's existing key-repository mock (named `mockKeyRepository` in `internal/services/keys/key_soft_delete_test.go:18`):

```go
// newKeyScopeFixture builds a keyService over a mock repository.
func newKeyScopeFixture(t *testing.T) (*mockKeyRepository, *keyService) {
	t.Helper()
	repo := new(mockKeyRepository)
	return repo, &keyService{
		keyRepo:  repo,
		keyCache: nil,
		logger:   newTestKeyLogger(t),
	}
}
```

Reuse whichever logger helper the package already provides; if there is none, build one inline with `logrus.New()` at `PanicLevel` wrapped in `&logging.Logger{Logger: l}`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/keys/... -run 'Scoped' -v`

Expected: FAIL to build — `unknown field Scope in struct literal of type UpdateKeyRequest` and `svc.GetKeyScoped undefined (type *keyService has no field or method GetKeyScoped)`.

- [ ] **Step 3: Implement the scoped methods and shim the old ones**

In `internal/services/keys/key_service.go`, add the field to `UpdateKeyRequest`:

```go
// UpdateKeyRequest represents a request to update an existing key.
type UpdateKeyRequest struct {
	KeyID     uuid.UUID
	Scope     model.Scope // Authorization scope for the read and the write.
	VaultID   uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	UserID    uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	Name      *string     // Optional - nil means no change
	Tags      []string    // Optional - nil means no change; empty slice clears
	Revoked   *bool       // Optional - nil means no change
	Enabled   *bool       // Optional - nil means no change
	ExpiresAt *time.Time  // Optional - nil means no change
	NotBefore *time.Time  // Optional - nil means no change
}
```

Add to the `KeyService` interface:

```go
	// GetKeyScoped retrieves a key authorized by scope and enforces its lifecycle.
	GetKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// ListKeysScoped lists keys authorized by scope and narrowed by filter.
	ListKeysScoped(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error)
	// UpdateKeyScoped updates a key authorized by req.Scope.
	UpdateKeyScoped(ctx context.Context, req UpdateKeyRequest) error
	// DeleteKeyScoped soft-deletes a key authorized by scope.
	DeleteKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
```

Add the canonical implementations:

```go
// GetKeyScoped retrieves a key authorized by scope. The scoped read is the
// access check; a key outside the scope is reported as not found so the
// endpoint is not an existence oracle.
func (s *keyService) GetKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	actor := scope.ActorID().String()
	s.logger.LogAuditInfo(actor, "get_key", "attempt", fmt.Sprintf("Accessing key: %s", keyID))

	key, err := s.keyRepo.ReadScoped(ctx, keyID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "get_key", "failed", fmt.Sprintf("Key not found: %s", keyID), err)
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	if !key.IsAccessible() {
		s.logger.LogAuditError(actor, "get_key", "denied",
			fmt.Sprintf("Key is disabled or outside its valid time window: %s", keyID), nil)
		return nil, fmt.Errorf("%w", ErrKeyLifecycleDenied)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":   key.ID,
		"key_name": key.Name,
		"key_type": key.Type,
		"scope":    scope.String(),
		"revoked":  key.Revoked,
	}).Info("Key accessed successfully")

	s.logger.LogAuditInfo(actor, "get_key", "success",
		fmt.Sprintf("Key accessed: %s (name: %s, type: %s, revoked: %t)", key.ID, key.Name, key.Type, key.Revoked))

	return key, nil
}

// ListKeysScoped lists keys authorized by scope and narrowed by filter.
func (s *keyService) ListKeysScoped(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	keys, err := s.keyRepo.ListScoped(ctx, scope, filter)
	if err != nil {
		s.logger.LogAuditError(scope.ActorID().String(), "list_keys", "failed", "Failed to list keys", err)
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	logrus.WithFields(logrus.Fields{"scope": scope.String(), "key_count": len(keys)}).Info("Keys listed successfully")
	return keys, nil
}

// UpdateKeyScoped updates a key authorized by req.Scope. It reads with the
// scope directly rather than through GetKeyScoped so operators can still
// re-enable a disabled or expired key.
func (s *keyService) UpdateKeyScoped(ctx context.Context, req UpdateKeyRequest) error {
	actor := req.Scope.ActorID().String()
	logrus.WithFields(logrus.Fields{
		"key_id": req.KeyID.String(),
		"scope":  req.Scope.String(),
	}).Info("Updating key")

	key, err := s.keyRepo.ReadScoped(ctx, req.KeyID, req.Scope)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	updatedKey, err := applyKeyUpdate(key, req)
	if err != nil {
		return err
	}

	if err := s.keyRepo.UpdateScoped(ctx, updatedKey, req.Scope); err != nil {
		s.logger.LogAuditError(actor, "update_key", "failed", "Failed to update key", err)
		return fmt.Errorf("failed to update key: %w", err)
	}

	// Evict stale cached material (covers revoke, disable, and expiry changes).
	if s.keyCache != nil {
		s.keyCache.Invalidate(updatedKey.ID)
	}

	s.logger.LogAuditInfo(actor, "update_key", "success", fmt.Sprintf("Key updated: %s", updatedKey.Name))
	return nil
}

// DeleteKeyScoped soft-deletes a key authorized by scope and returns the
// deleted record so callers can read Azure-style deletion metadata.
func (s *keyService) DeleteKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	actor := scope.ActorID().String()

	key, err := s.keyRepo.ReadScoped(ctx, keyID, scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	// B6 conjunction, P1 only: an owner scope may carry an advisory vault id,
	// and the pre-refactor DeleteKeyInVault required BOTH predicates. A Scope
	// cannot express AND, so the vault half stays in Go until P2 retires
	// ScopeOwner from the data plane.
	if _, ownerScoped := scope.OwnerID(); ownerScoped && scope.VaultID() != uuid.Nil && key.VaultID != scope.VaultID() {
		s.logger.LogAuditError(actor, "delete_key", "forbidden", "key does not belong to the requested vault", nil)
		return nil, fmt.Errorf("%w: key does not belong to the requested vault", ErrKeyNotFound)
	}

	if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
		s.logger.LogAuditError(actor, "delete_key", "failed", "Failed to soft-delete key", err)
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	if s.keyCache != nil {
		s.keyCache.Invalidate(keyID)
	}

	deleted, err := s.keyRepo.ReadDeleted(ctx, keyID)
	if err != nil {
		s.logger.LogAuditInfo(actor, "delete_key", "success", "Key deleted (metadata unavailable)")
		return key, nil
	}

	s.logger.LogAuditInfo(actor, "delete_key", "success", "Key deleted successfully")
	return deleted, nil
}
```

Replace the old bodies with shims:

```go
// Deprecated: shim over GetKeyScoped; removed in Phase 6.
func (s *keyService) GetKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	return s.GetKeyScoped(ctx, keyID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over GetKeyScoped; removed in Phase 6.
func (s *keyService) GetKeyInVault(ctx context.Context, keyID, vaultID uuid.UUID) (*model.Key, error) {
	return s.GetKeyScoped(ctx, keyID, model.NewVaultScope(vaultID, uuid.Nil))
}

// Deprecated: shim over ListKeysScoped; removed in Phase 6.
func (s *keyService) ListKeys(ctx context.Context, userID uuid.UUID) ([]model.Key, error) {
	return s.ListKeysScoped(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.KeyFilter{})
}

// Deprecated: shim over ListKeysScoped; removed in Phase 6.
func (s *keyService) ListKeysInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	return s.ListKeysScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.KeyFilter{Type: keyType, Tags: tags})
}

// Deprecated: shim over ListKeysScoped; removed in Phase 6. The isAdmin guard
// is a runtime re-derivation of what the caller already knew; callers migrate
// to model.NewAdminScope in Phase 4.
func (s *keyService) ListKeysWithFilters(ctx context.Context, userID *uuid.UUID, keyType string, tags []string, isAdmin bool) ([]model.Key, error) {
	if !isAdmin && userID == nil {
		s.logger.LogAuditError("unknown", "list_keys_with_filters", "failed", "Non-admin users cannot list all keys", nil)
		return nil, fmt.Errorf("forbidden: non-admin users cannot list all keys")
	}
	scope := model.NewAdminScope(uuid.Nil)
	if userID != nil {
		scope = model.NewOwnerScope(uuid.Nil, *userID)
	}
	return s.ListKeysScoped(ctx, scope, repositories.KeyFilter{Type: keyType, Tags: tags})
}

// Deprecated: shim over UpdateKeyScoped; removed in Phase 6.
func (s *keyService) UpdateKey(ctx context.Context, req UpdateKeyRequest) error {
	req.Scope = model.NewOwnerScope(uuid.Nil, req.UserID)
	return s.UpdateKeyScoped(ctx, req)
}

// Deprecated: shim over UpdateKeyScoped; removed in Phase 6.
func (s *keyService) UpdateKeyInVault(ctx context.Context, req UpdateKeyRequest) error {
	req.Scope = model.NewVaultScope(req.VaultID, req.UserID)
	return s.UpdateKeyScoped(ctx, req)
}

// Deprecated: shim over DeleteKeyScoped; removed in Phase 6.
func (s *keyService) DeleteKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	return s.DeleteKeyScoped(ctx, keyID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over DeleteKeyScoped; removed in Phase 6. The uuid.Nil
// userID sentinel ("skip the ownership check") maps to a plain vault scope.
func (s *keyService) DeleteKeyInVault(ctx context.Context, keyID, vaultID, userID uuid.UUID) (*model.Key, error) {
	if userID == uuid.Nil {
		return s.DeleteKeyScoped(ctx, keyID, model.NewVaultScope(vaultID, uuid.Nil))
	}
	return s.DeleteKeyScoped(ctx, keyID, model.NewOwnerScope(vaultID, userID))
}
```

`internal/services/keys/key_service.go` already imports `repositories`; no new imports are needed.

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Hand-written `KeyService` mocks (`cmd/testutils/test_utils.go`, `cmd/keys/service_test.go`) need the four new methods in the same testify style. Two behaviour notes: `DeleteKeyInVault`'s non-owner path now returns `ErrKeyNotFound` instead of `ErrKeyForbidden` (the spec's "404, not 403" decision), so B6 tests asserting 403 on key delete need their expectation changed to 404 in this commit — call that out in the commit message. `GetKey`'s cross-user path already returned `ErrKeyNotFound`, so it is unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/services/keys/key_service.go internal/services/keys/key_scope_service_test.go cmd/testutils/test_utils.go cmd/keys/service_test.go
git commit -S -m "refactor(keys): scope-aware read, list, update and delete on KeyService"
```

---

### Task 20: CryptoService loadAndAuthorize on a scope

`loadAndAuthorize` (`internal/services/keys/crypto_service.go:239-270`) applies four checks in Go after an unscoped `Read`: vault match, owner match, not revoked, accessible. The first two become the scope; the last two stay, because they are lifecycle, not authorization. All six crypto entry points (`Sign` `:302`, `Verify` `:358`, `Encrypt` `:415`, `Decrypt` `:468`, `WrapKey` `:528`, `UnwrapKey` `:583`) call it.

**Files:**
- Modify: `internal/services/keys/crypto_service.go:239-270` (`loadAndAuthorize`) and its six call sites
- Test: `internal/services/keys/crypto_scope_test.go`

**Interfaces:**
- Consumes: `repositories.KeyRepositoryInterface.ReadScoped` (Task 11); `model.NewOwnerScope` (Task 1).
- Produces: `func (s *cryptoService) loadAndAuthorize(ctx context.Context, keyID uuid.UUID, scope model.Scope, op string) (*model.Key, error)` — unexported; the six request structs keep their `UserID`/`VaultID` fields (handlers build the scope in Phase 4).

- [ ] **Step 1: Write the failing test**

Create `internal/services/keys/crypto_scope_test.go`:

```go
package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func newCryptoScopeFixture(t *testing.T) (*mockKeyRepository, *cryptoService) {
	t.Helper()
	repo := new(mockKeyRepository)
	return repo, &cryptoService{keyRepo: repo, logger: newTestKeyLogger(t)}
}

func TestLoadAndAuthorizeUsesTheScopedRead(t *testing.T) {
	repo, svc := newCryptoScopeFixture(t)
	ctx := context.Background()

	keyID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()
	scope := model.NewOwnerScope(vaultID, ownerID)
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Enabled: true}, nil).Once()

	key, err := svc.loadAndAuthorize(ctx, keyID, scope, "sign")
	require.NoError(t, err)
	assert.Equal(t, keyID, key.ID)
	repo.AssertExpectations(t)
}

func TestLoadAndAuthorizeKeepsTheB6VaultConjunction(t *testing.T) {
	repo, svc := newCryptoScopeFixture(t)
	ctx := context.Background()

	keyID, ownerID := uuid.New(), uuid.New()
	requestedVault, actualVault := uuid.New(), uuid.New()
	scope := model.NewOwnerScope(requestedVault, ownerID)
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: actualVault, Enabled: true}, nil).Once()

	_, err := svc.loadAndAuthorize(ctx, keyID, scope, "sign")
	assert.ErrorIs(t, err, ErrKeyForbidden)
}

func TestLoadAndAuthorizeRejectsRevokedAndInaccessibleKeys(t *testing.T) {
	ctx := context.Background()
	keyID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()
	scope := model.NewOwnerScope(vaultID, ownerID)

	repo, svc := newCryptoScopeFixture(t)
	repo.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Enabled: true, Revoked: true}, nil).Once()
	_, err := svc.loadAndAuthorize(ctx, keyID, scope, "sign")
	assert.ErrorIs(t, err, ErrKeyRevoked)

	repo2, svc2 := newCryptoScopeFixture(t)
	repo2.On("ReadScoped", ctx, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Enabled: false}, nil).Once()
	_, err = svc2.loadAndAuthorize(ctx, keyID, scope, "sign")
	assert.ErrorIs(t, err, ErrKeyLifecycleDenied)
}

func TestLoadAndAuthorizeDeniesOutOfScope(t *testing.T) {
	repo, svc := newCryptoScopeFixture(t)
	ctx := context.Background()

	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, keyID, scope).Return(nil, assert.AnError).Once()

	_, err := svc.loadAndAuthorize(ctx, keyID, scope, "sign")
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/keys/... -run TestLoadAndAuthorize -v`

Expected: FAIL to build — `cannot use scope (variable of type model.Scope) as uuid.UUID value in argument to svc.loadAndAuthorize` and `not enough arguments in call to svc.loadAndAuthorize`.

- [ ] **Step 3: Rewrite loadAndAuthorize around the scope**

Replace `internal/services/keys/crypto_service.go:237-270` with:

```go
// loadAndAuthorize fetches the key authorized by scope and enforces the
// remaining lifecycle rules for op. Authorization (vault membership or
// ownership) lives in the scope; revocation and the validity window do not.
func (s *cryptoService) loadAndAuthorize(ctx context.Context, keyID uuid.UUID, scope model.Scope, op string) (*model.Key, error) {
	actor := scope.ActorID().String()

	key, err := s.keyRepo.ReadScoped(ctx, keyID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, op, "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// B6 conjunction, P1 only: crypto operations required BOTH vault membership
	// and ownership. A Scope cannot express AND, so the vault half stays in Go
	// until P2 gates crypto by Key Vault Crypto User at vault scope.
	if _, ownerScoped := scope.OwnerID(); ownerScoped && scope.VaultID() != uuid.Nil && key.VaultID != scope.VaultID() {
		s.logger.LogAuditError(actor, op, "forbidden",
			fmt.Sprintf("Unauthorized %s attempt: key %s not in vault %s", op, keyID, scope.VaultID()), nil)
		return nil, fmt.Errorf("%w: key does not belong to the requested vault", ErrKeyForbidden)
	}

	if key.Revoked {
		s.logger.LogAuditError(actor, op, "failed",
			fmt.Sprintf("Attempted to %s with revoked key: %s", op, keyID), nil)
		return nil, fmt.Errorf("%w: %s", ErrKeyRevoked, keyID)
	}

	if !key.IsAccessible() {
		s.logger.LogAuditError(actor, op, "failed",
			fmt.Sprintf("Attempted %s with inaccessible key: %s", op, keyID), nil)
		return nil, fmt.Errorf("%w", ErrKeyLifecycleDenied)
	}

	return key, nil
}
```

Update all six call sites to build an owner scope from the request fields (the handlers take over in Phase 4). For example, `Sign` at `:302`:

```go
	key, err := s.loadAndAuthorize(ctx, req.KeyID, model.NewOwnerScope(req.VaultID, req.UserID), "sign")
```

and identically for `Verify` (`"verify"`, `:358`), `Encrypt` (`"encrypt"`, `:415`), `Decrypt` (`"decrypt"`, `:468`), `WrapKey` (`"wrap_key"`, `:528`) and `UnwrapKey` (`"unwrap_key"`, `:583`).

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS, including the P0 B6 tests, which are this task's equivalence proof. One error-message note: an out-of-scope key now fails at the scoped read with `"key not found: …"` rather than at the in-Go owner comparison with `ErrKeyForbidden`; tests asserting `ErrKeyForbidden` for a *cross-user* key must change to assert an error (or `ErrKeyNotFound`), while the cross-*vault* case still returns `ErrKeyForbidden`.

- [ ] **Step 5: Commit**

```bash
git add internal/services/keys/crypto_service.go internal/services/keys/crypto_scope_test.go
git commit -S -m "refactor(keys): authorize crypto operations through a scope"
```

---

### Task 21: CertificateService read, list, update and delete on a scope

**Files:**
- Modify: `internal/services/certificates/certificate_service.go:64-73` (`UpdateCertificateRequest`), `:78-95` (interface), `:409-441` (`GetCertificate`), `:443-445` (`ListCertificates`), `:457-516` (`UpdateCertificate`), `:518-533` (`DeleteCertificate`), `:535-550` (`GetCertificateInVault`), `:552-554` (`ListCertificatesInVault`), `:558-583` (`DeleteCertificateInVault`)
- Test: `internal/services/certificates/certificate_scope_service_test.go`

**Interfaces:**
- Consumes: `repositories.CertificateRepositoryInterface.ReadScoped/UpdateScoped/ListScoped`, `repositories.CertificateFilter` (Task 12).
- Produces, on `certificates.CertificateService`:
  - `GetCertificateScoped(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error)`
  - `ListCertificatesScoped(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error)`
  - `UpdateCertificateScoped(ctx context.Context, req UpdateCertificateRequest) error` — `UpdateCertificateRequest` gains `Scope model.Scope`
  - `DeleteCertificateScoped(ctx context.Context, certID uuid.UUID, scope model.Scope) error`

- [ ] **Step 1: Write the failing test**

Create `internal/services/certificates/certificate_scope_service_test.go`:

```go
package certificates

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func newCertScopeFixture(t *testing.T) (*mockCertRepository, *certificateService) {
	t.Helper()
	repo := new(mockCertRepository)
	return repo, &certificateService{
		certRepo: repo,
		keyRepo:  new(mockKeyRepo),
		logger:   newTestCertLogger(t),
	}
}

func TestGetCertificateScopedPassesTheScopeToTheRepository(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	certID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	repo.On("ReadScoped", ctx, certID, scope).
		Return(&model.Certificate{ID: certID, VaultID: vaultID, Enabled: true}, nil).Once()

	got, err := svc.GetCertificateScoped(ctx, certID, scope)
	require.NoError(t, err)
	assert.Equal(t, certID, got.ID)
	repo.AssertExpectations(t)
}

func TestGetCertificateScopedEnforcesLifecycle(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	certID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, certID, scope).
		Return(&model.Certificate{ID: certID, Enabled: false}, nil).Once()

	_, err := svc.GetCertificateScoped(ctx, certID, scope)
	assert.ErrorIs(t, err, ErrCertLifecycleDenied)
}

func TestGetCertificateScopedDeniesOutOfScope(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, mock.Anything, scope).Return(nil, assert.AnError).Once()

	_, err := svc.GetCertificateScoped(ctx, uuid.New(), scope)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestListCertificatesScopedForwardsTheFilter(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	filter := repositories.CertificateFilter{Tags: []string{"tls"}}
	repo.On("ListScoped", ctx, scope, filter).Return([]model.Certificate{{ID: uuid.New()}}, nil).Once()

	got, err := svc.ListCertificatesScoped(ctx, scope, filter)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	repo.AssertExpectations(t)
}

func TestUpdateCertificateScopedUsesTheSameScopeForReadAndWrite(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	certID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	name := "renamed"

	repo.On("ReadScoped", ctx, certID, scope).
		Return(&model.Certificate{ID: certID, VaultID: vaultID, Name: "original", Enabled: true, RenewalDays: 30}, nil).Once()
	repo.On("UpdateScoped", ctx, mock.MatchedBy(func(c *model.Certificate) bool {
		return c.Name == "renamed"
	}), scope).Return(nil).Once()

	require.NoError(t, svc.UpdateCertificateScoped(ctx, UpdateCertificateRequest{CertID: certID, Scope: scope, Name: &name}))
	repo.AssertExpectations(t)
}

func TestDeleteCertificateScopedChecksScopeFirst(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	certID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, certID, scope).Return(nil, assert.AnError).Once()

	err := svc.DeleteCertificateScoped(ctx, certID, scope)
	assert.ErrorIs(t, err, ErrCertNotFound)
	repo.AssertNotCalled(t, "SoftDelete", mock.Anything, mock.Anything)
}
```

Reuse the package's existing `mockCertRepository` (`cert_soft_delete_test.go:23`) and `mockKeyRepo` (`cert_soft_delete_test.go:127`); if the package has no logger helper, build one inline with `logrus.New()` at `PanicLevel` wrapped in `&logging.Logger{Logger: l}`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/certificates/... -run 'Scoped' -v`

Expected: FAIL to build — `unknown field Scope in struct literal of type UpdateCertificateRequest` and `svc.GetCertificateScoped undefined (type *certificateService has no field or method GetCertificateScoped)`.

- [ ] **Step 3: Implement the scoped methods and shim the old ones**

In `internal/services/certificates/certificate_service.go`, add the field to `UpdateCertificateRequest`:

```go
// UpdateCertificateRequest represents a request to update an existing certificate.
type UpdateCertificateRequest struct {
	CertID      uuid.UUID
	Scope       model.Scope // Authorization scope for the read and the write.
	UserID      uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	Name        *string     // Optional - nil means no change.
	Tags        []string    // Optional - empty means no change.
	AutoRenew   *bool       // Optional - nil means no change.
	RenewalDays *int        // Optional - nil means no change.
	Enabled     *bool       // Optional - nil means no change.
	NotBefore   *time.Time  // Optional - nil means no change.
}
```

Add to the `CertificateService` interface:

```go
	// GetCertificateScoped retrieves a certificate authorized by scope.
	GetCertificateScoped(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error)
	// ListCertificatesScoped lists certificates authorized by scope.
	ListCertificatesScoped(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error)
	// UpdateCertificateScoped updates a certificate authorized by req.Scope.
	UpdateCertificateScoped(ctx context.Context, req UpdateCertificateRequest) error
	// DeleteCertificateScoped soft-deletes a certificate authorized by scope.
	DeleteCertificateScoped(ctx context.Context, certID uuid.UUID, scope model.Scope) error
```

Add the canonical implementations:

```go
// GetCertificateScoped retrieves a certificate authorized by scope and
// enforces its lifecycle policy.
func (s *certificateService) GetCertificateScoped(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	actor := scope.ActorID().String()

	cert, err := s.certRepo.ReadScoped(ctx, certID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "get_certificate", "failed",
			fmt.Sprintf("Certificate not found: %s", certID), err)
		return nil, fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}

	if !cert.IsAccessible() {
		s.logger.LogAuditError(actor, "get_certificate", "denied",
			fmt.Sprintf("Certificate is disabled or outside its valid time window: %s", certID), nil)
		return nil, fmt.Errorf("%w", ErrCertLifecycleDenied)
	}

	return cert, nil
}

// ListCertificatesScoped lists certificates authorized by scope.
func (s *certificateService) ListCertificatesScoped(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	certs, err := s.certRepo.ListScoped(ctx, scope, filter)
	if err != nil {
		s.logger.LogAuditError(scope.ActorID().String(), "list_certificates", "failed", "Failed to list certificates", err)
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	return certs, nil
}

// UpdateCertificateScoped updates a certificate authorized by req.Scope.
func (s *certificateService) UpdateCertificateScoped(ctx context.Context, req UpdateCertificateRequest) error {
	actor := req.Scope.ActorID().String()

	cert, err := s.certRepo.ReadScoped(ctx, req.CertID, req.Scope)
	if err != nil {
		s.logger.LogAuditError(actor, "update_certificate", "failed", "Certificate not found", err)
		return fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}

	updated := *cert
	if req.Name != nil {
		updated.Name = *req.Name
	}
	if req.Tags != nil {
		updated.Tags = req.Tags
	}
	if req.AutoRenew != nil {
		updated.AutoRenew = *req.AutoRenew
	}
	if req.RenewalDays != nil {
		updated.RenewalDays = *req.RenewalDays
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.NotBefore != nil {
		updated.NotBefore = req.NotBefore
	}

	if err := s.certRepo.UpdateScoped(ctx, &updated, req.Scope); err != nil {
		s.logger.LogAuditError(actor, "update_certificate", "failed", "Failed to update certificate", err)
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	s.logger.LogAuditInfo(actor, "update_certificate", "success", fmt.Sprintf("Certificate updated: %s", updated.Name))
	return nil
}

// DeleteCertificateScoped soft-deletes a certificate authorized by scope.
func (s *certificateService) DeleteCertificateScoped(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	actor := scope.ActorID().String()

	cert, err := s.certRepo.ReadScoped(ctx, certID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "delete_certificate", "failed", "Certificate not found", err)
		return fmt.Errorf("%w: %s", ErrCertNotFound, err.Error())
	}

	if err := s.certRepo.SoftDelete(ctx, certID); err != nil {
		s.logger.LogAuditError(actor, "delete_certificate", "failed", "Failed to soft-delete certificate", err)
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	s.logger.LogAuditInfo(actor, "delete_certificate", "success", fmt.Sprintf("Certificate deleted: %s", cert.Name))
	return nil
}
```

Replace the old bodies with shims:

```go
// Deprecated: shim over GetCertificateScoped; removed in Phase 6.
func (s *certificateService) GetCertificate(ctx context.Context, certID, userID uuid.UUID) (*model.Certificate, error) {
	return s.GetCertificateScoped(ctx, certID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over GetCertificateScoped; removed in Phase 6.
func (s *certificateService) GetCertificateInVault(ctx context.Context, certID, vaultID uuid.UUID) (*model.Certificate, error) {
	return s.GetCertificateScoped(ctx, certID, model.NewVaultScope(vaultID, uuid.Nil))
}

// Deprecated: shim over ListCertificatesScoped; removed in Phase 6.
func (s *certificateService) ListCertificates(ctx context.Context, userID uuid.UUID) ([]model.Certificate, error) {
	return s.ListCertificatesScoped(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.CertificateFilter{})
}

// Deprecated: shim over ListCertificatesScoped; removed in Phase 6.
func (s *certificateService) ListCertificatesInVault(ctx context.Context, vaultID uuid.UUID) ([]model.Certificate, error) {
	return s.ListCertificatesScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.CertificateFilter{})
}

// Deprecated: shim over UpdateCertificateScoped; removed in Phase 6.
func (s *certificateService) UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error {
	req.Scope = model.NewOwnerScope(uuid.Nil, req.UserID)
	return s.UpdateCertificateScoped(ctx, req)
}

// Deprecated: shim over DeleteCertificateScoped; removed in Phase 6.
func (s *certificateService) DeleteCertificate(ctx context.Context, certID, userID uuid.UUID) error {
	return s.DeleteCertificateScoped(ctx, certID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over DeleteCertificateScoped; removed in Phase 6.
func (s *certificateService) DeleteCertificateInVault(ctx context.Context, certID, vaultID uuid.UUID) error {
	return s.DeleteCertificateScoped(ctx, certID, model.NewVaultScope(vaultID, uuid.Nil))
}
```

- [ ] **Step 4: Regenerate mocks and run the full suite**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Hand-written `CertificateService` mocks (`cmd/testutils/test_utils.go`, `cmd/certificates/service_test.go`) need the four new methods in the same testify style. `GetCertificate`'s error for a certificate owned by another user changes from whatever the old in-Go comparison produced to a wrapped `ErrCertNotFound`; update assertions to `assert.ErrorIs(t, err, certificates.ErrCertNotFound)`.

- [ ] **Step 5: Commit**

```bash
git add internal/services/certificates/certificate_service.go internal/services/certificates/certificate_scope_service_test.go cmd/testutils/test_utils.go cmd/certificates/service_test.go
git commit -S -m "refactor(certificates): scope-aware read, list, update and delete on CertificateService"
```

---

### Task 22: Generic retried[T] helper for the retry decorators

`internal/services/retry/retry_secret_service.go` is ~293 lines of `var result T; var err error; retryErr := …; return result, retryErr` boilerplate repeated for every method.

**Files:**
- Create: `internal/services/retry/retried.go`
- Modify: `internal/services/retry/retry_secret_service.go` (all value-returning methods)
- Test: `internal/services/retry/retried_test.go`

**Interfaces:**
- Consumes: `RetryService.ExecuteDatabaseOperation(ctx context.Context, op func() error) error`.
- Produces: `func retried[T any](ctx context.Context, rs RetryService, op func() (T, error)) (T, error)` — unexported, package `retry`.

- [ ] **Step 1: Write the failing test**

Create `internal/services/retry/retried_test.go`:

```go
package retry

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRetryService runs the operation exactly attempts times, stopping early on
// success, so retried's plumbing can be tested without real backoff.
type stubRetryService struct {
	attempts int
	calls    int
}

func (s *stubRetryService) ExecuteDatabaseOperation(ctx context.Context, op func() error) error {
	var err error
	for i := 0; i < s.attempts; i++ {
		s.calls++
		if err = op(); err == nil {
			return nil
		}
	}
	return err
}

func TestRetriedReturnsTheValueOnSuccess(t *testing.T) {
	rs := &stubRetryService{attempts: 3}

	got, err := retried(context.Background(), rs, func() (string, error) { return "ok", nil })
	require.NoError(t, err)
	assert.Equal(t, "ok", got)
	assert.Equal(t, 1, rs.calls)
}

func TestRetriedRetriesUntilSuccess(t *testing.T) {
	rs := &stubRetryService{attempts: 3}
	calls := 0

	got, err := retried(context.Background(), rs, func() (int, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("transient")
		}
		return 42, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 42, got)
	assert.Equal(t, 3, calls)
}

func TestRetriedPropagatesTheFinalError(t *testing.T) {
	rs := &stubRetryService{attempts: 2}
	boom := errors.New("permanent")

	got, err := retried(context.Background(), rs, func() (*string, error) { return nil, boom })
	assert.ErrorIs(t, err, boom)
	assert.Nil(t, got)
}

func TestRetriedReturnsTheZeroValueOnFailure(t *testing.T) {
	rs := &stubRetryService{attempts: 1}

	got, err := retried(context.Background(), rs, func() ([]int, error) {
		return []int{1, 2, 3}, errors.New("partial result must not be returned as success")
	})
	require.Error(t, err)
	assert.Equal(t, []int{1, 2, 3}, got, "retried returns the last value alongside the error, matching the existing decorators")
}
```

If the `RetryService` interface in this package declares methods beyond `ExecuteDatabaseOperation`, add them to `stubRetryService` as no-ops returning `nil` so it satisfies the interface.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/retry/... -run TestRetried -v`

Expected: FAIL to build — `internal/services/retry/retried_test.go:…: undefined: retried`.

- [ ] **Step 3: Implement the helper and collapse the decorators**

Create `internal/services/retry/retried.go`:

```go
package retry

import "context"

// retried runs a value-returning operation under the retry policy, removing the
// var/closure/return boilerplate repeated across every decorator method. The
// last observed value is returned alongside any error, matching the behaviour
// of the hand-written decorators it replaces.
func retried[T any](ctx context.Context, rs RetryService, op func() (T, error)) (T, error) {
	var result T
	var opErr error

	retryErr := rs.ExecuteDatabaseOperation(ctx, func() error {
		result, opErr = op()
		return opErr
	})

	return result, retryErr
}
```

Rewrite every value-returning method in `internal/services/retry/retry_secret_service.go` through it. For example, `GetSecret` (`:59-69`) becomes:

```go
// GetSecret retrieves a secret with retry logic for database operations.
func (s *retrySecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	return retried(ctx, s.retryService, func() (*model.Secret, error) {
		return s.baseService.GetSecret(ctx, secretID, userID)
	})
}
```

Apply the same shape to `CreateSecret`, `ListSecrets`, `GetSecretInVault`, `ListSecretsInVault`, `GetSecretVersions`, `GetSecretVersion`, `GetLatestSecretVersion`, `GetSecretVersionsInVault`, `GetSecretVersionInVault`, `GetLatestSecretVersionInVault`, `GenerateSecret`, `ExportSecrets`, `ImportSecrets`, `ListDeletedSecretsInVault`, `IsSecretSoftDeletedInVault`, `IsSecretSoftDeletedForUser`, and the scoped methods added in Tasks 14-17 (`GetSecretScoped`, `ListSecretsScoped`, `ListDeletedSecretsScoped`, `GetSecretVersionsScoped`, `GetSecretVersionScoped`, `GetLatestSecretVersionScoped`). Leave the error-only methods (`UpdateSecret`, `UpdateSecretInVault`, `UpdateSecretScoped`, `DeleteSecret`, `DeleteSecretInVault`, `DeleteSecretScoped`, `RecoverSecret*`, `PurgeSecret*`) as direct `ExecuteDatabaseOperation` calls — they have no boilerplate to remove.

Apply the same collapse to the value-returning methods of `internal/services/retry/retry_repository_wrapper.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS, including `internal/services/retry/retry_wrappers_test.go`, which is the equivalence proof for this mechanical change. Confirm the shrink with `wc -l internal/services/retry/retry_secret_service.go` — the target from the spec is roughly a third of the original length.

- [ ] **Step 5: Commit**

```bash
git add internal/services/retry/retried.go internal/services/retry/retried_test.go internal/services/retry/retry_secret_service.go internal/services/retry/retry_repository_wrapper.go
git commit -S -m "refactor(retry): collapse decorator boilerplate onto a generic retried helper"
```

---
## Phase 4 — Handlers, then CLI

### Task 23: scopeFromRequest, ownerScopeFromRequest and writeSecretError

**Files:**
- Modify: `api/context.go` (add the two scope helpers; `isVaultScopedRoute` at `:52-59` stays until Task 28)
- Create: `api/errors_secret.go`
- Test: `api/scope_helpers_test.go`

**Interfaces:**
- Consumes: `vaultIDFromRequest(r *http.Request) (uuid.UUID, error)` (`api/context.go:44`); `userIDFromClaims(c *Context) (uuid.UUID, bool)` (`api/soft_delete.go:418`); `model.NewVaultScope`, `model.NewOwnerScope` (Task 1); `secrets.ErrSecretNotFound`, `secrets.ErrSecretLifecycleDenied`.
- Produces:
  - `func scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool)`
  - `func ownerScopeFromRequest(c *Context, r *http.Request) (model.Scope, bool)`
  - `func writeSecretError(c *Context, err error)`

Both helpers set `c.Err` and return `false` on failure, so a handler's call site is `scope, ok := scopeFromRequest(c, r); if !ok { return }`.

- [ ] **Step 1: Write the failing test**

Create `api/scope_helpers_test.go`:

```go
package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// newScopeRequest builds a request carrying a resolved vault id and, when
// vaultName is non-empty, the vault_name route variable that marks a
// vault-scoped route.
func newScopeRequest(t *testing.T, vaultID uuid.UUID, vaultName string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/"+uuid.NewString(), nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	if vaultName != "" {
		r = mux.SetURLVars(r, map[string]string{"vault_name": vaultName})
	}
	return r
}

func newScopeContext(userID uuid.UUID) *Context {
	return &Context{Claims: jwt.MapClaims{"user_id": userID.String()}}
}

func TestScopeFromRequestVaultScopedRouteYieldsVaultScope(t *testing.T) {
	vaultID, userID := uuid.New(), uuid.New()
	c := newScopeContext(userID)

	scope, ok := scopeFromRequest(c, newScopeRequest(t, vaultID, "team-a"))
	require.True(t, ok)
	assert.Equal(t, model.ScopeVault, scope.Kind())
	assert.Equal(t, vaultID, scope.VaultID())
	assert.Equal(t, userID, scope.ActorID(), "the actor travels for audit")
	assert.NoError(t, scope.Validate())
}

func TestScopeFromRequestFlatRouteYieldsOwnerScope(t *testing.T) {
	vaultID, userID := uuid.New(), uuid.New()
	c := newScopeContext(userID)

	scope, ok := scopeFromRequest(c, newScopeRequest(t, vaultID, ""))
	require.True(t, ok)
	assert.Equal(t, model.ScopeOwner, scope.Kind())

	owner, isOwner := scope.OwnerID()
	require.True(t, isOwner)
	assert.Equal(t, userID, owner)
	assert.NoError(t, scope.Validate())
}

func TestOwnerScopeFromRequestAlwaysYieldsOwnerScope(t *testing.T) {
	vaultID, userID := uuid.New(), uuid.New()
	c := newScopeContext(userID)

	for _, vaultName := range []string{"", "team-a"} {
		scope, ok := ownerScopeFromRequest(c, newScopeRequest(t, vaultID, vaultName))
		require.True(t, ok)
		assert.Equal(t, model.ScopeOwner, scope.Kind())
		assert.Equal(t, vaultID, scope.VaultID(), "the advisory vault id carries the B6 conjunction")

		owner, isOwner := scope.OwnerID()
		require.True(t, isOwner)
		assert.Equal(t, userID, owner)
	}
}

func TestScopeHelpersFailClosedWithoutAUserClaim(t *testing.T) {
	c := &Context{Claims: jwt.MapClaims{}}
	r := newScopeRequest(t, uuid.New(), "team-a")

	scope, ok := scopeFromRequest(c, r)
	assert.False(t, ok)
	assert.Equal(t, model.ScopeInvalid, scope.Kind())
	require.NotNil(t, c.Err)

	c2 := &Context{Claims: jwt.MapClaims{}}
	scope2, ok2 := ownerScopeFromRequest(c2, r)
	assert.False(t, ok2)
	assert.Equal(t, model.ScopeInvalid, scope2.Kind())
	require.NotNil(t, c2.Err)
}

func TestWriteSecretErrorMapsEachCase(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		statusCode int
	}{
		{"not found", secrets.ErrSecretNotFound, http.StatusNotFound},
		{"wrapped not found", errors.Join(secrets.ErrSecretNotFound, errors.New("ctx")), http.StatusNotFound},
		{"lifecycle denied", secrets.ErrSecretLifecycleDenied, http.StatusForbidden},
		{"anything else", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Context{}
			writeSecretError(c, tc.err)
			require.NotNil(t, c.Err)
			assert.Equal(t, tc.statusCode, c.Err.StatusCode)
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run 'TestScopeFromRequest|TestOwnerScopeFromRequest|TestScopeHelpersFailClosed|TestWriteSecretError' -v`

Expected: FAIL to build — `api/scope_helpers_test.go:…: undefined: scopeFromRequest`, `undefined: ownerScopeFromRequest`, `undefined: writeSecretError`.

- [ ] **Step 3: Add the helpers**

Add to `api/context.go`, directly below `isVaultScopedRoute`:

```go
// scopeFromRequest builds the authorization scope for a resource operation.
//
// Vault-scoped routes (/api/v1/vaults/{vault_name}/...) yield a vault scope, so
// any vault member may act. Legacy flat routes yield an owner scope, preserving
// pre-multi-vault per-user visibility. P2 collapses both onto the vault scope.
//
// It sets c.Err and returns false when the caller's identity cannot be
// determined, so a handler can never proceed with an invalid scope.
func scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return model.Scope{}, false
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return model.Scope{}, false
	}

	if isVaultScopedRoute(r) {
		return model.NewVaultScope(vaultID, userID), true
	}
	return model.NewOwnerScope(vaultID, userID), true
}

// ownerScopeFromRequest always yields an owner scope, regardless of route shape.
// It marks the B6 handlers — key crypto operations and key delete — which are
// owner-gated on both route shapes today. The advisory vault id carries the
// vault half of that conjunction. Removed in P2.
func ownerScopeFromRequest(c *Context, r *http.Request) (model.Scope, bool) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return model.Scope{}, false
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return model.Scope{}, false
	}

	return model.NewOwnerScope(vaultID, userID), true
}
```

These two functions are the sole exception to the repo-wide `model.Scope{}` composite-literal ban: they return the zero value only on the failure path, where the caller must not proceed. Add `//nolint:exhaustruct // deliberate fail-closed zero value` above each return if the linter objects, and record the exception in the Task 34 grep gate.

Create `api/errors_secret.go`:

```go
package api

import (
	"errors"

	"rocketvault/internal/services/secrets"
)

// writeSecretError maps a secret-service error onto an HTTP response. It
// replaces the identical three-way errors.Is chain that was repeated across
// getSecret, updateSecret, deleteSecret and the three version handlers — and
// with it the inconsistency where listSecretVersionsHandler returned 500 for a
// wrong-vault lookup while its two siblings returned 404.
func writeSecretError(c *Context, err error) {
	switch {
	case errors.Is(err, secrets.ErrSecretLifecycleDenied):
		c.SetPermissionError("secret is disabled or outside its valid time window")
	case errors.Is(err, secrets.ErrSecretNotFound):
		c.SetNotFound("secret")
	default:
		c.SetInternalError(err)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./api/... -run 'TestScopeFromRequest|TestOwnerScopeFromRequest|TestScopeHelpersFailClosed|TestWriteSecretError' -v && go test ./...`

Expected: PASS. Nothing calls the helpers yet, so the rest of the suite is unaffected.

- [ ] **Step 5: Commit**

```bash
git add api/context.go api/errors_secret.go api/scope_helpers_test.go
git commit -S -m "feat(api): add scopeFromRequest, ownerScopeFromRequest and writeSecretError"
```

---

### Task 24: Secret handlers onto scopes

Eight `isVaultScopedRoute` branches collapse. `listSecretVersionsHandler`'s 500-on-wrong-vault becomes a 404, matching its two siblings.

**Files:**
- Modify: `api/secrets.go:82-125` (`listSecretVersionsHandler`), `:128-172` (`getSecretVersionHandler`), `:175-218` (`getLatestSecretVersionHandler`), `:222-292` (`exportSecrets`), `:296-384` (`importSecrets`), `:483-541` (`listSecrets`), `:545-620` (`getSecret`), `:624-781` (`updateSecret`), `:784-823` (`deleteSecret`)
- Test: `api/secrets_scope_test.go`

**Interfaces:**
- Consumes: `scopeFromRequest`, `writeSecretError` (Task 23); `SecretService.GetSecretScoped`, `ListSecretsScoped`, `DeleteSecretScoped`, `UpdateSecretScoped` (Tasks 14-15); `GetSecretVersionsScoped`, `GetSecretVersionScoped`, `GetLatestSecretVersionScoped` (Task 17).
- Produces: no new exported symbols. `secrets.ExportSecretsRequest` and `secrets.ImportSecretsRequest` gain a `Scope model.Scope` field set by the handlers.

- [ ] **Step 1: Write the failing test**

Create `api/secrets_scope_test.go`:

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// TestListSecretVersionsWrongVaultReturns404 pins the deliberate 500 -> 404
// correction from spec §1: listSecretVersionsHandler returned 500 for a
// wrong-vault lookup while getSecretVersionHandler and
// getLatestSecretVersionHandler returned 404.
func TestListSecretVersionsWrongVaultReturns404(t *testing.T) {
	secretID := uuid.New()
	svc := &scopeStubSecretService{
		versionsScopedErr: secrets.ErrSecretNotFound,
	}
	c, w, r := newSecretHandlerFixture(t, svc, secretID, "team-a")

	listSecretVersionsHandler(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
}

func TestGetSecretUsesTheScopeFromTheRoute(t *testing.T) {
	secretID := uuid.New()
	svc := &scopeStubSecretService{
		secret: &model.Secret{ID: secretID, Name: "s", Value: "v", Enabled: true},
	}

	c, w, r := newSecretHandlerFixture(t, svc, secretID, "team-a")
	getSecret(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())

	c, w, r = newSecretHandlerFixture(t, svc, secretID, "")
	getSecret(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
}

func TestGetSecretMapsLifecycleDenialTo403(t *testing.T) {
	secretID := uuid.New()
	svc := &scopeStubSecretService{secretErr: secrets.ErrSecretLifecycleDenied}
	c, w, r := newSecretHandlerFixture(t, svc, secretID, "team-a")

	getSecret(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)
}

func TestDeleteSecretAlwaysUsesAVaultScope(t *testing.T) {
	secretID := uuid.New()
	svc := &scopeStubSecretService{}

	// deleteSecret was already vault-scoped on both route shapes before the
	// refactor; that must not change.
	c, w, r := newSecretHandlerFixture(t, svc, secretID, "")
	r.Method = http.MethodDelete
	deleteSecret(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}

func TestListSecretsUsesTheScopeFromTheRoute(t *testing.T) {
	svc := &scopeStubSecretService{list: []model.Secret{{ID: uuid.New(), Name: "a"}}}

	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "team-a")
	listSecrets(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
	assert.Equal(t, http.StatusOK, w.Code)
}
```

Add the stub and fixture in the same file. `scopeStubSecretService` embeds `secrets.SecretService` so only the methods under test need bodies; the embedded nil interface panics loudly if a handler calls anything else, which is the desired signal:

```go
type scopeStubSecretService struct {
	secrets.SecretService

	secret            *model.Secret
	secretErr         error
	list              []model.Secret
	listErr           error
	versionsScopedErr error
	lastScope         model.Scope
}

func (s *scopeStubSecretService) GetSecretScoped(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Secret, error) {
	s.lastScope = scope
	return s.secret, s.secretErr
}

func (s *scopeStubSecretService) ListSecretsScoped(_ context.Context, scope model.Scope, _ []string) ([]model.Secret, error) {
	s.lastScope = scope
	return s.list, s.listErr
}

func (s *scopeStubSecretService) DeleteSecretScoped(_ context.Context, _ uuid.UUID, scope model.Scope) error {
	s.lastScope = scope
	return nil
}

func (s *scopeStubSecretService) GetSecretVersionsScoped(_ context.Context, _ uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	s.lastScope = scope
	return nil, s.versionsScopedErr
}

// newSecretHandlerFixture wires a Context whose service container returns svc,
// reusing newSecretCtx from api/secrets_handlers_test.go:324 rather than
// introducing a second wiring style. vaultName != "" marks a vault-scoped route.
func newSecretHandlerFixture(t *testing.T, svc secrets.SecretService, secretID uuid.UUID,
	vaultName string) (*Context, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	c := newSecretCtx(svc)
	c.Params.SecretID = secretID.String()

	return c, httptest.NewRecorder(), newScopeRequest(t, uuid.New(), vaultName)
}
```

`newSecretCtx` sets `Claims["user_id"]` to the package constant `secretHTestUserID` (`api/secrets_handlers_test.go:322`), which is what `scopeFromRequest` reads through `userIDFromClaims`. `newScopeRequest` comes from `api/scope_helpers_test.go` (Task 23) and is in the same package.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run 'TestListSecretVersionsWrongVaultReturns404|TestGetSecretUsesTheScope|TestDeleteSecretAlwaysUsesAVaultScope|TestListSecretsUsesTheScope' -v`

Expected: FAIL — `TestListSecretVersionsWrongVaultReturns404` fails with `expected: 404, actual: 500` (the current handler calls `c.SetInternalError(err)`), and the scope assertions fail to build because the handlers still call `GetSecretInVault`/`GetSecret` rather than `GetSecretScoped`.

- [ ] **Step 3: Rewrite the eight branch sites**

`listSecretVersionsHandler` (`api/secrets.go:82-125`) — the whole `if isVaultScopedRoute(r) { … } else { … }` block becomes:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	versions, err := secretService.GetSecretVersionsScoped(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
```

`getSecretVersionHandler` (`:128-172`):

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := secretService.GetSecretVersionScoped(r.Context(), secretID, versionNum, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
```

`getLatestSecretVersionHandler` (`:175-218`):

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := secretService.GetLatestSecretVersionScoped(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
```

`listSecrets` (`:483-541`):

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	secretsList, err := secretService.ListSecretsScoped(r.Context(), scope, c.Params.Tags)
	if err != nil {
		writeSecretError(c, err)
		return
	}
```

`getSecret` (`:545-620`):

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	secret, err := secretService.GetSecretScoped(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
```

`updateSecret` (`:624-781`) — replace the `vaultScoped`/`vaultID` plumbing at `:677-699` and the dispatch at `:752-757`:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	secret, err := secretService.GetSecretScoped(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
```

and, after the existing field-merge and `secret.Version++` block:

```go
	updateReq := secrets.UpdateSecretRequest{
		SecretID:    secret.ID,
		Scope:       scope,
		Name:        &secret.Name,
		Value:       &secret.Value,
		Tags:        &secret.Tags,
		ContentType: req.ContentType,
		Enabled:     req.Enabled,
		ExpiresAt:   req.ExpiresAt,
		NotBefore:   req.NotBefore,
	}
	if err := secretService.UpdateSecretScoped(r.Context(), updateReq); err != nil {
		writeSecretError(c, err)
		return
	}
```

The `userIDStr`/`userID` block at `:657-668` is still needed for the trailing `c.Logger.Printf` — keep it, or switch the log line to `scope.ActorID()` and delete the block.

`deleteSecret` (`:784-823`) is already vault-scoped on both route shapes; build the scope explicitly rather than via `scopeFromRequest`, so that stays true:

```go
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}
	scope := model.NewVaultScope(vaultID, userID)

	if err := secretService.DeleteSecretScoped(r.Context(), secretID, scope); err != nil {
		writeSecretError(c, err)
		return
	}
```

`exportSecrets` (`:261-268`) and `importSecrets` (`:352-359`) — replace the `if isVaultScopedRoute(r) { serviceReq.VaultID = vaultID }` blocks with a scope. Add `Scope model.Scope` to `secrets.ExportSecretsRequest` (`internal/services/secrets/secret_service.go:87-93`) and `secrets.ImportSecretsRequest` (`:96-102`), and in `ExportSecrets` (`:962`) replace the `if req.VaultID != uuid.Nil { … } else { … }` dispatch at `:978-982` with a single `s.ListSecretsScoped(ctx, req.Scope, req.FilterTags)`. In `ImportSecrets` (`:1056`) set `VaultID: req.Scope.ResolvedVaultID()` on the `CreateSecretRequest` at `:1123`. The handler sites become:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}
	serviceReq.Scope = scope
```

Keep `ExportSecretsRequest.VaultID` and `ImportSecretsRequest.VaultID` as deprecated shim fields until Phase 6, and have the legacy `VaultID`-only callers keep working by defaulting `req.Scope` when it is invalid:

```go
	scope := req.Scope
	if scope.Validate() != nil {
		if req.VaultID != uuid.Nil {
			scope = model.NewVaultScope(req.VaultID, req.UserID)
		} else {
			scope = model.NewOwnerScope(uuid.Nil, req.UserID)
		}
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS, including the new 404 assertion. `api/secrets_handlers_test.go`, `api/vault_scoped_routes_test.go` and the P0 cross-vault regression tests are the equivalence proof; the only expectation that legitimately changes is `listSecretVersionsHandler`'s wrong-vault status, 500 → 404. Update that one assertion and note it in the commit message.

- [ ] **Step 5: Commit**

```bash
git add api/secrets.go api/secrets_scope_test.go api/secrets_handlers_test.go internal/services/secrets/secret_service.go
git commit -S -m "refactor(api): drive secret handlers from a scope and unify error mapping"
```

---

### Task 25: Soft-delete handlers onto scopes

`authorizeSecretSoftDeleteOp` (`api/soft_delete.go:59-91`) is the TOCTOU pre-check that Task 16 replaced with an in-service scoped check. Delete it.

**Files:**
- Modify: `api/soft_delete.go:13-54` (`listDeletedSecrets`), `:56-91` (`authorizeSecretSoftDeleteOp` — delete), `:93-117` (`recoverSecret`), `:119-142` (`purgeSecret`)
- Test: `api/soft_delete_scope_test.go`

**Interfaces:**
- Consumes: `scopeFromRequest`, `writeSecretError`, `newScopeRequest` (Task 23); `newSecretHandlerFixture` (Task 24 — this task's tests reuse it, so Task 24 must land first); `SecretService.ListDeletedSecretsScoped` (Task 14), `RecoverSecretScoped`, `PurgeSecretScoped` (Task 16).
- Produces: no new symbols. Removes `authorizeSecretSoftDeleteOp`.

- [ ] **Step 1: Write the failing test**

Create `api/soft_delete_scope_test.go`:

```go
package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

type scopeStubSoftDeleteService struct {
	secrets.SecretService

	deleted     []model.Secret
	recoverErr  error
	purgeErr    error
	lastScope   model.Scope
	recoverCalls int
	purgeCalls   int
}

func (s *scopeStubSoftDeleteService) ListDeletedSecretsScoped(_ context.Context, scope model.Scope) ([]model.Secret, error) {
	s.lastScope = scope
	return s.deleted, nil
}

func (s *scopeStubSoftDeleteService) RecoverSecretScoped(_ context.Context, _ uuid.UUID, scope model.Scope) error {
	s.lastScope = scope
	s.recoverCalls++
	return s.recoverErr
}

func (s *scopeStubSoftDeleteService) PurgeSecretScoped(_ context.Context, _ uuid.UUID, scope model.Scope) error {
	s.lastScope = scope
	s.purgeCalls++
	return s.purgeErr
}

func TestRecoverSecretPassesTheScopeAndDropsThePreCheck(t *testing.T) {
	svc := &scopeStubSoftDeleteService{}
	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "team-a")

	recoverSecret(c, w, r)

	require.Nil(t, c.Err)
	assert.Equal(t, 1, svc.recoverCalls, "the service performs the authorization; no handler pre-check")
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}

func TestRecoverSecretOutOfScopeReturns404(t *testing.T) {
	svc := &scopeStubSoftDeleteService{recoverErr: secrets.ErrSecretNotFound}
	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "team-a")

	recoverSecret(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
}

func TestPurgeSecretOutOfScopeReturns404(t *testing.T) {
	svc := &scopeStubSoftDeleteService{purgeErr: secrets.ErrSecretNotFound}
	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "")

	purgeSecret(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind(), "flat routes keep per-user visibility in P1")
}

func TestListDeletedSecretsUsesAVaultScope(t *testing.T) {
	svc := &scopeStubSoftDeleteService{deleted: []model.Secret{{ID: uuid.New(), Name: "gone"}}}
	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "team-a")

	listDeletedSecrets(c, w, r)

	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run 'TestRecoverSecretPassesTheScope|TestRecoverSecretOutOfScope|TestPurgeSecretOutOfScope|TestListDeletedSecretsUsesAVaultScope' -v`

Expected: FAIL to build — the stub does not satisfy the calls the handlers make (`IsSecretSoftDeletedInVault`, `RecoverSecret`), so the embedded nil `secrets.SecretService` panics: `panic: runtime error: invalid memory address or nil pointer dereference`.

- [ ] **Step 3: Rewrite the handlers and delete the pre-check**

`listDeletedSecrets` (`api/soft_delete.go:18-54`) — replace the `vaultIDFromRequest` block with a vault scope. This handler is vault-scoped on both route shapes today, so build it explicitly:

```go
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	secretSvc := c.secretSvc()
	if secretSvc == nil {
		return
	}

	secrets, err := secretSvc.ListDeletedSecretsScoped(r.Context(), model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}
```

Delete `authorizeSecretSoftDeleteOp` entirely (`:56-91`), including its `secretServices` import if nothing else in the file uses it.

`recoverSecret` (`:93-117`):

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := secretSvc.RecoverSecretScoped(r.Context(), secretID, scope); err != nil {
		writeSecretError(c, err)
		return
	}
```

`purgeSecret` (`:119-142`):

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := secretSvc.PurgeSecretScoped(r.Context(), secretID, scope); err != nil {
		writeSecretError(c, err)
		return
	}
```

Add `"rocketvault/model"` to the file's imports.

The key and certificate soft-delete handlers (`listDeletedKeys` `:145`, `getDeletedKey` `:181`, `recoverKey` `:217`, `purgeKey` `:259`, `listDeletedCertificates` `:300`, `recoverCertificate` `:334`, `purgeCertificate` `:376`) go through repositories directly and are registered only on the flat routes (`:450-462`); they are out of P1 scope and stay unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS. `api/soft_delete_test.go` and `api/soft_delete_extended_test.go` are the equivalence proof. Tests that stub `IsSecretSoftDeletedInVault`/`IsSecretSoftDeletedForUser` to drive these handlers must switch to stubbing `RecoverSecretScoped`/`PurgeSecretScoped`, because the pre-check no longer exists.

- [ ] **Step 5: Commit**

```bash
git add api/soft_delete.go api/soft_delete_scope_test.go api/soft_delete_test.go api/soft_delete_extended_test.go
git commit -S -m "refactor(api): scope the secret soft-delete handlers and drop the TOCTOU pre-check"
```

---
### Task 26: Key handlers onto scopes

Three `isVaultScopedRoute` branches collapse (`listKeys` `:381`, `getKey` `:439`, `updateKey` `:527`). The seven B6 handlers — `deleteKey` and the six crypto operations — switch to `ownerScopeFromRequest`, which is what keeps the P0 B6 tests green.

**Files:**
- Modify: `api/keys.go:374-421` (`listKeys`), `:424-483` (`getKey`), `:485-590` (`updateKey`), `:592-653` (`deleteKey`), `:732-809` (`wrapKey`), `:811-888` (`unwrapKey`), `:890-968` (`signKey`), `:970-1051` (`verifyKey`), `:1053-1136` (`encryptKey`), `:1138-1222` (`decryptKey`)
- Test: `api/keys_scope_test.go`

**Interfaces:**
- Consumes: `scopeFromRequest`, `ownerScopeFromRequest` (Task 23); `KeyService.GetKeyScoped`, `ListKeysScoped`, `UpdateKeyScoped`, `DeleteKeyScoped` (Task 19); `repositories.KeyFilter` (Task 11).
- Produces: no new symbols.

The crypto handlers keep passing `UserID` and `VaultID` on their request structs — Task 20 left those fields in place and builds the scope inside `crypto_service.go`. Only `deleteKey` changes service call shape here.

- [ ] **Step 1: Write the failing test**

Create `api/keys_scope_test.go`:

```go
package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

type scopeStubKeyService struct {
	keyservices.KeyService

	key       *model.Key
	keyErr    error
	list      []model.Key
	deleted   *model.Key
	deleteErr error
	lastScope model.Scope
	lastFilter repositories.KeyFilter
}

func (s *scopeStubKeyService) GetKeyScoped(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Key, error) {
	s.lastScope = scope
	return s.key, s.keyErr
}

func (s *scopeStubKeyService) ListKeysScoped(_ context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	s.lastScope = scope
	s.lastFilter = filter
	return s.list, nil
}

func (s *scopeStubKeyService) DeleteKeyScoped(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Key, error) {
	s.lastScope = scope
	return s.deleted, s.deleteErr
}

func TestListKeysUsesTheScopeFromTheRoute(t *testing.T) {
	svc := &scopeStubKeyService{list: []model.Key{{ID: uuid.New(), Name: "k"}}}

	c, w, r := newKeyHandlerFixture(t, svc, uuid.New(), "team-a")
	listKeys(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())

	c, w, r = newKeyHandlerFixture(t, svc, uuid.New(), "")
	listKeys(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
}

func TestGetKeyUsesTheScopeFromTheRoute(t *testing.T) {
	keyID := uuid.New()
	svc := &scopeStubKeyService{key: &model.Key{ID: keyID, Name: "k", Type: model.KeyTypeRSA, Enabled: true}}

	c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
	getKey(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}

func TestGetKeyMapsLifecycleDenialTo403AndNotFoundTo404(t *testing.T) {
	keyID := uuid.New()

	svc := &scopeStubKeyService{keyErr: keyservices.ErrKeyLifecycleDenied}
	c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
	getKey(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)

	svc = &scopeStubKeyService{keyErr: keyservices.ErrKeyNotFound}
	c, w, r = newKeyHandlerFixture(t, svc, keyID, "team-a")
	getKey(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
}

// TestDeleteKeyUsesAnOwnerScope pins B6: key delete stays owner-gated on both
// route shapes until P2 replaces it with Key Vault Crypto Officer.
func TestDeleteKeyUsesAnOwnerScope(t *testing.T) {
	keyID := uuid.New()
	svc := &scopeStubKeyService{deleted: &model.Key{ID: keyID, Name: "k"}}

	for _, vaultName := range []string{"", "team-a"} {
		c, w, r := newKeyHandlerFixture(t, svc, keyID, vaultName)
		deleteKey(c, w, r)
		require.Nil(t, c.Err)
		assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind(),
			"B6: key delete is owner-gated on route shape %q", vaultName)
	}
}
```

Add the fixture to the same file, reusing `newKeyCtx` from `api/keys_crud_test.go:265`:

```go
// newKeyHandlerFixture wires a Context whose container returns svc as the key
// service. vaultName != "" marks a vault-scoped route.
func newKeyHandlerFixture(t *testing.T, svc keyservices.KeyService, keyID uuid.UUID,
	vaultName string) (*Context, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	c := newKeyCtx(svc)
	c.Params.KeyID = keyID.String()

	return c, httptest.NewRecorder(), newScopeRequest(t, uuid.New(), vaultName)
}
```

Add `"net/http/httptest"` to the test file's imports. If `newKeyCtx` does not populate `Claims["user_id"]`, set it on the returned Context before returning — `scopeFromRequest` and `ownerScopeFromRequest` both fail closed without it, which would make every assertion in this task fail with a nil-scope error rather than the behaviour under test.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run 'TestListKeysUsesTheScope|TestGetKeyUsesTheScope|TestGetKeyMapsLifecycle|TestDeleteKeyUsesAnOwnerScope' -v`

Expected: FAIL — the stub does not implement the methods the handlers currently call (`ListKeysInVault`, `GetKeyInVault`, `DeleteKeyInVault`), so the embedded nil `keyservices.KeyService` panics with `nil pointer dereference`.

- [ ] **Step 3: Rewrite the branch sites and the B6 handlers**

`listKeys` (`api/keys.go:374-421`) — replace the whole `if isVaultScopedRoute(r) { … } else { … }` block:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keysList, err := keyService.ListKeysScoped(r.Context(), scope, repositories.KeyFilter{
		Type: r.URL.Query().Get("type"),
		Tags: c.Params.Tags,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}
```

Note this is a deliberate, small widening of the flat route: it previously ignored `?type=` and `tags` (it called `ListKeys(ctx, userID)`). Forwarding the filter on both shapes is consistent and cannot expose a key the owner scope does not already authorize. Add `"rocketvault/internal/repositories"` to the file's imports.

`getKey` (`:424-483`):

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	key, err := keyService.GetKeyScoped(r.Context(), keyID, scope)
	if err != nil {
		if errors.Is(err, keyservices.ErrKeyLifecycleDenied) {
			c.SetPermissionError("key is disabled or outside its valid time window")
		} else if errors.Is(err, keyservices.ErrKeyNotFound) {
			c.SetNotFound("key")
		} else {
			c.SetInternalError(err)
		}
		return
	}
```

`updateKey` (`:485-590`) — replace the `vaultScoped`/`vaultID` block at `:527-560` and the flat branch that follows it with one path:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := keyService.UpdateKeyScoped(r.Context(), keyservices.UpdateKeyRequest{
		KeyID:     keyID,
		Scope:     scope,
		Name:      req.Name,
		Tags:      req.Tags,
		Revoked:   req.Revoked,
		Enabled:   req.Enabled,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}); err != nil {
		if errors.Is(err, keyservices.ErrKeyNotFound) {
			c.SetNotFound("key")
		} else {
			c.SetInternalError(err)
		}
		return
	}
```

`deleteKey` (`:592-653`) — replace the `userID`/`vaultID`/`DeleteKeyInVault` block at `:600-623`:

```go
	// B6: key delete stays owner-gated on both route shapes. Removed in P2,
	// where Key Vault Crypto Officer at vault scope replaces it.
	scope, ok := ownerScopeFromRequest(c, r)
	if !ok {
		return
	}

	deleted, err := keyService.DeleteKeyScoped(r.Context(), keyID, scope)
	if err != nil {
		if errors.Is(err, keyservices.ErrKeyNotFound) {
			c.SetNotFound("key")
		} else {
			c.SetInternalError(err)
		}
		return
	}
```

`wrapKey` (`:732`), `unwrapKey` (`:811`), `signKey` (`:890`), `verifyKey` (`:970`), `encryptKey` (`:1053`) and `decryptKey` (`:1138`) each currently read `userID` from claims and `vaultID` from `vaultIDFromRequest` and put both on their request struct. Replace those two blocks with:

```go
	// B6: crypto operations stay owner-gated. Removed in P2, where Key Vault
	// Crypto User at vault scope replaces the ownership check.
	scope, ok := ownerScopeFromRequest(c, r)
	if !ok {
		return
	}
```

and set the request fields from the scope, keeping the existing struct shape (Task 20 rebuilds the scope inside the service from exactly these two fields):

```go
		UserID:  scope.ActorID(),
		VaultID: scope.VaultID(),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS. The P0 B6 tests and `api/keys_crypto_test.go` are the equivalence proof — every crypto operation must still return 403 for a non-owner vault member. One expectation legitimately changes: `deleteKey`'s non-owner case now returns 404 rather than 403 (Task 19 mapped it to `ErrKeyNotFound`, per the spec's "404, not 403" decision). Update that one B6 assertion and call it out in the commit message.

- [ ] **Step 5: Commit**

```bash
git add api/keys.go api/keys_scope_test.go api/keys_crud_test.go api/keys_crypto_test.go
git commit -S -m "refactor(api): drive key handlers from a scope, marking B6 with ownerScopeFromRequest"
```

---

### Task 27: Certificate and certificate-policy handlers onto scopes

Five `isVaultScopedRoute` branches collapse: `listCertificates` (`api/certificates.go:256`), `getCertificate` (`:312`), `getCertificatePolicy` (`api/certificate_policy.go:29`), the policy upsert (`:100`) and the policy delete (`:170`).

**Files:**
- Modify: `api/certificates.go:248-292` (`listCertificates`), `:294-…` (`getCertificate`)
- Modify: `api/certificate_policy.go:16-…` (`getCertificatePolicy`), `:…` (upsert), `:…` (delete)
- Test: `api/certificates_scope_test.go`

**Interfaces:**
- Consumes: `scopeFromRequest` (Task 23); `CertificateService.GetCertificateScoped`, `ListCertificatesScoped` (Task 21); `repositories.CertificateFilter` (Task 12); the existing `certPolicyRepo()` accessor (`api/context.go:257`).
- Produces: no new symbols.

- [ ] **Step 1: Write the failing test**

Create `api/certificates_scope_test.go`:

```go
package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

type scopeStubCertService struct {
	certServices.CertificateService

	cert      *model.Certificate
	certErr   error
	list      []model.Certificate
	lastScope model.Scope
}

func (s *scopeStubCertService) GetCertificateScoped(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	s.lastScope = scope
	return s.cert, s.certErr
}

func (s *scopeStubCertService) ListCertificatesScoped(_ context.Context, scope model.Scope, _ repositories.CertificateFilter) ([]model.Certificate, error) {
	s.lastScope = scope
	return s.list, nil
}

func TestListCertificatesUsesTheScopeFromTheRoute(t *testing.T) {
	svc := &scopeStubCertService{list: []model.Certificate{{ID: uuid.New(), Name: "c"}}}

	c, w, r := newCertHandlerFixture(t, svc, uuid.New(), "team-a")
	listCertificates(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())

	c, w, r = newCertHandlerFixture(t, svc, uuid.New(), "")
	listCertificates(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
}

func TestGetCertificateMapsErrors(t *testing.T) {
	certID := uuid.New()

	svc := &scopeStubCertService{certErr: certServices.ErrCertLifecycleDenied}
	c, w, r := newCertHandlerFixture(t, svc, certID, "team-a")
	getCertificate(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)

	svc = &scopeStubCertService{certErr: certServices.ErrCertNotFound}
	c, w, r = newCertHandlerFixture(t, svc, certID, "team-a")
	getCertificate(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
}

func TestGetCertificatePolicyResolvesTheCertificateThroughTheScope(t *testing.T) {
	certID := uuid.New()
	svc := &scopeStubCertService{certErr: certServices.ErrCertNotFound}
	c, w, r := newCertHandlerFixture(t, svc, certID, "team-a")

	getCertificatePolicy(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}
```

Add the fixture to the same file, reusing `newCertCtx` from `api/certificates_test.go:252` (it takes explicit claims, so pass a user id):

```go
// newCertHandlerFixture wires a Context whose container returns svc as the
// certificate service. vaultName != "" marks a vault-scoped route.
func newCertHandlerFixture(t *testing.T, svc certServices.CertificateService, certID uuid.UUID,
	vaultName string) (*Context, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	c := newCertCtx(svc, jwt.MapClaims{"user_id": uuid.NewString()})
	c.Params.CertificateID = certID.String()

	return c, httptest.NewRecorder(), newScopeRequest(t, uuid.New(), vaultName)
}
```

Add `"net/http/httptest"` and `"github.com/golang-jwt/jwt/v5"` to the test file's imports. `TestGetCertificatePolicyResolvesTheCertificateThroughTheScope` also needs the container to return a certificate-policy repository; if `newCertCtx`'s container panics on `GetCertificatePolicyRepository`, extend that container stub to return the stub repository used by `newCertPolicyCtx` (`api/certificate_policy_test.go:211`) rather than adding a third container type.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run 'TestListCertificatesUsesTheScope|TestGetCertificateMapsErrors|TestGetCertificatePolicyResolves' -v`

Expected: FAIL — the stub does not implement `ListCertificatesInVault`/`GetCertificateInVault`/`ListCertificates`/`GetCertificate`, so the embedded nil interface panics with `nil pointer dereference`.

- [ ] **Step 3: Rewrite the five branch sites**

`listCertificates` (`api/certificates.go:248-292`):

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certs, err := certService.ListCertificatesScoped(r.Context(), scope, repositories.CertificateFilter{})
	if err != nil {
		c.SetInternalError(err)
		return
	}
```

Add `"rocketvault/internal/repositories"` to the file's imports.

`getCertificate` (starting at `api/certificates.go:294`) — replace the whole `if isVaultScopedRoute(r) { … } else { … }` block:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	cert, err := certService.GetCertificateScoped(r.Context(), certID, scope)
	if err != nil {
		if errors.Is(err, certServices.ErrCertLifecycleDenied) {
			c.SetPermissionError("certificate is disabled or outside its valid time window")
		} else if errors.Is(err, certServices.ErrCertNotFound) {
			c.SetNotFound("certificate")
		} else {
			c.SetInternalError(err)
		}
		return
	}
```

`getCertificatePolicy` (`api/certificate_policy.go:16` onward) — the two branches differ in which repository method they call (`GetByCertificateIDAny` vs `GetByCertificateID`). Resolve the certificate through the scope first, then always use the owner-agnostic repository method, because the scope has already authorized the parent certificate:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}
	if _, err := certService.GetCertificateScoped(r.Context(), certID, scope); err != nil {
		c.SetNotFound("certificate")
		return
	}

	policy, err := repo.GetByCertificateIDAny(r.Context(), certID)
	if err != nil {
		c.SetNotFound("policy")
		return
	}
```

This is behaviour-preserving on the flat route: `GetByCertificateID(certID, userID)` filtered by owner, and the owner scope now applies that same predicate one layer up, on the certificate itself.

The policy upsert (the handler containing `vaultScoped := isVaultScopedRoute(r)` at `:100`) — replace the conditional certificate check with an unconditional scoped one:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}
	if _, err := certService.GetCertificateScoped(r.Context(), certID, scope); err != nil {
		c.SetNotFound("certificate")
		return
	}
```

Keep `UserID: userID` on the `model.CertificatePolicy` literal that follows — after P2 `user_id` is provenance only, and P1 must not change what is written. Source it from `scope.ActorID()`.

The policy delete (`:170` onward) — same shape, then always call the owner-agnostic delete:

```go
	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}
	if _, err := certService.GetCertificateScoped(r.Context(), certID, scope); err != nil {
		c.SetNotFound("certificate")
		return
	}

	if err := repo.DeleteByCertificateIDAny(r.Context(), certID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.SetNotFound("policy not found")
		} else {
			c.SetInternalError(err)
		}
		return
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS. `api/certificates_test.go`, `api/certificate_policy_test.go` and `api/vault_scoped_keys_certs_test.go` are the equivalence proof, together with the P0 cross-vault certificate-policy regression test. Remove any now-unused `GetByCertificateID`/`DeleteByCertificateID` imports or helper calls the linter flags; leave the repository methods themselves in place (they are used by the CLI).

- [ ] **Step 5: Commit**

```bash
git add api/certificates.go api/certificate_policy.go api/certificates_scope_test.go
git commit -S -m "refactor(api): drive certificate and policy handlers from a scope"
```

---

### Task 28: Delete isVaultScopedRoute

**Files:**
- Modify: `api/context.go:52-59` (delete `isVaultScopedRoute`)
- Test: no new test; the gate is a grep plus the full suite.

**Interfaces:**
- Consumes: all 17 call sites removed by Tasks 24-27.
- Produces: `api/context.go` no longer imports `github.com/gorilla/mux` unless another function needs it.

- [ ] **Step 1: Verify every call site is gone**

Run:

```bash
grep -rn "isVaultScopedRoute" --include="*.go" . | grep -v "_test.go"
```

Expected: exactly two matches, both in `api/context.go` — the doc comment at `:52` and the declaration at `:57`. If any handler still matches, that handler was missed; go back to the owning task (secrets → Task 24, soft delete → Task 25, keys → Task 26, certificates and policy → Task 27) rather than deleting the function out from under it.

- [ ] **Step 2: Delete the function**

Remove these eight lines from `api/context.go`:

```go
// isVaultScopedRoute reports whether the request was served by an explicit
// vault-scoped route (/api/v1/vaults/{vault_name}/...), as opposed to a legacy
// flat route (/api/v1/secrets/...). Vault-scoped routes carry the "vault_name"
// path variable. Legacy routes preserve pre-multi-vault per-user visibility,
// while vault-scoped routes use vault-level "members see all" visibility.
func isVaultScopedRoute(r *http.Request) bool {
	return mux.Vars(r)["vault_name"] != ""
}
```

`scopeFromRequest` (Task 23) called it, so inline the check there:

```go
	if mux.Vars(r)["vault_name"] != "" {
		return model.NewVaultScope(vaultID, userID), true
	}
	return model.NewOwnerScope(vaultID, userID), true
```

`api/context.go` keeps its `gorilla/mux` import for that expression.

- [ ] **Step 3: Verify the symbol is gone repo-wide**

Run:

```bash
grep -rn "isVaultScopedRoute" --include="*.go" .
```

Expected: zero matches, including test files. If a test still calls it, replace that call with an assertion on `scopeFromRequest`'s returned `Kind()`.

- [ ] **Step 4: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS. A handler that neither builds nor uses a scope now fails to compile, which is the structural property this task buys.

- [ ] **Step 5: Commit**

```bash
git add api/context.go
git commit -S -m "refactor(api): remove isVaultScopedRoute in favour of explicit scopes"
```

---

### Task 29: CLI onto scopes

**Files:**
- Modify: `cmd/secrets/get.go:68` (`GetSecretInVault`), `cmd/secrets/list.go:66` (`ListSecretsInVault`), `cmd/secrets/delete.go:67` (`DeleteSecretInVault`), `cmd/keys/list.go:85-91` (`keyRepo.ListByUser` / `keyService.ListKeys`)
- Test: `cmd/secrets/scope_test.go`

**Interfaces:**
- Consumes: `SecretService.GetSecretScoped`, `ListSecretsScoped`, `DeleteSecretScoped` (Task 14); `KeyService.ListKeysScoped` (Task 19); `repositories.KeyFilter` (Task 11); the existing `resolveVaultID(ctx, cmd, serviceContainer)` helper in `cmd/secrets`.
- Produces: no new symbols.

The CLI has no HTTP request to derive an actor from; it uses the authenticated principal from the command's claims. `cmd/secrets/{get,list,delete}.go` currently have no claims plumbing, so pass `uuid.Nil` as the actor — that is audit metadata only and never an access predicate. `cmd/keys/list.go` already has `claims.UserID`.

- [ ] **Step 1: Write the failing test**

Create `cmd/secrets/scope_test.go`:

```go
package secrets

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestSecretsGetBuildsAVaultScope pins that the CLI resolves --vault into a
// vault scope rather than calling a *InVault method.
func TestSecretsGetBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID := newCLIScopeFixture(t)
	secretID := uuid.New()

	svc.On("GetSecretScoped", mock.Anything, secretID, model.NewVaultScope(vaultID, uuid.Nil)).
		Return(&model.Secret{ID: secretID, Name: "s", Value: "v", Version: 1}, nil).Once()

	cmd.SetArgs([]string{secretID.String()})
	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

func TestSecretsListBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID := newCLIScopeFixture(t)

	svc.On("ListSecretsScoped", mock.Anything, model.NewVaultScope(vaultID, uuid.Nil), mock.Anything).
		Return([]model.Secret{{ID: uuid.New(), Name: "a"}}, nil).Once()

	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

func TestSecretsDeleteBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID := newCLIScopeFixture(t)
	secretID := uuid.New()

	svc.On("DeleteSecretScoped", mock.Anything, secretID, model.NewVaultScope(vaultID, uuid.Nil)).
		Return(nil).Once()

	cmd.SetArgs([]string{secretID.String()})
	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

var _ = context.Background
var _ = assert.New
```

Add the fixture to the same file. It reuses `testutils.NewTestContext(t)` (`cmd/testutils/test_utils.go:50`), which already wires `MockServiceContainer` into `tc.Ctx` under `common.ServiceContainerKey` and pre-registers a `GetVault(ctx, "default")` expectation returning the default vault, so `resolveVaultID` resolves to `tc.TestVaultID` without extra setup:

```go
// newCLIScopeFixture returns the mock secret service, a command wired to the
// test context, and the vault id resolveVaultID will produce.
func newCLIScopeFixture(t *testing.T) (*testutils.MockSecretService, *cobra.Command, uuid.UUID) {
	t.Helper()

	tc := testutils.NewTestContext(t)
	t.Cleanup(func() { tc.MockSecretService.AssertExpectations(t) })

	// Build the command under test the same way the package's other tests do:
	// a fresh instance per test so cobra flag registration cannot collide.
	cmd := newCommandUnderTest()
	cmd.SetContext(tc.Ctx)

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	return tc.MockSecretService, cmd, tc.TestVaultID
}
```

Replace `newCommandUnderTest()` with the constructor for the command each test exercises — the `cmd/secrets` package builds a fresh `&cobra.Command{...}` inline in `list_test.go:104`, so mirror that shape per test, registering only the flags that command reads (`--tags` for list, none for get and delete). Do not share one fixture across all three commands if that forces a flag set none of them declares.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/secrets/... -run 'BuildsAVaultScope' -v`

Expected: FAIL — testify reports `mock: I don't know what to return because the method call was unexpected: GetSecretInVault(…)`, because the command still calls the `*InVault` shim.

- [ ] **Step 3: Rewrite the four call sites**

`cmd/secrets/get.go:68`:

```go
		secret, err := secretService.GetSecretScoped(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
		if err != nil {
			return fmt.Errorf("failed to retrieve secret: %w", err)
		}
```

`cmd/secrets/list.go:66`:

```go
		secretsList, err := secretService.ListSecretsScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), tags)
		if err != nil {
			return fmt.Errorf("failed to list secrets: %w", err)
		}
```

`cmd/secrets/delete.go:67`:

```go
		err = secretService.DeleteSecretScoped(ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil))
		if err != nil {
			logrus.WithError(err).Error("Failed to delete secret")
			os.Exit(1)
			return
		}
```

Add `"rocketvault/model"` to each file's imports where it is not already present.

`cmd/keys/list.go:85-91` — the `if claims.Role == model.RoleAdmin` branch reaches around the service layer into `keyRepo.ListByUser(ctx, nil, keyType, tags)`. Replace the whole branch with one scoped service call, which is exactly the "state the RBAC decision once, at the call site where it was made" point from spec §5.3:

```go
		scope := model.NewOwnerScope(uuid.Nil, claims.UserID)
		if claims.Role == model.RoleAdmin {
			scope = model.NewAdminScope(claims.UserID)
		}

		keys, err := keyService.ListKeysScoped(ctx, scope, repositories.KeyFilter{Type: keyType, Tags: tags})
```

Add `"rocketvault/internal/repositories"` to the imports and drop the now-unused `serviceContainer.GetKeyRepository()` call and its `var keys []model.Key` / `var err error` declarations.

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS. `cmd/secrets/*_test.go` and `cmd/keys/*_test.go` are the equivalence proof; existing tests that set expectations on `GetSecretInVault`/`ListSecretsInVault`/`DeleteSecretInVault`/`ListByUser` must move to the scoped methods. Watch for the runtime panic mode called out in spec §4.3: `cmd/testutils.MockServiceContainer` type-asserts, so a mock missing a method shows up as a `go test` panic, never a `go vet` error.

- [ ] **Step 5: Commit**

```bash
git add cmd/secrets/get.go cmd/secrets/list.go cmd/secrets/delete.go cmd/secrets/scope_test.go cmd/keys/list.go
git commit -S -m "refactor(cmd): drive the CLI from explicit scopes"
```

---
## Phase 5 — Cache rework (isolated, so it bisects cleanly)

### Task 30: Compound cache key, byID reverse index, DeleteByID, Flush vs Clear

The cache is keyed by secret ID alone (`internal/cache/secret_cache.go:45`) and the decorator admits a hit after checking only `cached.UserID == userID` (`cache_integration.go:38`). Once `GetSecret` is one method it caches vault-scoped reads too, so an ID-keyed cache would serve an owner-scoped caller a value admitted under a vault scope. The rejected alternative — an ID-only key plus a Go-side `Admits(scope, secret) bool` — would mirror `scopePredicate`'s SQL in a second language forever, and a divergence would be a silent authorization bypass with no compiler or test to catch it.

**Files:**
- Modify: `internal/cache/secret_cache.go:17-38` (struct + constructor), `:40-60` (`Get`), `:62-84` (`Set`), `:86-96` (`Delete`), `:98-115` (`Clear`), `:117-134` (`StartCleanup`), `:136-153` (`GetStats`)
- Test: `internal/cache/secret_cache_scope_test.go`

**Interfaces:**
- Consumes: `model.Scope`, `Scope.Kind`, `Scope.VaultID`, `Scope.OwnerID` (Task 1).
- Produces:
  - `func scopeCacheKey(secretID uuid.UUID, scope model.Scope) (string, bool)` — unexported; `"v|{vaultID}|{secretID}"`, `"o|{ownerID}|{secretID}"`, and `false` for admin or invalid scopes
  - `func (c *SecretCache) Get(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, bool)`
  - `func (c *SecretCache) Set(ctx context.Context, secret *model.Secret, scope model.Scope) error`
  - `func (c *SecretCache) DeleteByID(ctx context.Context, secretID uuid.UUID) error`
  - `func (c *SecretCache) Flush(ctx context.Context) error`
  - `func (c *SecretCache) Clear(ctx context.Context) error` — unchanged semantics, now documented as expiry pruning only

- [ ] **Step 1: Write the failing test**

Create `internal/cache/secret_cache_scope_test.go`:

```go
package cache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func newScopeCache(t *testing.T, ttl time.Duration) *SecretCache {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return NewSecretCache(ttl, l)
}

func TestScopeCacheKeyIsCompoundAndNeverCachesAdmin(t *testing.T) {
	secretID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()

	key, ok := scopeCacheKey(secretID, model.NewVaultScope(vaultID, uuid.New()))
	require.True(t, ok)
	assert.Equal(t, "v|"+vaultID.String()+"|"+secretID.String(), key)

	key, ok = scopeCacheKey(secretID, model.NewOwnerScope(vaultID, ownerID))
	require.True(t, ok)
	assert.Equal(t, "o|"+ownerID.String()+"|"+secretID.String(), key)

	_, ok = scopeCacheKey(secretID, model.NewAdminScope(uuid.New()))
	assert.False(t, ok, "admin reads are never cached")

	var zero model.Scope
	_, ok = scopeCacheKey(secretID, zero)
	assert.False(t, ok, "an invalid scope is never cached")
}

// TestVaultScopedEntryIsNotServedToAnOwnerScopedCaller is the security property
// the compound key exists for.
func TestVaultScopedEntryIsNotServedToAnOwnerScopedCaller(t *testing.T) {
	c := newScopeCache(t, time.Minute)
	ctx := context.Background()

	secretID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()
	secret := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Value: "plaintext", Enabled: true}

	require.NoError(t, c.Set(ctx, secret, model.NewVaultScope(vaultID, uuid.New())))

	_, found := c.Get(ctx, secretID, model.NewOwnerScope(vaultID, ownerID))
	assert.False(t, found, "a vault-scoped entry must not satisfy an owner-scoped read")

	_, found = c.Get(ctx, secretID, model.NewVaultScope(vaultID, uuid.New()))
	assert.True(t, found)
}

func TestDeleteByIDEvictsEveryScopedView(t *testing.T) {
	c := newScopeCache(t, time.Minute)
	ctx := context.Background()

	secretID, vaultID, ownerID := uuid.New(), uuid.New(), uuid.New()
	secret := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Value: "plaintext", Enabled: true}
	vaultScope := model.NewVaultScope(vaultID, uuid.New())
	ownerScope := model.NewOwnerScope(vaultID, ownerID)

	require.NoError(t, c.Set(ctx, secret, vaultScope))
	require.NoError(t, c.Set(ctx, secret, ownerScope))

	require.NoError(t, c.DeleteByID(ctx, secretID))

	_, found := c.Get(ctx, secretID, vaultScope)
	assert.False(t, found)
	_, found = c.Get(ctx, secretID, ownerScope)
	assert.False(t, found)
}

func TestFlushRemovesLiveEntriesWhileClearOnlyPrunesExpired(t *testing.T) {
	ctx := context.Background()
	secretID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	secret := &model.Secret{ID: secretID, VaultID: vaultID, Value: "plaintext", Enabled: true}

	live := newScopeCache(t, time.Minute)
	require.NoError(t, live.Set(ctx, secret, scope))
	require.NoError(t, live.Clear(ctx))
	_, found := live.Get(ctx, secretID, scope)
	assert.True(t, found, "Clear only prunes expired entries")

	require.NoError(t, live.Flush(ctx))
	_, found = live.Get(ctx, secretID, scope)
	assert.False(t, found, "Flush removes live entries")
}

func TestExpiredEntryIsAMiss(t *testing.T) {
	c := newScopeCache(t, time.Nanosecond)
	ctx := context.Background()

	secretID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	require.NoError(t, c.Set(ctx, &model.Secret{ID: secretID, VaultID: vaultID, Enabled: true}, scope))

	time.Sleep(time.Millisecond)
	_, found := c.Get(ctx, secretID, scope)
	assert.False(t, found)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/... -run 'TestScopeCacheKey|TestVaultScopedEntryIsNotServed|TestDeleteByIDEvicts|TestFlushRemovesLiveEntries|TestExpiredEntryIsAMiss' -v`

Expected: FAIL to build — `undefined: scopeCacheKey`, `too many arguments in call to c.Get`, `too many arguments in call to c.Set`, `c.DeleteByID undefined`, `c.Flush undefined`.

- [ ] **Step 3: Rework the cache**

Replace `internal/cache/secret_cache.go:17-115` with:

```go
// SecretCache provides thread-safe in-memory caching for secrets with TTL
// support. Entries are keyed by (scope, secret id), so a value admitted under
// one scope can never satisfy a read under another. A byID reverse index lets
// a single mutation evict every scoped view of a secret.
type SecretCache struct {
	cache  map[string]*CachedSecret
	byID   map[uuid.UUID]map[string]struct{}
	mu     sync.RWMutex
	ttl    time.Duration
	logger *logrus.Logger
}

// CachedSecret represents a cached secret with expiration time.
type CachedSecret struct {
	Secret    *model.Secret
	ExpiresAt time.Time
}

// NewSecretCache creates a new secret cache with the specified TTL.
func NewSecretCache(ttl time.Duration, logger *logrus.Logger) *SecretCache {
	return &SecretCache{
		cache:  make(map[string]*CachedSecret),
		byID:   make(map[uuid.UUID]map[string]struct{}),
		ttl:    ttl,
		logger: logger,
	}
}

// scopeCacheKey builds the compound cache key for a scoped read. It reports
// false for scopes that must never be cached: ScopeAdmin, which has no
// predicate, and any invalid scope.
func scopeCacheKey(secretID uuid.UUID, scope model.Scope) (string, bool) {
	if scope.Validate() != nil {
		return "", false
	}
	switch scope.Kind() {
	case model.ScopeVault:
		return "v|" + scope.VaultID().String() + "|" + secretID.String(), true
	case model.ScopeOwner:
		ownerID, ok := scope.OwnerID()
		if !ok {
			return "", false
		}
		return "o|" + ownerID.String() + "|" + secretID.String(), true
	default:
		return "", false
	}
}

// Get retrieves a secret cached under the given scope, if it has not expired.
func (c *SecretCache) Get(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, bool) {
	key, cacheable := scopeCacheKey(secretID, scope)
	if !cacheable {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.cache[key]
	if !exists {
		c.logger.WithField("secret_id", secretID).Debug("Cache miss - secret not found")
		return nil, false
	}
	if time.Now().After(cached.ExpiresAt) {
		c.logger.WithField("secret_id", secretID).Debug("Cache miss - secret expired")
		return nil, false
	}

	c.logger.WithField("secret_id", secretID).Debug("Cache hit")
	return cached.Secret, true
}

// Set stores a secret under the given scope with TTL expiration. Scopes that
// must not be cached are a silent no-op.
func (c *SecretCache) Set(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	if secret == nil {
		return fmt.Errorf("cannot cache nil secret")
	}

	key, cacheable := scopeCacheKey(secret.ID, scope)
	if !cacheable {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = &CachedSecret{Secret: secret, ExpiresAt: time.Now().Add(c.ttl)}
	if c.byID[secret.ID] == nil {
		c.byID[secret.ID] = make(map[string]struct{})
	}
	c.byID[secret.ID][key] = struct{}{}

	c.logger.WithFields(logrus.Fields{
		"secret_id": secret.ID,
		"scope":     scope.String(),
		"ttl":       c.ttl,
	}).Debug("Secret cached successfully")

	return nil
}

// DeleteByID evicts every scoped view of a secret. It is the invalidation
// primitive: a mutation authorized under one scope must not leave a stale
// entry visible under another.
func (c *SecretCache) DeleteByID(ctx context.Context, secretID uuid.UUID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key := range c.byID[secretID] {
		delete(c.cache, key)
	}
	delete(c.byID, secretID)

	c.logger.WithField("secret_id", secretID).Debug("Secret removed from cache")
	return nil
}

// Flush removes every entry, expired or not. Use it after a bulk operation
// whose effects the cache cannot enumerate.
func (c *SecretCache) Flush(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := len(c.cache)
	c.cache = make(map[string]*CachedSecret)
	c.byID = make(map[uuid.UUID]map[string]struct{})

	c.logger.WithField("removed_count", removed).Debug("Cache flushed")
	return nil
}

// Clear removes only expired entries. It is the background-cleanup primitive
// and is deliberately NOT a flush — see Flush.
func (c *SecretCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, cached := range c.cache {
		if now.After(cached.ExpiresAt) {
			delete(c.cache, key)
			if keys := c.byID[cached.Secret.ID]; keys != nil {
				delete(keys, key)
				if len(keys) == 0 {
					delete(c.byID, cached.Secret.ID)
				}
			}
			removed++
		}
	}

	c.logger.WithField("removed_count", removed).Debug("Expired cache entries cleared")
	return nil
}
```

`StartCleanup` keeps calling `Clear`. `GetStats` is unchanged. Delete the old `Delete` method; Task 31 moves its five call sites to `DeleteByID`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./internal/cache/... -v`

Expected: FAIL to build `internal/cache/cache_integration.go` — `c.cache.Get`, `c.cache.Set` and `c.cache.Delete` no longer match. That is expected and is exactly what Task 31 fixes; run `go test ./internal/cache/... -run 'TestScopeCacheKey|TestVaultScopedEntryIsNotServed|TestDeleteByIDEvicts|TestFlushRemovesLiveEntries|TestExpiredEntryIsAMiss'` only after Task 31, and land both tasks before pushing. To keep this commit independently green, apply Task 31's Step 3 edits now and split the commits at the file boundary.

- [ ] **Step 5: Commit**

```bash
git add internal/cache/secret_cache.go internal/cache/secret_cache_scope_test.go internal/cache/secret_cache_test.go
git commit -S -m "feat(cache): key secrets by scope with a byID reverse index"
```

---

### Task 31: Re-enable caching on the unified read with an IsAccessible recheck

**Files:**
- Modify: `internal/cache/cache_integration.go` — `GetSecret` (`:34-60`), `GetSecretScoped` (added in Task 14), `CreateSecret` (`:63-77`), `GenerateSecret` (`:178-192`), `ImportSecrets` (`:200-215`), `ClearCache` (`:223-225`), and every `s.cache.Delete` call site (`:88`, `:110`, `:141`, `:257`, `:274`)
- Test: `internal/cache/cache_integration_test.go` (append)

**Interfaces:**
- Consumes: `SecretCache.Get/Set/DeleteByID/Flush`, `scopeCacheKey` (Task 30); `SecretService.GetSecretScoped` (Task 14); `model.Secret.IsAccessible` (`model/secret.go:44`).
- Produces: no new exported symbols. `CachedSecretService.GetSecretScoped` becomes a caching read again.

- [ ] **Step 1: Write the failing test**

Append to `internal/cache/cache_integration_test.go`:

```go
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
```

Add the `countingSecretService` stub (embedding `secrets.SecretService`, counting `getScopedCalls`, returning `secret`, and implementing `ImportSecrets` as a no-op success) plus `newQuietLogger`, unless equivalents already exist in `internal/cache/cache_integration_test.go` — in which case extend those.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/... -v`

Expected: FAIL to build — `s.cache.Get(ctx, secretID)` and `s.cache.Set(ctx, secret)` no longer match the Task 30 signatures, and `s.cache.Delete` is undefined.

- [ ] **Step 3: Rewire the decorator**

`GetSecretScoped` becomes the caching read:

```go
// GetSecretScoped retrieves a scoped secret, using cache when available. The
// entry is keyed by (scope, id), so a value admitted under one scope can never
// satisfy a read under another, and the hit path rechecks IsAccessible so a
// secret that expired or was disabled while cached is not served anyway.
func (s *CachedSecretService) GetSecretScoped(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error) {
	if cached, found := s.cache.Get(ctx, secretID, scope); found {
		if cached.IsAccessible() {
			s.logger.WithFields(logrus.Fields{
				"secret_id": secretID,
				"scope":     scope.String(),
			}).Debug("Cache hit for secret")
			return cached, nil
		}
		if err := s.cache.DeleteByID(ctx, secretID); err != nil {
			s.logger.WithError(err).Warn("Failed to evict inaccessible cached secret")
		}
	}

	secret, err := s.secretService.GetSecretScoped(ctx, secretID, scope)
	if err != nil {
		return nil, err
	}

	if err := s.cache.Set(ctx, secret, scope); err != nil {
		s.logger.WithError(err).Warn("Failed to cache secret")
	}

	return secret, nil
}
```

`GetSecret` becomes a shim onto it so the two paths cannot diverge:

```go
// GetSecret retrieves a secret for its owner, using cache when available.
// Deprecated: shim over GetSecretScoped; removed in Phase 6.
func (s *CachedSecretService) GetSecret(ctx context.Context, secretID uuid.UUID, userID uuid.UUID) (*model.Secret, error) {
	return s.GetSecretScoped(ctx, secretID, model.NewOwnerScope(uuid.Nil, userID))
}
```

`CreateSecret` (`:63-77`) and `GenerateSecret` (`:178-192`) cannot know the reading scope, so stop caching on write and let the first read populate the cache. Replace both `s.cache.Set(ctx, secret)` calls with nothing, keeping the rest of each method.

Replace every `s.cache.Delete(ctx, …)` call with `s.cache.DeleteByID(ctx, …)`: `UpdateSecret` (`:88`), `DeleteSecret` (`:110`), `DeleteSecretInVault` (`:141`), `RecoverSecret` (`:257`), `PurgeSecret` (`:274`), plus the scoped decorators added in Tasks 14-16 (`DeleteSecretScoped`, `UpdateSecretScoped`, `RecoverSecretScoped`, `PurgeSecretScoped`).

`ImportSecrets` (`:200-215`) switches from `Clear` to `Flush`:

```go
	// Flush the cache to ensure consistency after a bulk import. Clear only
	// prunes expired entries and was a no-op for live ones.
	if err := s.cache.Flush(ctx); err != nil {
		s.logger.WithError(err).Warn("Failed to flush cache after import")
	}
```

`ClearCache` (`:223-225`) is called as a flush by its name, so point it at `Flush`:

```go
// ClearCache removes every cached secret.
func (s *CachedSecretService) ClearCache(ctx context.Context) error {
	return s.cache.Flush(ctx)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS, including the four new tests and Task 30's five.

- [ ] **Step 5: Commit**

```bash
git add internal/cache/cache_integration.go internal/cache/cache_integration_test.go
git commit -S -m "feat(cache): re-enable scoped caching with an IsAccessible recheck"
```

---

### Task 32: TestEveryMutatorInvalidates

A new mutator forgetting cache invalidation has already happened once (`UpdateSecretInVault`), and because the cache stores **decrypted** values the consequence is stale plaintext.

**Files:**
- Create: `internal/cache/mutator_invalidation_test.go`

**Interfaces:**
- Consumes: `CachedSecretService` and every mutating method on it (Tasks 14-16, 31); `SecretCache.Set/Get` (Task 30).
- Produces: no production symbols. Establishes the rule that a new mutating method joins the table in the same commit that adds it.

- [ ] **Step 1: Write the failing test**

Create `internal/cache/mutator_invalidation_test.go`:

```go
package cache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// TestEveryMutatorInvalidates primes the cache under BOTH a vault scope and an
// owner scope, invokes each mutating method under one of them, and asserts both
// entries are gone. The cache stores decrypted values, so a missed invalidation
// serves stale plaintext.
//
// RULE: a new mutating method on CachedSecretService joins this table in the
// same commit that adds it.
func TestEveryMutatorInvalidates(t *testing.T) {
	secretID := uuid.New()
	vaultID := uuid.New()
	ownerID := uuid.New()
	vaultScope := model.NewVaultScope(vaultID, ownerID)
	ownerScope := model.NewOwnerScope(uuid.Nil, ownerID)

	mutators := []struct {
		name   string
		invoke func(ctx context.Context, svc *CachedSecretService) error
	}{
		{"UpdateSecret", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, UserID: ownerID})
		}},
		{"UpdateSecretInVault", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.UpdateSecretInVault(ctx, secrets.UpdateSecretRequest{SecretID: secretID, UserID: ownerID, VaultID: vaultID})
		}},
		{"UpdateSecretScoped", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.UpdateSecretScoped(ctx, secrets.UpdateSecretRequest{SecretID: secretID, Scope: vaultScope})
		}},
		{"DeleteSecret", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.DeleteSecret(ctx, secretID, ownerID)
		}},
		{"DeleteSecretInVault", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.DeleteSecretInVault(ctx, secretID, vaultID)
		}},
		{"DeleteSecretScoped", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.DeleteSecretScoped(ctx, secretID, vaultScope)
		}},
		{"RecoverSecret", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.RecoverSecret(ctx, secretID)
		}},
		{"RecoverSecretScoped", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.RecoverSecretScoped(ctx, secretID, vaultScope)
		}},
		{"PurgeSecret", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.PurgeSecret(ctx, secretID)
		}},
		{"PurgeSecretScoped", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.PurgeSecretScoped(ctx, secretID, vaultScope)
		}},
		{"ImportSecrets", func(ctx context.Context, svc *CachedSecretService) error {
			_, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Format: "json", Data: []byte("[]")})
			return err
		}},
	}

	for _, m := range mutators {
		t.Run(m.name, func(t *testing.T) {
			ctx := context.Background()
			cache := newScopeCache(t, time.Minute)
			inner := &countingSecretService{secret: &model.Secret{
				ID: secretID, UserID: ownerID, VaultID: vaultID, Value: "plaintext", Enabled: true,
			}}
			svc := NewCachedSecretService(inner, cache, newQuietLogger(t))

			secret := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Value: "plaintext", Enabled: true}
			require.NoError(t, cache.Set(ctx, secret, vaultScope))
			require.NoError(t, cache.Set(ctx, secret, ownerScope))

			require.NoError(t, m.invoke(ctx, svc))

			_, found := cache.Get(ctx, secretID, vaultScope)
			assert.False(t, found, "%s left a stale vault-scoped entry", m.name)
			_, found = cache.Get(ctx, secretID, ownerScope)
			assert.False(t, found, "%s left a stale owner-scoped entry", m.name)
		})
	}
}
```

Extend `countingSecretService` from Task 31 so every method invoked above returns success.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache/... -run TestEveryMutatorInvalidates -v`

Expected: FAIL on the subtests for any mutator that does not invalidate — with `UpdateSecretInVault left a stale vault-scoped entry` being the historical case if Task 15's decorator was missed, and every `*Scoped` subtest failing on the owner-scoped entry unless the decorator calls `DeleteByID` rather than a scoped delete.

- [ ] **Step 3: Fix any mutator the table catches**

For each failing subtest, add or correct the invalidation in `internal/cache/cache_integration.go`:

```go
	if err := s.cache.DeleteByID(ctx, secretID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate cached secret")
	}
```

`DeleteByID`, not a scoped delete: a mutation authorized under one scope must evict every scoped view. If every subtest already passes, add a comment recording that the table is the gate and move on — do not weaken it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS for all eleven subtests and the full suite.

- [ ] **Step 5: Commit**

```bash
git add internal/cache/mutator_invalidation_test.go internal/cache/cache_integration.go
git commit -S -m "test(cache): assert every mutator invalidates both scoped views"
```

---
## Phase 6 — Delete the shims (irreversible)

This is the point of no return. Each task deletes the legacy methods and, in the same commit, renames the transitional `…Scoped` names to the final ones.

### Task 33: Delete the secret shims and rename to the final API

**Files:**
- Modify: `internal/repositories/secret_repository.go` (interface + all shims)
- Modify: `internal/services/secrets/secret_service.go`, `versioning_service.go`
- Modify: `internal/services/retry/retry_secret_service.go`, `retry_repository_wrapper.go`
- Modify: `internal/cache/cache_integration.go`
- Modify: `api/secrets.go`, `api/soft_delete.go`, `cmd/secrets/{get,list,delete}.go`
- Test: all secret test files (mechanical rename)

**Interfaces:**
- Consumes: every scoped method from Tasks 6, 10, 14-17, 22, 24, 25, 29, 31.
- Produces, final names:
  - `SecretRepositoryInterface.Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error)`
  - `SecretRepositoryInterface.Update(ctx context.Context, secret *model.Secret, scope model.Scope) error`
  - `SecretRepositoryInterface.List(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error)`
  - `SecretService.GetSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) (*model.Secret, error)`
  - `SecretService.ListSecrets(ctx context.Context, scope model.Scope, tags []string) ([]model.Secret, error)`
  - `SecretService.DeleteSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error`
  - `SecretService.UpdateSecret(ctx context.Context, req UpdateSecretRequest) error` (`req.Scope` only)
  - `SecretService.RecoverSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error`
  - `SecretService.PurgeSecret(ctx context.Context, secretID uuid.UUID, scope model.Scope) error`
  - `SecretService.ListDeletedSecrets(ctx context.Context, scope model.Scope) ([]model.Secret, error)`
  - `SecretService.GetSecretVersions/GetSecretVersion/GetLatestSecretVersion` taking a `model.Scope`
  - `VersioningServiceInterface.GetVersions/GetVersion/GetLatestVersion` taking a `model.Scope`

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/final_api_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// TestSecretRepositoryFinalAPIShape is a compile-time gate: it fails to build
// while any legacy secret method still exists on the interface, and while the
// scoped methods still carry the transitional Scoped suffix.
func TestSecretRepositoryFinalAPIShape(t *testing.T) {
	var repo repositories.SecretRepositoryInterface
	if repo != nil {
		ctx := context.Background()
		_, _ = repo.Read(ctx, uuid.New(), model.NewAdminScope(uuid.Nil))
		_ = repo.Update(ctx, &model.Secret{}, model.NewAdminScope(uuid.Nil))
		_, _ = repo.List(ctx, model.NewAdminScope(uuid.Nil), repositories.SecretFilter{})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestSecretRepositoryFinalAPIShape -v`

Expected: FAIL to build — `not enough arguments in call to repo.Read` (the interface still declares `Read(ctx, id)`), `not enough arguments in call to repo.Update`, and `repo.List undefined`.

- [ ] **Step 3: Delete the shims and rename**

Repository (`internal/repositories/secret_repository.go`): delete the nine shim methods `Read`, `ReadByOwner`, `ReadInVault`, `Update`, `UpdateInVault`, `ListByUser`, `ListByUserIncludeDeleted`, `ListInVault`, `ListInVaultIncludeDeleted` and their interface entries. Then rename `ReadScoped` → `Read`, `UpdateScoped` → `Update`, `ListScoped` → `List` on both the struct and the interface. The interface's remaining entries are:

```go
type SecretRepositoryInterface interface {
	Create(ctx context.Context, secret *model.Secret) error
	Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error)
	Update(ctx context.Context, secret *model.Secret, scope model.Scope) error
	List(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error)
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverSecret(ctx context.Context, id uuid.UUID) error
	PurgeSecret(ctx context.Context, id uuid.UUID) error
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error)
	ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error)
	GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error)
}
```

Service (`internal/services/secrets/secret_service.go`): delete `GetSecretInVault`, `ListSecretsInVault`, `DeleteSecretInVault`, `ListDeletedSecretsInVault`, `IsSecretSoftDeletedInVault`, `IsSecretSoftDeletedForUser`, `UpdateSecretInVault`, and the unscoped `RecoverSecret`/`PurgeSecret` shims, plus their interface entries. Rename the scoped methods to the final names above, and rename `ListDeletedSecretsScoped` → `ListDeletedSecrets`. Delete `UserID` and `VaultID` from `UpdateSecretRequest`, `ExportSecretsRequest` and `ImportSecretsRequest`, and delete the `if scope.Validate() != nil { … }` fallback added in Task 24; `CreateSecretRequest` keeps `UserID` (provenance) and `VaultID` (creation target) — those are not authorization inputs.

Versioning (`internal/services/secrets/versioning_service.go`): delete the six shims and rename `GetVersionsScoped` → `GetVersions`, `GetVersionScoped` → `GetVersion`, `GetLatestVersionScoped` → `GetLatestVersion`.

Decorators: apply the same deletions and renames in `internal/services/retry/retry_secret_service.go`, `retry_repository_wrapper.go` and `internal/cache/cache_integration.go`.

Callers: `api/secrets.go`, `api/soft_delete.go` and `cmd/secrets/{get,list,delete}.go` already pass scopes, so this is a pure rename — drop the `Scoped` suffix at each call site.

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Regenerating mocks is mandatory here — the interfaces changed shape, not just gained methods. Every remaining compile error is a caller still using a deleted name; fix it by passing the appropriate scope (`model.NewAdminScope(actor)` for trusted internal callers such as the vault cascade, backup/restore and the rotation scheduler).

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/secret_repository.go internal/repositories/final_api_test.go internal/services/secrets internal/services/retry internal/cache api/secrets.go api/soft_delete.go cmd/secrets
git commit -S -m "refactor(secrets)!: remove the InVault and ByOwner shims"
```

---

### Task 34: Delete the key and certificate shims and rename to the final API

**Files:**
- Modify: `internal/repositories/key_repository.go`, `certificate_repository.go`
- Modify: `internal/services/keys/key_service.go`, `crypto_service.go`
- Modify: `internal/services/certificates/certificate_service.go`
- Modify: `api/keys.go`, `api/certificates.go`, `api/certificate_policy.go`, `cmd/keys/list.go`
- Test: `internal/repositories/final_api_test.go` (append)

**Interfaces:**
- Consumes: every scoped method from Tasks 7, 8, 11, 12, 19, 20, 21, 26, 27, 29.
- Produces, final names:
  - `KeyRepositoryInterface.Read/Update/List` taking a `model.Scope`; the interface no longer embeds `db.Repository[model.Key]`
  - `CertificateRepositoryInterface.Read/Update/List` taking a `model.Scope`
  - `KeyService.GetKey/ListKeys/UpdateKey/DeleteKey` taking a `model.Scope`
  - `CertificateService.GetCertificate/ListCertificates/UpdateCertificate/DeleteCertificate` taking a `model.Scope`

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/final_api_test.go`:

```go
// TestKeyRepositoryFinalAPIShape is a compile-time gate for the key repository.
func TestKeyRepositoryFinalAPIShape(t *testing.T) {
	var repo repositories.KeyRepositoryInterface
	if repo != nil {
		ctx := context.Background()
		_, _ = repo.Read(ctx, uuid.New(), model.NewAdminScope(uuid.Nil))
		_ = repo.Update(ctx, &model.Key{}, model.NewAdminScope(uuid.Nil))
		_, _ = repo.List(ctx, model.NewAdminScope(uuid.Nil), repositories.KeyFilter{})
	}
}

// TestCertificateRepositoryFinalAPIShape is a compile-time gate for the
// certificate repository.
func TestCertificateRepositoryFinalAPIShape(t *testing.T) {
	var repo repositories.CertificateRepositoryInterface
	if repo != nil {
		ctx := context.Background()
		_, _ = repo.Read(ctx, uuid.New(), model.NewAdminScope(uuid.Nil))
		_ = repo.Update(ctx, &model.Certificate{}, model.NewAdminScope(uuid.Nil))
		_, _ = repo.List(ctx, model.NewAdminScope(uuid.Nil), repositories.CertificateFilter{})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run 'TestKeyRepositoryFinalAPIShape|TestCertificateRepositoryFinalAPIShape' -v`

Expected: FAIL to build — `not enough arguments in call to repo.Read` for both interfaces (the key interface still inherits `Read(ctx, id)` from the embedded `db.Repository[model.Key]`, and the certificate interface still declares its own two-argument `Read`), plus `repo.List undefined`.

- [ ] **Step 3: Delete the shims and rename**

Key repository (`internal/repositories/key_repository.go`): delete `Read`, `ReadInVault`, `Update`, `ListByUser`, `ListInVault` and their interface entries. Rename `ReadScoped` → `Read`, `UpdateScoped` → `Update`, `ListScoped` → `List`. **Stop embedding `db.Repository[model.Key]`** — its `Read(ctx, id)` and `Update(ctx, entity)` now collide with the scoped names — and declare `Create` and `Delete` explicitly:

```go
type KeyRepositoryInterface interface {
	Create(ctx context.Context, key *model.Key) error
	Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error)
	Update(ctx context.Context, key *model.Key, scope model.Scope) error
	List(ctx context.Context, scope model.Scope, filter KeyFilter) ([]model.Key, error)
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverKey(ctx context.Context, id uuid.UUID) error
	PurgeKey(ctx context.Context, id uuid.UUID) error
	SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
	ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Key, error)
	ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error)
	CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error
	ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error)
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
}
```

Certificate repository (`internal/repositories/certificate_repository.go`): delete `Read`, `ReadInVault`, `Update`, `ListByUser`, `ListInVault` and their interface entries; rename `ReadScoped` → `Read`, `UpdateScoped` → `Update`, `ListScoped` → `List`.

Key service (`internal/services/keys/key_service.go`): delete `GetKeyInVault`, `ListKeysInVault`, `ListKeysWithFilters`, `DeleteKeyInVault`, `UpdateKeyInVault` and the unscoped `GetKey`, `ListKeys`, `UpdateKey`, `DeleteKey` shims; rename the scoped methods to the final names. Delete `UserID` and `VaultID` from `UpdateKeyRequest`. `CreateKeyRequest` keeps both — they are provenance and creation target, not authorization.

Also update the three unscoped internal reads left in the key service — `RotateKey` (`key_service.go:692`), `ValidateKeyAccess` (`:802`) and `DeleteKey`'s re-read — to pass `model.NewAdminScope(userID)` (rotation and validation are trusted internal paths that already did their own ownership comparison) or the caller's scope where one is available.

Crypto service (`internal/services/keys/crypto_service.go`): `loadAndAuthorize` already takes a scope; no rename needed. Keep the B6 conjunction — it is deleted in P2, not here.

Certificate service (`internal/services/certificates/certificate_service.go`): delete `GetCertificateInVault`, `ListCertificatesInVault`, `DeleteCertificateInVault` and the unscoped `GetCertificate`, `ListCertificates`, `UpdateCertificate`, `DeleteCertificate` shims; rename the scoped methods. Delete `UserID` from `UpdateCertificateRequest`. Update `RenewCertificate` (`:585`) and `ValidateCertificateAccess` (`:620`) to pass an explicit scope.

Callers: `api/keys.go`, `api/certificates.go`, `api/certificate_policy.go` and `cmd/keys/list.go` already pass scopes — drop the `Scoped` suffix at each call site.

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
mockery
go build ./... && go test ./...
```

Expected: PASS. Regenerate mocks first; the interfaces changed shape. Callers outside the request path — `internal/backup`, `internal/signing`, the renewal scheduler and the rotation scheduler — must pass `model.NewAdminScope(actor)`; that is the deliberate, explicit statement of trust the refactor buys.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/key_repository.go internal/repositories/certificate_repository.go internal/repositories/final_api_test.go internal/services/keys internal/services/certificates api/keys.go api/certificates.go api/certificate_policy.go cmd/keys/list.go
git commit -S -m "refactor(keys,certificates)!: remove the InVault and ByOwner shims"
```

---

### Task 35: CI grep gate and documentation corrections

**Files:**
- Modify: `.github/workflows/go.yml` (add a gate job)
- Modify: `CLAUDE.md` (remove the `internal/domain/` fiction)
- Modify: `.claude/multi-vault.md` (correct the vault-scoped-route claim)
- Test: the gate script itself, run locally.

**Interfaces:**
- Consumes: the final API from Tasks 33 and 34.
- Produces: a CI job that fails the build if a legacy name returns.

- [ ] **Step 1: Run the gate locally and confirm it is clean**

Run:

```bash
grep -rn "InVault\|ReadByOwner\|ListByUser(" --include="*.go" . | grep -v "_test.go"
grep -rn "ReadScoped\|UpdateScoped\|ListScoped\|GetSecretScoped\|ListSecretsScoped\|DeleteSecretScoped\|UpdateSecretScoped\|GetKeyScoped\|ListKeysScoped\|UpdateKeyScoped\|DeleteKeyScoped\|GetCertificateScoped\|ListCertificatesScoped\|UpdateCertificateScoped\|DeleteCertificateScoped" --include="*.go" .
grep -rn "model\.Scope{" --include="*.go" . | grep -v "^./model/scope_test.go" | grep -v "^./api/context.go"
```

Expected: zero matches from all three. The first is the spec's §5.4 gate. The second catches a transitional name that survived the Phase 6 rename. The third enforces the composite-literal ban, with the two documented exceptions: `model/scope_test.go` (which writes unqualified `Scope{…}` and so does not match anyway) and `api/context.go`'s two fail-closed returns from Task 23. If the third grep is non-empty for any other file, that file is constructing a scope by hand — replace it with a constructor.

- [ ] **Step 2: Add the gate to CI**

Add to `.github/workflows/go.yml`, after the existing `lint` job:

```yaml
  scope-gate:
    name: Scope API Gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: No legacy InVault/ByOwner methods
        run: |
          if grep -rn "InVault\|ReadByOwner\|ListByUser(" --include="*.go" . | grep -v "_test.go"; then
            echo "::error::legacy vault-scoping methods reintroduced; use model.Scope"
            exit 1
          fi

      - name: No transitional Scoped suffix
        run: |
          if grep -rnE "(Read|Update|List)Scoped|(Get|List|Update|Delete)(Secret|Secrets|Key|Keys|Certificate|Certificates)Scoped" --include="*.go" .; then
            echo "::error::transitional Scoped suffix survived the Phase 6 rename"
            exit 1
          fi

      - name: No hand-built Scope literals
        run: |
          if grep -rn "model\.Scope{" --include="*.go" . | grep -v "^./api/context.go"; then
            echo "::error::construct scopes with NewVaultScope/NewOwnerScope/NewAdminScope"
            exit 1
          fi
```

- [ ] **Step 3: Correct the documentation**

In `CLAUDE.md`, the architecture tree and the "Perfect Domain-Driven Design Implementation" section describe an `internal/domain/` package that does not exist. Replace every reference to `internal/domain/` (`internal/domain/user.go`, `secret.go`, `key.go`, `certificate.go`) with `model/`, and add to the architecture tree:

```
├── model/                 # Pure domain types and constants (DDD)
│   ├── user.go            # User, Claims, Role constants
│   ├── secret.go          # Secret domain type
│   ├── key.go             # Key domain type
│   ├── certificate.go     # Certificate domain type
│   ├── vault.go           # Vault, DefaultVaultID, name/tag validation
│   └── scope.go           # Scope authorization value object
```

Add a short section documenting the scope model:

```markdown
### 🔐 Authorization Scope (`model/scope.go`)

Every repository and service operation carries a `model.Scope` describing how it
is authorized: `ScopeVault` (any vault member), `ScopeOwner` (the owner only;
retired in P2) or `ScopeAdmin` (no predicate, trusted internal callers). The zero
value is `ScopeInvalid`, so an uninitialised scope fails closed. Build scopes
with `NewVaultScope`, `NewOwnerScope` or `NewAdminScope`; composite literals are
banned outside `model/scope_test.go` and enforced by the `scope-gate` CI job.
```

In `.claude/multi-vault.md`, the claim "no vault-scoped route silently ignores its vault" is false for `PUT /vaults/{n}/certificates/{id}` (no vault-scoped certificate update exists at all), `POST /vaults/{n}/keys/{id}/rotate` and `GET /vaults/{n}/keys/{id}/versions`. Replace it with:

```markdown
Three vault-scoped routes still ignore their vault and are fixed in P3:
`PUT /vaults/{n}/certificates/{id}`, `POST /vaults/{n}/keys/{id}/rotate` and
`GET /vaults/{n}/keys/{id}/versions`.
```

- [ ] **Step 4: Run the full suite and the gate**

Run:

```bash
go build ./... && go test ./...
grep -rn "InVault\|ReadByOwner\|ListByUser(" --include="*.go" . | grep -v "_test.go"
```

Expected: PASS, and the grep returns zero matches.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/go.yml CLAUDE.md .claude/multi-vault.md
git commit -S -m "ci: gate the scope API and correct the domain-package documentation"
```

---

## Completion checklist

- [ ] `go build ./... && go test ./...` green on the final commit.
- [ ] All three greps in Task 35 Step 1 return zero matches.
- [ ] `TestScopePredicateBindArity`, `TestZeroScopeRejectedByEveryRepositoryMethod` and `TestEveryMutatorInvalidates` all present and passing.
- [ ] The P0 B6 tests are still green and were never edited by a refactor commit except for the two documented 403→404 changes (Tasks 19 and 26).
- [ ] Every commit is GPG-signed.
- [ ] P1 is **not** deployed without P0 and P2 in the same release.
