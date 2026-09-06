# API Refactor 09 — Fix `getDeletedKey`'s Full-Listing Scan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve `GET /deleted/keys/{key_id}` with a single scoped row read instead of listing every soft-deleted key in the vault and scanning for one id.

**Architecture:** This is the first **behavior-changing** plan; tests may be added and modified from here on. The fix needs a scoped by-id read of a soft-deleted key, which does not exist today — `KeyRepository.Read` filters `deleted_at IS NULL`, and the existing `KeyRepository.ReadDeleted(ctx, id)` takes **no scope at all**, so calling it from a handler would read across vault boundaries. So this plan adds a properly scoped repository method and a service method on top of it.

**Tech Stack:** Go 1.25, `internal/repositories/scoped_crud.go`'s `ScopedGet[T]`.

**Spec:** `docs/superpowers/specs/2026-09-06-api-generic-primitives-design.md`

## Global Constraints

- Go 1.25.0.
- Worktree `/home/numericlabs/data/rocket/rocketvault-api-refactor`, branch `refactor/api-generics`.
- **This plan crosses out of `api/`** into `internal/services/keys/` and `internal/repositories/`. That is a deliberate, flagged widening of the original scope, because the defect cannot be fixed inside `api/` alone.
- **Never use the unscoped `KeyRepository.ReadDeleted` from a handler.** Scope is the authorization predicate; a handler reaching an unscoped read is a vault-isolation hole.
- Gate: `./scripts/verify-api-refactor.sh` before every commit.
- Commits GPG-signed. Comments are short plain sentences ending in punctuation. No emojis.

---

### Task 1: Confirm the fan-out cost and decide

**Files:**
- Modify: none (analysis only)

**Interfaces:**
- Consumes: `internal/services/keys/key_service.go`, `internal/repositories/key_repository.go`.
- Produces: a go/no-go decision, recorded either as a commit in Task 2 or as a `.claude/known-bugs.md` entry.

Adding a method to `KeyService`'s interface has a known, documented fan-out. Measure it before writing code, so the decision is made with the real number rather than an optimistic one.

- [ ] **Step 1: Enumerate everything that implements `KeyService`**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
grep -rln 'ListDeletedKeys' --include='*.go' . | sort
```

Every file in that list implements or stubs the interface and will need a pass-through for any new method. Expect at least:
- `internal/services/keys/key_service.go` (the interface and the real implementation)
- `internal/services/retry/retry_key_service.go` (the retry wrapper)
- generated mockery doubles under `internal/services/keys/mocks/` or similar
- hand-rolled stubs in `cmd/testutils/test_utils.go` and `internal/testutils/mocks.go`

- [ ] **Step 2: Confirm the two facts this plan rests on**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
grep -n 'FROM keys WHERE id = ?' internal/repositories/key_repository.go
grep -n 'func (r \*KeyRepository) ReadDeleted' internal/repositories/key_repository.go
```
Expected:
1. `Read`'s query ends `AND deleted_at IS NULL`, so `GetKey` genuinely cannot serve a soft-deleted key.
2. `ReadDeleted(ctx context.Context, id uuid.UUID)` takes no `model.Scope`.

If either has changed, re-plan rather than proceeding — the second in particular would mean a scoped read already exists and Task 2 should use it instead of adding one.

- [ ] **Step 3: Decide**

Proceed to Task 2 if the fan-out from Step 1 is five files or fewer.

If it is larger, **stop**. Do not proceed. Instead file the defect and end the plan here:

```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
```
Append to `.claude/known-bugs.md` under its open-bugs section:

```markdown
### OPEN: `getDeletedKey` lists an entire vault to serve one id

`api/soft_delete.go`'s `getDeletedKey` calls `KeyService.ListDeletedKeys` for
the whole vault and linear-scans the result for one key id. It is O(n) in the
vault's soft-deleted key count for a single-item GET.

Root cause: no scoped by-id read of a soft-deleted key exists.
`KeyRepository.Read` filters `deleted_at IS NULL`, and `KeyRepository.ReadDeleted`
takes no `model.Scope`, so a handler calling it would read across vault
boundaries.

Fix recipe: add `ReadDeletedScoped(ctx, id, scope)` to `KeyRepository` built on
`ScopedGet[T]`, expose it as `KeyService.GetDeletedKey`, and rewire the handler.
Deferred because the `KeyService` interface fan-out exceeded five files.

Also worth auditing separately: every current caller of the unscoped
`ReadDeleted`, to confirm none of them is on an authorization-relevant path.
```

Then commit and skip to the next plan:
```bash
git add .claude/known-bugs.md
git commit -S -m "docs(api): file the getDeletedKey full-listing scan as a known bug"
```

---

### Task 2: Add the scoped repository and service reads

**Files:**
- Modify: `internal/repositories/key_repository.go`
- Modify: `internal/services/keys/key_service.go`
- Modify: `internal/services/retry/retry_key_service.go`
- Modify: every mock or stub enumerated in Task 1 Step 1

**Interfaces:**
- Consumes: `ScopedGet[T]` (`internal/repositories/scoped_crud.go`), `model.Scope`.
- Produces:
  - `func (r *KeyRepository) ReadDeletedScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error)`
  - `KeyService.GetDeletedKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)`

- [ ] **Step 1: Write the failing test**

Add to `internal/services/keys/key_service_test.go` (or the file where `ListDeletedKeys` is already tested — match the existing table style there):

```go
func TestGetDeletedKey_ReturnsSoftDeletedKeyInScope(t *testing.T) {
	svc, repo := newTestKeyService(t)
	scope := model.NewVaultScope(testVaultID, testUserID)

	key := seedSoftDeletedKey(t, repo, testVaultID, testUserID)

	got, err := svc.GetDeletedKey(context.Background(), key.ID, scope)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, key.ID, got.ID)
	assert.NotNil(t, got.DeletedAt, "a soft-deleted key must carry its deleted_at")
}

func TestGetDeletedKey_DeniesKeyInAnotherVault(t *testing.T) {
	svc, repo := newTestKeyService(t)

	key := seedSoftDeletedKey(t, repo, testVaultID, testUserID)
	otherVault := model.NewVaultScope(uuid.New(), testUserID)

	_, err := svc.GetDeletedKey(context.Background(), key.ID, otherVault)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound,
		"a key outside the scope must read as not found, not as a permission error, "+
			"so the endpoint is not an existence oracle")
}
```

`newTestKeyService` and `seedSoftDeletedKey` are placeholders for whatever the
existing tests in that file already use — read the file first and reuse its
helpers rather than inventing new ones. If no soft-deleted-key seeding helper
exists, write one modelled on how the `ListDeletedKeys` tests build their fixtures.

- [ ] **Step 2: Run it and watch it fail**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
go test ./internal/services/keys/... -count=1 -run 'GetDeletedKey' -v 2>&1 | tail -20
```
Expected: a compile failure, `svc.GetDeletedKey undefined`. That is the correct first failure.

- [ ] **Step 3: Implement, then make it pass**

In `internal/repositories/key_repository.go`, beside `ReadDeleted`:

```go
// ReadDeletedScoped retrieves a soft-deleted key by ID within scope.
//
// It is the scoped counterpart of ReadDeleted, which takes no scope and must
// therefore never be reached from a request handler: scope is the
// authorization predicate, and an unscoped read crosses vault boundaries.
func (r *KeyRepository) ReadDeletedScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	query := "SELECT " + keyColumns + " FROM keys WHERE id = ? AND deleted_at IS NOT NULL"
	return ScopedGet[model.Key](ctx, r.conn, query, []any{id.String()}, scope, scanKeyRow)
}
```

Match `ScopedGet`'s real signature and the repository's real field and scanner
names — read `internal/repositories/scoped_crud.go` and the existing `Read`
before writing this. Two constraints from that file: the query must already
carry a `WHERE`, because the scope predicate is appended with `" AND "`; and
the appended predicate is unqualified (`vault_id = ?`), which is fine here
because `keys` is the only table in the query.

Add to the `KeyService` interface and implementation:

```go
	// GetDeletedKey retrieves a soft-deleted key by id, authorized by scope.
	// A key outside the scope reads as not found so the endpoint is not an
	// existence oracle, matching GetKey.
	GetDeletedKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
```

```go
func (s *keyService) GetDeletedKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	key, err := s.keyRepo.ReadDeletedScoped(ctx, keyID, scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}
	// No IsAccessible check here, unlike GetKey: a soft-deleted key is by
	// definition outside its normal lifecycle, and this endpoint exists
	// precisely to report on it.
	return key, nil
}
```

Add the pass-through to `internal/services/retry/retry_key_service.go`, using
the package's `retried[T]` helper as every other method there does, plus a stub
in each mock and test double from Task 1 Step 1.

Run:
```bash
go test ./internal/services/keys/... -count=1 -run 'GetDeletedKey' -v 2>&1 | tail -20
```
Expected: both tests pass.

Then commit:
```bash
git add internal/repositories/key_repository.go internal/services/keys/ internal/services/retry/ internal/testutils/ cmd/testutils/
git commit -S -m "feat(keys): add a scoped read for soft-deleted keys"
```

---

### Task 3: Rewire the handler and prove the fix

**Files:**
- Modify: `api/soft_delete.go` (`getDeletedKey`)
- Modify: `api/soft_delete_test.go` or `api/soft_delete_extended_test.go`

**Interfaces:**
- Consumes: `KeyService.GetDeletedKey` from Task 2, `svc[T]`, `resourceID`, `writeJSON`, `writeKeyError`.
- Produces: no new symbols.

- [ ] **Step 1: Rewrite the handler**

Replace `getDeletedKey` in `api/soft_delete.go`:

```go
// getDeletedKey returns a single soft-deleted key by its UUID, resolved within
// the same vault scope as listDeletedKeys.
//
// It has no vault-scoped route counterpart (secrets exposes no single-item
// deleted GET either), so it stays registered on the flat router only, where it
// resolves to the default vault.
//
// It reads one row rather than listing the vault's soft-deleted keys and
// scanning for a match, which is what it did before.
func getDeletedKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	keyID, ok := resourceID(c, c.Params.KeyID, "key_id")
	if !ok {
		return
	}

	keySvc, ok := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !ok {
		return
	}

	key, err := keySvc.GetDeletedKey(r.Context(), keyID, model.NewVaultScope(vaultID, userID))
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, map[string]any{
		"id":               key.ID.String(),
		"name":             key.Name,
		"type":             key.Type,
		"deleted_at":       key.DeletedAt,
		"purge_protection": key.PurgeProtection,
	})
}
```

Keep the step order — vault, then user claim, then key id — because that is the
order the previous handler used and it decides which 400 a doubly-malformed
request gets.

**One deliberate behavior change:** a missing key previously produced
`c.SetNotFound("key")` from the fall-through after the scan. It now flows
through `writeKeyError`, which maps `ErrKeyNotFound` to `c.SetNotFound("key")`
— the same 404 with the same body. Confirm that in Step 2 rather than assuming it.

- [ ] **Step 2: Add the regression test**

Add to `api/soft_delete_extended_test.go`, matching that file's existing style:

```go
func TestGetDeletedKey_UnknownID_Returns404(t *testing.T) {
	// The pre-fix handler produced this 404 by exhausting a listing; the
	// rewritten one produces it from ErrKeyNotFound through writeKeyError.
	// The response must be identical either way.
	rec := doGetDeletedKey(t, uuid.New())

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "key not found")
}

func TestGetDeletedKey_DoesNotListTheVault(t *testing.T) {
	// The point of the fix: serving one id must not fetch the whole vault.
	svc := &countingKeyService{}
	rec := doGetDeletedKeyWith(t, svc, uuid.New())

	assert.Zero(t, svc.listDeletedCalls,
		"getDeletedKey must not call ListDeletedKeys to serve a single id")
	assert.Equal(t, 1, svc.getDeletedCalls)
	_ = rec
}
```

`doGetDeletedKey`, `doGetDeletedKeyWith` and `countingKeyService` are
placeholders for that file's existing request helpers and mock type — read it
first and reuse what is there. The second test is the one that actually pins
the fix; without it a future change could silently reintroduce the scan.

- [ ] **Step 3: Gate and commit**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault-api-refactor
gofmt -l api/ internal/
go test ./api/... -count=1 -run 'Deleted' -v 2>&1 | tail -30
./scripts/verify-api-refactor.sh
```
Expected: targeted run passes, gate `PASS`. Coverage should hold or rise; the
new tests add covered statements.

```bash
git add api/soft_delete.go api/soft_delete_extended_test.go
git commit -S -m "fix(api): serve getDeletedKey from a scoped read, not a vault listing"
```

---

## Next plan

**Execute `docs/superpowers/plans/2026-09-06-api-refactor-10-typed-responses.md` next.**
