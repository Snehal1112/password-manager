# Drop the Vestigial `user_id` Filter from Key-Version Queries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the `userID` parameter and its `k.user_id` SQL filter from the five `KeyRepository` version methods, where it can no longer fail and therefore authorizes nothing — while looking like it does.

**Architecture:** Pure refactor, no behavior change. Every caller obtains the key from an already-scoped `Read` and then passes that key's *owner* ID — not the caller's — so the predicate is satisfied by construction on every code path. The methods align with the existing precedent for secret versions: `SecretVersionRepositoryInterface` (`internal/repositories/versioning_repository.go:18-29`) takes no user or scope on any method, because its caller has already authorized the parent secret.

**Tech Stack:** Go 1.24, `database/sql` over SQLite (dev) / PostgreSQL (prod), mockery v2 (`.mockery.yaml`), testify.

**Spec:** No separate design doc. The finding comes from the 2026-08-19 whole-branch review of `docs/superpowers/plans/2026-08-19-item-backup-vault-scoped-authz.md`, which observed that after that branch *"every caller passes an owner ID taken from an already-vault-scoped read, so the predicate can never fail — but it looks like it does, which is exactly how the [version-history] bug was born."* The design decisions are stated inline below.

## Why this is worth doing

`.claude/known-bugs.md` § B28 records a bug this exact ambiguity caused. `ItemBackupService.BackupKey` passed the **caller's** ID to `ListVersionRecords`. That was correct only while an ownership check upstream guaranteed caller == owner. When the 2026-08-19 branch removed that check, the parameter silently became wrong: a non-owning caller's backup would have returned zero version rows and dropped the key's rotation history with no error. It was caught at plan time, not by the type system — because a parameter that looks like an authorization control, but is really "pass the owner's ID you just read", gives no signal when it is passed the wrong thing.

Deleting the parameter makes the wrong call impossible to write.

## What this deliberately does NOT do

Authorization is unchanged. It lives where it already lives: `PolicyMiddleware` checks the RBAC data action, and the caller's scoped `Read` of the parent key enforces the vault predicate (`internal/repositories/scope_predicate.go:29-31`). These five methods are reached only *after* that read succeeds. This plan does not add, move, or weaken any check — it removes a parameter that performs none.

An alternative was considered and rejected: threading `model.Scope` into these methods and applying `scopePredicate`. It re-validates what the caller has already proved one line earlier, adds a parameter to five signatures, and breaks the secret-version precedent. Rejected as defense-in-theatre.

## Global Constraints

- **No behavior change *for any production caller*.** Every existing test must pass with only the mechanical signature update at its call site, with exactly one expected exception, named below. If any *other* test's assertion has to change, stop and report — that means behavior moved somewhere it shouldn't.
- **The one expected deletion: `TestKeyVersions_ReadVersionValue_WrongOwner`** (`internal/repositories/key_versions_test.go:95`). It calls `repo.ReadVersionValue(ctx, keyID, 1, other)` with a non-owner ID and asserts `ErrKeyVersionNotFound`. It pins the filter this plan removes, and it cannot be rewritten — after the change there is no owner argument to pass. Delete it, and say so in your report. It is the direct analogue of the six ownership-403 tests deleted on the 2026-08-19 branch: a test asserting behavior that is being deliberately retired. No production caller could ever reach the state it describes, because no production caller passes anything but the owner ID from a scoped read — which is the entire premise of this refactor.
- **`CurrentVersion` keeps its `LEFT JOIN keys k`.** Only the `AND k.user_id = ?` term goes. The join is load-bearing for a different reason, documented at `internal/repositories/key_repository.go:857-862`: a never-rotated key has zero `key_versions` rows, and the `LEFT JOIN` from `keys` is what makes `COALESCE(MAX(kv.version), 1)` return 1 instead of no row at all. The other four methods select only from `key_versions` and drop their join entirely.
- **Every changed method gets a doc comment stating the new contract** in place of the old "authorized against userID" wording: the caller MUST have already authorized the parent key via a scoped `Read`. A silent removal leaves the next reader assuming the check still exists somewhere.
- **Mocks are regenerated, not hand-edited.** `internal/repositories/mocks/mock_KeyRepositoryInterface.go` is mockery-generated (`.mockery.yaml`). Run mockery; do not patch it by hand.
- **Go 1.24, existing dependencies only.**

## File structure

| File | Responsibility |
|---|---|
| `internal/repositories/key_repository.go` (modify) | Interface decls + 5 implementations + their SQL |
| `internal/services/keys/key_service.go` (modify) | Callers of `ListVersions`, `GetVersion` |
| `internal/services/keys/crypto_service.go` (modify) | Callers of `CurrentVersion`, `ReadVersionValue` |
| `internal/backup/item_backup.go` (modify) | Caller of `ListVersionRecords` |
| `internal/repositories/mocks/mock_KeyRepositoryInterface.go` (regenerate) | mockery output |
| Hand-written mocks in 8 test files (modify) | Signature updates |
| `internal/repositories/key_versions_test.go` (modify) | Real-DB tests; add the new contract assertion |
| `.claude/known-bugs.md` (modify) | Deferred-refactor entry recording why the parameter went |

**The five methods and their single callers** — all five callers pass an owner ID read from a scoped `Read`:

| Method | Impl | Caller |
|---|---|---|
| `ListVersions` | `key_repository.go:717` | `key_service.go:510` (`ListKeyVersions`) |
| `ReadVersionValue` | `key_repository.go:750` | `crypto_service.go:227` (`resolveVersionValue`) |
| `GetVersion` | `key_repository.go:789` | `key_service.go:527` (`GetKeyVersion`) |
| `ListVersionRecords` | `key_repository.go:831` | `item_backup.go:107` (`BackupKey`) |
| `CurrentVersion` | `key_repository.go:871` | `crypto_service.go:212` (`currentVersionNumber`) |

Tasks 1 and 2 split the five by whether they return key *material*, so a reviewer can gate the material-returning ones separately. Each task compiles and tests green on its own.

---

### Task 1: Drop the filter from the two material-returning methods

**Files:**
- Modify: `internal/repositories/key_repository.go` (interface decls ~51 and ~57; impls at `:750` `ReadVersionValue`, `:831` `ListVersionRecords`)
- Modify: `internal/services/keys/crypto_service.go:227`
- Modify: `internal/backup/item_backup.go:107`
- Regenerate: `internal/repositories/mocks/mock_KeyRepositoryInterface.go`
- Test: `internal/repositories/key_versions_test.go`

**Interfaces:**
- Produces: `ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int) (string, error)` and `ListVersionRecords(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error)`. Task 2 mirrors this shape for the other three.

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/key_versions_test.go`. Read the file's existing setup helpers first and reuse them — it already builds a real database; do not introduce a second harness.

```go
// TestVersionQueries_NotFilteredByOwner pins the contract these methods moved
// to: they return a key's versions by key ID alone. Authorization is the
// caller's scoped Read of the parent key, performed before these are reached.
// Before this change the queries joined keys and filtered k.user_id, so a
// lookup keyed on anyone but the owner returned nothing.
func TestVersionQueries_NotFilteredByOwner(t *testing.T) {
	t.Parallel()
	db := setupTestDB(t)
	log := logging.InitLogger()
	repo := repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	ctx := context.Background()
	keyID := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: uuid.New(), Name: "rotated",
		Type: model.KeyTypeRSA, Value: "pem-v2", Enabled: true, CreatedAt: time.Now(),
	}))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 1, "pem-v1"))

	value, err := repo.ReadVersionValue(ctx, keyID, 1)
	require.NoError(t, err)
	require.Equal(t, "pem-v1", value)

	records, err := repo.ListVersionRecords(ctx, keyID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "pem-v1", records[0].Value)
}
```

This is the harness the file already uses — `setupTestDB(t)` plus `repositories.NewKeyRepository(rvdb.NewConn(db, rvdb.SQLite), log)`, package `repositories_test`, imports already present at the top of the file (`rvdb "rocketvault/internal/db"`, `"rocketvault/internal/logging"`, `"rocketvault/internal/repositories"`, `"rocketvault/model"`, `"time"`). Do not add a new harness or helper.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/repositories/ -run TestVersionQueries_NotFilteredByOwner -v`

Expected: **build failure** — `not enough arguments in call to repo.ReadVersionValue` (3 supplied, 4 wanted).

- [ ] **Step 3: Change the two interface declarations**

In `internal/repositories/key_repository.go`, replace the two decls:

```go
	// ReadVersionValue returns the encrypted/handle material for one version
	// of a key, by key ID and version.
	//
	// It performs NO authorization. The caller MUST have already authorized
	// the parent key with a scoped Read -- these version rows are reachable
	// only through a key the caller has proved access to. A previous
	// signature took a userID and filtered on k.user_id; every caller
	// satisfied it by passing the owner ID from that same scoped Read, so it
	// could never fail while appearing to be a check. See known-bugs B28 for
	// the bug that ambiguity caused.
	ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int) (string, error)
```

```go
	// ListVersionRecords returns every version of a key INCLUDING material,
	// by key ID. Internal use only (the backup service) -- never wired to an
	// HTTP response.
	//
	// Performs no authorization; see ReadVersionValue for the contract.
	ListVersionRecords(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error)
```

- [ ] **Step 4: Change the two implementations and their SQL**

`ReadVersionValue` (`:750`) — drop the parameter, the `JOIN`, and the third bind:

```go
func (r *KeyRepository) ReadVersionValue(ctx context.Context, keyID uuid.UUID, version int) (string, error) {
```

```go
	err := r.db.QueryRowContext(ctx, `
		SELECT kv.value
		FROM key_versions kv
		WHERE kv.key_id = ? AND kv.version = ?`,
		keyID.String(), version,
	).Scan(&value)
```

`ListVersionRecords` (`:831`) — same treatment:

```go
func (r *KeyRepository) ListVersionRecords(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT kv.version, kv.value, kv.created_at
		FROM key_versions kv
		WHERE kv.key_id = ?
		ORDER BY kv.version ASC`,
		keyID.String(),
	)
```

Leave the rest of each function body — error wrapping, scanning, `rows.Err()` — exactly as it is.

- [ ] **Step 5: Update the two callers**

`internal/services/keys/crypto_service.go:227`:

```go
	value, err = s.keyRepo.ReadVersionValue(ctx, key.ID, requested)
```

`internal/backup/item_backup.go:107` — the comment above it explained why the owner ID was passed; that reason is gone, so replace it:

```go
	// Version records are fetched by key ID. The scoped Read above is the
	// authorization for them.
	versions, err := s.keyRepo.ListVersionRecords(ctx, id)
```

- [ ] **Step 6: Delete the test that pins the removed filter**

Delete `TestKeyVersions_ReadVersionValue_WrongOwner` (`internal/repositories/key_versions_test.go:95-110`) in full. It asserts that `ReadVersionValue` with a non-owner ID returns `ErrKeyVersionNotFound` — precisely the behavior being retired, and unrewritable once the argument is gone. Record the deletion in your report.

Check for siblings while you are there: `grep -n "WrongOwner\|other :=" internal/repositories/key_versions_test.go`. Delete any other test in that file whose assertion depends on the owner filter; leave alone every test that exercises `model.Scope`-based `Read`, which this plan does not touch.

- [ ] **Step 7: Regenerate the mockery mock and update hand-written mocks**

Run: `mockery` (config at `.mockery.yaml`; if the binary is absent, `go run github.com/vektra/mockery/v2@latest`).

Then update the hand-written mocks. Find them:

`grep -rln "ReadVersionValue\|ListVersionRecords" --include="*_test.go" .`

Each is a plain method-signature edit: drop the `userID uuid.UUID` parameter and drop it from the `m.Called(...)` argument list. Do not change any assertion.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go build ./... && go test ./internal/repositories/ -run TestVersionQueries_NotFilteredByOwner -v`
Expected: PASS.

Run: `go test ./... -count=1 2>&1 | grep -v "^ok" | head -20`
Expected: no failures. **If any test's assertion (not just its call site) had to change, stop and report** — this task must not move behavior.

- [ ] **Step 9: Commit**

```bash
git add internal/repositories/key_repository.go internal/repositories/key_versions_test.go internal/repositories/mocks/ internal/services/keys/crypto_service.go internal/backup/item_backup.go
git add -u
git commit -m "refactor(keys): drop the vestigial user_id filter from material-returning version queries"
```

---

### Task 2: Drop the filter from the three metadata methods

**Files:**
- Modify: `internal/repositories/key_repository.go` (interface decls; impls at `:717` `ListVersions`, `:789` `GetVersion`, `:871` `CurrentVersion`)
- Modify: `internal/services/keys/key_service.go:510` and `:527`
- Modify: `internal/services/keys/crypto_service.go:212`
- Regenerate: `internal/repositories/mocks/mock_KeyRepositoryInterface.go`
- Test: `internal/repositories/key_versions_test.go`

**Interfaces:**
- Consumes: the contract wording established in Task 1's doc comments — reuse it verbatim rather than inventing a second phrasing.
- Produces: `ListVersions(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error)`, `GetVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error)`, `CurrentVersion(ctx context.Context, keyID uuid.UUID) (int, error)`.

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/key_versions_test.go`:

```go
// TestCurrentVersion_NeverRotatedKeyStillReturnsOne guards the one subtlety in
// this refactor: CurrentVersion keeps its LEFT JOIN against keys even though
// the user_id term is gone. A never-rotated key has zero key_versions rows,
// and the LEFT JOIN is what makes COALESCE(MAX(kv.version), 1) yield a row
// containing 1 rather than no row at all. Dropping the join with the filter
// would turn this into sql.ErrNoRows.
func TestCurrentVersion_NeverRotatedKeyStillReturnsOne(t *testing.T) {
	repo, cleanup := newTestKeyRepo(t)
	defer cleanup()

	ctx := context.Background()
	keyID := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: uuid.New(), VaultID: uuid.New(),
		Name: "never-rotated", Value: "material", Type: model.KeyTypeRSA, Enabled: true,
	}))

	current, err := repo.CurrentVersion(ctx, keyID)
	require.NoError(t, err)
	require.Equal(t, 1, current, "a never-rotated key's implicit current version is 1")
}

// TestVersionMetadataQueries_NotFilteredByOwner mirrors Task 1's assertion for
// the metadata-only queries.
func TestVersionMetadataQueries_NotFilteredByOwner(t *testing.T) {
	repo, cleanup := newTestKeyRepo(t)
	defer cleanup()

	ctx := context.Background()
	keyID := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: uuid.New(), VaultID: uuid.New(),
		Name: "rotated", Value: "v2", Type: model.KeyTypeRSA, Enabled: true,
	}))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 1, "v1"))

	versions, err := repo.ListVersions(ctx, keyID)
	require.NoError(t, err)
	require.Len(t, versions, 1)

	v, err := repo.GetVersion(ctx, keyID, 1)
	require.NoError(t, err)
	require.Equal(t, 1, v.Version)

	current, err := repo.CurrentVersion(ctx, keyID)
	require.NoError(t, err)
	require.Equal(t, 1, current)
}
```

Use the file's real harness helper, as in Task 1.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/repositories/ -run 'TestCurrentVersion_NeverRotatedKeyStillReturnsOne|TestVersionMetadataQueries_NotFilteredByOwner' -v`
Expected: **build failure** — `not enough arguments in call to repo.ListVersions`.

- [ ] **Step 3: Change the three interface declarations**

```go
	// ListVersions returns all version records for a key, ordered by version
	// ASC. Performs no authorization; see ReadVersionValue for the contract.
	ListVersions(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error)
```

```go
	// GetVersion returns metadata (no material) for one version of a key.
	// Performs no authorization; see ReadVersionValue for the contract.
	GetVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error)
```

```go
	// CurrentVersion returns keyID's current version number: the highest
	// key_versions row if any rotation has happened, else the implicit 1
	// (a never-rotated key's only material is keys.value). Single aggregate
	// query -- avoids fetching every version row just to find the max.
	// Performs no authorization; see ReadVersionValue for the contract.
	CurrentVersion(ctx context.Context, keyID uuid.UUID) (int, error)
```

- [ ] **Step 4: Change the three implementations**

`ListVersions` (`:717`) — drop the join:

```go
func (r *KeyRepository) ListVersions(ctx context.Context, keyID uuid.UUID) ([]model.KeyVersion, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT kv.version, kv.created_at
		FROM key_versions kv
		WHERE kv.key_id = ?
		ORDER BY kv.version ASC`,
		keyID.String(),
	)
```

`GetVersion` (`:789`) — drop the join:

```go
func (r *KeyRepository) GetVersion(ctx context.Context, keyID uuid.UUID, version int) (*model.KeyVersion, error) {
```

```go
	err := r.db.QueryRowContext(ctx, `
		SELECT kv.created_at
		FROM key_versions kv
		WHERE kv.key_id = ? AND kv.version = ?`,
		keyID.String(), version,
	).Scan(&createdAt)
```

`CurrentVersion` (`:871`) — **keep the `LEFT JOIN`**, drop only the `user_id` term and its bind. Keep the existing explanatory comment block above the function, which documents why the `LEFT JOIN` (not an `INNER JOIN` from `key_versions`) is required; delete only the `userID` bullet from its parameter list:

```go
func (r *KeyRepository) CurrentVersion(ctx context.Context, keyID uuid.UUID) (int, error) {
	var version int
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(kv.version), 1)
		FROM keys k
		LEFT JOIN key_versions kv ON kv.key_id = k.id
		WHERE k.id = ?`,
		keyID.String(),
	).Scan(&version)
```

- [ ] **Step 5: Update the three callers**

`internal/services/keys/key_service.go:510`:

```go
	versions, err := s.keyRepo.ListVersions(ctx, keyID)
```

`internal/services/keys/key_service.go:527`:

```go
	return s.keyRepo.GetVersion(ctx, keyID, version)
```

Note both are preceded by a `GetKey(ctx, keyID, scope)` call whose result was used only for `key.UserID` in one case — check whether `key` is still used afterwards. In `GetKeyVersion` the `key` variable exists solely to supply `key.UserID`; once that argument is gone the variable is unused and the compiler will say so. Replace the assignment with a bare authorization check:

```go
func (s *keyService) GetKeyVersion(ctx context.Context, keyID uuid.UUID, version int, scope model.Scope) (*model.KeyVersion, error) {
	// The scoped read is the authorization for the version rows below.
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return nil, err
	}
	return s.keyRepo.GetVersion(ctx, keyID, version)
}
```

In `ListKeyVersions`, `key` is still used for the `key.CreatedAt` fallback, so keep the assignment there.

`internal/services/keys/crypto_service.go:212` (`currentVersionNumber`):

```go
func (s *cryptoService) currentVersionNumber(ctx context.Context, key *model.Key) (int, error) {
	return s.keyRepo.CurrentVersion(ctx, key.ID)
}
```

- [ ] **Step 6: Regenerate mocks and update hand-written mocks**

Run: `mockery`

Then: `grep -rln "ListVersions(\|GetVersion(\|CurrentVersion(" --include="*_test.go" . | grep -v worktrees`

Update each hand-written mock's signature and `m.Called(...)` list. Note `GetVersion` also exists on the *secret* version repository with a different signature — do not touch `MockSecretRepository`/`MockSecretVersionRepository`/`MockVersioningService`; only the key-repository mocks change.

- [ ] **Step 7: Run the full suite**

Run: `go build ./... && go vet ./... && go test ./... -count=1 2>&1 | grep -v "^ok" | head -20`
Expected: no failures. Same rule as Task 1 — if an assertion had to change, stop and report.

- [ ] **Step 8: Commit**

```bash
git add -u
git commit -m "refactor(keys): drop the vestigial user_id filter from version metadata queries"
```

---

### Task 3: Record the refactor

**Files:**
- Modify: `.claude/known-bugs.md`

**Interfaces:** none.

- [ ] **Step 1: Append a deferred-refactor entry**

`.claude/known-bugs.md` has a `## Deferred Refactors` section (around line 1300) using `### <ID> — <title>` headings with IDs like `H3`, `M2`, `F1`, `I1`. Read two neighbouring entries and match their structure. Add one using the next free ID in that scheme:

```markdown
### <ID> — Key-version queries carried a `user_id` filter that authorized nothing — FIXED

**Status:** Fixed 2026-08-20.

**What it was:** `KeyRepository`'s five version methods — `ListVersions`,
`ReadVersionValue`, `GetVersion`, `ListVersionRecords`, `CurrentVersion` — each
took a `userID uuid.UUID` and filtered `JOIN keys k ... AND k.user_id = ?`.

**Why it authorized nothing:** all five are reachable only after the caller has
read the parent key through a scoped `Read`, and every caller passed *that
key's owner ID* — never the caller's own. The predicate was therefore satisfied
by construction on every code path and could not fail.

**Why it was worth removing:** a parameter that looks like an authorization
control but is really "pass back the owner ID you just read" gives no signal
when it is passed the wrong value. § B28 is exactly that bug:
`ItemBackupService.BackupKey` passed the *caller's* ID, which was correct only
while an upstream ownership check guaranteed caller == owner. When that check
was removed, the argument silently became wrong, and a non-owning caller's
backup would have returned zero version rows — dropping a rotated key's history
with no error. It was caught by review, not by the type system.

**Fix:** parameter and filter removed from all five; the interface now states
the real contract (the caller must have authorized the parent key via a scoped
`Read`). This matches `SecretVersionRepositoryInterface`
(`internal/repositories/versioning_repository.go:18-29`), which has always taken
no user or scope for the same reason. `CurrentVersion` keeps its
`LEFT JOIN keys k` — that join is load-bearing for the never-rotated-key
`COALESCE(..., 1)` fallback, not for authorization.

**Pinned by:** `TestVersionQueries_NotFilteredByOwner`,
`TestVersionMetadataQueries_NotFilteredByOwner`,
`TestCurrentVersion_NeverRotatedKeyStillReturnsOne`
(`internal/repositories/key_versions_test.go`).
```

- [ ] **Step 2: Commit**

```bash
git add .claude/known-bugs.md
git commit -m "docs: record the key-version user_id filter removal"
```
