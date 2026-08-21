# B38 — `secrets import --overwrite` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `secrets import --overwrite` actually overwrite an existing secret of the same name (versioning the prior value), skip it when `--overwrite` is unset, and report skipped counts separately from failed counts.

**Architecture:** `SecretRepositoryInterface` gains a new scoped lookup, `FindByName`, so `secretService.ImportSecrets` can tell "name does not exist" from "name exists" before deciding whether to `CreateSecret` or `UpdateSecret`. `ImportResult` gains `FailedCount` so a record that errored is no longer folded into the same counter as a record the import intentionally declined to touch. The CLI prints the new counter and its help text stops describing the bug as documented behavior.

**Tech Stack:** Go 1.24.2, database/sql (SQLite/PostgreSQL via `internal/db`), testify (`mock`, `require`, `assert`), Cobra.

**Spec:** `docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`

## Global Constraints

- Go 1.24.2. Do not raise the version floor.
- Comments are short, full sentences ending in a punctuation mark.
- Every fix starts with a failing test (see the design doc's "Testing" table).
- `cmd/help_examples_test.go` guards CLI help text: every `--flag` named in an
  `Example` block must already be registered on that command or an ancestor,
  or the build fails the validator. Do not invent flags.
- `.claude/cli-help-conventions.md` is the house style for `Use`/`Short`/`Long`/
  `Example` — follow it for any help-text change in this plan.
- No change to `CreateSecret`'s behavior for the not-found path: a name that
  does not exist in the target vault is still created exactly as today.
- `model.Scope`'s vault predicate (`internal/repositories/scope_predicate.go`)
  is the only access boundary; `FindByName` must go through it like every
  other scoped repository method, never bypass it with a raw query.
- Do not change `CreateSecret`/`UpdateSecret`'s own signatures or behavior —
  this bug is fixed entirely in the import loop and the repository lookup it
  needs.

---

### Task 1: Add `FindByName` to `SecretRepositoryInterface`

No scoped lookup-by-name method exists on `SecretRepositoryInterface` today
(`internal/repositories/secret_repository.go:20-46`) — the closest analogue is
`VaultRepositoryInterface.ReadByName` (`internal/repositories/vault_repository.go:21,121-129`),
which this task mirrors: same `ErrNotFound`-wrapped sentinel on a miss, same
`scopePredicate` plumbing `Read` already uses for id-based lookups.

Every other implementer of `SecretRepositoryInterface` must gain the same
method to keep compiling once it is added: `RetryRepositoryWrapper`
(`internal/services/retry/retry_repository_wrapper.go`), the hand-written
testify mocks (`internal/testutils/mocks.go`'s `MockSecretRepository`,
`internal/services/retry/retry_wrappers_test.go`'s `MockSecretRepo`,
`api/backup_item_test.go`'s `mockSecretRepo`), and the mockery-generated
`internal/repositories/mocks/mock_SecretRepositoryInterface.go` (regenerated,
not hand-edited, via the `mockery` binary already installed at
`/home/numericlabs/go/bin/mockery`, driven by the repo's `.mockery.yaml`).

**Files:**
- Modify: `internal/repositories/secret_repository.go` (interface at l.20-46,
  implementation after `Read` at l.183-206)
- Modify: `internal/repositories/secret_repository_test.go` (new tests)
- Modify: `internal/services/retry/retry_repository_wrapper.go`
- Modify: `internal/services/retry/retry_wrappers_test.go` (l.302-405,
  `MockSecretRepo`)
- Modify: `internal/testutils/mocks.go` (l.126-227, `MockSecretRepository`)
- Modify: `api/backup_item_test.go` (l.291-349, `mockSecretRepo`)
- Regenerate: `internal/repositories/mocks/mock_SecretRepositoryInterface.go`

**Interfaces:**
- Consumes: `scopePredicate(scope model.Scope) (string, []any, error)`
  (`internal/repositories/scope_predicate.go`), `scanSecretRow`, `secretColumns`
  (`internal/repositories/secret_repository.go`), `repositories.ErrNotFound`
  (`internal/repositories/errors.go`).
- Produces:
  ```go
  // FindByName looks up the active (non-deleted) secret named name within
  // scope. It returns repositories.ErrNotFound, wrapped, when no such secret
  // exists in scope — including when a secret of that name exists but is
  // outside the scope or soft-deleted.
  FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error)
  ```

- [ ] **Step 1: Write the failing repository tests**

Add to `internal/repositories/secret_repository_test.go` (append at end of
file):

```go
func TestSecretRepository_FindByName_VaultScope_FindsActiveSecret(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()
	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    userID,
		VaultID:   vaultID,
		Name:      "db-password",
		Value:     "encrypted-data",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, repo.Create(ctx, secret))

	found, err := repo.FindByName(ctx, "db-password", model.NewVaultScope(vaultID, userID))
	require.NoError(t, err)
	assert.Equal(t, secret.ID, found.ID)
	assert.Equal(t, "db-password", found.Name)
}

func TestSecretRepository_FindByName_UnknownReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()

	_, err := repo.FindByName(ctx, "ghost", model.NewVaultScope(vaultID, userID))
	require.Error(t, err)
	assert.ErrorIs(t, err, repositories.ErrNotFound)
}

func TestSecretRepository_FindByName_SoftDeletedSecretNotVisible(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()
	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    userID,
		VaultID:   vaultID,
		Name:      "rotated-out",
		Value:     "encrypted-data",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, repo.Create(ctx, secret))
	require.NoError(t, repo.SoftDelete(ctx, secret.ID))

	_, err := repo.FindByName(ctx, "rotated-out", model.NewVaultScope(vaultID, userID))
	require.Error(t, err)
	assert.ErrorIs(t, err, repositories.ErrNotFound)
}

func TestSecretRepository_FindByName_WrongVaultReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultA := uuid.New()
	vaultB := uuid.New()
	userID := uuid.New()
	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    userID,
		VaultID:   vaultA,
		Name:      "shared-name",
		Value:     "encrypted-data",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, repo.Create(ctx, secret))

	_, err := repo.FindByName(ctx, "shared-name", model.NewVaultScope(vaultB, userID))
	require.Error(t, err)
	assert.ErrorIs(t, err, repositories.ErrNotFound)
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `go test ./internal/repositories/... -run TestSecretRepository_FindByName -v`
Expected: FAIL — compile error, `repo.FindByName undefined (type
repositories.SecretRepositoryInterface has no field or method FindByName)`.

- [ ] **Step 3: Add the method to the interface and implement it**

In `internal/repositories/secret_repository.go`, add to
`SecretRepositoryInterface` (after `Read`, before `Update`, l.25-28):

```go
	// FindByName looks up the active (non-deleted) secret named name within
	// scope. It returns ErrNotFound, wrapped, when no such secret exists in
	// scope. ImportSecrets uses this to decide whether a record is a create
	// or an overwrite.
	FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error)
```

Add the implementation directly after `Read` (after l.206):

```go
// FindByName looks up the active secret named name, authorized by scope. It
// mirrors Read's scoping rules exactly, keyed on name instead of id.
func (r *SecretRepository) FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	query := "SELECT " + secretColumns + " FROM secrets WHERE name = ? AND " + predicate + " AND deleted_at IS NULL"
	queryArgs := append([]any{name}, args...)

	secret, err := scanSecretRow(r.db.QueryRowContext(ctx, query, queryArgs...).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("secret %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret by name: %w", err)
	}
	return &secret, nil
}
```

- [ ] **Step 4: Run the repository tests to see them pass**

Run: `go test ./internal/repositories/... -run TestSecretRepository_FindByName -v`
Expected: PASS, all four tests.

- [ ] **Step 5: Find every other implementer that now fails to compile**

Run: `go build ./...`
Expected: FAIL, listing `*RetryRepositoryWrapper does not implement
repositories.SecretRepositoryInterface (missing method FindByName)` for
`internal/services/retry` and a similar error for
`internal/repositories/mocks` (`MockSecretRepositoryInterface`) and
`internal/testutils` (`MockSecretRepository`), depending on where each is
referenced as the interface type.

- [ ] **Step 6: Add `FindByName` to `RetryRepositoryWrapper`**

In `internal/services/retry/retry_repository_wrapper.go`, add after `Read`
(after l.39):

```go
// FindByName wraps the FindByName operation with retry logic.
func (r *RetryRepositoryWrapper) FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error) {
	return retried(ctx, r.retryService, func() (*model.Secret, error) {
		return r.baseRepo.FindByName(ctx, name, scope)
	})
}
```

- [ ] **Step 7: Add `FindByName` to `internal/testutils.MockSecretRepository`**

In `internal/testutils/mocks.go`, add after the `Read` mock method (after
l.142):

```go
func (m *MockSecretRepository) FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, name, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}
```

- [ ] **Step 8: Run `go build ./...` again**

Run: `go build ./...`
Expected: PASS. Non-test-file implementers are now complete; test-file-only
implementers (`_test.go`, which `go build` does not compile) still need
fixing — the next step finds them.

- [ ] **Step 9: Find the remaining test-file implementers**

Run: `go vet ./...`
Expected: FAIL, listing `*MockSecretRepo does not implement
repositories.SecretRepositoryInterface` in
`internal/services/retry/retry_wrappers_test.go` and `*mockSecretRepo does
not implement repositories.SecretRepositoryInterface` in
`api/backup_item_test.go`.

- [ ] **Step 10: Add `FindByName` to `MockSecretRepo`**

In `internal/services/retry/retry_wrappers_test.go`, add after the `Read`
mock method (after l.317, before `Update`):

```go
func (m *MockSecretRepo) FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, name, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}
```

- [ ] **Step 11: Add `FindByName` to `mockSecretRepo`**

In `api/backup_item_test.go`, add after the `Read` mock method (after l.311,
before `Update`):

```go
func (m *mockSecretRepo) FindByName(_ context.Context, _ string, _ model.Scope) (*model.Secret, error) {
	return nil, errors.New("not implemented")
}
```

- [ ] **Step 12: Regenerate the mockery mock**

Run (from the repo root, so `.mockery.yaml` is picked up):
```bash
/home/numericlabs/go/bin/mockery
```
Expected: `internal/repositories/mocks/mock_SecretRepositoryInterface.go` is
rewritten with a new `FindByName`/`EXPECT().FindByName` pair, in the same
generated style as every other method. Confirm with:
```bash
grep -n "FindByName" internal/repositories/mocks/mock_SecretRepositoryInterface.go
```
Expected: several matches (method, expecter, call-return, run-and-return).

- [ ] **Step 13: Confirm the whole build and vet are clean**

Run: `go build ./... && go vet ./...`
Expected: both succeed with no output.

- [ ] **Step 14: Run the affected package tests**

Run: `go test ./internal/repositories/... ./internal/services/retry/... ./api/... -v 2>&1 | tail -60`
Expected: PASS across all three packages (spot-check the tail; these
packages have large suites, so `-run` a narrower pattern first if the full
run is slow, then widen once green).

- [ ] **Step 15: Commit**

```bash
git add internal/repositories/secret_repository.go \
  internal/repositories/secret_repository_test.go \
  internal/repositories/mocks/mock_SecretRepositoryInterface.go \
  internal/services/retry/retry_repository_wrapper.go \
  internal/services/retry/retry_wrappers_test.go \
  internal/testutils/mocks.go \
  api/backup_item_test.go
git commit -m "feat(secrets): add scoped FindByName lookup to SecretRepositoryInterface

Adds the by-name lookup ImportSecrets needs to detect an existing
secret before deciding whether to create or overwrite it (B38). No
existing repository method exposed a scoped name lookup, so every
implementer of SecretRepositoryInterface gains the method to keep
compiling: the retry wrapper, the generated mockery mock, and the
hand-written test doubles."
```

---

### Task 2: Make `--overwrite` actually overwrite, and count skipped separately from failed

**Files:**
- Modify: `internal/services/secrets/secret_service.go` (`ImportResult` at
  l.105-111, `ImportSecrets` loop at l.751-773)
- Modify: `internal/services/secrets/secret_service_test.go` (l.557-583,
  `TestImportSecrets_VaultScoped_ThreadsVaultIDIntoCreatedSecrets`; new tests)
- Modify: `internal/services/secrets/coverage_boost_test.go` (l.725-741, the
  `ImportSecrets` portion of the combined export/import test)

**Interfaces:**
- Consumes: `repositories.SecretRepositoryInterface.FindByName` (Task 1),
  `secretService.UpdateSecret(ctx, UpdateSecretRequest) error` (existing,
  l.285-355 — already versions the prior value via
  `versionService.CreateVersion` before applying the update),
  `secretService.CreateSecret` (existing, unchanged).
- Produces (extends `ImportResult`):
  ```go
  type ImportResult struct {
  	ImportedCount int
  	SkippedCount  int
  	FailedCount   int // new
  	TotalCount    int
  	Errors        []string
  }
  ```

- [ ] **Step 1: Write the failing tests**

In `internal/services/secrets/secret_service_test.go`, replace
`TestImportSecrets_VaultScoped_ThreadsVaultIDIntoCreatedSecrets` (l.557-583)
with the same test plus a `FindByName` stub for the not-found path, and add
the two headline B38 tests after it:

```go
func TestImportSecrets_VaultScoped_ThreadsVaultIDIntoCreatedSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	actorID := uuid.New()
	scope := model.NewVaultScope(vaultID, actorID)

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "n1", scope).Return(nil, repositories.ErrNotFound)
	crypto.On("EncryptSecret", "v1").Return("enc-v1", nil)
	repo.On("Create", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.VaultID == vaultID && s.Name == "n1"
	})).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	data := []byte(`[{"name":"n1","value":"v1"}]`)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  scope,
		Data:   data,
		Format: "json",
	})

	require.NoError(t, err)
	require.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)
	repo.AssertExpectations(t)
}

func TestImportSecrets_ExistingNameWithOverwrite_UpdatesAndVersionsPriorValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewVaultScope(vaultID, ownerID)
	existingID := uuid.New()

	existing := &model.Secret{
		ID:      existingID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "db-password",
		Value:   "old-encrypted",
		Version: 1,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "db-password", scope).Return(existing, nil).Once()
	repo.On("Read", ctx, existingID, scope).Return(existing, nil).Once()
	crypto.On("DecryptSecret", "old-encrypted").Return("old-plain", nil).Once()
	ver.On("CreateVersion", ctx, secrets.CreateVersionRequest{
		SecretID: existingID,
		UserID:   ownerID,
		Name:     "db-password",
		Value:    "old-plain",
		Version:  1,
	}).Return(&model.SecretVersion{}, nil).Once()
	crypto.On("EncryptSecret", "new-value").Return("new-encrypted", nil).Once()
	repo.On("Update", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.ID == existingID && s.Value == "new-encrypted" && s.Version == 2
	}), scope).Return(nil).Once()

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:     scope,
		Format:    "json",
		Overwrite: true,
		Data:      []byte(`[{"name":"db-password","value":"new-value"}]`),
	})

	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)
	repo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	ver.AssertExpectations(t)
}

func TestImportSecrets_ExistingNameWithoutOverwrite_SkipsAndCounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewVaultScope(vaultID, ownerID)
	existingID := uuid.New()

	existing := &model.Secret{
		ID:      existingID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "db-password",
		Value:   "old-encrypted",
		Version: 1,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "db-password", scope).Return(existing, nil).Once()

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:     scope,
		Format:    "json",
		Overwrite: false,
		Data:      []byte(`[{"name":"db-password","value":"new-value"}]`),
	})

	require.NoError(t, err)
	assert.Equal(t, 0, result.ImportedCount)
	assert.Equal(t, 1, result.SkippedCount)
	assert.Equal(t, 0, result.FailedCount)
	repo.AssertExpectations(t)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
	repo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything, mock.Anything)
	ver.AssertNotCalled(t, "CreateVersion", mock.Anything, mock.Anything)
}

func TestImportSecrets_CreateError_CountsAsFailedNotSkipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("FindByName", ctx, "broken", scope).Return(nil, repositories.ErrNotFound).Once()
	crypto.On("EncryptSecret", "value").Return("", errors.New("crypto failure")).Once()

	svc := newService(repo, crypto, ver, tag, t)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  scope,
		Format: "json",
		Data:   []byte(`[{"name":"broken","value":"value"}]`),
	})

	require.NoError(t, err)
	assert.Equal(t, 0, result.ImportedCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Equal(t, 1, result.FailedCount)
	repo.AssertExpectations(t)
	crypto.AssertExpectations(t)
}
```

In `internal/services/secrets/coverage_boost_test.go`, in the combined
export/import test (l.725-741), add a `FindByName` stub before the existing
`Create` stub so the not-found branch is reachable:

```go
	crypto.On("EncryptSecret", "one").Return("encrypted-one", nil).Once()
	repo.On("FindByName", ctx, "api", model.NewOwnerScope(uuid.Nil, userID)).Return(nil, repositories.ErrNotFound).Once()
	repo.On("Create", ctx, mock.MatchedBy(func(secret *model.Secret) bool {
		return secret.UserID == userID && secret.Name == "api" && secret.Value == "encrypted-one"
	})).Return(nil).Once()

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		Scope:  model.NewOwnerScope(uuid.Nil, userID),
		Format: "csv",
		Data:   []byte("name,value,tags\napi,one,\"prod,api\"\nmissing,\n"),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 1, result.SkippedCount)
	assert.Equal(t, 2, result.TotalCount)
```

(This replaces the existing five lines from `crypto.On("EncryptSecret", "one"...` through the `assert.Equal(t, 2, result.TotalCount)` line; the `assert.Equal(t, 1, result.SkippedCount)` assertion is unchanged in value — the record it counts is still the "missing value" CSV line, not a name collision.)

- [ ] **Step 2: Run the tests to see them fail**

Run: `go test ./internal/services/secrets/... -run 'TestImportSecrets' -v`
Expected: FAIL — compile error, `result.FailedCount undefined (type
*secrets.ImportResult has no field or method FailedCount)`.

- [ ] **Step 3: Extend `ImportResult` and rewrite the import loop**

In `internal/services/secrets/secret_service.go`, replace the `ImportResult`
struct (l.105-111):

```go
// ImportResult represents the result of importing secrets.
type ImportResult struct {
	ImportedCount int
	SkippedCount  int
	// FailedCount counts records that were attempted (create or overwrite)
	// but errored. It is reported separately from SkippedCount, which counts
	// records the import intentionally did not act on: a record missing a
	// name or value, or an existing name with Overwrite unset.
	FailedCount int
	TotalCount  int
	Errors      []string
}
```

Replace the import loop (l.751-773, from `// Import each secret` through the
closing `}` of the `for` loop) with:

```go
	// Import each secret. A record whose name already exists in the target
	// vault is only overwritten when the caller asked for it; otherwise it is
	// skipped and counted separately from a record that fails outright, so
	// the printed summary distinguishes "chose not to" from "tried and
	// failed".
	for _, importSec := range secretsToImport {
		if importSec.Name == "" || importSec.Value == "" {
			result.Errors = append(result.Errors, "Secret missing name or value")
			result.SkippedCount++
			continue
		}

		existing, err := s.secretRepo.FindByName(ctx, importSec.Name, req.Scope)
		if err != nil && !errors.Is(err, repositories.ErrNotFound) {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to look up '%s': %v", importSec.Name, err))
			result.FailedCount++
			continue
		}

		if existing != nil {
			if !req.Overwrite {
				result.SkippedCount++
				continue
			}

			value := importSec.Value
			if err := s.UpdateSecret(ctx, UpdateSecretRequest{
				SecretID: existing.ID,
				Scope:    req.Scope,
				Value:    &value,
			}); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to overwrite '%s': %v", importSec.Name, err))
				result.FailedCount++
			} else {
				result.ImportedCount++
			}
			continue
		}

		createReq := CreateSecretRequest{
			UserID:  req.Scope.ActorID(),
			VaultID: req.Scope.ResolvedVaultID(),
			Name:    importSec.Name,
			Value:   importSec.Value,
			Tags:    importSec.Tags,
		}

		if _, err := s.CreateSecret(ctx, createReq); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to import '%s': %v", importSec.Name, err))
			result.FailedCount++
		} else {
			result.ImportedCount++
		}
	}
```

Update the two log statements immediately after the loop (l.775-783) to
include the failed count:

```go
	s.logger.LogAuditInfo(req.Scope.ActorID().String(), "import_secrets", "success",
		fmt.Sprintf("Imported %d/%d secrets (%d skipped, %d failed)",
			result.ImportedCount, result.TotalCount, result.SkippedCount, result.FailedCount))
	logrus.WithFields(logrus.Fields{
		"user_id":        req.Scope.ActorID().String(),
		"format":         req.Format,
		"imported_count": result.ImportedCount,
		"skipped_count":  result.SkippedCount,
		"failed_count":   result.FailedCount,
		"total_count":    result.TotalCount,
	}).Info("Secrets import completed")
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./internal/services/secrets/... -run 'TestImportSecrets' -v`
Expected: PASS — all six `TestImportSecrets*` tests (the four new/updated
ones plus the two that were already passing and are untouched by this loop
change: the invalid-format test and any other pre-existing import test not
listed above).

- [ ] **Step 5: Run the whole package and vet it**

Run: `go test ./internal/services/secrets/... -v 2>&1 | tail -80` and
`go vet ./internal/services/secrets/...`
Expected: full package PASS, `go vet` silent.

- [ ] **Step 6: Commit**

```bash
git add internal/services/secrets/secret_service.go \
  internal/services/secrets/secret_service_test.go \
  internal/services/secrets/coverage_boost_test.go
git commit -m "fix(secrets): make import --overwrite actually overwrite (B38)

ImportSecrets called CreateSecret unconditionally, so an existing
secret of the same name was silently left untouched regardless of
--overwrite. It now looks the name up in the target vault first: not
found creates as before, found with Overwrite set updates (versioning
the prior value via the existing UpdateSecret path), found without
Overwrite is skipped. ImportResult gains FailedCount so a record that
errored is no longer counted the same as one the import declined to
touch."
```

---

### Task 3: CLI — print the new counter, fix the help text

**Files:**
- Modify: `cmd/secrets/import.go` (`Long`/`Example` at l.50-72, `Printf` at
  l.125-126)
- Modify: `cmd/secrets/import_cmd_test.go` (new test)

**Interfaces:**
- Consumes: `secretServices.ImportResult{ImportedCount, SkippedCount,
  FailedCount int}` (Task 2).
- Produces: no new exported symbols — output text and help text only.

- [ ] **Step 1: Write the failing test**

Add to `cmd/secrets/import_cmd_test.go`. This needs `"io"` and
`"github.com/stretchr/testify/require"` added to the existing import block.

```go
func TestImportCommand_PrintsImportedSkippedAndFailedCounts(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(&secretServices.ImportResult{ImportedCount: 1, SkippedCount: 2, FailedCount: 3}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsSet).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpImport, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600) //nolint:errcheck,gosec

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importOverwrite = true

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	origStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w

	execErr := cmd.Execute()

	w.Close() //nolint:errcheck
	os.Stdout = origStdout

	out, readErr := io.ReadAll(r)
	require.NoError(t, readErr)

	assert.NoError(t, execErr)
	assert.Equal(t, "Secrets imported successfully\nImported: 1\nSkipped: 2\nFailed: 3\n", string(out))
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `go test ./cmd/secrets/... -run TestImportCommand_PrintsImportedSkippedAndFailedCounts -v`
Expected: FAIL — `assert.Equal` mismatch; actual output is
`"Secrets imported successfully\nImported: 1\nSkipped: 2\n"` (no `Failed:`
line, since the `Printf` in `import.go` doesn't print it yet).

- [ ] **Step 3: Update the `Printf` in `import.go`**

In `cmd/secrets/import.go`, replace (l.125-126):

```go
		fmt.Printf("Secrets imported successfully\nImported: %d\nSkipped: %d\n",
			result.ImportedCount, result.SkippedCount)
```

with:

```go
		fmt.Printf("Secrets imported successfully\nImported: %d\nSkipped: %d\nFailed: %d\n",
			result.ImportedCount, result.SkippedCount, result.FailedCount)
```

- [ ] **Step 4: Run the test to see it pass**

Run: `go test ./cmd/secrets/... -run TestImportCommand_PrintsImportedSkippedAndFailedCounts -v`
Expected: PASS.

- [ ] **Step 5: Fix the help text**

In `cmd/secrets/import.go`, replace the `Long` field (l.50-64):

```go
	Long: `Import secrets into the target vault from a JSON or CSV file in the layout
"secrets export" produces. Each record is matched by name against the
target vault: a name that does not already exist is created at version 1.
A name that already exists is updated when --overwrite is set, which
versions the previous value; otherwise it is skipped. --encrypted is
accepted and unused because the export is plaintext.

Requires the admin or secrets_manager role, and the
Microsoft.KeyVault/vaults/secrets/setSecret/action data action in the
target vault.

Acts on the vault named by --vault, which defaults to "default". The caller
becomes the owner of every imported secret.

Records missing a name or a value are skipped rather than failing the run.
Imported, skipped, and failed counts are all printed when the run finishes.`,
```

Replace the `Example` field (l.65-72) to add an `--overwrite` scenario,
matching the house style (two-space indent, `#` comment per scenario, blank
line between scenarios):

```go
	Example: `  # Import secrets from a JSON file into the default vault
  rocketvault secrets import --file secrets.json

  # Import a CSV export
  rocketvault secrets import --format csv --file secrets.csv

  # Import into a named vault
  rocketvault secrets import --file secrets.json --vault <vault-name>

  # Overwrite existing secrets with the same name
  rocketvault secrets import --file secrets.json --overwrite`,
```

- [ ] **Step 6: Verify the help-text guards still pass**

Run:
```bash
go test ./cmd/... -run TestExampleFlagsAreRegistered -v
go test ./cmd/... -run TestLeafExamplesDoNotShowCredentials -v
go test ./cmd/... -run TestExamplesDoNotAdvertiseUnsupportedRemoteFlags -v
```
Expected: all three PASS. `--overwrite` is already registered
(`secretsImportCmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", ...)`
at the bottom of `import.go`), so the new example line does not trip the
flag-registration guard.

- [ ] **Step 7: Run the full package and build**

Run: `go build ./... && go test ./cmd/secrets/... -v`
Expected: build succeeds, full package PASSes.

- [ ] **Step 8: Commit**

```bash
git add cmd/secrets/import.go cmd/secrets/import_cmd_test.go
git commit -m "docs(cli): fix secrets import help text and print failed count (B38)

The Long text documented --overwrite as a known no-op; now that
ImportSecrets honors it (previous commit), describe what actually
happens instead. The printed summary gains a Failed: line so a
skipped record and a failed one are visibly distinct to the operator,
matching the new ImportResult.FailedCount field."
```

---

## Final verification

- [ ] **Run the full suite**

```bash
go build ./...
go vet ./...
go test ./... 2>&1 | tail -100
```
Expected: build and vet clean; test suite green (spot-check the tail for any
`FAIL` line across the whole module, not just the packages touched above).

- [ ] **Manual sanity check**

```bash
go run . secrets import --help
```
Expected: the printed help shows the corrected `Long` text and the new
`--overwrite` example line, and `--overwrite`/`-w` still appears in the
flags list.
