# Vault-Scope Inconsistency Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the 8 routes that are registered under `/vaults/{name}/...` but currently ignore the resolved vault (secrets UPDATE, secrets versions ×3, secrets export, secrets import, keys UPDATE, certificate policy ×3) actually vault-scoped, matching the "vault members see all" model already used correctly by list/get/delete.

**Architecture:** Every fix follows the existing branch pattern already used by `getSecret`/`listSecrets`/`getKey` (NOT the `deleteSecret` pattern, which is a pre-existing outlier out of scope here): check `isVaultScopedRoute(r)`. When true (explicit `/vaults/{name}/...` URL), call a new vault-scoped service method that verifies membership via `ReadInVault`-style repository calls and grants access to any vault member — no ownership check. When false (legacy flat route), call the existing owner-scoped method unchanged. This means zero behavior change on flat routes; only the already-registered vault-scoped URLs start actually respecting the vault.

**Tech Stack:** Go 1.24, SQLite/PostgreSQL via `internal/db`, testify mocks (`internal/testutils`, and package-local mocks in `internal/services/keys`), gorilla/mux.

## Global Constraints

- Follow the `isVaultScopedRoute(r)` branch pattern exactly as used in `api/secrets.go`'s existing `getSecret`/`listSecrets` and `api/keys.go`'s existing `getKey` — do not invent a different branching style.
- Vault-scoped paths perform NO ownership check — any vault member can act on any resource in that vault (this is the existing, deliberate "members see all" model, confirmed correct for list/get/delete of secrets/keys/certs).
- Legacy flat routes (no `{vault_name}` path var) must be byte-for-byte behaviorally unchanged after this plan — same method calls, same SQL, same results.
- Do not touch keys' `DeleteKeyInVault` or any crypto operation (`internal/services/keys/crypto_service.go`) — those stay owner-gated. Out of scope (tracked separately as B6).
- Do not touch `internal/middleware/middleware.go`, `internal/repositories/role_assignment_repository.go`, `internal/db/db.go`'s audit_logs schema, or `internal/repositories/certificate_repository.go`'s `type`-column filter — those are separate bugs (B1/B3/B4/B5), not part of this plan.
- After adding any method to `SecretService`, `VersioningServiceInterface`, `KeyService`, or `CertificatePolicyRepositoryInterface`, run `go build ./...` and `go vet ./...` and fix every reported missing-method error before moving on — these interfaces have multiple implementers (real service, retry decorator, cache decorator, and test mocks) that Go's compiler will name exactly.
- Every new repository/service method that mirrors an existing `*InVault` method must follow that method's exact structure (same field population, same log calls, same error wrapping) — do not simplify or diverge stylistically.

---

### Task 1: Secrets — vault-scoped UPDATE

**Files:**
- Modify: `internal/repositories/secret_repository.go` (add `UpdateInVault`)
- Modify: `internal/services/secrets/secret_service.go` (add `VaultID` field to `UpdateSecretRequest`, add `UpdateSecretInVault` to interface + impl)
- Modify: `api/secrets.go:575-713` (`updateSecret` handler)
- Modify (mechanical, compiler-driven): every other implementer of `SecretService` and `SecretRepositoryInterface` — at minimum `internal/services/retry/retry_secret_service.go`, `internal/cache/cache_integration.go`, `internal/testutils/mocks.go` (`MockSecretRepository`), `internal/services/retry/retry_wrappers_test.go` (`MockSecretService`), `cmd/testutils/test_utils.go` (`MockSecretService`), `api/secrets_handlers_test.go` (`mockSecretService`)
- Test: `internal/repositories/secret_repository_test.go`, `internal/services/secrets/secret_service_test.go`, `api/secrets_handlers_test.go`

**Interfaces:**
- Consumes: `SecretRepository.ReadInVault(ctx, id, vaultID) (*model.Secret, error)` (exists, returns the secret with `VaultID` populated, or an error if not found/wrong vault) — `internal/repositories/secret_repository.go:662`.
- Produces: `SecretRepositoryInterface.UpdateInVault(ctx context.Context, secret *model.Secret) error`. `SecretService.UpdateSecretInVault(ctx context.Context, req UpdateSecretRequest) error`. `UpdateSecretRequest.VaultID uuid.UUID` field. Later tasks do not depend on these, but Task 6's full-suite run does.

- [ ] **Step 1: Write the failing repository test**

Add to `internal/repositories/secret_repository_test.go` (open the file first to see its existing setup helpers — it uses a real in-memory SQLite DB via `testutils`, mirroring the file's existing `TestSecretRepository_ReadInVault`-style tests; use the same DB-setup helper those tests use):

```go
func TestSecretRepository_UpdateInVault_UpdatesWhenVaultMatches(t *testing.T) {
	repo, cleanup := newTestSecretRepository(t) // use the exact helper name already defined in this file
	defer cleanup()
	ctx := context.Background()

	vaultID := uuid.New()
	secret := &model.Secret{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID,
		Name: "s1", Value: "enc-v1", Version: 1, CreatedAt: time.Now(), Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	secret.Name = "s1-renamed"
	secret.Value = "enc-v2"
	secret.Version = 2
	err := repo.UpdateInVault(ctx, secret)
	require.NoError(t, err)

	got, err := repo.ReadInVault(ctx, secret.ID, vaultID)
	require.NoError(t, err)
	assert.Equal(t, "s1-renamed", got.Name)
	assert.Equal(t, "enc-v2", got.Value)
	assert.Equal(t, 2, got.Version)
}

func TestSecretRepository_UpdateInVault_NoOpWhenVaultMismatch(t *testing.T) {
	repo, cleanup := newTestSecretRepository(t)
	defer cleanup()
	ctx := context.Background()

	realVault := uuid.New()
	secret := &model.Secret{
		ID: uuid.New(), UserID: uuid.New(), VaultID: realVault,
		Name: "s1", Value: "enc-v1", Version: 1, CreatedAt: time.Now(), Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	secret.VaultID = uuid.New() // wrong vault
	secret.Name = "should-not-apply"
	err := repo.UpdateInVault(ctx, secret)
	require.Error(t, err)

	got, err := repo.ReadInVault(ctx, secret.ID, realVault)
	require.NoError(t, err)
	assert.Equal(t, "s1", got.Name) // unchanged
}
```

If `newTestSecretRepository` is not the actual helper name in that file, use whatever helper the file's existing `ReadInVault`/`ListInVault` tests already call — read the top of the file to confirm before writing these two tests, and match it exactly.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestSecretRepository_UpdateInVault -v`
Expected: FAIL with `repo.UpdateInVault undefined` (compile error).

- [ ] **Step 3: Add `UpdateInVault` to the repository interface and implementation**

In `internal/repositories/secret_repository.go`, add to `SecretRepositoryInterface` (near the existing `ReadInVault`/`ListInVault` declarations, around line 30-35):

```go
	// UpdateInVault updates a secret only when it belongs to the given vault.
	// It mirrors Update but scopes by vault_id instead of user_id.
	UpdateInVault(ctx context.Context, secret *model.Secret) error
```

Add the implementation directly after the existing `ReadInVault` method (after line 700):

```go
// UpdateInVault updates a secret in the database, scoped to a vault instead
// of an owner. It mirrors Update but the WHERE clause matches vault_id
// instead of user_id, so any vault member's update succeeds.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secret: The secret entity with updated fields; VaultID must be set.
//
// Returns:
//
//	An error if the update fails or no row matches id+vault_id.
func (r *SecretRepository) UpdateInVault(ctx context.Context, secret *model.Secret) error {
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"vault_id":  secret.VaultID.String(),
		"version":   secret.Version,
	}).Debug("Updating secret in database (vault-scoped)")

	result, err := r.db.ExecContext(
		ctx,
		"UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ?, enabled = ?, expires_at = ?, not_before = ? WHERE id = ? AND vault_id = ?",
		secret.Name, secret.Value, secret.Version, secret.ContentType, secret.Enabled, secret.ExpiresAt, secret.NotBefore, secret.ID.String(), secret.VaultID.String(),
	)
	if err != nil {
		r.log.LogAuditError("", "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError("", "update_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError("", "update_secret", "failed", "Secret not found for update", nil)
		return fmt.Errorf("secret not found")
	}

	r.log.LogAuditInfo("", "update_secret", "success", fmt.Sprintf("Secret updated: %s", secret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"vault_id":  secret.VaultID.String(),
		"version":   secret.Version,
	}).Debug("Secret updated successfully")

	return nil
}
```

- [ ] **Step 4: Run `go vet ./...` and fix every implementer the compiler names**

Run: `go vet ./... 2>&1` (use `go vet`, not `go build` — the mock implementers live in `_test.go` files, which plain `go build ./...` does not compile; `go vet ./...` type-checks test files too and will report exactly the same "missing method" errors for them.)

Expected: compile errors naming every type that implements `SecretRepositoryInterface` but is now missing `UpdateInVault`. For each file the compiler names (expect at least `internal/testutils/mocks.go`'s `MockSecretRepository`), add a method matching this exact shape, placed directly after that file's existing `Update` method:

```go
func (m *MockSecretRepository) UpdateInVault(ctx context.Context, secret *model.Secret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}
```

Re-run `go vet ./...` until it's clean, fixing each reported file the same way (mirror whatever mock style — testify `m.Called(...)` — that file's existing `Update` method already uses).

- [ ] **Step 5: Run the repository tests to verify they pass**

Run: `go test ./internal/repositories/... -run TestSecretRepository_UpdateInVault -v`
Expected: PASS (both tests).

- [ ] **Step 6: Commit the repository layer**

```bash
git add internal/repositories/secret_repository.go internal/repositories/secret_repository_test.go internal/testutils/mocks.go
git commit -m "feat(secrets): add vault-scoped UpdateInVault repository method"
```

- [ ] **Step 7: Write the failing service test**

Add to `internal/services/secrets/secret_service_test.go`, directly after the existing `TestUpdateSecret_WrongOwner`:

```go
func TestUpdateSecretInVault_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	callerID := uuid.New()  // a different vault member than the secret's original owner
	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Name: "old", Value: "enc-old", Version: 1}
	newValue := "new-plain"
	newName := "new-name"

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("ReadInVault", ctx, secretID, vaultID).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-old").Return("old-plain", nil)
	ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).Return(
		&model.SecretVersion{Version: 1}, nil,
	)
	crypto.On("EncryptSecret", newValue).Return("enc-new", nil)
	repo.On("UpdateInVault", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecretInVault(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		UserID:   callerID,
		VaultID:  vaultID,
		Name:     &newName,
		Value:    &newValue,
	})

	require.NoError(t, err)
	ver.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestUpdateSecretInVault_WrongVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("ReadInVault", ctx, secretID, vaultID).Return(nil, errors.New("secret not found or access denied"))

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecretInVault(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		UserID:   uuid.New(),
		VaultID:  vaultID,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}
```

- [ ] **Step 8: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run TestUpdateSecretInVault -v`
Expected: FAIL with `svc.UpdateSecretInVault undefined`.

- [ ] **Step 9: Add `VaultID` to `UpdateSecretRequest` and implement `UpdateSecretInVault`**

In `internal/services/secrets/secret_service.go`, modify the `UpdateSecretRequest` struct (around line 42):

```go
// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	SecretID    uuid.UUID
	UserID      uuid.UUID
	VaultID     uuid.UUID  // Set only for vault-scoped updates; ignored by UpdateSecret.
	Name        *string    // Optional - nil means no change.
	Value       *string    // Optional - nil means no change.
	Tags        *[]string  // Optional - nil means no change.
	ContentType *string    // Optional - nil means no change.
	Enabled     *bool      // Optional - nil means no change.
	ExpiresAt   *time.Time // Optional - nil means no change.
	NotBefore   *time.Time // Optional - nil means no change.
}
```

Add to the `SecretService` interface (directly after the existing `UpdateSecret` line):

```go
	// UpdateSecretInVault updates a secret scoped to a vault. Any vault
	// member may update any secret in the vault (no ownership check).
	UpdateSecretInVault(ctx context.Context, req UpdateSecretRequest) error
```

Add the implementation directly after the existing `UpdateSecret` method (after line 365):

```go
// UpdateSecretInVault updates a secret scoped to a vault, with versioning
// support. It mirrors UpdateSecret but verifies vault scope via ReadInVault
// instead of ownership — any vault member may update any secret in the vault.
func (s *secretService) UpdateSecretInVault(ctx context.Context, req UpdateSecretRequest) error {
	logrus.WithFields(logrus.Fields{
		"secret_id": req.SecretID.String(),
		"vault_id":  req.VaultID.String(),
	}).Info("Updating secret (vault-scoped)")

	currentSecret, err := s.secretRepo.ReadInVault(ctx, req.SecretID, req.VaultID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Secret not found or not in vault", err)
		return fmt.Errorf("%w: %s", ErrSecretNotFound, err.Error())
	}

	currentValue, err := s.cryptoService.DecryptSecret(currentSecret.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to decrypt current secret", err)
		return fmt.Errorf("failed to decrypt current secret: %w", err)
	}

	versionReq := CreateVersionRequest{
		SecretID: currentSecret.ID,
		UserID:   req.UserID,
		Name:     currentSecret.Name,
		Value:    currentValue,
		Version:  currentSecret.Version,
	}
	if _, err = s.versionService.CreateVersion(ctx, versionReq); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to create version", err)
		return fmt.Errorf("failed to create version: %w", err)
	}

	updatedSecret := *currentSecret
	updatedSecret.Version++

	if req.ContentType != nil {
		if err := validateContentType(*req.ContentType); err != nil {
			return err
		}
		updatedSecret.ContentType = *req.ContentType
	}
	if req.Name != nil {
		updatedSecret.Name = *req.Name
	}
	if req.Enabled != nil {
		updatedSecret.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		updatedSecret.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		updatedSecret.NotBefore = req.NotBefore
	}
	if req.Value != nil {
		encryptedValue, err := s.cryptoService.EncryptSecret(*req.Value)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to encrypt updated secret", err)
			return fmt.Errorf("failed to encrypt updated secret: %w", err)
		}
		updatedSecret.Value = encryptedValue
	}

	if err := s.secretRepo.UpdateInVault(ctx, &updatedSecret); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to update secret", err)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	if req.Tags != nil {
		if err := s.tagService.RemoveAllTags(ctx, req.SecretID); err != nil {
			s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to remove old tags", err)
			return fmt.Errorf("failed to remove old tags: %w", err)
		}
		if len(*req.Tags) > 0 {
			if err := s.tagService.AddTags(ctx, req.SecretID, *req.Tags); err != nil {
				s.logger.LogAuditError(req.UserID.String(), "update_secret", "failed", "Failed to add new tags", err)
				return fmt.Errorf("failed to add new tags: %w", err)
			}
		}
	}

	s.logger.LogAuditInfo(req.UserID.String(), "update_secret", "success", fmt.Sprintf("Secret updated: %s", updatedSecret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": req.SecretID.String(),
		"vault_id":  req.VaultID.String(),
		"version":   updatedSecret.Version,
	}).Info("Secret updated successfully (vault-scoped)")

	return nil
}
```

- [ ] **Step 10: Run `go vet ./...` and fix every implementer the compiler names**

Run: `go vet ./... 2>&1` (not `go build` — several implementers live in `_test.go` files, which `go vet ./...` type-checks and plain `go build ./...` does not.)

Expected compile errors naming each `SecretService` implementer missing `UpdateSecretInVault`. For each, add a method mirroring that file's existing `UpdateSecret`/`GetSecretInVault` pattern:

In `internal/services/retry/retry_secret_service.go`, add directly after the existing `UpdateSecret` method:

```go
// UpdateSecretInVault updates a vault-scoped secret with retry logic.
func (s *retrySecretService) UpdateSecretInVault(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		return s.baseService.UpdateSecretInVault(ctx, req)
	})
}
```

In `internal/cache/cache_integration.go`, add directly after the existing `UpdateSecret` method:

```go
// UpdateSecretInVault updates a vault-scoped secret (not cached).
func (s *CachedSecretService) UpdateSecretInVault(ctx context.Context, req secrets.UpdateSecretRequest) error {
	return s.secretService.UpdateSecretInVault(ctx, req)
}
```

For the testify-style mocks the compiler names (`internal/services/retry/retry_wrappers_test.go`'s `MockSecretService`, `cmd/testutils/test_utils.go`'s `MockSecretService`), add directly after each file's existing `UpdateSecret` mock method:

```go
func (m *MockSecretService) UpdateSecretInVault(ctx context.Context, req secrets.UpdateSecretRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
```

(Adjust the `secrets.` import alias to match whatever alias that specific file already uses for `rocketvault/internal/services/secrets` — check its existing `UpdateSecret` mock signature and copy the alias exactly.)

For the custom struct-based stub in `api/secrets_handlers_test.go` (`mockSecretService`), add directly after its existing `UpdateSecret` method, following that file's existing panic-on-unexpected-call style for any field this specific test doesn't need, or a real passthrough if it does — check the file's existing `GetSecretInVault` stub (already present per this file) and mirror its exact style.

Re-run `go vet ./...` until clean.

- [ ] **Step 11: Run the service tests to verify they pass**

Run: `go test ./internal/services/secrets/... -run TestUpdateSecretInVault -v`
Expected: PASS (both tests).

- [ ] **Step 12: Commit the service layer**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_service_test.go internal/services/retry/retry_secret_service.go internal/cache/cache_integration.go internal/services/retry/retry_wrappers_test.go cmd/testutils/test_utils.go
git commit -m "feat(secrets): add UpdateSecretInVault service method"
```

- [ ] **Step 13: Modify the `updateSecret` HTTP handler**

Replace the body of `updateSecret` in `api/secrets.go` (currently lines 575-713) with:

```go
func updateSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	req, err := model.UpdateSecretRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	var updateName, updateValue *string
	if req.Name != "" {
		updateName = &req.Name
	}
	if req.Value != "" {
		updateValue = &req.Value
	}
	if err := vvalidation.ValidateSecretUpdate(vvalidation.SecretUpdateRequest{
		Name:      updateName,
		Value:     updateValue,
		Tags:      req.Tags,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	// Legacy flat routes use per-user visibility; vault-scoped routes use
	// vault-level visibility (members see all items in the vault).
	vaultScoped := isVaultScopedRoute(r)
	var vaultID uuid.UUID
	var secret *model.Secret
	if vaultScoped {
		vaultID, err = vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		secret, err = secretService.GetSecretInVault(r.Context(), secretID, vaultID)
	} else {
		secret, err = secretService.GetSecret(r.Context(), secretID, userID)
	}
	if err != nil {
		if errors.Is(err, secrets.ErrSecretLifecycleDenied) {
			c.SetPermissionError("secret is disabled or outside its valid time window")
		} else if errors.Is(err, secrets.ErrSecretNotFound) {
			c.SetNotFound("secret")
		} else {
			c.SetInternalError(err)
		}
		return
	}

	updated := false
	if req.Name != "" && req.Name != secret.Name {
		secret.Name = req.Name
		updated = true
	}
	if req.Value != "" && req.Value != secret.Value {
		secret.Value = req.Value
		updated = true
	}
	if req.Tags != nil {
		secret.Tags = req.Tags
		updated = true
	}
	if req.ContentType != nil && *req.ContentType != secret.ContentType {
		secret.ContentType = *req.ContentType
		updated = true
	}
	if req.Enabled != nil {
		secret.Enabled = *req.Enabled
		updated = true
	}
	if req.ExpiresAt != nil {
		secret.ExpiresAt = req.ExpiresAt
		updated = true
	}
	if req.NotBefore != nil {
		secret.NotBefore = req.NotBefore
		updated = true
	}

	if !updated {
		c.SetInvalidParam("no changes provided")
		return
	}

	secret.Version++

	updateReq := secrets.UpdateSecretRequest{
		UserID:      userID,
		SecretID:    secret.ID,
		Name:        &secret.Name,
		Value:       &secret.Value,
		Tags:        &secret.Tags,
		ContentType: req.ContentType,
		Enabled:     req.Enabled,
		ExpiresAt:   req.ExpiresAt,
		NotBefore:   req.NotBefore,
	}
	if vaultScoped {
		updateReq.VaultID = vaultID
		err = secretService.UpdateSecretInVault(r.Context(), updateReq)
	} else {
		err = secretService.UpdateSecret(r.Context(), updateReq)
	}
	if err != nil {
		c.SetInternalError(err)
		return
	}

	response := model.SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Tags:        secret.Tags,
		Version:     secret.Version,
		ContentType: secret.ContentType,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
		Enabled:     secret.Enabled,
		ExpiresAt:   secret.ExpiresAt,
		NotBefore:   secret.NotBefore,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))

	c.Logger.Printf("User %s updated secret %s", userIDStr, secret.Name)
}
```

- [ ] **Step 14: Write an HTTP-level test proving the vault-scoped route calls the new method**

The existing harness for this is in `api/vault_scoped_routes_test.go`: `recordingSecretService` (a hand-written fake implementing `SecretService`, panicking on any method it doesn't expect a call to) plus `newVaultScopedTestAPI(secretSvc)` (wires both vault-management and vault-scoped `/secrets` routes) plus `doVaultRequest(api, method, path, body []byte)` (issues an authed request as `vaultTestUserID` with `model.RoleAdmin`).

`recordingSecretService` currently panics on `GetSecretInVault`, `GetSecret`, and `UpdateSecret`, and has no `UpdateSecretInVault` method at all (interface won't compile without it). Replace its existing panicking `GetSecretInVault`, `GetSecret`, and `UpdateSecret` methods, and add fields plus a new `UpdateSecretInVault` method, so the struct becomes:

```go
type recordingSecretService struct {
	listVaultID       uuid.UUID
	listCalled        bool
	listUserScoped    bool
	listUserID        uuid.UUID
	updateCalled      bool
	updateVaultScoped bool
	updateVaultID     uuid.UUID
	updateUserID      uuid.UUID
}
```

```go
func (s *recordingSecretService) GetSecret(_ context.Context, secretID, userID uuid.UUID) (*model.Secret, error) {
	return &model.Secret{ID: secretID, UserID: userID, Name: "existing", Value: "plain-value", Version: 1}, nil
}
func (s *recordingSecretService) UpdateSecret(_ context.Context, req secretServices.UpdateSecretRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = false
	s.updateUserID = req.UserID
	return nil
}
func (s *recordingSecretService) GetSecretInVault(_ context.Context, secretID, vaultID uuid.UUID) (*model.Secret, error) {
	return &model.Secret{ID: secretID, VaultID: vaultID, Name: "existing", Value: "plain-value", Version: 1}, nil
}
func (s *recordingSecretService) UpdateSecretInVault(_ context.Context, req secretServices.UpdateSecretRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = true
	s.updateVaultID = req.VaultID
	return nil
}
```

(Delete the old `panic("unexpected")` bodies for these three methods; every other method in the struct stays exactly as-is.) Then add, directly after the existing `TestLegacyFlatRoute_UsesUserScopedListing` (after line 175):

```go
// TestVaultScopedRoute_UsesVaultScopedUpdate verifies that PUT on the
// explicit /vaults/{name}/secrets/{id} route dispatches to
// UpdateSecretInVault, not the owner-scoped UpdateSecret.
func TestVaultScopedRoute_UsesVaultScopedUpdate(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	secretID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/secrets/"+secretID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped PUT /vaults/prod/secrets/%s: expected 200, got %d (%s)", secretID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("vault-scoped route did not dispatch to the secret update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("vault-scoped /secrets/{id} PUT must use vault-scoped update (UpdateSecretInVault)")
	}
	if rec.updateVaultID != id {
		t.Fatalf("update dispatched with vault ID %s, want %s", rec.updateVaultID, id)
	}
}

// TestLegacyFlatRoute_UsesUserScopedUpdate verifies that PUT on the legacy
// flat /secrets/{id} route still dispatches to the owner-scoped UpdateSecret.
func TestLegacyFlatRoute_UsesUserScopedUpdate(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	secretID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/secrets/"+secretID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy PUT /secrets/%s: expected 200, got %d (%s)", secretID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("legacy route did not dispatch to the secret update handler")
	}
	if rec.updateVaultScoped {
		t.Fatalf("legacy /secrets/{id} PUT must use owner-scoped update (UpdateSecret), not vault-scoped")
	}
	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route scoped update to user %s, want caller %s", rec.updateUserID, vaultTestUserID)
	}
}
```

- [ ] **Step 15: Run test to verify it passes**

Run: `go test ./api/... -run "TestVaultScopedRoute_UsesVaultScopedUpdate|TestLegacyFlatRoute_UsesUserScopedUpdate" -v`
Expected: PASS (both tests). If either fails to compile because `recordingSecretService` still has old panicking bodies for `GetSecret`/`UpdateSecret`/`GetSecretInVault`, re-check Step 14's struct edit was applied.

- [ ] **Step 16: Run the full secrets test suite**

Run: `go test ./api/... ./internal/services/secrets/... ./internal/repositories/... -v 2>&1 | tail -60`
Expected: all PASS, no failures.

- [ ] **Step 17: Commit the handler layer**

```bash
git add api/secrets.go api/vault_scoped_routes_test.go
git commit -m "feat(secrets): vault-scope the UPDATE endpoint"
```

---

### Task 2: Secrets — vault-scoped versions (list/get/latest)

**Files:**
- Modify: `internal/services/secrets/versioning_service.go` (add `GetVersionsInVault`, `GetVersionInVault`, `GetLatestVersionInVault` to `VersioningServiceInterface` + impl)
- Modify: `internal/services/secrets/secret_service.go` (add `GetSecretVersionsInVault`, `GetSecretVersionInVault`, `GetLatestSecretVersionInVault` to `SecretService` interface + impl)
- Modify: `api/secrets.go:82-188` (the 3 version handlers)
- Modify (compiler-driven): every `VersioningServiceInterface` and `SecretService` implementer/mock
- Test: `internal/services/secrets/secret_service_test.go`, `api/secrets_handlers_test.go`

**Interfaces:**
- Consumes: `SecretRepositoryInterface.ReadInVault` (from Task 1's context, already existed before this plan). `SecretVersionRepositoryInterface.GetVersions/GetVersion/GetLatestVersion(ctx, secretID)` (existing, unchanged — these are already vault-agnostic since a version's identity is scoped by its parent secret, and the parent secret's vault membership is what needs verifying).
- Produces: `VersioningServiceInterface.GetVersionsInVault(ctx, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error)`, `.GetVersionInVault(ctx, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error)`, `.GetLatestVersionInVault(ctx, secretID, vaultID uuid.UUID) (*model.SecretVersion, error)`. `SecretService.GetSecretVersionsInVault`, `.GetSecretVersionInVault`, `.GetLatestSecretVersionInVault` with the same respective signatures.

- [ ] **Step 1: Write the failing versioning-service test**

Add to a new file `internal/services/secrets/versioning_service_vault_test.go` (no existing versioning-service test file was found in this package — create one, following the same package/import style as `secret_service_test.go`):

```go
package secrets_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

func TestGetVersionsInVault_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	vaultID := uuid.New()

	userRepo := &testutils.MockUserRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	versionRepo := &testutils.MockSecretVersionRepository{}
	crypto := &testutils.MockCryptographyService{}

	secretRepo.On("ReadInVault", ctx, secretID, vaultID).Return(
		&model.Secret{ID: secretID, VaultID: vaultID}, nil,
	)
	versionRepo.On("GetVersions", ctx, secretID).Return(
		[]model.SecretVersion{{ID: uuid.New(), SecretID: secretID, Value: "enc-v1", Version: 1}}, nil,
	)
	crypto.On("DecryptSecret", "enc-v1").Return("plain-v1", nil)

	svc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t))
	versions, err := svc.GetVersionsInVault(ctx, secretID, vaultID)

	require.NoError(t, err)
	require.Len(t, versions, 1)
	require.Equal(t, "plain-v1", versions[0].Value)
}

func TestGetVersionsInVault_WrongVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	vaultID := uuid.New()

	userRepo := &testutils.MockUserRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	versionRepo := &testutils.MockSecretVersionRepository{}
	crypto := &testutils.MockCryptographyService{}

	secretRepo.On("ReadInVault", ctx, secretID, vaultID).Return(nil, errors.New("secret not found or access denied"))

	svc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t))
	_, err := svc.GetVersionsInVault(ctx, secretID, vaultID)

	require.Error(t, err)
}
```

Add `"errors"` to the import block for the second test. Check `internal/testutils/mocks.go` for the exact names `MockUserRepository` and `MockSecretVersionRepository` (they should already exist since `NewVersioningService` already takes these types today — grep to confirm before use) and adjust the import/type names if this plan's guessed names differ from what's actually there.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run TestGetVersionsInVault -v`
Expected: FAIL with `svc.GetVersionsInVault undefined`.

- [ ] **Step 3: Add the 3 new methods to `VersioningServiceInterface` and implement them**

In `internal/services/secrets/versioning_service.go`, add to the interface (directly after the existing `GetVersions`/`GetVersion`/`GetLatestVersion` lines):

```go
	GetVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error)
	GetVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error)
	GetLatestVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error)
```

Add the implementations directly after the existing `GetLatestVersion` method (after line 230):

```go
// GetVersionsInVault retrieves all versions of a secret scoped to a vault
// instead of ownership. It mirrors GetVersions but verifies vault membership
// via ReadInVault.
func (s *versioningService) GetVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	if _, err := s.secretRepo.ReadInVault(ctx, secretID, vaultID); err != nil {
		return nil, fmt.Errorf("secret not found or not in vault: %w", err)
	}

	encryptedVersions, err := s.versionRepo.GetVersions(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get secret versions")
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}

	var versions []model.SecretVersion
	for _, encVersion := range encryptedVersions {
		decryptedValue, err := s.cryptoSvc.DecryptSecret(encVersion.Value)
		if err != nil {
			s.log.WithError(err).WithField("version_id", encVersion.ID).Error("Failed to decrypt secret version")
			return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
		}
		decVersion := encVersion
		decVersion.Value = decryptedValue
		versions = append(versions, decVersion)
	}

	return versions, nil
}

// GetVersionInVault retrieves a specific version of a secret scoped to a
// vault instead of ownership. It mirrors GetVersion but verifies vault
// membership via ReadInVault.
func (s *versioningService) GetVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	if _, err := s.secretRepo.ReadInVault(ctx, secretID, vaultID); err != nil {
		return nil, fmt.Errorf("secret not found or not in vault: %w", err)
	}

	encryptedVersion, err := s.versionRepo.GetVersion(ctx, secretID, version)
	if err != nil {
		s.log.WithError(err).WithFields(map[string]any{
			"secret_id": secretID,
			"version":   version,
		}).Error("Failed to get secret version")
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

// GetLatestVersionInVault retrieves the latest version of a secret scoped to
// a vault instead of ownership. It mirrors GetLatestVersion but verifies
// vault membership via ReadInVault.
func (s *versioningService) GetLatestVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	if _, err := s.secretRepo.ReadInVault(ctx, secretID, vaultID); err != nil {
		return nil, fmt.Errorf("secret not found or not in vault: %w", err)
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

- [ ] **Step 4: Run `go vet ./...` and fix every `VersioningServiceInterface` implementer the compiler names**

Run: `go vet ./... 2>&1` (not `go build` — mock implementers can live in `_test.go` files, which only `go vet ./...`/`go test ./...` type-check). For `internal/testutils/mocks.go`'s `MockVersioningService` (already confirmed to exist), add directly after its existing `GetLatestVersion` mock method:

```go
func (m *MockVersioningService) GetVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID, vaultID)
	if v := args.Get(0); v != nil {
		return v.([]model.SecretVersion), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockVersioningService) GetVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version, vaultID)
	if v := args.Get(0); v != nil {
		return v.(*model.SecretVersion), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockVersioningService) GetLatestVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, vaultID)
	if v := args.Get(0); v != nil {
		return v.(*model.SecretVersion), args.Error(1)
	}
	return nil, args.Error(1)
}
```

Fix any other file the compiler names the same way, mirroring that file's existing `GetVersions`/`GetVersion`/`GetLatestVersion` mock style. Re-run until `go vet ./...` is clean.

- [ ] **Step 5: Run the versioning tests to verify they pass**

Run: `go test ./internal/services/secrets/... -run TestGetVersionsInVault -v`
Expected: PASS (both tests).

- [ ] **Step 6: Commit the versioning-service layer**

```bash
git add internal/services/secrets/versioning_service.go internal/services/secrets/versioning_service_vault_test.go internal/testutils/mocks.go
git commit -m "feat(secrets): add vault-scoped version lookup methods"
```

- [ ] **Step 7: Add the 3 wrapper methods to `SecretService`**

In `internal/services/secrets/secret_service.go`, add to the interface (directly after `GetLatestSecretVersion`):

```go
	GetSecretVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error)
	GetSecretVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error)
	GetLatestSecretVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error)
```

Add the implementations directly after `GetLatestSecretVersion` (after line 647):

```go
// GetSecretVersionsInVault retrieves all versions of a secret scoped to a vault.
func (s *secretService) GetSecretVersionsInVault(ctx context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	return s.versionService.GetVersionsInVault(ctx, secretID, vaultID)
}

// GetSecretVersionInVault retrieves a specific version of a secret scoped to a vault.
func (s *secretService) GetSecretVersionInVault(ctx context.Context, secretID uuid.UUID, version int, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return s.versionService.GetVersionInVault(ctx, secretID, version, vaultID)
}

// GetLatestSecretVersionInVault retrieves the latest version of a secret scoped to a vault.
func (s *secretService) GetLatestSecretVersionInVault(ctx context.Context, secretID, vaultID uuid.UUID) (*model.SecretVersion, error) {
	return s.versionService.GetLatestVersionInVault(ctx, secretID, vaultID)
}
```

- [ ] **Step 8: Run `go vet ./...` and fix every `SecretService` implementer the compiler names**

Same procedure as Task 1 Step 10 (use `go vet ./...`, not `go build`) — add a delegating method to `internal/services/retry/retry_secret_service.go`, `internal/cache/cache_integration.go`, and every test mock the compiler names, mirroring each file's existing `GetSecretVersions`/`GetSecretVersion`/`GetLatestSecretVersion` pattern. For the retry decorator, these are NOT wrapped in `ExecuteDatabaseOperation` if the existing `GetSecretVersions` isn't either — check that method first and match its style exactly (do not add retry wrapping if the sibling method doesn't have it).

- [ ] **Step 9: Run the service tests, then commit**

Run: `go test ./internal/services/secrets/... -v 2>&1 | tail -40`
Expected: all PASS.

```bash
git add internal/services/secrets/secret_service.go internal/services/retry/retry_secret_service.go internal/cache/cache_integration.go
git commit -m "feat(secrets): add SecretService vault-scoped version wrappers"
```

- [ ] **Step 10: Modify the 3 version HTTP handlers**

Replace `listSecretVersionsHandler` in `api/secrets.go` (currently lines 82-112) with:

```go
func listSecretVersionsHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	var versions []model.SecretVersion
	if isVaultScopedRoute(r) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		versions, err = secretService.GetSecretVersionsInVault(r.Context(), secretID, vaultID)
		if err != nil {
			c.SetInternalError(err)
			return
		}
	} else {
		userIDStr, ok := c.Claims["user_id"].(string)
		if !ok {
			c.SetInternalError(nil)
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.SetInvalidParam("user_id")
			return
		}
		versions, err = secretService.GetSecretVersions(r.Context(), secretID, userID)
		if err != nil {
			c.SetInternalError(err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions)
}
```

Replace `getSecretVersionHandler` (currently lines 117-151) with:

```go
func getSecretVersionHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}
	versionNum := c.Params.Version

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	var version *model.SecretVersion
	if isVaultScopedRoute(r) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		version, err = secretService.GetSecretVersionInVault(r.Context(), secretID, versionNum, vaultID)
		if err != nil {
			c.SetNotFound("secret version")
			return
		}
	} else {
		userIDStr, ok := c.Claims["user_id"].(string)
		if !ok {
			c.SetInternalError(nil)
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.SetInvalidParam("user_id")
			return
		}
		version, err = secretService.GetSecretVersion(r.Context(), secretID, versionNum, userID)
		if err != nil {
			c.SetNotFound("secret version")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version)
}
```

Replace `getLatestSecretVersionHandler` (currently lines 153-188) with:

```go
func getLatestSecretVersionHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	var version *model.SecretVersion
	if isVaultScopedRoute(r) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		version, err = secretService.GetLatestSecretVersionInVault(r.Context(), secretID, vaultID)
		if err != nil {
			c.SetNotFound("secret version")
			return
		}
	} else {
		userIDStr, ok := c.Claims["user_id"].(string)
		if !ok {
			c.SetInternalError(nil)
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.SetInvalidParam("user_id")
			return
		}
		version, err = secretService.GetLatestSecretVersion(r.Context(), secretID, userID)
		if err != nil {
			c.SetNotFound("secret version")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version)
}
```

- [ ] **Step 11: Write an HTTP-level test for the vault-scoped versions route**

In `api/vault_scoped_routes_test.go`, add version-tracking fields to `recordingSecretService` (it already has `listVaultID`/`listCalled`/... and, after Task 1, `updateCalled`/...):

```go
	versionsCalled      bool
	versionsVaultScoped bool
	versionsVaultID     uuid.UUID
```

Replace the existing panicking `GetSecretVersions` method with:

```go
func (s *recordingSecretService) GetSecretVersions(_ context.Context, secretID, userID uuid.UUID) ([]model.SecretVersion, error) {
	s.versionsCalled = true
	s.versionsVaultScoped = false
	return []model.SecretVersion{}, nil
}
func (s *recordingSecretService) GetSecretVersionsInVault(_ context.Context, secretID, vaultID uuid.UUID) ([]model.SecretVersion, error) {
	s.versionsCalled = true
	s.versionsVaultScoped = true
	s.versionsVaultID = vaultID
	return []model.SecretVersion{}, nil
}
```

(`GetSecretVersion`, `GetLatestSecretVersion`, `GetSecretVersionInVault`, `GetLatestSecretVersionInVault` are not exercised by this test — leave `GetSecretVersion`/`GetLatestSecretVersion` panicking as they already are, and add `GetSecretVersionInVault`/`GetLatestSecretVersionInVault` as new panicking stubs so the struct still satisfies `SecretService`:)

```go
func (s *recordingSecretService) GetSecretVersionInVault(context.Context, uuid.UUID, int, uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected")
}
func (s *recordingSecretService) GetLatestSecretVersionInVault(context.Context, uuid.UUID, uuid.UUID) (*model.SecretVersion, error) {
	panic("unexpected")
}
```

Then add, directly after the tests added in Task 1:

```go
// TestVaultScopedRoute_UsesVaultScopedVersionsList verifies that GET on the
// explicit /vaults/{name}/secrets/{id}/versions route dispatches to
// GetSecretVersionsInVault, not the owner-scoped GetSecretVersions.
func TestVaultScopedRoute_UsesVaultScopedVersionsList(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	secretID := uuid.New()
	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/prod/secrets/"+secretID.String()+"/versions", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET .../versions: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.versionsCalled {
		t.Fatalf("vault-scoped route did not dispatch to the versions list handler")
	}
	if !rec.versionsVaultScoped {
		t.Fatalf("vault-scoped .../versions GET must use vault-scoped lookup (GetSecretVersionsInVault)")
	}
	if rec.versionsVaultID != id {
		t.Fatalf("versions lookup dispatched with vault ID %s, want %s", rec.versionsVaultID, id)
	}
}

// TestLegacyFlatRoute_UsesUserScopedVersionsList verifies that GET on the
// legacy flat /secrets/{id}/versions route still dispatches to the
// owner-scoped GetSecretVersions.
func TestLegacyFlatRoute_UsesUserScopedVersionsList(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	secretID := uuid.New()
	w := doVaultRequest(api, http.MethodGet, "/api/v1/secrets/"+secretID.String()+"/versions", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET .../versions: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.versionsCalled {
		t.Fatalf("legacy route did not dispatch to the versions list handler")
	}
	if rec.versionsVaultScoped {
		t.Fatalf("legacy .../versions GET must use owner-scoped lookup (GetSecretVersions), not vault-scoped")
	}
}
```

- [ ] **Step 12: Run tests, then commit**

Run: `go test ./api/... -run "TestVaultScopedRoute_UsesVaultScopedVersionsList|TestLegacyFlatRoute_UsesUserScopedVersionsList" -v`
Expected: PASS (both tests).

```bash
git add api/secrets.go api/vault_scoped_routes_test.go
git commit -m "feat(secrets): vault-scope the version list/get/latest endpoints"
```

---

### Task 3: Secrets — vault-scoped export/import

**Files:**
- Modify: `internal/services/secrets/secret_service.go` (add `VaultID` to `ExportSecretsRequest` and `ImportSecretsRequest`; branch `ExportSecrets`/`ImportSecrets` on it)
- Modify: `api/secrets.go:189-337` (`exportSecrets`, `importSecrets`)
- Test: `internal/services/secrets/secret_service_test.go`, `api/secrets_handlers_test.go`

**Interfaces:**
- Consumes: `SecretService.ListSecretsInVault` (exists, from the multi-vault work — `internal/services/secrets/secret_service.go:542`). `CreateSecretRequest.VaultID` (already exists — `internal/services/secrets/secret_service.go:31`).
- Produces: `ExportSecretsRequest.VaultID uuid.UUID` field (zero value = not vault-scoped, unchanged export-by-owner behavior). `ImportSecretsRequest.VaultID uuid.UUID` field (threaded into created secrets).

- [ ] **Step 1: Write the failing service test**

Add to `internal/services/secrets/secret_service_test.go`, directly after the existing export/import tests (search the file for `TestExportSecrets` / `TestImportSecrets` to find the right spot):

```go
func TestExportSecrets_VaultScoped_UsesListSecretsInVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "enc-v1"}}
	repo.On("ListInVault", ctx, vaultID, []string(nil)).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("plain-v1", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		UserID:  uuid.New(),
		VaultID: vaultID,
		Format:  "json",
	})

	require.NoError(t, err)
	require.Contains(t, string(data), "plain-v1")
	repo.AssertExpectations(t)
}

func TestImportSecrets_VaultScoped_ThreadsVaultIDIntoCreatedSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", "v1").Return("enc-v1", nil)
	repo.On("Create", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.VaultID == vaultID && s.Name == "n1"
	})).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	data := []byte(`[{"name":"n1","value":"v1"}]`)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		UserID:  uuid.New(),
		VaultID: vaultID,
		Data:    data,
		Format:  "json",
	})

	require.NoError(t, err)
	require.Equal(t, 1, result.ImportedCount)
	repo.AssertExpectations(t)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/secrets/... -run "TestExportSecrets_VaultScoped|TestImportSecrets_VaultScoped" -v`
Expected: FAIL (compile error: `ExportSecretsRequest` / `ImportSecretsRequest` have no field `VaultID`).

- [ ] **Step 3: Add `VaultID` fields and branch `ExportSecrets`/`ImportSecrets`**

In `internal/services/secrets/secret_service.go`, modify `ExportSecretsRequest` (around line 86):

```go
// ExportSecretsRequest represents a request to export secrets.
type ExportSecretsRequest struct {
	UserID      uuid.UUID
	VaultID     uuid.UUID // Set only for vault-scoped export; zero value exports by owner.
	Format      string    // "json" or "csv"
	FilterTags  []string  // Optional tag filter
	IncludeTags bool      // Include tags in export
}
```

Modify `ImportSecretsRequest` (around line 94):

```go
// ImportSecretsRequest represents a request to import secrets.
type ImportSecretsRequest struct {
	UserID    uuid.UUID
	VaultID   uuid.UUID // Set only for vault-scoped import; zero value uses CreateSecret's default-vault fallback.
	Data      []byte
	Format    string // "json" or "csv"
	Overwrite bool   // Overwrite existing secrets with same name
}
```

In `ExportSecrets` (around line 769), replace the `List secrets with optional tag filter` block:

```go
	var secretsList []model.Secret
	if req.VaultID != uuid.Nil {
		secretsList, err = s.ListSecretsInVault(ctx, req.VaultID, req.FilterTags)
	} else {
		secretsList, err = s.ListSecrets(ctx, req.UserID, req.FilterTags)
	}
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "export_secrets", "failed", "Failed to list secrets", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
```

Update every following reference to the old local variable `secrets` in that method to `secretsList` (the JSON/CSV building loops and the final log line) — the rest of the method body is unchanged except for this rename, needed because the local variable previously named `secrets` shadowed nothing problematic before but should be renamed for clarity now that the method has two possible sources. Read the current method body first and rename every `secrets` reference within `ExportSecrets` (not the package name usage elsewhere) to `secretsList`.

In `ImportSecrets` (around line 917), change the `createReq` construction inside the import loop:

```go
		createReq := CreateSecretRequest{
			UserID:  req.UserID,
			VaultID: req.VaultID,
			Name:    importSec.Name,
			Value:   importSec.Value,
			Tags:    importSec.Tags,
		}
```

(This is the only change to `ImportSecrets` — `CreateSecretRequest` already has a `VaultID` field, and `CreateSecret` already resolves `uuid.Nil` to the default vault, so this is fully backward compatible for the flat/legacy path.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/secrets/... -run "TestExportSecrets_VaultScoped|TestImportSecrets_VaultScoped" -v`
Expected: PASS. Also run the full pre-existing export/import tests to confirm no regression: `go test ./internal/services/secrets/... -run "TestExportSecrets|TestImportSecrets" -v`

- [ ] **Step 5: Commit the service layer**

```bash
git add internal/services/secrets/secret_service.go internal/services/secrets/secret_service_test.go
git commit -m "feat(secrets): thread VaultID through export/import"
```

- [ ] **Step 6: Modify the `exportSecrets` and `importSecrets` HTTP handlers**

In `api/secrets.go`'s `exportSecrets` (currently lines 189-254), insert directly before the `data, err := secretService.ExportSecrets(...)` call:

```go
	serviceReq := secrets.ExportSecretsRequest{
		UserID:      userID,
		Format:      exportReq.Format,
		FilterTags:  exportReq.Tags,
		IncludeTags: exportReq.IncludeTags,
	}
	if isVaultScopedRoute(r) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		serviceReq.VaultID = vaultID
	}

	data, err := secretService.ExportSecrets(r.Context(), serviceReq)
```

Delete the old `serviceReq := secrets.ExportSecretsRequest{...}` block and old `data, err := secretService.ExportSecrets(r.Context(), serviceReq)` line that this replaces (they were directly above/below each other in the original).

In `importSecrets` (currently lines 255-337), insert the same branch directly before the `result, err := secretService.ImportSecrets(...)` call:

```go
	serviceReq := secrets.ImportSecretsRequest{
		UserID:    userID,
		Data:      data,
		Format:    format,
		Overwrite: overwrite,
	}
	if isVaultScopedRoute(r) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		serviceReq.VaultID = vaultID
	}

	result, err := secretService.ImportSecrets(r.Context(), serviceReq)
```

Delete the old `serviceReq`/`result, err :=` pair this replaces.

- [ ] **Step 7: Write HTTP-level tests for both vault-scoped routes**

In `api/vault_scoped_routes_test.go`, add fields to `recordingSecretService`:

```go
	exportCalled  bool
	exportVaultID uuid.UUID
	importCalled  bool
	importVaultID uuid.UUID
```

Replace the existing panicking `ExportSecrets` and `ImportSecrets` methods with:

```go
func (s *recordingSecretService) ExportSecrets(_ context.Context, req secretServices.ExportSecretsRequest) ([]byte, error) {
	s.exportCalled = true
	s.exportVaultID = req.VaultID
	return []byte("[]"), nil
}
func (s *recordingSecretService) ImportSecrets(_ context.Context, req secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
	s.importCalled = true
	s.importVaultID = req.VaultID
	return &secretServices.ImportResult{}, nil
}
```

Add `"bytes"` and `"mime/multipart"` to the file's import block (the import test builds a real multipart body). Then add:

```go
// TestVaultScopedRoute_UsesVaultScopedExport verifies that POST on the
// explicit /vaults/{name}/secrets/export route threads the resolved vault's
// ID into ExportSecretsRequest.
func TestVaultScopedRoute_UsesVaultScopedExport(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	body := []byte(`{"format":"json"}`)
	w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults/prod/secrets/export", body)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped POST .../export: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.exportCalled {
		t.Fatalf("vault-scoped route did not dispatch to the export handler")
	}
	if rec.exportVaultID != id {
		t.Fatalf("export dispatched with vault ID %s, want %s", rec.exportVaultID, id)
	}
}

// TestLegacyFlatRoute_ExportOmitsVaultID verifies that POST on the legacy
// flat /secrets/export route leaves VaultID unset (owner-scoped export).
func TestLegacyFlatRoute_ExportOmitsVaultID(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	body := []byte(`{"format":"json"}`)
	w := doVaultRequest(api, http.MethodPost, "/api/v1/secrets/export", body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy POST /secrets/export: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.exportCalled {
		t.Fatalf("legacy route did not dispatch to the export handler")
	}
	if rec.exportVaultID != uuid.Nil {
		t.Fatalf("legacy /secrets/export must not set VaultID, got %s", rec.exportVaultID)
	}
}

// TestVaultScopedRoute_UsesVaultScopedImport verifies that POST on the
// explicit /vaults/{name}/secrets/import route threads the resolved vault's
// ID into ImportSecretsRequest.
func TestVaultScopedRoute_UsesVaultScopedImport(t *testing.T) {
	rec := &recordingSecretService{}
	api, repo := newVaultScopedTestAPI(rec)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "secrets.json")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	fw.Write([]byte(`[{"name":"n1","value":"v1"}]`))
	mw.WriteField("format", "json")
	mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/secrets/import", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	ctx := context.WithValue(r.Context(), common.UserIDKey, vaultTestUserID)
	ctx = context.WithValue(ctx, common.RoleKey, string(model.RoleAdmin))
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	api.rootRouter.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped POST .../import: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.importCalled {
		t.Fatalf("vault-scoped route did not dispatch to the import handler")
	}
	if rec.importVaultID != id {
		t.Fatalf("import dispatched with vault ID %s, want %s", rec.importVaultID, id)
	}
}
```

- [ ] **Step 8: Run tests, then commit**

Run: `go test ./api/... -run "TestVaultScopedRoute_UsesVaultScopedExport|TestLegacyFlatRoute_ExportOmitsVaultID|TestVaultScopedRoute_UsesVaultScopedImport" -v`
Expected: PASS (all 3).

```bash
git add api/secrets.go api/vault_scoped_routes_test.go
git commit -m "feat(secrets): vault-scope export/import endpoints"
```

---

### Task 4: Keys — vault-scoped UPDATE

**Files:**
- Modify: `internal/services/keys/key_service.go` (add `VaultID` to `UpdateKeyRequest`, add `UpdateKeyInVault` to `KeyService` interface + impl)
- Modify: `api/keys.go:485-563` (`updateKey` handler)
- Modify (compiler-driven): every `KeyService` mock — at minimum `cmd/keys/service_test.go`'s `MockKeyService`, `cmd/keys/update_test.go`'s `MockKeyServiceForUpdate`, and `api/vault_scoped_keys_certs_test.go`'s `recordingKeyService`
- Test: `internal/services/keys/key_service_update_test.go`, `api/keys_crud_test.go` or `api/vault_scoped_keys_certs_test.go`

**Interfaces:**
- Consumes: `KeyRepositoryInterface.ReadInVault(ctx, id, vaultID) (*model.Key, error)` (exists — `internal/repositories/key_repository.go:943`). `KeyRepositoryInterface.Update(ctx, key) error` (exists, already SQL-unscoped: `WHERE id = ?` only — no new repository method needed for this task).
- Produces: `KeyService.UpdateKeyInVault(ctx context.Context, req UpdateKeyRequest) error`. `UpdateKeyRequest.VaultID uuid.UUID` field.

- [ ] **Step 1: Write the failing service test**

Add to `internal/services/keys/key_service_update_test.go` (open it first to confirm it uses the package-local `mockKeyRepository` from `key_soft_delete_test.go`, same package `keys`):

```go
func TestUpdateKeyInVault_HappyPath(t *testing.T) {
	repo := &mockKeyRepository{}
	logger := testLogger() // use whatever logger helper this file's existing tests already call

	keyID := uuid.New()
	vaultID := uuid.New()
	ownerID := uuid.New()
	callerID := uuid.New() // a different vault member than the key's owner

	stored := &model.Key{ID: keyID, UserID: ownerID, VaultID: vaultID, Name: "old"}
	repo.On("ReadInVault", mock.Anything, keyID, vaultID).Return(stored, nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.Key")).Return(nil)

	svc := &keyService{keyRepo: repo, logger: logger}

	newName := "new-name"
	err := svc.UpdateKeyInVault(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		UserID:  callerID,
		VaultID: vaultID,
		Name:    &newName,
	})

	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestUpdateKeyInVault_WrongVault(t *testing.T) {
	repo := &mockKeyRepository{}
	logger := testLogger()

	keyID := uuid.New()
	vaultID := uuid.New()

	repo.On("ReadInVault", mock.Anything, keyID, vaultID).Return(nil, errors.New("key not found or access denied"))

	svc := &keyService{keyRepo: repo, logger: logger}
	err := svc.UpdateKeyInVault(context.Background(), UpdateKeyRequest{
		KeyID:   keyID,
		UserID:  uuid.New(),
		VaultID: vaultID,
	})

	assert.ErrorIs(t, err, ErrKeyNotFound)
}
```

If `testLogger()` is not the actual helper name used elsewhere in this file, open `key_service_update_test.go` first and use whatever logger construction its existing tests (e.g. an existing `TestUpdateKey_*` test) already use, matching it exactly. Add `"errors"` to the import block if not already present.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/keys/... -run TestUpdateKeyInVault -v`
Expected: FAIL with `svc.UpdateKeyInVault undefined` and/or `UpdateKeyRequest has no field VaultID`.

- [ ] **Step 3: Add `VaultID` to `UpdateKeyRequest` and implement `UpdateKeyInVault`**

In `internal/services/keys/key_service.go`, modify `UpdateKeyRequest` (around line 74):

```go
type UpdateKeyRequest struct {
	KeyID     uuid.UUID
	VaultID   uuid.UUID  // Set only for vault-scoped updates; ignored by UpdateKey.
	Name      *string    // Optional - nil means no change
	Tags      []string   // Optional - empty means no change
	Revoked   *bool      // Optional - nil means no change
	UserID    uuid.UUID  // For access control (legacy path only)
	Enabled   *bool      // Optional - nil means no change
	ExpiresAt *time.Time // Optional - nil means no change
	NotBefore *time.Time // Optional - nil means no change
}
```

Add to the `KeyService` interface (directly after the existing `UpdateKey` line):

```go
	// UpdateKeyInVault updates a key scoped to a vault. Any vault member may
	// update any key in the vault (no ownership check).
	UpdateKeyInVault(ctx context.Context, req UpdateKeyRequest) error
```

Add the implementation directly after the existing `UpdateKey` method (after line 593):

```go
// UpdateKeyInVault updates a key scoped to a vault instead of ownership. It
// mirrors UpdateKey but verifies vault membership via ReadInVault — any vault
// member may update any key in the vault.
func (s *keyService) UpdateKeyInVault(ctx context.Context, req UpdateKeyRequest) error {
	logrus.WithFields(logrus.Fields{
		"key_id":   req.KeyID.String(),
		"vault_id": req.VaultID.String(),
	}).Info("Updating key (vault-scoped)")

	key, err := s.keyRepo.ReadInVault(ctx, req.KeyID, req.VaultID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	updatedKey := *key

	if req.Name != nil {
		updatedKey.Name = *req.Name
	}
	if req.Tags != nil {
		updatedKey.Tags = req.Tags
	}
	if req.Revoked != nil {
		updatedKey.Revoked = *req.Revoked
	}
	if req.Enabled != nil {
		updatedKey.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		updatedKey.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		updatedKey.NotBefore = req.NotBefore
	}

	if err := s.keyRepo.Update(ctx, &updatedKey); err != nil {
		s.logger.LogAuditError("", "update_key", "failed", "Failed to update key", err)
		return fmt.Errorf("failed to update key: %w", err)
	}

	if s.keyCache != nil {
		s.keyCache.Invalidate(updatedKey.ID)
	}

	s.logger.LogAuditInfo("", "update_key", "success", fmt.Sprintf("Key updated: %s", updatedKey.Name))
	return nil
}
```

- [ ] **Step 4: Run `go vet ./...` and fix every `KeyService` implementer the compiler names**

Run: `go vet ./... 2>&1` (not `go build` — `MockKeyService`, `MockKeyServiceForUpdate`, and `recordingKeyService` all live in `_test.go` files). Expected reports include `cmd/keys/service_test.go`'s `MockKeyService` and `cmd/keys/update_test.go`'s `MockKeyServiceForUpdate`. For each, add directly after that file's existing `UpdateKey` mock method, matching that file's mock style (testify `mock.Mock` embedding, following the existing `UpdateKey` signature exactly but renamed):

```go
func (m *MockKeyService) UpdateKeyInVault(ctx context.Context, req keyServices.UpdateKeyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
```

(Use whatever import alias for `internal/services/keys` that file's existing `UpdateKey` mock signature already uses — copy it exactly rather than assuming `keyServices`.) Also fix `api/vault_scoped_keys_certs_test.go`'s `recordingKeyService` (referenced in this plan's investigation) — since that struct panics on unexpected calls by design, add:

```go
func (s *recordingKeyService) UpdateKeyInVault(context.Context, keyServices.UpdateKeyRequest) error {
	panic("unexpected")
}
```

matching its existing panic-stub style for methods that test doesn't exercise, unless a specific test in that file needs `UpdateKeyInVault` to actually record — in which case follow the pattern of its existing `GetKeyInVault` method (record a bool + captured args, return a zero-value success) instead of panicking. Re-run `go vet ./...` until clean.

- [ ] **Step 5: Run the service tests to verify they pass**

Run: `go test ./internal/services/keys/... -run TestUpdateKeyInVault -v`
Expected: PASS (both tests).

- [ ] **Step 6: Commit the service layer**

```bash
git add internal/services/keys/key_service.go internal/services/keys/key_service_update_test.go cmd/keys/service_test.go cmd/keys/update_test.go api/vault_scoped_keys_certs_test.go
git commit -m "feat(keys): add UpdateKeyInVault service method"
```

- [ ] **Step 7: Modify the `updateKey` HTTP handler**

Replace the body of `updateKey` in `api/keys.go` (currently lines 485-563) with:

```go
func updateKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	var req UpdateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}

	if req.Name == nil && req.Revoked == nil && req.Tags == nil && req.Enabled == nil && req.ExpiresAt == nil && req.NotBefore == nil {
		c.SetInvalidParam("at least one update field (name, revoked, tags, enabled, expires_at, not_before) must be provided")
		return
	}

	if err := vvalidation.ValidateKeyUpdate(vvalidation.KeyUpdateRequest{
		Name: req.Name,
		Tags: req.Tags,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	vaultScoped := isVaultScopedRoute(r)
	var vaultID uuid.UUID
	if vaultScoped {
		vaultID, err = vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		updateReq := keyservices.UpdateKeyRequest{
			KeyID:     keyID,
			VaultID:   vaultID,
			Name:      req.Name,
			Tags:      req.Tags,
			Revoked:   req.Revoked,
			Enabled:   req.Enabled,
			ExpiresAt: req.ExpiresAt,
			NotBefore: req.NotBefore,
		}
		if err := keyService.UpdateKeyInVault(r.Context(), updateReq); err != nil {
			if errors.Is(err, keyservices.ErrKeyNotFound) {
				c.SetNotFound("key")
			} else {
				c.SetInternalError(err)
			}
			return
		}
	} else {
		updateReq := keyservices.UpdateKeyRequest{
			KeyID:     keyID,
			Name:      req.Name,
			Tags:      req.Tags,
			UserID:    userID,
			Revoked:   req.Revoked,
			Enabled:   req.Enabled,
			ExpiresAt: req.ExpiresAt,
			NotBefore: req.NotBefore,
		}
		if err := keyService.UpdateKey(r.Context(), updateReq); err != nil {
			if errors.Is(err, keyservices.ErrKeyNotFound) {
				c.SetNotFound("key")
			} else {
				c.SetInternalError(err)
			}
			return
		}
	}

	// Get updated key for response, using the same scope as the update.
	var key *model.Key
	if vaultScoped {
		key, err = keyService.GetKeyInVault(r.Context(), keyID, vaultID)
	} else {
		key, err = keyService.GetKey(r.Context(), keyID, userID)
	}
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildKeyResponse(key))
}
```

- [ ] **Step 8: Write an HTTP-level test for the vault-scoped update route**

`api/vault_test.go` already defines a package-level helper `doVaultRequest(api *API, method, path string, body []byte) *httptest.ResponseRecorder` that issues an authed request (as `vaultTestUserID` with `model.RoleAdmin`) with an optional body — it is usable from any `_test.go` file in package `api`, including this one. No need to touch `doScopedRequest`.

In `api/vault_scoped_keys_certs_test.go`, add tracking fields to `recordingKeyService`:

```go
	updateCalled      bool
	updateVaultScoped bool
	updateVaultID     uuid.UUID
	updateUserID      uuid.UUID
```

Replace the existing panicking `UpdateKey` method with:

```go
func (s *recordingKeyService) UpdateKey(_ context.Context, req keyServices.UpdateKeyRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = false
	s.updateUserID = req.UserID
	return nil
}
```

Add a new `UpdateKeyInVault` method directly after it:

```go
func (s *recordingKeyService) UpdateKeyInVault(_ context.Context, req keyServices.UpdateKeyRequest) error {
	s.updateCalled = true
	s.updateVaultScoped = true
	s.updateVaultID = req.VaultID
	return nil
}
```

Then add, directly after the existing `TestVaultScopedKeyRoute_UsesVaultScopedListing`:

```go
// TestVaultScopedKeyRoute_UsesVaultScopedUpdate verifies that PUT on the
// explicit /vaults/{name}/keys/{id} route dispatches to UpdateKeyInVault,
// not the owner-scoped UpdateKey.
func TestVaultScopedKeyRoute_UsesVaultScopedUpdate(t *testing.T) {
	rec := &recordingKeyService{}
	api, repo := newVaultScopedKeyCertTestAPI(rec, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	keyID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/keys/"+keyID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped PUT /vaults/prod/keys/%s: expected 200, got %d (%s)", keyID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("vault-scoped route did not dispatch to the key update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("vault-scoped /keys/{id} PUT must use vault-scoped update (UpdateKeyInVault)")
	}
	if rec.updateVaultID != id {
		t.Fatalf("update dispatched with vault ID %s, want %s", rec.updateVaultID, id)
	}
}

// TestLegacyFlatKeyRoute_UsesUserScopedUpdate verifies that PUT on the legacy
// flat /keys/{id} route still dispatches to the owner-scoped UpdateKey.
func TestLegacyFlatKeyRoute_UsesUserScopedUpdate(t *testing.T) {
	rec := &recordingKeyService{}
	api, _ := newVaultScopedKeyCertTestAPI(rec, nil)

	keyID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/keys/"+keyID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy PUT /keys/%s: expected 200, got %d (%s)", keyID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("legacy route did not dispatch to the key update handler")
	}
	if rec.updateVaultScoped {
		t.Fatalf("legacy /keys/{id} PUT must use owner-scoped update (UpdateKey), not vault-scoped")
	}
	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route scoped update to user %s, want caller %s", rec.updateUserID, vaultTestUserID)
	}
}
```

- [ ] **Step 9: Run tests, then commit**

Run: `go test ./api/... -run "TestVaultScopedKeyRoute_UsesVaultScopedUpdate|TestLegacyFlatKeyRoute_UsesUserScopedUpdate" -v`
Expected: PASS (both tests).

```bash
git add api/keys.go api/vault_scoped_keys_certs_test.go
git commit -m "feat(keys): vault-scope the UPDATE endpoint"
```

---

### Task 5: Certificates — vault-scoped policy (get/upsert/delete)

**Files:**
- Modify: `internal/repositories/certificate_policy_repository.go` (add `GetByCertificateIDAny`, `DeleteByCertificateIDAny` to `CertificatePolicyRepositoryInterface` + impl)
- Modify: `api/certificate_policy.go` (all 3 handlers)
- Modify (compiler-driven): `api/certificate_policy_test.go`'s `mockCertPolicyRepo`
- Modify: `api/vault_test.go` (`vaultSvcTestContainer` gains a `certPolicyRepo` field)
- Modify: `api/vault_scoped_keys_certs_test.go` (`recordingCertService` gains a `getInVaultErr` field; new `newVaultScopedCertPolicyTestAPI` helper)
- Test: `internal/repositories/certificate_policy_repository_test.go`, `api/vault_scoped_keys_certs_test.go`

**Interfaces:**
- Consumes: `CertificateService.GetCertificateInVault(ctx, certID, vaultID) (*model.Certificate, error)` (exists — `internal/services/certificates/certificate_service.go:535`, returns `certServices.ErrCertNotFound` wrapped when not found/not in vault). `Context.certSvc() certServices.CertificateService` (exists — `api/context.go:233`).
- Produces: `CertificatePolicyRepositoryInterface.GetByCertificateIDAny(ctx, certID uuid.UUID) (*model.CertificatePolicy, error)`, `.DeleteByCertificateIDAny(ctx, certID uuid.UUID) error` — both unscoped by owner; callers MUST verify vault/owner access before calling them.

- [ ] **Step 1: Write the failing repository test**

Add to `internal/repositories/certificate_policy_repository_test.go` (open it first to confirm its DB-setup helper name, matching the existing `TestCertificatePolicyRepository_GetByCertificateID`-style tests):

```go
func TestCertificatePolicyRepository_GetByCertificateIDAny_IgnoresOwner(t *testing.T) {
	repo, cleanup := newTestCertificatePolicyRepository(t) // match this file's actual helper name
	defer cleanup()
	ctx := context.Background()

	certID := uuid.New()
	ownerID := uuid.New()
	policy := &model.CertificatePolicy{
		ID: uuid.New(), CertificateID: certID, UserID: ownerID,
		ValidityMonths: 12, KeyType: "RSA", KeySize: 2048,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	got, err := repo.GetByCertificateIDAny(ctx, certID) // no ownerID passed
	require.NoError(t, err)
	assert.Equal(t, certID, got.CertificateID)
}

func TestCertificatePolicyRepository_DeleteByCertificateIDAny_IgnoresOwner(t *testing.T) {
	repo, cleanup := newTestCertificatePolicyRepository(t)
	defer cleanup()
	ctx := context.Background()

	certID := uuid.New()
	ownerID := uuid.New()
	policy := &model.CertificatePolicy{
		ID: uuid.New(), CertificateID: certID, UserID: ownerID,
		ValidityMonths: 12, KeyType: "RSA", KeySize: 2048,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	require.NoError(t, repo.Upsert(ctx, policy))

	err := repo.DeleteByCertificateIDAny(ctx, certID) // no ownerID passed
	require.NoError(t, err)

	_, err = repo.GetByCertificateIDAny(ctx, certID)
	require.Error(t, err)
}
```

If the actual helper name differs from `newTestCertificatePolicyRepository`, read the top of the file and use its real name.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestCertificatePolicyRepository_.*Any -v`
Expected: FAIL with `repo.GetByCertificateIDAny undefined`.

- [ ] **Step 3: Add the 2 new methods to the interface and implementation**

In `internal/repositories/certificate_policy_repository.go`, add to `CertificatePolicyRepositoryInterface`:

```go
	// GetByCertificateIDAny retrieves the policy for a certificate regardless
	// of owner. Callers must independently verify the caller's access to the
	// certificate (e.g. vault membership) before calling this.
	GetByCertificateIDAny(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error)
	// DeleteByCertificateIDAny removes the policy for a certificate regardless
	// of owner. Callers must independently verify the caller's access to the
	// certificate before calling this.
	DeleteByCertificateIDAny(ctx context.Context, certID uuid.UUID) error
```

Add the implementations at the end of the file:

```go
// GetByCertificateIDAny retrieves the policy for a certificate, ignoring
// owner. Callers are responsible for verifying access to the certificate
// (e.g. vault membership) before calling this.
func (r *CertificatePolicyRepository) GetByCertificateIDAny(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, certificate_id, user_id, validity_months, key_type, key_size, curve,
		       subject, sans, auto_renew, days_before_expiry, issuer_name, created_at, updated_at
		FROM certificate_policies
		WHERE certificate_id = ?`,
		certID.String(),
	)
	var p model.CertificatePolicy
	var idStr, cidStr, uidStr string
	if err := row.Scan(&idStr, &cidStr, &uidStr,
		&p.ValidityMonths, &p.KeyType, &p.KeySize, &p.Curve,
		&p.Subject, &p.SANs, &p.AutoRenew, &p.DaysBeforeExpiry,
		&p.IssuerName, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.ID, _ = uuid.Parse(idStr)
	p.CertificateID, _ = uuid.Parse(cidStr)
	p.UserID, _ = uuid.Parse(uidStr)
	return &p, nil
}

// DeleteByCertificateIDAny removes the policy for a certificate, ignoring
// owner. Callers are responsible for verifying access to the certificate
// before calling this. Returns sql.ErrNoRows when no matching policy exists.
func (r *CertificatePolicyRepository) DeleteByCertificateIDAny(ctx context.Context, certID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM certificate_policies WHERE certificate_id = ?",
		certID.String(),
	)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
```

- [ ] **Step 4: Run `go vet ./...` and fix the stub in `api/certificate_policy_test.go`**

Run: `go vet ./... 2>&1` (not `go build` — `mockCertPolicyRepo` lives in a `_test.go` file). Expected: `api/certificate_policy_test.go`'s `mockCertPolicyRepo` (a testify `mock.Mock`-based implementer of `CertificatePolicyRepositoryInterface` — NOT `certPolicyRepoContainer`, which only delegates `GetCertificatePolicyRepository()` to whatever concrete repo it's given, typically a `*mockCertPolicyRepo`) is missing the 2 new methods. Add directly after its existing `DeleteByCertificateID` method:

```go
func (m *mockCertPolicyRepo) GetByCertificateIDAny(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error) {
	args := m.Called(ctx, certID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.CertificatePolicy), args.Error(1)
}

func (m *mockCertPolicyRepo) DeleteByCertificateIDAny(ctx context.Context, certID uuid.UUID) error {
	args := m.Called(ctx, certID)
	return args.Error(0)
}
```

Re-run `go vet ./...` until clean.

- [ ] **Step 5: Run the repository tests, then commit**

Run: `go test ./internal/repositories/... -run TestCertificatePolicyRepository_.*Any -v`
Expected: PASS (both tests).

```bash
git add internal/repositories/certificate_policy_repository.go internal/repositories/certificate_policy_repository_test.go api/certificate_policy_test.go
git commit -m "feat(certificates): add owner-agnostic certificate policy repository methods"
```

- [ ] **Step 6: Modify the 3 certificate policy HTTP handlers**

Replace `getCertificatePolicy` in `api/certificate_policy.go` (currently lines 16-46) with:

```go
// getCertificatePolicy returns the policy for a certificate.
func getCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	repo := c.certPolicyRepo()
	if repo == nil {
		return
	}

	var policy *model.CertificatePolicy
	if isVaultScopedRoute(r) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		certService := c.certSvc()
		if certService == nil {
			return
		}
		if _, err := certService.GetCertificateInVault(r.Context(), certID, vaultID); err != nil {
			c.SetNotFound("certificate")
			return
		}
		policy, err = repo.GetByCertificateIDAny(r.Context(), certID)
		if err != nil {
			c.SetNotFound("policy")
			return
		}
	} else {
		userIDStr, ok := c.Claims["user_id"].(string)
		if !ok {
			c.SetInternalError(nil)
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.SetInvalidParam("user_id")
			return
		}
		policy, err = repo.GetByCertificateID(r.Context(), certID, userID)
		if err != nil {
			c.SetNotFound("policy")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}
```

Replace `upsertCertificatePolicy` (currently lines 48-110) with:

```go
// upsertCertificatePolicy creates or replaces the policy for a certificate.
func upsertCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	req, err := model.UpsertCertificatePolicyRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	repo := c.certPolicyRepo()
	if repo == nil {
		return
	}

	vaultScoped := isVaultScopedRoute(r)
	if vaultScoped {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		certService := c.certSvc()
		if certService == nil {
			return
		}
		if _, err := certService.GetCertificateInVault(r.Context(), certID, vaultID); err != nil {
			c.SetNotFound("certificate")
			return
		}
	}

	now := time.Now()
	policy := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           userID,
		ValidityMonths:   req.ValidityMonths,
		KeyType:          req.KeyType,
		KeySize:          req.KeySize,
		Curve:            req.Curve,
		Subject:          req.Subject,
		SANs:             req.SANs,
		AutoRenew:        req.AutoRenew,
		DaysBeforeExpiry: req.DaysBeforeExpiry,
		IssuerName:       req.IssuerName,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := repo.Upsert(r.Context(), policy); err != nil {
		c.SetInternalError(err)
		return
	}

	// Read-after-write so the response reflects the canonical stored ID.
	var stored *model.CertificatePolicy
	if vaultScoped {
		stored, err = repo.GetByCertificateIDAny(r.Context(), certID)
	} else {
		stored, err = repo.GetByCertificateID(r.Context(), certID, userID)
	}
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stored)
}
```

Replace `deleteCertificatePolicy` (currently lines 112-145) with:

```go
// deleteCertificatePolicy removes the policy for a certificate.
func deleteCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	repo := c.certPolicyRepo()
	if repo == nil {
		return
	}

	if isVaultScopedRoute(r) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}
		certService := c.certSvc()
		if certService == nil {
			return
		}
		if _, err := certService.GetCertificateInVault(r.Context(), certID, vaultID); err != nil {
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
	} else {
		userIDStr, ok := c.Claims["user_id"].(string)
		if !ok {
			c.SetInternalError(nil)
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.SetInvalidParam("user_id")
			return
		}
		if err := repo.DeleteByCertificateID(r.Context(), certID, userID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.SetNotFound("policy not found")
			} else {
				c.SetInternalError(err)
			}
			return
		}
	}

	ReturnStatusOK(w)
}
```

Add `certServices "rocketvault/internal/services/certificates"` is NOT needed here since only `c.certSvc()`'s return type is used implicitly and no sentinel error from that package is referenced directly in this file — but if `go build` reports an unused-import or missing-type error, add the exact import alias `api/certificates.go` already uses (`certServices "rocketvault/internal/services/certificates"`) to `api/certificate_policy.go`'s import block.

- [ ] **Step 6a: Add a `certPolicyRepo` field to the shared `vaultSvcTestContainer`**

`api/vault_test.go`'s `vaultSvcTestContainer` (shared test dependency-injection stub, used by every `newVaultScoped*TestAPI` helper across the `api` package's test files) currently has `GetCertificatePolicyRepository()` unconditionally panicking. Add a field and change it to the same nil-check pattern its `secretSvc`/`keySvc`/`certSvc` fields already use.

In the `vaultSvcTestContainer` struct (around line 160-168), add:

```go
	certPolicyRepo repositories.CertificatePolicyRepositoryInterface
```

Replace its `GetCertificatePolicyRepository` method (around line 203-205):

```go
func (c *vaultSvcTestContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	if c.certPolicyRepo != nil {
		return c.certPolicyRepo
	}
	panic("unexpected call: GetCertificatePolicyRepository")
}
```

This is additive and nil-checked, so every existing test that constructs `vaultSvcTestContainer{...}` without setting `certPolicyRepo` keeps panicking exactly as before if it's ever called — no behavior change for existing tests.

- [ ] **Step 6b: Add a test-API helper wiring vault-scoped certificate + policy routes**

In `api/vault_scoped_keys_certs_test.go`, add a new field to `recordingCertService` so a specific test can force the vault-membership pre-check to fail:

```go
	getInVaultErr error
```

Replace its existing `GetCertificateInVault` method:

```go
func (s *recordingCertService) GetCertificateInVault(_ context.Context, _, vaultID uuid.UUID) (*model.Certificate, error) {
	s.getCalled = true
	s.getUserScoped = false
	s.listVaultID = vaultID
	if s.getInVaultErr != nil {
		return nil, s.getInVaultErr
	}
	return &model.Certificate{ID: uuid.New(), Name: "c"}, nil
}
```

Then add a new helper directly after `newVaultScopedKeyCertTestAPI`:

```go
// newVaultScopedCertPolicyTestAPI wires vault management and vault-scoped
// certificate routes (including the policy sub-resource) onto one router,
// backed by a recording cert service and a certificate policy repository.
func newVaultScopedCertPolicyTestAPI(certSvc certServices.CertificateService, policyRepo repositories.CertificatePolicyRepositoryInterface) (*API, *vaultFakeRepo) {
	repo := newVaultFakeRepo()
	vsvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	a := &app.App{ServiceContainer: &vaultSvcTestContainer{vaultSvc: vsvc, certSvc: certSvc, certPolicyRepo: policyRepo}}
	a.Logger = userTestLog()

	router := mux.NewRouter()
	api := &API{
		App:        a,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     userTestLog(),
	}
	r := api.BaseRoutes
	r.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	r.Vaults = r.ApiRoot.PathPrefix("/vaults").Subrouter()
	r.VaultScoped = r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()
	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	api.InitVault()
	api.InitCertificates()
	return api, repo
}
```

Add `"rocketvault/internal/repositories"` to this file's import block if not already present (needed for the `repositories.CertificatePolicyRepositoryInterface` parameter type), and add `"github.com/stretchr/testify/mock"` if not already present (needed by Step 7's tests, which call `policyRepo.On(...)`).

- [ ] **Step 7: Write HTTP-level tests for the 3 vault-scoped policy routes**

Add to `api/vault_scoped_keys_certs_test.go`, directly after the helper added in Step 6b. These reuse `mockCertPolicyRepo` from `api/certificate_policy_test.go` (same package `api`, no import needed) and the two new `...Any` methods it gained in Step 4:

```go
// TestGetCertificatePolicy_VaultScopedRoute_UsesGetByCertificateIDAny verifies
// that GET on the explicit /vaults/{name}/certificates/{id}/policy route
// succeeds even when the stored policy's owner differs from the caller,
// proving vault-wide access rather than ownership-gated access.
func TestGetCertificatePolicy_VaultScopedRoute_UsesGetByCertificateIDAny(t *testing.T) {
	certSvc := &recordingCertService{}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	otherOwnerID := uuid.New() // different from the caller (vaultTestUserID)
	stored := &model.CertificatePolicy{ID: uuid.New(), CertificateID: certID, UserID: otherOwnerID, ValidityMonths: 12}
	policyRepo.On("GetByCertificateIDAny", mock.Anything, certID).Return(stored, nil)

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped GET .../policy: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	policyRepo.AssertExpectations(t)
}

// TestUpsertCertificatePolicy_VaultScopedRoute_VerifiesCertInVaultFirst
// verifies that PUT on the vault-scoped policy route 404s (and never calls
// Upsert) when the certificate does not belong to the resolved vault.
func TestUpsertCertificatePolicy_VaultScopedRoute_VerifiesCertInVaultFirst(t *testing.T) {
	certSvc := &recordingCertService{getInVaultErr: fmt.Errorf("%w: not in vault", certServices.ErrCertNotFound)}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	body := []byte(`{"validity_months":12,"key_type":"RSA","key_size":2048}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", body)

	if w.Code != http.StatusNotFound {
		t.Fatalf("vault-scoped PUT .../policy for cert not in vault: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
	policyRepo.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
}

// TestDeleteCertificatePolicy_VaultScopedRoute_UsesDeleteByCertificateIDAny verifies
// that DELETE on the explicit vault-scoped policy route succeeds even when
// the stored policy's owner differs from the caller.
func TestDeleteCertificatePolicy_VaultScopedRoute_UsesDeleteByCertificateIDAny(t *testing.T) {
	certSvc := &recordingCertService{}
	policyRepo := &mockCertPolicyRepo{}
	api, repo := newVaultScopedCertPolicyTestAPI(certSvc, policyRepo)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	certID := uuid.New()
	policyRepo.On("DeleteByCertificateIDAny", mock.Anything, certID).Return(nil)

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/certificates/"+certID.String()+"/policy", nil)

	if w.Code != http.StatusOK {
		t.Fatalf("vault-scoped DELETE .../policy: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	policyRepo.AssertExpectations(t)
}
```

Add `"fmt"` to this file's import block if not already present (needed by the second test's `fmt.Errorf` call).

- [ ] **Step 8: Run tests, then commit**

Run: `go test ./api/... -run "TestGetCertificatePolicy_VaultScopedRoute|TestUpsertCertificatePolicy_VaultScopedRoute|TestDeleteCertificatePolicy_VaultScopedRoute" -v`
Expected: PASS (all 3).

```bash
git add api/certificate_policy.go api/certificate_policy_test.go api/vault_scoped_keys_certs_test.go api/vault_test.go
git commit -m "feat(certificates): vault-scope the policy get/upsert/delete endpoints"
```

---

### Task 6: Full verification and doc update

**Files:**
- Modify: `.claude/multi-vault.md` (update the "Known deferrals" section)
- No code files — verification only.

**Interfaces:** None — this is the closing task confirming Tasks 1-5 are correct together.

- [ ] **Step 1: Run the full test suite**

Run: `go build ./... && go vet ./... && go test ./... -v 2>&1 | tail -150`
Expected: build clean, vet clean, all tests PASS. If anything fails, it means an earlier task's compiler-driven stub-fixing step (Task 1 Step 4/10, Task 2 Step 4/8, Task 4 Step 4, Task 5 Step 4) missed an implementer — find it via the failure's file:line and fix it following that file's existing sibling-method pattern, same as the earlier steps did.

- [ ] **Step 2: Manually confirm the flat legacy routes are unchanged**

Run: `go test ./api/... -run "TestLegacyFlat" -v`
Expected: PASS — these are the pre-existing tests proving flat routes still use owner-scoped methods (e.g. `TestLegacyFlatKeyRoute_UsesUserScopedListing`, `TestLegacyFlatCertRoute_UsesUserScopedListing`). If any of these fail, a handler change in Tasks 1-5 accidentally changed flat-route behavior — find the offending branch and fix it so the `else` (non-vault-scoped) arm is byte-identical to what it was before this plan.

- [ ] **Step 3: Update `.claude/multi-vault.md`'s "Known deferrals" section**

Read the current file, find the bullet list under "## Known deferrals (intentional, not bugs)". Remove or rewrite the bullets that are no longer true:

- Delete the "Secrets UPDATE, versions, export/import ignore vault" implication (there was no explicit bullet for this in the original doc — it predates this plan — skip if not present).
- Update the "Keys/certs CLI `--vault` wiring" bullet to clarify it's about CLI only now, since keys' HTTP UPDATE is vault-scoped as of this plan (the CLI itself is untouched by this plan and remains default-vault-only — do not imply otherwise).
- Update the "Keys/certs deleted flow not vault-scoped" bullet: this plan does NOT touch the deleted-flow (that's the one place the codebase's own rule about vault-scoped routes was already honoured correctly, per the audit) — leave this bullet as-is, it's still accurate.
- Add a new bullet: "Certificate policy, secrets versions/export/import, and keys/secrets UPDATE are now vault-scoped (fixed YYYY-MM-DD, see `docs/superpowers/plans/2026-07-26-vault-scope-inconsistency-fixes.md`)." — replace `YYYY-MM-DD` with the actual date this task is executed (check the system date at execution time, do not guess).
- Add a note: "Keys' `DeleteKeyInVault` and crypto operations remain owner-gated even on vault-scoped routes — a deliberate, separate decision (tracked as B6), not fixed by the above."

Write the updated section back to the file.

- [ ] **Step 4: Commit the doc update**

```bash
git add .claude/multi-vault.md
git commit -m "docs: update multi-vault deferrals after vault-scope inconsistency fixes"
```

Note: `.claude/` is gitignored in this repo by deliberate convention (confirmed in prior work on this codebase) — this commit will report "nothing added to commit" if so, which is expected; do not force-add it or modify `.gitignore`. If the commit genuinely no-ops for this reason, skip it and move on.

- [ ] **Step 5: Final report**

Summarize: which of the 8 originally-broken routes are now vault-scoped, confirm all flat-route tests still pass (no behavior change there), confirm `go build`/`go vet`/`go test ./...` are clean, and note that B6 (keys delete/crypto ownership) remains intentionally untouched.
