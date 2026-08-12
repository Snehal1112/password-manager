# Vault-Scoped Soft-Delete for Keys and Certificates — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the parity gap documented in `.claude/azure-keyvault-parity.md` §5 ("Vault-scoped deleted/restore/purge: 🟡 secrets only; keys/certs deferred to flat routes") by extending vault-scoped `/vaults/{name}/deleted/...` list/restore/purge routes to keys and certificates, exactly mirroring the existing secrets implementation.

**Architecture:** Add scope-aware `ListDeletedKeys`/`RecoverKey`/`PurgeKey` to `KeyService` and `ListDeletedCertificates`/`RecoverCertificate`/`PurgeCertificate` to `CertificateService`. Each is built on the repository's existing scope-aware `List(ctx, scope, Filter{OnlyDeleted: true})` method (already vault-aware — this is not a new capability) plus the existing by-ID `RecoverKey`/`PurgeKey`/`RecoverCertificate`/`PurgeCertificate` repository methods, which keep their current signature (no `scope` param — authorization happens once, in the service layer). This exactly mirrors the live pattern in `secretService.RecoverSecret`/`PurgeSecret`/`softDeletedInScope`/`ListDeletedSecrets` (`internal/services/secrets/secret_service.go:420-429,750-798`). Rewire the seven key/cert handlers in `api/soft_delete.go` to resolve `model.Scope` via the same `scopeFromRequest`/`vaultIDFromRequest` helpers the secrets handlers already use, replacing direct `ServiceContainer.GetKeyRepository()`/`GetCertificateRepository()` calls. Register list/restore/purge for keys and certificates on the vault-scoped `/vaults/{name}/deleted` subrouter. Remove the now-dead `ListSoftDeleted(ctx, userID uuid.UUID)` repository method once its only callers (the old handlers) are gone.

**Tech Stack:** Go, gorilla/mux, testify/mock, mockery v2.53.6 (`~/go/bin/mockery`, config at `.mockery.yaml`).

## Global Constraints

- `go build ./...` and `go vet ./...` must pass after every task.
- Mirror `internal/services/secrets/secret_service.go:420-429,750-798` exactly for the new service methods — same shape, same error-wrapping style, same audit-logging calls. Do not invent a different pattern for keys/certs.
- Regenerate mocks with `mockery` (run from repo root; it reads `.mockery.yaml`) after every interface change. Never hand-edit `mocks/mock_*.go` files.
- Repository-level `RecoverKey`/`PurgeKey`/`RecoverCertificate`/`PurgeCertificate` keep their current by-ID-only signature. Do not add a redundant scope parameter at the repository layer — the service layer is the single authorization checkpoint, exactly as it already is for secrets.

---

### Task 1: Add scope-aware deleted-key operations to `KeyService`

**Files:**
- Modify: `internal/services/keys/key_service.go:88-102` (interface), add new methods after `DeleteKey` (~line 440, before `RotateKey`)
- Modify: `internal/services/keys/mocks/mock_KeyService.go` (regenerate, do not hand-edit)
- Modify: `internal/services/keys/key_soft_delete_test.go` (add tests; the existing `mockKeyRepository` in this file already implements `List`, `RecoverKey`, `PurgeKey` — no mock changes needed there)

**Interfaces:**
- Consumes: `repositories.KeyRepositoryInterface.List(ctx, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error)` (already exists, already scope-aware — `internal/repositories/key_repository.go:34`), `RecoverKey(ctx, id uuid.UUID) error` and `PurgeKey(ctx, id uuid.UUID) error` (already exist, by-ID only — `key_repository.go:38-39`).
- Produces: `KeyService.ListDeletedKeys(ctx, scope model.Scope) ([]model.Key, error)`, `KeyService.RecoverKey(ctx, keyID uuid.UUID, scope model.Scope) error`, `KeyService.PurgeKey(ctx, keyID uuid.UUID, scope model.Scope) error` — consumed by Task 3's handler rewrite.

- [ ] **Step 1: Add the three methods to the `KeyService` interface**

In `internal/services/keys/key_service.go`, change:

```go
type KeyService interface {
	CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	// GetKey retrieves a key authorized by scope and enforces its lifecycle.
	GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// ListKeys lists keys authorized by scope and narrowed by filter.
	ListKeys(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error)
	// UpdateKey updates a key authorized by req.Scope.
	UpdateKey(ctx context.Context, req UpdateKeyRequest) error
	// DeleteKey soft-deletes a key authorized by scope.
	DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// RotateKey rotates a key authorized by scope.
	RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*CreateKeyResult, error)
	ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error
}
```

to:

```go
type KeyService interface {
	CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	// GetKey retrieves a key authorized by scope and enforces its lifecycle.
	GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// ListKeys lists keys authorized by scope and narrowed by filter.
	ListKeys(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error)
	// UpdateKey updates a key authorized by req.Scope.
	UpdateKey(ctx context.Context, req UpdateKeyRequest) error
	// DeleteKey soft-deletes a key authorized by scope.
	DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// RotateKey rotates a key authorized by scope.
	RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*CreateKeyResult, error)
	// ListDeletedKeys lists soft-deleted keys authorized by scope.
	ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error)
	// RecoverKey restores a soft-deleted key authorized by scope.
	RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	// PurgeKey permanently deletes a soft-deleted key authorized by scope.
	PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error
}
```

- [ ] **Step 2: Write the failing tests**

Append to `internal/services/keys/key_soft_delete_test.go`:

```go
// TestListDeletedKeys_FiltersInSQLNotInGo verifies ListDeletedKeys delegates
// straight to the scope-aware List with OnlyDeleted, mirroring
// secretService.ListDeletedSecrets.
func TestListDeletedKeys_FiltersInSQLNotInGo(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	now := time.Now()
	want := []model.Key{{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).Return(want, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	got, err := svc.ListDeletedKeys(context.Background(), scope)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
	repo.AssertExpectations(t)
}

// TestRecoverKey_RequiresTheKeyToBeInScope verifies RecoverKey rejects a key
// ID that isn't in the scope's soft-deleted listing, without ever calling
// the repository's RecoverKey.
func TestRecoverKey_RequiresTheKeyToBeInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).Return([]model.Key{}, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	err := svc.RecoverKey(context.Background(), keyID, scope)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	repo.AssertNotCalled(t, "RecoverKey", mock.Anything, mock.Anything)
}

// TestRecoverKey_RecoversWhenInScope verifies RecoverKey calls the
// repository's RecoverKey once the key is confirmed in scope.
func TestRecoverKey_RecoversWhenInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}, nil)
	repo.On("RecoverKey", mock.Anything, keyID).Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	err := svc.RecoverKey(context.Background(), keyID, scope)
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

// TestPurgeKey_RequiresTheKeyToBeInScope mirrors TestRecoverKey_RequiresTheKeyToBeInScope for purge.
func TestPurgeKey_RequiresTheKeyToBeInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).Return([]model.Key{}, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	err := svc.PurgeKey(context.Background(), keyID, scope)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	repo.AssertNotCalled(t, "PurgeKey", mock.Anything, mock.Anything)
}

// TestPurgeKey_PurgesWhenInScope mirrors TestRecoverKey_RecoversWhenInScope for purge.
func TestPurgeKey_PurgesWhenInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	keyID := uuid.New()
	now := time.Now()

	repo := &mockKeyRepository{}
	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now}}, nil)
	repo.On("PurgeKey", mock.Anything, keyID).Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, Logger: logger})

	err := svc.PurgeKey(context.Background(), keyID, scope)
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/services/keys/... -run 'TestListDeletedKeys_FiltersInSQLNotInGo|TestRecoverKey_RequiresTheKeyToBeInScope|TestRecoverKey_RecoversWhenInScope|TestPurgeKey_RequiresTheKeyToBeInScope|TestPurgeKey_PurgesWhenInScope' -v`

Expected: FAIL with `svc.ListDeletedKeys undefined (type KeyService has no field or method ListDeletedKeys)` (compile error) — this is the go equivalent of a red test, since the interface doesn't have the methods yet.

- [ ] **Step 4: Implement the three methods**

In `internal/services/keys/key_service.go`, add after the closing brace of `DeleteKey` (currently ends ~line 440, right before the `RotateKey` doc comment):

```go
// keyDeletedInScope reports whether keyID names a soft-deleted key the scope
// authorizes.
func (s *keyService) keyDeletedInScope(ctx context.Context, keyID uuid.UUID, scope model.Scope) (bool, error) {
	deleted, err := s.keyRepo.List(ctx, scope, repositories.KeyFilter{OnlyDeleted: true})
	if err != nil {
		return false, fmt.Errorf("failed to list deleted keys: %w", err)
	}
	for _, key := range deleted {
		if key.ID == keyID {
			return true, nil
		}
	}
	return false, nil
}

// ListDeletedKeys lists soft-deleted keys authorized by scope.
func (s *keyService) ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error) {
	keys, err := s.keyRepo.List(ctx, scope, repositories.KeyFilter{OnlyDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted keys: %w", err)
	}
	return keys, nil
}

// RecoverKey restores a soft-deleted key authorized by scope.
func (s *keyService) RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	inScope, err := s.keyDeletedInScope(ctx, keyID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "recover_key", "failed",
			"Key not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrKeyNotFound)
	}
	if err := s.keyRepo.RecoverKey(ctx, keyID); err != nil {
		return fmt.Errorf("failed to recover key: %w", err)
	}
	return nil
}

// PurgeKey permanently deletes a soft-deleted key authorized by scope.
func (s *keyService) PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	inScope, err := s.keyDeletedInScope(ctx, keyID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_key", "failed",
			"Key not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrKeyNotFound)
	}
	if err := s.keyRepo.PurgeKey(ctx, keyID); err != nil {
		return fmt.Errorf("failed to purge key: %w", err)
	}
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/services/keys/... -run 'TestListDeletedKeys_FiltersInSQLNotInGo|TestRecoverKey_RequiresTheKeyToBeInScope|TestRecoverKey_RecoversWhenInScope|TestPurgeKey_RequiresTheKeyToBeInScope|TestPurgeKey_PurgesWhenInScope' -v`

Expected: PASS (5 tests).

- [ ] **Step 6: Regenerate the `KeyService` mock**

Run: `cd /home/numericlabs/data/rocket/rocketvault && mockery`

This regenerates `internal/services/keys/mocks/mock_KeyService.go` (and every other mock listed in `.mockery.yaml`) to add `ListDeletedKeys`/`RecoverKey`/`PurgeKey`. Run `go build ./...` afterward to confirm every existing user of `mocks.MockKeyService` still compiles (none should break — this is a pure addition).

- [ ] **Step 7: Run the full package test suite and commit**

Run: `go build ./... && go vet ./... && go test ./internal/services/keys/... -v`

Expected: all pass.

```bash
git add internal/services/keys/key_service.go internal/services/keys/key_soft_delete_test.go internal/services/keys/mocks/mock_KeyService.go
git commit -m "feat(keys): add scope-aware ListDeletedKeys/RecoverKey/PurgeKey to KeyService"
```

---

### Task 2: Add scope-aware deleted-certificate operations to `CertificateService`

**Files:**
- Modify: `internal/services/certificates/certificate_service.go:80-97` (interface), add new methods after `DeleteCertificate`
- Modify: `internal/services/certificates/mocks/mock_CertificateService.go` (regenerate)
- Modify: `internal/services/certificates/cert_soft_delete_test.go` (add tests; existing `mockCertRepository` already implements `List`, `RecoverCertificate`, `PurgeCertificate`)

**Interfaces:**
- Consumes: `repositories.CertificateRepositoryInterface.List(ctx, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error)` (`internal/repositories/certificate_repository.go:34`), `RecoverCertificate(ctx, id uuid.UUID) error`, `PurgeCertificate(ctx, id uuid.UUID) error` (`certificate_repository.go:39-40`).
- Produces: `CertificateService.ListDeletedCertificates(ctx, scope model.Scope) ([]model.Certificate, error)`, `CertificateService.RecoverCertificate(ctx, certID uuid.UUID, scope model.Scope) error`, `CertificateService.PurgeCertificate(ctx, certID uuid.UUID, scope model.Scope) error` — consumed by Task 3.

- [ ] **Step 1: Add the three methods to the `CertificateService` interface**

In `internal/services/certificates/certificate_service.go`, change:

```go
type CertificateService interface {
	CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	// GetCertificate retrieves a certificate authorized by scope.
	GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error)
	// ListCertificates lists certificates authorized by scope.
	ListCertificates(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error)
	// UpdateCertificate updates a certificate authorized by req.Scope.
	UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error
	// DeleteCertificate soft-deletes a certificate authorized by scope.
	DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	// RenewCertificate renews certID, authorized by scope. scope.ActorID() is
	// also the audit-log principal and the identity used by the internal
	// key-ownership checks below.
	RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)
	ValidateCertificateAccess(ctx context.Context, certID, userID uuid.UUID, role string) error
	ValidateKeyOwnership(ctx context.Context, keyID, userID uuid.UUID, role string) error
}
```

to:

```go
type CertificateService interface {
	CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	// GetCertificate retrieves a certificate authorized by scope.
	GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error)
	// ListCertificates lists certificates authorized by scope.
	ListCertificates(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error)
	// UpdateCertificate updates a certificate authorized by req.Scope.
	UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error
	// DeleteCertificate soft-deletes a certificate authorized by scope.
	DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	// RenewCertificate renews certID, authorized by scope. scope.ActorID() is
	// also the audit-log principal and the identity used by the internal
	// key-ownership checks below.
	RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)
	// ListDeletedCertificates lists soft-deleted certificates authorized by scope.
	ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error)
	// RecoverCertificate restores a soft-deleted certificate authorized by scope.
	RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	// PurgeCertificate permanently deletes a soft-deleted certificate authorized by scope.
	PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error
	ValidateCertificateAccess(ctx context.Context, certID, userID uuid.UUID, role string) error
	ValidateKeyOwnership(ctx context.Context, keyID, userID uuid.UUID, role string) error
}
```

- [ ] **Step 2: Write the failing tests**

Append to `internal/services/certificates/cert_soft_delete_test.go`:

```go
// TestListDeletedCertificates_FiltersInSQLNotInGo verifies ListDeletedCertificates
// delegates straight to the scope-aware List with OnlyDeleted.
func TestListDeletedCertificates_FiltersInSQLNotInGo(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	now := time.Now()
	want := []model.Certificate{{ID: uuid.New(), Name: "cert", DeletedAt: &now}}

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).Return(want, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	got, err := svc.ListDeletedCertificates(context.Background(), scope)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
	repo.AssertExpectations(t)
}

// TestRecoverCertificate_RequiresTheCertToBeInScope verifies RecoverCertificate
// rejects a cert ID not in the scope's soft-deleted listing.
func TestRecoverCertificate_RequiresTheCertToBeInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).Return([]model.Certificate{}, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	err := svc.RecoverCertificate(context.Background(), certID, scope)
	assert.ErrorIs(t, err, ErrCertNotFound)
	repo.AssertNotCalled(t, "RecoverCertificate", mock.Anything, mock.Anything)
}

// TestRecoverCertificate_RecoversWhenInScope verifies RecoverCertificate calls
// the repository's RecoverCertificate once the cert is confirmed in scope.
func TestRecoverCertificate_RecoversWhenInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()
	now := time.Now()

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).
		Return([]model.Certificate{{ID: certID, Name: "cert", DeletedAt: &now}}, nil)
	repo.On("RecoverCertificate", mock.Anything, certID).Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	err := svc.RecoverCertificate(context.Background(), certID, scope)
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

// TestPurgeCertificate_RequiresTheCertToBeInScope mirrors
// TestRecoverCertificate_RequiresTheCertToBeInScope for purge.
func TestPurgeCertificate_RequiresTheCertToBeInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).Return([]model.Certificate{}, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	err := svc.PurgeCertificate(context.Background(), certID, scope)
	assert.ErrorIs(t, err, ErrCertNotFound)
	repo.AssertNotCalled(t, "PurgeCertificate", mock.Anything, mock.Anything)
}

// TestPurgeCertificate_PurgesWhenInScope mirrors
// TestRecoverCertificate_RecoversWhenInScope for purge.
func TestPurgeCertificate_PurgesWhenInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()
	now := time.Now()

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).
		Return([]model.Certificate{{ID: certID, Name: "cert", DeletedAt: &now}}, nil)
	repo.On("PurgeCertificate", mock.Anything, certID).Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	err := svc.PurgeCertificate(context.Background(), certID, scope)
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/services/certificates/... -run 'TestListDeletedCertificates_FiltersInSQLNotInGo|TestRecoverCertificate_RequiresTheCertToBeInScope|TestRecoverCertificate_RecoversWhenInScope|TestPurgeCertificate_RequiresTheCertToBeInScope|TestPurgeCertificate_PurgesWhenInScope' -v`

Expected: FAIL (compile error — methods don't exist yet).

- [ ] **Step 4: Implement the three methods**

In `internal/services/certificates/certificate_service.go`, add after the closing brace of `DeleteCertificate`:

```go
// certDeletedInScope reports whether certID names a soft-deleted certificate
// the scope authorizes.
func (s *certificateService) certDeletedInScope(ctx context.Context, certID uuid.UUID, scope model.Scope) (bool, error) {
	deleted, err := s.certRepo.List(ctx, scope, repositories.CertificateFilter{OnlyDeleted: true})
	if err != nil {
		return false, fmt.Errorf("failed to list deleted certificates: %w", err)
	}
	for _, cert := range deleted {
		if cert.ID == certID {
			return true, nil
		}
	}
	return false, nil
}

// ListDeletedCertificates lists soft-deleted certificates authorized by scope.
func (s *certificateService) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	certs, err := s.certRepo.List(ctx, scope, repositories.CertificateFilter{OnlyDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted certificates: %w", err)
	}
	return certs, nil
}

// RecoverCertificate restores a soft-deleted certificate authorized by scope.
func (s *certificateService) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	inScope, err := s.certDeletedInScope(ctx, certID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "recover_certificate", "failed",
			"Certificate not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrCertNotFound)
	}
	if err := s.certRepo.RecoverCertificate(ctx, certID); err != nil {
		return fmt.Errorf("failed to recover certificate: %w", err)
	}
	return nil
}

// PurgeCertificate permanently deletes a soft-deleted certificate authorized by scope.
func (s *certificateService) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	inScope, err := s.certDeletedInScope(ctx, certID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_certificate", "failed",
			"Certificate not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrCertNotFound)
	}
	if err := s.certRepo.PurgeCertificate(ctx, certID); err != nil {
		return fmt.Errorf("failed to purge certificate: %w", err)
	}
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/services/certificates/... -run 'TestListDeletedCertificates_FiltersInSQLNotInGo|TestRecoverCertificate_RequiresTheCertToBeInScope|TestRecoverCertificate_RecoversWhenInScope|TestPurgeCertificate_RequiresTheCertToBeInScope|TestPurgeCertificate_PurgesWhenInScope' -v`

Expected: PASS (5 tests).

- [ ] **Step 6: Regenerate the `CertificateService` mock and verify the build**

Run: `cd /home/numericlabs/data/rocket/rocketvault && mockery && go build ./... && go vet ./...`

- [ ] **Step 7: Run the full package test suite and commit**

Run: `go test ./internal/services/certificates/... -v`

Expected: all pass.

```bash
git add internal/services/certificates/certificate_service.go internal/services/certificates/cert_soft_delete_test.go internal/services/certificates/mocks/mock_CertificateService.go
git commit -m "feat(certificates): add scope-aware ListDeletedCertificates/RecoverCertificate/PurgeCertificate to CertificateService"
```

---

### Task 3: Rewire `api/soft_delete.go` handlers and routes to be vault-scope-aware

**Files:**
- Modify: `api/soft_delete.go` (entire keys and certificates section, lines 113-383, plus route registration lines 401-440)

**Interfaces:**
- Consumes: `c.keySvc() keyServices.KeyService` (`api/context.go:230`), `c.certSvc() certServices.CertificateService` (`api/context.go:254`), `scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool)` (`api/context.go:64`), `vaultIDFromRequest(r *http.Request) (uuid.UUID, error)` (`api/context.go:44`), `writeKeyError(c *Context, err error)` (`api/errors_key.go:18`), `writeCertificateError(c *Context, err error)` (`api/errors_certificate.go:17`), and the three new `KeyService`/`CertificateService` methods from Tasks 1-2.
- Produces: no change to the JSON response shape of any of the seven handlers — only their internal scope resolution and route registration change. `getDeletedKey` keeps its existing flat-only route (no vault-scoped equivalent exists for secrets either, so none is added here for parity — see the Global Constraints note on mirroring secrets exactly).

- [ ] **Step 1: Replace the keys section of `api/soft_delete.go`**

Replace lines 113-266 (from `// listDeletedKeys returns...` through the closing brace of `purgeKey`) with:

```go
// listDeletedKeys returns all soft-deleted keys in the resolved vault. The
// vault is read from the request context (falling back to the default vault
// for legacy flat routes), so the listing honours the vault-scoped
// /vaults/{name}/deleted/keys route. Per the visibility model, any caller
// authorized for a vault sees all of its soft-deleted keys (mirrors
// listDeletedSecrets).
func listDeletedKeys(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}

	keys, err := keySvc.ListDeletedKeys(r.Context(), model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	type keyItem struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Type            string `json:"type"`
		DeletedAt       any    `json:"deleted_at"`
		PurgeProtection bool   `json:"purge_protection"`
	}

	items := make([]keyItem, len(keys))
	for i, k := range keys {
		items[i] = keyItem{
			ID:              k.ID.String(),
			Name:            k.Name,
			Type:            k.Type,
			DeletedAt:       k.DeletedAt,
			PurgeProtection: k.PurgeProtection,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted_keys": items, "total": len(items)}) //nolint:errcheck,gosec
}

// getDeletedKey returns a single soft-deleted key by its UUID, resolved
// within the same vault scope as listDeletedKeys. It has no vault-scoped
// route counterpart (secrets doesn't have a single-item deleted GET either),
// so it stays registered on the flat router only, where it resolves to the
// default vault.
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

	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}

	keys, err := keySvc.ListDeletedKeys(r.Context(), model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	for _, k := range keys {
		if k.ID == keyID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec
				"id":               k.ID.String(),
				"name":             k.Name,
				"type":             k.Type,
				"deleted_at":       k.DeletedAt,
				"purge_protection": k.PurgeProtection,
			})
			return
		}
	}
	c.SetNotFound("key")
}

// recoverKey restores a soft-deleted key by ID.
func recoverKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := keySvc.RecoverKey(r.Context(), keyID, scope); err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Key recovered successfully", "id": keyID.String()}) //nolint:errcheck,gosec
}

// purgeKey permanently deletes a soft-deleted key by ID.
func purgeKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := keySvc.PurgeKey(r.Context(), keyID, scope); err != nil {
		writeKeyError(c, err)
		return
	}

	ReturnStatusOK(w)
}
```

- [ ] **Step 2: Replace the certificates section of `api/soft_delete.go`**

Replace lines 268-383 (from `// listDeletedCertificates returns...` through the closing brace of `purgeCertificate`) with:

```go
// listDeletedCertificates returns all soft-deleted certificates in the
// resolved vault, mirroring listDeletedKeys/listDeletedSecrets.
func listDeletedCertificates(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	certs, err := certSvc.ListDeletedCertificates(r.Context(), model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	type certItem struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		DeletedAt       any    `json:"deleted_at"`
		PurgeProtection bool   `json:"purge_protection"`
	}

	items := make([]certItem, len(certs))
	for i, cert := range certs {
		items[i] = certItem{
			ID:              cert.ID.String(),
			Name:            cert.Name,
			DeletedAt:       cert.DeletedAt,
			PurgeProtection: cert.PurgeProtection,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted_certificates": items, "total": len(items)}) //nolint:errcheck,gosec
}

// recoverCertificate restores a soft-deleted certificate by ID.
func recoverCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := certSvc.RecoverCertificate(r.Context(), certID, scope); err != nil {
		writeCertificateError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Certificate recovered successfully", "id": certID.String()}) //nolint:errcheck,gosec
}

// purgeCertificate permanently deletes a soft-deleted certificate by ID.
func purgeCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := certSvc.PurgeCertificate(r.Context(), certID, scope); err != nil {
		writeCertificateError(c, err)
		return
	}

	ReturnStatusOK(w)
}
```

- [ ] **Step 3: Update route registration and the `InitDeleted` doc comment**

Replace the block from `// InitDeleted registers...` (~line 401) through the end of the file with:

```go
// InitDeleted registers soft-delete management routes.
//
// All seven deleted-flow handlers (secrets, keys, certificates) are now
// vault-aware: they read the vault from the request context via
// scopeFromRequest/vaultIDFromRequest, so they are registered on both the
// legacy flat routes and the vault-scoped subrouter. getDeletedKey is the one
// exception — it has no vault-scoped route because it has no secrets
// equivalent to mirror (secrets exposes no single-item deleted GET either);
// it stays flat-only and resolves to the default vault.
func (api *API) InitDeleted() {
	api.registerDeletedRoutes(api.BaseRoutes.Deleted)
	if api.BaseRoutes.VaultScoped != nil {
		api.registerVaultScopedDeletedRoutes(api.BaseRoutes.VaultScoped.PathPrefix("/deleted").Subrouter())
	}
}

// registerDeletedRoutes registers all soft-delete handlers on the legacy flat
// routes. These resolve to the default vault / owner scope.
func (api *API) registerDeletedRoutes(r *mux.Router) {
	api.registerVaultScopedDeletedRoutes(r)

	// getDeletedKey has no vault-scoped counterpart; see the InitDeleted comment.
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getDeletedKey)).Methods("GET")
}

// registerVaultScopedDeletedRoutes registers the vault-aware soft-delete
// handlers for all three resource types. List handlers honour the resolved
// vault; restore/purge operate by globally-unique ID so they already act on
// the correct object once scoped.
func (api *API) registerVaultScopedDeletedRoutes(r *mux.Router) {
	r.Handle("/secrets", ApiSessionRequired(api.App, listDeletedSecrets)).Methods("GET")
	r.Handle("/secrets/{secret_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverSecret)).Methods("POST")
	r.Handle("/secrets/{secret_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeSecret)).Methods("DELETE")
	r.Handle("/keys", ApiSessionRequired(api.App, listDeletedKeys)).Methods("GET")
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverKey)).Methods("POST")
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeKey)).Methods("DELETE")
	r.Handle("/certificates", ApiSessionRequired(api.App, listDeletedCertificates)).Methods("GET")
	r.Handle("/certificates/{certificate_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverCertificate)).Methods("POST")
	r.Handle("/certificates/{certificate_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeCertificate)).Methods("DELETE")
}
```

- [ ] **Step 4: Build (tests will fail — that's expected, Task 4 fixes them)**

Run: `go build ./... && go vet ./...`

Expected: builds clean. `go test ./api/...` will fail to compile at this point because `api/soft_delete_test.go`, `api/soft_delete_extended_test.go`, and `api/coverage_boost_test.go` still reference `c.App.ServiceContainer.GetKeyRepository().ListSoftDeleted(...)`-based stubs that the handlers no longer call the same way — that's Task 4.

- [ ] **Step 5: Commit**

```bash
git add api/soft_delete.go
git commit -m "feat(api): make key/certificate deleted-flow handlers vault-scope-aware"
```

---

### Task 4: Migrate handler tests from repository stubs to service mocks, add vault-scope-routing proof

**Files:**
- Modify: `api/soft_delete_test.go` (rewrite `TestGetDeletedKey_*`)
- Modify: `api/soft_delete_extended_test.go` (rewrite all key/cert list/recover/purge tests)
- Modify: `api/coverage_boost_test.go` (delete now-duplicate not-found tests and their stub types)

**Interfaces:**
- Consumes: `mockKeyService` (`api/keys_crud_test.go:45`, implements `keyServices.KeyService`), `newKeyCtx(svc keyServices.KeyService) *Context` (`api/keys_crud_test.go:246`), `mockCertService` (`api/certificates_test.go:46`, implements `certServices.CertificateService`), `newCertCtx(svc certServices.CertificateService, claims jwt.MapClaims) *Context` (`api/certificates_test.go:243`), `certAdminClaims()` (`api/certificates_test.go:254`).
- Produces: no new exported symbols — this task only rewrites test bodies.

- [ ] **Step 1: Add `ListDeletedKeys`/`RecoverKey`/`PurgeKey` to `mockKeyService`**

In `api/keys_crud_test.go`, append after the existing `ValidateKeyAccess` method (line ~102-105 area, matching the style of the other methods in that file):

```go
func (m *mockKeyService) ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}

func (m *mockKeyService) RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}

func (m *mockKeyService) PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}
```

- [ ] **Step 2: Add `ListDeletedCertificates`/`RecoverCertificate`/`PurgeCertificate` to `mockCertService`**

In `api/certificates_test.go`, append after the existing `ValidateKeyOwnership` method:

```go
func (m *mockCertService) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

func (m *mockCertService) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, certID, scope).Error(0)
}

func (m *mockCertService) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, certID, scope).Error(0)
}
```

- [ ] **Step 3: Rewrite `api/soft_delete_test.go`'s `getDeletedKey` tests**

Replace the entire file's test section (everything from `// --- stub key repository ---` at line 62 through the end of the file, i.e. lines 62-339) with:

```go
// --- helpers ---

const sdTestUserIDStr = "c3d4e5f6-a7b8-9012-cdef-123456789012"

// newGetDeletedKeyContext builds a Context backed by the given KeyService mock.
func newGetDeletedKeyContext(svc keyServices.KeyService) *Context {
	a := &app.App{ServiceContainer: &keySvcTestContainer{keySvc: svc}}
	return &Context{
		App: a,
		Claims: jwt.MapClaims{
			"user_id": sdTestUserIDStr,
		},
	}
}

// --- tests ---

// TestGetDeletedKey_Found_Returns200 verifies that getDeletedKey returns 200
// with the expected JSON fields when the key exists in the soft-deleted list.
func TestGetDeletedKey_Found_Returns200(t *testing.T) {
	targetID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	deletedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return([]model.Key{
		{ID: targetID, Name: "my-rsa-key", Type: model.KeyTypeRSA, DeletedAt: &deletedAt},
	}, nil)

	c := newGetDeletedKeyContext(svc)
	c.Params = &ApiParams{KeyID: targetID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys/"+targetID.String(), nil)

	getDeletedKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, targetID.String(), body["id"])
	assert.Equal(t, "my-rsa-key", body["name"])
	assert.Equal(t, model.KeyTypeRSA, body["type"])
	assert.NotNil(t, body["deleted_at"], "deleted_at must be present in the response")
	svc.AssertExpectations(t)
}

// TestGetDeletedKey_NotFound_Returns404 verifies that getDeletedKey returns 404
// when no soft-deleted key with the requested ID exists.
func TestGetDeletedKey_NotFound_Returns404(t *testing.T) {
	existingID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	requestedID := uuid.MustParse("ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb")
	deletedAt := time.Now()

	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return([]model.Key{
		{ID: existingID, Name: "other-key", Type: model.KeyTypeECDSA, DeletedAt: &deletedAt},
	}, nil)

	c := newGetDeletedKeyContext(svc)
	c.Params = &ApiParams{KeyID: requestedID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys/"+requestedID.String(), nil)

	getDeletedKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}
```

Also trim this file's `import` block: remove `"database/sql"`, `"rocketvault/internal/backup"`, `"rocketvault/internal/cache"`, `"rocketvault/internal/crypto"`, `"rocketvault/internal/keycache"`, `"rocketvault/internal/logging"`, `"rocketvault/internal/metrics"`, `"rocketvault/internal/repositories"`, `auditServices "rocketvault/internal/services/audit"`, `authServices "rocketvault/internal/services/auth"`, `authzServices "rocketvault/internal/services/authorization"`, `certServices "rocketvault/internal/services/certificates"`, `oauth2Services "rocketvault/internal/services/oauth2"`, `retryServices "rocketvault/internal/services/retry"`, `secretServices "rocketvault/internal/services/secrets"`, `userServices "rocketvault/internal/services/users"`, `vaultServices "rocketvault/internal/services/vaults"`, `"rocketvault/internal/signing"` (all of these were only needed by the deleted `keyRepoTestContainer`'s full interface implementation) — keep `"context"` only if still used elsewhere in the file (check with `goimports`), and add `keyServices "rocketvault/internal/services/keys"`.

- [ ] **Step 4: Rewrite the keys section of `api/soft_delete_extended_test.go`**

Replace lines 452-605 (from `// listDeletedKeys` through the end of `TestPurgeKey_Success_Returns200`) with:

```go
// ============================================================
// listDeletedKeys
//
// These handlers now delegate entirely to the KeyService (see
// key_soft_delete_test.go for the scope-authorization branch coverage).
// What remains here is the equivalence proof that the handler still wires
// status codes correctly, mirroring listDeletedSecrets's tests above.
// ============================================================

func TestListDeletedKeys_ServiceError_Returns500(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return(nil, errTest)
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys", nil)

	listDeletedKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedKeys_Success_Returns200(t *testing.T) {
	now := time.Now()
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return([]model.Key{
		{ID: uuid.New(), Name: "k", Type: model.KeyTypeRSA, DeletedAt: &now},
	}, nil)
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys", nil)

	listDeletedKeys(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// recoverKey
// ============================================================

func TestRecoverKey_InvalidID_Returns400(t *testing.T) {
	c := newKeyCtx(&mockKeyService{})
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/bad/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecoverKey_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.Anything).Return(keyServices.ErrKeyNotFound)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/"+keyID.String()+"/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.Anything).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/"+keyID.String()+"/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// purgeKey
// ============================================================

func TestPurgeKey_InvalidID_Returns400(t *testing.T) {
	c := newKeyCtx(&mockKeyService{})
	c.Params = &ApiParams{KeyID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/bad/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeKey_NotFound_Returns404(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("PurgeKey", mock.Anything, keyID, mock.Anything).Return(keyServices.ErrKeyNotFound)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/"+keyID.String()+"/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeKey_Success_Returns200(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("PurgeKey", mock.Anything, keyID, mock.Anything).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/keys/"+keyID.String()+"/purge", nil)

	purgeKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}
```

- [ ] **Step 5: Rewrite the certificates section of `api/soft_delete_extended_test.go`**

Replace lines 607-754 (from `// listDeletedCertificates` through the end of the file) with:

```go
// ============================================================
// listDeletedCertificates
//
// These handlers now delegate entirely to the CertificateService — see the
// comment above the keys section for why the coverage shape changed.
// ============================================================

func TestListDeletedCertificates_ServiceError_Returns500(t *testing.T) {
	svc := &mockCertService{}
	svc.On("ListDeletedCertificates", mock.Anything, mock.Anything).Return(nil, errTest)
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil)

	listDeletedCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

func TestListDeletedCertificates_Success_Returns200(t *testing.T) {
	now := time.Now()
	svc := &mockCertService{}
	svc.On("ListDeletedCertificates", mock.Anything, mock.Anything).Return([]model.Certificate{
		{ID: uuid.New(), Name: "cert", DeletedAt: &now},
	}, nil)
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil)

	listDeletedCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// recoverCertificate
// ============================================================

func TestRecoverCertificate_InvalidID_Returns400(t *testing.T) {
	c := newCertCtx(&mockCertService{}, certAdminClaims())
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/bad/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRecoverCertificate_NotFound_Returns404(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("RecoverCertificate", mock.Anything, certID, mock.Anything).Return(certServices.ErrCertNotFound)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/"+certID.String()+"/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverCertificate_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("RecoverCertificate", mock.Anything, certID, mock.Anything).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/"+certID.String()+"/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// purgeCertificate
// ============================================================

func TestPurgeCertificate_InvalidID_Returns400(t *testing.T) {
	c := newCertCtx(&mockCertService{}, certAdminClaims())
	c.Params = &ApiParams{CertificateID: "bad", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/bad/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPurgeCertificate_NotFound_Returns404(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("PurgeCertificate", mock.Anything, certID, mock.Anything).Return(certServices.ErrCertNotFound)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/"+certID.String()+"/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

func TestPurgeCertificate_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("PurgeCertificate", mock.Anything, certID, mock.Anything).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/deleted/certificates/"+certID.String()+"/purge", nil)

	purgeCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}
```

Also delete the now-unused `stubCertRepo`, `certRepoTestContainer`, `newCertRepoCtxExt`/`newCertRepoCtx`, `newKeyRepoCtxExt` and their supporting code at the top of this file (lines 43-255), and trim the import block the same way as Step 3 (drop everything only needed by the deleted full-interface stub containers). Keep `errTest` (line 41) — it's still used by the rewritten `TestListDeletedKeys_ServiceError_Returns500`/`TestListDeletedCertificates_ServiceError_Returns500` tests above.

- [ ] **Step 6: Delete the now-duplicate not-found tests in `api/coverage_boost_test.go`**

Delete `TestPurgeKey_NotFoundInDeletedList_Returns404`, `TestRecoverKey_NotFoundInDeletedList_Returns404`, `TestPurgeCertificate_NotFoundInDeletedList_Returns404`, `TestRecoverCertificate_NotFoundInDeletedList_Returns404` (lines 769-851 per the current file) — they duplicate the `_NotFound_Returns404` tests rewritten in Step 4/5 above (the handler now returns not-found via a single service call instead of a separate "check the list, then call recover/purge" branch, so there's only one not-found path left to cover). Also delete their supporting stub types `stubKeyRepoNotFound` and `stubCertRepoEmptyDeleted` if this was their only use (`grep -n "stubKeyRepoNotFound\|stubCertRepoEmptyDeleted" api/*.go` to confirm before deleting).

- [ ] **Step 7: Add vault-scope-routing proof tests**

Append to `api/soft_delete_extended_test.go`, mirroring `api/soft_delete_scope_test.go`'s pattern for secrets:

```go
// ============================================================
// vault-scope routing proof — keys and certificates
//
// Mirrors soft_delete_scope_test.go's secrets coverage: proves the flat
// route builds an owner scope and the vault-scoped route builds a vault
// scope, now that keys/certs go through the same scopeFromRequest path.
// ============================================================

func TestRecoverKey_FlatRoute_UsesOwnerScope(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeOwner
	})).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/keys/"+keyID.String()+"/restore", nil)

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverKey_VaultScopedRoute_UsesVaultScope(t *testing.T) {
	keyID := uuid.New()
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault
	})).Return(nil)
	c := newKeyCtx(svc)
	c.Params = &ApiParams{KeyID: keyID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/vaults/team-a/deleted/keys/"+keyID.String()+"/restore", nil)
	r = mux.SetURLVars(r, map[string]string{"vault_name": "team-a"})

	recoverKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverCertificate_FlatRoute_UsesOwnerScope(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("RecoverCertificate", mock.Anything, certID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeOwner
	})).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/deleted/certificates/"+certID.String()+"/restore", nil)

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestRecoverCertificate_VaultScopedRoute_UsesVaultScope(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("RecoverCertificate", mock.Anything, certID, mock.MatchedBy(func(s model.Scope) bool {
		return s.Kind() == model.ScopeVault
	})).Return(nil)
	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/vaults/team-a/deleted/certificates/"+certID.String()+"/restore", nil)
	r = mux.SetURLVars(r, map[string]string{"vault_name": "team-a"})

	recoverCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}
```

This requires adding `"github.com/gorilla/mux"` to `api/soft_delete_extended_test.go`'s import block if not already present (check first — `mux.SetURLVars` is the standard gorilla/mux test helper for injecting route vars without a full router).

- [ ] **Step 8: Run the full `api` package test suite**

Run: `go build ./... && go vet ./... && go test ./api/... -v 2>&1 | tail -100`

Expected: all pass, including the new vault-scope-routing proofs.

- [ ] **Step 9: Commit**

```bash
git add api/soft_delete_test.go api/soft_delete_extended_test.go api/coverage_boost_test.go api/keys_crud_test.go api/certificates_test.go
git commit -m "test(api): migrate key/certificate deleted-flow tests to service mocks, add vault-scope-routing proof"
```

---

### Task 5: Remove the dead `ListSoftDeleted(ctx, userID)` repository method

**Files:**
- Modify: `internal/repositories/key_repository.go` (interface line 41, implementation)
- Modify: `internal/repositories/certificate_repository.go` (interface line 42, implementation)
- Modify: `internal/repositories/mocks/mock_KeyRepositoryInterface.go`, `mock_CertificateRepositoryInterface.go` (regenerate)
- Modify: `internal/services/keys/key_soft_delete_test.go`, `internal/services/certificates/cert_soft_delete_test.go` (remove `ListSoftDeleted` from `mockKeyRepository`/`mockCertRepository`)
- Modify: any other repository-level test file that directly tests `ListSoftDeleted` (find with `grep -rln "ListSoftDeleted" internal/repositories/*_test.go`)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new — pure deletion. This is the last task, run only after confirming no caller remains.

- [ ] **Step 1: Confirm no caller remains**

Run: `grep -rn "ListSoftDeleted" --include="*.go" /home/numericlabs/data/rocket/rocketvault | grep -v "_test.go\|/mocks/"`

Expected: zero results outside the two interface definitions and their two implementations (i.e., the method itself, not a caller). If anything else shows up, stop and investigate before deleting — Tasks 3-4 should have removed every caller.

- [ ] **Step 2: Remove from `KeyRepositoryInterface` and its implementation**

In `internal/repositories/key_repository.go`, delete the line:
```go
	ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Key, error)
```
from the interface (line 41), and delete the corresponding `func (r *KeyRepository) ListSoftDeleted(...)` implementation (the report identified it around line 687-689 plus its enclosing function — delete the whole function).

- [ ] **Step 3: Remove from `CertificateRepositoryInterface` and its implementation**

Same in `internal/repositories/certificate_repository.go`: delete the interface line (line 42) and the `func (r *CertificateRepository) ListSoftDeleted(...)` implementation (around line 715 onward per the earlier research — delete the whole function).

- [ ] **Step 4: Remove from the hand-written service-layer test mocks**

In `internal/services/keys/key_soft_delete_test.go`, delete the `mockKeyRepository.ListSoftDeleted` method (lines 51-57 per the file read earlier). In `internal/services/certificates/cert_soft_delete_test.go`, delete the equivalent `mockCertRepository.ListSoftDeleted` method (lines 85-90 area).

- [ ] **Step 5: Delete or update repository-level tests for the removed method**

Run: `grep -rln "ListSoftDeleted" internal/repositories/*_test.go`

For every match, delete the test functions that call `ListSoftDeleted` directly (they test a method that no longer exists). Do not delete tests for `List(ctx, scope, Filter{OnlyDeleted: true})` — those cover the method that replaces it and must stay.

- [ ] **Step 6: Regenerate repository mocks**

Run: `cd /home/numericlabs/data/rocket/rocketvault && mockery`

- [ ] **Step 7: Full verification**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | tail -60`

Expected: clean build, all tests pass, `ListSoftDeleted` no longer appears anywhere except possibly in historical git history / docs.

Run: `golangci-lint run ./... 2>&1 | tail -60` (per this repo's CLAUDE.md requirement that code build and lint clean before a PR) and fix anything it flags in the touched files.

- [ ] **Step 8: Update the parity doc**

In `.claude/azure-keyvault-parity.md`:
- §5 row `Vault-scoped deleted/restore/purge`: change from `🟡 secrets only; keys/certs deferred to flat routes` to `✅ all three resource types`.
- Remove the corresponding bullet from the **Partial (🟡)** summary section ("Vault-scoped deleted flow: only secrets are vault-aware...").
- Add a dated note (matching this doc's existing convention of dated re-verification notes) recording that this gap closed and on what date.

- [ ] **Step 9: Commit**

```bash
git add internal/repositories/key_repository.go internal/repositories/certificate_repository.go \
  internal/repositories/mocks/ internal/services/keys/key_soft_delete_test.go \
  internal/services/certificates/cert_soft_delete_test.go .claude/azure-keyvault-parity.md
git commit -m "refactor(repositories): remove dead ListSoftDeleted now that keys/certs use scope-aware List"
```
