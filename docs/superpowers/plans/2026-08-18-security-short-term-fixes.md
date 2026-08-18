# Security Short-Term Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six "Short-term (security-relevant, recommend before next release)" findings from the 2026-08-18 Azure Key Vault parity audit, without touching any Medium-term or deferred item from that audit.

**Architecture:** Each task is a self-contained vertical slice (model → repository → service → API → CLI, only where each layer actually needs a change) fixed and tested in isolation. No task depends on another task's code changes; they may be executed and reviewed in any order. All fixes follow existing codebase conventions exactly (sentinel errors, `model.Scope`, `logging.Logger.LogAuditInfo`/`LogAuditError`, `*bool`-optional DTO fields, `cobra` `Flags().Changed(...)`-gated flags) rather than introducing new patterns.

**Tech Stack:** Go 1.24.2, Gorilla Mux, SQLite/PostgreSQL, Cobra CLI, testify/mock.

**Spec:** `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` — specifically the "Next steps > Short-term (security-relevant, recommend before next release)" list (lines 395-401) and the six Critical Findings it references (#1/F2, #2, #6, #7, #8, and Access-control finding F1). The "RestoreSecret vault-ID mismatch" item (audit line 398) is expanded here to also cover `RestoreKey`/`RestoreCertificate`, which this plan's research confirmed share the identical bug (the audit only named the secret instance).

## Global Constraints

- Go 1.24.2; no new third-party dependencies.
- Every new/changed error must use `errors.New`/sentinel + `errors.Is` — never string-matching on error text (this repo's existing convention, e.g. `vaultServices.ErrVaultPurgeProtected`).
- Every new optional request field follows the `*bool`/`*T` "nil means no change / no explicit value" convention already used by `Enabled *bool` throughout `model/*.go` and the `internal/services/*` DTOs.
- Every audit-log call added must go through `*logging.Logger.LogAuditInfo`/`LogAuditError` (services layer) or `AuditService.RecordEvent` (only where explicitly specified in a task) — never a new logging mechanism.
- No CLI command may skip its authorization check (per `CLAUDE.md`'s "CLI Authorization" section) — any new/touched CLI command must call the same check its HTTP equivalent uses.
- Run `go build ./...` and the affected `go test ./...` package(s) before every commit in this plan; do not commit red.
- Do not fix, refactor, or touch anything outside a task's stated file list, even if you notice something else wrong nearby — file it as a comment for a human, don't scope-creep.

---

## Task 1: CLI `vaults get`/`list` authorization bypass

**Files:**
- Modify: `cmd/vaults/authz.go`
- Modify: `cmd/vaults/get.go`
- Modify: `cmd/vaults/list.go`
- Test: `cmd/vaults/vaults_more_test.go`

**Interfaces:**
- Consumes: `authz.CanManageVault(ctx, accountRole string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool` (`internal/services/authorization/vault_authz.go:23`, unchanged); `resolveTargetVaultID(ctx, svc, name) (uuid.UUID, error)` (`cmd/vaults/authz.go:39`, unchanged); `requireCanManageVault(ctx, sc, vaultName string) error` (`cmd/vaults/authz.go:68`, unchanged, reused by `get.go`).
- Produces: `requireCanListVaults(ctx context.Context, sc container.ServiceContainerInterface) error` — new helper in `cmd/vaults/authz.go`, same shape as the existing `requireCanCreateVault`, for `list.go` to call.

- [ ] **Step 1: Write the failing tests**

Add to `cmd/vaults/vaults_more_test.go`:

```go
func TestVaultsGet_ForbiddenWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser})
	tc.MockContainer.AccessPolicyService = &mockAccessPolicyService{decision: authzServices.AccessFallback}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "guarded-vault"}}, nil)

	cmd := &cobra.Command{Use: "get", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	cmd.SetContext(ctxWithFormatter(nonAdminCtx))
	cmd.SetArgs([]string{"guarded-vault"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "GetVault", mock.Anything, mock.Anything)
}

func TestVaultsList_ForbiddenWithoutGlobalGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	nonAdminCtx := context.WithValue(tc.Ctx, common.ClaimsKey, &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser})
	tc.MockContainer.AccessPolicyService = &mockAccessPolicyService{decision: authzServices.AccessFallback}

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.SetContext(ctxWithFormatter(nonAdminCtx))

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	tc.MockVaultService.AssertNotCalled(t, "ListVaults", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/vaults/... -run 'TestVaultsGet_ForbiddenWithoutGrant|TestVaultsList_ForbiddenWithoutGlobalGrant' -v`
Expected: FAIL — `GetVault`/`ListVaults` get called (no permission-denied error) because no authz check exists yet.

- [ ] **Step 3: Add `requireCanListVaults` to `cmd/vaults/authz.go`**

Add after `requireCanCreateVault` (after line 64):

```go
// requireCanListVaults checks that the caller may list vaults instance-wide.
// Like create, list has no single target vault, so authorization is checked
// against uuid.Nil — matching HTTP listVaults (api/vault.go's
// authzServices.CanManageVault(..., uuid.Nil)).
func requireCanListVaults(ctx context.Context, sc container.ServiceContainerInterface) error {
	role, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageVault(ctx, role, sc.GetAccessPolicyService(), principalID, uuid.Nil) {
		return fmt.Errorf("permission denied: admin or vaults/manage required")
	}
	return nil
}
```

- [ ] **Step 4: Wire the check into `get.go` and `list.go`**

In `cmd/vaults/get.go`, immediately after the service-container type assertion (before `vaultService := serviceContainer.GetVaultService()`):

```go
if err := requireCanManageVault(ctx, serviceContainer, name); err != nil {
    return err
}
```

In `cmd/vaults/list.go`, immediately after the service-container type assertion (before `vaultService := serviceContainer.GetVaultService()`):

```go
if err := requireCanListVaults(ctx, serviceContainer); err != nil {
    return err
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./cmd/vaults/... -v`
Expected: PASS, including the two new tests and every pre-existing `cmd/vaults` test (the happy-path `TestVaultsGet`/`TestVaultsList` still succeed because `testutils.NewTestContext` defaults to `model.RoleAdmin`, which short-circuits `CanManageVault`).

- [ ] **Step 6: Commit**

```bash
git add cmd/vaults/authz.go cmd/vaults/get.go cmd/vaults/list.go cmd/vaults/vaults_more_test.go
git commit -m "fix(cli): require vault-manage authorization on vaults get/list"
```

---

## Task 2: `RestoreSecret`/`RestoreKey`/`RestoreCertificate` vault-ID mismatch

**Files:**
- Modify: `internal/backup/item_backup.go`
- Modify: `api/backup_item.go`
- Test: `internal/backup/item_backup_test.go`
- Test: `api/backup_item_test.go`

**Interfaces:**
- Produces: `RestoreSecret(ctx, blob string, userID, vaultID, newID uuid.UUID) error`, `RestoreKey(ctx, blob string, userID, vaultID, newID uuid.UUID) error`, `RestoreCertificate(ctx, blob string, userID, vaultID, newID uuid.UUID) error` — each gains a `vaultID` parameter (new 3rd positional arg) on `ItemBackupService`. Any other caller of these three methods must be updated to pass the request's authorized vault ID.

- [ ] **Step 1: Write the failing service-level test**

Add to `internal/backup/item_backup_test.go`:

```go
func TestRestoreSecretWritesAuthorizedVaultNotBlobVault(t *testing.T) {
	repo := newStubSecretRepo()
	svc := NewItemBackupService(ItemBackupServiceConfig{SecretRepository: repo})

	vaultA := uuid.New()
	vaultB := uuid.New()
	owner := uuid.New()

	original := &model.Secret{ID: uuid.New(), UserID: owner, VaultID: vaultA, Name: "s1", Value: "v1", Version: 1}
	require.NoError(t, repo.Create(context.Background(), original))

	blob, err := svc.BackupSecret(context.Background(), original.ID, model.NewVaultScope(vaultA, owner))
	require.NoError(t, err)

	newID := uuid.New()
	err = svc.RestoreSecret(context.Background(), blob, owner, vaultB, newID)
	require.NoError(t, err)

	restored, err := repo.Read(context.Background(), newID, model.NewVaultScope(vaultB, owner))
	require.NoError(t, err)
	assert.Equal(t, vaultB, restored.VaultID, "restore must write the authorized vault, not the blob's embedded vault")

	_, err = repo.Read(context.Background(), newID, model.NewVaultScope(vaultA, owner))
	require.Error(t, err, "the restored secret must not be readable under the blob's original vault scope")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/backup/... -run TestRestoreSecretWritesAuthorizedVaultNotBlobVault -v`
Expected: FAIL with a compile error (`RestoreSecret` doesn't take a `vaultID` argument yet).

- [ ] **Step 3: Update `internal/backup/item_backup.go`**

Replace the three `Restore*` methods:

```go
// RestoreSecret decodes blob and inserts it as newID, owned by userID, into
// vaultID — the vault authorized by the caller's request, never the vault
// embedded in the blob. Trusting the blob's vault_id would let a caller with
// restore permission in one vault silently write into any vault a blob
// happens to reference.
func (s *ItemBackupService) RestoreSecret(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var secret model.Secret
	if err := decodeBlob(blob, "secret", &secret); err != nil {
		return err
	}
	secret.ID = newID
	secret.UserID = userID
	secret.VaultID = vaultID
	return s.secretRepo.Create(ctx, &secret)
}
```

```go
// RestoreKey decodes blob and inserts it as newID, owned by userID, into
// vaultID — the vault authorized by the caller's request. See RestoreSecret.
func (s *ItemBackupService) RestoreKey(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var key model.Key
	if err := decodeBlob(blob, "key", &key); err != nil {
		return err
	}
	key.ID = newID
	key.UserID = userID
	key.VaultID = vaultID
	return s.keyRepo.Create(ctx, &key)
}
```

```go
// RestoreCertificate decodes blob and inserts it as newID, owned by userID,
// into vaultID — the vault authorized by the caller's request. See RestoreSecret.
func (s *ItemBackupService) RestoreCertificate(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var cert model.Certificate
	if err := decodeBlob(blob, "certificate", &cert); err != nil {
		return err
	}
	cert.ID = newID
	cert.UserID = userID
	cert.VaultID = vaultID
	return s.certRepo.Create(ctx, &cert)
}
```

- [ ] **Step 4: Update the three HTTP handlers in `api/backup_item.go`**

In `restoreSecretHandler`, before the `svc.RestoreSecret(...)` call, resolve the authorized vault and pass it through:

```go
vaultID, err := vaultIDFromRequest(r)
if err != nil {
    c.SetInvalidParam("vault")
    return
}
```

then change the call from `svc.RestoreSecret(r.Context(), req.Blob, userID, uuid.New())` to:

```go
if err := svc.RestoreSecret(r.Context(), req.Blob, userID, vaultID, uuid.New()); err != nil {
```

Apply the identical two changes to `restoreKeyHandler` (`svc.RestoreKey(r.Context(), req.Blob, userID, vaultID, uuid.New())`) and `restoreCertificateHandler` (`svc.RestoreCertificate(r.Context(), req.Blob, userID, vaultID, uuid.New())`).

- [ ] **Step 5: Add the HTTP-level regression test**

Add to `api/backup_item_test.go`, modeled on the existing `TestRestoreSecretHandler_Success_Returns200`:

```go
func TestRestoreSecretHandler_WritesRequestVaultNotBlobVault(t *testing.T) {
	vaultA := uuid.New()
	vaultB := uuid.New()
	// ... reuse this file's existing test harness to back up a secret scoped
	// to vaultA, then POST to the restore route with common.VaultIDKey set to
	// vaultB in the request context, and assert the created secret's
	// persisted VaultID equals vaultB (via the mock secret service's
	// asserted Create/RestoreSecret call args), not vaultA.
}
```

Fill in the body using this file's existing `mockSecretService`/request-building helpers (see `TestRestoreSecretHandler_Success_Returns200` immediately above it in the file for the exact harness shape) — assert `mockSvc.AssertCalled(t, "RestoreSecret", mock.Anything, blob, userID, vaultB, mock.AnythingOfType("uuid.UUID"))`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/backup/... ./api/... -run 'Restore' -v`
Expected: PASS.

- [ ] **Step 7: Run the full affected package tests**

Run: `go test ./internal/backup/... ./api/... -v`
Expected: PASS (no regression in the surrounding backup/restore or api suites).

- [ ] **Step 8: Commit**

```bash
git add internal/backup/item_backup.go api/backup_item.go internal/backup/item_backup_test.go api/backup_item_test.go
git commit -m "fix(backup): restore secrets/keys/certificates into the authorized vault, not the blob's embedded vault"
```

---

## Task 3: Role-assignment grant/revoke audit-logging blind spot

**Files:**
- Modify: `internal/services/authorization/role_assignment_service.go`
- Test: `internal/services/authorization/role_assignment_service_test.go`

**Interfaces:**
- Consumes: `s.log *logging.Logger` (existing field), `logging.Logger.LogAuditInfo(userID, operation, status, message string)` (existing, unchanged).
- Produces: no signature changes; `AssignRole`'s success path now logs `LogAuditInfo(in.CreatedBy.String(), "assign_role", "success", ...)`; `RevokeAssignment`'s success path now logs `LogAuditInfo("", "revoke_role_assignment", "success", ...)` (empty actor — `RevokeAssignment`'s signature carries no actor parameter today, matching the existing `""`-actor convention already used by `vault_service.go`'s `DeleteVault`/`RecoverVault`/`PurgeVault`; do not widen `RevokeAssignment`'s signature in this task).

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/authorization/role_assignment_service_test.go`:

```go
type recordingAuditPersister struct {
	mu      sync.Mutex
	records []auditRecord
}

type auditRecord struct {
	userID  string
	action  string
	details string
}

func (p *recordingAuditPersister) PersistAudit(userID, action, details string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, auditRecord{userID, action, details})
	return nil
}

func (p *recordingAuditPersister) find(action, status string) (auditRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rec := range p.records {
		if rec.action == action && strings.Contains(rec.details, "status="+status) {
			return rec, true
		}
	}
	return auditRecord{}, false
}

func newAuditingSvc(rr *fakeRoleRepo, pr *fakePolicyRepo, ul *fakeUserLookup) (RoleAssignmentService, *recordingAuditPersister) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	logger := logging.WrapLogrus(l)
	persister := &recordingAuditPersister{}
	logger.SetAuditPersister(persister)
	return NewRoleAssignmentService(rr, pr, ul, logger), persister
}

func TestAssignRole_LogsSuccessAudit(t *testing.T) {
	rr, pr, ul := newFakeRepos()
	svc, audit := newAuditingSvc(rr, pr, ul)
	createdBy := uuid.New()

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: createdBy,
	})
	require.NoError(t, err)

	rec, ok := audit.find("assign_role", "success")
	require.True(t, ok, "AssignRole must emit a success audit row")
	assert.Equal(t, createdBy.String(), rec.userID)
}

func TestRevokeAssignment_LogsSuccessAudit(t *testing.T) {
	rr, pr, ul := newFakeRepos()
	svc, audit := newAuditingSvc(rr, pr, ul)
	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsUser, VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	require.NoError(t, err)

	require.NoError(t, svc.RevokeAssignment(context.Background(), ra.ID, ra.VaultID))

	_, ok := audit.find("revoke_role_assignment", "success")
	require.True(t, ok, "RevokeAssignment must emit a success audit row")
}
```

Check the existing test file for its actual repo-construction helper name (it may already be called something other than `newFakeRepos` — use whatever the file's existing tests use to build `fakeRoleRepo`/`fakePolicyRepo`/`fakeUserLookup`, e.g. inline construction matching `TestAssignRole_HappyPath`). Add `"strings"`, `"sync"`, `"github.com/sirupsen/logrus"`, and `"rocketvault/internal/logging"` to the test file's imports if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/authorization/... -run 'TestAssignRole_LogsSuccessAudit|TestRevokeAssignment_LogsSuccessAudit' -v`
Expected: FAIL — `audit.find(...)` returns `ok=false` for both, since neither method logs a success-path audit row today.

- [ ] **Step 3: Add the success-path audit calls in `role_assignment_service.go`**

In `AssignRole`, change the final `return ra, nil` (end of the method, after the policy-expansion loop) to:

```go
	if s.log != nil {
		s.log.LogAuditInfo(in.CreatedBy.String(), "assign_role", "success",
			fmt.Sprintf("Role %q assigned to principal %s in vault %s", in.Role, principalID, in.VaultID))
	}
	return ra, nil
```

In `RevokeAssignment`, change the final `return nil` to:

```go
	if s.log != nil {
		s.log.LogAuditInfo("", "revoke_role_assignment", "success",
			fmt.Sprintf("Role assignment %s (role %q) revoked in vault %s", assignmentID, ra.Role, vaultID))
	}
	return nil
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/authorization/... -v`
Expected: PASS, including all pre-existing tests in the package (the `if s.log != nil` guard keeps every test that passes `nil` for the logger — the current `newSvc` helper — working unchanged).

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/role_assignment_service.go internal/services/authorization/role_assignment_service_test.go
git commit -m "fix(authz): audit-log role assignment grant and revoke on success"
```

---

## Task 4: Recover/Purge success-path audit logging for secrets, keys, certificates

**Files:**
- Modify: `internal/services/secrets/secret_service.go`
- Modify: `internal/services/keys/key_service.go`
- Modify: `internal/services/certificates/certificate_service.go`
- Test: `internal/services/secrets/secret_scope_service_test.go`
- Test: `internal/services/keys/key_soft_delete_test.go`
- Test: `internal/services/certificates/cert_soft_delete_test.go`

**Interfaces:**
- Consumes: `s.logger.LogAuditInfo(userID, operation, status, message string)` (existing, unchanged) on all three services; `scope.ActorID() uuid.UUID` (`model/scope.go:65`, unchanged).
- Produces: no signature changes to any of the six methods; each now logs a success-path audit row using the same `operation` string its own failure branch already uses (`"recover_secret"`, `"purge_secret"`, `"recover_key"`, `"purge_key"`, `"recover_certificate"`, `"purge_certificate"`).

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/secrets/secret_scope_service_test.go` (reusing whatever mock-audit-persister pattern the file already has available, or adding the `recordingAuditPersister` shape shown in Task 3 if the package doesn't already have one — check `internal/services/secrets/direct_write_invalidation_test.go` first, which already defines `recordingAuditPersister`/`newAuditingLogger` in this package; reuse it rather than duplicating):

```go
func TestRecoverSecret_LogsSuccessAudit(t *testing.T) {
	logger, audit := newAuditingLogger(t)
	repo := newMockSecretRepoForScopeTests() // use this file's existing repo-mock constructor
	svc := NewSecretService(SecretServiceConfig{SecretRepository: repo, CryptoService: fakeCrypto, VersionService: fakeVersions, TagService: fakeTags, Logger: logger})

	owner := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, owner)
	secretID := uuid.New()
	// stub repo.List(OnlyDeleted) to include secretID, per this file's existing purge/recover tests

	require.NoError(t, svc.RecoverSecret(context.Background(), secretID, scope))

	rec, ok := audit.find("recover_secret", "success")
	require.True(t, ok, "RecoverSecret must emit a success audit row")
	assert.Equal(t, owner.String(), rec.userID)
}

func TestPurgeSecret_LogsSuccessAudit(t *testing.T) {
	// same shape as above, calling svc.PurgeSecret and asserting
	// audit.find("purge_secret", "success") is true.
}
```

Write the equivalent `TestRecoverKey_LogsSuccessAudit`/`TestPurgeKey_LogsSuccessAudit` in `internal/services/keys/key_soft_delete_test.go` (this file already has `TestPurgeKey_PurgesWhenInScope` at line 277 to model the mock-repo setup from) and `TestRecoverCertificate_LogsSuccessAudit`/`TestPurgeCertificate_LogsSuccessAudit` in `internal/services/certificates/cert_soft_delete_test.go` (model from `TestPurgeCertificate_PurgesWhenInScope` at line 370), each using that package's own logger+audit-persister wiring (add a local `recordingAuditPersister`/`newAuditingLogger` pair to each test file if the package doesn't already define one — keep it non-exported, file-local, matching the secrets package's existing helper).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/secrets/... ./internal/services/keys/... ./internal/services/certificates/... -run 'LogsSuccessAudit' -v`
Expected: FAIL for all six new tests — `audit.find(...)` returns `ok=false`.

- [ ] **Step 3: Add the success-path audit calls**

In `internal/services/secrets/secret_service.go`, `RecoverSecret` (ends `return nil` after `s.secretRepo.RecoverSecret(ctx, secretID)` succeeds):

```go
	s.logger.LogAuditInfo(scope.ActorID().String(), "recover_secret", "success",
		fmt.Sprintf("Secret recovered: %s", secretID))
	return nil
```

`PurgeSecret` (ends `return nil` after `s.secretRepo.PurgeSecret(ctx, secretID)` succeeds):

```go
	s.logger.LogAuditInfo(scope.ActorID().String(), "purge_secret", "success",
		fmt.Sprintf("Secret purged: %s", secretID))
	return nil
```

In `internal/services/keys/key_service.go`, `RecoverKey`:

```go
	s.logger.LogAuditInfo(scope.ActorID().String(), "recover_key", "success",
		fmt.Sprintf("Key recovered: %s", keyID))
	return nil
```

`PurgeKey`:

```go
	s.logger.LogAuditInfo(scope.ActorID().String(), "purge_key", "success",
		fmt.Sprintf("Key purged: %s", keyID))
	return nil
```

In `internal/services/certificates/certificate_service.go`, `RecoverCertificate`:

```go
	s.logger.LogAuditInfo(scope.ActorID().String(), "recover_certificate", "success",
		fmt.Sprintf("Certificate recovered: %s", certID))
	return nil
```

`PurgeCertificate`:

```go
	s.logger.LogAuditInfo(scope.ActorID().String(), "purge_certificate", "success",
		fmt.Sprintf("Certificate purged: %s", certID))
	return nil
```

None of these three services guard `LogAuditInfo` with a `s.logger != nil` check anywhere else in their files (unlike `vault_service.go`), so match that existing convention here too — no nil-guard.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/secrets/... ./internal/services/keys/... ./internal/services/certificates/... -v`
Expected: PASS, all six new tests plus every pre-existing test in the three packages.

- [ ] **Step 5: Commit**

```bash
git add internal/services/secrets/secret_service.go internal/services/keys/key_service.go internal/services/certificates/certificate_service.go \
        internal/services/secrets/secret_scope_service_test.go internal/services/keys/key_soft_delete_test.go internal/services/certificates/cert_soft_delete_test.go
git commit -m "fix(audit): log recover/purge success for secrets, keys, and certificates"
```

---

## Task 5: SOC2 report auth-outcome miscounting

**Files:**
- Modify: `internal/services/auth/authentication_service.go`
- Modify: `internal/container/service_container.go`
- Test: `internal/services/auth/authentication_service_test.go` (or wherever `AuthenticateUser` is currently unit-tested — locate via `grep -rl AuthenticateUser internal/services/auth/*_test.go` before writing; add to that file)
- Test: `internal/services/audit/compliance_report_service_test.go`

**Interfaces:**
- Consumes: `auditServices.AuditServiceInterface.RecordEvent(ctx, AuditEvent) error` (`internal/services/audit/audit_service.go:31-34`, unchanged); `AuditEvent{UserID, Action, Details, ResourceType, ResourceID, IPAddress, Outcome, Source string}` (unchanged).
- Produces: `authServices.AuthenticationConfig` gains a new field `AuditService auditServices.AuditServiceInterface` (optional — nil-safe, mirroring how `Logger` is already used unguarded but tests may omit it). `authenticationService` gains an unexported `auditService auditServices.AuditServiceInterface` field. No public method signatures change.

- [ ] **Step 1: Write the failing tests**

In `internal/services/audit/compliance_report_service_test.go`, add a test that exercises the real write path instead of seeding rows directly:

```go
func TestComplianceReportService_SOC2Report_CountsRealAuthenticateUserOutcomes(t *testing.T) {
	db := openTestDB(t)
	repo := repositories.NewAuditRepository(rvdb.NewConn(db, rvdb.SQLite))
	auditSvc := NewAuditService(repo)

	require.NoError(t, auditSvc.RecordEvent(context.Background(), AuditEvent{
		UserID: "u1", Action: "authenticate_user", Outcome: "success", Source: "system", ResourceType: "user",
	}))
	require.NoError(t, auditSvc.RecordEvent(context.Background(), AuditEvent{
		UserID: "u2", Action: "authenticate_user", Outcome: "failure", Source: "system", ResourceType: "user",
	}))

	reportSvc := NewComplianceReportService(repo)
	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)
	report, err := reportSvc.GenerateSOC2Report(context.Background(), from, to)
	require.NoError(t, err)

	assert.Equal(t, int64(1), report.AuthSuccesses)
	assert.Equal(t, int64(1), report.AuthFailures)
}
```

(This test alone doesn't fail today — `RecordEvent` called directly already populates `Outcome`. It documents the correct end state. The real regression test is the one below, exercising `AuthenticateUser` itself.)

In `internal/services/auth/authentication_service_test.go` (first run `grep -n "func Test" internal/services/auth/authentication_service_test.go | head -5` to confirm this is the right file and see its existing mock-repo setup to reuse), add:

```go
func TestAuthenticateUser_RecordsRichAuditOutcomeOnSuccessAndFailure(t *testing.T) {
	// Reuse this file's existing mock UserRepository/SessionRepository/
	// PasswordService/TOTPService/JWTService setup for a happy-path login.
	auditRepo := repositories.NewAuditRepository(openTestAuditDB(t)) // or this package's existing in-memory test DB helper
	auditSvc := auditServices.NewAuditService(auditRepo)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    mockUserRepo,
		SessionRepository: mockSessionRepo,
		PasswordService:   mockPasswordSvc,
		TOTPService:       mockTOTPSvc,
		JWTService:        mockJWTSvc,
		Logger:            logging.WrapLogrus(logrus.New()),
		AuditService:      auditSvc,
	})

	_, err := svc.AuthenticateUser(context.Background(), "gooduser", "goodpass", "123456")
	require.NoError(t, err)

	logs, _, err := auditRepo.QueryAuditLogs(context.Background(), repositories.AuditFilter{Limit: 10})
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	assert.Equal(t, "success", logs[len(logs)-1].Outcome, "a real successful login must persist Outcome=success, not NULL")

	_, err = svc.AuthenticateUser(context.Background(), "gooduser", "wrongpass", "123456")
	require.Error(t, err)

	logs, _, err = auditRepo.QueryAuditLogs(context.Background(), repositories.AuditFilter{Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, "failure", logs[len(logs)-1].Outcome, "a real failed login must persist Outcome=failure, not NULL")
}
```

Adapt the mock construction to whatever this test file's existing happy-path test (e.g. `TestAuthenticateUser_Success` or similar — locate it first) already builds; do not invent a new mock shape.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/auth/... -run TestAuthenticateUser_RecordsRichAuditOutcomeOnSuccessAndFailure -v`
Expected: FAIL — `logs[len(logs)-1].Outcome` is `""`, not `"success"`/`"failure"`, and/or a compile error since `AuthenticationConfig` doesn't yet have an `AuditService` field.

- [ ] **Step 3: Add `AuditService` to `AuthenticationConfig`/`authenticationService`**

In `internal/services/auth/authentication_service.go`, add the import `auditServices "rocketvault/internal/services/audit"`, then:

```go
type authenticationService struct {
	userRepo         repositories.UserRepositoryInterface
	sessionRepo      repositories.SessionRepositoryInterface
	passwordService  PasswordService
	totpService      TOTPService
	jwtService       JWTService
	oauth2ClientRepo repositories.OAuth2ClientRepositoryInterface
	logger           *logging.Logger
	auditService     auditServices.AuditServiceInterface
}

type AuthenticationConfig struct {
	UserRepository         repositories.UserRepositoryInterface
	SessionRepository      repositories.SessionRepositoryInterface
	PasswordService        PasswordService
	TOTPService            TOTPService
	JWTService             JWTService
	OAuth2ClientRepository repositories.OAuth2ClientRepositoryInterface
	Logger                 *logging.Logger
	AuditService           auditServices.AuditServiceInterface
}
```

Update `NewAuthenticationService` to set `auditService: config.AuditService`.

- [ ] **Step 4: Route `AuthenticateUser`'s four failure branches through `RecordEvent`**

Replace each of the four `s.logger.LogAuditError(...)` calls in `AuthenticateUser` with a `RecordEvent` call, guarded for nil since tests may omit `AuditService`. E.g. the "user not found" branch:

```go
	user, err := s.userRepo.ReadByUsername(ctx, username)
	if err != nil {
		if s.auditService != nil {
			_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
				Action: "authenticate_user", Outcome: "failure", Source: "system",
				ResourceType: "user", Details: "user not found",
			})
		}
		s.logger.WithField("username", username).Warn("Authentication failed: user not found")
		return nil, fmt.Errorf("invalid credentials")
	}
```

Apply the same shape to the "invalid password", "TOTP validation error", and "invalid TOTP code" branches, each with `UserID: user.ID.String()` added (the first branch has no `user` yet) and `Details` matching the existing message string. Remove the now-redundant `s.logger.LogAuditError(...)` call from each of these four branches (keep every `s.logger.With...Warn/Error(...)` operational-logging call unchanged).

- [ ] **Step 5: Route `issueSession`'s success log through `RecordEvent`**

Replace the line `s.logger.LogAuditInfo(user.ID.String(), auditAction, "success", "Session issued successfully")` in `issueSession` with:

```go
	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, auditServices.AuditEvent{
			UserID: user.ID.String(), Action: auditAction, Outcome: "success",
			Source: "system", ResourceType: "user", ResourceID: user.ID.String(),
		})
	} else {
		s.logger.LogAuditInfo(user.ID.String(), auditAction, "success", "Session issued successfully")
	}
```

This covers both `AuthenticateUser`'s `"authenticate_user"` action and `IssueSessionForUser`'s `"issue_session_for_user"` action (used by the OIDC login path), fixing both consistently since they share this one method.

- [ ] **Step 6: Wire `AuditService` in the container**

In `internal/container/service_container.go`, in the `baseAuthService := authServices.NewAuthenticationService(...)` call (around line 367), add:

```go
		AuditService:           c.auditService,
```

`c.auditService` is already constructed at line 295, before this call — no reordering needed.

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/services/auth/... ./internal/services/audit/... ./internal/container/... -v`
Expected: PASS. Also run `go build ./...` to confirm the container wiring compiles.

- [ ] **Step 8: Commit**

```bash
git add internal/services/auth/authentication_service.go internal/container/service_container.go \
        internal/services/auth/authentication_service_test.go internal/services/audit/compliance_report_service_test.go
git commit -m "fix(audit): record real authenticate_user outcomes so SOC2 auth counters aren't silently wrong"
```

---

## Task 6: Data Access Administrator role-grant restriction

**Files:**
- Modify: `internal/services/authorization/role_assignment_service.go`
- Modify: `api/role_assignments.go`
- Modify: `cmd/vault-access/grant.go`
- Test: `internal/services/authorization/role_assignment_service_test.go`

**Interfaces:**
- Produces: `AssignRoleInput` gains a new field `CallerIsGlobalAdmin bool`. New sentinel `ErrRoleNotGrantable = errors.New("role cannot be granted by a non-admin caller")` in `internal/services/authorization/role_assignment_service.go`. Both HTTP and CLI callers must set `CallerIsGlobalAdmin` from the same `common.HasRequiredRole(accountRole, string(model.RoleAdmin))` check `CanManageRoleAssignments` already performs internally.

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/authorization/role_assignment_service_test.go`:

```go
func TestAssignRole_NonAdminCannotGrantDataAccessAdministrator(t *testing.T) {
	rr, pr, ul := newFakeRepos()
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultDataAccessAdministrator, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: false,
	})
	require.ErrorIs(t, err, ErrRoleNotGrantable)
}

func TestAssignRole_NonAdminCannotGrantPurgeOperator(t *testing.T) {
	rr, pr, ul := newFakeRepos()
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultPurgeOperator, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: false,
	})
	require.ErrorIs(t, err, ErrRoleNotGrantable)
}

func TestAssignRole_NonAdminCannotGrantCertificateUser(t *testing.T) {
	rr, pr, ul := newFakeRepos()
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultCertificateUser, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: false,
	})
	require.ErrorIs(t, err, ErrRoleNotGrantable)
}

func TestAssignRole_NonAdminCanGrantOrdinaryRole(t *testing.T) {
	rr, pr, ul := newFakeRepos()
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultSecretsOfficer, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: false,
	})
	require.NoError(t, err)
}

func TestAssignRole_GlobalAdminCanGrantAnyRole(t *testing.T) {
	rr, pr, ul := newFakeRepos()
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: model.RoleKeyVaultDataAccessAdministrator, VaultID: uuid.New(), CreatedBy: uuid.New(),
		CallerIsGlobalAdmin: true,
	})
	require.NoError(t, err)
}
```

(Use whatever this file's actual repo-construction helper is named — see Task 3, Step 1's note; the existing `TestAssignRole_HappyPath` at line 100 shows the exact pattern.) Note `TestAssignRole_HappyPath` and every other pre-existing `AssignRole` test in this file constructs `AssignRoleInput` without `CallerIsGlobalAdmin` — its Go zero value is `false`. Check whether any pre-existing test grants `RoleKeyVaultDataAccessAdministrator`, `RoleKeyVaultPurgeOperator`, or `RoleKeyVaultCertificateUser` without setting `CallerIsGlobalAdmin: true`; if so, add `CallerIsGlobalAdmin: true` to that test's input in this step (not a separate task) so it keeps passing after Step 3.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/authorization/... -run TestAssignRole_ -v`
Expected: FAIL — compile error (`CallerIsGlobalAdmin` field and `ErrRoleNotGrantable` don't exist yet), or once added, the three restriction tests fail because nothing rejects the grant.

- [ ] **Step 3: Implement the restriction in `role_assignment_service.go`**

Add the sentinel next to the existing ones:

```go
var (
	ErrInvalidRole        = errors.New("invalid role")
	ErrPrincipalNotFound  = errors.New("principal not found")
	ErrAssignmentNotFound = errors.New("role assignment not found")
	// ErrRoleNotGrantable is returned when a non-global-admin caller attempts
	// to grant a role outside the allow-list a Key Vault Data Access
	// Administrator may assign — mirroring Azure's ABAC restriction that bars
	// Data Access Administrator from granting itself, Purge Operator, or
	// Certificate User.
	ErrRoleNotGrantable = errors.New("role cannot be granted by a non-admin caller")
)

// nonAdminGrantableRoles is the allow-list of roles a non-global-admin caller
// (i.e. one whose authority to manage role assignments comes from holding
// Key Vault Data Access Administrator, not the admin bypass) may grant or
// revoke. It deliberately excludes RoleKeyVaultDataAccessAdministrator itself,
// RoleKeyVaultPurgeOperator, and RoleKeyVaultCertificateUser.
var nonAdminGrantableRoles = map[string]bool{
	model.RoleKeyVaultAdministrator:               true,
	model.RoleKeyVaultReader:                      true,
	model.RoleKeyVaultSecretsUser:                 true,
	model.RoleKeyVaultSecretsOfficer:               true,
	model.RoleKeyVaultCryptoUser:                  true,
	model.RoleKeyVaultCryptoOfficer:                true,
	model.RoleKeyVaultCertificatesOfficer:          true,
	model.RoleKeyVaultCryptoServiceEncryptionUser:  true,
}
```

Add the field to `AssignRoleInput`:

```go
type AssignRoleInput struct {
	Principal           string
	PrincipalType       model.PrincipalType
	Role                string
	VaultID             uuid.UUID
	CreatedBy           uuid.UUID
	// CallerIsGlobalAdmin is true when the caller's authority to manage role
	// assignments comes from the global admin role, not from holding Key
	// Vault Data Access Administrator in this vault. Set by the caller (HTTP
	// handler or CLI command) from the same check CanManageRoleAssignments
	// already performs, since AssignRole itself has no access to the
	// account-role/session context.
	CallerIsGlobalAdmin bool
}
```

In `AssignRole`, add the check right after the `IsLegacyRole` check (before `resolvePrincipal`):

```go
	if !in.CallerIsGlobalAdmin && !nonAdminGrantableRoles[in.Role] {
		return nil, fmt.Errorf("%w: %q may only be granted by a global admin", ErrRoleNotGrantable, in.Role)
	}
```

- [ ] **Step 4: Wire `CallerIsGlobalAdmin` at both call sites**

In `api/role_assignments.go`'s `createRoleAssignment`, add the import `"rocketvault/common"` if not already present, and after the existing `role, callerID, ok := callerIdentity(c)` line, compute:

```go
	isGlobalAdmin := common.HasRequiredRole(role, string(model.RoleAdmin))
```

then add `CallerIsGlobalAdmin: isGlobalAdmin,` to the `authzServices.AssignRoleInput{...}` literal a few lines below.

In `cmd/vault-access/grant.go`, add the import `"rocketvault/common"` if not already present. The command already has `ctx` and needs the caller's account role — read it the same way `cmd/vaults/authz.go`'s `callerIdentity` does: `claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)`. Add before the `sc.GetRoleAssignmentService().AssignRole(...)` call:

```go
			claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
			if !ok {
				return fmt.Errorf("unauthorized: missing authentication claims")
			}
			isGlobalAdmin := common.HasRequiredRole(claims.Role, string(model.RoleAdmin))
```

then add `CallerIsGlobalAdmin: isGlobalAdmin,` to the `authz.AssignRoleInput{...}` literal.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/services/authorization/... ./api/... ./cmd/vault-access/... -v`
Expected: PASS.

- [ ] **Step 6: Run the full build**

Run: `go build ./...`
Expected: clean build (confirms `model.RoleKeyVault*` constant names used in `nonAdminGrantableRoles` are exact).

- [ ] **Step 7: Commit**

```bash
git add internal/services/authorization/role_assignment_service.go api/role_assignments.go cmd/vault-access/grant.go internal/services/authorization/role_assignment_service_test.go
git commit -m "fix(authz): restrict which roles a non-admin caller may grant, matching Azure's Data Access Administrator ABAC restriction"
```

---

## Task 7: Purge protection — secrets

**Files:**
- Create: `internal/repositories/purge_protection_errors.go`
- Modify: `internal/repositories/secret_repository.go`
- Modify: `internal/services/secrets/secret_service.go`
- Modify: `model/secret.go`
- Modify: `api/secrets.go`
- Modify: `api/errors_secret.go`
- Modify: `cmd/secrets/create.go`
- Modify: `cmd/secrets/update.go`
- Modify: `internal/container/service_container.go`
- Test: `internal/repositories/missing_coverage_test.go`
- Test: `internal/services/secrets/secret_scope_service_test.go`
- Test: `api/soft_delete_extended_test.go`

**Interfaces:**
- Produces: `repositories.ErrSecretPurgeProtected`, `ErrKeyPurgeProtected`, `ErrCertPurgeProtected` sentinels (all three defined now, used by this task for secrets and by Tasks 8/9 for keys/certs). `SecretRepositoryInterface` gains `SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error`. `secrets.CreateSecretRequest`/`UpdateSecretRequest` gain `PurgeProtection *bool`. `model.CreateSecretRequest`/`UpdateSecretRequest` (HTTP DTOs) gain `PurgeProtection *bool \`json:"purge_protection,omitempty"\``. `secretService` gains an optional `vaultRepo repositories.VaultRepositoryInterface` field via a new `SecretServiceConfig.VaultRepository` field.

- [ ] **Step 1: Write the failing repository test**

Add to `internal/repositories/missing_coverage_test.go` (near the existing `TestSecretRepository_PurgeSecret_PurgeProtection` at line 649):

```go
func TestSecretRepository_SetPurgeProtection(t *testing.T) {
	repo, db := newTestSecretRepo(t) // reuse this file's existing repo+db constructor
	secret := &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: uuid.New(), Name: "s1", Value: "v1", Version: 1, Enabled: true}
	require.NoError(t, repo.Create(context.Background(), secret))

	require.NoError(t, repo.SetPurgeProtection(context.Background(), secret.ID, true))

	require.NoError(t, repo.SoftDelete(context.Background(), secret.ID))
	err := repo.PurgeSecret(context.Background(), secret.ID)
	require.ErrorIs(t, err, repositories.ErrSecretPurgeProtected)
}
```

(Adjust `newTestSecretRepo`/import alias to match this file's actual existing helpers — check the file's other tests, e.g. `TestSecretRepository_PurgeSecret` at line 606, for the exact construction pattern before writing this.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestSecretRepository_SetPurgeProtection -v`
Expected: FAIL — compile error, `SecretRepository`/`SecretRepositoryInterface` has no `SetPurgeProtection` method.

- [ ] **Step 3: Create the shared sentinel-errors file**

`internal/repositories/purge_protection_errors.go`:

```go
package repositories

import "errors"

// ErrSecretPurgeProtected is returned when PurgeSecret refuses to act because
// the secret itself, or the vault containing it, has purge protection
// enabled.
var ErrSecretPurgeProtected = errors.New("secret has purge protection enabled")

// ErrKeyPurgeProtected is returned when PurgeKey refuses to act because the
// key itself, or the vault containing it, has purge protection enabled.
var ErrKeyPurgeProtected = errors.New("key has purge protection enabled")

// ErrCertPurgeProtected is returned when PurgeCertificate refuses to act
// because the certificate itself, or the vault containing it, has purge
// protection enabled.
var ErrCertPurgeProtected = errors.New("certificate has purge protection enabled")
```

- [ ] **Step 4: Add `SetPurgeProtection` to the secret repository**

In `internal/repositories/secret_repository.go`, add to `SecretRepositoryInterface` (after `PurgeSecret`):

```go
	// SetPurgeProtection enables or disables purge protection on a secret.
	SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
```

Add the implementation (mirroring `KeyRepository.SetPurgeProtection` at `internal/repositories/key_repository.go:646`), after `PurgeSecret`'s closing brace:

```go
// SetPurgeProtection enables or disables purge protection on a secret.
//
// Parameters:
//   - id: The secret's unique identifier.
//   - enabled: True to enable purge protection, false to disable it.
//
// Returns:
//
//	An error if the update fails.
func (r *SecretRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	result, err := r.db.ExecContext(ctx, "UPDATE secrets SET purge_protection = ? WHERE id = ?", enabled, id.String())
	if err != nil {
		r.log.LogAuditError("", "set_purge_protection_secret", "failed", "Failed to set purge protection", err)
		return fmt.Errorf("failed to set purge protection: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError("", "set_purge_protection_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError("", "set_purge_protection_secret", "failed", "Secret not found", nil)
		return fmt.Errorf("secret not found")
	}
	r.log.LogAuditInfo("", "set_purge_protection_secret", "success", fmt.Sprintf("Secret purge protection set to %v", enabled))
	return nil
}
```

- [ ] **Step 5: Change `PurgeSecret`'s protection check to return the sentinel**

In `PurgeSecret` (`internal/repositories/secret_repository.go:453-456`), change:

```go
	if purgeProtection {
		r.log.LogAuditError("", "purge_secret", "failed", "Secret has purge protection enabled", nil)
		return fmt.Errorf("secret has purge protection enabled")
	}
```

to:

```go
	if purgeProtection {
		r.log.LogAuditError("", "purge_secret", "failed", "Secret has purge protection enabled", nil)
		return ErrSecretPurgeProtected
	}
```

- [ ] **Step 6: Run the repository test to verify it passes**

Run: `go test ./internal/repositories/... -run TestSecretRepository_SetPurgeProtection -v`
Expected: PASS.

- [ ] **Step 7: Write the failing service-layer tests**

Add to `internal/services/secrets/secret_scope_service_test.go`:

```go
func TestCreateSecret_SetsPurgeProtectionWhenRequested(t *testing.T) {
	repo := newMockSecretRepoForScopeTests() // reuse this file's existing mock
	repo.On("SetPurgeProtection", mock.Anything, mock.AnythingOfType("uuid.UUID"), true).Return(nil)
	svc := NewSecretService(SecretServiceConfig{SecretRepository: repo, CryptoService: fakeCrypto, VersionService: fakeVersions, TagService: fakeTags, Logger: nopLogger})

	protect := true
	_, err := svc.CreateSecret(context.Background(), CreateSecretRequest{
		UserID: uuid.New(), Name: "s1", Value: "v1", PurgeProtection: &protect,
	})
	require.NoError(t, err)
	repo.AssertCalled(t, "SetPurgeProtection", mock.Anything, mock.AnythingOfType("uuid.UUID"), true)
}

func TestPurgeSecret_BlockedWhenVaultIsPurgeProtected(t *testing.T) {
	repo := newMockSecretRepoForScopeTests()
	vaultRepo := &mockVaultRepo{}
	vaultID := uuid.New()
	secretID := uuid.New()
	owner := uuid.New()
	scope := model.NewVaultScope(vaultID, owner)

	repo.On("List", mock.Anything, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, VaultID: vaultID}}, nil)
	vaultRepo.On("ReadByID", mock.Anything, vaultID).Return(&model.Vault{ID: vaultID, PurgeProtection: true}, nil)

	svc := NewSecretService(SecretServiceConfig{SecretRepository: repo, CryptoService: fakeCrypto, VersionService: fakeVersions, TagService: fakeTags, Logger: nopLogger, VaultRepository: vaultRepo})

	err := svc.PurgeSecret(context.Background(), secretID, scope)
	require.ErrorIs(t, err, repositories.ErrSecretPurgeProtected)
	repo.AssertNotCalled(t, "PurgeSecret", mock.Anything, mock.Anything)
}
```

Add a minimal `mockVaultRepo` implementing `repositories.VaultRepositoryInterface`'s `ReadByID` (via testify `mock.Mock`) to this test file, or to a shared test-helpers file in the package if one already exists — check for an existing `mockVaultRepo`/similar in `internal/services/secrets/*_test.go` first and reuse it if present.

- [ ] **Step 8: Run tests to verify they fail**

Run: `go test ./internal/services/secrets/... -run 'TestCreateSecret_SetsPurgeProtectionWhenRequested|TestPurgeSecret_BlockedWhenVaultIsPurgeProtected' -v`
Expected: FAIL — compile errors (`PurgeProtection` field and `VaultRepository` config field don't exist yet).

- [ ] **Step 9: Add `PurgeProtection` to the service DTOs and wire creation/update**

In `internal/services/secrets/secret_service.go`, add `PurgeProtection *bool // Optional; nil means leave default (false) unset.` to both `CreateSecretRequest` and `UpdateSecretRequest`.

Add `VaultRepository repositories.VaultRepositoryInterface` to `SecretServiceConfig` and `vaultRepo repositories.VaultRepositoryInterface` to the `secretService` struct; wire it in `NewSecretService`.

In `CreateSecret`, after the existing `if err = s.secretRepo.Create(ctx, secret); err != nil { ... }` block succeeds (before `secret.Value = req.Value`), add:

```go
	if req.PurgeProtection != nil && *req.PurgeProtection {
		if err := s.secretRepo.SetPurgeProtection(ctx, secret.ID, true); err != nil {
			return nil, fmt.Errorf("failed to set purge protection: %w", err)
		}
	}
```

In `UpdateSecret`, find where the updated secret is persisted (`s.secretRepo.Update(ctx, ...)`) and, after it succeeds, add:

```go
	if req.PurgeProtection != nil {
		if err := s.secretRepo.SetPurgeProtection(ctx, req.SecretID, *req.PurgeProtection); err != nil {
			return fmt.Errorf("failed to set purge protection: %w", err)
		}
	}
```

(Match the exact surrounding control flow of `UpdateSecret`, which this task's research did not fully transcribe — read the method first with `sed -n` before inserting, placing this block after the `s.secretRepo.Update` call succeeds and before the final success audit log/return.)

- [ ] **Step 10: Add the vault-level cascade check to `PurgeSecret`**

In `PurgeSecret`, after the `if !inScope { ... }` block and before `if err := s.secretRepo.PurgeSecret(ctx, secretID); err != nil {`, add:

```go
	if s.vaultRepo != nil && scope.VaultID() != uuid.Nil {
		vault, err := s.vaultRepo.ReadByID(ctx, scope.VaultID())
		if err == nil && vault.PurgeProtection {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_secret", "failed",
				"Vault has purge protection enabled", nil)
			return repositories.ErrSecretPurgeProtected
		}
	}
```

- [ ] **Step 11: Run the service tests to verify they pass**

Run: `go test ./internal/services/secrets/... -v`
Expected: PASS.

- [ ] **Step 12: Wire `VaultRepository` in the container**

In `internal/container/service_container.go`, in the `secretServices.NewSecretService(secretServices.SecretServiceConfig{...})` call (around line 486), add `VaultRepository: c.vaultRepository,`. `c.vaultRepository` is already constructed at line 282, before this call.

- [ ] **Step 13: Add `PurgeProtection` to the HTTP DTOs and API error mapping**

In `model/secret.go`, add `PurgeProtection *bool \`json:"purge_protection,omitempty"\`` to both `CreateSecretRequest` and `UpdateSecretRequest`.

In `api/secrets.go`'s `createSecret`, add `PurgeProtection: req.PurgeProtection,` to the `secrets.CreateSecretRequest{...}` literal. In `updateSecret`, add `PurgeProtection: req.PurgeProtection,` to the `secrets.UpdateSecretRequest{...}` literal.

In `api/errors_secret.go`, add a case to `writeSecretError` (before `default:`):

```go
	case errors.Is(err, repositories.ErrSecretPurgeProtected):
		c.SetPermissionError("secret has purge protection enabled")
```

Add the import `"rocketvault/internal/repositories"` to `api/errors_secret.go`.

- [ ] **Step 14: Add the CLI flag**

In `cmd/secrets/create.go`, add to the `secretsServices.CreateSecretRequest{...}` literal's construction: after building `req`, add:

```go
		if cmd.Flags().Changed("purge-protection") {
			pp, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &pp
		}
```

and in `InitSecretsCreate`, add `createCmd.Flags().Bool("purge-protection", false, "Protect the secret from being purged")`.

In `cmd/secrets/update.go`, add the equivalent block before `sc.GetSecretService().UpdateSecret(ctx, req)`:

```go
		if cmd.Flags().Changed("purge-protection") {
			pp, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &pp
		}
```

and in `InitSecretsUpdate`, add `updateCmd.Flags().Bool("purge-protection", false, "Protect the secret from being purged")`.

- [ ] **Step 15: Add the API-level regression test**

Add to `api/soft_delete_extended_test.go`:

```go
func TestPurgeSecret_BlockedByRepoErrSecretPurgeProtected_Returns403(t *testing.T) {
	mockSvc := &mockSecretService{}
	mockSvc.On("PurgeSecret", mock.Anything, mock.Anything, mock.Anything).Return(repositories.ErrSecretPurgeProtected)
	// ... reuse this file's existing request/response harness (see
	// TestPurgeSecret_NotFound_Returns404 immediately above) to POST the
	// purge route and assert the response status is 403, not 500.
}
```

- [ ] **Step 16: Run the full affected test suite**

Run: `go test ./internal/repositories/... ./internal/services/secrets/... ./api/... ./cmd/secrets/... ./internal/container/... -v`
Expected: PASS. Also run `go build ./...`.

- [ ] **Step 17: Commit**

```bash
git add internal/repositories/purge_protection_errors.go internal/repositories/secret_repository.go \
        internal/services/secrets/secret_service.go model/secret.go api/secrets.go api/errors_secret.go \
        cmd/secrets/create.go cmd/secrets/update.go internal/container/service_container.go \
        internal/repositories/missing_coverage_test.go internal/services/secrets/secret_scope_service_test.go api/soft_delete_extended_test.go
git commit -m "fix(secrets): make purge protection settable and enforce vault-level cascade"
```

---

## Task 8: Purge protection — keys

**Files:**
- Modify: `internal/repositories/key_repository.go`
- Modify: `internal/services/keys/key_service.go`
- Modify: `model/key.go`
- Modify: `api/keys.go`
- Modify: `api/errors_key.go`
- Modify: `cmd/keys/create.go`
- Modify: `cmd/keys/update.go`
- Modify: `internal/container/service_container.go`
- Test: `internal/services/keys/key_soft_delete_test.go`
- Test: `api/soft_delete_extended_test.go`

**Interfaces:**
- Consumes: `repositories.ErrKeyPurgeProtected` (defined in Task 7, Step 3 — this task does not redefine it). `KeyRepositoryInterface.SetPurgeProtection` already exists (`internal/repositories/key_repository.go:40`) — this task does not add it, only wires it up.
- Produces: `keys.CreateKeyRequest`/`UpdateKeyRequest` gain `PurgeProtection *bool`. `model.CreateKeyRequest`/`UpdateKeyRequest` (model/key.go HTTP DTOs) and `api.CreateKeyRequest`/`UpdateKeyRequest` (api/keys.go local DTOs — the ones actually decoded from the request body) both gain `PurgeProtection *bool \`json:"purge_protection,omitempty"\``. `keyService` gains an optional `vaultRepo repositories.VaultRepositoryInterface` field via `KeyServiceConfig.VaultRepository`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/keys/key_soft_delete_test.go`:

```go
func TestCreateRSAKey_SetsPurgeProtectionWhenRequested(t *testing.T) {
	repo := newMockKeyRepo() // reuse this file's existing mock constructor
	repo.On("SetPurgeProtection", mock.Anything, mock.AnythingOfType("uuid.UUID"), true).Return(nil)
	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: fakeKeyProvider, Logger: nopLogger})

	protect := true
	_, err := svc.CreateRSAKey(context.Background(), CreateKeyRequest{
		UserID: uuid.New(), Name: "k1", Type: "RSA", Bits: 2048, PurgeProtection: &protect,
	})
	require.NoError(t, err)
	repo.AssertCalled(t, "SetPurgeProtection", mock.Anything, mock.AnythingOfType("uuid.UUID"), true)
}

func TestPurgeKey_BlockedWhenVaultIsPurgeProtected(t *testing.T) {
	repo := newMockKeyRepo()
	vaultRepo := &mockVaultRepo{}
	vaultID := uuid.New()
	keyID := uuid.New()
	owner := uuid.New()
	scope := model.NewVaultScope(vaultID, owner)

	repo.On("List", mock.Anything, scope, repositories.KeyFilter{OnlyDeleted: true}).
		Return([]model.Key{{ID: keyID, VaultID: vaultID}}, nil)
	vaultRepo.On("ReadByID", mock.Anything, vaultID).Return(&model.Vault{ID: vaultID, PurgeProtection: true}, nil)

	svc := NewKeyService(KeyServiceConfig{KeyRepository: repo, KeyProvider: fakeKeyProvider, Logger: nopLogger, VaultRepository: vaultRepo})

	err := svc.PurgeKey(context.Background(), keyID, scope)
	require.ErrorIs(t, err, repositories.ErrKeyPurgeProtected)
	repo.AssertNotCalled(t, "PurgeKey", mock.Anything, mock.Anything)
}
```

Add a `mockVaultRepo` to this package's test files if one isn't already present (mirror Task 7 Step 7's).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/keys/... -run 'TestCreateRSAKey_SetsPurgeProtectionWhenRequested|TestPurgeKey_BlockedWhenVaultIsPurgeProtected' -v`
Expected: FAIL — compile errors.

- [ ] **Step 3: Change `PurgeKey`'s repo-layer protection check to return the sentinel**

In `internal/repositories/key_repository.go`, change (`:607-610`):

```go
		if purgeProtection {
			r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Key has purge protection enabled", nil)
			return fmt.Errorf("key has purge protection enabled")
		}
```

to:

```go
		if purgeProtection {
			r.log.LogAuditError(uuid.Nil.String(), "purge_key", "failed", "Key has purge protection enabled", nil)
			return ErrKeyPurgeProtected
		}
```

- [ ] **Step 4: Add `PurgeProtection` to the service DTOs and wire creation/update**

In `internal/services/keys/key_service.go`, add `PurgeProtection *bool` to `CreateKeyRequest` and to `UpdateKeyRequest`.

Add `VaultRepository repositories.VaultRepositoryInterface` to `KeyServiceConfig` and `vaultRepo repositories.VaultRepositoryInterface` to the `keyService` struct; wire it in `NewKeyService`.

In each of `CreateRSAKey`, `CreateECDSAKey`, and `CreateOctKey` (all three build a `key := &model.Key{...}` then call `s.keyRepo.Create(ctx, key)`), after the `Create` call succeeds, add:

```go
	if req.PurgeProtection != nil && *req.PurgeProtection {
		if err := s.keyRepo.SetPurgeProtection(ctx, key.ID, true); err != nil {
			s.logger.LogAuditError(req.UserID.String(), "create_key", "failed", "failed to set purge protection", err)
			return nil, fmt.Errorf("failed to set purge protection: %w", err)
		}
	}
```

(Match each method's existing local variable name for the created key — confirmed `key` in `CreateRSAKey`; verify the exact variable name in `CreateECDSAKey`/`CreateOctKey` before inserting, since this task's research only fully transcribed `CreateRSAKey`.)

In `UpdateKey`, after `s.keyRepo.Update(ctx, updatedKey, req.Scope)` succeeds and before the cache-invalidation block, add:

```go
	if req.PurgeProtection != nil {
		if err := s.keyRepo.SetPurgeProtection(ctx, req.KeyID, *req.PurgeProtection); err != nil {
			s.logger.LogAuditError(actor, "update_key", "failed", "failed to set purge protection", err)
			return fmt.Errorf("failed to set purge protection: %w", err)
		}
	}
```

Also add `PurgeProtection *bool` to `UpdateKeyRequest`'s struct definition (near `Enabled *bool`).

- [ ] **Step 5: Add the vault-level cascade check to `PurgeKey`**

In `PurgeKey`, after the `if !inScope { ... }` block and before `if err := s.keyRepo.PurgeKey(ctx, keyID); err != nil {`, add:

```go
	if s.vaultRepo != nil && scope.VaultID() != uuid.Nil {
		vault, err := s.vaultRepo.ReadByID(ctx, scope.VaultID())
		if err == nil && vault.PurgeProtection {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_key", "failed",
				"Vault has purge protection enabled", nil)
			return repositories.ErrKeyPurgeProtected
		}
	}
```

- [ ] **Step 6: Run the service tests to verify they pass**

Run: `go test ./internal/services/keys/... -v`
Expected: PASS.

- [ ] **Step 7: Wire `VaultRepository` in the container**

In `internal/container/service_container.go`, in the `keyServices.NewKeyService(keyServices.KeyServiceConfig{...})` call (around line 536), add `VaultRepository: c.vaultRepository,`.

- [ ] **Step 8: Add `PurgeProtection` to the HTTP DTOs and API error mapping**

In `model/key.go`, add `PurgeProtection *bool \`json:"purge_protection,omitempty"\`` to `CreateKeyRequest` and `UpdateKeyRequest`.

In `api/keys.go`, add the same field to the local `CreateKeyRequest` and `UpdateKeyRequest` structs (the ones actually decoded from the HTTP body — see file header comment). In `createKey`, add `PurgeProtection: req.PurgeProtection,` to the `keyservices.CreateKeyRequest{...}` literal. In `updateKey`, first extend the "at least one field" guard:

```go
	if req.Name == nil && req.Revoked == nil && req.Tags == nil && req.Enabled == nil && req.ExpiresAt == nil && req.NotBefore == nil && req.PurgeProtection == nil {
```

then add `PurgeProtection: req.PurgeProtection,` to the `keyservices.UpdateKeyRequest{...}` literal.

In `api/errors_key.go`, add before `default:`:

```go
	case errors.Is(err, repositories.ErrKeyPurgeProtected):
		c.SetPermissionError("key has purge protection enabled")
```

- [ ] **Step 9: Add the CLI flag**

In `cmd/keys/create.go` and `cmd/keys/update.go`, add the identical `Changed("purge-protection")`-gated block shown in Task 7 Step 14, setting `req.PurgeProtection` on each command's `keyservices.CreateKeyRequest`/`UpdateKeyRequest` construction, and register `Flags().Bool("purge-protection", false, "Protect the key from being purged")` in each `Init*` function.

- [ ] **Step 10: Add the API-level regression test**

Add to `api/soft_delete_extended_test.go`, mirroring Task 7 Step 15 but for `PurgeKey`/`repositories.ErrKeyPurgeProtected`.

- [ ] **Step 11: Run the full affected test suite**

Run: `go test ./internal/repositories/... ./internal/services/keys/... ./api/... ./cmd/keys/... ./internal/container/... -v`
Expected: PASS. Also run `go build ./...`.

- [ ] **Step 12: Commit**

```bash
git add internal/repositories/key_repository.go internal/services/keys/key_service.go model/key.go \
        api/keys.go api/errors_key.go cmd/keys/create.go cmd/keys/update.go internal/container/service_container.go \
        internal/services/keys/key_soft_delete_test.go api/soft_delete_extended_test.go
git commit -m "fix(keys): make purge protection settable and enforce vault-level cascade"
```

---

## Task 9: Purge protection — certificates

**Files:**
- Modify: `internal/repositories/certificate_repository.go`
- Modify: `internal/services/certificates/certificate_service.go`
- Modify: `model/certificate.go`
- Modify: `api/certificates.go`
- Modify: `api/errors_certificate.go`
- Modify: `cmd/certificates/create.go`
- Modify: `cmd/certificates/update.go`
- Modify: `internal/container/service_container.go`
- Test: `internal/services/certificates/cert_soft_delete_test.go`
- Test: `api/soft_delete_extended_test.go`

**Interfaces:**
- Consumes: `repositories.ErrCertPurgeProtected` (defined in Task 7, Step 3). `CertificateRepositoryInterface.SetPurgeProtection` already exists (`internal/repositories/certificate_repository.go:41`).
- Produces: `certificates.CreateCertificateRequest`/`UpdateCertificateRequest` gain `PurgeProtection *bool`. `model.CreateCertificateRequest`/`UpdateCertificateRequest` gain `PurgeProtection *bool \`json:"purge_protection,omitempty"\``. `certificateService` gains an optional `vaultRepo repositories.VaultRepositoryInterface` field via `CertificateServiceConfig.VaultRepository`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/certificates/cert_soft_delete_test.go`, mirroring Task 8 Step 1 exactly but for certificates: `TestCreateSelfSignedCertificate_SetsPurgeProtectionWhenRequested` (calling whichever certificate-creation method this file's existing tests use, e.g. `CreateSelfSignedCertificate`) and `TestPurgeCertificate_BlockedWhenVaultIsPurgeProtected`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/certificates/... -run 'SetsPurgeProtectionWhenRequested|BlockedWhenVaultIsPurgeProtected' -v`
Expected: FAIL — compile errors.

- [ ] **Step 3: Change `PurgeCertificate`'s repo-layer protection check to return the sentinel**

In `internal/repositories/certificate_repository.go`, change (`:640-643`):

```go
		if purgeProtection {
			r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Certificate has purge protection enabled", nil)
			return fmt.Errorf("certificate has purge protection enabled")
		}
```

to:

```go
		if purgeProtection {
			r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Certificate has purge protection enabled", nil)
			return ErrCertPurgeProtected
		}
```

- [ ] **Step 4: Add `PurgeProtection` to the service DTOs and wire creation/update**

In `internal/services/certificates/certificate_service.go`, add `PurgeProtection *bool` to `CreateCertificateRequest` and `UpdateCertificateRequest`.

Add `VaultRepository repositories.VaultRepositoryInterface` to `CertificateServiceConfig` and `vaultRepo repositories.VaultRepositoryInterface` to the `certificateService` struct; wire it in the constructor.

In every certificate-creation method that builds a `model.Certificate{...}` and calls `s.certRepo.Create(ctx, cert)` (self-signed and CA-signed paths — locate both via `grep -n "certRepo.Create" internal/services/certificates/certificate_service.go` before editing), after `Create` succeeds, add:

```go
	if req.PurgeProtection != nil && *req.PurgeProtection {
		if err := s.certRepo.SetPurgeProtection(ctx, cert.ID, true); err != nil {
			return nil, fmt.Errorf("failed to set purge protection: %w", err)
		}
	}
```

(Match each method's actual local variable name for the created certificate.)

In `UpdateCertificate`, after the repository update call succeeds, add:

```go
	if req.PurgeProtection != nil {
		if err := s.certRepo.SetPurgeProtection(ctx, req.CertID, *req.PurgeProtection); err != nil {
			return fmt.Errorf("failed to set purge protection: %w", err)
		}
	}
```

- [ ] **Step 5: Add the vault-level cascade check to `PurgeCertificate`**

In `PurgeCertificate`, after the `if !inScope { ... }` block and before `if err := s.certRepo.PurgeCertificate(ctx, certID); err != nil {`, add:

```go
	if s.vaultRepo != nil && scope.VaultID() != uuid.Nil {
		vault, err := s.vaultRepo.ReadByID(ctx, scope.VaultID())
		if err == nil && vault.PurgeProtection {
			s.logger.LogAuditError(scope.ActorID().String(), "purge_certificate", "failed",
				"Vault has purge protection enabled", nil)
			return repositories.ErrCertPurgeProtected
		}
	}
```

- [ ] **Step 6: Run the service tests to verify they pass**

Run: `go test ./internal/services/certificates/... -v`
Expected: PASS.

- [ ] **Step 7: Wire `VaultRepository` in the container**

In `internal/container/service_container.go`, in the `certServices.NewCertificateService(certServices.CertificateServiceConfig{...})` call (around line 554), add `VaultRepository: c.vaultRepository,`.

- [ ] **Step 8: Add `PurgeProtection` to the HTTP DTOs and API error mapping**

In `model/certificate.go`, add `PurgeProtection *bool \`json:"purge_protection,omitempty"\`` to `CreateCertificateRequest` and `UpdateCertificateRequest`.

In `api/certificates.go`, add `PurgeProtection: req.PurgeProtection,` to both the `certServices.CreateCertificateRequest{...}` literal in `createCertificate` and the `certServices.UpdateCertificateRequest{...}` literal in `updateCertificate`. Check the local `CreateCertificateAPIRequest`/`UpdateCertificateAPIRequest` DTOs (decoded from the request body, distinct from `model.*`) also gain `PurgeProtection *bool \`json:"purge_protection,omitempty"\``.

In `api/errors_certificate.go`, add before `default:`:

```go
	case errors.Is(err, repositories.ErrCertPurgeProtected):
		c.SetPermissionError("certificate has purge protection enabled")
```

- [ ] **Step 9: Add the CLI flag**

In `cmd/certificates/create.go` and `cmd/certificates/update.go`, add the identical `Changed("purge-protection")`-gated block, setting `req.PurgeProtection` on each command's request construction, and register `Flags().Bool("purge-protection", false, "Protect the certificate from being purged")` in each `Init*` function.

- [ ] **Step 10: Add the API-level regression test**

Add to `api/soft_delete_extended_test.go`, mirroring Task 7 Step 15 but for `PurgeCertificate`/`repositories.ErrCertPurgeProtected`.

- [ ] **Step 11: Run the full affected test suite**

Run: `go test ./internal/repositories/... ./internal/services/certificates/... ./api/... ./cmd/certificates/... ./internal/container/... -v`
Expected: PASS. Also run `go build ./...`.

- [ ] **Step 12: Run the entire project test suite once, end to end**

Run: `go build ./... && go test ./...`
Expected: PASS across the whole repository — this is the final integration check across all nine tasks.

- [ ] **Step 13: Commit**

```bash
git add internal/repositories/certificate_repository.go internal/services/certificates/certificate_service.go model/certificate.go \
        api/certificates.go api/errors_certificate.go cmd/certificates/create.go cmd/certificates/update.go internal/container/service_container.go \
        internal/services/certificates/cert_soft_delete_test.go api/soft_delete_extended_test.go
git commit -m "fix(certificates): make purge protection settable and enforce vault-level cascade"
```

---

## Post-implementation documentation follow-up (not a task with tests — do last, by hand)

Per the audit's "Documentation corrections recommended" section, after all nine tasks land:
- Update `.claude/azure-keyvault-parity.md`'s purge-protection row (currently states "✅ (per-key + per-vault)") to reflect the real, now-fixed behavior.
- Update `.claude/known-bugs.md` to record these six findings as fixed, per this file's own stated role as the living bug-status source of truth.
