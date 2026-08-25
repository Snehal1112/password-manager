# Certificate Export (Passphrase-Sealed) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a caller export a vault's certificates to a passphrase-sealed, portable file — mirroring the existing secrets export feature — over both the CLI and the REST API.

**Architecture:** `CertificateService.ExportCertificates` lists certificates by scope/tag filter, marshals an explicit export-shaped struct to JSON (no CSV — see Global Constraints), and returns unsealed bytes, exactly matching `SecretService.ExportSecrets`'s split between "format in the service" and "seal one layer up." The CLI and API handlers reuse `common.SealExport`/`common.ResolvePassphrase` unchanged. This is genuinely separate from the existing, unencrypted `POST /certificates/{id}/backup`.

**Tech Stack:** Go 1.24, `common/export_envelope.go` (existing, reused as-is), Cobra, testify/mock.

**Spec:** `docs/superpowers/specs/2026-08-25-certificate-export-design.md`

## Global Constraints

- **JSON-only. No CSV support, ever, for full-certificate export** (spec Design §1) — PEM/CSR content is exactly the multi-line, line-ending-sensitive text `.claude/known-bugs.md` § B49 (CSV normalizes embedded CRLF) warns against. `--format` on `certificates export` accepts only `json`; do not add a `csv` branch to this feature.
- Reuse `common.SealExport`/`OpenExport`/`IsSealedExport` (`common/export_envelope.go`) and the shared `ROCKETVAULT_EXPORT_PASSPHRASE` env var (`cmd/secrets/export.go:55`'s `exportPassphraseEnvVar` constant, in package `secrets` — this plan's CLI package is `certificates`, so declare a package-local constant with the identical string value, not a cross-package import of an unexported constant).
- This is a export-only plan: no "restore from export" / bulk-import counterpart is in scope. (Per the design doc's naming-collision note: if a bulk restore path is added later, it must be named distinctly from the sibling plan's singular `ImportCertificate`, e.g. `RestoreCertificatesFromExport` — not built here.)
- Do not modify `POST /certificates/{id}/backup` or `internal/backup/item_backup.go` — this plan adds a parallel, separately-named feature, not a change to the existing backup mechanism.
- Follows `cmd/secrets/export.go` and `api/secrets.go`'s `exportSecrets` structurally, adapted to certificates and to the no-CSV/no-remote-mode constraints above (certificate CLI commands are local-only today, matching `certificates create`).

---

### Task 1: `CertificateService.ExportCertificates`

**Files:**
- Modify: `internal/services/certificates/certificate_service.go`
- Test: `internal/services/certificates/certificate_service_extended_test.go`

**Interfaces:**
- Consumes: `certificateService.ListCertificates`/`model.CertificateFilter` (existing, `model/filters.go:23-32`)
- Produces: `CertificateService.ExportCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]byte, error)` — consumed by Task 3 (retry decorator), Task 5 (API handler), Task 6 (CLI)

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/certificates/certificate_service_extended_test.go`, reusing `mockCertRepository` (`internal/services/certificates/cert_soft_delete_test.go:27`) and `newCertLogger()`:

```go
func TestExportCertificates_Success(t *testing.T) {
	userID := uuid.New()
	vaultID := uuid.New()
	certs := []model.Certificate{
		{ID: uuid.New(), Name: "cert-a", Certificate: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----", Tags: []string{"prod"}},
		{ID: uuid.New(), Name: "cert-b", Certificate: "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"},
	}

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, mock.Anything, mock.Anything).Return(certs, nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: repo,
		Logger:                 newCertLogger(),
	})

	data, err := svc.ExportCertificates(context.Background(), model.NewVaultScope(vaultID, userID), model.CertificateFilter{})
	require.NoError(t, err)

	var exported []exportedCertificate
	require.NoError(t, json.Unmarshal(data, &exported))
	require.Len(t, exported, 2)
	assert.Equal(t, "cert-a", exported[0].Name)
	assert.Contains(t, exported[0].Certificate, "BEGIN CERTIFICATE")
	assert.Equal(t, []string{"prod"}, exported[0].Tags)
}

func TestExportCertificates_EmptyVault_ReturnsEmptyArray(t *testing.T) {
	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, mock.Anything, mock.Anything).Return([]model.Certificate{}, nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: repo,
		Logger:                 newCertLogger(),
	})

	data, err := svc.ExportCertificates(context.Background(), model.NewVaultScope(uuid.New(), uuid.New()), model.CertificateFilter{})
	require.NoError(t, err)

	var exported []exportedCertificate
	require.NoError(t, json.Unmarshal(data, &exported))
	assert.Empty(t, exported)
}

func TestExportCertificates_RepositoryError_Propagates(t *testing.T) {
	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("db unavailable"))

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: repo,
		Logger:                 newCertLogger(),
	})

	_, err := svc.ExportCertificates(context.Background(), model.NewVaultScope(uuid.New(), uuid.New()), model.CertificateFilter{})
	require.Error(t, err)
}

func TestExportCertificates_TagFilterPassedThrough(t *testing.T) {
	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, mock.Anything, mock.MatchedBy(func(f repositories.CertificateFilter) bool {
		return len(f.Tags) == 1 && f.Tags[0] == "production"
	})).Return([]model.Certificate{}, nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: repo,
		Logger:                 newCertLogger(),
	})

	_, err := svc.ExportCertificates(context.Background(), model.NewVaultScope(uuid.New(), uuid.New()), model.CertificateFilter{Tags: []string{"production"}})
	require.NoError(t, err)
}
```

Note: `TestExportCertificates_TagFilterPassedThrough` asserts against `repositories.CertificateFilter`, not `model.CertificateFilter` — confirm which type `CertificateRepositoryInterface.List`'s `filter` parameter actually is at implementation time (the earlier research captured `List(ctx, scope, filter CertificateFilter)` on the repository interface without pinning down its package; `ListCertificates`'s own signature uses `model.CertificateFilter`, so `ExportCertificates` likely needs to convert between the two, or they may be the same type aliased — resolve this before writing `ListCertificates`'s call in Step 3, and adjust this test's `mock.MatchedBy` type accordingly).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/services/certificates/... -run TestExportCertificates -v`
Expected: FAIL — `svc.ExportCertificates`, `exportedCertificate` undefined (compile error).

- [ ] **Step 3: Implement `ExportCertificates`**

Add to `internal/services/certificates/certificate_service.go`:

```go
// exportedCertificate is the JSON shape one certificate takes in an export
// file. Internal IDs (ID/UserID/VaultID/KeyID) are deliberately dropped --
// they're regenerated by whatever future restore path exists, not preserved
// verbatim, matching how a certificate's public/private material and
// caller-facing metadata are the only things a portable export should carry.
type exportedCertificate struct {
	Name        string   `json:"name"`
	Certificate string   `json:"certificate"`
	PrivateKey  string   `json:"private_key"` // decrypted PEM -- see security note below
	Tags        []string `json:"tags,omitempty"`
	AutoRenew   bool     `json:"auto_renew"`
	RenewalDays int      `json:"renewal_days"`
	Enabled     bool     `json:"enabled"`
}
```

In the `CertificateService` interface, after `MergeCertificate`:

```go
	// ExportCertificates returns the vault's certificates (filtered by
	// filter, authorized by scope) as unsealed, formatted JSON bytes.
	// Sealing under a passphrase happens one layer up (CLI or API handler) --
	// this method never sees a passphrase, matching SecretService.ExportSecrets.
	ExportCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]byte, error)
```

Implementation:

```go
// ExportCertificates lists certificates authorized by scope and narrowed by
// filter, and returns them as unsealed JSON bytes. Sealing is the caller's
// job -- see ExportCertificates's doc comment.
func (s *certificateService) ExportCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]byte, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": scope.ActorID().String(),
		"tags":    filter.Tags,
	}).Info("Exporting certificates")

	certs, err := s.ListCertificates(ctx, scope, filter)
	if err != nil {
		s.logger.LogAuditError(scope.ActorID().String(), "export_certificates", "failed", "failed to list certificates", err)
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	exported := make([]exportedCertificate, len(certs))
	for i, cert := range certs {
		privateKeyPEM, err := common.DecryptSecret(cert.PrivateKey)
		if err != nil {
			s.logger.LogAuditError(scope.ActorID().String(), "export_certificates", "failed", fmt.Sprintf("failed to decrypt private key for %q", cert.Name), err)
			return nil, fmt.Errorf("failed to decrypt private key for %q: %w", cert.Name, err)
		}
		exported[i] = exportedCertificate{
			Name:        cert.Name,
			Certificate: cert.Certificate,
			PrivateKey:  privateKeyPEM,
			Tags:        cert.Tags,
			AutoRenew:   cert.AutoRenew,
			RenewalDays: cert.RenewalDays,
			Enabled:     cert.Enabled,
		}
	}

	data, err := json.MarshalIndent(exported, "", "  ")
	if err != nil {
		s.logger.LogAuditError(scope.ActorID().String(), "export_certificates", "failed", "failed to marshal export", err)
		return nil, fmt.Errorf("failed to marshal certificate export: %w", err)
	}

	s.logger.LogAuditInfo(scope.ActorID().String(), "export_certificates", "success", fmt.Sprintf("exported %d certificate(s)", len(exported)))
	return data, nil
}
```

**Security note, deliberately called out in code review, not just this plan:** unlike `SecretService.ExportSecrets` (which only ever handles secret values, already the resource's entire point), `ExportCertificates` decrypts every exported certificate's private key into the plaintext JSON payload. This is safe *only* because the caller-facing contract requires `--encrypt` (default true) to seal the file before it ever reaches disk or the HTTP response body — verified in Task 5/6's handlers, which must call `common.SealExport` unconditionally unless the caller explicitly opts out with `--encrypt=false` (mirroring secrets export's exact same opt-out-with-warning pattern). If Task 5 or Task 6 is implemented without wiring the seal step correctly, this method will write plaintext private keys to disk/HTTP responses — this is precisely the class of defect `.claude/known-bugs.md` § B36 documents for secrets (`--encrypt` bound but never consulted). Do not skip the "Lessons applied" cross-checks in Tasks 5 and 6.

Add `"encoding/json"` to `certificate_service.go`'s import block if not already present.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/services/certificates/... -run TestExportCertificates -v`
Expected: PASS, all four tests.

- [ ] **Step 5: Run the full certificates package suite**

Run: `go build ./... && go test ./internal/services/certificates/... -v 2>&1 | tail -150`
Expected: no FAIL.

- [ ] **Step 6: Commit**

```bash
git add internal/services/certificates/certificate_service.go internal/services/certificates/certificate_service_extended_test.go
git commit -m "feat(certificates): add CertificateService.ExportCertificates"
```

---

### Task 2: Retry decorator + mock regeneration

**Files:**
- Modify: `internal/services/retry/retry_certificate_service.go`
- Modify (generated): `internal/services/certificates/mocks/mock_CertificateService.go`

**Interfaces:**
- Consumes: `certificates.CertificateService.ExportCertificates` (Task 1)
- Produces: retry passthrough + regenerated mock

- [ ] **Step 1: Confirm the compile break**

Run: `go build ./... 2>&1 | grep -i retrycertificateservice`

- [ ] **Step 2: Add the passthrough**

```go
// ExportCertificates exports certificates with retry logic for database operations.
func (s *retryCertificateService) ExportCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]byte, error) {
	return retried(ctx, s.retryService, func() ([]byte, error) {
		return s.baseService.ExportCertificates(ctx, scope, filter)
	})
}
```

- [ ] **Step 3: Verify the build is unblocked**

Run: `go build ./... 2>&1`
Expected: no `retrycertificateservice`/`ExportCertificates` errors.

- [ ] **Step 4: Regenerate the mock**

Run: `mockery` from the repo root. Verify: `git diff --stat internal/services/certificates/mocks/mock_CertificateService.go` shows only `ExportCertificates`-related additions.

- [ ] **Step 5: Run the retry package suite**

Run: `go test ./internal/services/retry/... -v 2>&1 | tail -60`
Expected: no FAIL.

- [ ] **Step 6: Commit**

```bash
git add internal/services/retry/retry_certificate_service.go internal/services/certificates/mocks/mock_CertificateService.go
git commit -m "feat(certificates): retry passthrough and regenerated mock for ExportCertificates"
```

---

### Task 3: Authorization — `ActionCertificatesExport`

**Files:**
- Modify: `model/azure_roles.go`
- Modify: `internal/services/authorization/data_actions.go`
- Test: `internal/services/authorization/data_actions_test.go`

**Interfaces:**
- Consumes: nothing new
- Produces: `model.ActionCertificatesExport`, `mapCertificateAction("POST", "export")` → `(model.ActionCertificatesExport, RouteVaultData)`

- [ ] **Step 1: Write the failing test**

Add to `TestMapRouteToDataAction`'s table:

```go
		{"export certificates", http.MethodPost, "/api/v1/certificates/export", model.ActionCertificatesExport, RouteVaultData},
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/authorization/... -run TestMapRouteToDataAction -v`
Expected: FAIL — `model.ActionCertificatesExport` undefined.

- [ ] **Step 3: Add the constant and grant it**

In `model/azure_roles.go`, next to `ActionCertificatesBackup` (this is the closest conceptual analog per the spec — export is a RocketVault-only addition with no Azure equivalent, so it's granted alongside backup rather than create/import):

```go
	// ActionCertificatesExport permits exporting certificates as a
	// passphrase-sealed, portable file. RocketVault-only -- Azure Key Vault
	// has no equivalent bulk-export operation for certificates.
	ActionCertificatesExport DataAction = "Microsoft.KeyVault/vaults/certificates/export/action"
```

Grant it to whichever roles hold `ActionCertificatesBackup` today (re-grep `ActionCertificatesBackup,` in the `azureRoleDataActions` map — likely the same `RoleKeyVaultAdministrator` and `RoleKeyVaultCertificatesOfficer` blocks Task 4 of the sibling import/merge plan already touched, so re-check exact line numbers at implementation time since they will have shifted).

- [ ] **Step 4: Add the `mapCertificateAction` case**

```go
	case "export":
		if method == http.MethodPost {
			return model.ActionCertificatesExport, RouteVaultData
		}
		return "", RouteVaultData
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/services/authorization/... -run TestMapRouteToDataAction -v`
Expected: PASS.

- [ ] **Step 6: Run the full authorization suite**

Run: `go test ./internal/services/authorization/... -v 2>&1 | tail -100`
Expected: no FAIL. Update `roles_test.go` if it asserts an exact per-role action count/list, same caveat as the sibling import/merge plan's Task 4.

- [ ] **Step 7: Commit**

```bash
git add model/azure_roles.go internal/services/authorization/data_actions.go internal/services/authorization/data_actions_test.go internal/services/authorization/roles_test.go
git commit -m "feat(authz): route POST /certificates/export to ActionCertificatesExport"
```

---

### Task 4: `common.SealExport` re-verification (no code change — confidence check)

**Files:**
- None modified — this task is a deliberate no-op verification step, not a placeholder.

**Interfaces:**
- Consumes: `common.SealExport`/`OpenExport`/`IsSealedExport` (existing, unmodified)

- [ ] **Step 1: Confirm `common.SealExport` is generic, not secrets-specific**

Run: `grep -n "secret" common/export_envelope.go`
Expected: no output (or only incidental matches in comments unrelated to the envelope format itself) — confirms the envelope format has no secrets-specific coupling, so certificates can reuse it verbatim with zero modification. If this grep finds real coupling (e.g. a `Secret`-typed field), stop and re-scope this task into a real code change before proceeding to Task 5/6 — do not silently work around a coupling that shouldn't exist.

- [ ] **Step 2: Run the existing `common` package export tests as a smoke check**

Run: `go test ./common/... -run 'Export|Seal|Open' -v 2>&1 | tail -60`
Expected: PASS (these tests already exist and are untouched by this plan — this step just confirms the baseline is green before Tasks 5/6 build on it).

(No commit — nothing changed.)

---

### Task 5: API — `POST /certificates/export`

**Files:**
- Modify: `api/certificates.go`
- Modify: `api/certificates_test.go`

**Interfaces:**
- Consumes: `certificates.CertificateService.ExportCertificates` (Task 1), `common.SealExport` (existing)
- Produces: `POST /certificates/export` (both legacy and vault-scoped routers)

- [ ] **Step 1: Add `ExportCertificates` to `mockCertService`**

Add to `api/certificates_test.go`'s `mockCertService` (`:44-`):

```go
func (m *mockCertService) ExportCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]byte, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}
```

- [ ] **Step 2: Write the failing tests**

Add next to `TestCreateCertificate_Success_Returns201` (`:407`), reusing `newCertCtx`/`certAdminClaims()`:

```go
func TestExportCertificates_Success_Returns200(t *testing.T) {
	svc := &mockCertService{}
	exportedJSON := []byte(`[{"name":"cert-a","certificate":"...","private_key":"...","enabled":true}]`)
	svc.On("ExportCertificates", mock.Anything, mock.Anything, mock.Anything).Return(exportedJSON, nil)

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"encrypt": true, "passphrase": "test-pass-1234"})
	r := httptest.NewRequest(http.MethodPost, "/certificates/export", bytes.NewReader(body))

	exportCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Disposition"), "certificates-export")
	svc.AssertExpectations(t)

	// The response body must be a sealed envelope, not plaintext -- proves
	// the handler actually calls common.SealExport rather than writing
	// ExportCertificates's raw (plaintext-private-key-bearing) output
	// straight through. See Task 1's security note.
	assert.True(t, common.IsSealedExport(w.Body.Bytes()), "response body must be a sealed export envelope")
}

func TestExportCertificates_EncryptTrueNoPassphrase_Returns400(t *testing.T) {
	svc := &mockCertService{}
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"encrypt": true})
	r := httptest.NewRequest(http.MethodPost, "/certificates/export", bytes.NewReader(body))

	exportCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "ExportCertificates", mock.Anything, mock.Anything, mock.Anything)
}

func TestExportCertificates_EncryptFalse_ReturnsPlaintext(t *testing.T) {
	svc := &mockCertService{}
	exportedJSON := []byte(`[{"name":"cert-a"}]`)
	svc.On("ExportCertificates", mock.Anything, mock.Anything, mock.Anything).Return(exportedJSON, nil)

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"encrypt": false})
	r := httptest.NewRequest(http.MethodPost, "/certificates/export", bytes.NewReader(body))

	exportCertificates(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, common.IsSealedExport(w.Body.Bytes()))
	assert.Equal(t, exportedJSON, w.Body.Bytes())
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./api/... -run TestExportCertificates -v`
Expected: FAIL — `exportCertificates` undefined (compile error).

- [ ] **Step 4: Add the route, request type, and handler**

In `api/certificates.go`:

```go
	c.Handle("/export", ApiSessionRequired(api.App, exportCertificates)).Methods("POST")
```

```go
// ExportCertificatesAPIRequest represents the request structure for
// exporting a vault's certificates.
type ExportCertificatesAPIRequest struct {
	Tags       []string `json:"tags,omitempty"`
	Encrypt    bool     `json:"encrypt"`
	Passphrase string   `json:"passphrase,omitempty"`
}

// exportCertificates exports the target vault's certificates as a
// passphrase-sealed (by default) JSON file. See CertificateService.
// ExportCertificates's security note: this handler must seal whenever
// Encrypt is true, and must reject Encrypt=true with no passphrase rather
// than silently writing plaintext (the class of bug .claude/known-bugs.md
// § B36 documents for secrets export).
func exportCertificates(c *Context, w http.ResponseWriter, r *http.Request) {
	var req ExportCertificatesAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Encrypt && req.Passphrase == "" {
		c.SetInvalidParam("passphrase is required when encrypt is true")
		return
	}

	userID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	data, err := certService.ExportCertificates(r.Context(), scope, model.CertificateFilter{Tags: req.Tags})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	if req.Encrypt {
		sealed, err := common.SealExport(data, req.Passphrase)
		if err != nil {
			c.SetInternalError(err)
			return
		}
		data = sealed
	}

	filename := fmt.Sprintf("certificates-export-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data) //nolint:errcheck,gosec

	_ = userID // userID reserved for an audit-log line if this handler adds one beyond the service layer's own logging
}
```

Add `"rocketvault/common"` to `api/certificates.go`'s import block if not already present (check first — it's likely already imported for other reasons in this large file).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./api/... -run TestExportCertificates -v`
Expected: PASS, all three tests — in particular, confirm `TestExportCertificates_Success_Returns200`'s `common.IsSealedExport` assertion passes, since that's the test that would have caught a B36-class defect.

- [ ] **Step 6: Run the full API package suite**

Run: `go build ./... && go test ./api/... -v 2>&1 | tail -150`
Expected: no FAIL.

- [ ] **Step 7: Commit**

```bash
git add api/certificates.go api/certificates_test.go
git commit -m "feat(api): add POST /certificates/export"
```

---

### Task 6: CLI — `rocketvault certificates export`

**Files:**
- Create: `cmd/certificates/export.go`
- Modify: `cmd/certificates.go`
- Modify: `cmd/certificates/certs_cmd_test.go`

**Interfaces:**
- Consumes: `certificates.CertificateService.ExportCertificates` (Task 1), `common.ResolvePassphrase`/`SealExport` (existing), `vaultcli.RequireDataAction`, `model.ActionCertificatesExport`

- [ ] **Step 1: Add `ExportCertificates` to `certCmdCertService` and register `InitCertificatesExport`**

Add to `certCmdCertService` (`cmd/certificates/certs_cmd_test.go:44-`):

```go
func (m *certCmdCertService) ExportCertificates(ctx context.Context, scope model.Scope, filter model.CertificateFilter) ([]byte, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}
```

Register in `TestMain`, next to `InitCertificatesMerge(parent)` (added by the sibling import/merge plan's Task 11):

```go
	InitCertificatesMerge(parent)
	InitCertificatesExport(parent)
```

- [ ] **Step 2: Write the failing tests**

```go
func TestCertExportCmd_EncryptTrueNoPassphrase_Fails(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	outFile := filepath.Join(t.TempDir(), "out.json")
	cleanup := viperSetCert(map[string]interface{}{
		"cert-export-file": outFile, "cert-export-encrypt": true, "cert-export-passphrase-file": "",
	})
	defer cleanup()
	// No ROCKETVAULT_EXPORT_PASSPHRASE set and no TTY -- common.ResolvePassphrase
	// must fail closed here, matching secrets export's exact behavior.
	t.Setenv(certExportPassphraseEnvVar, "")

	cmd, _ := newCertCmd(exportCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.Error(t, err)
	_, statErr := os.Stat(outFile)
	assert.True(t, os.IsNotExist(statErr), "no file must be written when passphrase resolution fails")
}

func TestCertExportCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	exportedJSON := []byte(`[{"name":"cert-a","certificate":"...","private_key":"...","enabled":true}]`)
	certSvc.On("ExportCertificates", mock.Anything, mock.Anything, mock.Anything).Return(exportedJSON, nil)

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	outFile := filepath.Join(t.TempDir(), "out.json")
	passFile := filepath.Join(t.TempDir(), "pass.txt")
	require.NoError(t, os.WriteFile(passFile, []byte("test-pass-1234\n"), 0o600))

	cleanup := viperSetCert(map[string]interface{}{
		"cert-export-file": outFile, "cert-export-encrypt": true, "cert-export-passphrase-file": passFile,
	})
	defer cleanup()

	cmd, buf := newCertCmd(exportCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)

	written, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.True(t, common.IsSealedExport(written), "written file must be a sealed export envelope")
}

func TestCertExportCmd_EncryptFalse_WritesPlaintext(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	exportedJSON := []byte(`[{"name":"cert-a"}]`)
	certSvc.On("ExportCertificates", mock.Anything, mock.Anything, mock.Anything).Return(exportedJSON, nil)

	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	outFile := filepath.Join(t.TempDir(), "out.json")
	cleanup := viperSetCert(map[string]interface{}{
		"cert-export-file": outFile, "cert-export-encrypt": false,
	})
	defer cleanup()

	cmd, _ := newCertCmd(exportCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)

	written, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, exportedJSON, written)
	assert.False(t, common.IsSealedExport(written))
}
```

Add `"path/filepath"` to this test file's import block if not already present.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./cmd/certificates/... -run TestCertExportCmd -v`
Expected: FAIL — `exportCmd`, `certExportPassphraseEnvVar` undefined (compile error).

- [ ] **Step 4: Implement `cmd/certificates/export.go`**

```go
/*
Copyright © 2025 Snehal Dangroshiya
... (same license header — copy verbatim from cmd/certificates/create.go)
*/

package certificates

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/model"
)

// certExportPassphraseEnvVar mirrors cmd/secrets/export.go's
// exportPassphraseEnvVar -- same variable name, same UX, across resource
// types. Declared locally since the secrets package's constant is
// unexported and this is a different package.
const certExportPassphraseEnvVar = "ROCKETVAULT_EXPORT_PASSPHRASE"

var (
	certExportFile           string
	certExportEncrypt        bool
	certExportPassphraseFile string
	certExportTags           []string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export certificates to a file",
	Long: `Export the target vault's certificates to a JSON file holding each
certificate's name, PEM material, decrypted private key PEM, and tags.

This is NOT the same as 'certificates <id> backup', which writes an
unencrypted, same-instance restore blob. This export is passphrase-sealed
by default and portable to any RocketVault instance or human recipient who
knows the passphrase.

The file is encrypted by default. --encrypt (default true) seals it under a
passphrase with argon2id key derivation and AES-256-GCM, read from
--passphrase-file, then the ROCKETVAULT_EXPORT_PASSPHRASE environment
variable, then an interactive prompt asking twice. If none of those yields
a passphrase the command fails and writes no file at all.

--encrypt=false writes the export in the clear, including every exported
certificate's private key, and prints a warning naming what is exposed.

Requires the admin or certificate_manager role, and the
Microsoft.KeyVault/vaults/certificates/export/action data action in the
target vault. Only JSON is supported -- there is no --format flag, unlike
secrets export, because certificate/CSR PEM content is exactly the kind of
multi-line text CSV's CRLF normalization corrupts (see
.claude/known-bugs.md § B49).`,
	Example: `  # Export every certificate in the default vault, prompting for a passphrase
  rocketvault certificates export --file certs.json

  # Export non-interactively, reading the passphrase from a file
  rocketvault certificates export --file certs.json --passphrase-file /run/secrets/export-pass

  # Export only production-tagged certificates from a named vault
  rocketvault certificates export --file prod-certs.json --tags production --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}
		userID := claims.UserID

		if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCertificateManager) {
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || sc == nil {
			return fmt.Errorf("service container not available in context")
		}

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionCertificatesExport, model.OpCreate)
		if err != nil {
			return err
		}

		if !certExportEncrypt && certExportPassphraseFile != "" {
			return fmt.Errorf("--passphrase-file was given with --encrypt=false: " +
				"drop one, since a plaintext export has no passphrase")
		}
		var passphrase string
		if certExportEncrypt {
			passphrase, err = common.ResolvePassphrase(common.PassphraseSource{
				File:    certExportPassphraseFile,
				EnvVar:  certExportPassphraseEnvVar,
				Prompt:  "Export passphrase: ",
				Confirm: true,
			})
			if err != nil {
				if errors.Is(err, common.ErrNoPassphraseAvailable) {
					return fmt.Errorf("export encryption is on but no passphrase is available: "+
						"pass --passphrase-file, set %s, or pass --encrypt=false to write plaintext deliberately",
						certExportPassphraseEnvVar)
				}
				return fmt.Errorf("failed to resolve export passphrase: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stderr,
				"Warning: --encrypt=false — %s will hold every exported certificate's PEM material and "+
					"plaintext private key in the clear.\n", certExportFile) //nolint:errcheck
		}

		certService := sc.GetCertificateService()
		data, err := certService.ExportCertificates(ctx, model.NewVaultScope(vaultID, userID), model.CertificateFilter{Tags: certExportTags})
		if err != nil {
			return fmt.Errorf("failed to export certificates: %w", err)
		}

		if certExportEncrypt {
			data, err = common.SealExport(data, passphrase)
			if err != nil {
				return fmt.Errorf("failed to seal export: %w", err)
			}
		}

		dir := filepath.Dir(certExportFile)
		if dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
		}
		if err := os.WriteFile(certExportFile, data, 0o600); err != nil {
			return fmt.Errorf("failed to write export file: %w", err)
		}

		encryption := "none (plaintext)"
		if certExportEncrypt {
			encryption = "passphrase (argon2id + AES-256-GCM)"
		}
		fmt.Printf("Certificates exported successfully\nEncryption: %s\nFile: %s\n", encryption, certExportFile)
		return nil
	},
}

// InitCertificatesExport registers the export sub-command under the given parent.
func InitCertificatesExport(parentCmd *cobra.Command) {
	parentCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVarP(&certExportFile, "file", "o", "", "Output file path (required)")
	exportCmd.Flags().BoolVarP(&certExportEncrypt, "encrypt", "e", true, "Encrypt the export file")
	exportCmd.Flags().StringVar(&certExportPassphraseFile, "passphrase-file", "",
		"Read the export passphrase from the first line of this file")
	exportCmd.Flags().StringSliceVarP(&certExportTags, "tags", "t", []string{}, "Include only certificates with these tags")
	exportCmd.MarkFlagRequired("file") //nolint:errcheck,gosec
}
```

Note: unlike `keys create`/`certificates create`, which take `--tags` as a single comma-separated string flag and split it manually, this command declares `--tags` via `StringSliceVarP` (matching `cmd/secrets/export.go`'s own `--tags` flag exactly), which already parses repeated or comma-separated flag values into `certExportTags []string` — no manual splitting needed, and no `strings` import required in this file.

Register in `cmd/certificates.go`, next to `InitCertificatesMerge`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/certificates/... -run TestCertExportCmd -v`
Expected: PASS, all three tests.

- [ ] **Step 6: Run the full CLI certificates package suite**

Run: `go build ./... && go test ./cmd/certificates/... -v 2>&1 | tail -150`
Expected: no FAIL.

- [ ] **Step 7: Manual smoke test**

```bash
go run main.go certificates export --file /tmp/certs-export.json --vault default
go run main.go certificates export --file /tmp/certs-export-plain.json --encrypt=false --vault default
```

Confirm the first command prompts for a passphrase (or reads `ROCKETVAULT_EXPORT_PASSPHRASE`) and the resulting file is not human-readable JSON (it's a sealed envelope); confirm the second writes readable JSON directly and prints the plaintext warning to stderr.

- [ ] **Step 8: Commit**

```bash
git add cmd/certificates/export.go cmd/certificates.go cmd/certificates/certs_cmd_test.go
git commit -m "feat(cli): add certificates export command"
```

---

### Task 7: Full build/test verification and documentation

**Files:**
- Modify: `.claude/azure-keyvault-parity.md`
- Modify: `.claude/roadmap-azure-parity-and-beyond.md`
- Modify: `README.md`
- Modify: `docs/cli-guide.md`
- Modify: `docs/api-developer-guide.md`
- Modify: `docs/integration-examples.md`

- [ ] **Step 1: Full build and test suite**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | tail -150`
Expected: builds clean, `go vet` clean, no FAIL anywhere.

- [ ] **Step 2: Flip the parity doc's certificate-export footnote into a real row**

`.claude/azure-keyvault-parity.md` §4 currently has a footnote (added 2026-08-25 alongside the import/merge rows) noting certificate export has "no Azure equivalent... design specified, not yet built." Since Azure has no equivalent, this doesn't become a normal ✅/❌ comparison row — add it as a `➕` row instead, matching the file's existing convention for RocketVault-only extras (e.g. the secrets bulk export/import row in §1), with text explicitly distinguishing it from the existing "Backup / Restore" row so a reader doesn't conflate the two.

- [ ] **Step 3: Update the Scorecard**

Add one to the ➕ column for "§4. Certificate management" (currently `6 | 1 | 2 | 0` after the sibling import/merge plan lands, becoming `6 | 1 | 2 | 1`) and the Total row's ➕ column. `➕` rows are excluded from the parity-percentage denominator per the Scorecard's own stated methodology, so the percentage figures do not change.

- [ ] **Step 4: Update the roadmap doc**

In `.claude/roadmap-azure-parity-and-beyond.md`'s Phase 3 ("Beyond Azure"), mark the "Certificate export (passphrase-sealed)" bullet (added 2026-08-25) closed.

- [ ] **Step 5: Update README's roadmap checklist**

If `README.md`'s roadmap checklist has a certificate-export line (unlikely, since Phase 3 items aren't typically checklisted the way Phase 1 is — verify at write time), mark it done; otherwise add a `### Shipped` entry in the most recent dated block.

- [ ] **Step 6: Update CLI, API, and integration-examples docs**

Add `certificates export` to `docs/cli-guide.md`, cross-referencing `secrets export`'s shared passphrase/env-var UX. Add `POST /certificates/export` to `docs/api-developer-guide.md`. Add a worked example to `docs/integration-examples.md` (per `.claude/known-bugs.md` § B51's lesson — update both docs, not just the guide).

- [ ] **Step 7: Commit**

```bash
git add .claude/azure-keyvault-parity.md .claude/roadmap-azure-parity-and-beyond.md README.md docs/cli-guide.md docs/api-developer-guide.md docs/integration-examples.md
git commit -m "docs: mark certificate export shipped"
```
