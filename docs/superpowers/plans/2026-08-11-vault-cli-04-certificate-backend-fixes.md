# Certificate Backend Fixes (Plan 04 of 5: Vault CLI Extension) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two backend defects that block genuine vault-scoping of certificate `update` and `renew`: `api/certificates.go`'s `updateCertificate` handler is hardcoded to an owner-only scope regardless of route shape, and `CertificateService.RenewCertificate` ignores any caller-supplied scope, hardcoding its own owner scope internally.

**Architecture:** Two independent, surgical fixes, both confined to `api/` and `internal/services/certificates/` (no CLI code touched). Fix 1 replaces `updateCertificate`'s hardcoded scope with the same `scopeFromRequest` pattern every other vault-scoped handler already uses. Fix 2 changes `RenewCertificate`'s signature to accept a `model.Scope` parameter instead of a bare `userID`, threading it through to the two internal call sites that used to construct their own scope, and updates the two permanent callers (the CA auto-renewal scheduler) plus the CLI's one call site with a deliberate, temporary stopgap (superseded by Plan 05).

**Tech Stack:** Go 1.24.2, `testify/mock`, table-driven `net/http/httptest` handler tests.

## Global Constraints

- This plan has no dependency on Plan 01, 02, or 03 of the `2026-08-11-vault-cli-extension-design.md` series — it only touches `api/certificates.go`, `internal/services/certificates/*`, their test files, and one CLI file with a stopgap edit.
- Plan 05 (certificates CLI wiring) depends on this plan: it consumes the frozen `RenewCertificate` signature produced by Task 2. Do not deviate from it:
  ```go
  RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)
  ```
- `Scope`'s audit-principal accessor is `(s Scope) ActorID() uuid.UUID` (`model/scope.go:65`) — use this exact method name everywhere a scope needs to yield a `uuid.UUID` for audit logging or an internal admin-scoped lookup. This is the name Plan 05 will also rely on.
- The edit to `cmd/certificates/renew.go` in Task 3 is a deliberate, temporary stopgap: it preserves the exact pre-existing owner-only, no-vault-flag behavior (`model.NewOwnerScope(uuid.Nil, claims.UserID)`), not a design decision. Plan 05 replaces it with a real vault-scoped, `RequireDataAction`-gated call.
- `go build ./...` and `go vet ./...` must be clean after Task 1 and after Task 3. After Task 2 specifically, `go build ./...` is expected to report exactly one failure — `cmd/certificates/renew.go:62`, a genuine type mismatch against the new interface — because Task 3 (not Task 2) is where that call site is fixed; this is documented and verified explicitly in Task 2's own verification step, not silently left broken. Every other package (including `internal/services/certificates` and `api`) must build and vet clean after Task 2.
- Documentation follow-up (not fixed in this plan): `.claude/multi-vault.md` (lines ~109–115 and ~125–126) still describes certificate `update` as hardcoded-owner-only and lists `PUT /vaults/{n}/certificates/{id}` as a route that "still ignores its vault." Both are made stale by Task 1 of this plan. A future doc pass should update that file; this plan does not touch it.
- `cmd/certificates/service_test.go`'s `MockCertificateService` type is a legacy, self-contained mock with a `GetCertificate(ctx, certID, userID uuid.UUID)` / `ListCertificates(ctx, userID uuid.UUID)` shape that already does not match the current `CertificateService` interface (which takes `model.Scope`), and it is never assigned to the `certServices.CertificateService` interface type anywhere in that file — it's only ever used via its own concrete type. It is verified out of scope for both fixes in this plan; do not edit it.

---

### Task 1: Fix `updateCertificate` to use `scopeFromRequest` instead of a hardcoded owner scope

**Files:**
- Modify: `api/certificates.go:299-368` (`updateCertificate` handler)
- Modify: `api/certificates_test.go:574-599` (`TestUpdateCertificate_Success_Returns200`)
- Modify: `api/certificates_extra_test.go:150-181` (`TestUpdateCertificate_MultipleFieldsUpdated_Returns200`)
- Modify: `api/vault_scoped_keys_certs_test.go` (`recordingCertService` struct/methods, plus two new tests)

**Interfaces:**
- Consumes: `scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool)` — already defined in `api/context.go:64`, already used by `updateKey` (`api/keys.go:462`) and every other vault-scoped handler in this file (`listCertificates`, `getCertificate`).
- Consumes: `certServices.UpdateCertificateRequest{CertID, Scope, Name, Tags, AutoRenew, RenewalDays, Enabled, NotBefore}` — already has a `Scope model.Scope` field (`internal/services/certificates/certificate_service.go:66-75`); no service-layer change needed for this fix.
- Produces: nothing consumed by Task 2 or Task 3 — this task is self-contained.

- [ ] **Step 1: Give `recordingCertService.UpdateCertificate` real recording behavior instead of panicking**

  In `api/vault_scoped_keys_certs_test.go`, add four fields to the `recordingCertService` struct (mirroring the existing `recordingKeyService` fields immediately above it):

  ```go
  // recordingCertService records which list/get method was called and with what
  // scope, mirroring recordingKeyService for certificates.
  type recordingCertService struct {
  	listCalled     bool
  	listUserScoped bool
  	listUserID     uuid.UUID
  	listVaultID    uuid.UUID
  	getCalled      bool
  	getUserScoped  bool

  	updateCalled      bool
  	updateVaultScoped bool
  	updateVaultID     uuid.UUID
  	updateUserID      uuid.UUID

  	// getInVaultErr, when set, is returned by GetCertificateInVault instead of
  	// a synthetic certificate -- simulates the vault-membership pre-check
  	// failing (e.g. the certificate does not belong to the resolved vault).
  	getInVaultErr error
  }
  ```

  Replace the panicking `UpdateCertificate` method:

  ```go
  func (s *recordingCertService) UpdateCertificate(context.Context, certServices.UpdateCertificateRequest) error {
  	panic("unexpected")
  }
  ```

  with a recording implementation matching `recordingKeyService.UpdateKey`:

  ```go
  func (s *recordingCertService) UpdateCertificate(_ context.Context, req certServices.UpdateCertificateRequest) error {
  	s.updateCalled = true
  	s.updateVaultScoped = req.Scope.Kind() == model.ScopeVault
  	s.updateVaultID = req.Scope.VaultID()
  	s.updateUserID = req.Scope.ActorID()
  	return nil
  }
  ```

- [ ] **Step 2: Add the two vault-scope regression tests, mirroring the existing key tests**

  In `api/vault_scoped_keys_certs_test.go`, add these two tests right after `TestVaultScopedCertRoute_UsesVaultScopedListing`:

  ```go
  // TestVaultScopedCertRoute_UsesVaultScopedUpdate verifies that PUT on the
  // explicit /vaults/{name}/certificates/{id} route dispatches with a vault
  // scope, proving the updateCertificate fix: it is no longer hardcoded to an
  // owner scope regardless of route shape.
  func TestVaultScopedCertRoute_UsesVaultScopedUpdate(t *testing.T) {
  	rec := &recordingCertService{}
  	api, repo := newVaultScopedKeyCertTestAPI(nil, rec, nil)

  	id := uuid.New()
  	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
  	repo.byID[id.String()] = repo.byName["prod"]

  	certID := uuid.New()
  	body := []byte(`{"name":"new-name"}`)
  	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/certificates/"+certID.String(), body)

  	if w.Code != http.StatusOK {
  		t.Fatalf("vault-scoped PUT /vaults/prod/certificates/%s: expected 200, got %d (%s)", certID, w.Code, w.Body.String())
  	}
  	if !rec.updateCalled {
  		t.Fatalf("vault-scoped route did not dispatch to the certificate update handler")
  	}
  	if !rec.updateVaultScoped {
  		t.Fatalf("vault-scoped /certificates/{id} PUT must use a vault scope, not an owner scope")
  	}
  	if rec.updateVaultID != id {
  		t.Fatalf("update dispatched with vault ID %s, want %s", rec.updateVaultID, id)
  	}
  }

  // TestLegacyFlatCertRoute_UsesUserScopedUpdate verifies that PUT on the legacy
  // flat /certificates/{id} route still dispatches with an owner scope,
  // preserving pre-fix behaviour for callers that never adopted vault-scoped
  // routes.
  func TestLegacyFlatCertRoute_UsesUserScopedUpdate(t *testing.T) {
  	rec := &recordingCertService{}
  	api, _ := newVaultScopedKeyCertTestAPI(nil, rec, nil)

  	certID := uuid.New()
  	body := []byte(`{"name":"new-name"}`)
  	w := doVaultRequest(api, http.MethodPut, "/api/v1/certificates/"+certID.String(), body)

  	if w.Code != http.StatusOK {
  		t.Fatalf("legacy PUT /certificates/%s: expected 200, got %d (%s)", certID, w.Code, w.Body.String())
  	}
  	if !rec.updateCalled {
  		t.Fatalf("legacy route did not dispatch to the certificate update handler")
  	}
  	if rec.updateVaultScoped {
  		t.Fatalf("legacy /certificates/{id} PUT must use an owner scope, not a vault scope")
  	}
  	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
  		t.Fatalf("legacy route scoped update to user %s, want caller %s", rec.updateUserID, vaultTestUserID)
  	}
  }
  ```

- [ ] **Step 3: Update `TestUpdateCertificate_Success_Returns200` to expect the post-fix scope**

  In `api/certificates_test.go`, replace:

  ```go
  	svc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(nil)
  	// updateCertificate builds an owner scope with an advisory nil vault id
  	// (see api/certificates.go: it is not yet vault-scope aware).
  	svc.On("GetCertificate", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Certificate{
  		ID: certID, Name: "new-name", UserID: userID, CreatedAt: time.Now(),
  	}, nil)
  ```

  with:

  ```go
  	svc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(nil)
  	// Legacy flat route (no vault_name) yields an owner scope, same as
  	// getCertificate/listCertificates on this same route shape.
  	svc.On("GetCertificate", mock.Anything, certID, certLegacyOwnerScope()).Return(&model.Certificate{
  		ID: certID, Name: "new-name", UserID: userID, CreatedAt: time.Now(),
  	}, nil)
  ```

  (`certLegacyOwnerScope()` is already defined at `api/certificates_test.go:261-263`; `userID` in this test is still needed for the returned `model.Certificate`'s `UserID` field, so keep its declaration.)

- [ ] **Step 4: Update `TestUpdateCertificate_MultipleFieldsUpdated_Returns200` the same way**

  In `api/certificates_extra_test.go`, replace:

  ```go
  func TestUpdateCertificate_MultipleFieldsUpdated_Returns200(t *testing.T) {
  	certID := uuid.New()
  	userID := uuid.MustParse(certTestUserID)
  	svc := &mockCertService{}
  	// updateCertificate builds an owner scope with an advisory nil vault id
  	// (see api/certificates.go: it is not yet vault-scope aware).
  	svc.On("GetCertificate", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(
  		&model.Certificate{
  			ID:   certID,
  			Name: "original-name",
  		}, nil,
  	)
  ```

  with:

  ```go
  func TestUpdateCertificate_MultipleFieldsUpdated_Returns200(t *testing.T) {
  	certID := uuid.New()
  	svc := &mockCertService{}
  	// Legacy flat route (no vault_name) yields an owner scope, same as
  	// getCertificate/listCertificates on this same route shape.
  	svc.On("GetCertificate", mock.Anything, certID, certLegacyOwnerScope()).Return(
  		&model.Certificate{
  			ID:   certID,
  			Name: "original-name",
  		}, nil,
  	)
  ```

  (`userID` was only used in the deleted line — remove its declaration entirely; the rest of the test function is unchanged.)

- [ ] **Step 5: Run the updated/new tests and confirm they fail against the current handler**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestVaultScopedCertRoute_UsesVaultScopedUpdate|TestUpdateCertificate_Success_Returns200|TestUpdateCertificate_MultipleFieldsUpdated_Returns200" -v`

  Expected: `TestVaultScopedCertRoute_UsesVaultScopedUpdate` FAILs (`rec.updateVaultScoped` is `false` because the handler still hardcodes an owner scope regardless of route). `TestUpdateCertificate_Success_Returns200` and `TestUpdateCertificate_MultipleFieldsUpdated_Returns200` FAIL with a testify "mock: I don't know what to return" panic, because the handler still calls `GetCertificate` with `model.NewOwnerScope(uuid.Nil, userID)`, which no longer matches the `certLegacyOwnerScope()` expectation.

- [ ] **Step 6: Fix `updateCertificate` in `api/certificates.go`**

  Replace the full function body (`api/certificates.go:299-368`):

  ```go
  // updateCertificate updates an existing certificate's metadata.
  func updateCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
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

  	var req UpdateCertificateAPIRequest
  	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
  		c.SetInvalidParam("request body")
  		return
  	}

  	if req.Name == nil && req.Tags == nil && req.AutoRenew == nil && req.RenewalDays == nil && req.Enabled == nil && req.NotBefore == nil {
  		c.SetInvalidParam("at least one update field must be provided")
  		return
  	}

  	certService := c.certSvc()
  	if certService == nil {
  		return
  	}

  	// Preserves the pre-refactor owner-scope semantics of the deleted
  	// UpdateCertificate shim: this handler is not yet vault-scope aware (see
  	// .claude/multi-vault.md's keys/certs deferral).
  	scope := model.NewOwnerScope(uuid.Nil, userID)

  	updateReq := certServices.UpdateCertificateRequest{
  		CertID:      certID,
  		Scope:       scope,
  		Name:        req.Name,
  		Tags:        req.Tags,
  		AutoRenew:   req.AutoRenew,
  		RenewalDays: req.RenewalDays,
  		Enabled:     req.Enabled,
  		NotBefore:   req.NotBefore,
  	}

  	if err := certService.UpdateCertificate(r.Context(), updateReq); err != nil {
  		writeCertificateError(c, err)
  		return
  	}

  	// Fetch updated certificate for response. The read-back can legitimately
  	// be lifecycle-denied — the update may have just disabled the certificate,
  	// or it may already have expired — so map it like any other lifecycle
  	// denial rather than reporting an internal error for a write that
  	// succeeded.
  	cert, err := certService.GetCertificate(r.Context(), certID, scope)
  	if err != nil {
  		writeCertificateError(c, err)
  		return
  	}

  	w.Header().Set("Content-Type", "application/json")
  	json.NewEncoder(w).Encode(certToDomainResponse(cert))
  }
  ```

  with (the manual `userIDStr`/`userID` claim parse is deleted — `scopeFromRequest` resolves the actor internally — and the hardcoded scope + stale comment are replaced, exactly mirroring `updateKey`'s structure at `api/keys.go:430-493`):

  ```go
  // updateCertificate updates an existing certificate's metadata.
  func updateCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
  	certID, err := uuid.Parse(c.Params.CertificateID)
  	if err != nil {
  		c.SetInvalidParam("certificate_id")
  		return
  	}

  	var req UpdateCertificateAPIRequest
  	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
  		c.SetInvalidParam("request body")
  		return
  	}

  	if req.Name == nil && req.Tags == nil && req.AutoRenew == nil && req.RenewalDays == nil && req.Enabled == nil && req.NotBefore == nil {
  		c.SetInvalidParam("at least one update field must be provided")
  		return
  	}

  	certService := c.certSvc()
  	if certService == nil {
  		return
  	}

  	scope, ok := scopeFromRequest(c, r)
  	if !ok {
  		return
  	}

  	updateReq := certServices.UpdateCertificateRequest{
  		CertID:      certID,
  		Scope:       scope,
  		Name:        req.Name,
  		Tags:        req.Tags,
  		AutoRenew:   req.AutoRenew,
  		RenewalDays: req.RenewalDays,
  		Enabled:     req.Enabled,
  		NotBefore:   req.NotBefore,
  	}

  	if err := certService.UpdateCertificate(r.Context(), updateReq); err != nil {
  		writeCertificateError(c, err)
  		return
  	}

  	// Fetch updated certificate for response. The read-back can legitimately
  	// be lifecycle-denied — the update may have just disabled the certificate,
  	// or it may already have expired — so map it like any other lifecycle
  	// denial rather than reporting an internal error for a write that
  	// succeeded.
  	cert, err := certService.GetCertificate(r.Context(), certID, scope)
  	if err != nil {
  		writeCertificateError(c, err)
  		return
  	}

  	w.Header().Set("Content-Type", "application/json")
  	json.NewEncoder(w).Encode(certToDomainResponse(cert))
  }
  ```

- [ ] **Step 7: Run the same tests again and confirm they pass**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestVaultScopedCertRoute_UsesVaultScopedUpdate|TestLegacyFlatCertRoute_UsesUserScopedUpdate|TestUpdateCertificate" -v`

  Expected: all tests PASS, including `TestUpdateCertificate_ServiceError_Returns500`, `TestUpdateCertificate_NotFound_Returns404`, `TestUpdateCertificate_InvalidCertID_Returns400`, `TestUpdateCertificate_NoFieldsProvided_Returns400` (`api/certificates_test.go`), `TestUpdateCertificate_ServiceError2_Returns500` (`api/extra_coverage_test.go`) — none of these were touched and none depended on the exact scope value, so they must still be green.

- [ ] **Step 8: Run the full build/vet check**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go vet ./...`

  Expected: both commands exit 0 with no output. This task touches only `api/certificates.go` and three `api/*_test.go` files, so nothing outside the `api` package is affected.

- [ ] **Step 9: Commit**

  ```bash
  git add api/certificates.go api/certificates_test.go api/certificates_extra_test.go api/vault_scoped_keys_certs_test.go
  git commit -m "$(cat <<'EOF'
  fix(api): make certificate update handler vault-scope aware

  updateCertificate hardcoded an owner-only scope regardless of route
  shape, unlike every other vault-scoped certificate/key handler. Switch
  to scopeFromRequest, the same pattern updateKey already uses, so
  PUT /vaults/{name}/certificates/{id} genuinely authorizes by vault
  membership instead of silently falling back to the caller's own
  certificates.
  EOF
  )"
  ```

---

### Task 2: Change `RenewCertificate` to accept an explicit `model.Scope`

**Files:**
- Modify: `internal/services/certificates/renewal_service_test.go` (`mockCertSvcForRenewal.RenewCertificate`, `TestCheckAndRenewCertificates_AutoRenew`)
- Modify: `internal/services/certificates/certificate_service_extended_test.go` (`TestRenewCertificate_NoKeyID`, `TestRenewCertificate_GetCertificateFails`, `mockRenewalCertSvc.RenewCertificate`, `TestCheckAndRenewCertificates_AutoRenewFailureSkipped`)
- Modify: `internal/services/certificates/cert_soft_delete_test.go` (`TestRenewCertificate_Succeeds_WhenKeyIDSet`)
- Modify: `internal/services/certificates/certificate_service.go` (interface line + `RenewCertificate` implementation)
- Modify: `internal/services/certificates/renewal_service.go` (the scheduler's call site, plus a new `model` import)
- Modify: `internal/services/certificates/mocks/mock_CertificateService.go` (`RenewCertificate` mock + `_Expecter` companion)
- Modify: `api/certificates_test.go` (`mockCertService.RenewCertificate` — interface-conformance only, no behavior change)
- Modify: `api/vault_scoped_keys_certs_test.go` (`recordingCertService.RenewCertificate` — interface-conformance only, no behavior change)

**Interfaces:**
- Produces (frozen, consumed by Plan 05): `RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)` on `certServices.CertificateService`.
- Produces (consumed by Task 3): the scheduler's permanent call `s.certSvc.RenewCertificate(ctx, cert.ID, model.NewAdminScope(cert.UserID), validityDays)` in `internal/services/certificates/renewal_service.go`.
- Consumes: `model.NewAdminScope(actorID uuid.UUID) Scope` and `model.NewOwnerScope(vaultID, ownerID uuid.UUID) Scope` (`model/scope.go:47-56`); `(s Scope) ActorID() uuid.UUID` (`model/scope.go:65`).

- [ ] **Step 1: Update `mockCertSvcForRenewal.RenewCertificate` and its caller in `renewal_service_test.go`**

  In `internal/services/certificates/renewal_service_test.go`, replace:

  ```go
  func (m *mockCertSvcForRenewal) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*certificates.CreateCertificateResult, error) {
  	args := m.Called(ctx, certID, userID, validityDays)
  	if args.Get(0) == nil {
  		return nil, args.Error(1)
  	}
  	return args.Get(0).(*certificates.CreateCertificateResult), args.Error(1)
  }
  ```

  with:

  ```go
  func (m *mockCertSvcForRenewal) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certificates.CreateCertificateResult, error) {
  	args := m.Called(ctx, certID, scope, validityDays)
  	if args.Get(0) == nil {
  		return nil, args.Error(1)
  	}
  	return args.Get(0).(*certificates.CreateCertificateResult), args.Error(1)
  }
  ```

  and in `TestCheckAndRenewCertificates_AutoRenew`, replace:

  ```go
  	certSvc.On("RenewCertificate", mock.Anything, certID, userID, mock.AnythingOfType("int")).
  		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)
  ```

  with:

  ```go
  	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewAdminScope(userID), mock.AnythingOfType("int")).
  		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)
  ```

  (`model` is already imported in this file.)

- [ ] **Step 2: Update `certificate_service_extended_test.go`'s direct `RenewCertificate` calls, its scheduler mock, and its failure-branch test**

  Replace `TestRenewCertificate_NoKeyID`:

  ```go
  func TestRenewCertificate_NoKeyID(t *testing.T) {
  	userID := uuid.New()
  	certID := uuid.New()
  	certRepo := &mockCertRepository{}
  	keyRepo := &mockKeyRepo{}

  	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Certificate{
  		ID:      certID,
  		UserID:  userID,
  		Enabled: true,
  		KeyID:   uuid.Nil, // no key attached
  	}, nil)

  	svc := newCertSvc(certRepo, keyRepo)
  	_, err := svc.RenewCertificate(context.Background(), certID, userID, 365)
  	require.Error(t, err)
  	assert.Contains(t, err.Error(), "no associated key ID")
  }
  ```

  with:

  ```go
  func TestRenewCertificate_NoKeyID(t *testing.T) {
  	userID := uuid.New()
  	certID := uuid.New()
  	scope := model.NewOwnerScope(uuid.Nil, userID)
  	certRepo := &mockCertRepository{}
  	keyRepo := &mockKeyRepo{}

  	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
  		ID:      certID,
  		UserID:  userID,
  		Enabled: true,
  		KeyID:   uuid.Nil, // no key attached
  	}, nil)

  	svc := newCertSvc(certRepo, keyRepo)
  	_, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
  	require.Error(t, err)
  	assert.Contains(t, err.Error(), "no associated key ID")
  }
  ```

  Replace `TestRenewCertificate_GetCertificateFails`:

  ```go
  func TestRenewCertificate_GetCertificateFails(t *testing.T) {
  	userID := uuid.New()
  	certID := uuid.New()
  	certRepo := &mockCertRepository{}
  	keyRepo := &mockKeyRepo{}

  	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

  	svc := newCertSvc(certRepo, keyRepo)
  	_, err := svc.RenewCertificate(context.Background(), certID, userID, 365)
  	require.Error(t, err)
  }
  ```

  with:

  ```go
  func TestRenewCertificate_GetCertificateFails(t *testing.T) {
  	userID := uuid.New()
  	certID := uuid.New()
  	scope := model.NewOwnerScope(uuid.Nil, userID)
  	certRepo := &mockCertRepository{}
  	keyRepo := &mockKeyRepo{}

  	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

  	svc := newCertSvc(certRepo, keyRepo)
  	_, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
  	require.Error(t, err)
  }
  ```

  Replace `mockRenewalCertSvc.RenewCertificate`:

  ```go
  func (m *mockRenewalCertSvc) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*CreateCertificateResult, error) {
  	args := m.Called(ctx, certID, userID, validityDays)
  	if args.Get(0) == nil {
  		return nil, args.Error(1)
  	}
  	return args.Get(0).(*CreateCertificateResult), args.Error(1)
  }
  ```

  with:

  ```go
  func (m *mockRenewalCertSvc) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error) {
  	args := m.Called(ctx, certID, scope, validityDays)
  	if args.Get(0) == nil {
  		return nil, args.Error(1)
  	}
  	return args.Get(0).(*CreateCertificateResult), args.Error(1)
  }
  ```

  and in `TestCheckAndRenewCertificates_AutoRenewFailureSkipped`, replace:

  ```go
  	certSvc.On("RenewCertificate", mock.Anything, certID, userID, mock.AnythingOfType("int")).
  		Return(nil, errors.New("renewal failed"))
  ```

  with:

  ```go
  	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewAdminScope(userID), mock.AnythingOfType("int")).
  		Return(nil, errors.New("renewal failed"))
  ```

  (`model` is already imported in this file.)

- [ ] **Step 3: Update `cert_soft_delete_test.go`'s `TestRenewCertificate_Succeeds_WhenKeyIDSet`**

  Replace:

  ```go
  	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(existingCert, nil)

  	// keyRepo.Read is called twice with the same admin scope: once in
  	// ValidateKeyOwnership, once to get the key PEM.
  	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(mockKey, nil)

  	// Renewal must update the existing row in place (same ID/name), not insert a
  	// second row: certificates has a UNIQUE(vault_id, name) index, so inserting
  	// a new row while the original (same name) still exists always fails.
  	var updatedCert *model.Certificate
  	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), model.NewOwnerScope(uuid.Nil, userID)).
  		Run(func(args mock.Arguments) {
  			updatedCert = args.Get(1).(*model.Certificate)
  		}).
  		Return(nil)

  	logger := &logging.Logger{Logger: logrus.New()}
  	svc := NewCertificateService(CertificateServiceConfig{
  		CertificateRepository: certRepo,
  		KeyRepository:         keyRepo,
  		Logger:                logger,
  	})

  	result, err := svc.RenewCertificate(context.Background(), certID, userID, 365)
  ```

  with:

  ```go
  	scope := model.NewOwnerScope(uuid.Nil, userID)
  	certRepo.On("Read", mock.Anything, certID, scope).Return(existingCert, nil)

  	// keyRepo.Read is called twice with the same admin scope: once in
  	// ValidateKeyOwnership, once to get the key PEM.
  	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(mockKey, nil)

  	// Renewal must update the existing row in place (same ID/name), not insert a
  	// second row: certificates has a UNIQUE(vault_id, name) index, so inserting
  	// a new row while the original (same name) still exists always fails.
  	var updatedCert *model.Certificate
  	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).
  		Run(func(args mock.Arguments) {
  			updatedCert = args.Get(1).(*model.Certificate)
  		}).
  		Return(nil)

  	logger := &logging.Logger{Logger: logrus.New()}
  	svc := NewCertificateService(CertificateServiceConfig{
  		CertificateRepository: certRepo,
  		KeyRepository:         keyRepo,
  		Logger:                logger,
  	})

  	result, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
  ```

- [ ] **Step 4: Confirm the package fails to compile against the still-unchanged interface**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go vet ./internal/services/certificates/...`

  Expected: FAIL. The three test files now call `RenewCertificate`/build mocks with a `model.Scope` third argument, but `CertificateService.RenewCertificate` (in `certificate_service.go`) still declares `userID uuid.UUID` — every `RenewalServiceConfig{CertificateService: ...}` assignment and every direct `svc.RenewCertificate(...)` call fails to type-check.

- [ ] **Step 5: Change the interface and implementation in `certificate_service.go`**

  Replace the interface line (`internal/services/certificates/certificate_service.go:91`):

  ```go
  	RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*CreateCertificateResult, error)
  ```

  with:

  ```go
  	// RenewCertificate renews certID, authorized by scope. scope.ActorID() is
  	// also the audit-log principal and the identity used by the internal
  	// key-ownership checks below.
  	RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)
  ```

  Replace the full `RenewCertificate` implementation (`internal/services/certificates/certificate_service.go:488-583`):

  ```go
  // RenewCertificate creates a new certificate to replace an expiring one.
  // It generates a new certificate with the same properties as the original.
  //
  // Parameters:
  //
  //	ctx: The context for the operation.
  //	certID: The certificate to renew.
  //	userID: The requesting user's ID for access control.
  //	validityDays: The validity period for the new certificate.
  //
  // Returns:
  //
  //	The new certificate information or an error if renewal fails.
  func (s *certificateService) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*CreateCertificateResult, error) {
  	// Verify certificate exists and access; original carries AutoRenew/RenewalDays.
  	// An owner scope preserves the pre-refactor ownership check: this is the
  	// sole authorization gate for this path (unlike RotateKey/ValidateKeyAccess,
  	// there is no separate manual ownership comparison here).
  	scope := model.NewOwnerScope(uuid.Nil, userID)
  	original, err := s.GetCertificate(ctx, certID, scope)
  	if err != nil {
  		return nil, err
  	}

  	if original.KeyID == (uuid.UUID{}) {
  		return nil, fmt.Errorf("certificate has no associated key ID; cannot renew")
  	}

  	if validityDays <= 0 {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days must be positive", nil)
  		return nil, fmt.Errorf("validity days must be positive")
  	}

  	// Certificates are unique per (vault_id, name), so renewal must update the
  	// existing row in place rather than inserting a new one under the same
  	// name (CreateSelfSignedCertificate always mints a new ID/row and would
  	// collide with the certificate being renewed).
  	if err := s.ValidateKeyOwnership(ctx, original.KeyID, userID, ""); err != nil {
  		return nil, err
  	}

  	key, err := s.keyRepo.Read(ctx, original.KeyID, model.NewAdminScope(userID))
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to read key", err)
  		return nil, fmt.Errorf("failed to read key: %w", err)
  	}

  	privateKeyPEM, err := common.DecryptSecret(key.Value)
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to decrypt key", err)
  		return nil, fmt.Errorf("failed to decrypt key: %w", err)
  	}

  	certPEM, err := crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, key.Type, crypto.CertificateTemplate{
  		CommonName:   original.Name,
  		ValidityDays: validityDays,
  		IsCA:         true,
  	})
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to generate certificate", err)
  		return nil, fmt.Errorf("failed to generate renewed certificate: %w", err)
  	}

  	expiresAt, err := extractExpiresAt(certPEM)
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to parse certificate expiry", err)
  		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
  	}

  	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to encrypt private key", err)
  		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
  	}

  	updated := *original
  	updated.Certificate = certPEM
  	updated.PrivateKey = encryptedKey
  	updated.CreatedAt = time.Now()
  	updated.ExpiresAt = expiresAt

  	if err := s.certRepo.Update(ctx, &updated, scope); err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to store renewed certificate", err)
  		return nil, fmt.Errorf("failed to store renewed certificate: %w", err)
  	}

  	s.logger.LogAuditInfo(userID.String(), "renew_certificate", "success", fmt.Sprintf("certificate renewed: %s, ID: %s", updated.Name, updated.ID))

  	return &CreateCertificateResult{
  		CertID:    updated.ID,
  		Name:      updated.Name,
  		Tags:      updated.Tags,
  		CreatedAt: updated.CreatedAt,
  		ExpiresAt: expiresAt,
  	}, nil
  }
  ```

  with:

  ```go
  // RenewCertificate creates a new certificate to replace an expiring one.
  // It generates a new certificate with the same properties as the original.
  //
  // Parameters:
  //
  //	ctx: The context for the operation.
  //	certID: The certificate to renew.
  //	scope: The authorization scope for the read and the write; scope.ActorID()
  //	  is also used for audit logging and the internal key-ownership checks.
  //	validityDays: The validity period for the new certificate.
  //
  // Returns:
  //
  //	The new certificate information or an error if renewal fails.
  func (s *certificateService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error) {
  	userID := scope.ActorID()

  	// Verify certificate exists and access; original carries AutoRenew/RenewalDays.
  	original, err := s.GetCertificate(ctx, certID, scope)
  	if err != nil {
  		return nil, err
  	}

  	if original.KeyID == (uuid.UUID{}) {
  		return nil, fmt.Errorf("certificate has no associated key ID; cannot renew")
  	}

  	if validityDays <= 0 {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "validity days must be positive", nil)
  		return nil, fmt.Errorf("validity days must be positive")
  	}

  	// Certificates are unique per (vault_id, name), so renewal must update the
  	// existing row in place rather than inserting a new one under the same
  	// name (CreateSelfSignedCertificate always mints a new ID/row and would
  	// collide with the certificate being renewed).
  	if err := s.ValidateKeyOwnership(ctx, original.KeyID, userID, ""); err != nil {
  		return nil, err
  	}

  	key, err := s.keyRepo.Read(ctx, original.KeyID, model.NewAdminScope(userID))
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to read key", err)
  		return nil, fmt.Errorf("failed to read key: %w", err)
  	}

  	privateKeyPEM, err := common.DecryptSecret(key.Value)
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to decrypt key", err)
  		return nil, fmt.Errorf("failed to decrypt key: %w", err)
  	}

  	certPEM, err := crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, key.Type, crypto.CertificateTemplate{
  		CommonName:   original.Name,
  		ValidityDays: validityDays,
  		IsCA:         true,
  	})
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to generate certificate", err)
  		return nil, fmt.Errorf("failed to generate renewed certificate: %w", err)
  	}

  	expiresAt, err := extractExpiresAt(certPEM)
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to parse certificate expiry", err)
  		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
  	}

  	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
  	if err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to encrypt private key", err)
  		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
  	}

  	updated := *original
  	updated.Certificate = certPEM
  	updated.PrivateKey = encryptedKey
  	updated.CreatedAt = time.Now()
  	updated.ExpiresAt = expiresAt

  	if err := s.certRepo.Update(ctx, &updated, scope); err != nil {
  		s.logger.LogAuditError(userID.String(), "renew_certificate", "failed", "failed to store renewed certificate", err)
  		return nil, fmt.Errorf("failed to store renewed certificate: %w", err)
  	}

  	s.logger.LogAuditInfo(userID.String(), "renew_certificate", "success", fmt.Sprintf("certificate renewed: %s, ID: %s", updated.Name, updated.ID))

  	return &CreateCertificateResult{
  		CertID:    updated.ID,
  		Name:      updated.Name,
  		Tags:      updated.Tags,
  		CreatedAt: updated.CreatedAt,
  		ExpiresAt: expiresAt,
  	}, nil
  }
  ```

- [ ] **Step 6: Update the permanent scheduler call site in `renewal_service.go`**

  Add `"rocketvault/model"` to the import block:

  ```go
  import (
  	"context"
  	"time"

  	"rocketvault/internal/logging"
  	"rocketvault/internal/repositories"
  	"rocketvault/model"
  )
  ```

  Replace the call (`internal/services/certificates/renewal_service.go:85`):

  ```go
  			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, cert.UserID, validityDays)
  ```

  with (`ScopeAdmin`: the scheduler already found this exact cert row via its own `ListAll` query and has no caller identity to authorize against — it's a trusted internal caller, matching `model/scope.go`'s documented `ScopeAdmin` contract):

  ```go
  			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, model.NewAdminScope(cert.UserID), validityDays)
  ```

- [ ] **Step 7: Run the internal/services/certificates package tests and confirm everything passes**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go build ./internal/services/certificates/... && go vet ./internal/services/certificates/... && go test ./internal/services/certificates/... -v`

  Expected: build and vet clean; all tests PASS, including `TestRenewCertificate_NoKeyID`, `TestRenewCertificate_GetCertificateFails`, `TestRenewCertificate_Succeeds_WhenKeyIDSet`, `TestCheckAndRenewCertificates_AutoRenew`, `TestCheckAndRenewCertificates_WarnOnly`, `TestCheckAndRenewCertificates_AutoRenewFailureSkipped`, `TestCheckAndRenewCertificates_OutsideWindowSkipped`.

- [ ] **Step 8: Regenerate the `RenewCertificate` section of `mocks/mock_CertificateService.go`**

  Replace the full `RenewCertificate` mock + `_Expecter` block (`internal/services/certificates/mocks/mock_CertificateService.go:317-376`):

  ```go
  // RenewCertificate provides a mock function with given fields: ctx, certID, userID, validityDays
  func (_m *MockCertificateService) RenewCertificate(ctx context.Context, certID uuid.UUID, userID uuid.UUID, validityDays int) (*certificates.CreateCertificateResult, error) {
  	ret := _m.Called(ctx, certID, userID, validityDays)

  	if len(ret) == 0 {
  		panic("no return value specified for RenewCertificate")
  	}

  	var r0 *certificates.CreateCertificateResult
  	var r1 error
  	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID, int) (*certificates.CreateCertificateResult, error)); ok {
  		return rf(ctx, certID, userID, validityDays)
  	}
  	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, uuid.UUID, int) *certificates.CreateCertificateResult); ok {
  		r0 = rf(ctx, certID, userID, validityDays)
  	} else {
  		if ret.Get(0) != nil {
  			r0 = ret.Get(0).(*certificates.CreateCertificateResult)
  		}
  	}

  	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, uuid.UUID, int) error); ok {
  		r1 = rf(ctx, certID, userID, validityDays)
  	} else {
  		r1 = ret.Error(1)
  	}

  	return r0, r1
  }

  // MockCertificateService_RenewCertificate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RenewCertificate'
  type MockCertificateService_RenewCertificate_Call struct {
  	*mock.Call
  }

  // RenewCertificate is a helper method to define mock.On call
  //   - ctx context.Context
  //   - certID uuid.UUID
  //   - userID uuid.UUID
  //   - validityDays int
  func (_e *MockCertificateService_Expecter) RenewCertificate(ctx interface{}, certID interface{}, userID interface{}, validityDays interface{}) *MockCertificateService_RenewCertificate_Call {
  	return &MockCertificateService_RenewCertificate_Call{Call: _e.mock.On("RenewCertificate", ctx, certID, userID, validityDays)}
  }

  func (_c *MockCertificateService_RenewCertificate_Call) Run(run func(ctx context.Context, certID uuid.UUID, userID uuid.UUID, validityDays int)) *MockCertificateService_RenewCertificate_Call {
  	_c.Call.Run(func(args mock.Arguments) {
  		run(args[0].(context.Context), args[1].(uuid.UUID), args[2].(uuid.UUID), args[3].(int))
  	})
  	return _c
  }

  func (_c *MockCertificateService_RenewCertificate_Call) Return(_a0 *certificates.CreateCertificateResult, _a1 error) *MockCertificateService_RenewCertificate_Call {
  	_c.Call.Return(_a0, _a1)
  	return _c
  }

  func (_c *MockCertificateService_RenewCertificate_Call) RunAndReturn(run func(context.Context, uuid.UUID, uuid.UUID, int) (*certificates.CreateCertificateResult, error)) *MockCertificateService_RenewCertificate_Call {
  	_c.Call.Return(run)
  	return _c
  }
  ```

  with (following the same mockery-style shape `DeleteCertificate`/`GetCertificate` already use for their `model.Scope` parameter, adapted for the extra `validityDays` argument):

  ```go
  // RenewCertificate provides a mock function with given fields: ctx, certID, scope, validityDays
  func (_m *MockCertificateService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certificates.CreateCertificateResult, error) {
  	ret := _m.Called(ctx, certID, scope, validityDays)

  	if len(ret) == 0 {
  		panic("no return value specified for RenewCertificate")
  	}

  	var r0 *certificates.CreateCertificateResult
  	var r1 error
  	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, model.Scope, int) (*certificates.CreateCertificateResult, error)); ok {
  		return rf(ctx, certID, scope, validityDays)
  	}
  	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID, model.Scope, int) *certificates.CreateCertificateResult); ok {
  		r0 = rf(ctx, certID, scope, validityDays)
  	} else {
  		if ret.Get(0) != nil {
  			r0 = ret.Get(0).(*certificates.CreateCertificateResult)
  		}
  	}

  	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID, model.Scope, int) error); ok {
  		r1 = rf(ctx, certID, scope, validityDays)
  	} else {
  		r1 = ret.Error(1)
  	}

  	return r0, r1
  }

  // MockCertificateService_RenewCertificate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RenewCertificate'
  type MockCertificateService_RenewCertificate_Call struct {
  	*mock.Call
  }

  // RenewCertificate is a helper method to define mock.On call
  //   - ctx context.Context
  //   - certID uuid.UUID
  //   - scope model.Scope
  //   - validityDays int
  func (_e *MockCertificateService_Expecter) RenewCertificate(ctx interface{}, certID interface{}, scope interface{}, validityDays interface{}) *MockCertificateService_RenewCertificate_Call {
  	return &MockCertificateService_RenewCertificate_Call{Call: _e.mock.On("RenewCertificate", ctx, certID, scope, validityDays)}
  }

  func (_c *MockCertificateService_RenewCertificate_Call) Run(run func(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int)) *MockCertificateService_RenewCertificate_Call {
  	_c.Call.Run(func(args mock.Arguments) {
  		run(args[0].(context.Context), args[1].(uuid.UUID), args[2].(model.Scope), args[3].(int))
  	})
  	return _c
  }

  func (_c *MockCertificateService_RenewCertificate_Call) Return(_a0 *certificates.CreateCertificateResult, _a1 error) *MockCertificateService_RenewCertificate_Call {
  	_c.Call.Return(_a0, _a1)
  	return _c
  }

  func (_c *MockCertificateService_RenewCertificate_Call) RunAndReturn(run func(context.Context, uuid.UUID, model.Scope, int) (*certificates.CreateCertificateResult, error)) *MockCertificateService_RenewCertificate_Call {
  	_c.Call.Return(run)
  	return _c
  }
  ```

- [ ] **Step 9: Update the two API-package mocks for interface conformance (no behavior change — `RenewCertificate` is never exercised through HTTP)**

  In `api/certificates_test.go`, replace:

  ```go
  func (m *mockCertService) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*certServices.CreateCertificateResult, error) {
  	args := m.Called(ctx, certID, userID, validityDays)
  	if args.Get(0) == nil {
  		return nil, args.Error(1)
  	}
  	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
  }
  ```

  with:

  ```go
  func (m *mockCertService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certServices.CreateCertificateResult, error) {
  	args := m.Called(ctx, certID, scope, validityDays)
  	if args.Get(0) == nil {
  		return nil, args.Error(1)
  	}
  	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
  }
  ```

  In `api/vault_scoped_keys_certs_test.go`, replace:

  ```go
  func (s *recordingCertService) RenewCertificate(context.Context, uuid.UUID, uuid.UUID, int) (*certServices.CreateCertificateResult, error) {
  	panic("unexpected")
  }
  ```

  with:

  ```go
  func (s *recordingCertService) RenewCertificate(context.Context, uuid.UUID, model.Scope, int) (*certServices.CreateCertificateResult, error) {
  	panic("unexpected")
  }
  ```

- [ ] **Step 10: Run the `api` package's vet and tests and confirm clean**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go vet ./api/... && go test ./api/... -run Certificate -v`

  Expected: `go vet` clean; every `TestCertificate*`/`Test*Certificate*` test PASSes (nothing in `api` calls `RenewCertificate`, so this step only proves interface conformance didn't regress the certificate handler tests from Task 1).

- [ ] **Step 11: Run a repo-wide build and confirm the one expected, documented failure**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | tee /tmp/plan04-task2-build.log`

  Expected: exactly one failure, in `rocketvault/cmd/certificates`:

  ```
  # rocketvault/cmd/certificates
  cmd/certificates/renew.go:62:66: cannot use claims.UserID (variable of type uuid.UUID) as model.Scope value in argument to certService.RenewCertificate
  ```

  This is the deliberate, temporary gap this plan's Global Constraints section documents — Task 3 closes it in the same plan, before this branch is considered done. If any other package appears in the output, stop and investigate; only `cmd/certificates` may fail at this point.

- [ ] **Step 12: Commit**

  ```bash
  git add internal/services/certificates/certificate_service.go \
    internal/services/certificates/renewal_service.go \
    internal/services/certificates/mocks/mock_CertificateService.go \
    internal/services/certificates/renewal_service_test.go \
    internal/services/certificates/certificate_service_extended_test.go \
    internal/services/certificates/cert_soft_delete_test.go \
    api/certificates_test.go \
    api/vault_scoped_keys_certs_test.go
  git commit -m "$(cat <<'EOF'
  refactor(certificates)!: change RenewCertificate to accept an explicit scope

  RenewCertificate hardcoded its own owner scope internally, ignoring
  whatever scope the caller actually authorized. Accept model.Scope as a
  parameter instead, and use scope.ActorID() for the audit-log principal
  and the internal key-ownership checks. The automatic renewal scheduler
  now passes an admin scope (it already found the exact cert row via its
  own query and has no caller identity to check against).

  cmd/certificates/renew.go does not yet compile against this signature;
  that is fixed in the next commit as a deliberate, temporary stopgap
  pending the CLI's real --vault wiring.
  EOF
  )"
  ```

---

### Task 3: Stopgap fix for `cmd/certificates/renew.go` and final repo-wide verification

**Files:**
- Modify: `cmd/certificates/renew.go:62`
- Modify: `cmd/certificates/certs_cmd_test.go` (`certCmdCertService.RenewCertificate`, `TestCertRenewCmd_Success`, `TestCertRenewCmd_ServiceError`)

**Interfaces:**
- Consumes: the frozen `RenewCertificate(ctx, certID uuid.UUID, scope model.Scope, validityDays int)` signature produced by Task 2.
- Produces: nothing — Plan 05 replaces this call site entirely; nothing in this repo depends on its exact shape surviving.

- [ ] **Step 1: Update `certCmdCertService.RenewCertificate`'s signature in `certs_cmd_test.go`**

  Replace:

  ```go
  func (m *certCmdCertService) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*certServices.CreateCertificateResult, error) {
  	args := m.Called(ctx, certID, userID, validityDays)
  	if args.Get(0) == nil {
  		return nil, args.Error(1)
  	}
  	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
  }
  ```

  with:

  ```go
  func (m *certCmdCertService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certServices.CreateCertificateResult, error) {
  	args := m.Called(ctx, certID, scope, validityDays)
  	if args.Get(0) == nil {
  		return nil, args.Error(1)
  	}
  	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
  }
  ```

- [ ] **Step 2: Update the two test expectations that assert on the third argument**

  In `TestCertRenewCmd_Success`, replace:

  ```go
  	certSvc.On("RenewCertificate", mock.Anything, certID, userID, 365).Return(result, nil)
  ```

  with:

  ```go
  	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID), 365).Return(result, nil)
  ```

  In `TestCertRenewCmd_ServiceError`, replace:

  ```go
  	certSvc.On("RenewCertificate", mock.Anything, certID, userID, 180).Return(nil, fmt.Errorf("renew failed"))
  ```

  with:

  ```go
  	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID), 180).Return(nil, fmt.Errorf("renew failed"))
  ```

  (`model` is already imported in this file.)

- [ ] **Step 3: Confirm the package still fails to build (production call site not yet fixed)**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go build ./cmd/certificates/...`

  Expected: FAIL, same error as Task 2 Step 11 (`cmd/certificates/renew.go:62`). This confirms the test-side updates alone don't paper over the still-broken production call site.

- [ ] **Step 4: Apply the stopgap fix to `cmd/certificates/renew.go`**

  Replace (`cmd/certificates/renew.go:62`):

  ```go
  		result, err := certService.RenewCertificate(ctx, certID, claims.UserID, validityDays)
  ```

  with:

  ```go
  		// Stopgap: no --vault flag or vault resolution yet, so this preserves
  		// the exact pre-existing owner-only behaviour RenewCertificate used to
  		// hardcode internally. Plan 05 (vault CLI wiring) replaces this with a
  		// real vault-scoped call gated by vaultcli.RequireDataAction.
  		result, err := certService.RenewCertificate(ctx, certID, model.NewOwnerScope(uuid.Nil, claims.UserID), validityDays)
  ```

  (`model` and `uuid` are already imported in this file.)

- [ ] **Step 5: Run the cmd/certificates package tests and confirm everything passes**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go build ./cmd/certificates/... && go vet ./cmd/certificates/... && go test ./cmd/certificates/... -v`

  Expected: build and vet clean; all tests PASS, including `TestCertRenewCmd_Success`, `TestCertRenewCmd_ServiceError`, `TestCertRenewCmd_InvalidUUID`, `TestCertRenewCmd_InvalidValidityDays`, `TestCertRenewCmd_NoServiceContainer`, and every other `TestCert*Cmd*` test in the package (none of the other commands were touched).

- [ ] **Step 6: Run the full repo-wide build and vet**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go vet ./...`

  Expected: both commands exit 0 with no output — the gap documented after Task 2 is now closed.

- [ ] **Step 7: Run the full test suite for every package this plan touched**

  Run: `cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... ./cmd/certificates/... ./internal/services/certificates/... -v 2>&1 | tail -60`

  Expected: PASS across all three packages. Skim the full (non-tailed) output once locally if anything looks off — `tail -60` here is just to keep the command's own output manageable.

- [ ] **Step 8: Commit**

  ```bash
  git add cmd/certificates/renew.go cmd/certificates/certs_cmd_test.go
  git commit -m "$(cat <<'EOF'
  fix(cmd): stopgap RenewCertificate call site for the new scope signature

  RenewCertificate now takes a model.Scope instead of a bare userID
  (previous commit). cmd/certificates renew has no --vault flag yet, so
  this passes the exact owner scope RenewCertificate used to build
  internally, preserving today's behavior exactly. This is a deliberate,
  temporary stopgap: the vault CLI wiring plan replaces it with a real
  vault-scoped, role-gated call.
  EOF
  )"
  ```
