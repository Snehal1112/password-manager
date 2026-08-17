# Flat-Route Vault Scope Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close a High-severity cross-vault authorization bypass: on the legacy flat data-plane routes (`/api/v1/secrets/{id}`, `/api/v1/keys/{id}`, `/api/v1/certificates/{id}` and their sub-routes) the request is authorized against the **default** vault while the data lookup is vault-agnostic, keyed only on `user_id == caller` — so a caller can keep reading and writing resources they created in any *other* vault, even after their role assignment there is revoked.

**Architecture:** The bug lives in one branch of one helper. `scopeFromRequest` (`api/context.go:71`) returns `model.NewVaultScope` for `/vaults/{vault_name}/...` routes and `model.NewOwnerScope` for flat routes; `NewOwnerScope`'s repository predicate is `user_id = ?` with no vault term (`internal/repositories/scope_predicate.go:31-36`), while `NewVaultScope`'s is `vault_id = ?`. The vault ID is *already* resolved correctly for flat routes — `VaultResolutionMiddleware` resolves `model.DefaultVaultName` when there is no `vault_name` path variable (`internal/middleware/middleware.go:580-583`) and `vaultIDFromRequest` falls back to `model.DefaultVaultID` when the middleware is bypassed (`api/context.go:47-57`) — which is the same vault `PolicyMiddleware` authorized against. So the fix is to return a vault scope unconditionally, which makes all 35 call sites behave like the two handlers (`deleteSecret`, `deleteCertificate`) that were already hardened by hand against this exact bug. One direct `NewOwnerScope` call outside the helper (`api/keys.go:372`, `createKey`'s response read-back) changes with it.

**Tech Stack:** Go 1.24.2, `net/http`, Gorilla Mux, testify (`assert`/`require`/`mock`), in-memory SQLite (`github.com/mattn/go-sqlite3`) for the real-repository regression harnesses already present in `api/vault_cross_denial_test.go`.

**Spec:** `docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md` — §"Root cause", §"Blast radius", §"Design decisions" (fix the helper not the call sites; leave `deleteSecret`/`deleteCertificate` alone; no `ScopeOwner` retirement), §"Behavior changes", §"Not in scope", §"Testing".

## Global Constraints

- Go 1.24.2. No new module dependencies.
- Scopes are built only with `model.NewVaultScope` / `model.NewOwnerScope` / `model.NewAdminScope`. Hand-built `model.Scope{}` literals are banned outside `api/context.go` and `model/scope_test.go`, enforced by the `scope-gate` CI job (`.github/workflows/go.yml:120-160`). The two `return model.Scope{}, false` failure returns already inside `api/context.go` stay as they are — that file is the gate's single exception.
- Do **not** modify `model/scope.go`, `internal/repositories/scope_predicate.go`, `internal/services/keys/key_service.go`, `internal/services/keys/crypto_service.go`, `cmd/version.go`, or `internal/services/secrets/versioning_service.go`. Retiring `ScopeOwner` codebase-wide is explicitly out of scope (spec §"Not in scope").
- Code comments: short full sentences, ending with a punctuation mark. No emojis.
- Commits must be GPG-signed (`git commit -S`), per repo convention.
- Verification gate for every task: `go build ./...`, `go vet ./...`, and the package tests named in that task must pass before the commit step.

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `api/context.go` | Modify | `scopeFromRequest` returns `model.NewVaultScope` for every route shape; drop the now-unused `github.com/gorilla/mux` import |
| `api/keys.go` | Modify | `createKey`'s read-back at line 372 uses `NewVaultScope` instead of `NewOwnerScope` |
| `api/secrets.go` | Modify | Comment-only: `deleteSecret`'s explanation of why it builds its scope by hand (lines 614-616) |
| `api/certificates.go` | Modify | Comment-only: `deleteCertificate`'s equivalent explanation (lines 374-378) |
| `api/scope_helpers_test.go` | Modify | Flat-route scope test flips from owner scope to vault scope |
| `api/keys_crud_test.go` | Modify | `keyLegacyOwnerScope()` → `keyLegacyVaultScope()` (fixture shared by ~20 mock expectations) |
| `api/certificates_test.go` | Modify | `certLegacyOwnerScope()` → `certLegacyVaultScope()` (fixture shared by ~10 mock expectations) |
| `api/coverage_boost_test.go`, `api/extra_coverage_test.go`, `api/certificates_extra_test.go` | Modify | Follow the two fixture renames |
| `api/secrets_scope_test.go`, `api/keys_scope_test.go`, `api/certificates_scope_test.go`, `api/soft_delete_scope_test.go` | Modify | Flip `assert.Equal(t, model.ScopeOwner, ...)` scope-shape assertions |
| `api/soft_delete_extended_test.go` | Modify | Four flat-route `mock.MatchedBy` scope matchers |
| `api/vault_scoped_routes_test.go` | Modify | Four router-level flat-route secret tests |
| `api/vault_scoped_keys_certs_test.go` | Modify | Four router-level flat-route key/certificate tests |
| `api/flat_route_vault_scope_test.go` | Create | New behavioral regression tests (real SQLite repositories + real router) |
| `.claude/known-bugs.md` | Modify | New entry B11 |
| `.claude/multi-vault.md` | Modify | Correct the now-false "flat routes yield `ScopeOwner`" claims |
| `.claude/e2e-manual-testing-guide.md` | Modify | Annotate the certificates `PUT`/`DELETE` asymmetry finding as resolved |
| `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md` | Modify | Breaking-change note |

**Why Task 1 is one commit and not several.** The production change and the ~60 stale test expectations are a single atomic unit: `keyLegacyOwnerScope()`/`certLegacyOwnerScope()` are also used by `createKey`'s read-back expectations, and every scope-shape assertion in the package encodes the old behavior. Splitting them leaves the `api` package red at a task boundary, which no reviewer can gate on.

---

## Task 1: Flat routes build a vault scope

**Files:**
- Modify: `api/context.go:59-87` (`scopeFromRequest`), `api/context.go:3-20` (imports)
- Modify: `api/keys.go:372` (`createKey` read-back)
- Modify: `api/secrets.go:614-616`, `api/certificates.go:374-378` (comments only)
- Modify: `api/scope_helpers_test.go:49-61`
- Modify: `api/keys_crud_test.go:299-306`, `api/certificates_test.go:305-311`
- Modify: `api/secrets_scope_test.go:95`, `api/keys_scope_test.go:117`, `api/certificates_scope_test.go:115,270,293,315,334`, `api/soft_delete_scope_test.go:73`
- Modify: `api/soft_delete_extended_test.go:553-641,682-747`
- Modify: `api/vault_scoped_routes_test.go:196-219,249-273,299-321,347-369`
- Modify: `api/vault_scoped_keys_certs_test.go` — the four flat-route tests at lines 405, 477, 501 and 576
- Modify (rename only): `api/coverage_boost_test.go`, `api/extra_coverage_test.go`, `api/certificates_extra_test.go`

**Interfaces:**
- Consumes: `model.NewVaultScope(vaultID, actorID uuid.UUID) model.Scope`, `vaultIDFromRequest(r *http.Request) (uuid.UUID, error)`, `userIDFromClaims(c *Context) (uuid.UUID, bool)` — all already exist and are unchanged.
- Produces: `scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool)` — same signature, now always returns a `model.ScopeVault` scope on success. Test fixtures `keyLegacyVaultScope() model.Scope` and `certLegacyVaultScope() model.Scope` replace the `*OwnerScope` names and return `model.NewVaultScope(uuid.MustParse(model.DefaultVaultID), uuid.MustParse(<keyTestUserID|certTestUserID>))`.

- [ ] **Step 1: Write the failing test**

In `api/scope_helpers_test.go`, replace `TestScopeFromRequestFlatRouteYieldsOwnerScope` (lines 49-61) in full with:

```go
// TestScopeFromRequestFlatRouteYieldsVaultScope pins the fix for the
// 2026-08-16 pentest finding H2. A legacy flat route must resolve to a vault
// scope carrying the vault the request was authorized against. An owner scope
// here filtered on user_id with no vault term at all, so a caller could read
// and write their own resources in any other vault.
func TestScopeFromRequestFlatRouteYieldsVaultScope(t *testing.T) {
	vaultID, userID := uuid.New(), uuid.New()
	c := newScopeContext(userID)

	scope, ok := scopeFromRequest(c, newScopeRequest(t, vaultID, ""))
	require.True(t, ok)
	assert.Equal(t, model.ScopeVault, scope.Kind())
	assert.Equal(t, vaultID, scope.VaultID(), "a flat route targets the vault it was authorized against")
	assert.Equal(t, userID, scope.ActorID(), "the actor travels for audit")

	_, isOwnerScoped := scope.OwnerID()
	assert.False(t, isOwnerScoped, "ownership is never an access predicate on the data plane")
	assert.NoError(t, scope.Validate())
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./api/ -run TestScopeFromRequestFlatRouteYieldsVaultScope -v`
Expected: FAIL — `Error: Not equal: expected: 1 (model.ScopeVault) actual: 2 (model.ScopeOwner)`.

- [ ] **Step 3: Fix `scopeFromRequest`**

In `api/context.go`, replace the doc comment and body of `scopeFromRequest` (lines 59-87) with:

```go
// scopeFromRequest builds the authorization scope for a resource operation. It
// is the only scope constructor on the data plane: ownership is provenance and
// audit metadata, never an access predicate. Crypto operations are gated by the
// Key Vault Crypto User role at vault scope, not by who created the key.
//
// Every route shape yields a vault scope. Vault-scoped routes
// (/api/v1/vaults/{vault_name}/...) carry the vault resolved from the path;
// legacy flat routes carry the default vault, which is the same vault
// PolicyMiddleware authorized the request against, because
// VaultResolutionMiddleware resolves model.DefaultVaultName for any route with
// no vault_name variable.
//
// Flat routes used to yield an owner scope, whose SQL predicate is "user_id = ?"
// with no vault term (internal/repositories/scope_predicate.go). That let a
// caller authorized against the default vault read and write their own
// resources in any other vault, surviving revocation of their role assignment
// there. See docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md.
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

	return model.NewVaultScope(vaultID, userID), true
}
```

Then remove the now-unused import — line 83 was the only use of `mux` in this file. Delete `"github.com/gorilla/mux"` from the import block at `api/context.go:3-20`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./api/ -run TestScopeFromRequestFlatRouteYieldsVaultScope -v`
Expected: PASS. (`go build ./api/` must also succeed — if it reports `"github.com/gorilla/mux" imported and not used`, the import removal in Step 3 was missed.)

- [ ] **Step 5: Remove the last owner scope on the request path**

In `api/keys.go`, line 372 inside `createKey`, change the response read-back:

```go
	// Fetch the full key record so buildKeyResponse can inspect the stored value.
	key, err := keyService.GetKey(r.Context(), result.KeyID, model.NewVaultScope(vaultID, userID))
```

Verify nothing else in the package constructs an owner scope:

Run: `grep -rn "NewOwnerScope" api/`
Expected: only matches inside `*_test.go` fixtures, which Step 6 removes; no matches in non-test files.

- [ ] **Step 6: Rename the two legacy scope fixtures and flip their bodies**

From the repo root:

```bash
grep -rl "keyLegacyOwnerScope" api/ | xargs sed -i 's/keyLegacyOwnerScope/keyLegacyVaultScope/g'
grep -rl "certLegacyOwnerScope" api/ | xargs sed -i 's/certLegacyOwnerScope/certLegacyVaultScope/g'
```

Then replace the fixture definition in `api/keys_crud_test.go` (lines 299-306) with:

```go
// keyLegacyVaultScope is the exact scope scopeFromRequest builds for a legacy
// flat route (no vault_name mux var): a vault scope carrying the default vault
// id and keyTestUserID as the actor. Flat routes used to yield an owner scope
// here, which is the 2026-08-16 cross-vault bypass this fixture now pins shut.
func keyLegacyVaultScope() model.Scope {
	return model.NewVaultScope(uuid.MustParse(model.DefaultVaultID), uuid.MustParse(keyTestUserID))
}
```

And in `api/certificates_test.go` (lines 305-311):

```go
// certLegacyVaultScope is the exact scope scopeFromRequest builds for a legacy
// flat route (no vault_name mux var): a vault scope carrying the default vault
// id and certTestUserID as the actor. Flat routes used to yield an owner scope
// here, which is the 2026-08-16 cross-vault bypass this fixture now pins shut.
func certLegacyVaultScope() model.Scope {
	return model.NewVaultScope(uuid.MustParse(model.DefaultVaultID), uuid.MustParse(certTestUserID))
}
```

Run: `go vet ./api/`
Expected: no output (the package still compiles; assertions may now fail, which later steps fix).

- [ ] **Step 7: Flip the direct scope-shape assertions**

Four one-line assertions, each currently `assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())` on a flat-route call:

- `api/secrets_scope_test.go:95` (in `TestGetSecretUsesTheScopeFromTheRoute`) → `assert.Equal(t, model.ScopeVault, svc.lastScope.Kind(), "flat routes are vault-scoped to the default vault")`
- `api/keys_scope_test.go:117` (in `TestListKeysUsesTheScopeFromTheRoute`) → same replacement text.
- `api/certificates_scope_test.go:115` (in `TestListCertificatesUsesTheScopeFromTheRoute`) → same replacement text.
- `api/soft_delete_scope_test.go:73` (in `TestPurgeSecretOutOfScopeReturns404`) → `assert.Equal(t, model.ScopeVault, svc.lastScope.Kind(), "flat routes are vault-scoped to the default vault")`

`TestGetSecretUsesTheScopeFromTheRoute`, `TestListKeysUsesTheScopeFromTheRoute` and `TestListCertificatesUsesTheScopeFromTheRoute` each exercise both route shapes and will now assert the same kind twice. Keep both halves: route-shape independence is exactly the property under test.

Four more in `api/certificates_scope_test.go` at lines 270, 293, 315 and 334 (the flat-route certificate-policy tests) → replace `model.ScopeOwner` with `model.ScopeVault` in each. Also update that file's explanatory comment block at lines 191-213: replace the sentence

```
// closes both gaps: all three handlers now authorize on "does the caller own
// the certificate" (certificates.user_id, via the scope), then use the
```

with

```
// closes both gaps: all three handlers now authorize on "is the certificate in
// the caller's resolved vault" (certificates.vault_id, via the scope — an owner
// scope here was the 2026-08-16 cross-vault bypass), then use the
```

and at line 235 replace `// variable, so scopeFromRequest yields an owner scope) for a` with `// variable, so scopeFromRequest yields a default-vault scope) for a`.

- [ ] **Step 8: Rewrite the four flat-route soft-delete matchers**

In `api/soft_delete_extended_test.go`, four tests assert an owner-scope matcher. For each, rename the test and replace the matcher. `TestRecoverKey_FlatRoute_UsesOwnerScope` (line 553) becomes:

```go
func TestRecoverKey_FlatRoute_UsesDefaultVaultScope(t *testing.T) {
	keyID := uuid.New()
	wantActorID := uuid.MustParse(keyTestUserID)
	wantVaultID := uuid.MustParse(model.DefaultVaultID)
	svc := &mockKeyService{}
	svc.On("RecoverKey", mock.Anything, keyID, mock.MatchedBy(func(s model.Scope) bool {
		_, ownerScoped := s.OwnerID()
		return s.Kind() == model.ScopeVault && !ownerScoped &&
			s.VaultID() == wantVaultID && s.ActorID() == wantActorID
	})).Return(nil)
```

Apply the identical matcher rewrite (keeping each test's own service mock, method name and request) to:

- `TestPurgeKey_FlatRoute_UsesOwnerScope` (line 596) → `TestPurgeKey_FlatRoute_UsesDefaultVaultScope`, mocks `"PurgeKey"`, uses `keyTestUserID`.
- `TestRecoverCertificate_FlatRoute_UsesOwnerScope` (line 682) → `TestRecoverCertificate_FlatRoute_UsesDefaultVaultScope`, mocks `"RecoverCertificate"`, uses `certTestUserID`.
- `TestPurgeCertificate_FlatRoute_UsesOwnerScope` (line 725) → `TestPurgeCertificate_FlatRoute_UsesDefaultVaultScope`, mocks `"PurgeCertificate"`, uses `certTestUserID`.

Finally update the section comment at lines 530-544: replace

```
// Mirrors soft_delete_scope_test.go's secrets coverage: proves the flat
// route builds an owner scope and the vault-scoped route builds a vault
// scope, now that keys/certs go through the same scopeFromRequest path.
```

with

```
// Mirrors soft_delete_scope_test.go's secrets coverage: proves the flat route
// builds a vault scope pinned to the default vault and the vault-scoped route
// builds one pinned to the resolved vault. Neither shape may build an owner
// scope — that was the 2026-08-16 cross-vault bypass.
```

- [ ] **Step 9: Rewrite the four router-level flat-route secret tests**

In `api/vault_scoped_routes_test.go`:

`TestLegacyFlatRoute_UsesUserScopedListing` (comment from line 196, function at 200) becomes:

```go
// TestLegacyFlatRoute_UsesDefaultVaultScopedListing verifies that the legacy
// flat /secrets route lists the default vault, not the caller's rows across
// every vault. Vault-level "members see all" visibility now applies to both
// route shapes; only the targeted vault differs.
func TestLegacyFlatRoute_UsesDefaultVaultScopedListing(t *testing.T) {
	rec := &recordingSecretService{}
	api, _ := newVaultScopedTestAPI(rec)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/secrets")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /secrets: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the secret list handler")
	}
	if rec.listScope.Kind() != model.ScopeVault {
		t.Fatalf("legacy route must use a vault scope, got %s", rec.listScope.String())
	}
	if rec.listScope.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy route scoped to vault %s, want the default vault", rec.listScope.VaultID())
	}
	if rec.listScope.ActorID() != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route actor %s, want caller %s", rec.listScope.ActorID(), vaultTestUserID)
	}
}
```

`TestLegacyFlatRoute_UsesUserScopedUpdate` (comment from line 249, function at 250) becomes:

```go
// TestLegacyFlatRoute_UsesDefaultVaultScopedUpdate verifies that PUT on the
// legacy flat /secrets/{id} route updates within the default vault, not by
// ownership across every vault.
func TestLegacyFlatRoute_UsesDefaultVaultScopedUpdate(t *testing.T) {
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
	if rec.updateScope.Kind() != model.ScopeVault {
		t.Fatalf("legacy /secrets/{id} PUT must use a vault scope, got %s", rec.updateScope.String())
	}
	if rec.updateScope.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy update scoped to vault %s, want the default vault", rec.updateScope.VaultID())
	}
	if rec.updateScope.ActorID() != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route actor %s, want caller %s", rec.updateScope.ActorID(), vaultTestUserID)
	}
}
```

`TestLegacyFlatRoute_UsesUserScopedVersionsList` (comment from line 299, function at 303) becomes:

```go
// TestLegacyFlatRoute_UsesDefaultVaultScopedVersionsList verifies that GET on
// the legacy flat /secrets/{id}/versions route looks the secret up in the
// default vault rather than by ownership across every vault.
func TestLegacyFlatRoute_UsesDefaultVaultScopedVersionsList(t *testing.T) {
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
	if rec.versionsScope.Kind() != model.ScopeVault {
		t.Fatalf("legacy .../versions GET must use a vault scope, got %s", rec.versionsScope.String())
	}
	if rec.versionsScope.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy .../versions scoped to vault %s, want the default vault", rec.versionsScope.VaultID())
	}
}
```

`TestLegacyFlatRoute_ExportUsesOwnerScope` (comment from line 347, function at 351) becomes:

```go
// TestLegacyFlatRoute_ExportUsesDefaultVaultScope verifies that POST on the
// legacy flat /secrets/export route exports the default vault, not the
// caller's rows across every vault.
func TestLegacyFlatRoute_ExportUsesDefaultVaultScope(t *testing.T) {
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
	if rec.exportScope.Kind() != model.ScopeVault {
		t.Fatalf("legacy /secrets/export must use a vault scope, got %s", rec.exportScope.String())
	}
	if rec.exportScope.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy export scoped to vault %s, want the default vault", rec.exportScope.VaultID())
	}
}
```

- [ ] **Step 10: Rewrite the four router-level flat-route key/certificate tests**

In `api/vault_scoped_keys_certs_test.go`, the recorder fields `getUserScoped`/`listUserScoped`/`updateVaultScoped` stay as they are (the vault-scoped tests still assert on them). Only the four flat-route tests change.

`TestLegacyFlatKeyRoute_UsesUserScopedListing` (line 405) becomes:

```go
// TestLegacyFlatKeyRoute_UsesDefaultVaultScopedListing verifies the legacy flat
// /keys route lists the default vault rather than the caller's keys across
// every vault.
func TestLegacyFlatKeyRoute_UsesDefaultVaultScopedListing(t *testing.T) {
	rec := &recordingKeyService{}
	api, _ := newVaultScopedKeyCertTestAPI(rec, nil, nil)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/keys")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /keys: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the key list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("legacy /keys must no longer build an owner scope")
	}
	if rec.listVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy /keys scoped to vault %s, want the default vault", rec.listVaultID)
	}
	if rec.listUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy /keys actor %s, want caller %s", rec.listUserID, vaultTestUserID)
	}
}
```

`TestLegacyFlatKeyRoute_UsesUserScopedUpdate` (line 477) becomes:

```go
// TestLegacyFlatKeyRoute_UsesDefaultVaultScopedUpdate verifies that PUT on the
// legacy flat /keys/{id} route updates within the default vault.
func TestLegacyFlatKeyRoute_UsesDefaultVaultScopedUpdate(t *testing.T) {
	rec := &recordingKeyService{}
	api, _ := newVaultScopedKeyCertTestAPI(rec, nil, nil)

	keyID := uuid.New()
	body := []byte(`{"name":"new-name"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/keys/"+keyID.String(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("legacy PUT /keys/%s: expected 200, got %d (%s)", keyID, w.Code, w.Body.String())
	}
	if !rec.updateCalled {
		t.Fatalf("legacy route did not dispatch to the key update handler")
	}
	if !rec.updateVaultScoped {
		t.Fatalf("legacy /keys/{id} PUT must use a vault scope, not an owner scope")
	}
	if rec.updateVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy update scoped to vault %s, want the default vault", rec.updateVaultID)
	}
	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route actor %s, want caller %s", rec.updateUserID, vaultTestUserID)
	}
}
```

`TestLegacyFlatCertRoute_UsesUserScopedListing` (line 501) becomes the certificate mirror of the key listing test above — same body with `newVaultScopedKeyCertTestAPI(nil, rec, nil)`, `rec := &recordingCertService{}`, the path `/api/v1/certificates`, and the name `TestLegacyFlatCertRoute_UsesDefaultVaultScopedListing`:

```go
// TestLegacyFlatCertRoute_UsesDefaultVaultScopedListing verifies the legacy
// flat /certificates route lists the default vault rather than the caller's
// certificates across every vault.
func TestLegacyFlatCertRoute_UsesDefaultVaultScopedListing(t *testing.T) {
	rec := &recordingCertService{}
	api, _ := newVaultScopedKeyCertTestAPI(nil, rec, nil)

	w := doScopedRequest(api, http.MethodGet, "/api/v1/certificates")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET /certificates: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if !rec.listCalled {
		t.Fatalf("legacy route did not dispatch to the certificate list handler")
	}
	if rec.listUserScoped {
		t.Fatalf("legacy /certificates must no longer build an owner scope")
	}
	if rec.listVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy /certificates scoped to vault %s, want the default vault", rec.listVaultID)
	}
	if rec.listUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy /certificates actor %s, want caller %s", rec.listUserID, vaultTestUserID)
	}
}
```

`TestLegacyFlatCertRoute_UsesUserScopedUpdate` (line 576) becomes:

```go
// TestLegacyFlatCertRoute_UsesDefaultVaultScopedUpdate verifies that PUT on the
// legacy flat /certificates/{id} route updates within the default vault.
func TestLegacyFlatCertRoute_UsesDefaultVaultScopedUpdate(t *testing.T) {
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
	if !rec.updateVaultScoped {
		t.Fatalf("legacy /certificates/{id} PUT must use a vault scope, not an owner scope")
	}
	if rec.updateVaultID != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("legacy update scoped to vault %s, want the default vault", rec.updateVaultID)
	}
	if rec.updateUserID != uuid.MustParse(vaultTestUserID) {
		t.Fatalf("legacy route actor %s, want caller %s", rec.updateUserID, vaultTestUserID)
	}
}
```

- [ ] **Step 11: Refresh the stale comments**

Bulk-fix the two recurring phrases, from the repo root:

```bash
grep -rl "yields an owner scope" api/ | xargs sed -i 's/yields an owner scope/yields a default-vault scope/g'
grep -rl "uses per-user visibility via" api/ | xargs sed -i 's/uses per-user visibility via/uses default-vault visibility via/g'
```

Then fix the three remaining hand-written comments:

`api/keys_crud_test.go:884` — replace `// rotateKey re-fetches with the same owner scope that authorized the rotation.` with `// rotateKey re-fetches with the same vault scope that authorized the rotation.`

`api/secrets.go:614-616` — replace the `deleteSecret` comment block:

```go
	// deleteSecret builds its scope explicitly rather than calling
	// scopeFromRequest. Both now produce the same vault scope, so this is
	// belt-and-braces: it keeps the handler correct even if route-shape
	// branching is ever reintroduced into the shared helper.
```

`api/certificates.go:374-378` — replace the `deleteCertificate` comment block:

```go
	// deleteCertificate builds its scope explicitly rather than calling
	// scopeFromRequest, like deleteSecret. Both now produce the same vault
	// scope, so this is belt-and-braces against route-shape branching being
	// reintroduced into the shared helper. The actor comes from the claims — a
	// uuid.Nil actor would attribute every certificate deletion to nobody in
	// the audit log.
```

Also update the two handler doc comments that still promise per-user visibility: `api/secrets.go:386-388` (`listSecrets`), `api/keys.go:383-385` (`listKeys`) and `api/certificates.go:237-239` (`listCertificates`) — in each, replace the "Legacy flat routes use per-user visibility (the caller's own X)" sentence with "Legacy flat routes list the default vault; explicit vault-scoped routes list the vault named in the path. Both use vault-level 'members see all' visibility."

- [ ] **Step 12: Run the full api package**

Run: `go build ./... && go vet ./... && go test ./api/...`
Expected: PASS. Any remaining failure names a test that still encodes the old behavior — fix it the same way (flat route ⇒ `model.ScopeVault` carrying `model.DefaultVaultID`) rather than weakening the assertion.

- [ ] **Step 13: Run the wider suites and the gate greps**

Run: `go test ./internal/services/... ./internal/repositories/... ./internal/cache/... ./model/... ./cmd/...`
Expected: PASS — no production code outside `api/` changed, so this is a no-regression check.

Run:
```bash
grep -rn "NewOwnerScope" --include="*.go" api/
grep -rn "model\.Scope{" --include="*.go" . | grep -v "^./api/context.go"
```
Expected: the first prints nothing; the second prints nothing (the `scope-gate` CI job runs the same check).

- [ ] **Step 14: Commit**

```bash
git add api/context.go api/keys.go api/secrets.go api/certificates.go api/*_test.go
git commit -S -m "fix(api)!: scope flat data-plane routes to the resolved vault

scopeFromRequest returned an owner scope for legacy flat routes, whose SQL
predicate is user_id = ? with no vault term, while PolicyMiddleware authorized
the request against the default vault. A caller could keep reading and writing
resources they created in any other vault after their role assignment there was
revoked (pentest 2026-08-16, finding H2). It now returns a vault scope for every
route shape, matching deleteSecret and deleteCertificate."
```

---

## Task 2: Cross-vault regression tests

**Files:**
- Create: `api/flat_route_vault_scope_test.go`

**Interfaces:**
- Consumes (all already exist in package `api`, defined in `api/vault_cross_denial_test.go`, `api/vault_test.go`, `api/keys_crypto_test.go`, `api/scope_helpers_test.go`): `newCrossVaultSecretVersionsTestAPI(t) (*API, *vaultFakeRepo, repositories.SecretRepositoryInterface)`, `newCrossVaultKeysTestAPI(t) (*API, *vaultFakeRepo, repositories.KeyRepositoryInterface)`, `newCrossVaultCertsTestAPI(t) (*API, *vaultFakeRepo, repositories.CertificateRepositoryInterface)`, `seedCrossVaultPair(repo *vaultFakeRepo) (vaultAID, vaultBID uuid.UUID)`, `doVaultRequest(api *API, method, path string, body []byte) *httptest.ResponseRecorder`, `vaultTestUserID`, `stubCryptoSvc`, `newCryptoContext(svc keyServices.CryptoService) *Context`, `newScopeRequest(t *testing.T, vaultID uuid.UUID, vaultName string) *http.Request`.
- Produces: nothing consumed by later tasks.

These harnesses wire **real** repositories over in-memory SQLite behind the real router, and they already register the flat subrouters (`r.Secrets`, `r.Keys`, `r.Certificates`), so a flat request exercises the genuine `WHERE ... AND vault_id = ?` predicate. The flat subrouter has no vault-resolution middleware, so `vaultIDFromRequest` falls back to `model.DefaultVaultID` — exactly as in production, where `VaultResolutionMiddleware` resolves the default vault by name.

- [ ] **Step 1: Write the failing tests**

Create `api/flat_route_vault_scope_test.go`:

```go
// Package api — regression tests for the flat-route vault-scope fix
// (docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md).
//
// These reuse the real-SQLite harnesses from vault_cross_denial_test.go, so
// denial is enforced by the repository's own SQL predicate rather than by a
// fake. Each test reproduces the pentest precondition exactly: the caller OWNS
// the resource (user_id == caller) but it lives in a vault other than the one
// the flat route resolves to. Before the fix these all succeeded.
package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// TestFlatRoute_CannotReachSecretInAnotherVault seeds a secret owned by the
// caller in vault B and requests its versions through the flat route, which
// resolves to the default vault. The scoped read must miss.
func TestFlatRoute_CannotReachSecretInAnotherVault(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretVersionsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.MustParse(vaultTestUserID), VaultID: vaultBID,
		Name: "db-password", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/secrets/"+secretID.String()+"/versions", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("flat GET .../versions for a secret in another vault: expected 404, got %d (%s)",
			w.Code, w.Body.String())
	}
}

// TestFlatRoute_ReachesSecretInTheDefaultVault is the positive control: the
// same request against a secret that IS in the flat route's resolved vault
// still succeeds, so the test above proves denial rather than breakage.
func TestFlatRoute_ReachesSecretInTheDefaultVault(t *testing.T) {
	api, vrepo, secretRepo := newCrossVaultSecretVersionsTestAPI(t)
	seedCrossVaultPair(vrepo)

	secretID := uuid.New()
	if err := secretRepo.Create(context.Background(), &model.Secret{
		ID: secretID, UserID: uuid.MustParse(vaultTestUserID),
		VaultID: uuid.MustParse(model.DefaultVaultID),
		Name:    "db-password", Value: "ciphertext", Version: 1,
	}); err != nil {
		t.Fatalf("seed secret in the default vault: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/secrets/"+secretID.String()+"/versions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("flat GET .../versions in the default vault: expected 200, got %d (%s)",
			w.Code, w.Body.String())
	}
}

// TestFlatRoute_CannotReachKeyInAnotherVault mirrors the secret case for keys.
func TestFlatRoute_CannotReachKeyInAnotherVault(t *testing.T) {
	api, vrepo, keyRepo := newCrossVaultKeysTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	keyID := uuid.New()
	if err := keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: uuid.MustParse(vaultTestUserID), VaultID: vaultBID,
		Name: "signing-key", Type: model.KeyTypeRSA, Value: "encrypted-pem", Enabled: true,
	}); err != nil {
		t.Fatalf("seed key in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/keys/"+keyID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("flat GET key in another vault: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestFlatRoute_ReachesKeyInTheDefaultVault is the key positive control.
func TestFlatRoute_ReachesKeyInTheDefaultVault(t *testing.T) {
	api, vrepo, keyRepo := newCrossVaultKeysTestAPI(t)
	seedCrossVaultPair(vrepo)

	keyID := uuid.New()
	if err := keyRepo.Create(context.Background(), &model.Key{
		ID: keyID, UserID: uuid.MustParse(vaultTestUserID),
		VaultID: uuid.MustParse(model.DefaultVaultID),
		Name:    "signing-key", Type: model.KeyTypeRSA, Value: "encrypted-pem", Enabled: true,
	}); err != nil {
		t.Fatalf("seed key in the default vault: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/keys/"+keyID.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("flat GET key in the default vault: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestFlatRoute_CannotReachCertificateInAnotherVault mirrors the secret case
// for certificates.
func TestFlatRoute_CannotReachCertificateInAnotherVault(t *testing.T) {
	api, vrepo, certRepo := newCrossVaultCertsTestAPI(t)
	_, vaultBID := seedCrossVaultPair(vrepo)

	certID := uuid.New()
	if err := certRepo.Create(context.Background(), &model.Certificate{
		ID: certID, UserID: uuid.MustParse(vaultTestUserID), VaultID: vaultBID,
		Name:        "tls-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
		Enabled:     true,
	}); err != nil {
		t.Fatalf("seed certificate in vault B: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/certificates/"+certID.String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("flat GET certificate in another vault: expected 404, got %d (%s)",
			w.Code, w.Body.String())
	}
}

// TestFlatRoute_ReachesCertificateInTheDefaultVault is the certificate
// positive control.
func TestFlatRoute_ReachesCertificateInTheDefaultVault(t *testing.T) {
	api, vrepo, certRepo := newCrossVaultCertsTestAPI(t)
	seedCrossVaultPair(vrepo)

	certID := uuid.New()
	if err := certRepo.Create(context.Background(), &model.Certificate{
		ID: certID, UserID: uuid.MustParse(vaultTestUserID),
		VaultID:     uuid.MustParse(model.DefaultVaultID),
		Name:        "tls-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-private-key",
		Enabled:     true,
	}); err != nil {
		t.Fatalf("seed certificate in the default vault: %v", err)
	}

	w := doVaultRequest(api, http.MethodGet, "/api/v1/certificates/"+certID.String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("flat GET certificate in the default vault: expected 200, got %d (%s)",
			w.Code, w.Body.String())
	}
}

// TestFlatRoute_CryptoOperationCarriesTheResolvedVault covers the crypto
// handlers, whose denial happens inside CryptoService rather than at the HTTP
// layer: the scope they hand the service must pin the resolved vault and carry
// no owner predicate, so loadAndAuthorize's vault_id check applies.
func TestFlatRoute_CryptoOperationCarriesTheResolvedVault(t *testing.T) {
	var got model.Scope
	svc := &stubCryptoSvc{
		signFn: func(_ context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error) {
			got = req.Scope
			return &keyServices.SignResult{Signature: []byte("sig"), Algorithm: "RS256"}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := newScopeRequest(t, uuid.MustParse(model.DefaultVaultID), "")
	r.Body = jsonBody(t, map[string]string{"value": base64.StdEncoding.EncodeToString([]byte("hello"))})

	signKey(c, w, r)

	if c.Err != nil {
		t.Fatalf("flat POST /keys/{id}/sign: unexpected error %v", c.Err)
	}
	if got.Kind() != model.ScopeVault {
		t.Fatalf("crypto scope kind %v, want a vault scope", got.Kind())
	}
	if got.VaultID() != uuid.MustParse(model.DefaultVaultID) {
		t.Fatalf("crypto scope vault %s, want the default vault", got.VaultID())
	}
	if _, ownerScoped := got.OwnerID(); ownerScoped {
		t.Fatalf("crypto scope must carry no owner predicate")
	}
}
```

- [ ] **Step 2: Run the tests to verify they pass against the fixed code**

Run: `go test ./api/ -run TestFlatRoute_ -v`
Expected: PASS (7 tests).

- [ ] **Step 3: Prove the new tests bite**

Temporarily restore the vulnerable branch in `api/context.go`'s `scopeFromRequest` (add back `if mux.Vars(r)["vault_name"] != "" { return model.NewVaultScope(vaultID, userID), true }` / `return model.NewOwnerScope(vaultID, userID), true`, plus the `mux` import), then:

Run: `go test ./api/ -run TestFlatRoute_ -v`
Expected: FAIL — `TestFlatRoute_CannotReachSecretInAnotherVault`, `..._CannotReachKeyInAnotherVault`, `..._CannotReachCertificateInAnotherVault` get 200 instead of 404, and `..._CryptoOperationCarriesTheResolvedVault` reports scope kind `ScopeOwner`. The three positive controls still pass, which confirms they are not what is doing the work.

Then revert the temporary edit (`git checkout -- api/context.go`) and re-run to confirm PASS again.

- [ ] **Step 4: Run the package**

Run: `go build ./... && go vet ./... && go test ./api/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/flat_route_vault_scope_test.go
git commit -S -m "test(api): pin flat-route cross-vault denial for secrets, keys and certs

Real SQLite repositories behind the real router, reproducing the pentest
precondition: the caller owns the resource but it lives in another vault.
Each denial test is paired with a positive control in the resolved vault."
```

---

## Task 3: Documentation

**Files:**
- Modify: `.claude/known-bugs.md` (append a new entry in the "Open Bugs" section, after B8, before the `## Deferred Refactors` heading at line 243)
- Modify: `.claude/multi-vault.md:70-90`
- Modify: `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`

**Interfaces:** none — documentation only.

- [ ] **Step 1: Add the known-bugs entry**

In `.claude/known-bugs.md`, insert immediately before the `## Deferred Refactors` heading:

```markdown
### B11 — Cross-vault authorization bypass on flat data-plane routes

**Status**: Fixed in commit `<fill in the Task 1 commit hash>`
**Severity**: High — broken access control; per-vault revocation was not enforced
**Files**: `api/context.go`, `api/keys.go`

**Root cause**: `scopeFromRequest` (`api/context.go`) branched on route shape: a
vault scope for `/api/v1/vaults/{vault_name}/...`, an owner scope for the legacy
flat routes (`/api/v1/secrets/{id}`, `/keys/{id}`, `/certificates/{id}` and their
sub-routes). An owner scope's repository predicate is `user_id = ?` with no
`vault_id` term at all (`internal/repositories/scope_predicate.go`), and
`model/scope.go` had already flagged `ScopeOwner` as "P1 only; retired in P2".
Meanwhile `PolicyMiddleware` authorized every flat-route request against the
**default** vault, because `VaultResolutionMiddleware` resolves
`model.DefaultVaultName` for any route with no `vault_name` variable. So the
authorization decision and the data lookup disagreed about which vault the
request targeted: a caller holding any data-plane grant on the default vault
could keep reading — and, with a set/create grant, writing — resources they had
created in **any other vault**, including one where their role assignment had
been explicitly revoked. Confirmed by live exploitation during the 2026-08-16
pentest (`.claude/pentest-report-2026-08-16.md` § H2): after
`DELETE .../role-assignments/{id}` returned 200, the vault-scoped route returned
403 for the secret while `GET /api/v1/secrets/{id}` still returned its value.

Secrets and certificates were affected on every flat read and write. Keys were
affected on get/list/update/versions only: `KeyService.DeleteKey`,
`KeyService.RotateKey` and `cryptoService.loadAndAuthorize` each carry an in-Go
"B6 conjunction" that re-applies the vault term when the scope is owner-scoped.
`deleteSecret` and `deleteCertificate` were already immune — both build
`model.NewVaultScope` by hand instead of calling the helper — which is why the
bug survived: the pattern was known and applied to two handlers out of 35 call
sites.

**Fix**: `scopeFromRequest` now returns `model.NewVaultScope(vaultID, userID)`
for every route shape. The vault id needed no change — `vaultIDFromRequest`
already resolved the default vault for flat routes, which is the same vault
`PolicyMiddleware` checks. `createKey`'s response read-back (`api/keys.go`), the
only other owner-scope construction on the request path, changed with it, so
`grep -rn "NewOwnerScope" api/` is now empty. `deleteSecret`/`deleteCertificate`
keep their hand-built scopes as belt-and-braces; only their comments changed.
Regression coverage is in `api/flat_route_vault_scope_test.go`: real SQLite
repositories behind the real router, seeding a caller-owned resource in another
vault and asserting 404 on the flat route, each paired with a positive control
in the resolved vault.

**Known behavior change**: flat-route listing (`GET /secrets`, `/keys`,
`/certificates`, `POST /secrets/export`, the deleted-item lists) now returns
every row in the default vault rather than only the caller's own rows across
every vault — the Azure-parity "vault members see all" semantic already in force
on the vault-scoped routes. See
`docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`.

**Deliberately not fixed here** (bounded fix, see
`docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md`
§ "Not in scope"): `ScopeOwner` still exists in `model/scope.go` and the
repository predicate; `cmd/version.go` still builds
`model.NewOwnerScope(uuid.Nil, userID)` on the CLI path, which needs its own
`vaultcli.ResolveVaultID` + `RequireDataAction` treatment; and the three B6
conjunctions in the key services are now unreachable from HTTP but were left in
place, along with their comments claiming flat routes still reach them.
```

- [ ] **Step 2: Correct `.claude/multi-vault.md`**

In the "B6 resolved (2026-08-02, commit `da6fb9b`)" paragraph (lines 76-90), replace the two now-false clauses. Change

```
(`api/context.go`) like the rest of the vault-scoped surface — `ScopeVault` on
`/vaults/{name}/...`, `ScopeOwner` on the legacy flat routes. The
`ownerScoped`-branch code paths that used to enforce the old behavior
(`key_service.go` delete/rotate, `crypto_service.go`'s `loadAndAuthorize`)
still exist but are only reachable via `ScopeOwner`, i.e. the flat routes —
they're dead code on the vault-scoped path.
```

to

```
(`api/context.go`) like the rest of the vault-scoped surface. As of 2026-08-16
`scopeFromRequest` yields `ScopeVault` on **both** route shapes — the flat
routes carry the default vault — because the owner scope there was a cross-vault
authorization bypass (see `.claude/known-bugs.md` § B11). The
`ownerScoped`-branch code paths that used to enforce the old behavior
(`key_service.go` delete/rotate, `crypto_service.go`'s `loadAndAuthorize`)
still exist but are now unreachable from any HTTP route; they were left in
place deliberately rather than removed with the security fix.
```

- [ ] **Step 3: Add the release note**

Append to `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`, after the existing "Fixed:" sections:

```markdown
## Fixed: flat data-plane routes ignored the vault when reading and writing

`GET/PUT /api/v1/secrets/{id}`, `/keys/{id}`, `/certificates/{id}` and their
sub-routes (versions, policies, crypto operations, soft-delete flows) were
authorized against the **default** vault but looked the resource up by owner
alone, with no vault constraint. A user who kept any data-plane grant on the
default vault could keep reading and writing resources they had created in other
vaults — even after their role assignment in those vaults was revoked. Reported
as High severity in the 2026-08-16 penetration test and confirmed by live
exploitation. Flat routes now resolve to a vault scope pinned to the default
vault, exactly like `/vaults/{vault_name}/...` routes resolve to the vault they
name.

**Two breaking behavior changes:**

1. **Flat routes can only reach the default vault.** A request for a resource in
   any other vault now returns 404. Use `/api/v1/vaults/{vault_name}/...`, or set
   `Vault` in `vaultclient.Config`, which builds that URL for you.
2. **Flat-route listings widened within the default vault.** `GET /secrets`,
   `GET /keys`, `GET /certificates`, `POST /secrets/export` and the deleted-item
   lists previously returned only the caller's own rows; they now return every
   row in the default vault. This is the same "vault members see all" semantic
   the vault-scoped routes have always used, and callers still need the
   corresponding data action on the default vault to reach the route at all.
```

- [ ] **Step 4: Annotate the e2e testing guide's now-resolved finding**

`.claude/e2e-manual-testing-guide.md` line 1240 records the certificates-area finding this fix resolves. Append one sentence to the end of that bullet, leaving the original text intact:

```
**Resolved 2026-08-16**: `updateCertificate` no longer resolves via an owner scope on any route — `scopeFromRequest` builds a vault scope for flat and vault-scoped routes alike, so `PUT` and `DELETE` now agree (see `.claude/known-bugs.md` § B11).
```

- [ ] **Step 5: Verify the docs render and links resolve**

Run: `grep -n "B11" .claude/known-bugs.md && grep -n "2026-08-16" .claude/multi-vault.md docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`
Expected: the B11 heading plus its cross-references print; no other `B11` entry already exists.

- [ ] **Step 6: Commit**

```bash
git add .claude/known-bugs.md .claude/multi-vault.md .claude/e2e-manual-testing-guide.md docs/release-notes/v4.1.0-role-parity-and-authz-fix.md
git commit -S -m "docs: record the flat-route cross-vault bypass (B11) and its fix"
```

---

## Final verification

- [ ] `go build ./...` — PASS
- [ ] `go vet ./...` — PASS
- [ ] `go test ./...` — PASS
- [ ] `grep -rn "NewOwnerScope" --include="*.go" api/` — empty
- [ ] `grep -rn "model\.Scope{" --include="*.go" . | grep -v "^./api/context.go"` — empty (the `scope-gate` CI job runs this)
- [ ] The Task 1 commit hash is filled into `.claude/known-bugs.md` § B11 (amend the Task 3 commit if needed)
