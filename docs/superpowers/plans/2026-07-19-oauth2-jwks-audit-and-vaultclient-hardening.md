# OAuth2/JWKS Security Fixes and vaultclient SDK Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two production-readiness blockers found in a security audit of RocketVault's OAuth2/JWKS endpoints (unauthorized signing-key rotation, no audit trail for machine-credential usage), and harden the `internal/vaultclient` Go SDK against the four non-blocking gaps the same audit found (silent retries, coarse error typing, no TLS-scheme enforcement, no proven concurrency safety).

**Architecture:** Two independently shippable parts. Part A (Tasks 1-4) touches only server-side `api/` and `internal/middleware/` — it adds an admin-role gate to `POST /jwks/rotate` and wires `internal/services/audit`'s existing `RecordEvent` call into OAuth2 token issuance, JWKS rotation, and service-account lifecycle handlers, all of which currently produce zero audit trail. Part B (Tasks 5-8) touches only `internal/vaultclient/` — it adds three new error sentinels with retry-safe `errors.Is` support, an optional `Logger` hook, default-on HTTPS enforcement (loopback exempted), and a `-race`-verified concurrency test. Neither part depends on the other; they can be executed and merged in either order.

**Tech Stack:** Go 1.25, Gorilla Mux, testify/mock, the existing `internal/retry` exponential-backoff package. GPG-signed commits (key `61D246B30285ED35`).

## Global Constraints

- Every commit must be GPG-signed: `git commit -S -m "..."`.
- Before any commit: `go build ./...` and `go vet ./...` must succeed, and `gofmt -l <touched files>` must produce no output.
- Every task's tests must pass in isolation (`go test <package> -run <TestName> -v`) and the full existing package test suite must still pass after the change (no regressions).
- Match existing code conventions exactly — this plan cites the precise existing patterns (error wrapping, admin-role checks, audit-event shape, mock-container structure) to copy; do not invent new ones.
- Comments end with a period, are short, and only explain non-obvious "why," matching the existing codebase style.

---

## Part A — Server-side OAuth2/JWKS fixes

### Task 1: Export `ExtractClientIP` from `internal/middleware` for reuse

Every audit-log call added in Tasks 2-4 needs the caller's IP address. The only existing IP-extraction logic is `extractClientIP` (unexported) in `internal/middleware/middleware.go`, already used by that package's own audit call. Exporting it avoids duplicating X-Forwarded-For/X-Real-IP handling in `api/`. `api/api.go` already imports `rocketvault/internal/middleware`, so this doesn't introduce a new dependency edge.

**Files:**
- Modify: `internal/middleware/middleware.go:223-236` (definition), `:295` (the one call site)

- [ ] **Step 1: Rename the function and its call site**

In `internal/middleware/middleware.go`, change:

```go
// extractClientIP returns the client's IP address, preferring X-Forwarded-For.
func extractClientIP(r *http.Request) string {
```

to:

```go
// ExtractClientIP returns the client's IP address, preferring X-Forwarded-For.
func ExtractClientIP(r *http.Request) string {
```

(the function body is unchanged). Then update the single call site at line 295 from:

```go
				IPAddress: extractClientIP(r),
```

to:

```go
				IPAddress: ExtractClientIP(r),
```

- [ ] **Step 2: Run the middleware package tests to confirm nothing broke**

Run: `go test ./internal/middleware/... -v`
Expected: PASS, same test count as before the rename (no test referenced the old lowercase name directly — confirmed via `grep -rn "extractClientIP" internal/middleware/*_test.go` returning nothing).

- [ ] **Step 3: Build the whole module to confirm no other caller exists**

Run: `go build ./...`
Expected: success, no output.

- [ ] **Step 4: Commit**

```bash
git add internal/middleware/middleware.go
git commit -S -m "refactor(middleware): export ExtractClientIP for reuse by api package"
```

---

### Task 2: Close the `POST /jwks/rotate` authorization gap and audit-log rotations

**The bug:** `POST /jwks/rotate` is registered via `ApiHandler` (`api/jwks.go:17`), the wrapper for *public* handlers — its `Context{}` construction (`api/context.go:90-118`) never populates `c.Claims`. The route sits under `ApiRoot`, which does run `AuthenticationMiddleware` (`api/api.go:66-70`), so a valid Bearer token is already required — but `mapEndpointToPermission` (`internal/services/authorization/rbac_service.go:220`) has no entry for `jwks/rotate`, so `ValidateEndpointAccess` returns "no permission required" for it regardless of role. Combined with `ApiHandler` never exposing `c.Claims`, there is currently no way for a handler-level check to distinguish an admin from a read-only service account. Net effect: **any authenticated principal, including a read-only service account, can rotate the vault's JWT signing keys**, and it happens with zero audit trail.

**The fix:** switch the route to `ApiSessionRequired` (which populates `c.Claims` from context and is what every other admin-gated handler in this codebase uses — see `createServiceAccount` in `api/oauth2.go:140-146`), add the same in-handler admin check those handlers use, and audit-log both successful and failed rotation attempts.

**Files:**
- Modify: `api/jwks.go`
- Modify: `api/jwks_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `api/jwks_test.go`. First add two imports to the existing import block (it currently has `crypto`, `crypto/rand`, `crypto/rsa`, `database/sql`, `encoding/json`, `errors`, `net/http`, `net/http/httptest`, `testing`, testify `assert`/`require`, and a block of `rocketvault/...` packages ending in `"rocketvault/internal/signing"`):

```go
	"github.com/golang-jwt/jwt/v5"
```

(alongside the existing `testify` imports), and:

```go
	"rocketvault/internal/testutils"
	"rocketvault/model"
```

(alongside the existing `rocketvault/...` imports, keeping them alphabetically grouped as the file already does).

Then add a helper right after the existing `newJWKSCtx` function (`api/jwks_test.go:199-206`):

```go
// newJWKSAdminCtx builds a Context with an admin role claim, for handlers gated to admins.
func newJWKSAdminCtx(provider signing.SigningKeyProvider) *Context {
	c := newJWKSCtx(provider)
	c.Claims = jwt.MapClaims{"role": string(model.RoleAdmin), "user_id": "00000000-0000-0000-0000-000000000001"}
	return c
}
```

Then update the field and getter on `jwkContainerBase` (`api/jwks_test.go:69-71` and `:191-193`) so a test can inject a mock audit service. Change:

```go
type jwkContainerBase struct {
	signingProvider signing.SigningKeyProvider
}
```

to:

```go
type jwkContainerBase struct {
	signingProvider signing.SigningKeyProvider
	auditSvc        auditServices.AuditServiceInterface
}
```

and change:

```go
func (c *jwkContainerBase) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
```

to:

```go
func (c *jwkContainerBase) GetAuditService() auditServices.AuditServiceInterface {
	return c.auditSvc
}
```

Then, in the `rotateJWKS` test section (after `TestRotateJWKS_Success_Returns200`, before the `buildJWKSet` section comment at `api/jwks_test.go:326`), add:

```go
// TestRotateJWKS_NonAdmin_Returns403 verifies a non-admin caller cannot rotate signing keys.
func TestRotateJWKS_NonAdmin_Returns403(t *testing.T) {
	provider := &rotatableStubProvider{rotateKID: "new-kid", rotateUntil: "2026-01-01T00:00:00Z"}
	c := newJWKSCtx(provider)
	c.Claims = jwt.MapClaims{"role": "user"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)
}

// TestRotateJWKS_Success_RecordsAuditEvent verifies a successful rotation writes
// a "jwks_rotate"/"success" audit event tagged with the new key ID.
func TestRotateJWKS_Success_RecordsAuditEvent(t *testing.T) {
	provider := &rotatableStubProvider{rotateKID: "new-kid", rotateUntil: "2026-01-01T00:00:00Z"}
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "jwks_rotate" && e.Outcome == "success" && e.ResourceID == "new-kid"
	})).Return(nil)

	a := &app.App{ServiceContainer: &jwkContainerBase{signingProvider: provider, auditSvc: mockAudit}}
	c := &Context{
		App:    a,
		Claims: jwt.MapClaims{"role": string(model.RoleAdmin), "user_id": "00000000-0000-0000-0000-000000000001"},
		Params: &ApiParams{PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jwks/rotate", nil)

	rotateJWKS(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	mockAudit.AssertExpectations(t)
}
```

`mock` (testify) is already imported in this file — verify with `grep -n "stretchr/testify/mock" api/jwks_test.go`; if absent, add `"github.com/stretchr/testify/mock"` to the import block.

Finally, update the four existing rotate tests to use the new admin-context helper (they currently call `rotateJWKS` with no `Claims` set at all, which will start failing with 403 once Step 2 below lands). In `api/jwks_test.go`, replace every `newJWKSCtx(...)` call **inside** `TestRotateJWKS_NilProvider_SetsErrWith503`, `TestRotateJWKS_NonRotatableProvider_SetsErrWith400`, `TestRotateJWKS_Success_Returns200`, and `TestRotateJWKS_RotateError_Returns500` with `newJWKSAdminCtx(...)`. Do not change `newJWKSCtx` calls in the `getJWKS` tests (`TestGetJWKS_*`) — that endpoint stays public.

- [ ] **Step 2: Run the new/updated tests to verify they fail**

Run: `go test ./api/... -run TestRotateJWKS -v`
Expected: `TestRotateJWKS_NonAdmin_Returns403` and `TestRotateJWKS_Success_RecordsAuditEvent` FAIL (compile passes, but the handler doesn't check role or call the audit service yet — non-admin currently succeeds with 200 instead of 403, and no `RecordEvent` call is made so `mockAudit.AssertExpectations` fails). The four updated existing tests should still PASS unchanged (admin context doesn't change their behavior yet).

- [ ] **Step 3: Implement the fix**

In `api/jwks.go`, update the import block from:

```go
import (
	"encoding/json"
	"net/http"

	"rocketvault/common"
	"rocketvault/internal/signing"
)
```

to:

```go
import (
	"encoding/json"
	"net/http"

	"rocketvault/common"
	"rocketvault/internal/middleware"
	auditSvc "rocketvault/internal/services/audit"
	"rocketvault/internal/signing"
	"rocketvault/model"
)
```

Change the route registration (`api/jwks.go:16-17`) from:

```go
	// POST /api/v1/jwks/rotate — admin only, behind the auth middleware.
	a.BaseRoutes.ApiRoot.Handle("/jwks/rotate", ApiHandler(a.App, rotateJWKS)).Methods(http.MethodPost)
```

to:

```go
	// POST /api/v1/jwks/rotate — admin only, behind the auth middleware.
	a.BaseRoutes.ApiRoot.Handle("/jwks/rotate", ApiSessionRequired(a.App, rotateJWKS)).Methods(http.MethodPost)
```

Replace the whole `rotateJWKS` function with:

```go
// rotateJWKS serves POST /api/v1/jwks/rotate — only available with the self_pki provider.
// Admin-only: rotating the signing key is a sensitive, availability-affecting action.
func rotateJWKS(c *Context, w http.ResponseWriter, r *http.Request) {
	roleStr, _ := c.Claims["role"].(string)
	if !common.HasRequiredRole(roleStr, model.RoleAdmin) {
		c.SetPermissionError("admin role required to rotate signing keys")
		return
	}

	provider := c.App.ServiceContainer.GetSigningProvider()
	if provider == nil {
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.provider_unavailable", nil,
			"signing provider not available", http.StatusServiceUnavailable)
		return
	}

	rotatable, ok := provider.(signing.RotatableProvider)
	if !ok {
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.rotate_not_supported", nil,
			"key rotation is only supported for the self_pki key source", http.StatusBadRequest)
		return
	}

	newKID, overlapUntil, err := rotatable.Rotate()
	if err != nil {
		recordJWKSRotateAudit(c, r, "", "failure")
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.rotate_failed", nil,
			err.Error(), http.StatusInternalServerError)
		return
	}

	recordJWKSRotateAudit(c, r, newKID, "success")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"status":        "ok",
		"new_kid":       newKID,
		"overlap_until": overlapUntil,
	})
}

// recordJWKSRotateAudit writes an audit entry for a signing-key rotation attempt.
// Swallows a nil audit service (test doubles, or a container without one wired) —
// audit failures must never block vault operations.
func recordJWKSRotateAudit(c *Context, r *http.Request, newKID, outcome string) {
	svc := c.App.ServiceContainer.GetAuditService()
	if svc == nil {
		return
	}
	userIDStr, _ := c.Claims["user_id"].(string)
	_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
		UserID:       userIDStr,
		Action:       "jwks_rotate",
		Outcome:      outcome,
		Source:       "api",
		ResourceType: "signing_key",
		ResourceID:   newKID,
		IPAddress:    middleware.ExtractClientIP(r),
	})
}
```

- [ ] **Step 4: Run the tests again to verify they pass**

Run: `go test ./api/... -run TestRotateJWKS -v`
Expected: all `TestRotateJWKS_*` tests PASS, including the two new ones.

- [ ] **Step 5: Run the full api package test suite to check for regressions**

Run: `go test ./api/... -count=1`
Expected: PASS, all packages.

- [ ] **Step 6: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: success, no output.

- [ ] **Step 7: Commit**

```bash
git add api/jwks.go api/jwks_test.go
git commit -S -m "fix(api): gate JWKS rotation to admins and audit-log attempts"
```

---

### Task 3: Audit-log OAuth2 token issuance (success and failure)

**The gap:** `tokenHandler` (`api/oauth2.go:53-102`) never calls the audit service — neither successful token issuance nor failed authentication attempts leave a trail. `internal/middleware/middleware.go:289-296` shows the established call convention for `RecordEvent`.

**Files:**
- Modify: `api/oauth2.go`
- Modify: `api/oauth2_handlers_test.go`

- [ ] **Step 1: Write the failing tests**

In `api/oauth2_handlers_test.go`, add `"rocketvault/internal/testutils"` to the import block (alongside the existing `rocketvault/...` imports).

Update `oauth2HTestContainer` (`api/oauth2_handlers_test.go:92-96`) to hold an audit service. Change:

```go
type oauth2HTestContainer struct {
	svc oauth2Services.OAuth2Service
}

func (c *oauth2HTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service { return c.svc }
```

to:

```go
type oauth2HTestContainer struct {
	svc      oauth2Services.OAuth2Service
	auditSvc auditServices.AuditServiceInterface
}

func (c *oauth2HTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service { return c.svc }
```

And change the existing `GetAuditService` stub (`api/oauth2_handlers_test.go:210-212`) from:

```go
func (c *oauth2HTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return nil
}
```

to:

```go
func (c *oauth2HTestContainer) GetAuditService() auditServices.AuditServiceInterface {
	return c.auditSvc
}
```

Then add two new tests directly after `TestTokenHandler_Success_Returns200` (`api/oauth2_handlers_test.go:347-362`):

```go
func TestTokenHandler_Success_RecordsAuditEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "good_client", "good_sec").Return(&oauth2Services.TokenResponse{
		AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600,
	}, nil)
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "oauth2_token_issue" && e.Outcome == "success" && e.ResourceID == "good_client"
	})).Return(nil)

	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}
	api := &API{App: a, Logger: userTestLog()}
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=good_client&client_secret=good_sec")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestTokenHandler_InvalidCreds_RecordsFailureAuditEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	svc.On("IssueToken", mock.Anything, "bad_client", "bad_sec").Return(nil, errors.New("invalid"))
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "oauth2_token_issue" && e.Outcome == "failure" && e.ResourceID == "bad_client"
	})).Return(nil)

	a := &app.App{ServiceContainer: &oauth2HTestContainer{svc: svc, auditSvc: mockAudit}}
	api := &API{App: a, Logger: userTestLog()}
	w := httptest.NewRecorder()
	body := strings.NewReader("grant_type=client_credentials&client_id=bad_client&client_secret=bad_sec")
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	api.tokenHandler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `go test ./api/... -run "TestTokenHandler_Success_RecordsAuditEvent|TestTokenHandler_InvalidCreds_RecordsFailureAuditEvent" -v`
Expected: both FAIL — `mockAudit.AssertExpectations` fails because `tokenHandler` never calls `RecordEvent`.

- [ ] **Step 3: Implement the fix**

In `api/oauth2.go`, update the import block from:

```go
import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)
```

to:

```go
import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/middleware"
	auditSvc "rocketvault/internal/services/audit"
	"rocketvault/model"
)
```

Replace the body of `tokenHandler` from the `tokenResp, err := svc.IssueToken(...)` line onward (`api/oauth2.go:91-102`), i.e. change:

```go
	tokenResp, err := svc.IssueToken(r.Context(), clientID, clientSecret)
	if err != nil {
		// RFC 6749 §5.2: 401 + WWW-Authenticate for invalid_client.
		w.Header().Set("WWW-Authenticate", `Basic realm="rocketvault"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenResp) //nolint:errcheck
}
```

to:

```go
	tokenResp, err := svc.IssueToken(r.Context(), clientID, clientSecret)
	if err != nil {
		api.recordOAuth2TokenAudit(r, clientID, "failure")
		// RFC 6749 §5.2: 401 + WWW-Authenticate for invalid_client.
		w.Header().Set("WWW-Authenticate", `Basic realm="rocketvault"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	api.recordOAuth2TokenAudit(r, clientID, "success")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenResp) //nolint:errcheck
}

// recordOAuth2TokenAudit writes an audit entry for a token-issuance attempt.
// clientID is the caller-supplied identifier — safe to log even on failure
// since the response never reveals whether the ID or the secret was wrong
// (RFC 6749 §5.2 non-enumerating error). Swallows a nil audit service.
func (api *API) recordOAuth2TokenAudit(r *http.Request, clientID, outcome string) {
	svc := api.App.ServiceContainer.GetAuditService()
	if svc == nil {
		return
	}
	_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
		UserID:       clientID,
		Action:       "oauth2_token_issue",
		Outcome:      outcome,
		Source:       "api",
		ResourceType: "oauth2_client",
		ResourceID:   clientID,
		IPAddress:    middleware.ExtractClientIP(r),
	})
}
```

- [ ] **Step 4: Run the tests again to verify they pass**

Run: `go test ./api/... -run TestTokenHandler -v`
Expected: all `TestTokenHandler_*` tests PASS, including the two new ones.

- [ ] **Step 5: Run the full api package test suite to check for regressions**

Run: `go test ./api/... -count=1`
Expected: PASS.

- [ ] **Step 6: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: success, no output.

- [ ] **Step 7: Commit**

```bash
git add api/oauth2.go api/oauth2_handlers_test.go
git commit -S -m "feat(api): audit-log OAuth2 token issuance success and failure"
```

---

### Task 4: Audit-log service-account lifecycle (create, delete, rotate secret)

**The gap:** `createServiceAccount`, `deleteServiceAccount`, and `rotateServiceAccountSecret` (`api/oauth2.go:140-278`) never call the audit service. This task reuses the `oauth2HTestContainer.auditSvc` field added in Task 3.

**Files:**
- Modify: `api/oauth2.go`
- Modify: `api/oauth2_handlers_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `api/oauth2_handlers_test.go`, directly after `TestCreateSA_Success_Returns201` (`api/oauth2_handlers_test.go:400-420`):

```go
func TestCreateSA_Success_RecordsAuditEvent(t *testing.T) {
	svc := &mockOAuth2Svc{}
	clientID := uuid.New()
	now := time.Now()
	svc.On("CreateClient", mock.Anything, "svcname", "", (*time.Time)(nil)).Return(&model.OAuth2Client{
		ID: clientID, Name: "svcname", Enabled: true, CreatedAt: now,
	}, "plain-secret", nil)
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "service_account_create" && e.Outcome == "success" && e.ResourceID == clientID.String()
	})).Return(nil)

	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = mockAudit
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "svcname"})
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", bytes.NewReader(body))

	createServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}
```

Add directly after `TestDeleteSA_Success_Returns200` (`api/oauth2_handlers_test.go:553-570`):

```go
func TestDeleteSA_Success_RecordsAuditEvent(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("DeleteClient", mock.Anything, saID).Return(nil)
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "service_account_delete" && e.Outcome == "success" && e.ResourceID == saID.String()
	})).Return(nil)

	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = mockAudit
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/service-accounts/"+saID.String(), nil)

	deleteServiceAccount(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}
```

Add directly after `TestRotateSA_Success_Returns200` (`api/oauth2_handlers_test.go:609-...`, the last test in the file):

```go
func TestRotateSA_Success_RecordsAuditEvent(t *testing.T) {
	saID := uuid.New()
	svc := &mockOAuth2Svc{}
	svc.On("RotateSecret", mock.Anything, saID).Return("new-secret", nil)
	mockAudit := &testutils.MockAuditService{}
	mockAudit.On("RecordEvent", mock.Anything, mock.MatchedBy(func(e auditServices.AuditEvent) bool {
		return e.Action == "service_account_rotate_secret" && e.Outcome == "success" && e.ResourceID == saID.String()
	})).Return(nil)

	c := newOAuth2HCtx(svc)
	c.App.ServiceContainer.(*oauth2HTestContainer).auditSvc = mockAudit
	c.Params = &ApiParams{ServiceAccountID: saID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/service-accounts/"+saID.String()+"/rotate", nil)

	rotateServiceAccountSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `go test ./api/... -run "TestCreateSA_Success_RecordsAuditEvent|TestDeleteSA_Success_RecordsAuditEvent|TestRotateSA_Success_RecordsAuditEvent" -v`
Expected: all three FAIL — none of the three handlers call `RecordEvent` yet.

- [ ] **Step 3: Implement the fix**

In `api/oauth2.go`, add this helper directly after `writeTokenError` (`api/oauth2.go:126-133`), before the `─── Service-account management handlers` comment:

```go
// recordServiceAccountAudit writes an audit entry for a service-account
// lifecycle action. Swallows a nil audit service.
func recordServiceAccountAudit(c *Context, r *http.Request, action, resourceID, outcome string) {
	svc := c.App.ServiceContainer.GetAuditService()
	if svc == nil {
		return
	}
	callerIDStr, _ := c.Claims["user_id"].(string)
	_ = svc.RecordEvent(r.Context(), auditSvc.AuditEvent{
		UserID:       callerIDStr,
		Action:       action,
		Outcome:      outcome,
		Source:       "api",
		ResourceType: "oauth2_client",
		ResourceID:   resourceID,
		IPAddress:    middleware.ExtractClientIP(r),
	})
}
```

In `createServiceAccount` (`api/oauth2.go:158-176`), change:

```go
	svc := c.App.ServiceContainer.GetOAuth2Service()
	client, plainSecret, err := svc.CreateClient(r.Context(), req.Name, req.Description, req.ExpiresAt)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
```

to:

```go
	svc := c.App.ServiceContainer.GetOAuth2Service()
	client, plainSecret, err := svc.CreateClient(r.Context(), req.Name, req.Description, req.ExpiresAt)
	if err != nil {
		recordServiceAccountAudit(c, r, "service_account_create", "", "failure")
		c.SetInternalError(err)
		return
	}

	recordServiceAccountAudit(c, r, "service_account_create", client.ID.String(), "success")

	w.Header().Set("Content-Type", "application/json")
```

In `deleteServiceAccount` (`api/oauth2.go:242-249`), change:

```go
	svc := c.App.ServiceContainer.GetOAuth2Service()
	if err := svc.DeleteClient(r.Context(), id); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}
```

to:

```go
	svc := c.App.ServiceContainer.GetOAuth2Service()
	if err := svc.DeleteClient(r.Context(), id); err != nil {
		recordServiceAccountAudit(c, r, "service_account_delete", id.String(), "failure")
		c.SetInternalError(err)
		return
	}

	recordServiceAccountAudit(c, r, "service_account_delete", id.String(), "success")

	ReturnStatusOK(w)
}
```

In `rotateServiceAccountSecret` (`api/oauth2.go:267-278`), change:

```go
	svc := c.App.ServiceContainer.GetOAuth2Service()
	newSecret, err := svc.RotateSecret(r.Context(), id)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"client_secret": newSecret, // returned once only — store securely
	})
}
```

to:

```go
	svc := c.App.ServiceContainer.GetOAuth2Service()
	newSecret, err := svc.RotateSecret(r.Context(), id)
	if err != nil {
		recordServiceAccountAudit(c, r, "service_account_rotate_secret", id.String(), "failure")
		c.SetInternalError(err)
		return
	}

	recordServiceAccountAudit(c, r, "service_account_rotate_secret", id.String(), "success")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"client_secret": newSecret, // returned once only — store securely
	})
}
```

- [ ] **Step 4: Run the tests again to verify they pass**

Run: `go test ./api/... -run "TestCreateSA|TestDeleteSA|TestRotateSA" -v`
Expected: all PASS, including the three new audit tests.

- [ ] **Step 5: Run the full api package test suite to check for regressions**

Run: `go test ./api/... -count=1`
Expected: PASS.

- [ ] **Step 6: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: success, no output.

- [ ] **Step 7: Commit**

```bash
git add api/oauth2.go api/oauth2_handlers_test.go
git commit -S -m "feat(api): audit-log service-account create/delete/rotate"
```

---

## Part B — vaultclient SDK hardening

### Task 5: Add error-category sentinels with retry-safe `errors.Is` support

**The gap:** only `ErrSecretNotFound` and `ErrAuthFailed` exist. Every other failure (network error, unexpected HTTP status, malformed JSON) is an unwrapped `fmt.Errorf`, so callers can't distinguish them programmatically. Naively adding `%w`-wrapped sentinels isn't enough on its own: `internal/retry.WithExponentialBackoff` (`internal/retry/retry.go:274-317`) re-wraps whatever error it's given using `fmt.Errorf("%w: %v", ErrNonRetryable, err)` or `fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)` — note `%v` for the inner error, not `%w` — so the original sentinel chain is lost once it passes through the retry loop's *own* returned error. This is exactly why the existing code already has a `terminalErr` side-channel for `ErrAuthFailed`/`ErrSecretNotFound`; this task extends that same pattern to the new sentinels, and additionally fixes a related bug where `fetchToken` was pre-wrapping its own errors with `retry.Retryable(...)` (from `internal/retry`), which — because `*retryableError` (`internal/retry/retry.go:227-238`) has no `Unwrap()` method either — silently discarded any sentinel wrapped inside it once it reached `Get`'s closure.

**Files:**
- Modify: `internal/vaultclient/errors.go`
- Modify: `internal/vaultclient/client.go`
- Test: `internal/vaultclient/client_edge_test.go`

- [ ] **Step 1: Write the failing tests**

In `internal/vaultclient/client_edge_test.go`, add `"sync"` to the import block (needed later in this task for a fake logger — skip if not yet needed, but it will be needed by Task 6 in this same file, so add it now to avoid a second import-block edit).

Replace `TestGet_UnexpectedStatus` (`internal/vaultclient/client_edge_test.go:109-125`) — change its final assertion from:

```go
	_, err = c.Get(context.Background(), "some-uuid")
	require.Error(t, err)
}
```

to:

```go
	_, err = c.Get(context.Background(), "some-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, vaultclient.ErrUnexpectedStatus)
}
```

Replace `TestFetchToken_NonOKStatus` (`internal/vaultclient/client_edge_test.go:128-141`) — change its final assertion from:

```go
	_, err = c.Get(context.Background(), "some-uuid")
	require.Error(t, err)
}
```

to:

```go
	_, err = c.Get(context.Background(), "some-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, vaultclient.ErrUnexpectedStatus)
}
```

Add three new tests at the end of `internal/vaultclient/client_edge_test.go`:

```go
// TestGet_NetworkError_ReturnsErrNetwork verifies a connection failure is
// identifiable via errors.Is(err, ErrNetwork) even after retries are exhausted.
func TestGet_NetworkError_ReturnsErrNetwork(t *testing.T) {
	// Point at a server that's already closed — connection refused on every attempt.
	closedSrv := httptest.NewServer(http.NewServeMux())
	deadURL := closedSrv.URL
	closedSrv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: deadURL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrNetwork)
}

// TestGet_MalformedJSON_ReturnsErrDecodeFailed verifies a 200 response with
// unparseable JSON is treated as terminal (not retried) and identifiable via
// errors.Is(err, ErrDecodeFailed).
func TestGet_MalformedJSON_ReturnsErrDecodeFailed(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not valid json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrDecodeFailed)
	assert.Equal(t, 1, calls, "malformed JSON should be terminal, not retried")
}

// TestGet_ContextCanceled_ReturnsContextError verifies a canceled context is
// surfaced as ctx.Err(), not masked as a generic retries-exhausted error.
func TestGet_ContextCanceled_ReturnsContextError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before the call

	_, err = c.Get(ctx, "some-uuid")
	assert.ErrorIs(t, err, context.Canceled)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vaultclient/... -run "TestGet_UnexpectedStatus|TestFetchToken_NonOKStatus|TestGet_NetworkError_ReturnsErrNetwork|TestGet_MalformedJSON_ReturnsErrDecodeFailed|TestGet_ContextCanceled_ReturnsContextError" -v`
Expected: compile FAILS first (`ErrNetwork`/`ErrUnexpectedStatus`/`ErrDecodeFailed` undefined). After adding the sentinels to `errors.go` alone (an intermediate check, optional), the behavioral assertions still FAIL because `client.go` doesn't wrap or track them yet.

- [ ] **Step 3: Implement the fix — add the sentinels**

Replace the full contents of `internal/vaultclient/errors.go` with:

```go
package vaultclient

import "errors"

// ErrSecretNotFound is returned when the vault responds with 404 for a secret.
var ErrSecretNotFound = errors.New("vaultclient: secret not found")

// ErrAuthFailed is returned when the vault rejects the client credentials (401).
var ErrAuthFailed = errors.New("vaultclient: authentication failed — check VAULT_CLIENT_ID and VAULT_CLIENT_SECRET")

// ErrNetwork is returned when a request to RocketVault fails at the transport
// level (DNS failure, connection refused, timeout, TLS handshake, etc.) and
// retries have been exhausted. Check with errors.Is.
var ErrNetwork = errors.New("vaultclient: network error")

// ErrUnexpectedStatus is returned when RocketVault responds with a status
// code other than the ones this package understands (200, 401, 404) and
// retries have been exhausted. Check with errors.Is.
var ErrUnexpectedStatus = errors.New("vaultclient: unexpected response status")

// ErrDecodeFailed is returned when a 200 response body cannot be decoded as
// the expected JSON shape. Not retried — a malformed body on a 200 status is
// treated as a permanent incompatibility, not a transient failure.
var ErrDecodeFailed = errors.New("vaultclient: failed to decode response")
```

- [ ] **Step 4: Implement the fix — rewrite `fetchToken` to return chain-preserving errors**

In `internal/vaultclient/client.go`, replace the whole `fetchToken` function (`internal/vaultclient/client.go:228-266`) with:

```go
// fetchToken exchanges client credentials for an access token.
func (c *Client) fetchToken(ctx context.Context) (string, int, error) {
	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("client_id", c.cfg.ClientID)
	body.Set("client_secret", c.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.URL+"/api/v1/oauth2/token", strings.NewReader(body.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("vaultclient: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrNetwork, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", 0, ErrAuthFailed
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}
	if result.AccessToken == "" {
		return "", 0, ErrAuthFailed
	}
	return result.AccessToken, result.ExpiresIn, nil
}
```

Note what changed: the network-error and non-OK-status branches no longer call `retry.Retryable(...)` themselves — that decision now belongs entirely to the caller (`Get`'s closure, via `ensureToken`), which is the only place that actually feeds a function into `retry.WithExponentialBackoff`. Returning a plain `%w`-wrapped error here keeps the sentinel chain intact all the way up.

- [ ] **Step 5: Implement the fix — rewrite `Get` to track and re-surface the underlying error**

In `internal/vaultclient/client.go`, replace the whole `Get` function (`internal/vaultclient/client.go:99-163`) with:

```go
// Get fetches a secret by UUID. Retries on transient network errors; fails fast on 401/404.
func (c *Client) Get(ctx context.Context, uuid string) (string, error) {
	// terminalErr captures errors that must not be retried and must be returned as-is.
	var terminalErr error
	// lastAttemptErr tracks the most recent retryable failure so its sentinel chain
	// (ErrNetwork/ErrUnexpectedStatus) survives even after retries are exhausted —
	// WithExponentialBackoff re-wraps its own return value with %v, not %w, which
	// would otherwise break errors.Is checks (see the retryErr handling below).
	var lastAttemptErr error
	var value string

	retryErr := retry.WithExponentialBackoff(ctx, retry.ExternalServicePolicy(), func() error {
		tok, err := c.ensureToken(ctx)
		if err != nil {
			// Auth failures are terminal — stop retrying immediately.
			if errors.Is(err, ErrAuthFailed) {
				terminalErr = err
				return retry.NonRetryable(err)
			}
			lastAttemptErr = err
			return retry.Retryable(err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			c.cfg.URL+"/api/v1/secrets/"+uuid, nil)
		if err != nil {
			terminalErr = fmt.Errorf("vaultclient: build request: %w", err)
			return retry.NonRetryable(terminalErr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastAttemptErr = fmt.Errorf("%w: %v", ErrNetwork, err)
			return retry.Retryable(lastAttemptErr)
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var body struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				terminalErr = fmt.Errorf("%w: %v", ErrDecodeFailed, err)
				return retry.NonRetryable(terminalErr)
			}
			value = body.Value
			return nil
		case http.StatusUnauthorized:
			// Invalidate cached token so next attempt re-authenticates.
			c.mu.Lock()
			c.token = nil
			c.mu.Unlock()
			terminalErr = ErrAuthFailed
			return retry.NonRetryable(ErrAuthFailed)
		case http.StatusNotFound:
			terminalErr = ErrSecretNotFound
			return retry.NonRetryable(ErrSecretNotFound)
		default:
			lastAttemptErr = fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
			return retry.Retryable(lastAttemptErr)
		}
	})

	if terminalErr != nil {
		return "", terminalErr
	}
	if retryErr != nil {
		// A canceled/deadline-exceeded context is the true cause — don't mask it
		// behind a stale "retries exhausted" error from an earlier attempt.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if lastAttemptErr != nil {
			return "", fmt.Errorf("vaultclient: retries exhausted: %w", lastAttemptErr)
		}
		return "", retryErr
	}
	return value, nil
}
```

- [ ] **Step 6: Run the tests again to verify they pass**

Run: `go test ./internal/vaultclient/... -run "TestGet_UnexpectedStatus|TestFetchToken_NonOKStatus|TestGet_NetworkError_ReturnsErrNetwork|TestGet_MalformedJSON_ReturnsErrDecodeFailed|TestGet_ContextCanceled_ReturnsContextError" -v`
Expected: all PASS.

- [ ] **Step 7: Run the full vaultclient package test suite to check for regressions**

Run: `go test ./internal/vaultclient/... -count=1 -v`
Expected: PASS, every existing test (including `TestGet_ReturnsErrAuthFailed_On401`, `TestGet_ReturnsErrSecretNotFound_On404`, `TestFetchToken_EmptyAccessToken`, `TestGet_SecretUnauthorized`, `TestGetMany_ErrorPropagation`) still passes unchanged — they all hit the `terminalErr` paths, which are untouched by this task.

- [ ] **Step 8: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: success, no output.

- [ ] **Step 9: Commit**

```bash
git add internal/vaultclient/errors.go internal/vaultclient/client.go internal/vaultclient/client_edge_test.go
git commit -S -m "feat(vaultclient): add ErrNetwork/ErrUnexpectedStatus/ErrDecodeFailed sentinels"
```

---

### Task 6: Add an optional `Logger` hook for retry/auth-failure observability

**The gap:** zero logging or metrics anywhere in the package. A consuming service sees only the final returned error string, with no visibility into how many attempts were made or why.

**Files:**
- Modify: `internal/vaultclient/client.go`
- Test: `internal/vaultclient/client_edge_test.go`

- [ ] **Step 1: Write the failing tests**

Add to the end of `internal/vaultclient/client_edge_test.go` (the `"sync"` import was already added in Task 5, Step 1):

```go
// fakeLogger captures Warn calls for assertions. Safe for concurrent use since
// Client may call it from a retry loop driven by a single goroutine, but tests
// should not assume single-threaded access.
type fakeLogger struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeLogger) Warn(msg string, _ ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, msg)
}

func (f *fakeLogger) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestGet_NoLogger_DoesNotPanicOnFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{URL: srv.URL, ClientID: "id", ClientSecret: "s"})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		_, _ = c.Get(context.Background(), "missing")
	})
}

func TestGet_WithLogger_WarnsOnRetryableFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	logger := &fakeLogger{}
	c, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "id", ClientSecret: "s", Logger: logger,
	})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	require.Error(t, err)
	assert.Positive(t, logger.callCount(), "expected at least one Warn call across the retried attempts")
}

func TestGet_WithLogger_SilentOnFirstTrySuccess(t *testing.T) {
	srv := newTestServer(t, "value")
	defer srv.Close()

	logger := &fakeLogger{}
	c, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "test-id", ClientSecret: "test-secret", Logger: logger,
	})
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "some-uuid")
	require.NoError(t, err)
	assert.Equal(t, 0, logger.callCount())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vaultclient/... -run "TestGet_NoLogger_DoesNotPanicOnFailure|TestGet_WithLogger_WarnsOnRetryableFailure|TestGet_WithLogger_SilentOnFirstTrySuccess" -v`
Expected: compile FAILS (`Config.Logger` field and `vaultclient.Logger` type undefined).

- [ ] **Step 3: Implement the fix**

In `internal/vaultclient/client.go`, add the `Logger` type directly after the `SecretMapping` struct (`internal/vaultclient/client.go:20-25`), before the `Config` struct:

```go
// Logger is the minimal logging interface accepted by Client for
// observability into retries and auth failures. A nil Logger (the Config
// zero value) disables all logging — the client always works without one.
type Logger interface {
	Warn(msg string, keysAndValues ...any)
}
```

Add a `Logger` field to `Config` (`internal/vaultclient/client.go:27-33`) — change:

```go
// Config holds credentials and secret mappings for the vault client.
type Config struct {
	URL          string          `yaml:"url"           mapstructure:"url"`
	ClientID     string          `yaml:"client_id"     mapstructure:"client_id"`
	ClientSecret string          `yaml:"client_secret" mapstructure:"client_secret"`
	Secrets      []SecretMapping `yaml:"secrets"       mapstructure:"secrets"`
}
```

to:

```go
// Config holds credentials and secret mappings for the vault client.
type Config struct {
	URL          string          `yaml:"url"           mapstructure:"url"`
	ClientID     string          `yaml:"client_id"     mapstructure:"client_id"`
	ClientSecret string          `yaml:"client_secret" mapstructure:"client_secret"`
	Secrets      []SecretMapping `yaml:"secrets"       mapstructure:"secrets"`
	// Logger receives Warn calls on retries and auth failures. Optional; nil
	// disables all logging. Not settable via YAML/viper (interface value).
	Logger Logger
}
```

Add a `logger` field to `Client` (`internal/vaultclient/client.go:41-47`) — change:

```go
// Client authenticates to RocketVault and fetches secrets.
type Client struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	token      *tokenCache
	nameIndex  map[string]string
}
```

to:

```go
// Client authenticates to RocketVault and fetches secrets.
type Client struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	token      *tokenCache
	nameIndex  map[string]string
	logger     Logger
}
```

In `New` (`internal/vaultclient/client.go:50-69`), add `logger: cfg.Logger,` to the returned `&Client{...}` literal:

```go
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		nameIndex:  index,
		logger:     cfg.Logger,
	}, nil
```

Add a helper method directly after `New` (before `NewFromEnv`):

```go
// logRetry logs a retryable failure if a Logger is configured; a no-op otherwise.
func (c *Client) logRetry(msg string, err error) {
	if c.logger == nil {
		return
	}
	c.logger.Warn(msg, "error", err)
}
```

Wire it into `fetchToken` — the function now reads (replacing the version from Task 5):

```go
// fetchToken exchanges client credentials for an access token.
func (c *Client) fetchToken(ctx context.Context) (string, int, error) {
	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("client_id", c.cfg.ClientID)
	body.Set("client_secret", c.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.URL+"/api/v1/oauth2/token", strings.NewReader(body.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("vaultclient: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logRetry("vaultclient: token request failed, may retry", err)
		return "", 0, fmt.Errorf("%w: %v", ErrNetwork, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		c.logRetry("vaultclient: token request rejected — check client credentials", ErrAuthFailed)
		return "", 0, ErrAuthFailed
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
		c.logRetry("vaultclient: token endpoint returned unexpected status, may retry", err)
		return "", 0, err
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}
	if result.AccessToken == "" {
		c.logRetry("vaultclient: token endpoint returned an empty access token", ErrAuthFailed)
		return "", 0, ErrAuthFailed
	}
	return result.AccessToken, result.ExpiresIn, nil
}
```

Wire it into `Get` — the function now reads (replacing the version from Task 5):

```go
// Get fetches a secret by UUID. Retries on transient network errors; fails fast on 401/404.
func (c *Client) Get(ctx context.Context, uuid string) (string, error) {
	var terminalErr error
	var lastAttemptErr error
	var value string

	retryErr := retry.WithExponentialBackoff(ctx, retry.ExternalServicePolicy(), func() error {
		tok, err := c.ensureToken(ctx)
		if err != nil {
			if errors.Is(err, ErrAuthFailed) {
				terminalErr = err
				return retry.NonRetryable(err)
			}
			lastAttemptErr = err
			return retry.Retryable(err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			c.cfg.URL+"/api/v1/secrets/"+uuid, nil)
		if err != nil {
			terminalErr = fmt.Errorf("vaultclient: build request: %w", err)
			return retry.NonRetryable(terminalErr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastAttemptErr = fmt.Errorf("%w: %v", ErrNetwork, err)
			c.logRetry("vaultclient: secret fetch network error, may retry", lastAttemptErr)
			return retry.Retryable(lastAttemptErr)
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var body struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				terminalErr = fmt.Errorf("%w: %v", ErrDecodeFailed, err)
				return retry.NonRetryable(terminalErr)
			}
			value = body.Value
			return nil
		case http.StatusUnauthorized:
			c.mu.Lock()
			c.token = nil
			c.mu.Unlock()
			terminalErr = ErrAuthFailed
			c.logRetry("vaultclient: secret endpoint rejected the token, invalidating cache", ErrAuthFailed)
			return retry.NonRetryable(ErrAuthFailed)
		case http.StatusNotFound:
			terminalErr = ErrSecretNotFound
			return retry.NonRetryable(ErrSecretNotFound)
		default:
			lastAttemptErr = fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
			c.logRetry("vaultclient: secret endpoint returned unexpected status, may retry", lastAttemptErr)
			return retry.Retryable(lastAttemptErr)
		}
	})

	if terminalErr != nil {
		return "", terminalErr
	}
	if retryErr != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if lastAttemptErr != nil {
			return "", fmt.Errorf("vaultclient: retries exhausted: %w", lastAttemptErr)
		}
		return "", retryErr
	}
	return value, nil
}
```

- [ ] **Step 4: Run the tests again to verify they pass**

Run: `go test ./internal/vaultclient/... -run "TestGet_NoLogger_DoesNotPanicOnFailure|TestGet_WithLogger_WarnsOnRetryableFailure|TestGet_WithLogger_SilentOnFirstTrySuccess" -v`
Expected: all PASS.

- [ ] **Step 5: Run the full vaultclient package test suite to check for regressions**

Run: `go test ./internal/vaultclient/... -count=1 -v`
Expected: PASS.

- [ ] **Step 6: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: success, no output.

- [ ] **Step 7: Commit**

```bash
git add internal/vaultclient/client.go internal/vaultclient/client_edge_test.go
git commit -S -m "feat(vaultclient): add optional Logger hook for retry observability"
```

---

### Task 7: Enforce HTTPS by default (loopback exempted, explicit opt-out)

**The gap:** `New` accepts any URL scheme, so a misconfigured plaintext `http://` URL in production would silently send client credentials in the clear. All existing tests use `httptest.NewServer`, which always binds to `127.0.0.1` — so the fix exempts loopback hosts (`127.0.0.1`, `localhost`, `::1`) from the check by default, and adds `AllowInsecureHTTP` as an explicit, opt-in override for any other host. Four existing tests use the placeholder host `http://vault.local`, which is **not** loopback, and need `AllowInsecureHTTP: true` added; two others (`TestNew_MissingClientID`, `TestNew_MissingClientSecret`) don't need changes because the scheme check runs after the presence checks and they never reach it.

**Files:**
- Modify: `internal/vaultclient/client.go`
- Modify: `internal/vaultclient/client_edge_test.go`

- [ ] **Step 1: Write the failing tests**

Add to the end of `internal/vaultclient/client_edge_test.go`:

```go
// TestNew_RejectsPlainHTTPForNonLoopbackHost verifies a production-style
// plaintext URL is rejected by default.
func TestNew_RejectsPlainHTTPForNonLoopbackHost(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{
		URL: "http://vault.internal.example.com", ClientID: "id", ClientSecret: "s",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestNew_AllowInsecureHTTP_PermitsPlainHTTP verifies the explicit opt-out works.
func TestNew_AllowInsecureHTTP_PermitsPlainHTTP(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{
		URL: "http://vault.internal.example.com", ClientID: "id", ClientSecret: "s",
		AllowInsecureHTTP: true,
	})
	require.NoError(t, err)
}

// TestNew_AcceptsHTTPSWithoutOptOut verifies a proper https:// URL never needs the flag.
func TestNew_AcceptsHTTPSWithoutOptOut(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{
		URL: "https://vault.internal.example.com", ClientID: "id", ClientSecret: "s",
	})
	require.NoError(t, err)
}

// TestNew_AllowsPlainHTTPOnLoopback verifies loopback hosts never need the flag —
// this is what every httptest.NewServer-backed test in this package relies on.
func TestNew_AllowsPlainHTTPOnLoopback(t *testing.T) {
	for _, host := range []string{"http://127.0.0.1:9999", "http://localhost:9999", "http://[::1]:9999"} {
		_, err := vaultclient.New(vaultclient.Config{URL: host, ClientID: "id", ClientSecret: "s"})
		require.NoError(t, err, "loopback URL %q should not require AllowInsecureHTTP", host)
	}
}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `go test ./internal/vaultclient/... -run "TestNew_RejectsPlainHTTPForNonLoopbackHost|TestNew_AllowInsecureHTTP_PermitsPlainHTTP|TestNew_AcceptsHTTPSWithoutOptOut|TestNew_AllowsPlainHTTPOnLoopback" -v`
Expected: compile FAILS (`Config.AllowInsecureHTTP` undefined). After adding the field alone, `TestNew_RejectsPlainHTTPForNonLoopbackHost` still FAILS since `New` doesn't check the scheme yet.

- [ ] **Step 3: Implement the fix**

In `internal/vaultclient/client.go`, update the import block from:

```go
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	"rocketvault/internal/retry"
)
```

to:

```go
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	"rocketvault/internal/retry"
)
```

Add `AllowInsecureHTTP` to `Config` — change (this is the version from Task 6):

```go
// Config holds credentials and secret mappings for the vault client.
type Config struct {
	URL          string          `yaml:"url"           mapstructure:"url"`
	ClientID     string          `yaml:"client_id"     mapstructure:"client_id"`
	ClientSecret string          `yaml:"client_secret" mapstructure:"client_secret"`
	Secrets      []SecretMapping `yaml:"secrets"       mapstructure:"secrets"`
	// Logger receives Warn calls on retries and auth failures. Optional; nil
	// disables all logging. Not settable via YAML/viper (interface value).
	Logger Logger
}
```

to:

```go
// Config holds credentials and secret mappings for the vault client.
type Config struct {
	URL          string          `yaml:"url"           mapstructure:"url"`
	ClientID     string          `yaml:"client_id"     mapstructure:"client_id"`
	ClientSecret string          `yaml:"client_secret" mapstructure:"client_secret"`
	Secrets      []SecretMapping `yaml:"secrets"       mapstructure:"secrets"`
	// AllowInsecureHTTP permits a non-https URL for non-loopback hosts. New
	// always allows plain http:// to 127.0.0.1/localhost/::1 (local dev,
	// tests) regardless of this flag. Defaults to false — set true only when
	// TLS is deliberately terminated elsewhere (e.g. a trusted internal mesh).
	AllowInsecureHTTP bool `yaml:"allow_insecure_http" mapstructure:"allow_insecure_http"`
	// Logger receives Warn calls on retries and auth failures. Optional; nil
	// disables all logging. Not settable via YAML/viper (interface value).
	Logger Logger
}
```

Replace `New` (`internal/vaultclient/client.go:50-69` originally; by now it also has the Task 6 `logger:` line) with:

```go
// New creates a Client from an explicit Config.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("vaultclient: Config.URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("vaultclient: Config.ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("vaultclient: Config.ClientSecret is required")
	}
	if !cfg.AllowInsecureHTTP {
		parsed, err := url.Parse(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("vaultclient: invalid Config.URL: %w", err)
		}
		if parsed.Scheme != "https" && !isLoopbackHost(parsed.Host) {
			return nil, fmt.Errorf(
				"vaultclient: Config.URL %q must use https for non-loopback hosts; set AllowInsecureHTTP to override for local/dev use",
				cfg.URL)
		}
	}
	index := make(map[string]string, len(cfg.Secrets))
	for _, m := range cfg.Secrets {
		index[m.Name] = m.UUID
	}
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		nameIndex:  index,
		logger:     cfg.Logger,
	}, nil
}

// isLoopbackHost reports whether host (as found in a parsed URL, optionally
// with a ":port" suffix) refers to the local machine.
func isLoopbackHost(host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
```

Replace `NewFromEnv` (`internal/vaultclient/client.go:72-78`) with:

```go
// NewFromEnv creates a Client from VAULT_URL, VAULT_CLIENT_ID, VAULT_CLIENT_SECRET,
// and optionally VAULT_ALLOW_INSECURE_HTTP env vars.
func NewFromEnv() (*Client, error) {
	allowInsecure, _ := strconv.ParseBool(os.Getenv("VAULT_ALLOW_INSECURE_HTTP"))
	return New(Config{
		URL:               os.Getenv("VAULT_URL"),
		ClientID:          os.Getenv("VAULT_CLIENT_ID"),
		ClientSecret:      os.Getenv("VAULT_CLIENT_SECRET"),
		AllowInsecureHTTP: allowInsecure,
	})
}
```

Replace `NewFromViper` (`internal/vaultclient/client.go:81-97`) with:

```go
// NewFromViper creates a Client from the vault_client Viper config section.
// client_secret falls back to VAULT_CLIENT_SECRET env var if absent from config.
func NewFromViper() (*Client, error) {
	var mappings []SecretMapping
	if err := viper.UnmarshalKey("vault_client.secrets", &mappings); err != nil {
		return nil, fmt.Errorf("vaultclient: failed to parse vault_client.secrets: %w", err)
	}
	secret := viper.GetString("vault_client.client_secret")
	if secret == "" {
		secret = os.Getenv("VAULT_CLIENT_SECRET")
	}
	return New(Config{
		URL:               viper.GetString("vault_client.url"),
		ClientID:          viper.GetString("vault_client.client_id"),
		ClientSecret:      secret,
		Secrets:           mappings,
		AllowInsecureHTTP: viper.GetBool("vault_client.allow_insecure_http"),
	})
}
```

- [ ] **Step 4: Update the four existing tests that use the non-loopback placeholder host**

In `internal/vaultclient/client_edge_test.go`, update `TestNewFromEnv_Success` (`:19-27`) by adding one more `t.Setenv` call:

```go
func TestNewFromEnv_Success(t *testing.T) {
	t.Setenv("VAULT_URL", "http://vault.local")
	t.Setenv("VAULT_CLIENT_ID", "env-id")
	t.Setenv("VAULT_CLIENT_SECRET", "env-secret")
	t.Setenv("VAULT_ALLOW_INSECURE_HTTP", "true")

	c, err := vaultclient.NewFromEnv()
	require.NoError(t, err)
	require.NotNil(t, c)
}
```

Update `TestNewFromViper_Success` (`:40-48`):

```go
func TestNewFromViper_Success(t *testing.T) {
	viper.Set("vault_client.url", "http://vault.local")
	viper.Set("vault_client.client_id", "viper-id")
	viper.Set("vault_client.client_secret", "viper-secret")
	viper.Set("vault_client.allow_insecure_http", true)

	c, err := vaultclient.NewFromViper()
	require.NoError(t, err)
	require.NotNil(t, c)
}
```

Update `TestNewFromViper_SecretFromEnv` (`:51-60`):

```go
func TestNewFromViper_SecretFromEnv(t *testing.T) {
	viper.Set("vault_client.url", "http://vault.local")
	viper.Set("vault_client.client_id", "viper-id")
	viper.Set("vault_client.client_secret", "")
	viper.Set("vault_client.allow_insecure_http", true)
	t.Setenv("VAULT_CLIENT_SECRET", "env-fallback")

	c, err := vaultclient.NewFromViper()
	require.NoError(t, err)
	require.NotNil(t, c)
}
```

Update `TestGetByName_UnknownName` (`:75-83`):

```go
func TestGetByName_UnknownName(t *testing.T) {
	c, err := vaultclient.New(vaultclient.Config{
		URL: "http://vault.local", ClientID: "id", ClientSecret: "s", AllowInsecureHTTP: true,
	})
	require.NoError(t, err)
	_, err = c.GetByName(context.Background(), "unknown-name")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no UUID mapping")
}
```

Do **not** change `TestNew_MissingClientID` or `TestNew_MissingClientSecret` — both return before the scheme check runs.

- [ ] **Step 5: Run the tests again to verify they pass**

Run: `go test ./internal/vaultclient/... -run "TestNew_|TestNewFromEnv|TestNewFromViper|TestGetByName_UnknownName" -v`
Expected: all PASS.

- [ ] **Step 6: Run the full vaultclient package test suite to check for regressions**

Run: `go test ./internal/vaultclient/... -count=1 -v`
Expected: PASS — every test using `httptest.NewServer` (loopback) is unaffected.

- [ ] **Step 7: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: success, no output.

- [ ] **Step 8: Commit**

```bash
git add internal/vaultclient/client.go internal/vaultclient/client_edge_test.go
git commit -S -m "feat(vaultclient): enforce https by default, exempt loopback hosts"
```

---

### Task 8: Prove the token-cache mutex with a `-race`-tested concurrency check

**The gap:** the mutex guarding the cached token is central to the design, but nothing proves it's correct under real concurrent load — only single-goroutine tests exist today.

**Files:**
- Create: `internal/vaultclient/concurrency_test.go`

- [ ] **Step 1: Write the test**

Create `internal/vaultclient/concurrency_test.go`:

```go
package vaultclient_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultclient"
)

// TestClient_ConcurrentGet_NoDataRace exercises the token cache from many
// goroutines simultaneously. Run with -race to prove the mutex is load-bearing.
func TestClient_ConcurrentGet_NoDataRace(t *testing.T) {
	srv := newTestServer(t, "concurrent-value")
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "test-id", ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "some-uuid"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("unexpected error from concurrent Get: %v", err)
	}
}
```

`newTestServer` is defined in `internal/vaultclient/client_test.go`, same `vaultclient_test` package — no import needed for it, it's already in scope.

- [ ] **Step 2: Run with `-race` to verify it passes clean**

Run: `go test ./internal/vaultclient/... -race -run TestClient_ConcurrentGet_NoDataRace -v`
Expected: PASS, no `WARNING: DATA RACE` output.

- [ ] **Step 3: Run the whole package under `-race` as a final proof**

Run: `go test ./internal/vaultclient/... -race -count=1 -v`
Expected: PASS, no data races anywhere in the package (this also re-verifies every test added in Tasks 5-7 under `-race`).

- [ ] **Step 4: Build and vet the whole module one last time**

Run: `go build ./... && go vet ./...`
Expected: success, no output.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultclient/concurrency_test.go
git commit -S -m "test(vaultclient): prove token-cache mutex under -race with concurrent Get"
```

---

## Final verification gate (after all 8 tasks)

- [ ] Run the full repository test suite: `go test ./... -count=1`. Expected: PASS, every package.
- [ ] Run `gofmt -l api/jwks.go api/jwks_test.go api/oauth2.go api/oauth2_handlers_test.go internal/middleware/middleware.go internal/vaultclient/*.go`. Expected: no output.
- [ ] Run `go vet ./...`. Expected: no output.
- [ ] Run `staticcheck -checks U1000 ./...` if available (`which staticcheck`). Expected: no new findings — this plan doesn't leave any dead code (`recordJWKSRotateAudit`, `recordOAuth2TokenAudit`, `recordServiceAccountAudit`, `logRetry`, `isLoopbackHost` are all called from the functions this plan modifies).
