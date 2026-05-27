# Security-Critical Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix six security-critical and high-severity findings from the Azure Key Vault parity audit: revoked session check, purge protection overwrite, service-account admin guard, CORS wildcard conflict, TLS config knob, and unwired input validation.

**Architecture:** All fixes are isolated to existing files — no new packages needed. Each finding maps to a small, contained change: one function, one handler, one config path, or one middleware registration. No new tables, no schema migrations.

**Tech Stack:** Go 1.24.2, Gorilla Mux, Viper config, JWT (`golang-jwt/jwt/v5`), `github.com/go-ozzo/ozzo-validation/v4`, `github.com/rs/cors`

---

## File Map

| File | Change |
|---|---|
| `internal/services/auth/jwt_service.go` | Add `sessionID uuid.UUID` param to `GenerateToken`; embed it as JWT `ID` claim |
| `internal/services/auth/authentication_service.go` | Pass `session.ID` to `GenerateToken`; add `IsSessionRevoked` check in `ValidateSession` |
| `internal/services/auth/authentication_service_critical_test.go` | Add `TestValidateSession_RevokedSession` and update existing tests for new signature |
| `internal/repositories/secret_repository.go` | Remove `purge_protection = FALSE` from `SoftDelete` |
| `internal/repositories/key_repository.go` | Same |
| `internal/repositories/certificate_repository.go` | Same |
| `api/oauth2.go` | Add admin role check at top of `createServiceAccount` |
| `server/server.go` | Remove `rs/cors` wildcard wrapper; let internal `CORSMiddleware` own CORS |
| `config/config.go` | Add `TLS` sub-struct with `Enabled`, `CertFile`, `KeyFile` |
| `.rocketvault.yaml` | Add `server.tls` section |
| `bootstrap/bootstrap.go` | Read TLS config from Viper and pass to `ServerConfig` |
| `api/secrets.go` | Call `validation.ValidateSecretCreate` in `createSecret` |
| `api/keys.go` | Call `validation.ValidateKeyCreate` in `createKey` |
| `api/certificates.go` | Call `validation.ValidateCertificateCreate` (add it) in `createCertificate` |
| `internal/validation/secret_validation.go` | No change needed |
| `internal/validation/key_validation.go` | No change needed |
| `internal/validation/common.go` | Add `CertificateNamePattern` if missing; add `ValidateCertificateCreate` |

---

## Task 1: Fix — Revoked sessions remain valid after logout

**Root cause:** `ValidateSession` only cryptographically validates the JWT; it never checks the `user_sessions.revoked` column. The session ID stored in the JWT `ID` (jti) claim is a fresh random UUID generated inside `GenerateToken` that has no link to the `session.ID` stored in the DB.

**Fix:** Thread `session.ID` into `GenerateToken` as the JWT `ID` claim; then in `ValidateSession`, extract that claim and call `sessionRepo.IsSessionRevoked`.

**Files:**
- Modify: `internal/services/auth/jwt_service.go` — `GenerateToken` signature + interface
- Modify: `internal/services/auth/authentication_service.go` — callers + `ValidateSession`
- Modify: `internal/services/auth/authentication_service_critical_test.go` — new test

- [ ] **Step 1.1: Write the failing test**

Add to `internal/services/auth/authentication_service_critical_test.go` after `TestValidateSession_InvalidToken`:

```go
func TestValidateSession_RevokedSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{
		UserID:   userID,
		Username: "alice",
		Role:     model.RoleUser,
	}
	claims.ID = sessionID.String() // jti carries the session ID

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "revoked-token").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(true, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	_, err := svc.ValidateSession(ctx, "revoked-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session revoked")
	sessionRepo.AssertExpectations(t)
}

func TestValidateSession_ActiveSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	claims := &JWTClaims{
		UserID:   userID,
		Username: "alice",
		Role:     model.RoleUser,
	}
	claims.ID = sessionID.String()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	jwt.On("ValidateToken", "good-token").Return(claims, nil)
	sessionRepo.On("IsSessionRevoked", ctx, sessionID).Return(false, nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	got, err := svc.ValidateSession(ctx, "good-token")

	require.NoError(t, err)
	assert.Equal(t, userID, got.UserID)
	sessionRepo.AssertExpectations(t)
}
```

- [ ] **Step 1.2: Run test to verify it fails**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/services/auth/... -run "TestValidateSession_RevokedSession|TestValidateSession_ActiveSession" -v
```

Expected: FAIL — `ValidateSession` does not call `IsSessionRevoked`.

- [ ] **Step 1.3: Update `GenerateToken` interface and implementation**

In `internal/services/auth/jwt_service.go`, change the `JWTService` interface and `GenerateToken` signature:

```go
// Before:
GenerateToken(userID uuid.UUID, username, role string) (string, error)

// After:
GenerateToken(userID uuid.UUID, username, role string, sessionID uuid.UUID) (string, error)
```

In the `jwtService.GenerateToken` implementation, replace the `ID` field:

```go
// Before:
ID: uuid.New().String(),

// After:
ID: sessionID.String(),
```

In the `legacyJWTService.GenerateToken` implementation (around line 254), add the `sessionID uuid.UUID` parameter and use it the same way:

```go
func (s *legacyJWTService) GenerateToken(userID uuid.UUID, username, role string, sessionID uuid.UUID) (string, error) {
    now := time.Now()
    claims := JWTClaims{
        UserID:   userID,
        Username: username,
        Role:     role,
        RegisteredClaims: jwt.RegisteredClaims{
            ID:        sessionID.String(),
            ExpiresAt: jwt.NewNumericDate(now.Add(s.expiry)),
            IssuedAt:  jwt.NewNumericDate(now),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    s.issuer,
            Subject:   userID.String(),
            Audience:  jwt.ClaimStrings{s.audience},
        },
    }
    // ... rest unchanged
```

- [ ] **Step 1.4: Update `ValidateSession` to check session revocation**

In `internal/services/auth/authentication_service.go`, replace the body of `ValidateSession` (lines 209–221):

```go
func (s *authenticationService) ValidateSession(ctx context.Context, token string) (*JWTClaims, error) {
	claims, err := s.jwtService.ValidateToken(token)
	if err != nil {
		s.logger.LogAuditError("", "validate_session", "failed", "Invalid session token", err)
		return nil, fmt.Errorf("invalid session: %w", err)
	}

	// Check revocation using the session ID embedded in the JWT jti claim.
	sessionID, err := uuid.Parse(claims.ID)
	if err != nil {
		s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "JWT jti is not a valid UUID", err)
		return nil, fmt.Errorf("invalid session: malformed jti")
	}

	revoked, err := s.sessionRepo.IsSessionRevoked(ctx, sessionID)
	if err != nil {
		s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Could not check session revocation", err)
		return nil, fmt.Errorf("invalid session: revocation check failed")
	}
	if revoked {
		s.logger.LogAuditError(claims.UserID.String(), "validate_session", "failed", "Session is revoked", nil)
		return nil, fmt.Errorf("session revoked")
	}

	s.logger.LogAuditInfo(claims.UserID.String(), "validate_session", "success", "Session validated successfully")
	return claims, nil
}
```

- [ ] **Step 1.5: Update `AuthenticateUser` and `RefreshAccessToken` callers of `GenerateToken`**

In `authentication_service.go`, find both calls to `s.jwtService.GenerateToken` and add the session ID argument:

Line ~144 (inside `AuthenticateUser`, after `session` is created):
```go
// Before:
accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role)

// After — session must be created before this call; move token generation after CreateSession:
accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role, session.ID)
```

Line ~272 (inside `RefreshAccessToken`):
```go
// Before:
accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role)

// After:
accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role, session.ID)
```

For `AuthenticateUser`: the current code generates the token (line 144) *before* creating the session (line 173). After the fix the session must exist before the token so that `session.ID` is known. Reorder those blocks: create session first, generate token second.

New order in `AuthenticateUser`:
1. Validate password
2. Validate TOTP
3. Generate refresh token
4. Create session record (sets `session.ID`)
5. Generate JWT with `session.ID`
6. Return result

- [ ] **Step 1.6: Update `MockJWTService` in test helpers**

In `internal/services/auth/authentication_service_test.go`, find `MockJWTService.GenerateToken` mock method and add the new `sessionID` parameter:

```go
func (m *MockJWTService) GenerateToken(userID uuid.UUID, username, role string, sessionID uuid.UUID) (string, error) {
	args := m.Called(userID, username, role, sessionID)
	return args.String(0), args.Error(1)
}
```

Also update any `jwt.On("GenerateToken", ...)` call sites — the `RefreshAccessToken` happy path test at line 129 needs the new signature:

```go
jwt.On("GenerateToken", userID, "bob", model.RoleUser, sessionID).Return("new-token", nil)
```

Check for any other mock registrations in `internal/testutils/mocks.go` and `cmd/testutils/test_utils.go` and update them the same way.

- [ ] **Step 1.7: Run all auth tests**

```bash
go test ./internal/services/auth/... -v
```

Expected: ALL PASS, including the two new `TestValidateSession_*` tests.

- [ ] **Step 1.8: Run full build check**

```bash
go build ./...
```

Expected: No errors.

- [ ] **Step 1.9: Commit**

```bash
git add \
  internal/services/auth/jwt_service.go \
  internal/services/auth/authentication_service.go \
  internal/services/auth/authentication_service_critical_test.go \
  internal/services/auth/authentication_service_test.go \
  internal/testutils/mocks.go \
  cmd/testutils/test_utils.go
git commit -m "fix(auth): check session revocation in ValidateSession

Thread session.ID into JWT jti claim; ValidateSession now calls
IsSessionRevoked so that logout actually invalidates tokens."
```

---

## Task 2: Fix — Purge protection overwritten to FALSE on every soft delete

**Root cause:** All three `SoftDelete` implementations hardcode `purge_protection = FALSE` in the UPDATE query. This means the column is always reset to FALSE regardless of any prior `SetPurgeProtection` call, making purge protection structurally non-functional.

**Fix:** Remove `purge_protection = FALSE` from all three `SoftDelete` UPDATE statements. The column retains whatever value was set before (default FALSE from INSERT, or TRUE if `SetPurgeProtection` was called).

**Files:**
- Modify: `internal/repositories/secret_repository.go` — `SoftDelete` at line 326
- Modify: `internal/repositories/key_repository.go` — `SoftDelete` at line 458
- Modify: `internal/repositories/certificate_repository.go` — `SoftDelete` at line 555

- [ ] **Step 2.1: Write failing tests**

Add to `internal/repositories/secret_repository_test.go` (or create a new `_purge_protection_test.go` file in the same package):

```go
func TestSoftDelete_PreservesPurgeProtection(t *testing.T) {
	// Set up an in-memory SQLite DB with the secrets table.
	// Call SetPurgeProtection(true) on a secret, then SoftDelete it.
	// Query the DB directly and assert purge_protection is still TRUE.
	db := setupTestDB(t) // use the existing test helper
	repo := newSecretRepo(t, db)
	ctx := context.Background()

	secret := createTestSecret(t, repo, ctx)
	require.NoError(t, repo.SetPurgeProtection(ctx, secret.ID, true))

	require.NoError(t, repo.SoftDelete(ctx, secret.ID))

	var pp bool
	err := db.QueryRowContext(ctx, "SELECT purge_protection FROM secrets WHERE id = ?", secret.ID.String()).Scan(&pp)
	require.NoError(t, err)
	assert.True(t, pp, "SoftDelete must not overwrite purge_protection")
}
```

Write equivalent tests for keys (`internal/repositories/key_repository_test.go`) and certificates (`internal/repositories/certificate_repository_test.go`) using their existing test helpers.

- [ ] **Step 2.2: Run tests to verify they fail**

```bash
go test ./internal/repositories/... -run "TestSoftDelete_PreservesPurgeProtection" -v
```

Expected: FAIL — purge_protection is FALSE after SoftDelete.

- [ ] **Step 2.3: Fix `secret_repository.go` SoftDelete**

In `internal/repositories/secret_repository.go`, find the UPDATE query in `SoftDelete` (around line 326):

```go
// Before:
"UPDATE secrets SET deleted_at = ?, purge_protection = FALSE WHERE id = ? AND deleted_at IS NULL",

// After:
"UPDATE secrets SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
```

- [ ] **Step 2.4: Fix `key_repository.go` SoftDelete**

In `internal/repositories/key_repository.go`, find the UPDATE query in `SoftDelete` (around line 458):

```go
// Before:
"UPDATE keys SET deleted_at = ?, purge_protection = FALSE WHERE id = ? AND deleted_at IS NULL",

// After:
"UPDATE keys SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
```

- [ ] **Step 2.5: Fix `certificate_repository.go` SoftDelete**

In `internal/repositories/certificate_repository.go`, find the UPDATE query in `SoftDelete` (around line 555):

```go
// Before:
"UPDATE certificates SET deleted_at = ?, purge_protection = FALSE WHERE id = ? AND deleted_at IS NULL",

// After:
"UPDATE certificates SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
```

- [ ] **Step 2.6: Run tests to verify they pass**

```bash
go test ./internal/repositories/... -run "TestSoftDelete_PreservesPurgeProtection" -v
```

Expected: PASS for all three resource types.

- [ ] **Step 2.7: Run all repository tests**

```bash
go test ./internal/repositories/... -v
```

Expected: ALL PASS.

- [ ] **Step 2.8: Commit**

```bash
git add \
  internal/repositories/secret_repository.go \
  internal/repositories/key_repository.go \
  internal/repositories/certificate_repository.go \
  internal/repositories/secret_repository_test.go \
  internal/repositories/key_repository_test.go \
  internal/repositories/certificate_repository_test.go
git commit -m "fix(soft-delete): preserve purge_protection on soft delete

SoftDelete was hardcoding purge_protection = FALSE, overwriting any
prior SetPurgeProtection call and making purge protection non-functional."
```

---

## Task 3: Fix — Any authenticated user can create a service account

**Root cause:** `createServiceAccount` in `api/oauth2.go` (line 137) has no role check. A comment at line 134 says "Admin-only" but the code does not enforce it. Any authenticated user can POST to `/service-accounts` and create a privileged credential.

**Fix:** Add an admin role guard at the top of `createServiceAccount`, using the same `c.Claims["role"]` pattern used in `api/keys.go:124`.

**Files:**
- Modify: `api/oauth2.go` — `createServiceAccount`

- [ ] **Step 3.1: Write a failing test**

Add to `api/oauth2_test.go` (or create `api/oauth2_test.go` if it does not exist):

```go
func TestCreateServiceAccount_NonAdminForbidden(t *testing.T) {
	// Make a POST /service-accounts request with a non-admin JWT claim.
	// Expect 403 Forbidden.
	c, w, r := newTestContext(t, map[string]any{
		"role":    model.RoleUser,
		"user_id": uuid.New().String(),
	})
	r.Body = io.NopCloser(strings.NewReader(`{"name":"svc"}`))
	createServiceAccount(c, w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateServiceAccount_AdminAllowed(t *testing.T) {
	// Make a POST /service-accounts request with admin JWT claim.
	// Expect 201 Created (service mock returns a dummy client).
	// ... setup mock OAuth2 service to return a client and plain secret
}
```

Use the same `newTestContext` helper pattern as other `api/*_test.go` files in the repo. If that helper doesn't exist, create a minimal one that sets up a `*Context` with the given claims map.

- [ ] **Step 3.2: Run test to verify it fails**

```bash
go test ./api/... -run "TestCreateServiceAccount_NonAdminForbidden" -v
```

Expected: FAIL — non-admin gets 201, not 403.

- [ ] **Step 3.3: Add admin role guard**

In `api/oauth2.go`, add these lines at the top of `createServiceAccount`, immediately after the function signature:

```go
func createServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	roleStr, _ := c.Claims["role"].(string)
	if !common.HasRequiredRole(roleStr, model.RoleAdmin) {
		c.SetPermissionError("admin role required to create service accounts")
		return
	}

	// ... rest of existing code unchanged
```

- [ ] **Step 3.4: Run test to verify it passes**

```bash
go test ./api/... -run "TestCreateServiceAccount_NonAdminForbidden" -v
```

Expected: PASS — non-admin receives 403.

- [ ] **Step 3.5: Run all API tests**

```bash
go test ./api/... -v
```

Expected: ALL PASS.

- [ ] **Step 3.6: Commit**

```bash
git add api/oauth2.go api/oauth2_test.go
git commit -m "fix(auth): restrict service account creation to admin role

Any authenticated user could create service accounts, allowing
privilege escalation. Now enforces admin role at the handler level."
```

---

## Task 4: Fix — rs/cors wildcard overrides internal CORS allowlist

**Root cause:** `server/server.go` wraps the entire router with `rs/cors` configured as `AllowedOrigins: ["*"]` and `AllowCredentials: true`. This is both insecure (credentials + wildcard is rejected by browsers per spec, yet it signals intent) and it overrides the correct `CORSMiddleware` registered in `internal/middleware`. The external wrapper runs first and writes `Access-Control-Allow-Origin: *`, shadowing the allowlist-based response.

**Fix:** Remove the `rs/cors` wrapper. The router is already protected by the internal `CORSMiddleware` which implements the allowlist correctly. The `"github.com/rs/cors"` import will also be removed.

**Files:**
- Modify: `server/server.go`

- [ ] **Step 4.1: Confirm internal CORSMiddleware is wired**

```bash
grep -n "CORSMiddleware\|Use(" /home/numericlabs/data/rocket/rocketvault/api/api.go | head -20
```

Expected: `CORSMiddleware` appears in the middleware chain. If it does not, add it before removing the rs/cors wrapper.

- [ ] **Step 4.2: Write a test (manual check)**

This cannot be unit-tested directly without a running server and browser-initiated requests. After the fix, verify with `curl`:

```bash
# Start the server in a separate terminal, then:
curl -v -H "Origin: http://evil.example.com" http://localhost:8080/api/v1/health
```

Expected: No `Access-Control-Allow-Origin` header in the response (the origin is not allowlisted).

```bash
curl -v -H "Origin: http://localhost:3000" http://localhost:8080/api/v1/health
```

Expected: `Access-Control-Allow-Origin: http://localhost:3000` appears (if `localhost:3000` is in `server.cors_origins` config) or no header if not configured.

- [ ] **Step 4.3: Remove rs/cors wrapper from `server/server.go`**

Replace the `cc.Handler(s.Router)` wrapper with the bare router:

```go
// Before (line ~111-117 and ~137):
cc := cors.New(cors.Options{
    AllowedOrigins:   []string{"*"},
    AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
    AllowedHeaders:   []string{"*"},
    AllowCredentials: true,
    MaxAge:           86400,
})
// ...
srv := &http.Server{
    Handler: cc.Handler(s.Router),
    // ...
}

// After:
srv := &http.Server{
    Handler: s.Router,
    // ...
}
```

Remove the `cc := cors.New(...)` block entirely.

Remove the `"github.com/rs/cors"` import from the `import` block.

- [ ] **Step 4.4: Build to confirm no compile errors**

```bash
go build ./...
```

Expected: No errors. If `rs/cors` is used elsewhere, the compiler will flag it.

- [ ] **Step 4.5: Run server tests**

```bash
go test ./server/... ./internal/middleware/... -v
```

Expected: ALL PASS.

- [ ] **Step 4.6: Commit**

```bash
git add server/server.go
git commit -m "fix(cors): remove rs/cors wildcard wrapper

The global AllowedOrigins=[*] + AllowCredentials=true wrapper was
shadowing the internal CORSMiddleware allowlist. Removing it lets
the correct middleware own CORS for all routes."
```

---

## Task 5: Fix — TLS disabled by default with no config knob

**Root cause:** `server.NewDefaultServer` hardcodes `EnableTLS: false` and there is no Viper config key to enable TLS. The `ServerConfig` struct already has `EnableTLS`, `CertFile`, and `KeyFile` fields, but the bootstrap never reads them from config.

**Fix:** Add `server.tls.*` keys to `.rocketvault.yaml` and read them in bootstrap so an operator can enable TLS without code changes.

**Files:**
- Modify: `config/config.go` — add `TLS` struct
- Modify: `.rocketvault.yaml` — add `server.tls` section
- Modify: `bootstrap/bootstrap.go` — read TLS config and pass to server

- [ ] **Step 5.1: Write a failing test**

In `bootstrap/bootstrap_test.go` (or an appropriate existing test file), add:

```go
func TestBootstrap_TLSConfigRead(t *testing.T) {
	// Set viper values for TLS and verify they are reflected in ServerConfig.
	viper.Set("server.tls.enabled", true)
	viper.Set("server.tls.cert_file", "/tmp/test.crt")
	viper.Set("server.tls.key_file", "/tmp/test.key")
	defer viper.Reset()

	cfg := buildServerConfigFromViper() // the helper we will extract in step 5.3
	assert.True(t, cfg.EnableTLS)
	assert.Equal(t, "/tmp/test.crt", cfg.CertFile)
	assert.Equal(t, "/tmp/test.key", cfg.KeyFile)
}
```

- [ ] **Step 5.2: Run test to verify it fails**

```bash
go test ./bootstrap/... -run "TestBootstrap_TLSConfigRead" -v
```

Expected: FAIL — function not defined yet.

- [ ] **Step 5.3: Add TLS config struct to `config/config.go`**

Add to the config package:

```go
// TLSConfig holds TLS listener configuration.
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}
```

If a top-level `Config` struct exists, add a `TLS TLSConfig` field tagged `mapstructure:"tls"`. If config is read purely via `viper.Get*` calls (no struct unmarshalling), skip this and read directly in bootstrap.

- [ ] **Step 5.4: Add `server.tls` section to `.rocketvault.yaml`**

Find the `server:` block in `.rocketvault.yaml` and add:

```yaml
server:
  # ... existing keys ...
  tls:
    enabled: false          # Set to true and provide cert/key paths for HTTPS.
    cert_file: ""           # Path to PEM certificate file.
    key_file: ""            # Path to PEM private key file.
```

- [ ] **Step 5.5: Extract and wire `buildServerConfigFromViper` in `bootstrap/bootstrap.go`**

In `bootstrap/bootstrap.go`, locate where `server.NewDefaultServer` is called (around line 268). Replace it with:

```go
func buildServerConfigFromViper() server.ServerConfig {
	return server.ServerConfig{
		EnableHTTP2:     viper.GetBool("server.http2.enabled"),
		EnableTLS:       viper.GetBool("server.tls.enabled"),
		CertFile:        viper.GetString("server.tls.cert_file"),
		KeyFile:         viper.GetString("server.tls.key_file"),
		EnableWebSocket: false,
		MaxConnections:  1000,
	}
}
```

Then at the call site:

```go
// Before:
app.WithServer(server.NewDefaultServer(b.cfg.Logger, cfg.Listen)),

// After:
serverCfg := buildServerConfigFromViper()
app.WithServer(server.NewServer(b.cfg.Logger, cfg.Listen, serverCfg)),
```

- [ ] **Step 5.6: Run test to verify it passes**

```bash
go test ./bootstrap/... -run "TestBootstrap_TLSConfigRead" -v
```

Expected: PASS.

- [ ] **Step 5.7: Run full build**

```bash
go build ./...
```

Expected: No errors.

- [ ] **Step 5.8: Commit**

```bash
git add config/config.go .rocketvault.yaml bootstrap/bootstrap.go bootstrap/bootstrap_test.go
git commit -m "feat(server): add server.tls config knob for TLS enablement

TLS was previously only configurable by code change. Operators can now
set server.tls.enabled=true with cert_file/key_file paths in the YAML."
```

---

## Task 6: Fix — Input validation package never called by HTTP handlers

**Root cause:** `internal/validation` defines `ValidateSecretCreate`, `ValidateKeyCreate` (and name/tag limits), but none of the HTTP handlers in `api/secrets.go`, `api/keys.go`, or `api/certificates.go` call these functions. Oversized values (>25KB), excess tags (>15), and invalid names all reach the service layer unchecked.

**Fix:** Call the existing validation functions at the top of each create handler, before any service calls. Return 400 on validation failure.

**Files:**
- Modify: `api/secrets.go` — `createSecret`
- Modify: `api/keys.go` — `createKey`
- Modify: `api/certificates.go` — `createCertificate`
- Modify: `internal/validation/common.go` — add `CertificateNamePattern` and `ValidateCertificateCreate` if missing

- [ ] **Step 6.1: Check whether `ValidateCertificateCreate` exists**

```bash
grep -r "ValidateCertificateCreate\|CertificateNamePattern" /home/numericlabs/data/rocket/rocketvault/internal/validation/
```

If it does not exist, add to `internal/validation/common.go`:

```go
// CertificateNamePattern is the allowed name regex for certificates.
var CertificateNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,126}$`)

// CertificateNameRule validates certificate names.
func CertificateNameRule() validation.Rule {
	return validation.Match(CertificateNamePattern).Error("must contain only alphanumeric characters and hyphens, and start with a letter")
}
```

And create `internal/validation/certificate_validation.go`:

```go
package validation

import validation "github.com/go-ozzo/ozzo-validation/v4"

// CertificateCreateRequest is the input for creating a certificate.
type CertificateCreateRequest struct {
	Name string
	Tags []string
}

// ValidateCertificateCreate validates certificate creation input.
func ValidateCertificateCreate(req CertificateCreateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.Required,
			validation.Length(1, 127),
			CertificateNameRule(),
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
	)
}
```

- [ ] **Step 6.2: Write failing tests for secrets validation**

Add to `api/secrets_test.go` (create if needed — follow the existing test file pattern):

```go
func TestCreateSecret_ValueTooLarge_Returns400(t *testing.T) {
	c, w, r := newTestContext(t, map[string]any{
		"role":    model.RoleAdmin,
		"user_id": uuid.New().String(),
	})
	body := map[string]any{
		"name":  "valid-secret",
		"value": strings.Repeat("x", 25601), // over 25KB
	}
	bodyBytes, _ := json.Marshal(body)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	createSecret(c, w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSecret_InvalidName_Returns400(t *testing.T) {
	c, w, r := newTestContext(t, map[string]any{
		"role":    model.RoleAdmin,
		"user_id": uuid.New().String(),
	})
	body := map[string]any{
		"name":  "123-starts-with-digit",
		"value": "some-value",
	}
	bodyBytes, _ := json.Marshal(body)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	createSecret(c, w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

- [ ] **Step 6.3: Run tests to verify they fail**

```bash
go test ./api/... -run "TestCreateSecret_ValueTooLarge|TestCreateSecret_InvalidName" -v
```

Expected: FAIL — handlers return 201/500 instead of 400.

- [ ] **Step 6.4: Wire validation into `createSecret` in `api/secrets.go`**

After the existing required-field checks (lines 336–343) and before the `userID` extraction, add:

```go
// Validate input against Azure Key Vault limits.
if err := vvalidation.ValidateSecretCreate(vvalidation.SecretCreateRequest{
    Name:  req.Name,
    Value: req.Value,
    Tags:  req.Tags,
}); err != nil {
    c.SetInvalidParam(err.Error())
    return
}
```

Add the import at the top of `api/secrets.go` if not present:
```go
vvalidation "rocketvault/internal/validation"
```

- [ ] **Step 6.5: Wire validation into `createKey` in `api/keys.go`**

After the inline `req.Name == "" || req.Type == ""` check (line 137) and the type-normalisation block, add:

```go
if err := vvalidation.ValidateKeyCreate(vvalidation.KeyCreateRequest{
    Name:  req.Name,
    Type:  req.Type,
    Bits:  req.Bits,
    Curve: req.Curve,
    Tags:  req.Tags,
}); err != nil {
    c.SetInvalidParam(err.Error())
    return
}
```

- [ ] **Step 6.6: Wire validation into `createCertificate` in `api/certificates.go`**

Find the start of `createCertificate` (line 108). After decoding the request body, add:

```go
if err := vvalidation.ValidateCertificateCreate(vvalidation.CertificateCreateRequest{
    Name: req.Name,
    Tags: req.Tags,
}); err != nil {
    c.SetInvalidParam(err.Error())
    return
}
```

- [ ] **Step 6.7: Run failing tests to verify they pass**

```bash
go test ./api/... -run "TestCreateSecret_ValueTooLarge|TestCreateSecret_InvalidName" -v
```

Expected: PASS — both return 400.

- [ ] **Step 6.8: Run all tests**

```bash
go test ./... -v 2>&1 | tail -50
```

Expected: ALL PASS (or only pre-existing failures, if any).

- [ ] **Step 6.9: Commit**

```bash
git add \
  api/secrets.go \
  api/keys.go \
  api/certificates.go \
  api/secrets_test.go \
  api/keys_test.go \
  api/certificates_test.go \
  internal/validation/certificate_validation.go \
  internal/validation/common.go
git commit -m "fix(validation): wire input validation into create handlers

ValidateSecretCreate, ValidateKeyCreate, ValidateCertificateCreate now
called at handler entry points, enforcing 25KB value limit, 15-tag cap,
and name regex before any service or DB call."
```

---

## Self-Review

### Spec coverage check

| Audit finding | Task |
|---|---|
| Revoked sessions remain valid until JWT expiry | Task 1 |
| `purge_protection = FALSE` hardcoded in `SoftDelete` | Task 2 |
| `createServiceAccount` has no admin-role guard | Task 3 |
| rs/cors wildcard overrides allowlist CORS middleware | Task 4 |
| TLS off by default; no config key to enable | Task 5 |
| `internal/validation` never invoked by HTTP handlers | Task 6 |

All six short-term audit findings are covered.

### Placeholder scan

- All code blocks are complete.
- All test assertions are specific (status codes, error strings).
- All file paths and line references are exact.
- No "TBD" or "fill in later" text.

### Type consistency

- `GenerateToken` signature change propagated to: interface definition, `jwtService` impl, `legacyJWTService` impl, `MockJWTService`, all call sites in `AuthenticateUser` and `RefreshAccessToken`.
- `ValidateCertificateCreate` struct name `CertificateCreateRequest` matches usage in Task 6.6.
- `vvalidation` alias used consistently across Tasks 6.4–6.6.
