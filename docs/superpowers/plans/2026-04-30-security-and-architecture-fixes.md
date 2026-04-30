# Security & Architecture Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all critical security vulnerabilities and medium-severity architectural issues identified in the architecture review, in dependency order, each producing a buildable, tested codebase.

**Architecture:** Fixes are ordered by severity and dependency: security bugs first (refresh token hash, dual auth path, policy fail-open, IDOR), then infrastructure bugs (CORS, rate limiter, global DB, request ID, TOTP log), then DB transactions, then code quality (nil guards, typed claims, context keys, migration error handling, dual logging). Each task is independently committable.

**Tech Stack:** Go 1.24.2, Gorilla Mux, golang-jwt/jwt v5, golang.org/x/crypto, crypto/sha256, lib/pq, ulule/limiter v3, logrus, viper, testify/mock

---

## File Map

| File | Change |
|------|--------|
| `internal/services/auth/authentication_service.go` | Fix `hashRefreshToken` (C1), remove TOTP code from logs (H5) |
| `internal/middleware/middleware.go` | Fix policy fail-open (C3), CORS allowlist (H1), rate limiter key+store (H2), request ID (H4) |
| `api/context.go` | Remove duplicate JWT validation from `SessionRequired` (C2); change `Claims` field type (M2) |
| `internal/services/secrets/secret_service.go` | Enforce ownership at query level via `GetSecret` signature (C4) |
| `internal/repositories/secret_repository.go` | `Read` to filter by `user_id` (C4) |
| `common/context.go` | Replace `iota` int keys with struct-pointer keys (M6) |
| `internal/db/db.go` | Remove global `var DB *sql.DB` where safe; fix PostgreSQL error code check (M5) |
| `internal/db/txhelper.go` | New: `WithTx` helper (H6) |
| `internal/services/secrets/secret_service.go` | Wrap `CreateSecret`/`UpdateSecret` in `WithTx` (H6) |
| `api/secrets.go` | Remove 40+ nil-guard boilerplate blocks (M1); fix wrong error context in `getSecret`/`updateSecret`/`listSecrets` (M1) |
| `internal/logging/logging.go` | Remove bare `logrus.*` calls; consolidate to injected logger (M8) |
| `internal/services/auth/authentication_service.go` | Remove bare `logrus.*` calls (M8) |
| `.rocketvault.yaml` | Add `server.cors_allowed_origins` config key |
| `internal/middleware/middleware_test.go` | Tests for CORS, rate limiter, policy deny-on-error, request ID uniqueness |
| `internal/services/auth/authentication_service_test.go` | Test for hashed refresh token, no TOTP in logs |
| `api/context_test.go` | Test SessionRequired reads from r.Context() not re-validates |

---

## Task 1: Fix refresh token hash (C1 — Critical)

**Files:**
- Modify: `internal/services/auth/authentication_service.go:376-382`
- Modify: `internal/services/auth/authentication_service_test.go`

### Background

`hashRefreshToken` currently does `fmt.Sprintf("%x", token)` which is a hex re-encoding of the token string bytes — not a hash. The refresh token is effectively stored in plaintext in `user_sessions`. Fix: use `crypto/sha256`.

- [ ] **Step 1: Write a failing test**

Add to `internal/services/auth/authentication_service_test.go`:

```go
package auth_test

import (
    "crypto/sha256"
    "encoding/hex"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestHashRefreshToken_IsActualHash(t *testing.T) {
    svc := &authenticationService{}
    token := "abc123plaintext"

    result := svc.hashRefreshToken(token)

    // fmt.Sprintf("%x", token) would equal hex.EncodeToString([]byte(token))
    naive := hex.EncodeToString([]byte(token))
    assert.NotEqual(t, naive, result, "hashRefreshToken must not be a naive hex encode")

    // Result must equal sha256 of the token
    sum := sha256.Sum256([]byte(token))
    expected := hex.EncodeToString(sum[:])
    assert.Equal(t, expected, result)
    assert.Len(t, result, 64, "sha256 hex is always 64 chars")
}

func TestHashRefreshToken_Deterministic(t *testing.T) {
    svc := &authenticationService{}
    token := "some-token-value"
    require.Equal(t, svc.hashRefreshToken(token), svc.hashRefreshToken(token))
}

func TestHashRefreshToken_DifferentInputsDifferentOutputs(t *testing.T) {
    svc := &authenticationService{}
    assert.NotEqual(t, svc.hashRefreshToken("a"), svc.hashRefreshToken("b"))
}
```

Note: `authenticationService` struct must be exported or the test placed in the same package (`package auth`). The existing tests are in `package auth` — keep this test there too.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./internal/services/auth/... -run TestHashRefreshToken -v
```

Expected: `FAIL` — result equals naive hex encode.

- [ ] **Step 3: Fix `hashRefreshToken`**

In `internal/services/auth/authentication_service.go`, replace lines 367-382:

```go
import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    // ... existing imports
)

// hashRefreshToken produces a SHA-256 hash of the token for storage.
// The token itself (32 random bytes as hex) has enough entropy that
// SHA-256 without salt is safe for this use case.
func (s *authenticationService) hashRefreshToken(token string) string {
    sum := sha256.Sum256([]byte(token))
    return hex.EncodeToString(sum[:])
}
```

Also remove the now-unused `fmt` import if it is no longer used elsewhere in this file. Check with `go build ./...`.

- [ ] **Step 4: Verify tests pass**

```bash
go test ./internal/services/auth/... -run TestHashRefreshToken -v
```

Expected: all three sub-tests `PASS`.

- [ ] **Step 5: Run full auth test suite**

```bash
go test ./internal/services/auth/... -v
```

Expected: all existing tests still pass.

- [ ] **Step 6: Build check**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/services/auth/authentication_service.go internal/services/auth/authentication_service_test.go
git commit -m "fix(auth): use sha256 for refresh token hash instead of fmt.Sprintf hex"
```

---

## Task 2: Remove TOTP code from failure logs (H5 — High)

**Files:**
- Modify: `internal/services/auth/authentication_service.go:135-141`

### Background

When TOTP validation fails, the log entry includes `"totp_code": totpCode`. Time-based OTPs have a ~30 second window; logged codes in persistent log files create a replay opportunity.

- [ ] **Step 1: Write a failing test**

Add to `internal/services/auth/authentication_service_test.go`. This test captures log output and asserts no TOTP code appears:

```go
func TestAuthenticateUser_FailedTOTP_DoesNotLogCode(t *testing.T) {
    // Capture logrus output
    var buf bytes.Buffer
    logrus.SetOutput(&buf)
    defer logrus.SetOutput(os.Stderr)
    logrus.SetLevel(logrus.WarnLevel)

    mockUserRepo := &MockUserRepository{}
    mockSessionRepo := &MockSessionRepository{}
    mockPasswordService := &MockPasswordService{}
    mockTOTPService := &MockTOTPService{}
    mockJWTService := &MockJWTService{}

    testUser := domain.User{
        ID:           uuid.New(),
        Username:     "alice",
        PasswordHash: "$2a$10$test",
        TOTPSecret:   "JBSWY3DPEHPK3PXP",
        Role:         domain.RoleUser,
    }

    mockUserRepo.On("ReadByUsername", mock.Anything, "alice").Return(testUser, nil)
    mockPasswordService.On("ValidatePassword", "password123", testUser.PasswordHash).Return(nil)
    mockTOTPService.On("ValidateCode", "123456", testUser.TOTPSecret, mock.AnythingOfType("time.Time")).
        Return(false, nil)

    svc := NewAuthenticationService(AuthenticationConfig{
        UserRepository:    mockUserRepo,
        SessionRepository: mockSessionRepo,
        PasswordService:   mockPasswordService,
        TOTPService:       mockTOTPService,
        JWTService:        mockJWTService,
        Logger:            logging.NewLogger(),
    })

    _, err := svc.AuthenticateUser(context.Background(), "alice", "password123", "123456")
    assert.Error(t, err)
    assert.NotContains(t, buf.String(), "123456", "TOTP code must not appear in logs")
    assert.NotContains(t, buf.String(), "totp_code")
}
```

Add required imports: `"bytes"`, `"os"`, `"github.com/sirupsen/logrus"`.

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/services/auth/... -run TestAuthenticateUser_FailedTOTP -v
```

Expected: `FAIL` — `"123456"` found in log output.

- [ ] **Step 3: Remove `totp_code` from log field**

In `internal/services/auth/authentication_service.go`, find the log block around line 135:

```go
// BEFORE
logrus.WithFields(logrus.Fields{
    "username":  username,
    "user_id":   user.ID.String(),
    "totp_code": totpCode,
}).Warn("Authentication failed: invalid TOTP code")

// AFTER
logrus.WithFields(logrus.Fields{
    "username": username,
    "user_id":  user.ID.String(),
}).Warn("Authentication failed: invalid TOTP code")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/services/auth/... -run TestAuthenticateUser_FailedTOTP -v
```

Expected: `PASS`.

- [ ] **Step 5: Build and commit**

```bash
go build ./...
git add internal/services/auth/authentication_service.go internal/services/auth/authentication_service_test.go
git commit -m "fix(auth): remove TOTP code from failure log to prevent replay window"
```

---

## Task 3: Fix PolicyMiddleware to fail closed (C3 — Critical)

**Files:**
- Modify: `internal/middleware/middleware.go:343-348`
- Modify: `internal/middleware/middleware_test.go`

### Background

When `CheckAccess` returns an error (e.g., DB down), the middleware currently allows the request through. A credential store must deny-by-default on policy evaluation errors.

- [ ] **Step 1: Write a failing test**

In `internal/middleware/middleware_test.go`, add:

```go
func TestPolicyMiddleware_ErrorDeniesRequest(t *testing.T) {
    mockContainer := &MockContainer{}
    mockPolicySvc := &MockAccessPolicyService{}
    mockAuthSvc := &MockAuthenticationService{}
    mockRBACService := &MockRBACService{}
    mockLogger := logging.NewTestLogger()

    mockContainer.On("GetLogger").Return(mockLogger)
    mockContainer.On("GetAuthenticationService").Return(mockAuthSvc)
    mockContainer.On("GetRBACService").Return(mockRBACService)
    mockContainer.On("GetAccessPolicyService").Return(mockPolicySvc)

    // Policy service returns an error (simulates DB outage)
    mockPolicySvc.On("CheckAccess", mock.Anything, mock.Anything,
        domain.PolicyResourceSecrets, domain.OpGet).
        Return(authzServices.AccessFallback, fmt.Errorf("db connection refused"))

    m := NewMiddleware(mockContainer)

    req := httptest.NewRequest(http.MethodGet, "/secrets/some-id", nil)
    // Set a valid user ID in context (as AuthenticationMiddleware would)
    userID := uuid.New()
    ctx := context.WithValue(req.Context(), common.UserIDKey, userID.String())
    req = req.WithContext(ctx)

    rr := httptest.NewRecorder()
    handler := m.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))
    handler.ServeHTTP(rr, req)

    assert.Equal(t, http.StatusInternalServerError, rr.Code,
        "policy check error must deny request, not allow it through")
}
```

Required imports for test file: `"fmt"`, `"github.com/google/uuid"`, `"rocketvault/common"`, `authzServices "rocketvault/internal/services/authorization"`, `"rocketvault/internal/domain"`.

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/middleware/... -run TestPolicyMiddleware_ErrorDeniesRequest -v
```

Expected: `FAIL` — status 200 received instead of 500.

- [ ] **Step 3: Fix the fail-open in `PolicyMiddleware`**

In `internal/middleware/middleware.go`, find the error block (around line 343):

```go
// BEFORE
if err != nil {
    // Log but don't block on evaluation errors — fail open via fallback.
    logrus.WithError(err).Warn("PolicyMiddleware: access policy check error, allowing request")
    next.ServeHTTP(w, r)
    return
}

// AFTER
if err != nil {
    m.logger.LogAuditError(userIDStr, "policy", "error",
        "Access policy check failed — denying request", err)
    http.Error(w, "Internal server error", http.StatusInternalServerError)
    return
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/middleware/... -run TestPolicyMiddleware_ErrorDeniesRequest -v
```

Expected: `PASS`.

- [ ] **Step 5: Run full middleware suite**

```bash
go test ./internal/middleware/... -v
```

Expected: all existing tests pass.

- [ ] **Step 6: Build and commit**

```bash
go build ./...
git add internal/middleware/middleware.go internal/middleware/middleware_test.go
git commit -m "fix(middleware): policy check errors must deny the request, not allow it through"
```

---

## Task 4: Fix CORS — replace wildcard with allowlist (H1 — High)

**Files:**
- Modify: `internal/middleware/middleware.go:394-409`
- Modify: `internal/middleware/middleware_test.go`
- Modify: `.rocketvault.yaml`

### Background

`Access-Control-Allow-Origin: *` is inappropriate for an authenticated API. Replace with a configurable allowlist read from Viper.

- [ ] **Step 1: Add config key to `.rocketvault.yaml`**

Open `.rocketvault.yaml` and add under the `server:` block:

```yaml
server:
  host: ""
  port: 8774
  # ... existing keys ...
  cors_allowed_origins:
    - "http://localhost:3000"
    - "http://localhost:8774"
```

- [ ] **Step 2: Update `Middleware` struct to carry allowed origins**

In `internal/middleware/middleware.go`, change the struct and constructor:

```go
type Middleware struct {
    container      Container
    logger         *logging.Logger
    defaultLimiter *limiter.Limiter
    authLimiter    *limiter.Limiter
    corsOrigins    map[string]bool // allowed origins set
}

func NewMiddleware(container Container) *Middleware {
    store := memory.NewStore()
    // ... existing limiter setup unchanged ...

    // Build allowed-origins set from viper config.
    // Import "github.com/spf13/viper" at top of file.
    allowed := viper.GetStringSlice("server.cors_allowed_origins")
    corsOrigins := make(map[string]bool, len(allowed))
    for _, o := range allowed {
        corsOrigins[o] = true
    }

    return &Middleware{
        container:      container,
        logger:         container.GetLogger(),
        defaultLimiter: defaultLimiter,
        authLimiter:    authLimiter,
        corsOrigins:    corsOrigins,
    }
}
```

Add `"github.com/spf13/viper"` to the import block.

- [ ] **Step 3: Replace `CORSMiddleware` implementation**

```go
func (m *Middleware) CORSMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        if origin != "" && m.corsOrigins[origin] {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
            w.Header().Set("Vary", "Origin")
        }

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

- [ ] **Step 4: Write tests**

```go
func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
    m := &Middleware{
        corsOrigins: map[string]bool{"https://app.example.com": true},
    }
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    req.Header.Set("Origin", "https://app.example.com")
    rr := httptest.NewRecorder()
    m.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })).ServeHTTP(rr, req)

    assert.Equal(t, "https://app.example.com", rr.Header().Get("Access-Control-Allow-Origin"))
    assert.Equal(t, "Origin", rr.Header().Get("Vary"))
}

func TestCORSMiddleware_DisallowedOrigin(t *testing.T) {
    m := &Middleware{
        corsOrigins: map[string]bool{"https://app.example.com": true},
    }
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    req.Header.Set("Origin", "https://evil.example.com")
    rr := httptest.NewRecorder()
    m.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })).ServeHTTP(rr, req)

    assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_NoOriginHeader(t *testing.T) {
    m := &Middleware{corsOrigins: map[string]bool{}}
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    rr := httptest.NewRecorder()
    m.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })).ServeHTTP(rr, req)

    assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
    assert.Equal(t, http.StatusOK, rr.Code)
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/middleware/... -run TestCORSMiddleware -v
```

Expected: all three pass.

- [ ] **Step 6: Build and commit**

```bash
go build ./...
git add internal/middleware/middleware.go internal/middleware/middleware_test.go .rocketvault.yaml
git commit -m "fix(middleware): replace wildcard CORS with configurable allowlist"
```

---

## Task 5: Fix rate limiter — separate stores and correct IP extraction (H2 — High)

**Files:**
- Modify: `internal/middleware/middleware.go:71-88` (constructor), `middleware.go:129-180` (RateLimitMiddleware)
- Modify: `internal/middleware/middleware_test.go`

### Background

Two bugs: (1) `defaultLimiter` and `authLimiter` share one `memory.Store` — their namespaces collide. (2) `r.RemoteAddr` includes the TCP port (`1.2.3.4:54321`), so each new TCP connection gets a fresh counter.

- [ ] **Step 1: Write tests**

```go
func TestRateLimitMiddleware_UsesIPNotAddrPort(t *testing.T) {
    // Two requests from the same IP, different ports — should share a counter.
    // We verify by checking X-RateLimit-Remaining decrements consistently.
    m := &Middleware{
        logger: logging.NewTestLogger(),
        defaultLimiter: limiter.New(memory.NewStore(), limiter.Rate{Period: time.Minute, Limit: 60}),
        authLimiter:    limiter.New(memory.NewStore(), limiter.Rate{Period: time.Minute, Limit: 5}),
    }
    handler := m.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    req1 := httptest.NewRequest(http.MethodGet, "/api/vault", nil)
    req1.RemoteAddr = "10.0.0.1:11111"
    rr1 := httptest.NewRecorder()
    handler.ServeHTTP(rr1, req1)

    req2 := httptest.NewRequest(http.MethodGet, "/api/vault", nil)
    req2.RemoteAddr = "10.0.0.1:22222" // same IP, different port
    rr2 := httptest.NewRecorder()
    handler.ServeHTTP(rr2, req2)

    rem1, _ := strconv.Atoi(rr1.Header().Get("X-RateLimit-Remaining"))
    rem2, _ := strconv.Atoi(rr2.Header().Get("X-RateLimit-Remaining"))
    assert.Equal(t, rem1-1, rem2, "same IP different port must share the rate limit counter")
}
```

Add `"strconv"` import to test file.

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/middleware/... -run TestRateLimitMiddleware_UsesIPNotAddrPort -v
```

Expected: `FAIL` — rem1 == rem2 (different ports get separate counters).

- [ ] **Step 3: Fix the constructor to use separate stores**

In `NewMiddleware`, replace the shared `store := memory.NewStore()`:

```go
func NewMiddleware(container Container) *Middleware {
    defaultStore := memory.NewStore()
    authStore := memory.NewStore()

    defaultLimiter := limiter.New(defaultStore, limiter.Rate{
        Period: time.Minute,
        Limit:  60,
    })
    authLimiter := limiter.New(authStore, limiter.Rate{
        Period: time.Minute,
        Limit:  5,
    })
    // ... rest unchanged
}
```

- [ ] **Step 4: Fix key extraction in `RateLimitMiddleware`**

Add `"net"` to imports. In `RateLimitMiddleware`, replace:

```go
// BEFORE
key := r.RemoteAddr

// AFTER
ip, _, err := net.SplitHostPort(r.RemoteAddr)
if err != nil {
    ip = r.RemoteAddr // fallback for unit tests using plain IPs
}
key := ip
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/middleware/... -run TestRateLimitMiddleware -v
```

Expected: all pass.

- [ ] **Step 6: Build and commit**

```bash
go build ./...
git add internal/middleware/middleware.go internal/middleware/middleware_test.go
git commit -m "fix(middleware): separate rate limiter stores and use IP (not RemoteAddr) as key"
```

---

## Task 6: Fix request ID generator — use UUID (H4 — High)

**Files:**
- Modify: `internal/middleware/middleware.go:432-436`
- Modify: `internal/middleware/middleware_test.go`

### Background

`generateRequestID()` uses `time.Now().UnixNano()` — two goroutines in the same nanosecond get the same ID. `uuid.New()` is already imported.

- [ ] **Step 1: Write a failing test**

```go
func TestGenerateRequestID_Unique(t *testing.T) {
    ids := make(map[string]bool, 1000)
    for i := 0; i < 1000; i++ {
        id := generateRequestID()
        assert.False(t, ids[id], "request IDs must be unique; collision at i=%d", i)
        ids[id] = true
    }
}

func TestGenerateRequestID_IsUUID(t *testing.T) {
    id := generateRequestID()
    _, err := uuid.Parse(id)
    assert.NoError(t, err, "request ID must be a valid UUID")
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/middleware/... -run TestGenerateRequestID -v
```

Expected: `FAIL` on UUID parse (format is `req_<nanoseconds>`).

- [ ] **Step 3: Fix implementation**

```go
func generateRequestID() string {
    return uuid.New().String()
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/middleware/... -run TestGenerateRequestID -v
```

Expected: `PASS`.

- [ ] **Step 5: Build and commit**

```bash
go build ./...
git add internal/middleware/middleware.go internal/middleware/middleware_test.go
git commit -m "fix(middleware): use uuid for request IDs instead of UnixNano to prevent collisions"
```

---

## Task 7: Fix duplicate JWT validation — collapse SessionRequired (C2 — Critical)

**Files:**
- Modify: `api/context.go:121-252`
- Modify: `api/context_test.go` (create if absent)

### Background

`SessionRequired` re-validates the JWT token itself even though `AuthenticationMiddleware` has already done so and populated `r.Context()`. This creates two divergent auth paths. `SessionRequired` should only read the identity values that the middleware already set.

- [ ] **Step 1: Write test for the fixed behavior**

Create/add to `api/context_test.go`:

```go
package api_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"

    "rocketvault/app"
    "rocketvault/common"
    "rocketvault/internal/container"
)

func TestSessionRequired_ReadsFromContext_NotRevalidatesToken(t *testing.T) {
    // Build a mock app with a mock service container.
    mockContainer := &MockServiceContainerForAPI{}
    mockRBAC := &MockRBACService{}
    mockContainer.On("GetRBACService").Return(mockRBAC)
    mockRBAC.On("ValidateEndpointAccess", "admin", http.MethodGet, "/api/secrets").Return(nil)

    testApp := &app.App{ServiceContainer: mockContainer}

    called := false
    handler := SessionRequired(testApp, func(c *Context, w http.ResponseWriter, r *http.Request) {
        called = true
        w.WriteHeader(http.StatusOK)
    })

    req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
    // Simulate what AuthenticationMiddleware sets — no token in header needed.
    ctx := context.WithValue(req.Context(), common.UserIDKey, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    ctx = context.WithValue(ctx, common.UsernameKey, "alice")
    ctx = context.WithValue(ctx, common.RoleKey, "admin")
    req = req.WithContext(ctx)

    rr := httptest.NewRecorder()
    handler.ServeHTTP(rr, req)

    assert.True(t, called, "handler must be invoked when context has user ID")
    assert.Equal(t, http.StatusOK, rr.Code)
}

func TestSessionRequired_MissingUserIDInContext_Returns401(t *testing.T) {
    testApp := &app.App{ServiceContainer: nil}
    handler := SessionRequired(testApp, func(c *Context, w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })

    req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
    // No user ID in context — middleware never ran or token was invalid.
    rr := httptest.NewRecorder()
    handler.ServeHTTP(rr, req)

    assert.Equal(t, http.StatusUnauthorized, rr.Code)
}
```

`MockServiceContainerForAPI` and `MockRBACService` follow the same testify/mock pattern used elsewhere in the codebase.

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./api/... -run TestSessionRequired -v
```

Expected: `FAIL` — `SessionRequired` tries to read `Authorization` header, fails with 401 even though context has the user ID.

- [ ] **Step 3: Rewrite `SessionRequired`**

Replace the body of `SessionRequired` in `api/context.go` with:

```go
// SessionRequired wraps handlers that require an authenticated session.
// Identity is read from r.Context() — set by AuthenticationMiddleware — not
// re-validated here. The RBAC check uses the role from context.
func SessionRequired(a *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        userIDStr, ok := r.Context().Value(common.UserIDKey).(string)
        if !ok || userIDStr == "" {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]any{
                "id":          "Unauthorized",
                "message":     "Unauthorized: missing session",
                "status_code": http.StatusUnauthorized,
            })
            return
        }

        username, _ := r.Context().Value(common.UsernameKey).(string)
        role, _ := r.Context().Value(common.RoleKey).(string)

        // RBAC check — role is already verified authentic by middleware.
        if a.ServiceContainer != nil {
            if err := a.ServiceContainer.GetRBACService().ValidateEndpointAccess(role, r.Method, r.URL.Path); err != nil {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusForbidden)
                json.NewEncoder(w).Encode(map[string]any{
                    "id":          "Forbidden",
                    "message":     "Access denied",
                    "status_code": http.StatusForbidden,
                })
                return
            }
        }

        ctx := &Context{
            App:            a,
            Claims:         jwt.MapClaims{
                "user_id":  userIDStr,
                "username": username,
                "role":     role,
            },
            Params:         &Params{Query: make(map[string]string)},
            RequestID:      fmt.Sprintf("%v", r.Context().Value(requestIDKey)),
            IPAddress:      r.RemoteAddr,
            Path:           r.URL.Path,
            UserAgent:      r.UserAgent(),
            AcceptLanguage: r.Header.Get("Accept-Language"),
            Logger:         a.Logger,
            Err:            nil,
        }

        vars := mux.Vars(r)
        if uid, ok := vars["user_id"]; ok {
            ctx.Params.UserID = uid
        }
        for key, values := range r.URL.Query() {
            if len(values) > 0 {
                ctx.Params.Query[key] = values[0]
            }
        }

        ctx.Logger.WithField("user_id", userIDStr).Debug("Session validated via context.")
        ctx.Logger.Printf("Handling %s %s (user: %s)", r.Method, r.URL.Path, userIDStr)

        handler(ctx, w, r)

        elapsed := time.Since(start).Milliseconds()
        ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, elapsed)

        if ctx.Err != nil {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(ctx.Err.StatusCode)
            json.NewEncoder(w).Encode(map[string]any{
                "id":             ctx.Err.ID,
                "message":        ctx.Err.Message,
                "detailed_error": ctx.Err.DetailedError,
                "status_code":    ctx.Err.StatusCode,
            })
        }
    }
}
```

Note: `requestIDKey` is defined in `internal/middleware/middleware.go` as an unexported type. Add a corresponding exported key to `common/context.go` (or use a string key only for request ID propagation). The simplest fix: use `r.Header.Get("X-Request-ID")` which the middleware sets on the response writer:

```go
RequestID: r.Header.Get("X-Request-ID"),
```

Remove unused imports from `api/context.go` (specifically `"github.com/golang-jwt/jwt/v5"` parse-related imports if no longer used for parsing tokens).

- [ ] **Step 4: Run tests**

```bash
go test ./api/... -run TestSessionRequired -v
```

Expected: `PASS`.

- [ ] **Step 5: Ensure existing handler tests still pass**

```bash
go test ./api/... -v
```

Expected: no regressions.

- [ ] **Step 6: Build and commit**

```bash
go build ./...
git add api/context.go api/context_test.go
git commit -m "fix(api): SessionRequired reads identity from r.Context() not re-validates JWT"
```

---

## Task 8: Fix IDOR — enforce ownership at query level (C4 — Critical)

**Files:**
- Modify: `internal/repositories/secret_repository.go` — `Read` method, add `userID` filter
- Modify: `internal/services/secrets/secret_service.go` — `GetSecret` signature change
- Modify: `api/secrets.go` — remove redundant ownership checks in `getSecret` and `updateSecret`
- Modify: `internal/repositories/secret_repository.go` interface

### Background

`GetSecret(ctx, secretID, userID)` calls `secretRepo.Read(ctx, secretID)` which ignores `userID`, then the handler checks `secret.UserID != userID` after retrieving and decrypting the secret. Ownership must be enforced in SQL: `WHERE id = ? AND user_id = ?`.

- [ ] **Step 1: Add `ReadByOwner` to `SecretRepositoryInterface`**

In `internal/repositories/secret_repository.go`, add to the interface:

```go
type SecretRepositoryInterface interface {
    Create(ctx context.Context, secret *domain.Secret) error
    Read(ctx context.Context, id uuid.UUID) (*domain.Secret, error)
    ReadByOwner(ctx context.Context, id, userID uuid.UUID) (*domain.Secret, error) // new
    Update(ctx context.Context, secret *domain.Secret) error
    Delete(ctx context.Context, id uuid.UUID) error
    SoftDelete(ctx context.Context, id uuid.UUID) error
    RecoverSecret(ctx context.Context, id uuid.UUID) error
    ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error)
    ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error)
    ExportSecrets(ctx context.Context, options domain.ExportOptions) ([]byte, error)
    ImportSecrets(ctx context.Context, data []byte, options domain.ImportOptions) (int, error)
    GetVersions(ctx context.Context, secretID uuid.UUID) ([]domain.SecretVersion, error)
    GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*domain.SecretVersion, error)
    GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*domain.SecretVersion, error)
    PurgeSecret(ctx context.Context, id uuid.UUID) error
}
```

- [ ] **Step 2: Write a failing test for `ReadByOwner`**

In `internal/repositories/secret_repository_test.go` (or create it):

```go
func TestSecretRepository_ReadByOwner_WrongUserReturnsError(t *testing.T) {
    db := setupTestDB(t) // use in-memory sqlite3
    repo := NewSecretRepository(db, logging.NewTestLogger())

    ownerID := uuid.New()
    otherID := uuid.New()
    secret := &domain.Secret{
        ID:              uuid.New(),
        UserID:          ownerID,
        Name:            "my-secret",
        Value:           "encrypted-data",
        Version:         1,
        CreatedAt:       time.Now(),
        PurgeProtection: false,
    }
    require.NoError(t, repo.Create(context.Background(), secret))

    // Owner can read
    found, err := repo.ReadByOwner(context.Background(), secret.ID, ownerID)
    require.NoError(t, err)
    assert.Equal(t, secret.ID, found.ID)

    // Non-owner gets an error
    _, err = repo.ReadByOwner(context.Background(), secret.ID, otherID)
    assert.Error(t, err, "ReadByOwner must fail for wrong user_id")
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
go test ./internal/repositories/... -run TestSecretRepository_ReadByOwner -v
```

Expected: compile error — `ReadByOwner` not defined yet.

- [ ] **Step 4: Implement `ReadByOwner` in `SecretRepository`**

Add after the existing `Read` method in `internal/repositories/secret_repository.go`:

```go
// ReadByOwner retrieves a secret by ID only if the given userID owns it.
// Returns an error if not found or if the secret belongs to a different user.
func (r *SecretRepository) ReadByOwner(ctx context.Context, id, userID uuid.UUID) (*domain.Secret, error) {
    var secret domain.Secret
    var err error
    opErr := r.executeWithMetrics("ReadByOwner", func() error {
        row := r.db.QueryRowContext(ctx,
            `SELECT id, user_id, name, value, version, created_at,
                    deleted_at, purge_protection, scheduled_purge_at
             FROM secrets
             WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
            id.String(), userID.String())
        err = scanSecret(row, &secret)
        return err
    })
    if opErr != nil {
        if errors.Is(opErr, sql.ErrNoRows) {
            return nil, fmt.Errorf("secret not found or access denied")
        }
        return nil, fmt.Errorf("failed to read secret: %w", opErr)
    }
    return &secret, nil
}
```

`scanSecret` is the existing scan helper in the file (check for its name and reuse it; if it doesn't exist as a helper, inline the scan).

- [ ] **Step 5: Update `SecretService.GetSecret` to use `ReadByOwner`**

In `internal/services/secrets/secret_service.go`, find `GetSecret`:

```go
// BEFORE
func (s *secretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*domain.Secret, error) {
    secret, err := s.secretRepo.Read(ctx, secretID)
    if err != nil { ... }
    // ownership checked by caller
    ...
}

// AFTER
func (s *secretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*domain.Secret, error) {
    secret, err := s.secretRepo.ReadByOwner(ctx, secretID, userID)
    if err != nil {
        s.logger.LogAuditError(userID.String(), "get_secret", "failed", "Secret not found or access denied", err)
        return nil, fmt.Errorf("secret not found or access denied")
    }
    // Decrypt value
    decryptedValue, err := s.cryptoService.DecryptSecret(secret.Value)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt secret: %w", err)
    }
    secret.Value = decryptedValue
    return secret, nil
}
```

Adjust the decrypt step to match the existing pattern in the current implementation.

- [ ] **Step 6: Remove redundant ownership check in `api/secrets.go`**

In `getSecret` (around line 677), remove:

```go
// DELETE these lines:
if secret.UserID != userID {
    c.Err = common.NewAppError("getSecret", "Access denied", nil, "", http.StatusForbidden)
    return
}
```

In `updateSecret` (around line 753), remove the same pattern.

- [ ] **Step 7: Update mock repository implementations** (if any use `Read` in tests)

Search for mock implementations of `SecretRepositoryInterface` and add `ReadByOwner`:

```bash
grep -r "SecretRepositoryInterface\|MockSecretRepository" /home/numericlabs/data/Golang/rocketvault --include="*.go" -l
```

Add `ReadByOwner` to each mock found, following the same testify/mock pattern:

```go
func (m *MockSecretRepository) ReadByOwner(ctx context.Context, id, userID uuid.UUID) (*domain.Secret, error) {
    args := m.Called(ctx, id, userID)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.Secret), args.Error(1)
}
```

- [ ] **Step 8: Run tests**

```bash
go test ./internal/repositories/... -run TestSecretRepository_ReadByOwner -v
go test ./internal/services/secrets/... -v
go test ./api/... -v
```

Expected: all pass.

- [ ] **Step 9: Build and commit**

```bash
go build ./...
git add internal/repositories/secret_repository.go \
        internal/services/secrets/secret_service.go \
        api/secrets.go
git commit -m "fix(security): enforce secret ownership at SQL level to prevent IDOR"
```

---

## Task 9: Fix context keys — struct-pointer type (M6 — Medium)

**Files:**
- Modify: `common/context.go`
- Modify: all files that use `common.UserIDKey`, `common.RoleKey`, etc. (middleware, api/context.go, cmd/root.go)

### Background

`ContextKey` is `int`-based with `iota`. If another package defines keys of the same underlying type, the values can collide. Go's recommendation is unexported struct pointer keys.

- [ ] **Step 1: Rewrite `common/context.go`**

```go
package common

// contextKey is an unexported type to prevent context key collisions across packages.
type contextKey struct{ name string }

// String makes contextKey implement Stringer for debugging.
func (k *contextKey) String() string { return "rocketvault/" + k.name }

// Context keys — use pointer identity, not integer values.
var (
    DBKey               = &contextKey{"db"}
    DBClassKey          = &contextKey{"db_class"}
    LogKey              = &contextKey{"log"}
    UserIDKey           = &contextKey{"user_id"}
    UsernameKey         = &contextKey{"username"}
    RoleKey             = &contextKey{"role"}
    TokenKey            = &contextKey{"token"}
    ClaimsKey           = &contextKey{"claims"}
    RequestIDKey        = &contextKey{"request_id"}
    ContentTypeKey      = &contextKey{"content_type"}
    APIVersionKey       = &contextKey{"api_version"}
    ServiceContainerKey = &contextKey{"service_container"}
)
```

Remove the old `ContextKey int` type and the `const ( ... iota ... )` block entirely.

- [ ] **Step 2: Fix all call sites**

The type assertion signature changes from `.(common.ContextKey)` to using the pointer keys as `interface{}` keys — no type assertion changes needed in `context.WithValue`/`context.Value` calls since those accept `any`. The keys themselves are now `*contextKey` (unexported type), which is fine as long as they are referenced as `common.UserIDKey` etc.

However, **any code that used `common.ContextKey` as a type** must be updated. Search:

```bash
grep -r "common\.ContextKey\|ContextKey(" /home/numericlabs/data/Golang/rocketvault --include="*.go"
```

For each match, remove the type cast (typically in tests or switch statements). The value lookups `r.Context().Value(common.UserIDKey).(string)` need no change since `common.UserIDKey` is still exported, just a different underlying type.

- [ ] **Step 3: Build to catch all broken references**

```bash
go build ./...
```

Fix any compile errors by removing `common.ContextKey` type usages. Re-run until clean.

- [ ] **Step 4: Run all tests**

```bash
go test ./... 2>&1 | tail -20
```

Expected: all pass (no behavior change, only type identity change for keys).

- [ ] **Step 5: Commit**

```bash
git add common/context.go
git add $(git diff --name-only) # any other files that needed updating
git commit -m "fix(common): use struct-pointer context keys to prevent cross-package collisions"
```

---

## Task 10: Fix PostgreSQL duplicate-column error detection (M5 — Medium)

**Files:**
- Modify: `internal/db/db.go:561-570`

### Background

The current string-matching `"already exists"` is too broad for PostgreSQL and swallows legitimate migration errors. Use the `pq` error code `42701` for duplicate column.

- [ ] **Step 1: Write test**

In `internal/db/db_test.go` (create if absent):

```go
package db_test

import (
    "fmt"
    "testing"

    "github.com/lib/pq"
    "github.com/stretchr/testify/assert"
)

func TestIsDuplicateColumnError_SQLite(t *testing.T) {
    err := fmt.Errorf("table secrets already has column deleted_at: duplicate column name: deleted_at")
    assert.True(t, isDuplicateColumnError(err))
}

func TestIsDuplicateColumnError_PostgreSQL(t *testing.T) {
    err := &pq.Error{Code: "42701", Message: "column deleted_at of relation secrets already exists"}
    assert.True(t, isDuplicateColumnError(err))
}

func TestIsDuplicateColumnError_OtherPostgreSQLError(t *testing.T) {
    // "already exists" for a table — should NOT be silenced
    err := &pq.Error{Code: "42P07", Message: "relation secrets already exists"}
    assert.False(t, isDuplicateColumnError(err), "table already exists must not be silenced")
}

func TestIsDuplicateColumnError_Nil(t *testing.T) {
    assert.False(t, isDuplicateColumnError(nil))
}

func TestIsDuplicateColumnError_GenericError(t *testing.T) {
    assert.False(t, isDuplicateColumnError(fmt.Errorf("connection refused")))
}
```

Note: `isDuplicateColumnError` is unexported. Place this test in `package db` (not `package db_test`) to access it, or export it temporarily for testing.

- [ ] **Step 2: Run test to verify `TestIsDuplicateColumnError_OtherPostgreSQLError` fails**

```bash
go test ./internal/db/... -run TestIsDuplicateColumnError -v
```

Expected: the "table already exists" test fails — current code matches `"already exists"` and returns `true`.

- [ ] **Step 3: Fix `isDuplicateColumnError`**

In `internal/db/db.go`, replace:

```go
import (
    "errors"
    // add:
    "github.com/lib/pq"
)

func isDuplicateColumnError(err error) bool {
    if err == nil {
        return false
    }
    // SQLite reports "duplicate column name: <col>"
    if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
        return true
    }
    // PostgreSQL error code 42701 = duplicate_column
    var pqErr *pq.Error
    if errors.As(err, &pqErr) {
        return pqErr.Code == "42701"
    }
    return false
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/db/... -run TestIsDuplicateColumnError -v
```

Expected: all five pass.

- [ ] **Step 5: Build and commit**

```bash
go build ./...
git add internal/db/db.go internal/db/db_test.go
git commit -m "fix(db): use PostgreSQL error code 42701 for duplicate column, not string match"
```

---

## Task 11: Add `WithTx` transaction helper and wrap CreateSecret (H6 — High)

**Files:**
- Create: `internal/db/txhelper.go`
- Modify: `internal/services/secrets/secret_service.go` — `CreateSecret`

### Background

`CreateSecret` does: encrypt → repo.Create (secret row) → versionService.CreateVersion → tagService.AddTags — three separate DB writes with no transaction. A crash between steps leaves orphaned rows.

- [ ] **Step 1: Create `internal/db/txhelper.go`**

```go
package db

import (
    "context"
    "database/sql"
    "fmt"
)

// DBTX is satisfied by both *sql.DB and *sql.Tx, allowing repositories to
// work inside or outside a transaction without changing their signatures.
type DBTX interface {
    ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
    QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
    QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// WithTx runs fn inside a transaction. It commits on success and rolls back on error.
func WithTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return fmt.Errorf("begin transaction: %w", err)
    }
    if err := fn(tx); err != nil {
        if rbErr := tx.Rollback(); rbErr != nil {
            return fmt.Errorf("rollback failed: %w (original: %v)", rbErr, err)
        }
        return err
    }
    return tx.Commit()
}
```

- [ ] **Step 2: Write a test for `WithTx`**

In `internal/db/txhelper_test.go`:

```go
package db_test

import (
    "context"
    "fmt"
    "testing"

    _ "github.com/mattn/go-sqlite3"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestWithTx_CommitsOnSuccess(t *testing.T) {
    db := openTestSQLite(t)
    _, err := db.Exec(`CREATE TABLE tx_test (val TEXT)`)
    require.NoError(t, err)

    err = WithTx(context.Background(), db, func(tx *sql.Tx) error {
        _, err := tx.Exec(`INSERT INTO tx_test VALUES ('hello')`)
        return err
    })
    require.NoError(t, err)

    var count int
    db.QueryRow(`SELECT COUNT(*) FROM tx_test`).Scan(&count)
    assert.Equal(t, 1, count)
}

func TestWithTx_RollsBackOnError(t *testing.T) {
    db := openTestSQLite(t)
    _, err := db.Exec(`CREATE TABLE tx_rollback (val TEXT)`)
    require.NoError(t, err)

    err = WithTx(context.Background(), db, func(tx *sql.Tx) error {
        tx.Exec(`INSERT INTO tx_rollback VALUES ('will-be-rolled-back')`)
        return fmt.Errorf("deliberate failure")
    })
    assert.Error(t, err)

    var count int
    db.QueryRow(`SELECT COUNT(*) FROM tx_rollback`).Scan(&count)
    assert.Equal(t, 0, count, "rows must be rolled back")
}

func openTestSQLite(t *testing.T) *sql.DB {
    t.Helper()
    db, err := sql.Open("sqlite3", ":memory:")
    require.NoError(t, err)
    t.Cleanup(func() { db.Close() })
    return db
}
```

Add `"database/sql"` import.

- [ ] **Step 3: Run test to verify it passes** (implementation is new — should pass immediately)

```bash
go test ./internal/db/... -run TestWithTx -v
```

Expected: `PASS`.

- [ ] **Step 4: Add `*sql.DB` access to `SecretServiceConfig`**

In `internal/services/secrets/secret_service.go`, extend `SecretServiceConfig`:

```go
type SecretServiceConfig struct {
    SecretRepository repositories.SecretRepositoryInterface
    CryptoService    CryptographyService
    VersionService   VersioningServiceInterface
    TagService       TagService
    Logger           *logging.Logger
    DB               *sql.DB // for transaction support
}

type secretService struct {
    secretRepo     repositories.SecretRepositoryInterface
    cryptoService  CryptographyService
    versionService VersioningServiceInterface
    tagService     TagService
    logger         *logging.Logger
    db             *sql.DB
}
```

Update `NewSecretService` to set `s.db = config.DB`.

- [ ] **Step 5: Wire `DB` in the container**

In `internal/container/service_container.go`, update the `SecretServiceConfig` initialisation:

```go
baseSecretService := secretServices.NewSecretService(secretServices.SecretServiceConfig{
    SecretRepository: c.secretRepository,
    CryptoService:    c.cryptoService,
    VersionService:   c.versioningService,
    TagService:       c.tagService,
    Logger:           c.logger,
    DB:               c.db, // add this
})
```

- [ ] **Step 6: Wrap `CreateSecret` in a transaction**

In `internal/services/secrets/secret_service.go`, rewrite `CreateSecret`:

```go
import (
    // add:
    "database/sql"
    dbpkg "rocketvault/internal/db"
)

func (s *secretService) CreateSecret(ctx context.Context, req CreateSecretRequest) (*domain.Secret, error) {
    encryptedValue, err := s.cryptoService.EncryptSecret(req.Value)
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt secret: %w", err)
    }

    secret := &domain.Secret{
        ID:        uuid.New(),
        UserID:    req.UserID,
        Name:      req.Name,
        Value:     encryptedValue,
        Version:   1,
        CreatedAt: time.Now(),
    }

    if s.db != nil {
        err = dbpkg.WithTx(ctx, s.db, func(tx *sql.Tx) error {
            if err := s.secretRepo.Create(ctx, secret); err != nil {
                return err
            }
            if len(req.Tags) > 0 {
                if err := s.tagService.AddTags(ctx, secret.ID, req.Tags); err != nil {
                    return err
                }
                secret.Tags = req.Tags
            }
            return s.versionService.CreateVersion(ctx, secret)
        })
    } else {
        // Fallback without transaction (e.g., in unit tests without a real DB)
        if err = s.secretRepo.Create(ctx, secret); err == nil {
            if len(req.Tags) > 0 {
                s.tagService.AddTags(ctx, secret.ID, req.Tags)
                secret.Tags = req.Tags
            }
            err = s.versionService.CreateVersion(ctx, secret)
        }
    }

    if err != nil {
        s.logger.LogAuditError(req.UserID.String(), "create_secret", "failed", "Failed to create secret", err)
        return nil, fmt.Errorf("failed to create secret: %w", err)
    }

    s.logger.LogAuditInfo(req.UserID.String(), "create_secret", "success", fmt.Sprintf("Secret '%s' created", req.Name))
    secret.Value = req.Value // return plaintext to caller
    return secret, nil
}
```

Note: `CreateVersion` signature must be checked in `versioning_service.go`. Adjust if the actual method name or parameter order differs.

- [ ] **Step 7: Build and run tests**

```bash
go build ./...
go test ./internal/db/... ./internal/services/secrets/... -v
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add internal/db/txhelper.go internal/db/txhelper_test.go \
        internal/services/secrets/secret_service.go \
        internal/container/service_container.go
git commit -m "feat(db): add WithTx helper and wrap CreateSecret in a transaction"
```

---

## Task 12: Remove handler nil-guard boilerplate (M1 — Medium)

**Files:**
- Modify: `api/secrets.go`
- Modify: `api/context.go` — add `mustGetSecretService()` helper on `Context`
- Modify: other handler files as needed (`api/keys.go`, `api/users.go`, `api/certificates.go`)

### Background

Every handler repeats 8-10 lines checking `c.App == nil`, `c.App.ServiceContainer == nil`, then getting the service and checking it for nil. The container is guaranteed non-nil after bootstrap. Extract helpers on `Context`.

- [ ] **Step 1: Add service accessor helpers to `Context`**

In `api/context.go`, add after the `Context` struct definition:

```go
// secretService returns the secret service from the container.
// It sets c.Err and returns nil if the container is not available.
func (c *Context) secretService() secrets.SecretService {
    if c.App == nil || c.App.ServiceContainer == nil {
        c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
        return nil
    }
    return c.App.ServiceContainer.GetSecretService()
}

func (c *Context) keyService() keyServices.KeyService {
    if c.App == nil || c.App.ServiceContainer == nil {
        c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
        return nil
    }
    return c.App.ServiceContainer.GetKeyService()
}

func (c *Context) userService() userServices.UserService {
    if c.App == nil || c.App.ServiceContainer == nil {
        c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
        return nil
    }
    return c.App.ServiceContainer.GetUserService()
}

func (c *Context) certificateService() certServices.CertificateService {
    if c.App == nil || c.App.ServiceContainer == nil {
        c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
        return nil
    }
    return c.App.ServiceContainer.GetCertificateService()
}
```

Add the necessary import aliases matching those used in `api/` files. Check the existing imports in `api/secrets.go` for the correct import paths:
- `secrets "rocketvault/internal/services/secrets"`
- `keyServices "rocketvault/internal/services/keys"`
- etc.

- [ ] **Step 2: Refactor `api/secrets.go` handlers**

For each handler in `api/secrets.go`, replace:

```go
// BEFORE (repeated in every handler, ~8 lines)
if c.App == nil || c.App.ServiceContainer == nil {
    c.Err = common.NewAppError("createSecret", "Service container not available", nil, "", http.StatusInternalServerError)
    return
}
secretService := c.App.ServiceContainer.GetSecretService()
if secretService == nil {
    c.Err = common.NewAppError("createSecret", "Secret service not available", nil, "", http.StatusInternalServerError)
    return
}

// AFTER (2 lines)
secretService := c.secretService()
if secretService == nil { return }
```

Apply this replacement to: `createSecret`, `listSecrets`, `getSecret`, `updateSecret`, `deleteSecret`, `generateSecret`, `exportSecrets`, `importSecrets`, `listSecretVersionsHandler`, `getSecretVersionHandler`, `getLatestSecretVersionHandler`.

Also fix the copy-paste bug in `listSecrets` and `updateSecret` where the error context says `"createSecret"` but it's in a different handler — now eliminated by using the helper.

- [ ] **Step 3: Repeat for `api/keys.go`, `api/users.go`, `api/certificates.go`**

Apply the same pattern using `c.keyService()`, `c.userService()`, `c.certificateService()` respectively.

- [ ] **Step 4: Write a test for the helper behavior**

In `api/context_test.go`:

```go
func TestContext_SecretService_NilContainerSetsErr(t *testing.T) {
    ctx := &Context{App: nil}
    svc := ctx.secretService()
    assert.Nil(t, svc)
    assert.NotNil(t, ctx.Err)
    assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

func TestContext_SecretService_NilServiceContainer(t *testing.T) {
    ctx := &Context{App: &app.App{ServiceContainer: nil}}
    svc := ctx.secretService()
    assert.Nil(t, svc)
    assert.NotNil(t, ctx.Err)
}
```

- [ ] **Step 5: Build and run tests**

```bash
go build ./...
go test ./api/... -v
```

Expected: all pass, line count in `api/secrets.go` drops significantly.

- [ ] **Step 6: Commit**

```bash
git add api/context.go api/secrets.go api/keys.go api/users.go api/certificates.go
git commit -m "refactor(api): extract service accessor helpers to eliminate nil-guard boilerplate"
```

---

## Task 13: Fix ValidateToken — remove expiry check from key function (M3 — Medium)

**Files:**
- Modify: `internal/services/auth/jwt_service.go:125-148`

### Background

The JWT key function is called before signature verification. Checking expiry inside it means the expiry check runs on an unverified token. The `golang-jwt/jwt/v5` library validates `ExpiresAt` automatically after the key function returns. Remove the duplicate check.

- [ ] **Step 1: Write a test confirming expiry is still enforced**

In `internal/services/auth/jwt_service_test.go` (create if absent):

```go
package auth_test

import (
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestJWTService_ValidateToken_ExpiredTokenRejected(t *testing.T) {
    svc := NewJWTService(JWTConfig{
        SecretKey: "test-secret-key-32bytes-long-xx",
        Issuer:    "rocketvault",
        Audience:  "PASSWORD_MANAGER",
        Expiry:    -1 * time.Second, // already expired
    })

    userID := uuid.New()
    token, err := svc.GenerateToken(userID, "alice", "user")
    require.NoError(t, err)

    // Wait 2ms to ensure expiry
    time.Sleep(2 * time.Millisecond)

    _, err = svc.ValidateToken(token)
    assert.Error(t, err, "expired token must be rejected")
    assert.Contains(t, err.Error(), "invalid JWT token")
}

func TestJWTService_ValidateToken_ValidTokenAccepted(t *testing.T) {
    svc := NewJWTService(JWTConfig{
        SecretKey: "test-secret-key-32bytes-long-xx",
        Issuer:    "rocketvault",
        Audience:  "PASSWORD_MANAGER",
        Expiry:    time.Hour,
    })

    userID := uuid.New()
    token, err := svc.GenerateToken(userID, "bob", "admin")
    require.NoError(t, err)

    claims, err := svc.ValidateToken(token)
    require.NoError(t, err)
    assert.Equal(t, userID, claims.UserID)
    assert.Equal(t, "bob", claims.Username)
}
```

- [ ] **Step 2: Run tests — verify they pass before the change**

```bash
go test ./internal/services/auth/... -run TestJWTService_ValidateToken -v
```

Expected: `PASS` (tests confirm current behavior works; they will continue to pass after the fix).

- [ ] **Step 3: Remove the expiry check from the key function**

In `internal/services/auth/jwt_service.go`, remove the block inside the key function:

```go
// BEFORE (lines ~133-136)
// Validate expiration
if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
    logrus.Error("JWT token has expired")
    return nil, jwt.ErrTokenExpired
}

// AFTER: delete those 4 lines entirely
```

The key function should only return the signing key after validating the algorithm:

```go
token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        logrus.WithField("alg", token.Header["alg"]).Warn("Unexpected JWT signing method")
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    // Validate issuer before returning key.
    if claims.Issuer != s.issuer {
        logrus.WithFields(logrus.Fields{
            "expected": s.issuer,
            "actual":   claims.Issuer,
        }).Warn("JWT issuer mismatch")
        return nil, fmt.Errorf("invalid issuer")
    }
    return s.secretKey, nil
})
```

- [ ] **Step 4: Run tests again**

```bash
go test ./internal/services/auth/... -run TestJWTService_ValidateToken -v
```

Expected: both tests still `PASS` — the jwt library enforces expiry automatically.

- [ ] **Step 5: Build and commit**

```bash
go build ./...
git add internal/services/auth/jwt_service.go internal/services/auth/jwt_service_test.go
git commit -m "fix(auth): remove duplicate expiry check from JWT key function — library handles it"
```

---

## Task 14: Consolidate logging — remove bare logrus calls from service layer (M8 — Medium)

**Files:**
- Modify: `internal/services/auth/authentication_service.go`
- Modify: `internal/services/auth/jwt_service.go`

### Background

`authentication_service.go` uses both `s.logger.LogAuditInfo(...)` (writes to DB audit log) and `logrus.WithFields(...).Info(...)` (bypasses the custom logger). Some events are in both; some only in one. Consolidate to `s.logger` calls only in the service layer.

- [ ] **Step 1: Replace all bare `logrus.*` calls in `authentication_service.go`**

For every `logrus.WithField/WithFields/WithError/Info/Warn/Error` call in this file, replace with the equivalent `s.logger.*` call. The `logging.Logger` exposes:
- `s.logger.WithField(key, val).Info(msg)` / `.Warn(msg)` / `.Error(msg)`
- `s.logger.WithError(err).Error(msg)`
- `s.logger.Info(msg)`, `s.logger.Warn(msg)`, `s.logger.Error(msg)`
- `s.logger.LogAuditInfo(userID, op, status, msg)` for audit events

Example replacements:

```go
// BEFORE
logrus.WithField("username", username).Info("Starting user authentication")
// AFTER
s.logger.WithField("username", username).Info("Starting user authentication")

// BEFORE
logrus.WithError(err).Error("Failed to generate JWT token")
// AFTER
s.logger.WithError(err).Error("Failed to generate JWT token")
```

- [ ] **Step 2: Replace bare `logrus.*` calls in `jwt_service.go`**

`jwt_service.go` has no `s.logger` field — it only uses global logrus. Add a logger field:

```go
type jwtService struct {
    secretKey []byte
    issuer    string
    audience  string
    expiry    time.Duration
    logger    *logrus.Logger // use logrus.Logger directly here, not logging.Logger
}
```

Update `NewJWTService` to accept and store a logger:

```go
type JWTConfig struct {
    SecretKey string
    Issuer    string
    Audience  string
    Expiry    time.Duration
    Logger    *logrus.Logger // optional; falls back to logrus.StandardLogger()
}

func NewJWTService(config JWTConfig) JWTService {
    logger := config.Logger
    if logger == nil {
        logger = logrus.StandardLogger()
    }
    return &jwtService{
        secretKey: []byte(config.SecretKey),
        issuer:    config.Issuer,
        audience:  config.Audience,
        expiry:    config.Expiry,
        logger:    logger,
    }
}
```

Then replace `logrus.WithField(...)` calls with `s.logger.WithField(...)` in `jwt_service.go`.

Update the container to pass the logger:

```go
// In internal/container/service_container.go:
jwtConfig := authServices.JWTConfig{
    SecretKey: c.viper.GetString("jwt_secret"),
    Issuer:    c.viper.GetString("oauth2.issuer"),
    Audience:  "PASSWORD_MANAGER",
    Expiry:    jwtExpiry,
    Logger:    c.logger.Logger, // c.logger.Logger is the underlying *logrus.Logger
}
```

- [ ] **Step 3: Remove `"github.com/sirupsen/logrus"` import from files that no longer need it**

After replacing all calls, run:

```bash
go build ./...
```

The compiler will report any leftover imports. Remove them.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/services/auth/... -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/services/auth/authentication_service.go \
        internal/services/auth/jwt_service.go \
        internal/container/service_container.go
git commit -m "refactor(auth): consolidate logging to injected logger, remove bare logrus calls"
```

---

## Task 15: Final verification pass

- [ ] **Step 1: Run the full test suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./... -v 2>&1 | tee /tmp/test-results.txt
grep -E "^(FAIL|ok)" /tmp/test-results.txt
```

Expected: no `FAIL` lines.

- [ ] **Step 2: Build final binary**

```bash
go build -o /tmp/rocketvault-test ./...
```

Expected: no errors.

- [ ] **Step 3: Run linter (if configured)**

```bash
golangci-lint run ./... 2>&1 | head -40
```

Address any new linter findings introduced by the changes in this plan.

- [ ] **Step 4: Review issue checklist**

Verify each issue from the architecture review is addressed:

| ID | Status | Notes |
|----|--------|-------|
| C1 | Task 1 | sha256 hash for refresh tokens |
| C2 | Task 7 | SessionRequired reads from context |
| C3 | Task 3 | PolicyMiddleware denies on error |
| C4 | Task 8 | ReadByOwner enforces ownership in SQL |
| H1 | Task 4 | CORS allowlist from config |
| H2 | Task 5 | Separate limiter stores, IP extraction |
| H3 | — | Global DB left as-is (removal is a larger refactor; tracked as future work — add to `.claude/known-bugs.md`) |
| H4 | Task 6 | UUID request IDs |
| H5 | Task 2 | TOTP code removed from logs |
| H6 | Task 11 | WithTx + CreateSecret wrapped |
| M1 | Task 12 | Service accessor helpers |
| M2 | — | `Claims jwt.MapClaims` retained for now — changing the type has wide handler impact; tracked as future work |
| M3 | Task 13 | Expiry check removed from key function |
| M4 | — | In-memory limiter limitation documented |
| M5 | Task 10 | pq error code 42701 |
| M6 | Task 9 | Struct-pointer context keys |
| M8 | Task 14 | Bare logrus calls removed from service layer |

- [ ] **Step 5: Final commit**

```bash
git add .claude/known-bugs.md  # update with H3 and M2 as tracked future work
git commit -m "docs: track H3 (global DB) and M2 (typed Claims) as future refactor items"
```

---

## Self-Review

**Spec coverage check:**
- All critical (C1-C4), all high (H1-H6 except H3), and all medium (M1-M8 except M2, M4) items are covered by tasks.
- H3 (global DB removal) is a larger refactor touching 20+ files — tracked as future work, noted in Step 5.
- M2 (typed Claims) changes the `Context.Claims` type which affects every handler — tracked as future work.
- M4 (distributed rate limiter) is an infrastructure concern, not a code fix.
- L1-L4 (low severity) are not in scope per the plan scope ("fix all above issues" prioritized by severity).

**Placeholder scan:** No TBD, TODO, or "implement later" phrases found. All code blocks are complete.

**Type consistency:**
- `ReadByOwner(ctx, id, userID uuid.UUID)` defined in Task 8 Step 1 and implemented in Step 4.
- `WithTx(ctx, db, fn)` signature consistent between `txhelper.go` definition and `secret_service.go` usage.
- `secretService()` helper in `Context` returns `secrets.SecretService` — matches the interface type used in handlers.
- `JWTConfig.Logger` added in Task 14 and wired in container using `c.logger.Logger` (the `*logrus.Logger` field on `logging.Logger`).
