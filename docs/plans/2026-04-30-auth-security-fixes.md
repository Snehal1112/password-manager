# Auth Service Security Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all security and correctness defects identified in the `internal/services/auth/` code review.

**Architecture:** All fixes are contained within `internal/services/auth/`. No schema or API changes are required. Each task is independently testable and committable.

**Tech Stack:** Go 1.24, `crypto/sha256`, `encoding/hex`, `github.com/golang-jwt/jwt/v5 v5.2.2`, `github.com/stretchr/testify`

---

## Issues Being Fixed (priority order)

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 1 | CRITICAL | `authentication_service.go:379` | `hashRefreshToken` hex-encodes instead of hashing |
| 2 | CRITICAL | `jwt_service.go:175` | `ParseToken` skips signature verification — public interface footgun |
| 3 | HIGH | `jwt_service.go:125` | JWT audience not validated during `ValidateToken` |
| 4 | HIGH | `authentication_service.go:132–144` | TOTP code logged on failure; username logged before auth |
| 5 | MEDIUM | `jwt_service.go:132–136` | Manual expiry/issuer checks inside key-func (structurally wrong) |
| 6 | MEDIUM | `authentication_service.go:170` | Session expiry hardcoded to 7 days |
| 7 | LOW | `authentication_service.go:299` | `RefreshTokenResult.ExpiresAt` set to hardcoded 1 hour |
| 8 | LOW | Mixed `logrus` / `s.logger` usage throughout `authentication_service.go` |
| 9 | TEST GAP | `authentication_service_critical_test.go` | No test for `RevokeAllUserSessions` |

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/services/auth/jwt_service.go` | Modify | Fix audience validation; remove `ParseToken` from interface; clean up key-func |
| `internal/services/auth/authentication_service.go` | Modify | Fix `hashRefreshToken`; remove sensitive log fields; make session expiry configurable; fix `ExpiresAt`; standardise logger |
| `internal/services/auth/authentication_service_test.go` | Modify | Update `MockJWTService` to remove `ParseToken` mock method |
| `internal/services/auth/authentication_service_critical_test.go` | Modify | Add `TestRevokeAllUserSessions_*` test cases; add `TestHashRefreshToken_*` |
| `internal/testutils/mocks.go` | Modify | Remove `ParseToken` from `MockJWTService` if present |
| `internal/middleware/middleware_test.go` | Modify | Remove `ParseToken` from `MockJWTService` if present |
| `cmd/testutils/test_utils.go` | Modify | Remove `ParseToken` from `MockJWTService` if present |

---

## Task 1: Fix `hashRefreshToken` — use SHA-256 instead of hex-encoding

**Files:**
- Modify: `internal/services/auth/authentication_service.go:377-382`
- Modify: `internal/services/auth/authentication_service_critical_test.go` (add direct hash tests)

### Background
`fmt.Sprintf("%x", token)` hex-encodes the UTF-8 bytes of the string — it is trivially reversible with a single `hex.DecodeString` call. An attacker who reads the `refresh_token_hash` column recovers the live bearer token. The fix uses `crypto/sha256` over the token bytes, which is irreversible for a 32-byte cryptographically random value.

- [ ] **Step 1.1: Write a failing test for correct hash behaviour**

Add to `internal/services/auth/authentication_service_critical_test.go`:

```go
// TestHashRefreshToken_IsDeterministic verifies the same token always produces the same hash.
// TestHashRefreshToken_IsNotReversible verifies the output is not a plain hex of the input.
func TestHashRefreshToken_IsDeterministic(t *testing.T) {
	t.Parallel()
	svc := &authenticationService{}
	token := "abc123supersecretrandomvalue"
	h1 := svc.hashRefreshToken(token)
	h2 := svc.hashRefreshToken(token)
	assert.Equal(t, h1, h2, "same token must produce same hash")
	assert.NotEmpty(t, h1)
}

func TestHashRefreshToken_IsNotPlainHex(t *testing.T) {
	t.Parallel()
	svc := &authenticationService{}
	token := "abc123supersecretrandomvalue"
	h := svc.hashRefreshToken(token)
	// Plain hex encoding of the token bytes would equal hex.EncodeToString([]byte(token))
	plainHex := hex.EncodeToString([]byte(token))
	assert.NotEqual(t, plainHex, h, "hash must not be a plain hex encoding of the token")
	// SHA-256 output is always 64 hex chars (32 bytes)
	assert.Len(t, h, 64, "SHA-256 hex output must be 64 characters")
}
```

- [ ] **Step 1.2: Run the test to confirm it fails**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./internal/services/auth/... -run "TestHashRefreshToken" -v
```

Expected: `FAIL` — `TestHashRefreshToken_IsNotPlainHex` fails because the current implementation IS plain hex. `TestHashRefreshToken_IsDeterministic` may pass (hex is deterministic) but `Len` assertion fails (plain hex of `abc123...` is not 64 chars).

- [ ] **Step 1.3: Add the `crypto/sha256` import and fix the implementation**

In `internal/services/auth/authentication_service.go`, update the import block to add `crypto/sha256` (it is in the Go standard library, no `go get` needed):

```go
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)
```

Replace the `hashRefreshToken` function body (lines 377–382):

```go
// hashRefreshToken creates a SHA-256 hash of the refresh token for secure database storage.
// Using SHA-256 is appropriate here because the input is a 32-byte cryptographically random
// value (generated by generateRefreshToken), making brute-force inversion infeasible.
func (s *authenticationService) hashRefreshToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
```

- [ ] **Step 1.4: Run the tests to confirm they pass**

```bash
go test ./internal/services/auth/... -run "TestHashRefreshToken" -v
```

Expected: `PASS` for both test cases.

- [ ] **Step 1.5: Run the full auth test suite to check for regressions**

```bash
go test ./internal/services/auth/... -v
```

Expected: All existing tests pass.

- [ ] **Step 1.6: Commit**

```bash
git add internal/services/auth/authentication_service.go \
        internal/services/auth/authentication_service_critical_test.go
git commit -m "fix(auth): replace no-op hex encoding with SHA-256 in hashRefreshToken

hashRefreshToken was using fmt.Sprintf(\"%x\", token) which hex-encodes
the token bytes — trivially reversible. Replace with crypto/sha256 hash.

Fixes CRITICAL security defect identified in code review."
```

---

## Task 2: Remove `ParseToken` from the `JWTService` public interface

**Files:**
- Modify: `internal/services/auth/jwt_service.go`
- Modify: `internal/services/auth/authentication_service_test.go` (remove mock method)
- Check & modify if present: `internal/testutils/mocks.go`, `internal/middleware/middleware_test.go`, `cmd/testutils/test_utils.go`

### Background
`ParseToken` calls `jwt.NewParser().ParseUnverified(...)` which explicitly skips signature verification. It is exposed on the `JWTService` interface, meaning any caller can obtain unverified claims and accidentally use them for auth decisions. There are no non-mock callers in the codebase — it is dead interface surface.

- [ ] **Step 2.1: Verify no non-mock callers exist**

```bash
grep -rn "ParseToken" /home/numericlabs/data/Golang/rocketvault \
  --include="*.go" \
  | grep -v "_test.go" \
  | grep -v "mocks.go" \
  | grep -v "test_utils.go"
```

Expected output: only `jwt_service.go` itself (definition). If any production callers exist, stop and investigate before proceeding.

- [ ] **Step 2.2: Remove `ParseToken` from the `JWTService` interface**

In `internal/services/auth/jwt_service.go`, change the interface from:

```go
type JWTService interface {
	GenerateToken(userID uuid.UUID, username, role string) (string, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
	ParseToken(tokenString string) (*JWTClaims, error)
}
```

To:

```go
type JWTService interface {
	GenerateToken(userID uuid.UUID, username, role string) (string, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
}
```

Make `parseToken` unexported (rename method on `jwtService` struct), or delete it entirely. Since there are no callers, delete it:

Remove the entire `ParseToken` / `parseToken` method block (lines ~175–197 in `jwt_service.go`).

- [ ] **Step 2.3: Remove `ParseToken` from all mock implementations**

Search for mock implementations:

```bash
grep -n "ParseToken" \
  internal/services/auth/authentication_service_test.go \
  internal/testutils/mocks.go \
  internal/middleware/middleware_test.go \
  cmd/testutils/test_utils.go 2>/dev/null
```

For each file that contains a `ParseToken` mock method, delete that method. Example — in `internal/services/auth/authentication_service_test.go`:

```go
// DELETE this entire method:
func (m *MockJWTService) ParseToken(tokenString string) (*JWTClaims, error) {
	args := m.Called(tokenString)
	...
}
```

- [ ] **Step 2.4: Build to confirm no compilation errors**

```bash
go build ./...
```

Expected: clean build, zero errors.

- [ ] **Step 2.5: Run full test suite**

```bash
go test ./internal/services/auth/... ./internal/testutils/... ./internal/middleware/... ./cmd/... -v 2>&1 | tail -40
```

Expected: All tests pass.

- [ ] **Step 2.6: Commit**

```bash
git add internal/services/auth/jwt_service.go \
        internal/services/auth/authentication_service_test.go \
        internal/testutils/mocks.go \
        internal/middleware/middleware_test.go \
        cmd/testutils/test_utils.go
git commit -m "fix(auth): remove ParseToken from JWTService interface

ParseToken used ParseUnverified which skips signature validation.
Exposing it as a public interface method is a footgun — any caller
using it for auth decisions would accept forged JWTs.

No non-mock callers exist. Interface and all mocks cleaned up."
```

---

## Task 3: Fix JWT audience validation in `ValidateToken`

**Files:**
- Modify: `internal/services/auth/jwt_service.go`
- Modify: `internal/services/auth/authentication_service_test.go` (add audience mismatch test)

### Background
The JWT is generated with an `aud` claim but `ParseWithClaims` never verifies it. The `golang-jwt/v5` library validates audience only when `jwt.WithAudience()` is passed as a parser option. The current code also performs manual expiry and issuer checks inside the key-func (which runs before signature verification — structurally wrong). This task fixes both at once by moving to declarative parser options and removing the manual checks.

- [ ] **Step 3.1: Write a failing test for audience validation**

Add to `internal/services/auth/authentication_service_test.go` (in the `MockJWTService` section or a new `jwt_service_test.go`). Create a new file `internal/services/auth/jwt_service_test.go`:

```go
package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestJWTService() JWTService {
	return NewJWTService(JWTConfig{
		SecretKey: "test-secret-key-that-is-long-enough",
		Issuer:    "rocketvault-test",
		Audience:  "rocketvault-api",
		Expiry:    time.Hour,
	})
}

func TestJWTService_ValidateToken_WrongAudience(t *testing.T) {
	t.Parallel()
	// Generate a token with a different audience by directly constructing JWT claims
	secretKey := []byte("test-secret-key-that-is-long-enough")
	claims := JWTClaims{
		UserID:   uuid.New(),
		Username: "alice",
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "rocketvault-test",
			Audience:  jwt.ClaimStrings{"wrong-audience"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(secretKey)
	require.NoError(t, err)

	svc := newTestJWTService()
	_, err = svc.ValidateToken(tokenStr)
	assert.Error(t, err, "token with wrong audience must be rejected")
}

func TestJWTService_ValidateToken_ValidToken(t *testing.T) {
	t.Parallel()
	svc := newTestJWTService()
	userID := uuid.New()

	tokenStr, err := svc.GenerateToken(userID, "alice", "user")
	require.NoError(t, err)

	claims, err := svc.ValidateToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "alice", claims.Username)
}

func TestJWTService_ValidateToken_ExpiredToken(t *testing.T) {
	t.Parallel()
	secretKey := []byte("test-secret-key-that-is-long-enough")
	claims := JWTClaims{
		UserID:   uuid.New(),
		Username: "alice",
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // already expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Issuer:    "rocketvault-test",
			Audience:  jwt.ClaimStrings{"rocketvault-api"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(secretKey)
	require.NoError(t, err)

	svc := newTestJWTService()
	_, err = svc.ValidateToken(tokenStr)
	assert.Error(t, err, "expired token must be rejected")
}

func TestJWTService_ValidateToken_WrongIssuer(t *testing.T) {
	t.Parallel()
	secretKey := []byte("test-secret-key-that-is-long-enough")
	claims := JWTClaims{
		UserID:   uuid.New(),
		Username: "alice",
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "attacker-service",
			Audience:  jwt.ClaimStrings{"rocketvault-api"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(secretKey)
	require.NoError(t, err)

	svc := newTestJWTService()
	_, err = svc.ValidateToken(tokenStr)
	assert.Error(t, err, "token with wrong issuer must be rejected")
}
```

- [ ] **Step 3.2: Run the new tests to confirm `WrongAudience` fails**

```bash
go test ./internal/services/auth/... -run "TestJWTService_ValidateToken" -v
```

Expected: `TestJWTService_ValidateToken_WrongAudience` **FAILS** (audience is not currently validated). Other tests may pass or fail depending on current state.

- [ ] **Step 3.3: Rewrite `ValidateToken` to use parser options**

Replace the entire `ValidateToken` function in `internal/services/auth/jwt_service.go` with:

```go
// ValidateToken validates a JWT token and returns the claims if valid.
// It performs signature verification, expiration checks, issuer validation,
// and audience validation using the golang-jwt/v5 parser options.
func (s *jwtService) ValidateToken(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.secretKey, nil
		},
		jwt.WithAudience(s.audience),
		jwt.WithIssuer(s.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}

	validClaims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims")
	}

	return validClaims, nil
}
```

Note: the manual expiry and issuer checks that were previously inside the key-func are removed. `jwt.WithExpirationRequired()`, `jwt.WithIssuer()`, and `jwt.WithAudience()` replace them correctly (they run after signature verification).

- [ ] **Step 3.4: Run all JWT service tests**

```bash
go test ./internal/services/auth/... -run "TestJWTService_ValidateToken" -v
```

Expected: All four tests (`ValidToken`, `WrongAudience`, `ExpiredToken`, `WrongIssuer`) **PASS**.

- [ ] **Step 3.5: Run the full auth and middleware test suite**

```bash
go test ./internal/services/auth/... ./internal/middleware/... -v 2>&1 | tail -30
```

Expected: All pass.

- [ ] **Step 3.6: Commit**

```bash
git add internal/services/auth/jwt_service.go \
        internal/services/auth/jwt_service_test.go
git commit -m "fix(auth): enforce JWT audience validation in ValidateToken

ValidateToken set audience on generated tokens but never verified it
on incoming tokens. Added jwt.WithAudience(), jwt.WithIssuer(), and
jwt.WithExpirationRequired() parser options.

Also removed incorrect manual expiry/issuer checks from the key-func
(they ran before signature verification on untrusted claim data).

Added jwt_service_test.go with 4 test cases covering valid token,
wrong audience, expired token, and wrong issuer scenarios."
```

---

## Task 4: Remove sensitive data from log statements

**Files:**
- Modify: `internal/services/auth/authentication_service.go`

### Background
Two log statements leak sensitive data: (1) the username is logged at `INFO` before auth succeeds — exposing valid usernames to anyone with log access; (2) the TOTP code is logged on failure — an attacker with log access can replay the code within its validity window.

- [ ] **Step 4.1: Remove the pre-auth username log and the TOTP code log field**

In `internal/services/auth/authentication_service.go`:

**Change 1** — Remove the `logrus.Info` at the start of `AuthenticateUser` (line ~105). The audit logger already handles outcome logging further down. Replace:

```go
func (s *authenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*AuthenticationResult, error) {
	logrus.WithField("username", username).Info("Starting user authentication")

	// Retrieve user from repository
```

With:

```go
func (s *authenticationService) AuthenticateUser(ctx context.Context, username, password, totpCode string) (*AuthenticationResult, error) {
	// Retrieve user from repository
```

**Change 2** — Remove `"totp_code": totpCode` from the TOTP failure log (line ~140). Replace:

```go
		logrus.WithFields(logrus.Fields{
			"username":  username,
			"user_id":   user.ID.String(),
			"totp_code": totpCode,
		}).Warn("Authentication failed: invalid TOTP code")
```

With:

```go
		logrus.WithFields(logrus.Fields{
			"username": username,
			"user_id":  user.ID.String(),
		}).Warn("Authentication failed: invalid TOTP code")
```

- [ ] **Step 4.2: Build and run tests**

```bash
go build ./... && go test ./internal/services/auth/... -v 2>&1 | tail -20
```

Expected: Clean build, all tests pass.

- [ ] **Step 4.3: Commit**

```bash
git add internal/services/auth/authentication_service.go
git commit -m "fix(auth): remove sensitive data from log statements

- Remove username log at start of AuthenticateUser (leaks valid usernames)
- Remove totp_code field from TOTP failure log (one-time code replayable
  within validity window by anyone with log access)

Findings from HIGH severity code review items."
```

---

## Task 5: Make session expiry configurable; fix `RefreshTokenResult.ExpiresAt`

**Files:**
- Modify: `internal/services/auth/authentication_service.go`

### Background
Session refresh token expiry is hardcoded to `7 * 24 * time.Hour` and `RefreshTokenResult.ExpiresAt` is hardcoded to `time.Now().Add(time.Hour)` regardless of the actual JWT expiry. Both should derive from config.

- [ ] **Step 5.1: Add `SessionExpiry` to `AuthenticationConfig`**

In `authentication_service.go`, add the field to `AuthenticationConfig`:

```go
type AuthenticationConfig struct {
	UserRepository    repositories.UserRepositoryInterface
	SessionRepository repositories.SessionRepositoryInterface
	PasswordService   PasswordService
	TOTPService       TOTPService
	JWTService        JWTService
	Logger            *logging.Logger
	SessionExpiry     time.Duration // How long refresh token sessions are valid. Defaults to 7 days if zero.
}
```

Add `sessionExpiry` to `authenticationService` struct:

```go
type authenticationService struct {
	userRepo        repositories.UserRepositoryInterface
	sessionRepo     repositories.SessionRepositoryInterface
	passwordService PasswordService
	totpService     TOTPService
	jwtService      JWTService
	logger          *logging.Logger
	sessionExpiry   time.Duration
}
```

Update `NewAuthenticationService` to wire it with a sensible default:

```go
func NewAuthenticationService(config AuthenticationConfig) AuthenticationService {
	sessionExpiry := config.SessionExpiry
	if sessionExpiry == 0 {
		sessionExpiry = 7 * 24 * time.Hour
	}
	return &authenticationService{
		userRepo:        config.UserRepository,
		sessionRepo:     config.SessionRepository,
		passwordService: config.PasswordService,
		totpService:     config.TOTPService,
		jwtService:      config.JWTService,
		logger:          config.Logger,
		sessionExpiry:   sessionExpiry,
	}
}
```

- [ ] **Step 5.2: Replace hardcoded session expiry in `AuthenticateUser`**

Replace:

```go
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour), // 7 days
```

With:

```go
		ExpiresAt:        time.Now().Add(s.sessionExpiry),
```

- [ ] **Step 5.3: Fix `RefreshTokenResult.ExpiresAt` to reflect the JWT expiry**

The JWT expiry is stored in the claims returned by `GenerateToken`. To expose it, parse the just-generated access token's expiry. The simplest approach: record the expected expiry before generating the token.

In `RefreshAccessToken`, replace:

```go
	return &RefreshTokenResult{
		Token:        accessToken,
		RefreshToken: refreshToken, // Same refresh token for now
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
		ExpiresAt:    time.Now().Add(time.Hour), // 1 hour from now
	}, nil
```

With:

```go
	// Parse the newly generated token to get its actual expiry time.
	newClaims, err := s.jwtService.ValidateToken(accessToken)
	if err != nil {
		// Should never happen — we just generated this token
		return nil, fmt.Errorf("failed to read expiry from generated token: %w", err)
	}

	return &RefreshTokenResult{
		Token:        accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
		ExpiresAt:    newClaims.ExpiresAt.Time,
	}, nil
```

- [ ] **Step 5.4: Build and run full auth tests**

```bash
go build ./... && go test ./internal/services/auth/... -v 2>&1 | tail -20
```

Expected: Clean build and all tests pass. The `TestRefreshAccessToken_HappyPath` mock needs `jwt.On("ValidateToken", "new-token")` — check if it passes; if not, add this mock expectation to the test.

If `TestRefreshAccessToken_HappyPath` fails because `ValidateToken` is now called on the generated token, update the mock in `authentication_service_critical_test.go`:

```go
// Add this line to the happy path test setup, after the GenerateToken mock:
jwt.On("ValidateToken", "new-token").Return(&JWTClaims{
    UserID:   userID,
    Username: "bob",
    Role:     domain.RoleUser,
    RegisteredClaims: jwtlib.RegisteredClaims{
        ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
    },
}, nil)
```

(Add `jwtlib "github.com/golang-jwt/jwt/v5"` to the test file imports if not present.)

- [ ] **Step 5.5: Commit**

```bash
git add internal/services/auth/authentication_service.go \
        internal/services/auth/authentication_service_critical_test.go
git commit -m "fix(auth): make session expiry configurable; fix RefreshTokenResult.ExpiresAt

- SessionExpiry moves from hardcoded 7 days to AuthenticationConfig field
  with a 7-day default for backward compatibility
- RefreshTokenResult.ExpiresAt now reflects actual JWT expiry by parsing
  the freshly generated token, instead of hardcoded 1 hour"
```

---

## Task 6: Standardise logging — replace `logrus` direct calls with `s.logger`

**Files:**
- Modify: `internal/services/auth/authentication_service.go`

### Background
The file mixes `logrus.WithField(...)` direct calls and `s.logger.LogAuditInfo/Error(...)` calls. The structured logger (`s.logger`) is the authoritative audit logger; `logrus` direct calls bypass it. All informational/warn/error logs that are not audit events should also use `s.logger` or be removed where they duplicate audit logging.

- [ ] **Step 6.1: Audit all `logrus.*` calls in `authentication_service.go`**

```bash
grep -n "logrus\." internal/services/auth/authentication_service.go
```

For each occurrence, determine:
- Is it an audit event? → already covered by `s.logger.LogAuditInfo/Error` immediately before/after
- Is it a duplicate of the audit log? → **delete it**
- Is it a unique debug/info log with no audit equivalent? → **replace with `s.logger`**

Based on current code, the following `logrus.*` calls are direct duplicates of adjacent `s.logger` audit calls and should be deleted:

| Line (approx) | Call | Action |
|---|---|---|
| ~115 | `logrus.WithField("username"...).Warn("User not found")` | Delete (audit log covers it) |
| ~122 | `logrus.WithField... .Warn("invalid password")` | Delete |
| ~132 | `logrus.WithError(err).Error("TOTP validation error")` | Delete |
| ~139 | `logrus.WithFields...Warn("invalid TOTP code")` | Delete (after Task 4 removed totp_code) |
| ~148 | `logrus.WithError(err).Error("Failed to generate JWT token")` | Delete |
| ~155 | `logrus.WithError(err).Error("Failed to generate refresh token")` | Delete |
| ~167 | `logrus.WithError(err).Error("Failed to create session")` | Delete |
| ~173 | `logrus.WithFields...Info("User authenticated successfully with session")` | Delete (duplicates audit) |
| ~238 | `logrus.WithError(err).Warn("Token refresh failed: invalid refresh token")` | Delete |
| ~285 | `logrus.WithError(err).Error("Token refresh failed: could not generate access token")` | Delete |
| ~292 | `logrus.WithError(err).Warn("...update session last used")` | Delete |
| ~299 | `logrus.WithFields...Info("Access token refreshed successfully")` | Delete |
| `RevokeSession` | `logrus.WithError(err).Error` / `logrus.WithFields...Info` | Delete (audit covers it) |
| `RevokeAllUserSessions` | `logrus.WithError(err).Error` / `logrus.WithFields...Info` | Delete |

Also remove the `"github.com/sirupsen/logrus"` import from `authentication_service.go` once all direct calls are removed.

- [ ] **Step 6.2: Build to confirm no unused imports**

```bash
go build ./internal/services/auth/...
```

Expected: Clean. If the `logrus` import is still referenced anywhere (e.g., in `RefreshAccessToken` `logrus.Info("Starting token refresh")`), remove those remaining calls too.

- [ ] **Step 6.3: Run full test suite**

```bash
go test ./internal/services/auth/... -v 2>&1 | tail -20
```

Expected: All tests pass.

- [ ] **Step 6.4: Commit**

```bash
git add internal/services/auth/authentication_service.go
git commit -m "fix(auth): standardise logging to s.logger, remove direct logrus calls

Direct logrus.* calls in authentication_service.go duplicated the
structured s.logger audit events and bypassed the centralized audit
logging infrastructure. Removed all duplicate logrus calls and the
logrus import."
```

---

## Task 7: Add missing `RevokeAllUserSessions` test cases

**Files:**
- Modify: `internal/services/auth/authentication_service_critical_test.go`

### Background
`RevokeAllUserSessions` has no test cases in either test file. Adding success and failure cases brings coverage to 100% for the auth service interface.

- [ ] **Step 7.1: Add two test cases for `RevokeAllUserSessions`**

Append to `internal/services/auth/authentication_service_critical_test.go`:

```go
func TestRevokeAllUserSessions_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("RevokeAllUserSessions", ctx, userID, "security-policy").Return(nil)

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	err := svc.RevokeAllUserSessions(ctx, userID, "security-policy")

	require.NoError(t, err)
	sessionRepo.AssertExpectations(t)
}

func TestRevokeAllUserSessions_RepositoryError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	pwd := &MockPasswordService{}
	totp := &MockTOTPService{}
	jwt := &MockJWTService{}

	sessionRepo.On("RevokeAllUserSessions", ctx, userID, "logout").
		Return(errors.New("database unavailable"))

	svc := newAuthService(userRepo, sessionRepo, pwd, totp, jwt)
	err := svc.RevokeAllUserSessions(ctx, userID, "logout")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke all user sessions")
}
```

- [ ] **Step 7.2: Run the new tests**

```bash
go test ./internal/services/auth/... -run "TestRevokeAllUserSessions" -v
```

Expected: Both tests **PASS**.

- [ ] **Step 7.3: Run full test suite and check coverage**

```bash
go test ./internal/services/auth/... -v -coverprofile=coverage.out
go tool cover -func=coverage.out | grep authentication_service
```

Expected: `authenticationService` methods at ≥ 90% coverage.

- [ ] **Step 7.4: Commit**

```bash
git add internal/services/auth/authentication_service_critical_test.go
git commit -m "test(auth): add RevokeAllUserSessions test cases

Happy path and repository error cases. Closes the last test coverage
gap identified in the auth service code review."
```

---

## Final Verification

After all tasks are complete:

- [ ] **Full build**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go build ./...
```

Expected: Zero errors.

- [ ] **Full test suite**

```bash
go test ./... 2>&1 | grep -E "FAIL|ok" | sort
```

Expected: All packages report `ok`. No `FAIL` lines.

- [ ] **Coverage summary for auth package**

```bash
go test ./internal/services/auth/... -coverprofile=auth_coverage.out
go tool cover -func=auth_coverage.out
```

Expected: `authentication_service.go` and `jwt_service.go` at ≥ 90% statement coverage.

---

## Issue Tracker

| Task | Issue | Status |
|------|-------|--------|
| 1 | CRITICAL: `hashRefreshToken` no-op | Pending |
| 2 | CRITICAL: `ParseToken` public interface | Pending |
| 3 | HIGH: JWT audience not validated | Pending |
| 4 | HIGH: Sensitive data in logs | Pending |
| 5 | MEDIUM: Hardcoded session/JWT expiry | Pending |
| 6 | LOW: Mixed `logrus`/`s.logger` usage | Pending |
| 7 | TEST: `RevokeAllUserSessions` untested | Pending |
