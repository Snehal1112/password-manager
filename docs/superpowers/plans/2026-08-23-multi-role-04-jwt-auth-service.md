# Multi-Role: JWT Claims & Authentication Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `model.Claims.Roles []string` embedded in every issued JWT, and
`JWTService.GenerateToken` threading a role list instead of one string
through login, token refresh, and OAuth2 service-account token issuance.

**Architecture:** `GenerateToken`'s third parameter changes from `role
string` to `roles []string`. Its three call sites (login, refresh, OAuth2)
each pass `user.Roles` (or, for service accounts, a literal one-element
slice — service accounts have no stored role at all, see Plan 09 notes).
`ValidateSession`'s service-account special case moves from `==` to a
`slices.Contains` check.

**Tech Stack:** Go, `github.com/golang-jwt/jwt`.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- Depends on Plan 02 (`model.User.Roles`) and Plan 03 (`common.HasAnyRole`,
  used nowhere in this plan directly, but establishes the pattern this plan
  follows for the `slices.Contains`-style check).
- `RefreshAccessToken` re-derives roles fresh from `s.userRepo.Read` — do not
  copy roles forward from the old token's claims.
- `model.Claims.Roles []string` is the single source of truth for a request's
  authorization — every plan from 06 onward reads `claims.Roles`, not
  `claims.Role`.

---

### Task 1: `model.Claims.Roles` + `JWTService.GenerateToken` signature

**Files:**
- Modify: `model/user.go:29-34` (`Claims` struct)
- Modify: `internal/services/auth/jwt_service.go` (`JWTClaims` struct,
  `JWTService` interface, `GenerateToken` implementation)
- Test: `internal/services/auth/jwt_service_test.go` (check if it exists
  first with `ls internal/services/auth/*_test.go`; add to it or create it)

**Interfaces:**
- Produces:
  - `model.Claims.Roles []string` (JSON tag `json:"role"` — keep the JSON
    field name `role`... no: change it to `"roles"` for consistency with
    every other JSON shape this feature touches. Use `json:"roles"`.)
  - `type JWTClaims struct { ...; Roles []string \`json:"role"\` ... }` — same
    rename, `json:"roles"`.
  - `GenerateToken(userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (string, error)`

- [ ] **Step 1: Write the failing test**

Create (or add to) `internal/services/auth/jwt_service_test.go`:

```go
package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestJWTService_GenerateToken_EmbedsMultipleRoles(t *testing.T) {
	svc := NewJWTService(JWTServiceConfig{
		SigningProvider: testSigningProvider(t), // see Step 2 note below
		Expiry:          time.Hour,
		Issuer:          "test",
		Audience:        "test",
	})

	userID := uuid.New()
	sessionID := uuid.New()
	tokenStr, err := svc.GenerateToken(userID, "alice", []string{"admin", "secrets_manager"}, sessionID)
	require.NoError(t, err)

	claims, err := svc.ValidateToken(tokenStr)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"admin", "secrets_manager"}, claims.Roles)
}
```

Before writing this test, check `internal/services/auth/jwt_service_test.go`
(if it already exists) or `internal/services/auth/signing_test_helpers.go`
/similar for how existing tests construct a `JWTService` in tests — there is
almost certainly already a helper providing a test `SigningProvider` (search
`grep -rn "NewJWTService(" internal/services/auth/*_test.go`). Use whatever
that existing helper is instead of inventing `testSigningProvider(t)` — that
name is illustrative, not a real symbol to create from scratch if one already
exists.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/auth/... -run TestJWTService_GenerateToken_EmbedsMultipleRoles -v`
Expected: FAIL — compile error, `claims.Roles` undefined (still `Role
string`), and `GenerateToken`'s third parameter type mismatch

- [ ] **Step 3: Change `model.Claims`**

In `model/user.go`:

```go
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Roles    []string  `json:"roles"`
	jwt.RegisteredClaims
}
```

- [ ] **Step 4: Change `JWTClaims` and `GenerateToken`**

In `internal/services/auth/jwt_service.go`:

```go
type JWTClaims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Roles    []string  `json:"roles"`
	jwt.RegisteredClaims
}

type JWTService interface {
	GenerateToken(userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (string, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
	ParseToken(tokenString string) (*JWTClaims, error)
}
```

```go
func (s *jwtService) GenerateToken(userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
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
	// ... rest of the function is unchanged below this point (signing logic) —
	// do not modify anything after the claims struct literal.
```

Do not change anything below the `claims := JWTClaims{...}` literal — the
signing/encoding logic that follows doesn't reference `role`/`Role` anywhere.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/services/auth/... -run TestJWTService_GenerateToken_EmbedsMultipleRoles -v`
Expected: PASS

- [ ] **Step 6: Fix compile errors this ripples into**

Run: `go build ./... 2>&1 | head -50`

Expected: compile failures in `internal/services/auth/authentication_service.go`
(three `GenerateToken(..., user.Role, ...)` calls) and
`internal/services/oauth2/oauth2_service.go` (one call) — these are Task 2
and Task 3 of this plan, not fixed yet. Confirm the failures are limited to
exactly these two files before moving on (a failure anywhere else means
something in this task's diff is wrong).

- [ ] **Step 7: Commit**

```bash
git add model/user.go internal/services/auth/jwt_service.go internal/services/auth/jwt_service_test.go
git commit -m "feat(auth): embed a role list in JWTClaims instead of one role string"
```

---

### Task 2: Wire `authentication_service.go`

**Files:**
- Modify: `internal/services/auth/authentication_service.go`
  (`AuthenticationResult`, `RefreshTokenResult`, `issueSession`,
  `ValidateSession`, `RefreshAccessToken`)
- Test: `internal/services/auth/authentication_service_test.go`

**Interfaces:**
- Consumes: `GenerateToken(userID, username, roles []string, sessionID)`
  from Task 1; `model.User.Roles` from Plan 02.
- Produces: `AuthenticationResult.Roles []string`, `RefreshTokenResult.Roles
  []string`.

- [ ] **Step 1: Write the failing test**

Check `internal/services/auth/authentication_service_test.go` for its
existing mock/fixture pattern (look for how `user.Role` is set on fixture
`model.User` values today), then add:

```go
func TestIssueSession_EmbedsAllUserRoles(t *testing.T) {
	// Follow this file's existing setup pattern (mocks for userRepo,
	// sessionRepo, jwtService, etc.) — construct a *model.User with
	// Roles: []string{"admin", "crypto_manager"}, call issueSession (or
	// whichever exported entry point this file's tests already use to reach
	// it, e.g. AuthenticateUser), and assert the returned
	// AuthenticationResult.Roles matches.
	t.Skip("fill in using this file's existing mock/fixture pattern before implementing")
}
```

Do not actually leave this as `t.Skip` in the final commit — read the
existing test file first (it has real mocks for every dependency of
`authenticationService`), write a real test matching its pattern with
`Roles: []string{"admin", "crypto_manager"}` as the fixture user's roles and
`assert.ElementsMatch(t, []string{"admin", "crypto_manager"}, result.Roles)`
as the assertion, then proceed.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/auth/... -run TestIssueSession_EmbedsAllUserRoles -v`
Expected: FAIL — compile error, `.Roles` undefined on `AuthenticationResult`

- [ ] **Step 3: Update the two result structs**

```go
type AuthenticationResult struct {
	Token        string // Access token
	RefreshToken string // Refresh token
	UserID       uuid.UUID
	Username     string
	Roles        []string
}

type RefreshTokenResult struct {
	Token        string // New access token
	RefreshToken string // New refresh token (if rotation is enabled)
	UserID       uuid.UUID
	Username     string
	Roles        []string
	ExpiresAt    time.Time
}
```

- [ ] **Step 4: Update `issueSession`**

Change the `GenerateToken` call and the returned struct literal:

```go
	// Generate access token (short-lived) with session.ID as jti for revocation checks.
	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Roles, session.ID)
	...
	return &AuthenticationResult{
		Token:        accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Username:     user.Username,
		Roles:        user.Roles,
	}, nil
```

(Only these two lines change — the rest of `issueSession`'s body, including
session creation and audit logging, is untouched.)

- [ ] **Step 5: Update `ValidateSession`'s service-account check**

Change:

```go
	if claims.Role == model.RoleServiceAccount {
```

to:

```go
	if slices.Contains(claims.Roles, model.RoleServiceAccount) {
```

Add `"slices"` to this file's imports (Go 1.21+ stdlib — this repo targets
Go 1.25 per `CLAUDE.md`, so the stdlib package is available, no external
dependency needed).

- [ ] **Step 6: Update `RefreshAccessToken`**

Change the `GenerateToken` call and the returned struct literal, same shape
as `issueSession`:

```go
	// Generate new access token with the existing session.ID as jti.
	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Roles, session.ID)
	...
	return &RefreshTokenResult{
		Token:        accessToken,
		RefreshToken: refreshToken, // Same refresh token for now
		UserID:       user.ID,
		Username:     user.Username,
		Roles:        user.Roles,
		ExpiresAt:    time.Now().Add(time.Hour), // 1 hour from now
	}, nil
```

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/services/auth/... -run TestIssueSession_EmbedsAllUserRoles -v`
Expected: PASS

- [ ] **Step 8: Run the full package test suite**

Run: `go test ./internal/services/auth/... -v`
Expected: all PASS. Any remaining `.Role`/`Role:` compile errors in this
package's other test files must be fixed as part of this step (mechanical —
`Role: "admin"` → `Roles: []string{"admin"}` wherever a `model.User` or
`AuthenticationResult`/`RefreshTokenResult` literal appears).

- [ ] **Step 9: Commit**

```bash
git add internal/services/auth/authentication_service.go internal/services/auth/authentication_service_test.go
git commit -m "feat(auth): thread multi-role through login, refresh, and session validation"
```

---

### Task 3: OAuth2 service-account call site + final verification

**Files:**
- Modify: `internal/services/oauth2/oauth2_service.go` (`IssueToken`)
- Test: `internal/services/oauth2/oauth2_service_test.go`

**Interfaces:**
- Consumes: `GenerateToken(userID, username, roles []string, sessionID)`.

- [ ] **Step 1: Write the failing test**

Find the existing test covering `IssueToken` in
`internal/services/oauth2/oauth2_service_test.go` (there is definitely at
least one — this is a well-tested path per the project's OAuth2 docs) and
add an assertion that the generated token's claims contain exactly
`[]string{model.RoleServiceAccount}` — check that file's existing pattern
for validating token claims (it likely already parses the returned JWT in at
least one test) and extend the same way rather than inventing a new pattern.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/oauth2/... -v`
Expected: FAIL — compile error, though NOT inside `oauth2_service.go` itself
(read on before assuming where).

**Correction to this brief, found during Task 1's review:** `oauth2_service.go`
defines its OWN local `JWTService` interface —
`GenerateToken(userID uuid.UUID, username, role string, sessionID uuid.UUID) (string, error)`
— separate from `internal/services/auth`'s `JWTService`. Because Go
interfaces are structural, `oauth2_service.go`'s own type-checking is
unaffected by Task 1's change to the *other* package's interface; the actual
break is an interface-satisfaction mismatch where the real `*jwtService` gets
wired in, at `internal/container/service_container.go`'s
`OAuth2Config{JWTService: c.jwtService}` assignment. Confirm this yourself
first with `go build ./internal/services/oauth2/... ./internal/container/...`
before proceeding, rather than assuming the brief's original file list is
complete.

- [ ] **Step 3: Fix both the local interface and the call site**

In `internal/services/oauth2/oauth2_service.go`, update the local `JWTService`
interface's `GenerateToken` method signature to match the real one:

```go
	GenerateToken(userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (string, error)
```

Then fix `IssueToken`'s call:

```go
	tokenStr, err := s.jwtSvc.GenerateToken(client.ID, client.Name, []string{model.RoleServiceAccount}, client.ID)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/oauth2/... -v`
Expected: PASS

- [ ] **Step 5: Full-repo build check**

Run: `go build ./... 2>&1 | head -80`

Expected: remaining failures are confined to files this plan set's later
plans (05-10) haven't touched yet — every `.Role`/`Role:` compile error
should trace to a file explicitly named in Plans 05-10's scope. If a failure
shows up in a file NOT covered by any later plan, note it — that's a gap in
the plan decomposition to flag before continuing.

- [ ] **Step 6: Commit**

```bash
git add internal/services/oauth2/oauth2_service.go internal/services/oauth2/oauth2_service_test.go
git commit -m "fix(oauth2): adapt IssueToken to GenerateToken's new roles []string signature"
```
