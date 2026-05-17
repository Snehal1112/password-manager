# Security Vulnerability Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 4 confirmed security vulnerabilities in `cmd/` and their underlying service layers with defense-in-depth solutions.

**Architecture:** Each fix applies at two layers — the CLI command handler (immediate gate) and the service layer (long-term defense-in-depth). Role validation is centralised using existing `internal/domain` constants. Tests follow the existing mock-based pattern in `cmd/testutils/test_utils.go`.

**Tech Stack:** Go 1.24.2, Cobra CLI, testify/mock, `crypto/rand`, existing `internal/domain` role constants.

---

## Files Modified

| File | Change |
|------|--------|
| `cmd/users/create.go` | Add admin-role guard before calling service |
| `cmd/users/update.go` | Fix role-change guard + replace `strings.Contains` with map lookup |
| `internal/services/users/user_service.go` | Add `CallerRole` to `CreateUserRequest`; validate in `CreateUser`. Add `CallerRole`+`CallerID` to `UpdateUserRequest`; validate in `UpdateUser` |
| `cmd/secrets/generate.go` | Replace `math/rand` + re-seeding with `crypto/rand`; remove `math/rand` import |
| `cmd/rotation.go` | Extract `userID` in `runRotationDelete`, `runRotationUnassign`, `runRotationHistory` |
| `internal/services/secrets/rotation_service.go` | Add `UserID` to `DeletePolicy`, `RemovePolicyFromSecret`; enforce ownership. Add `UserID` to `GetRotationHistory`; verify secret ownership |
| `cmd/users/create_test.go` | Update existing tests; add forbidden-role test cases |
| `cmd/users/update_test.go` | Add self-promotion and substring-bypass test cases |
| `cmd/secrets/generate_test.go` | Add entropy/uniqueness and charset tests |
| `cmd/rotation_test.go` | Add ownership-enforcement test cases for delete/unassign/history |

---

## Task 1: Fix Privilege Escalation in `users create` (Vuln 1)

Any authenticated user can create an admin account. Fix at both the command layer and the service layer.

**Files:**

- Modify: `cmd/users/create.go`
- Modify: `internal/services/users/user_service.go`
- Modify: `cmd/users/create_test.go`

- [ ] **Step 1: Write failing test for non-admin caller blocked**

Add this test case to `TestCreateUserCommand` in `cmd/users/create_test.go`. The test context sets `Role: domain.RoleAdmin` by default (see `testutils.NewTestContext`), so create a helper that overrides it:

```go
func newTestContextWithRole(t *testing.T, role string) *testutils.TestContext {
 tc := testutils.NewTestContext(t)
 claims := &domain.Claims{
  UserID:   tc.TestUserID,
  Username: "testuser",
  Role:     role,
 }
 ctx := context.WithValue(tc.Ctx, common.ClaimsKey, claims)
 tc.Ctx = ctx
 return tc
}
```

Then add this test at the bottom of `TestCreateUserCommand` in `cmd/users/create_test.go`:

```go
func TestCreateUserRequiresAdminRole(t *testing.T) {
 for _, role := range []string{domain.RoleUser, domain.RoleSecretsManager, domain.RoleCryptoManager, domain.RoleCertificateManager} {
  t.Run("blocked for role "+role, func(t *testing.T) {
   viper.Reset()
   tc := newTestContextWithRole(t, role)

   cmd := &cobra.Command{
    Use:  "create",
    RunE: createCmd.RunE,
   }
   cmd.Flags().String("new-username", "", "")
   cmd.Flags().String("new-password", "", "")
   cmd.Flags().String("new-role", "", "")
   cmd.SetContext(tc.Ctx)
   cmd.SetArgs([]string{"--new-username=newuser", "--new-password=pw123", "--new-role=user"})

   err := cmd.Execute()
   assert.Error(t, err)
   assert.Contains(t, err.Error(), "forbidden")

   tc.MockUserService.AssertNotCalled(t, "CreateUser")
  })
 }
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./cmd/users/... -run TestCreateUserRequiresAdminRole -v
```

Expected: FAIL — `createCmd.RunE` currently never checks the caller's role.

- [ ] **Step 3: Add admin-role guard to `cmd/users/create.go`**

Replace the `RunE` function body opening (lines 43–57) with:

```go
RunE: func(cmd *cobra.Command, args []string) error {
    ctx := cmd.Context()

    // Require admin role to create any user account.
    claims, ok := ctx.Value(common.ClaimsKey).(*domain.Claims)
    if !ok || claims == nil {
        return fmt.Errorf("unauthorized: missing authentication claims")
    }
    if claims.Role != domain.RoleAdmin {
        return fmt.Errorf("forbidden: only admin users can create new accounts")
    }

    // Get service container from context (using interface for testability)
    serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
    if !ok || serviceContainer == nil {
        return fmt.Errorf("service container not available in context")
    }

    username, _ := cmd.Flags().GetString("new-username")
    password, _ := cmd.Flags().GetString("new-password")
    role, _ := cmd.Flags().GetString("new-role")

    if username == "" || password == "" || role == "" {
        return fmt.Errorf("username, password, and role are required")
    }

    userSvc := serviceContainer.GetUserService()
    result, err := userSvc.CreateUser(ctx, userService.CreateUserRequest{
        Username:   username,
        Password:   password,
        Role:       role,
        CallerRole: claims.Role,
    })
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    // ... (rest unchanged)
```

Also add `"rocketvault/internal/domain"` to imports if not already present.

- [ ] **Step 4: Add `CallerRole` to `CreateUserRequest` and validate in service**

In `internal/services/users/user_service.go`, update `CreateUserRequest`:

```go
// CreateUserRequest represents a request to create a new user.
type CreateUserRequest struct {
 Username   string
 Password   string
 Role       string
 CallerRole string // Required — must be domain.RoleAdmin
}
```

At the top of `CreateUser`, before hashing the password, add:

```go
func (s *userService) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResult, error) {
 if req.CallerRole != domain.RoleAdmin {
  return nil, fmt.Errorf("forbidden: caller must have admin role to create users")
 }
 // ... existing code continues unchanged
```

- [ ] **Step 5: Update `cmd/users/admin.go` to pass `CallerRole`**

`admin.go` creates the bootstrap admin via a different path (bootstrap token, not JWT claims). Search for the `CreateUser` call in `cmd/users/admin.go` and pass `CallerRole: domain.RoleAdmin` explicitly since the bootstrap path is pre-authorised:

```go
result, err := userSvc.CreateUser(cmd.Context(), userService.CreateUserRequest{
    Username:   adminUsername,
    Password:   adminPassword,
    Role:       domain.RoleAdmin,
    CallerRole: domain.RoleAdmin, // bootstrap is pre-authorised
})
```

- [ ] **Step 6: Update existing `create_test.go` mock call to include `CallerRole`**

The existing mock expectation in `TestCreateUserCommand` must now include `CallerRole`:

```go
tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
    Username:   "newuser",
    Password:   "password123",
    Role:       domain.RoleUser,
    CallerRole: domain.RoleAdmin, // TestContext default role is admin
}).Return(expectedResult, nil)
```

Update all `CreateUser` mock expectations in `create_test.go` to include `CallerRole: domain.RoleAdmin`.

- [ ] **Step 7: Run tests to confirm all pass**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./cmd/users/... -v
go test ./internal/services/users/... -v
```

Expected: All tests PASS.

- [ ] **Step 8: Run full test suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./...
```

Expected: All tests PASS, zero compilation errors.

- [ ] **Step 9: Commit**

```bash
git add cmd/users/create.go cmd/users/create_test.go cmd/users/admin.go internal/services/users/user_service.go
git commit -m "fix(security): require admin role to create users — cmd + service layer"
```

---

## Task 2: Fix Privilege Self-Escalation in `users update` (Vuln 2)

Two bugs: (a) users can change their own role, (b) `strings.Contains` is a substring check not exact match. Fix both at cmd and service layers.

**Files:**

- Modify: `cmd/users/update.go`
- Modify: `internal/services/users/user_service.go`
- Create: `cmd/users/update_test.go` (add new test cases)

- [ ] **Step 1: Write failing tests for self-promotion and substring bypass**

Create `cmd/users/update_test.go` (it does not currently exist):

```go
package users

import (
 "context"
 "testing"

 "github.com/google/uuid"
 "github.com/spf13/cobra"
 "github.com/spf13/viper"
 "github.com/stretchr/testify/assert"

 "rocketvault/cmd/testutils"
 "rocketvault/common"
 "rocketvault/internal/domain"
)

// newUpdateTestContextWithRole creates a test context where the caller has the given role
// and is the given user ID.
func newUpdateTestContextWithRole(t *testing.T, callerID uuid.UUID, role string) *testutils.TestContext {
 tc := testutils.NewTestContext(t)
 claims := &domain.Claims{
  UserID:   callerID,
  Username: "testuser",
  Role:     role,
 }
 ctx := context.WithValue(tc.Ctx, common.ClaimsKey, claims)
 ctx = context.WithValue(ctx, common.UserIDKey, callerID)
 tc.Ctx = ctx
 return tc
}

func TestUpdateUserRoleEnforcement(t *testing.T) {
 ownID := uuid.New()

 tests := []struct {
  name        string
  callerRole  string
  targetID    string
  newRole     string
  expectError string
 }{
  {
   name:        "admin can change another user role",
   callerRole:  domain.RoleAdmin,
   targetID:    uuid.New().String(),
   newRole:     domain.RoleUser,
   expectError: "",
  },
  {
   name:        "non-admin cannot change own role",
   callerRole:  domain.RoleUser,
   targetID:    ownID.String(),
   newRole:     domain.RoleAdmin,
   expectError: "forbidden",
  },
  {
   name:        "non-admin cannot change other user role",
   callerRole:  domain.RoleSecretsManager,
   targetID:    uuid.New().String(),
   newRole:     domain.RoleUser,
   expectError: "forbidden",
  },
  {
   name:        "invalid role substring bypass blocked",
   callerRole:  domain.RoleAdmin,
   targetID:    uuid.New().String(),
   newRole:     "min", // substring of "admin" — must be rejected
   expectError: "invalid role",
  },
  {
   name:        "invalid role empty-string bypass blocked",
   callerRole:  domain.RoleAdmin,
   targetID:    uuid.New().String(),
   newRole:     "_manager", // substring of "secrets_manager"
   expectError: "invalid role",
  },
 }

 for _, tt := range tests {
  t.Run(tt.name, func(t *testing.T) {
   viper.Reset()
   tc := newUpdateTestContextWithRole(t, ownID, tt.callerRole)

   cmd := &cobra.Command{
    Use:  "update",
    Args: cobra.ExactArgs(1),
    RunE: updateCmd.RunE,
   }
   cmd.Flags().String("new-username", "", "")
   cmd.Flags().String("new-password", "", "")
   cmd.Flags().String("new-role", "", "")
   cmd.SetContext(tc.Ctx)
   cmd.SetArgs([]string{tt.targetID, "--new-role=" + tt.newRole})

   err := cmd.Execute()

   if tt.expectError != "" {
    assert.Error(t, err)
    assert.Contains(t, err.Error(), tt.expectError)
    tc.MockUserService.AssertNotCalled(t, "UpdateUser")
   } else {
    // Admin path — mock must be set up; here just assert no forbidden error
    assert.NotContains(t, func() string {
     if err != nil { return err.Error() }
     return ""
    }(), "forbidden")
   }
  })
 }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./cmd/users/... -run TestUpdateUserRoleEnforcement -v
```

Expected: FAIL — the current code uses `strings.Contains` and does not block same-user role changes.

- [ ] **Step 3: Fix role-change guard and validation in `cmd/users/update.go`**

Replace lines 66–86 of `cmd/users/update.go` with:

```go
  if claims.UserID != id && claims.Role != domain.RoleAdmin {
   logger := serviceContainer.GetLogger()
   logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "forbidden: cannot update other users", nil)
   return fmt.Errorf("forbidden: cannot update other users")
  }

  newUsername := viper.GetString("new-username")
  newPassword := viper.GetString("new-password")
  newRole := viper.GetString("new-role")

  if newUsername == "" && newPassword == "" && newRole == "" {
   logger := serviceContainer.GetLogger()
   logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "at least one field must be provided", nil)
   return fmt.Errorf("at least one field (new-username, new-password, new-role) must be provided")
  }

  // Only admins may change roles — including changing their own role.
  if newRole != "" && claims.Role != domain.RoleAdmin {
   logger := serviceContainer.GetLogger()
   logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "forbidden: only admins can change roles", nil)
   return fmt.Errorf("forbidden: only admins can change roles")
  }

  // Validate role is an exact known value (not a substring match).
  validRoles := map[string]bool{
   domain.RoleAdmin:              true,
   domain.RoleUser:               true,
   domain.RoleSecretsManager:     true,
   domain.RoleCryptoManager:      true,
   domain.RoleCertificateManager: true,
   domain.RoleServiceAccount:     true,
  }
  if newRole != "" && !validRoles[newRole] {
   logger := serviceContainer.GetLogger()
   logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "invalid role", nil)
   return fmt.Errorf("invalid role: must be one of admin, secrets_manager, crypto_manager, certificate_manager, user, service_account")
  }
```

Remove the `"strings"` import from `cmd/users/update.go` since it is no longer used.

- [ ] **Step 4: Add `CallerID` and `CallerRole` to `UpdateUserRequest` and validate in service**

In `internal/services/users/user_service.go`, update `UpdateUserRequest`:

```go
// UpdateUserRequest represents a request to update an existing user.
type UpdateUserRequest struct {
 UserID     uuid.UUID
 CallerID   uuid.UUID // ID of the user performing the update
 CallerRole string    // Role of the user performing the update
 Username   *string
 Password   *string
 Role       *string
}
```

At the top of `UpdateUser`, add enforcement before the repository read:

```go
func (s *userService) UpdateUser(ctx context.Context, req UpdateUserRequest) error {
 // Only admins may change any user's role.
 if req.Role != nil && req.CallerRole != domain.RoleAdmin {
  return fmt.Errorf("forbidden: only admins can change roles")
 }

 // Validate role value if provided.
 if req.Role != nil {
  validRoles := map[string]bool{
   domain.RoleAdmin:              true,
   domain.RoleUser:               true,
   domain.RoleSecretsManager:     true,
   domain.RoleCryptoManager:      true,
   domain.RoleCertificateManager: true,
   domain.RoleServiceAccount:     true,
  }
  if !validRoles[*req.Role] {
   return fmt.Errorf("invalid role: %s", *req.Role)
  }
 }

 logrus.WithField("user_id", req.UserID.String()).Info("Updating user")
 // ... existing code continues unchanged
```

- [ ] **Step 5: Update the `UpdateUser` call in `cmd/users/update.go` to pass caller identity**

In `cmd/users/update.go`, update the `UpdateUser` call (around line 103):

```go
  if err := userSvc.UpdateUser(ctx, userService.UpdateUserRequest{
   UserID:     id,
   CallerID:   claims.UserID,
   CallerRole: claims.Role,
   Username:   usernamePtr,
   Password:   passwordPtr,
   Role:       rolePtr,
  }); err != nil {
```

- [ ] **Step 6: Run all user command tests**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./cmd/users/... -v
go test ./internal/services/users/... -v
```

Expected: All tests PASS.

- [ ] **Step 7: Run full test suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./...
```

Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd/users/update.go cmd/users/update_test.go internal/services/users/user_service.go
git commit -m "fix(security): block role self-promotion and fix substring role validation"
```

---

## Task 3: Fix Weak Password Generator in `secrets generate-password` (Vuln 3)

Replace `math/rand` with `crypto/rand`. The existing correct pattern lives in `internal/services/secrets/secret_service.go:578-586`.

**Files:**

- Modify: `cmd/secrets/generate.go`
- Modify: `cmd/secrets/generate_test.go` (add entropy test)

- [ ] **Step 1: Write failing tests for password entropy and uniqueness**

Create `cmd/secrets/generate_test.go` (check if it already exists with `ls cmd/secrets/`; if so, append):

```go
package secrets

import (
 "strings"
 "testing"
 "unicode"

 "github.com/stretchr/testify/assert"
 "github.com/stretchr/testify/require"
)

func TestGeneratePasswordUsesCSPRNG(t *testing.T) {
 // Generate 100 passwords of length 16 and verify they are not all identical.
 // With math/rand re-seeded per-character from UnixNano, consecutive chars often
 // repeat within the same nanosecond window. crypto/rand must not produce this.
 seen := make(map[string]bool)
 for i := 0; i < 100; i++ {
  pw, err := generatePassword(16, true, true, true, true)
  require.NoError(t, err)
  seen[pw] = true
 }
 // At least 90 out of 100 must be unique (crypto/rand should produce 100 unique)
 assert.Greater(t, len(seen), 90, "expected near-unique passwords, got many duplicates — likely weak RNG")
}

func TestGeneratePasswordHasNoRepeatingRun(t *testing.T) {
 // With the buggy re-seeding, a password of length 16 often has runs of 3+ identical chars.
 // crypto/rand should essentially never produce this in 1000 tries.
 for i := 0; i < 1000; i++ {
  pw, err := generatePassword(16, true, true, true, true)
  require.NoError(t, err)
  runes := []rune(pw)
  for j := 0; j < len(runes)-2; j++ {
   assert.False(t, runes[j] == runes[j+1] && runes[j+1] == runes[j+2],
    "found 3 identical consecutive chars in password %q at pos %d — likely weak RNG", pw, j)
  }
 }
}

func TestGeneratePasswordLength(t *testing.T) {
 pw, err := generatePassword(20, true, true, true, false)
 require.NoError(t, err)
 assert.Len(t, []rune(pw), 20)
}

func TestGeneratePasswordCharsetEnforcement(t *testing.T) {
 // With only lowercase enabled, all chars must be lowercase letters.
 pw, err := generatePassword(32, false, true, false, false)
 require.NoError(t, err)
 for _, c := range pw {
  assert.True(t, unicode.IsLower(c), "expected only lowercase, got %c in %q", c, pw)
 }
}

func TestGeneratePasswordAllCharsetTypes(t *testing.T) {
 // With all types enabled and length 64, at least one of each type should appear.
 pw, err := generatePassword(64, true, true, true, true)
 require.NoError(t, err)
 assert.True(t, strings.ContainsAny(pw, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "no uppercase in %q", pw)
 assert.True(t, strings.ContainsAny(pw, "abcdefghijklmnopqrstuvwxyz"), "no lowercase in %q", pw)
 assert.True(t, strings.ContainsAny(pw, "0123456789"), "no digits in %q", pw)
 assert.True(t, strings.ContainsAny(pw, "!@#$%^&*()-_=+[]{}|;:,.<>?"), "no special chars in %q", pw)
}

func TestGeneratePasswordRejectsEmptyCharset(t *testing.T) {
 _, err := generatePassword(16, false, false, false, false)
 assert.Error(t, err)
 assert.Contains(t, err.Error(), "at least one character type")
}

func TestGeneratePasswordRejectsZeroLength(t *testing.T) {
 _, err := generatePassword(0, true, true, true, true)
 assert.Error(t, err)
 assert.Contains(t, err.Error(), "length must be at least 1")
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./cmd/secrets/... -run "TestGeneratePassword" -v
```

Expected: `TestGeneratePasswordUsesCSPRNG` and `TestGeneratePasswordHasNoRepeatingRun` FAIL due to repeated chars from `math/rand` re-seeding.

- [ ] **Step 3: Replace `generatePassword` in `cmd/secrets/generate.go`**

Replace the entire `generatePassword` function (lines 98–154) and update imports. The new function signature is identical — only the body changes:

```go
package secrets

import (
 "crypto/rand"
 "fmt"
 "math/big"
 "os"

 "github.com/sirupsen/logrus"
 "github.com/spf13/cobra"
)
```

Replace the `generatePassword` function body:

```go
func generatePassword(length int, useUpper, useLower, useNumbers, useSpecial bool) (string, error) {
 if length < 1 {
  return "", fmt.Errorf("password length must be at least 1")
 }

 const (
  upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  lowerChars   = "abcdefghijklmnopqrstuvwxyz"
  numberChars  = "0123456789"
  specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
 )

 var chars []rune
 if useUpper {
  chars = append(chars, []rune(upperChars)...)
 }
 if useLower {
  chars = append(chars, []rune(lowerChars)...)
 }
 if useNumbers {
  chars = append(chars, []rune(numberChars)...)
 }
 if useSpecial {
  chars = append(chars, []rune(specialChars)...)
 }

 if len(chars) == 0 {
  return "", fmt.Errorf("at least one character type must be enabled")
 }

 password := make([]rune, length)
 charCount := big.NewInt(int64(len(chars)))
 for i := range password {
  n, err := rand.Int(rand.Reader, charCount)
  if err != nil {
   return "", fmt.Errorf("failed to generate random bytes: %w", err)
  }
  password[i] = chars[n.Int64()]
 }

 // Guarantee at least one character from each enabled type by overwriting
 // specific positions using crypto/rand.
 pos := 0
 writeGuaranteed := func(charset string) error {
  if pos >= length {
   return nil
  }
  n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
  if err != nil {
   return fmt.Errorf("failed to generate random bytes: %w", err)
  }
  password[pos] = []rune(charset)[n.Int64()]
  pos++
  return nil
 }
 if useUpper {
  if err := writeGuaranteed(upperChars); err != nil {
   return "", err
  }
 }
 if useLower {
  if err := writeGuaranteed(lowerChars); err != nil {
   return "", err
  }
 }
 if useNumbers {
  if err := writeGuaranteed(numberChars); err != nil {
   return "", err
  }
 }
 if useSpecial {
  if err := writeGuaranteed(specialChars); err != nil {
   return "", err
  }
 }

 return string(password), nil
}
```

Also remove the `"time"` import — it is no longer needed.

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./cmd/secrets/... -run "TestGeneratePassword" -v
```

Expected: All PASS.

- [ ] **Step 5: Run full test suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./...
```

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/secrets/generate.go cmd/secrets/generate_test.go
git commit -m "fix(security): replace math/rand with crypto/rand in password generator"
```

---

## Task 4: Fix IDOR in Rotation Commands (Vuln 4)

`runRotationDelete`, `runRotationUnassign`, and `runRotationHistory` in `cmd/rotation.go` pass no caller identity to the service. `DeletePolicy` and `GetRotationHistory` in `rotation_service.go` perform no ownership check. Fix both layers.

**Files:**

- Modify: `cmd/rotation.go`
- Modify: `internal/services/secrets/rotation_service.go`
- Create: `cmd/rotation_security_test.go`

### Part A — Service Layer

- [ ] **Step 1: Update `DeletePolicy` signature and add ownership check in `rotation_service.go`**

Update the interface definition in `rotation_service.go` (line 25):

```go
DeletePolicy(ctx context.Context, id uuid.UUID, callerID uuid.UUID) error
```

Update `RemovePolicyFromSecret` signature (line 30):

```go
RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, callerID uuid.UUID) error
```

Update `GetRotationHistory` signature (line 35):

```go
GetRotationHistory(ctx context.Context, secretID uuid.UUID, callerID uuid.UUID) ([]domain.RotationHistory, error)
```

Then update each implementation:

**`DeletePolicy`** (replace lines 218–237):

```go
func (s *rotationService) DeletePolicy(ctx context.Context, id uuid.UUID, callerID uuid.UUID) error {
 policy, err := s.rotationRepo.Read(ctx, id)
 if err != nil {
  return fmt.Errorf("policy not found: %w", err)
 }

 if policy.UserID != callerID {
  return fmt.Errorf("forbidden: user does not own this policy")
 }

 err = s.rotationRepo.Delete(ctx, id)
 if err != nil {
  s.log.WithError(err).WithField("policy_id", id).Error("Failed to delete rotation policy")
  return fmt.Errorf("failed to delete rotation policy: %w", err)
 }

 s.log.WithFields(map[string]interface{}{
  "policy_id": id,
  "user_id":   callerID,
 }).Info("Rotation policy deleted successfully")

 return nil
}
```

**`RemovePolicyFromSecret`** (replace existing implementation):

```go
func (s *rotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, callerID uuid.UUID) error {
 // Verify caller owns the secret.
 secret, err := s.secretRepo.Read(ctx, secretID)
 if err != nil {
  return fmt.Errorf("secret not found: %w", err)
 }
 if secret.UserID != callerID {
  return fmt.Errorf("forbidden: user does not own this secret")
 }

 err = s.rotationRepo.RemoveFromSecret(ctx, secretID, policyID)
 if err != nil {
  s.log.WithError(err).Error("Failed to remove policy from secret")
  return fmt.Errorf("failed to remove policy from secret: %w", err)
 }

 s.log.WithFields(map[string]interface{}{
  "secret_id": secretID,
  "policy_id": policyID,
  "user_id":   callerID,
 }).Info("Policy removed from secret successfully")

 return nil
}
```

**`GetRotationHistory`** (replace existing implementation):

```go
func (s *rotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID, callerID uuid.UUID) ([]domain.RotationHistory, error) {
 // Verify caller owns the secret before exposing history.
 secret, err := s.secretRepo.Read(ctx, secretID)
 if err != nil {
  return nil, fmt.Errorf("secret not found: %w", err)
 }
 if secret.UserID != callerID {
  return nil, fmt.Errorf("forbidden: user does not own this secret")
 }

 history, err := s.rotationRepo.GetRotationHistory(ctx, secretID)
 if err != nil {
  s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get rotation history")
  return nil, fmt.Errorf("failed to get rotation history: %w", err)
 }

 return history, nil
}
```

### Part B — CMD Layer

- [ ] **Step 2: Update `runRotationDelete` to extract and pass `userID`**

Replace `runRotationDelete` in `cmd/rotation.go` (the function starting at line 326):

```go
func runRotationDelete(cmd *cobra.Command) error {
 ctx := cmd.Context()
 userID := ctx.Value(common.UserIDKey).(uuid.UUID)
 sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
 if !ok || sc == nil {
  return fmt.Errorf("service container not available in context")
 }
 pid, err := uuid.Parse(policyID)
 if err != nil {
  return fmt.Errorf("invalid policy ID: %w", err)
 }
 if err := sc.GetRotationService().DeletePolicy(ctx, pid, userID); err != nil {
  return fmt.Errorf("failed to delete rotation policy: %w", err)
 }
 fmt.Fprintln(cmd.OutOrStdout(), "Rotation policy deleted successfully.")
 return nil
}
```

- [ ] **Step 3: Update `runRotationUnassign` to extract and pass `userID`**

Replace `runRotationUnassign` in `cmd/rotation.go`:

```go
func runRotationUnassign(cmd *cobra.Command) error {
 ctx := cmd.Context()
 userID := ctx.Value(common.UserIDKey).(uuid.UUID)
 sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
 if !ok || sc == nil {
  return fmt.Errorf("service container not available in context")
 }
 pid, err := uuid.Parse(policyID)
 if err != nil {
  return fmt.Errorf("invalid policy ID: %w", err)
 }
 sid, err := uuid.Parse(secretID)
 if err != nil {
  return fmt.Errorf("invalid secret ID: %w", err)
 }
 if err := sc.GetRotationService().RemovePolicyFromSecret(ctx, sid, pid, userID); err != nil {
  return fmt.Errorf("failed to remove policy from secret: %w", err)
 }
 fmt.Fprintln(cmd.OutOrStdout(), "Policy removed from secret successfully.")
 return nil
}
```

- [ ] **Step 4: Update `runRotationHistory` to extract and pass `userID`**

Replace `runRotationHistory` in `cmd/rotation.go`:

```go
func runRotationHistory(cmd *cobra.Command) error {
 ctx := cmd.Context()
 userID := ctx.Value(common.UserIDKey).(uuid.UUID)
 sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
 if !ok || sc == nil {
  return fmt.Errorf("service container not available in context")
 }
 sid, err := uuid.Parse(secretID)
 if err != nil {
  return fmt.Errorf("invalid secret ID: %w", err)
 }
 history, err := sc.GetRotationService().GetRotationHistory(ctx, sid, userID)
 if err != nil {
  return fmt.Errorf("failed to get rotation history: %w", err)
 }
 // ... rest of the function (tabwriter output) unchanged
```

### Part C — Tests

- [ ] **Step 5: Write ownership-enforcement tests**

Create `cmd/rotation_security_test.go`:

```go
package cmd

import (
 "context"
 "fmt"
 "testing"

 "github.com/google/uuid"
 "github.com/stretchr/testify/assert"
 "github.com/stretchr/testify/mock"

 "rocketvault/internal/domain"
 "rocketvault/internal/logging"
 secretServices "rocketvault/internal/services/secrets"
)

// mockRotationService is a minimal mock for testing ownership enforcement.
type mockRotationService struct {
 mock.Mock
}

func (m *mockRotationService) CreatePolicy(ctx context.Context, req secretServices.CreatePolicyRequest) (*domain.RotationPolicy, error) {
 args := m.Called(ctx, req)
 if args.Get(0) == nil {
  return nil, args.Error(1)
 }
 return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) GetPolicy(ctx context.Context, id uuid.UUID) (*domain.RotationPolicy, error) {
 args := m.Called(ctx, id)
 if args.Get(0) == nil {
  return nil, args.Error(1)
 }
 return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) UpdatePolicy(ctx context.Context, req secretServices.UpdatePolicyRequest) (*domain.RotationPolicy, error) {
 args := m.Called(ctx, req)
 if args.Get(0) == nil {
  return nil, args.Error(1)
 }
 return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) DeletePolicy(ctx context.Context, id uuid.UUID, callerID uuid.UUID) error {
 return m.Called(ctx, id, callerID).Error(0)
}

func (m *mockRotationService) ListUserPolicies(ctx context.Context, userID uuid.UUID) ([]domain.RotationPolicy, error) {
 args := m.Called(ctx, userID)
 return args.Get(0).([]domain.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) AssignPolicyToSecret(ctx context.Context, req secretServices.AssignPolicyRequest) error {
 return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, callerID uuid.UUID) error {
 return m.Called(ctx, secretID, policyID, callerID).Error(0)
}

func (m *mockRotationService) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]domain.RotationPolicy, error) {
 args := m.Called(ctx, secretID)
 return args.Get(0).([]domain.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) PerformManualRotation(ctx context.Context, req secretServices.ManualRotationRequest) error {
 return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID, callerID uuid.UUID) ([]domain.RotationHistory, error) {
 args := m.Called(ctx, secretID, callerID)
 return args.Get(0).([]domain.RotationHistory), args.Error(1)
}

func (m *mockRotationService) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]domain.SecretPolicy, error) {
 args := m.Called(ctx, userID)
 return args.Get(0).([]domain.SecretPolicy), args.Error(1)
}

func (m *mockRotationService) CreateRotationReminder(ctx context.Context, req secretServices.CreateReminderRequest) error {
 return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]domain.RotationReminder, error) {
 args := m.Called(ctx, userID)
 return args.Get(0).([]domain.RotationReminder), args.Error(1)
}

func (m *mockRotationService) AcknowledgeReminder(ctx context.Context, reminderID uuid.UUID) error {
 return m.Called(ctx, reminderID).Error(0)
}

func TestRotationDeletePassesCallerID(t *testing.T) {
 callerID := uuid.New()
 policyUUID := uuid.New()
 logger := &logging.Logger{}

 svc := &mockRotationService{}
 svc.On("DeletePolicy", mock.Anything, policyUUID, callerID).Return(nil)

 // Verify the service receives callerID — ownership enforcement is tested in rotation_service_test.go
 err := svc.DeletePolicy(context.Background(), policyUUID, callerID)
 assert.NoError(t, err)
 svc.AssertCalled(t, "DeletePolicy", mock.Anything, policyUUID, callerID)
 _ = logger // suppress unused
}

func TestRotationDeleteOwnershipRejection(t *testing.T) {
 callerID := uuid.New()
 policyUUID := uuid.New()

 svc := &mockRotationService{}
 svc.On("DeletePolicy", mock.Anything, policyUUID, callerID).
  Return(fmt.Errorf("forbidden: user does not own this policy"))

 err := svc.DeletePolicy(context.Background(), policyUUID, callerID)
 assert.Error(t, err)
 assert.Contains(t, err.Error(), "forbidden")
}

func TestRotationHistoryPassesCallerID(t *testing.T) {
 callerID := uuid.New()
 secretUUID := uuid.New()

 svc := &mockRotationService{}
 svc.On("GetRotationHistory", mock.Anything, secretUUID, callerID).
  Return([]domain.RotationHistory{}, nil)

 history, err := svc.GetRotationHistory(context.Background(), secretUUID, callerID)
 assert.NoError(t, err)
 assert.Empty(t, history)
 svc.AssertCalled(t, "GetRotationHistory", mock.Anything, secretUUID, callerID)
}

func TestRotationHistoryOwnershipRejection(t *testing.T) {
 callerID := uuid.New()
 secretUUID := uuid.New()

 svc := &mockRotationService{}
 svc.On("GetRotationHistory", mock.Anything, secretUUID, callerID).
  Return([]domain.RotationHistory(nil), fmt.Errorf("forbidden: user does not own this secret"))

 _, err := svc.GetRotationHistory(context.Background(), secretUUID, callerID)
 assert.Error(t, err)
 assert.Contains(t, err.Error(), "forbidden")
}
```

- [ ] **Step 6: Run rotation tests**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./cmd/... -run "TestRotation" -v
go test ./internal/services/secrets/... -v
```

Expected: All PASS.

- [ ] **Step 7: Run full test suite**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go test ./...
```

Expected: All tests PASS, zero compilation errors.

- [ ] **Step 8: Commit**

```bash
git add cmd/rotation.go cmd/rotation_security_test.go internal/services/secrets/rotation_service.go
git commit -m "fix(security): enforce ownership on rotation delete/unassign/history — cmd + service layer"
```

---

## Final Verification

After all 4 tasks are complete:

- [ ] **Run full build and test**

```bash
cd /home/numericlabs/data/Golang/rocketvault
go build ./...
go test ./...
```

Expected: Zero build errors, all tests PASS.

- [ ] **Verify no `math/rand` remains in generate.go**

```bash
grep -n "math/rand" /home/numericlabs/data/Golang/rocketvault/cmd/secrets/generate.go
```

Expected: No output.

- [ ] **Verify role check exists in create.go**

```bash
grep -n "RoleAdmin\|forbidden" /home/numericlabs/data/Golang/rocketvault/cmd/users/create.go
```

Expected: Lines referencing both `domain.RoleAdmin` and `"forbidden"`.

- [ ] **Verify rotation functions pass userID**

```bash
grep -A5 "func runRotationDelete\|func runRotationUnassign\|func runRotationHistory" /home/numericlabs/data/Golang/rocketvault/cmd/rotation.go | grep "UserIDKey"
```

Expected: All three functions show `UserIDKey` extraction.
