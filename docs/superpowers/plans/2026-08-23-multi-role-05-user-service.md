# Multi-Role: UserService Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `UserService.CreateUser`/`UpdateUser` accept `Roles []string`,
validate every entry against one canonical allowlist (ending the current
four-way-duplicated `validRoles` list), and re-verify the self-promotion
guard against list-add semantics. `CreateUser` gains role validation it
currently lacks entirely.

**Architecture:** One new canonical `model.IsValidRole`/`model.ValidRoles`
replaces four independent copies of the same list (`user_service.go`,
`api/users.go` ×2, `cmd/users/update.go`). `RoleServiceAccount` is
deliberately excluded from the canonical list — service accounts are OAuth2
clients, not `users` table rows (confirmed: `model.OAuth2Client` has no role
field at all), so a human user row should never legitimately hold
`role=service_account`. The current service-layer map includes it; that's a
latent bug this plan fixes, not a feature this plan removes.

**Tech Stack:** Go.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- Depends on Plan 02 (`model.User.Roles`), Plan 03 (not directly used here,
  but this plan's canonical-allowlist pattern is the same "one source of
  truth" principle Plan 03 established for role *checking*, applied here to
  role *validity*).
- Self-promotion guard: `req.CallerRoles` must include `admin` for any role
  change to be permitted — this is unchanged in spirit from today's
  `req.CallerRole != model.RoleAdmin`, just re-expressed as
  `!common.HasAnyRole(req.CallerRoles, model.RoleAdmin)`.
- `UpdateUserRequest.CallerID` is currently defined but never read anywhere
  in `UpdateUser` (confirmed dead field) — leave it as-is, do not remove it
  in this plan; removing dead fields is out of scope here.

---

### Task 1: Canonical role allowlist + `CreateUser`

**Files:**
- Modify: `model/user.go` (add `ValidRoles`/`IsValidRole` near the existing
  role constants at lines 36-44)
- Modify: `internal/services/users/user_service.go` (`CreateUserRequest`,
  `CreateUser`)
- Test: `internal/services/users/user_service_test.go`

**Interfaces:**
- Produces:
  - `model.ValidRoles []string` = `{RoleAdmin, RoleSecretsManager,
    RoleCryptoManager, RoleCertificateManager, RoleUser}`
  - `model.IsValidRole(role string) bool`
  - `CreateUserRequest.Roles []string` (was `Role string`)
  - `CreateUserRequest.CallerRoles []string` (was `CallerRole string`)
  - `CreateUserResult.Roles []string` (was `Role string`)

- [ ] **Step 1: Write the failing test**

Add to `internal/services/users/user_service_test.go` (match its existing
`mockUserRepository`/`newService` pattern):

```go
func TestCreateUser_AllValidRoles_Accepted(t *testing.T) {
	t.Parallel()
	for _, role := range model.ValidRoles {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			repo := &mockUserRepository{}
			pw := &mockPasswordService{}
			totpSvc := &mockTOTPService{}
			svc := newService(repo, pw, totpSvc)

			pw.On("HashPassword", "pw12345678").Return("hashed", nil)
			totpSvc.On("GenerateSecret", "PasswordManager", "newuser").Return(fakeTOTPKey{}, nil)
			repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
				return len(u.Roles) == 1 && u.Roles[0] == role
			})).Return(nil)

			req := CreateUserRequest{
				Username:    "newuser",
				Password:    "pw12345678",
				Roles:       []string{role},
				CallerRoles: []string{model.RoleAdmin},
			}
			result, err := svc.CreateUser(context.Background(), req)
			require.NoError(t, err)
			assert.ElementsMatch(t, []string{role}, result.Roles)
		})
	}
}

func TestCreateUser_InvalidRole_Rejected(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := CreateUserRequest{
		Username:    "newuser",
		Password:    "pw12345678",
		Roles:       []string{"not_a_real_role"},
		CallerRoles: []string{model.RoleAdmin},
	}
	_, err := svc.CreateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
	repo.AssertNotCalled(t, "Create")
}

func TestCreateUser_MultipleRoles_AllStored(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	pw.On("HashPassword", "pw12345678").Return("hashed", nil)
	totpSvc.On("GenerateSecret", "PasswordManager", "newuser").Return(fakeTOTPKey{}, nil)
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return assert.ObjectsAreEqualValues([]string{"secrets_manager", "crypto_manager"}, u.Roles) ||
			assert.ObjectsAreEqualValues([]string{"crypto_manager", "secrets_manager"}, u.Roles)
	})).Return(nil)

	req := CreateUserRequest{
		Username:    "newuser",
		Password:    "pw12345678",
		Roles:       []string{"secrets_manager", "crypto_manager"},
		CallerRoles: []string{model.RoleAdmin},
	}
	result, err := svc.CreateUser(context.Background(), req)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"secrets_manager", "crypto_manager"}, result.Roles)
}
```

Check the existing test file for how `totpService.GenerateSecret`'s return
value (`fakeTOTPKey{}` above is illustrative) is actually mocked today — use
whatever real fake/mock type the file already defines instead.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/users/... -run TestCreateUser_AllValidRoles_Accepted -v`
Expected: FAIL — compile error, `CreateUserRequest.Roles`/`CallerRoles`
undefined

- [ ] **Step 3: Add the canonical allowlist to `model`**

In `model/user.go`, immediately after the existing role constants block:

```go
// ValidRoles is every role assignable to a human user account via
// CreateUser/UpdateUser. RoleServiceAccount is deliberately excluded --
// service accounts are OAuth2 clients (model.OAuth2Client), not rows in the
// users table, and never go through this validation path.
var ValidRoles = []string{RoleAdmin, RoleSecretsManager, RoleCryptoManager, RoleCertificateManager, RoleUser}

// IsValidRole reports whether role is one of ValidRoles.
func IsValidRole(role string) bool {
	for _, r := range ValidRoles {
		if r == role {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Update `CreateUserRequest`/`CreateUserResult` and `CreateUser`**

In `internal/services/users/user_service.go`:

```go
type CreateUserRequest struct {
	Username    string
	Password    string
	Roles       []string
	CallerRoles []string // Must include model.RoleAdmin.
}

type CreateUserResult struct {
	UserID     uuid.UUID
	Username   string
	Roles      []string
	TOTPSecret string
	CreatedAt  time.Time
}
```

```go
func (s *userService) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResult, error) {
	if !common.HasAnyRole(req.CallerRoles, model.RoleAdmin) {
		return nil, fmt.Errorf("forbidden: caller must have admin role to create users")
	}

	if len(req.Roles) == 0 {
		return nil, fmt.Errorf("invalid role: at least one role is required")
	}
	seen := map[string]bool{}
	var roles []string
	for _, r := range req.Roles {
		if r == "" || seen[r] {
			continue
		}
		if !model.IsValidRole(r) {
			return nil, fmt.Errorf("invalid role: %s", r)
		}
		seen[r] = true
		roles = append(roles, r)
	}

	logrus.WithFields(logrus.Fields{
		"username": req.Username,
		"roles":    roles,
	}).Info("Creating new user")

	hashedPassword, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		s.logger.LogAuditError("", "create_user", "failed", "Failed to hash password", err)
		return nil, fmt.Errorf("failed to prepare user: %w", err)
	}

	totpKey, err := s.totpService.GenerateSecret("PasswordManager", req.Username)
	if err != nil {
		s.logger.LogAuditError("", "create_user", "failed", "Failed to generate TOTP secret", err)
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	userID := uuid.New()
	user := &model.User{
		ID:           userID,
		Username:     req.Username,
		PasswordHash: hashedPassword,
		TOTPSecret:   totpKey.Secret(),
		Roles:        roles,
		CreatedAt:    time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.LogAuditError(userID.String(), "create_user", "failed", "Failed to create user", err)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "create_user", "success", fmt.Sprintf("User created: %s", req.Username))

	return &CreateUserResult{
		UserID:     userID,
		Username:   req.Username,
		Roles:      roles,
		TOTPSecret: totpKey.URL(),
		CreatedAt:  user.CreatedAt,
	}, nil
}
```

Add `"rocketvault/common"` to this file's imports if not already present
(for `common.HasAnyRole`).

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/services/users/... -run "TestCreateUser_AllValidRoles_Accepted|TestCreateUser_InvalidRole_Rejected|TestCreateUser_MultipleRoles_AllStored" -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add model/user.go internal/services/users/user_service.go internal/services/users/user_service_test.go
git commit -m "feat(users): validate roles on CreateUser (was previously unvalidated) using a shared allowlist"
```

---

### Task 2: `UpdateUser` — self-promotion guard + role replace

**Files:**
- Modify: `internal/services/users/user_service.go` (`UpdateUserRequest`,
  `UpdateUser`)
- Test: `internal/services/users/user_service_test.go`

**Interfaces:**
- Consumes: `model.IsValidRole`, `common.HasAnyRole` from Task 1.
- Produces: `UpdateUserRequest.Roles []string` (was `Role *string`),
  `UpdateUserRequest.CallerRoles []string` (was `CallerRole string`).

- [ ] **Step 1: Write the failing test**

Add to `internal/services/users/user_service_test.go`:

```go
func TestUpdateUser_SelfPromotion_Blocked(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleUser},
		Roles:       []string{model.RoleUser, model.RoleAdmin}, // self-promotion attempt
	}

	err := svc.UpdateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	repo.AssertNotCalled(t, "Update")
}

func TestUpdateUser_AdminCanGrantMultipleRoles(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	userID := uuid.New()
	existing := &model.User{ID: userID, Username: "alice", Roles: []string{model.RoleUser}}
	repo.On("Read", mock.Anything, userID).Return(existing, nil)
	repo.On("Update", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return assert.ObjectsAreEqualValues([]string{"secrets_manager", "crypto_manager"}, u.Roles)
	})).Return(nil)

	req := UpdateUserRequest{
		UserID:      userID,
		CallerRoles: []string{model.RoleAdmin},
		Roles:       []string{model.RoleSecretsManager, model.RoleCryptoManager},
	}
	err := svc.UpdateUser(context.Background(), req)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestUpdateUser_InvalidRoleInList_Rejected(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	req := UpdateUserRequest{
		UserID:      uuid.New(),
		CallerRoles: []string{model.RoleAdmin},
		Roles:       []string{model.RoleAdmin, "not_a_real_role"},
	}
	err := svc.UpdateUser(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
	repo.AssertNotCalled(t, "Update")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/users/... -run "TestUpdateUser_SelfPromotion_Blocked|TestUpdateUser_AdminCanGrantMultipleRoles|TestUpdateUser_InvalidRoleInList_Rejected" -v`
Expected: FAIL — compile error, `UpdateUserRequest.Roles`/`CallerRoles`
undefined

- [ ] **Step 3: Update `UpdateUserRequest` and `UpdateUser`**

```go
type UpdateUserRequest struct {
	UserID      uuid.UUID
	CallerID    uuid.UUID // Unused today (pre-existing dead field) -- left as-is.
	CallerRoles []string  // Must include model.RoleAdmin for any Roles change.
	Username    *string
	Password    *string
	Roles       []string // nil means no change; non-nil (even empty) is a validation error.
}
```

```go
func (s *userService) UpdateUser(ctx context.Context, req UpdateUserRequest) error {
	// Only admins may change any user's roles -- including their own. This
	// is the self-promotion guard: a non-admin including "admin" (or any
	// role) in req.Roles is rejected here before roles are ever validated
	// or written, regardless of which roles they already hold.
	if req.Roles != nil && !common.HasAnyRole(req.CallerRoles, model.RoleAdmin) {
		return fmt.Errorf("forbidden: only admins can change roles")
	}

	var newRoles []string
	if req.Roles != nil {
		if len(req.Roles) == 0 {
			return fmt.Errorf("invalid role: at least one role is required")
		}
		seen := map[string]bool{}
		for _, r := range req.Roles {
			if r == "" || seen[r] {
				continue
			}
			if !model.IsValidRole(r) {
				return fmt.Errorf("invalid role: %s", r)
			}
			seen[r] = true
			newRoles = append(newRoles, r)
		}
	}

	logrus.WithField("user_id", req.UserID.String()).Info("Updating user")

	existingUser, err := s.userRepo.Read(ctx, req.UserID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_user", "failed", "User not found", err)
		return fmt.Errorf("user not found: %w", err)
	}

	updatedUser := *existingUser

	if req.Username != nil {
		updatedUser.Username = *req.Username
	}

	if req.Password != nil {
		hashedPassword, err := s.passwordService.HashPassword(*req.Password)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "update_user", "failed", "Failed to hash password", err)
			return fmt.Errorf("failed to hash password: %w", err)
		}
		updatedUser.PasswordHash = hashedPassword
	}

	if req.Roles != nil {
		updatedUser.Roles = newRoles
	}

	if err := s.userRepo.Update(ctx, &updatedUser); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_user", "failed", "Failed to update user", err)
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "update_user", "success", fmt.Sprintf("User updated: %s", updatedUser.Username))
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/users/... -run "TestUpdateUser_SelfPromotion_Blocked|TestUpdateUser_AdminCanGrantMultipleRoles|TestUpdateUser_InvalidRoleInList_Rejected" -v`
Expected: PASS

- [ ] **Step 5: Run the full package test suite and fix ripple breaks**

Run: `go test ./internal/services/users/... -v`

Every pre-existing test in this file that builds a `model.User{Role: "x"}`,
`CreateUserRequest{Role: "x", CallerRole: "y"}`, or
`UpdateUserRequest{Role: &x, CallerRole: "y"}` literal is now a compile
error — mechanically convert each: `Role: "x"` → `Roles: []string{"x"}`,
`CallerRole: "y"` → `CallerRoles: []string{"y"}`, `Role: &x` → `Roles:
[]string{x}` (dropping the pointer, since the new field is a slice where
`nil` already means "no change" — no separate pointer wrapper needed).
Expected after fixes: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/services/users/user_service.go internal/services/users/user_service_test.go
git commit -m "feat(users): UpdateUser accepts and validates multiple roles, self-promotion guard re-verified"
```
