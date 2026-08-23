# Multi-Role: CLI Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rocketvault users create --new-role admin --new-role
secrets_manager` and the equivalent `update` — `--new-role` becomes a
repeatable flag on both commands.

**Architecture:** `--new-role` changes from `Flags().String(...)` to
`Flags().StringArray(...)` on both `create.go` and `update.go`.
`update.go`'s local `validRoles` map is deleted — `UserService` (Plan 05)
now owns that validation, so the CLI just forwards whatever was typed and
surfaces the service's error.

**Tech Stack:** Go, Cobra.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Note on the spec

The approved design spec's Section 5 says the flag is `--role`. The actual
flag in this codebase, on both `create.go` and `update.go`, has always been
`--new-role` — confirmed directly against the source. This plan uses the
real flag name, `--new-role`; the spec has a naming inaccuracy that doesn't
change the design intent (repeatable flag), so it isn't worth a spec
amendment, just noting here for whoever reads both documents side by side.

## Global Constraints

- Depends on Plan 03 (`common.HasAnyRole`), Plan 05
  (`UserService.CreateUser`/`UpdateUser` now take `Roles`/`CallerRoles` and
  validate internally).
- `cmd/users/admin.go` needs no change — confirmed it hardcodes
  `model.RoleAdmin` with no `--role`/`--new-role` flag at all.

---

### Task 1: `cmd/users/create.go`

**Files:**
- Modify: `cmd/users/create.go`
- Test: `cmd/users/create_test.go`

**Interfaces:**
- Consumes: `userService.CreateUserRequest.Roles`/`CallerRoles` from Plan 05.

- [ ] **Step 1: Write the failing test**

Add to `cmd/users/create_test.go`, following the existing
`TestCreateUserRequiresAdminRole`'s pattern (inline `*cobra.Command{RunE:
createCmd.RunE}`, `newTestContextWithRole` helper):

```go
func TestCreateUserCommand_MultipleRoles(t *testing.T) {
	viper.Reset()
	tc := newTestContextWithRole(t, model.RoleAdmin)

	cmd := &cobra.Command{
		Use:  "create",
		RunE: createCmd.RunE,
	}
	cmd.Flags().String("new-username", "", "")
	cmd.Flags().String("new-password", "", "")
	cmd.Flags().StringArray("new-role", []string{}, "")
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{
		"--new-username=newuser",
		"--new-password=pw12345678",
		"--new-role=admin",
		"--new-role=secrets_manager",
	})

	tc.MockUserService.On("CreateUser", mock.Anything, mock.MatchedBy(func(req userService.CreateUserRequest) bool {
		return assert.ObjectsAreEqualValues([]string{"admin", "secrets_manager"}, req.Roles)
	})).Return(&userService.CreateUserResult{Username: "newuser", Roles: []string{"admin", "secrets_manager"}}, nil)

	err := cmd.Execute()
	require.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}
```

Check the mock's exact method name/signature for `CreateUser` in this test
file's existing setup before writing the `.On("CreateUser", ...)` call —
match whatever's already there.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/users/... -run TestCreateUserCommand_MultipleRoles -v`
Expected: FAIL — compile error (flag is still `Flags().String`, request
field is still `Role string`)

- [ ] **Step 3: Change the flag and `RunE`**

Flag declaration (was `createCmd.Flags().String("new-role", "", ...)`):

```go
	createCmd.Flags().StringArray("new-role", []string{}, "Role(s) for the new user (repeatable, e.g. --new-role admin --new-role secrets_manager)")
```

`RunE` (was reading `role, _ := cmd.Flags().GetString("new-role")` and
checking `role == ""`):

```go
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	if !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
		return fmt.Errorf("forbidden: only admin users can create new accounts")
	}

	username, _ := cmd.Flags().GetString("new-username")
	password, _ := cmd.Flags().GetString("new-password")
	roles, _ := cmd.Flags().GetStringArray("new-role")

	if username == "" || password == "" || len(roles) == 0 {
		return fmt.Errorf("username, password, and at least one role are required")
	}

	userSvc := serviceContainer.GetUserService()
	result, err := userSvc.CreateUser(ctx, userService.CreateUserRequest{
		Username:    username,
		Password:    password,
		Roles:       roles,
		CallerRoles: claims.Roles,
	})
```

Keep every other line of the surrounding function (context/service-container
lookups, TOTP-printing/response output after the `CreateUser` call)
unchanged — this step only touches the admin check, flag reads, and the
request literal.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/users/... -run TestCreateUserCommand_MultipleRoles -v`
Expected: PASS

- [ ] **Step 5: Fix the existing `TestCreateUserRequiresAdminRole` and any
      other pre-existing test in this file**

Every inline `cmd.Flags().String("new-role", "", "")` in this file's
existing tests must become `cmd.Flags().StringArray("new-role", []string{}, "")`,
and every `"--new-role=user"`-style single arg stays valid syntax (Cobra's
`StringArray` accepts repeated single-value flags fine) — no other test
logic should need to change.

Run: `go test ./cmd/users/... -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/users/create.go cmd/users/create_test.go
git commit -m "feat(cli): --new-role is repeatable on 'users create'"
```

---

### Task 2: `cmd/users/update.go`

**Files:**
- Modify: `cmd/users/update.go`
- Test: `cmd/users/update_test.go`

**Interfaces:**
- Consumes: `userService.UpdateUserRequest.Roles`/`CallerRoles` from Plan 05.

- [ ] **Step 1: Write the failing test**

Add to `cmd/users/update_test.go`, following its existing
`newUpdateTestContextWithRole` helper pattern:

```go
func TestUpdateUserCommand_MultipleRoles_AdminAllowed(t *testing.T) {
	viper.Reset()
	targetID := uuid.New()
	tc := newUpdateTestContextWithRole(t, uuid.New(), model.RoleAdmin)

	cmd := &cobra.Command{
		Use:  "update",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("new-username", "", "")
	cmd.Flags().String("new-password", "", "")
	cmd.Flags().StringArray("new-role", []string{}, "")
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{targetID.String(), "--new-role=secrets_manager", "--new-role=crypto_manager"})

	tc.MockUserService.On("UpdateUser", mock.Anything, mock.MatchedBy(func(req userService.UpdateUserRequest) bool {
		return assert.ObjectsAreEqualValues([]string{"secrets_manager", "crypto_manager"}, req.Roles)
	})).Return(nil)

	err := cmd.Execute()
	require.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/users/... -run TestUpdateUserCommand_MultipleRoles_AdminAllowed -v`
Expected: FAIL — compile error

- [ ] **Step 3: Change the flag, delete the local `validRoles` map, update `RunE`**

Flag declaration (was `updateCmd.Flags().String("new-role", "", ...)` at
line 174):

```go
	updateCmd.Flags().StringArray("new-role", []string{}, "New role(s) for the user (repeatable, e.g. --new-role admin --new-role secrets_manager)")
```

Delete the entire `validRoles := map[string]bool{...}` block (lines 101-114)
and the `if newRole != "" && !validRoles[newRole] { ... }` check that follows
it — `UserService.UpdateUser` (Plan 05) now owns this validation.

Replace the "only admins may change roles" gate (was `if newRole != "" &&
claims.Role != model.RoleAdmin`) and the request-construction block (was
building a single `rolePtr *string`):

```go
	roles, _ := cmd.Flags().GetStringArray("new-role")

	if len(roles) > 0 && !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
		logger := serviceContainer.GetLogger()
		logger.LogAuditError(claims.UserID.String(), "update_user", "failed", "forbidden: only admins can change roles", nil)
		return fmt.Errorf("forbidden: only admins can change roles")
	}

	var usernamePtr, passwordPtr *string
	if newUsername != "" {
		usernamePtr = &newUsername
	}
	if newPassword != "" {
		passwordPtr = &newPassword
	}

	var rolesArg []string
	if len(roles) > 0 {
		rolesArg = roles
	}

	if err := userSvc.UpdateUser(ctx, userService.UpdateUserRequest{
		UserID:      id,
		CallerID:    claims.UserID,
		CallerRoles: claims.Roles,
		Username:    usernamePtr,
		Password:    passwordPtr,
		Roles:       rolesArg,
	}); err != nil {
```

Also apply the same "own-account-or-admin" gate change (line 77) elsewhere
in this file's `RunE`:

```go
	if claims.UserID != id && !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/users/... -run TestUpdateUserCommand_MultipleRoles_AdminAllowed -v`
Expected: PASS

- [ ] **Step 5: Fix the existing `TestUpdateUserRoleEnforcement` and run the full suite**

The existing table-driven test's `"invalid role substring bypass blocked"`
and `"invalid role manager substring blocked"` cases assert on this file's
own (now-deleted) `validRoles` map behavior — since that validation moved to
`UserService`, and this test's mock `UserService.UpdateUser` is never called
for genuinely-invalid input in the CLI's own layer anymore... reconsider:
these cases test that garbage role strings (`"min"`, `"_manager"`) never
even reach the service call, which is no longer this file's job. Move
these two specific cases out of this file's test and into
`internal/services/users/user_service_test.go` instead (Plan 05 already
covers this territory with `TestUpdateUser_InvalidRoleInList_Rejected` — if
that test doesn't already include a substring-bypass case like `"min"`,
add one there, not here). Update this file's flag declarations
(`cmd.Flags().String("new-role", "", "")` → `StringArray`) in the two
remaining legitimate cases (self-promotion, other-user-role-change) and
delete the two moved cases from this file.

Run: `go test ./cmd/users/... -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/users/update.go cmd/users/update_test.go internal/services/users/user_service_test.go
git commit -m "feat(cli): --new-role is repeatable on 'users update', delete duplicated role-validity map"
```

---

### Task 3: End-to-end CLI verification

**Files:**
- No new source files — this task is a manual/scripted verification pass,
  not new test code.

**Interfaces:**
- Consumes: everything from Tasks 1-2, plus the full stack from Plans 01-06.

- [ ] **Step 1: Full package build and vet**

Run: `go build ./... && go vet ./...`
Expected: clean. This is the first point in the plan series where the CLI
and API and service layers are all simultaneously updated — a real build
failure here means an interface mismatch between plans that unit tests
within a single package wouldn't have caught.

- [ ] **Step 2: Manual smoke test against a real local instance**

```bash
go build -o rocketvault-test .
export RV_MASTER_KEY=$(openssl rand -base64 32)
export RV_BOOTSTRAP_TOKEN=$(openssl rand -base64 32)
# ... use whatever this repo's existing local dev config setup is
# (.rocketvault.yaml.example) to get a scratch instance running, per
# CLAUDE.md's "Development" section.
./rocketvault-test users admin --admin-username=admin --admin-password=Testpass123! --bootstrap-token="$RV_BOOTSTRAP_TOKEN"
./rocketvault-test users login --username admin --password Testpass123! --totp-code <code-from-authenticator>
./rocketvault-test users create --new-username=multi --new-password=Testpass123! --new-role=secrets_manager --new-role=crypto_manager
./rocketvault-test users get multi
```

Expected: the `get` output shows both roles. Clean up the scratch instance
and binary afterward (`rm rocketvault-test`, remove the scratch DB file) —
do not leave test artifacts in the repo.

- [ ] **Step 3: No commit for this task**

This task is verification only — nothing to commit. If Step 1 or Step 2
surfaces a bug, fix it as part of whichever earlier task's file it belongs
to and amend that task's commit (or add a small fix-up commit referencing
which task it corrects), not a new unrelated commit here.
