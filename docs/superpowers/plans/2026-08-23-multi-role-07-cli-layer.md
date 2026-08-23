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
- Modify: `cmd/testutils/test_utils.go` (two stale `Role:` literals — added
  during this plan's pre-flight scan: this shared test-fixture helper is
  imported by essentially every `cmd/*` package's tests, including this
  task's own `cmd/users/create_test.go`, and is broken since Plan 02/04
  renamed `model.Claims.Role`/`model.User.Role`. No plan in this series
  names it. Left unfixed, this task's own Step 2 could never distinguish
  "the CLI change isn't done yet" from "the shared test helper doesn't
  compile" — fix it first, before touching `create.go`.)
- Modify: `cmd/users/create.go`
- Test: `cmd/users/create_test.go`

**Interfaces:**
- Consumes: `userService.CreateUserRequest.Roles`/`CallerRoles` from Plan 05.

- [ ] **Step 0: Fix `cmd/testutils/test_utils.go`**

Two literals, both simple field renames with the value wrapped in a
single-element slice:

```go
	testClaims := &model.Claims{
		UserID:   testUserID,
		Username: "testuser",
		Roles:    []string{model.RoleAdmin},
	}
```

and

```go
func CreateTestUser() *model.User {
	return &model.User{
		ID:           uuid.New(),
		Username:     "testuser",
		PasswordHash: "$2a$10$test.hash",
		Roles:        []string{model.RoleUser},
		TOTPSecret:   "testsecret",
	}
}
```

No other change to this file. Run `go build ./cmd/testutils/...` to confirm
it compiles before moving to Step 1.

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
git add cmd/testutils/test_utils.go cmd/users/create.go cmd/users/create_test.go
git commit -m "feat(cli): --new-role is repeatable on 'users create'

Also fixes cmd/testutils/test_utils.go's two stale Role literals, unowned
by any plan and blocking this task's own tests from compiling."
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

### Task 3: Remaining `cmd/users` gates + response formatting + verification

**Files:**
- Modify: `cmd/users/delete.go:68`, `cmd/users/get.go:70,92`,
  `cmd/users/list.go:64,88`, `cmd/users/admin.go:82-83` — added during Task
  1's own build-verification: these five files reference the pre-rename
  `claims.Role`/`user.Role`/`CreateUserRequest.Role`/`CallerRole` fields
  and are named in NO plan's file list (not Task 1, not Task 2, not Plan
  08, not Plan 09 — confirmed by checking both plans' file lists directly).
  Left unfixed, this task's own verification step could never distinguish
  "Tasks 1-2 are done" from "the rest of `cmd/users` was never touched" —
  fix them here, in the same package Tasks 1-2 already own.
- Test: `cmd/users/admin_test.go`, `cmd/users/list_test.go`,
  `cmd/users/users_cmd_test.go`, `cmd/users/login_password_test.go`,
  `cmd/users/service_test.go`, `cmd/users/cmd_rune_test.go` (also found
  during Task 1's build-verification — same gap, test-file side; ALL still
  reference the pre-rename fields, and `cmd_rune_test.go`'s
  `newCreateTestCmd()` helper additionally registers `new-role` as
  `Flags().String(...)` instead of `StringArray`, which must also change or
  it silently diverges from the real `createCmd` flag definition once this
  file compiles again)

**NOT in this task's scope — do not touch:**
`cmd/users/login.go`'s `performPasswordLogin` builds a
`common.SessionCache{..., Role: result.Role, ...}` literal. `SessionCache`
itself is not renamed to `Roles []string` until Plan 10 Task 1 — fixing
`login.go` here would require a field that doesn't exist yet. This has been
flagged as a gap in Plan 10's own file list (a sibling correction alongside
this one); leave `login.go` exactly as-is.

**Interfaces:**
- Consumes: `common.HasAnyRole`, `userService.CreateUserRequest.Roles`/
  `CallerRoles` (Plan 05), `model.Claims.Roles` (Plan 04), `model.User.Roles`
  (Plan 02).

- [ ] **Step 1: Write the failing test**

Pick one representative case per file — e.g. extend or add a test in
`cmd/users/list_test.go` asserting a caller with `Roles: []string{"user",
"admin"}` (admin present but not sole role) can list users, and one in
`cmd/users/service_test.go`/`admin_test.go` covering the bootstrap admin
creation path. Match each file's existing test conventions.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/users/... -v 2>&1 | head -80`
Expected: FAIL — compile errors across the whole package (this file group
has been broken since Plan 02/04 landed; that's the starting state this
task fixes).

- [ ] **Step 3: Fix the two remaining strict-equality gates**

`delete.go:68` and `get.go:70` share the identical shape:

```go
	if claims.UserID != id && !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
```

`list.go:64`:

```go
	if !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
```

- [ ] **Step 4: Fix the two display-formatting sites**

`list.go`'s table-row loop and `get.go`'s single-row output both print a
`Role` column sourced from `u.Role`/`user.Role` (now `Roles []string`).
Render as a comma-joined string — add `"strings"` to each file's imports if
not already present:

```go
			rows[i] = []string{
				u.ID.String(),
				u.Username,
				strings.Join(u.Roles, ", "),
				u.CreatedAt.Format(time.RFC3339),
			}
```

(and the equivalent single-row change in `get.go`, keeping the header label
`"Role"` as-is — this is a column header string, not a field name, and
changing it is optional polish, not required for correctness).

- [ ] **Step 5: Fix `admin.go`'s bootstrap request literal**

```go
		result, err := userSvc.CreateUser(ctx, userService.CreateUserRequest{
			Username:    username,
			Password:    password,
			Roles:       []string{model.RoleAdmin},
			CallerRoles: []string{model.RoleAdmin}, // Bootstrap is pre-authorised.
		})
```

- [ ] **Step 6: Fix the six test files' remaining literals**

Every `Role:`/`.Role`/`CallerRole:` reference in `admin_test.go`,
`list_test.go`, `users_cmd_test.go`, `login_password_test.go`,
`service_test.go`, `cmd_rune_test.go` is a mechanical rename to the
`Roles`/`CallerRoles []string` shape, same pattern used throughout this
plan series (wrap single values in a one-element slice, preserve exact
values, no logic changes). Additionally, in `cmd_rune_test.go`, change
`newCreateTestCmd()`'s `Flags().String("new-role", "", "")` to
`Flags().StringArray("new-role", []string{}, "")` so it matches the real
`createCmd` definition Task 1 already changed — otherwise this helper
silently drifts from what it's meant to be testing against.

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./cmd/users/... -v`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd/users/delete.go cmd/users/get.go cmd/users/list.go cmd/users/admin.go cmd/users/admin_test.go cmd/users/list_test.go cmd/users/users_cmd_test.go cmd/users/login_password_test.go cmd/users/service_test.go cmd/users/cmd_rune_test.go
git commit -m "fix(cli): migrate remaining cmd/users gates and response formatting to Roles []string"
```

- [ ] **Step 9: Full package build and vet**

Run: `go build ./... 2>&1`

Expected: **NOT clean** — Plan 08 (`cmd/keys`, `cmd/certificates`,
`cmd/secrets`, and 4 more strict-equality gates) and Plan 09
(`api/oauth2.go`/`jwks.go`/`access_policies.go`/`audit.go`/
`role_assignments.go`, `internal/services/authorization/vault_authz.go`,
`internal/middleware/middleware.go`, `cmd/vaults`/`vault-access`/
`vault-webhook` authz) haven't run yet, so those packages still fail to
compile — expected, not a regression this task introduced. Cross-reference
any error against Plan 08's and Plan 09's file lists; if something breaks
in a file neither plan names, stop and flag it — that would be a real gap,
same as several the controller already found and fixed earlier in this
series.

Then run, scoped to what this plan now fully owns: `go build
./cmd/users/... && go vet ./cmd/users/... && go test ./cmd/users/... -v`
— this MUST be fully clean (the one known exception is `login.go`, whose
fix is deliberately deferred to Plan 10 per this task's own scope note
above — its package still compiles fine since `common.SessionCache.Role`
itself hasn't been renamed yet, only its future rename is deferred).

- [ ] **Step 10: Manual smoke test — deferred, not runnable yet**

Corrected during this plan's pre-flight scan: `go build -o rocketvault-test .`
builds the WHOLE binary, which transitively imports every `cmd/*`
subpackage — including `cmd/keys`, `cmd/certificates`, `cmd/secrets`,
`cmd/master_key.go`, `cmd/backup.go`, `cmd/audit`, `cmd/vaults`,
`cmd/vault-access`, `cmd/vault-webhook`, all still broken (Plan 08/09
territory, not yet run). A real running-binary smoke test of
`--new-role`'s repeatable behavior is genuinely not possible until Plan 09
completes — do NOT attempt it, and do not treat a failed `go build -o
rocketvault-test .` as a bug in this task's own work.

Plan 10's own Task 3 ("End-to-end multi-role verification") already
performs this exact smoke test and more (creates a multi-role user via
`--new-role` repeated flags, then exercises secrets/keys/certificates
operations gated by different roles from that same account) once the whole
binary can build. This task's verification is scoped instead to what's
actually achievable now: confirm via `go doc` or direct inspection that
`createCmd`/`updateCmd`'s flag is genuinely registered as `StringArray`
(not `String`) on the real command objects, not just in test scaffolding:

```bash
grep -n 'Flags().StringArray("new-role"' cmd/users/create.go cmd/users/update.go
```

Expected: one match in each file. This is a cheap, real confirmation that
the actual Cobra command definition (not just a test's inline flag
registration) was updated — the two are easy to conflate since the tests in
Tasks 1/2 register their own inline `StringArray` flags on a throwaway
`*cobra.Command`, which would pass even if the real `create.go`/`update.go`
still declared `String`.

- [ ] **Step 11: No further commit**

Steps 9-10 are verification only — the task's real work is already
committed in Step 8. If Step 9 or Step 10 surfaces a bug, fix it as part of
whichever earlier step's file it belongs to and amend that fix into a new
small commit referencing which step it corrects, not silently folded back
into Step 8's already-made commit.
