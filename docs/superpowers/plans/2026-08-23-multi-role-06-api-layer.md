# Multi-Role: API Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `"roles": [...]` (JSON array) replaces `"role": "x"` across every
user-facing API request/response shape — a deliberate breaking change,
documented with release notes like this project's other breaking API
changes. `api/users.go`'s two duplicated comma-split validators are deleted
(validation now lives once, in `UserService`, per Plan 05); its five
strict-equality admin gates convert to `common.HasAnyRole`.

**Architecture:** `api/users.go` becomes a thin HTTP layer: decode request →
call `UserService` (which now validates roles itself) → map result to
response. No role-string-parsing logic remains in this file at all.

**Tech Stack:** Go, `net/http`, existing `Context`/`ApiSessionRequired`
middleware pattern.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- Depends on Plan 02 (`model.User.Roles`), Plan 03 (`common.HasAnyRole`),
  Plan 04 (`model.Claims.Roles`), Plan 05 (`UserService` now validates roles
  itself — this plan must NOT duplicate that validation).
- Breaking API change: `POST /users` and `PUT /users/{id}` now require
  `"roles": [...]`; a request still sending `"role": "x"` gets a JSON decode
  mismatch (the field no longer exists), not a silent fallback. This is
  intentional per the spec's locked decision — no dual-field transition
  period.
- `strings` import in `api/users.go` becomes unused once both comma-split
  loops are deleted — remove the import too, or `go vet`/the build fails.

---

### Task 1: Request/response shapes in `model/user.go`

**Files:**
- Modify: `model/user.go` (`CreateUserRequest`, `UpdateUserRequest`,
  `UserResponse`, `LoginResponse`, `RefreshTokenResponse`)
- Test: none needed for this task alone — these are pure struct/JSON-tag
  changes with no behavior to unit test in isolation; Task 2's tests cover
  the wiring.

**Interfaces:**
- Produces:
  - `CreateUserRequest.Roles []string` (`json:"roles"`)
  - `UpdateUserRequest.Roles []string` (`json:"roles,omitempty"`)
  - `UserResponse.Roles []string` (`json:"roles"`)
  - `LoginResponse.Roles []string` (`json:"roles"`)
  - `RefreshTokenResponse.Roles []string` (`json:"roles"`)

- [ ] **Step 1: Make the change**

In `model/user.go`:

```go
type CreateUserRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

func CreateUserRequestFromJson(data io.Reader) (*CreateUserRequest, error) {
	var r CreateUserRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateUserRequest struct {
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

func UpdateUserRequestFromJson(data io.Reader) (*UpdateUserRequest, error) {
	var r UpdateUserRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UserResponse struct {
	ID         string   `json:"id"`
	Username   string   `json:"username"`
	Roles      []string `json:"roles"`
	CreatedAt  string   `json:"created_at"`
	TOTPSecret string   `json:"totp_secret,omitempty"`
}
```

Find `LoginResponse` (around line 112-118) and `RefreshTokenResponse`
(around line 134-141) and apply the identical `Role string` → `Roles
[]string` (JSON tag `"roles"`) change to each. Leave every other field in
all five structs untouched.

- [ ] **Step 2: Confirm the compile error surface**

Run: `go build ./... 2>&1 | grep -c "^"`

Expected: a nonzero count of errors. Most are inside `api/users.go` (Task 2
fixes them); `api/oidc.go` and `api/oidc_test.go` also break (Task 3 fixes
them — see its file list, added during this plan's pre-flight scan). If
errors appear anywhere ELSE in the repo — a file not named in Task 2's or
Task 3's file list — stop and investigate before continuing rather than
assuming it's later-plan territory.

- [ ] **Step 3: Commit**

```bash
git add model/user.go
git commit -m "feat(api): roles []string replaces role string in user request/response shapes"
```

---

### Task 2: Rewrite `createUser`/`updateUser` handlers

**Files:**
- Modify: `api/users.go` (`createUser`, `updateUser`)
- Test: `api/users_test.go`

**Interfaces:**
- Consumes: `model.CreateUserRequest.Roles`, `model.UpdateUserRequest.Roles`
  from Task 1; `userService.CreateUser`/`UpdateUser` (now taking
  `Roles`/`CallerRoles`) from Plan 05.
- Produces: `createUser`/`updateUser` no longer contain any role-string
  parsing — all validation delegates to `UserService`.

- [ ] **Step 1: Write the failing test**

Add to `api/users_test.go` (match its existing handler-test pattern — check
how existing `createUser`/`updateUser` tests build a `*Context`/mock service
container):

```go
func TestCreateUser_MultipleRolesInRequestBody_Accepted(t *testing.T) {
	// Follow this file's existing pattern for constructing an admin-authed
	// *Context and a mock UserService whose CreateUser expectation matches
	// Roles: []string{"secrets_manager", "crypto_manager"}. POST a body of
	// {"username":"newuser","password":"pw12345678","roles":["secrets_manager","crypto_manager"]}
	// to createUser and assert a 201 with "roles":["secrets_manager","crypto_manager"]
	// (order-independent) in the response body.
}

func TestCreateUser_EmptyRolesArray_Rejected(t *testing.T) {
	// POST {"username":"newuser","password":"pw12345678","roles":[]} and
	// assert a 4xx response -- UserService.CreateUser rejects an empty
	// Roles slice (Plan 05, Task 1), the handler must surface that as a
	// client error, not a 500.
}
```

Write these against this file's real existing helpers (it has them — this
file already has role-gate tests per the codebase's own conventions) rather
than the placeholder comments above; the comments describe intent only.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestCreateUser_MultipleRolesInRequestBody_Accepted -v`
Expected: FAIL — compile error (file still references `req.Role`, a field
that no longer exists after Task 1)

- [ ] **Step 3: Rewrite `createUser`**

Replace the entire function body from the admin check through the
`userSvc.CreateUser` call:

```go
func createUser(c *Context, w http.ResponseWriter, r *http.Request) {
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}

	req, err := model.CreateUserRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	if req.Username == "" || len(req.Username) < 3 || len(req.Username) > 50 {
		c.SetInvalidParam("username: must be 3-50 characters")
		return
	}
	if req.Password == "" || len(req.Password) < 8 {
		c.SetInvalidParam("password: must be at least 8 characters")
		return
	}

	userSvc := c.userSvc()
	if userSvc == nil {
		return
	}

	result, err := userSvc.CreateUser(r.Context(), userService.CreateUserRequest{
		Username:    req.Username,
		Password:    req.Password,
		Roles:       req.Roles,
		CallerRoles: c.Claims.Roles,
	})
	if err != nil {
		// Role validation errors from UserService ("invalid role: ...",
		// "at least one role is required") are client errors, not server
		// errors -- surface them as 400s instead of masking as 500.
		if strings.Contains(err.Error(), "invalid role") || strings.Contains(err.Error(), "role is required") {
			c.SetInvalidParam(err.Error())
			return
		}
		c.SetInternalError(err)
		return
	}

	response := model.UserResponse{
		ID:         result.UserID.String(),
		Username:   result.Username,
		Roles:      result.Roles,
		CreatedAt:  time.Now().Format(time.RFC3339),
		TOTPSecret: result.TOTPSecret,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("Admin %s created user %s with roles %v", c.Claims.UserID, result.Username, result.Roles)
}
```

Note this KEEPS one `strings.Contains` usage (for error-message
classification) — so the `"strings"` import stays needed here, unlike the
Global Constraints note about `updateUser`'s comma-split loop removal. Don't
remove the import in this step.

- [ ] **Step 4: Rewrite `updateUser`**

Replace from the request-body validation through the `userSvc.UpdateUser`
call and the permission-check block:

```go
func updateUser(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(c.Params.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	req, err := model.UpdateUserRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	if req.Username != "" && (len(req.Username) < 3 || len(req.Username) > 50) {
		c.SetInvalidParam("username: must be 3-50 characters")
		return
	}
	if req.Password != "" && len(req.Password) < 8 {
		c.SetInvalidParam("password: must be at least 8 characters")
		return
	}

	currentUserID := c.Claims.UserID
	currentRoles := c.Claims.Roles

	if !common.HasAnyRole(currentRoles, model.RoleAdmin) {
		if currentUserID != userID.String() {
			c.SetPermissionError("can only update own profile")
			return
		}
		if req.Roles != nil {
			c.SetPermissionError("cannot change own role")
			return
		}
	}

	userSvc := c.userSvc()
	if userSvc == nil {
		return
	}

	var usernamePtr, passwordPtr *string
	if req.Username != "" {
		usernamePtr = &req.Username
	}
	if req.Password != "" {
		passwordPtr = &req.Password
	}

	callerID, _ := uuid.Parse(c.Claims.UserID)

	if err := userSvc.UpdateUser(r.Context(), userService.UpdateUserRequest{
		UserID:      userID,
		CallerID:    callerID,
		CallerRoles: currentRoles,
		Username:    usernamePtr,
		Password:    passwordPtr,
		Roles:       req.Roles,
	}); err != nil {
		if strings.Contains(err.Error(), "invalid role") || strings.Contains(err.Error(), "role is required") {
			c.SetInvalidParam(err.Error())
			return
		}
		c.SetInternalError(err)
		return
	}

	user, err := userSvc.GetUser(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	response := model.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Roles:     user.Roles,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s updated user %s", currentUserID, userID.String())
}
```

Both handlers' comma-split `validRoles`/`requestedRoles` loops are gone
entirely — deleted, not commented out.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./api/... -run "TestCreateUser_MultipleRolesInRequestBody_Accepted|TestCreateUser_EmptyRolesArray_Rejected" -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add api/users.go api/users_test.go
git commit -m "feat(api): createUser/updateUser accept roles arrays, delegate validation to UserService"
```

---

### Task 3: Remaining gates (`listUsers`, `getUser`, `deleteUser`) + response mapping + full suite

**Files:**
- Modify: `api/users.go` (`listUsers`, `getUser`, `deleteUser`, `loginUser`,
  `refreshToken`)
- Modify: `api/oidc.go` (`handleOIDCCallback`'s `model.LoginResponse{...}`
  literal — added during this plan's pre-flight scan: `api/oidc.go` builds
  its own `model.LoginResponse` from `AuthenticationResult.Role`, a field
  Plan 04 already renamed to `Roles []string`, so this file has been broken
  since Plan 04 landed and is named in NO other plan's file list. It's the
  same wire-response-mapping fix as `loginUser`/`refreshToken` below, just
  in a different file of the same `api` package — fix it here rather than
  leaving a gap.)
- Test: `api/users_test.go`, `api/oidc_test.go` (two pre-existing
  `model.User{Role: ...}`/`model.LoginResponse{Role: ...}` literals need the
  same mechanical `Role:` → `Roles: []string{...}` fix Step 6 below already
  asks you to apply package-wide)

**Interfaces:**
- Consumes: `common.HasAnyRole`, `model.Claims.Roles`.

- [ ] **Step 1: Write the failing test**

Add to `api/users_test.go`:

```go
func TestListUsers_MultiRoleAdmin_Allowed(t *testing.T) {
	// Caller with Roles: []string{"secrets_manager", "admin"} must pass
	// listUsers's admin gate -- this is the exact regression class the
	// whole feature exists to fix (a multi-role admin silently losing
	// access under the old strict-equality check).
}

func TestGetUser_MultiRoleNonAdmin_CanOnlyAccessOwnProfile(t *testing.T) {
	// Caller with Roles: []string{"secrets_manager", "crypto_manager"}
	// (no admin) accessing someone else's user_id must still be denied.
}
```

Write these against the file's real test helpers.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./api/... -run TestListUsers_MultiRoleAdmin_Allowed -v`
Expected: FAIL — compile error (`c.Claims.Role` no longer exists)

- [ ] **Step 3: Fix the three remaining gates**

`listUsers`:
```go
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}
```

`getUser`:
```go
	currentUserID := c.Claims.UserID
	currentRoles := c.Claims.Roles

	if !common.HasAnyRole(currentRoles, model.RoleAdmin) && currentUserID != userID.String() {
		c.SetPermissionError("can only access own profile")
		return
	}
```

`deleteUser`:
```go
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required")
		return
	}
```

- [ ] **Step 4: Fix response mapping in `listUsers`/`getUser`/`loginUser`/`refreshToken`**

`listUsers` and `getUser` each build a `model.UserResponse{..., Role:
user.Role, ...}` — change to `Roles: user.Roles`. `loginUser` and
`refreshToken` each build a `model.LoginResponse{..., Role: result.Role,
...}` / `model.RefreshTokenResponse{..., Role: result.Role, ...}` — change
both to `Roles: result.Roles` (this now reads from the `AuthenticationResult`/
`RefreshTokenResult.Roles` field Plan 04 added).

`api/oidc.go`'s `handleOIDCCallback` builds a third `model.LoginResponse{...,
Role: result.Role, ...}` from the same `AuthenticationResult` type (via
`authSvc.IssueSessionForUser`) — apply the identical `Role: result.Role` →
`Roles: result.Roles` fix there too.

- [ ] **Step 5: Remove the now-dead `strings` import if applicable**

Run: `goimports -l api/users.go` (or `go build ./api/...` and read the error)
— if `"strings"` is reported unused (it shouldn't be, since Task 2 kept one
`strings.Contains` call in each handler; this step is a safety check, not an
expected change).

- [ ] **Step 6: Run test to verify it passes, then the full file's suite**

Run: `go test ./api/... -run "TestListUsers_MultiRoleAdmin_Allowed|TestGetUser_MultiRoleNonAdmin_CanOnlyAccessOwnProfile" -v`
Expected: PASS

Run: `go test ./api/... -v`
Expected: all PASS. Fix any remaining `.Role`/`Role:` compile errors in this
package's other test files mechanically, same pattern as Plan 05's Step 5.

- [ ] **Step 7: Commit**

```bash
git add api/users.go api/users_test.go
git commit -m "fix(api): convert listUsers/getUser/deleteUser strict-equality gates to HasAnyRole"
```
