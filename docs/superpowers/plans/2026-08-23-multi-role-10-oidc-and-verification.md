# Multi-Role: OIDC Path & Completeness Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the last two known call sites (`FindOrCreateExternalUser`,
`common.SessionCache`/`cmd/root.go`'s cached-session path), then run the
completeness grep the design spec asked for and confirm it comes back
clean, then prove the whole feature end-to-end with one real multi-role
login through every layer these ten plans touched.

**Architecture:** No new logic in this plan — the last two mechanical
field-rename sites, then verification only.

**Tech Stack:** Go.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- Depends on every prior plan in this series (01-09) — this is the final
  plan, run last.
- Task 2's completeness grep is not optional — it's the actual proof this
  ten-plan decomposition covered everything the earlier research surfaced
  (and anything it didn't).

---

### Task 1: OIDC user creation + CLI session cache

**Files:**
- Modify: `internal/services/users/user_service.go`
  (`FindOrCreateExternalUser`)
- Modify: `common/session.go` (`SessionCache.Role` field)
- Modify: `cmd/users/login_oidc.go` (`oidcExchangeResponse.Role` field and
  its use at the `SessionCache{...}` literal — added during Plan 04's final
  review: this file hand-duplicates the OIDC exchange response's wire shape
  and was missed by every earlier plan's file list. It is NOT the same
  struct as `model.Claims`/`model.User`/`common.SessionCache`, so the
  Task 2 completeness grep in this plan does not catch it — fix it here,
  explicitly, alongside `SessionCache`, which it feeds directly.)
- Modify: `cmd/users/login.go` (`performPasswordLogin`'s
  `SessionCache{..., Role: result.Role, ...}` literal — added during Plan
  07's own execution: this is the password-login counterpart to
  `login_oidc.go` above, feeding the same `SessionCache` struct, and was
  likewise missed by every earlier plan's file list. Plan 07 deliberately
  left it untouched — `SessionCache.Roles` doesn't exist until this task
  creates it, so Plan 07 couldn't have fixed it even if it tried. Change
  `Role: result.Role` to `Roles: result.Roles` — `result` here is
  `*authServices.AuthenticationResult`, whose `.Roles` field Plan 04 already
  added.)
- Test: `internal/services/users/user_service_test.go`,
  `common/session_test.go` (check it exists first),
  `cmd/users/login_oidc_test.go` (check it exists first),
  `cmd/users/login_password_test.go` (check for a test covering
  `performPasswordLogin`'s `SessionCache` construction; fix any stale
  `Role:` fixture the same mechanical way if Plan 07 didn't already reach
  it)

**Interfaces:**
- Produces: `common.SessionCache.Roles []string` (was `Role string`).

- [ ] **Step 1: Write the failing test**

Add to `internal/services/users/user_service_test.go`:

```go
func TestFindOrCreateExternalUser_NewUser_GetsLeastPrivilegeRole(t *testing.T) {
	t.Parallel()
	repo := &mockUserRepository{}
	pw := &mockPasswordService{}
	totpSvc := &mockTOTPService{}
	svc := newService(repo, pw, totpSvc)

	repo.On("ReadByExternalSubject", mock.Anything, "oidc", "sub-123").
		Return(nil, errors.New("not found"))
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return assert.ObjectsAreEqualValues([]string{model.RoleUser}, u.Roles)
	})).Return(nil)

	user, err := svc.FindOrCreateExternalUser(context.Background(), FindOrCreateExternalUserRequest{
		Provider:          "oidc",
		Subject:           "sub-123",
		PreferredUsername: "newoidcuser",
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{model.RoleUser}, user.Roles)
}
```

Check this file's existing `mockUserRepository.ReadByExternalSubject`
signature/return shape before writing the `.On(...)` call — match whatever's
already there.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/users/... -run TestFindOrCreateExternalUser_NewUser_GetsLeastPrivilegeRole -v`
Expected: FAIL — compile error (`model.User.Roles` field set with `Role:`)

- [ ] **Step 3: Fix `FindOrCreateExternalUser`**

Change:
```go
	user := &model.User{
		ID:                 uuid.New(),
		Username:           username,
		PasswordHash:       "",
		TOTPSecret:         "",
		Role:               model.RoleUser,
		AuthProvider:       req.Provider,
		ExternalIDPSubject: req.Subject,
		CreatedAt:          time.Now(),
	}
```

to:
```go
	user := &model.User{
		ID:                 uuid.New(),
		Username:           username,
		PasswordHash:       "",
		TOTPSecret:         "",
		Roles:              []string{model.RoleUser},
		AuthProvider:       req.Provider,
		ExternalIDPSubject: req.Subject,
		CreatedAt:          time.Now(),
	}
```

- [ ] **Step 4: Fix `common.SessionCache`**

In `common/session.go`:
```go
type SessionCache struct {
	// ... unchanged fields ...
	Roles []string `json:"roles"`
	// ... unchanged fields ...
}
```

- [ ] **Step 4b: Fix `cmd/users/login.go`'s `SessionCache` construction**

Corrected during Plan 07 Task 3: this plan originally assumed `login.go`
still read `Role: result.Role` and compiled fine until this step ran. That
assumption was wrong — `AuthenticationResult.Role` was already renamed to
`Roles []string` back in Plan 04 (an earlier, unrelated auth-service
change), so `login.go` was already broken and Plan 07 Task 3 had to apply
an interim fix just to keep `cmd/users` compiling. The line you'll actually
find is:

```go
		Role:      strings.Join(result.Roles, ","),
```

not the `Role: result.Role` this step originally described. Change it to:

```go
	session := &common.SessionCache{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID,
		Username:     result.Username,
		Roles:        result.Roles,
		ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
	}
```

Remove the now-unnecessary `strings.Join` and its explanatory comment
(check whether `"strings"` becomes an unused import in this file once it's
gone — remove that too if so).

Check `cmd/users/login_password_test.go` for a test covering
`performPasswordLogin` and fix any stale `Role:`/`Roles: []string{"admin"}`
fixture literal the same mechanical way (Plan 07 Task 3 already updated
this file's `AuthenticationResult` fixture to `Roles: []string{"admin"}` —
confirm it's consistent with whatever `SessionCache` assertion the test
makes, adjusting only if the test still expects the old joined-string
shape).

- [ ] **Step 5: Fix `cmd/users/login_oidc.go`'s hand-duplicated wire shape**

This file defines its own local struct for decoding the OIDC exchange
response — a separate type from `model.Claims`/`model.User`, so it does not
show up in Task 2's completeness grep. Find the struct (grep
`oidcExchangeResponse` in `cmd/users/login_oidc.go`) and change:

```go
type oidcExchangeResponse struct {
	// ... unchanged fields ...
	Role         string `json:"role"`
}
```

to:

```go
type oidcExchangeResponse struct {
	// ... unchanged fields ...
	Roles        []string `json:"roles"`
}
```

Then find the `SessionCache{...}` literal built from `exchanged` (search for
`exchanged.Role`) and change the assignment from `Role: exchanged.Role` to
`Roles: exchanged.Roles`. Do not wrap `exchanged.Role` in a
`[]string{exchanged.Role}` literal — that compiles and looks like a fix but
silently produces a single-role session forever for every OIDC CLI login,
since `exchanged.Role` itself no longer exists as a populated field once the
struct's own field is renamed. The server-side OIDC callback response this
struct decodes already emits `"roles": [...]` (Plan 06 changes
`model.LoginResponse.Role` → `Roles []string` with `json:"roles"`, and the
OIDC HTTP handler reuses that same response type) — so the JSON tag rename
here is what makes decoding actually populate the field, not cosmetic.

Add or extend a test in `cmd/users/login_oidc_test.go` (check whether this
file exists first — if there's no existing test infrastructure for this
command, a minimal JSON-unmarshal test proving `{"roles":["admin","secrets_manager"]}`
decodes into `oidcExchangeResponse.Roles` as `[]string{"admin","secrets_manager"}`
is sufficient; don't build new CLI test scaffolding beyond what already
exists in this package).

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/services/users/... -run TestFindOrCreateExternalUser_NewUser_GetsLeastPrivilegeRole -v`
Expected: PASS

Also run whatever tests you added/extended in Steps 4b and 5 and confirm
they pass, plus `go test ./cmd/users/... ./common/... -v` for the two
packages this task's `SessionCache` change ripples into.

- [ ] **Step 7: Commit**

```bash
git add internal/services/users/user_service.go common/session.go cmd/users/login.go cmd/users/login_oidc.go internal/services/users/user_service_test.go cmd/users/login_password_test.go
git commit -m "fix(users): FindOrCreateExternalUser, SessionCache, and both CLI login paths use Roles []string"
```

---

### Task 2: `cmd/root.go` + completeness grep

**Files:**
- Modify: `cmd/root.go` (5 sites: lines ~297, ~327, ~346, ~357, ~484 per the
  investigation — confirm exact line numbers at edit time, prior plans in
  this series may have shifted them slightly)
- Test: `cmd/root_test.go` (check existing coverage of
  `resolveAuthentication`)

**Interfaces:**
- Consumes: `common.SessionCache.Roles`, `authServices.AuthenticationResult.Roles`,
  `authServices.RefreshTokenResult.Roles`, `model.Claims.Roles` — every
  field this whole plan series has been building toward.

- [ ] **Step 1: Write the failing test**

Find `cmd/root.go`'s existing test coverage for `resolveAuthentication`
(check `cmd/root_test.go` for `TestResolveAuthentication`-style names) and
extend/add a case asserting that a cached session with
`Roles: []string{"admin", "secrets_manager"}` round-trips correctly through
`resolveAuthentication` into the returned `*authServices.AuthenticationResult`
and, downstream, into `model.Claims.Roles`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/... -run TestResolveAuthentication -v`
Expected: FAIL — compile errors, `Role:` field no longer exists on the
structs involved

- [ ] **Step 3: Fix all 5 sites**

Every occurrence is the identical one-line rename, `Role:` → `Roles:`, with
the right-hand side already being whatever `.Roles` field its source struct
now has (no logic changes, just the field name on both sides of each `:`).
Locate each with:

```bash
grep -n "Role:" cmd/root.go
```

and fix every hit the same way. There are exactly 5, in: the
password/TOTP-login branch's `SessionCache{...}` literal, the
cached-and-still-valid-session branch's `AuthenticationResult{...}` literal,
the refreshed-session `SessionCache{...}` literal, the refreshed-session
`AuthenticationResult{...}` literal, and the final `model.Claims{...}`
literal built from `authResult`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/... -run TestResolveAuthentication -v`
Expected: PASS

- [ ] **Step 5: The completeness grep**

This is the check the design spec's Section 7 explicitly asked for instead
of trusting any file list (including this ten-plan series') at face value:

```bash
grep -rn "claims\.Role\b\|\.Claims\.Role\b\|model\.Claims{.*Role:\|model\.User{.*Role:\|\.Role ==\|\.Role !=\|HasRequiredRole" --include="*.go" . | grep -v _test.go
```

Expected: **zero hits.** If anything remains, it is a gap this ten-plan
series didn't cover — fix it in this step directly (it's late in the plan
series specifically so any straggler is caught here, not shipped). Also run:

```bash
grep -rn "rolePermissions\[" --include="*.go" internal/services/authorization/
```

to catch any other map-keyed-by-role-string pattern beyond the one Plan 09
already fixed (`RBACService.HasPermission`) — that class of bug doesn't
match the first grep's textual patterns at all, which is exactly how it was
missed until manual tracing found it during this plan's own research phase.

- [ ] **Step 6: Full repo build, vet, and test**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | grep -v "^ok"`
Expected: clean build, clean vet, zero failing tests, zero skipped tests
that were previously passing.

- [ ] **Step 6b: Release notes + admin-manual update**

Added during Plan 06's final whole-plan review: the design spec's locked
decisions require this breaking change to get release notes "same as other
breaking API changes in this project (v4.0.0, v4.1.0)" — no task in this
ten-plan series produced one, and this is the last plan, positioned after
every wire-shape change has landed, so it's the natural place.

Create `docs/release-notes/v4.4.0-multi-role-user-assignment.md` (check
`docs/release-notes/` for the next unused version number — v4.3.0 exists as
of this plan's writing; use the actual next one). Model its structure on
`docs/release-notes/v4.3.0-api-secrets-passphrase.md` (title, "What
changed", a "Breaking" or "Not breaking" section, migration guidance). It
must cover, factually and specifically (no placeholders):

- `POST /users` and `PUT /users/{id}` now require `"roles": [...]` (a JSON
  array) instead of `"role": "x"` (a string) — same for the response shape
  of `POST /users`, `GET /users`, `GET /users/{id}`, `POST /users/login`,
  `POST /users/refresh` (all now return `"roles": [...]`).
- This IS a breaking change, and callers must update client code — do not
  write a "not breaking" section for this one, unlike the v4.3.0 precedent.
- If Step 0's fix landed (a request still sending the old `"role"` field
  now gets an explicit 400, per the fix dispatched after Plan 06's final
  review) — describe that behavior precisely, including the exact error
  message, so callers get an actionable upgrade signal rather than
  discovering the break by trial and error.
- The CLI's `rocketvault users create`/`update --new-role` flag behavior
  (repeatable flag for multiple roles, per this whole plan series) if not
  already documented elsewhere — check `docs/cli-guide.md` first and link
  to it rather than duplicating if it already covers this.
- A short migration example: an old-style request body next to its new
  equivalent.
- A short note (found during Plan 07's final review): `rocketvault users
  list`/`get -o json`/`-o yaml` now emit the `Role` column as a single
  comma-joined string (e.g. `"admin, secrets_manager"`), not a JSON array —
  `internal/formatter`'s `Write(headers []string, rows [][]string)` is
  string-only, and changing that interface to support a real array column
  is out of scope for this plan series. Machine consumers of this output
  must split on `", "` for now.

Then fix `docs/admin-manual.html`'s stale `"role"`-shaped JSON examples —
found during Plan 06's final review at (approximately, confirm each at edit
time since earlier plans in this series may have shifted line numbers)
lines 525, 755, 854, 942, 949, and 964. Line ~964 is the highest-priority
fix: it documents `curl ... -d '{"role":"admin"}'` as the way to change a
user's role via `PUT /users/{id}` — under this plan's new behavior that
request is either a silent no-op or an explicit 400 (depending on whether
Step 0's fix landed), and either way the documented example must change to
`{"roles": ["admin"]}` or `{"roles": ["admin", ...]}` to remain correct.
Change every one of the six sites' JSON examples from `"role": "x"` to
`"roles": ["x"]` (or a multi-role example where it makes the doc clearer),
and check the surrounding prose at each site for singular-role language
("the user's role is...") that should become plural.

Also check `README.md:585,594` — found during Plan 07's final whole-plan
review, unowned by any plan: these lines show `rocketvault users create`/
`update` examples using the single-flag `--new-role user` form only. The
old single-flag syntax stays valid under the new `StringArray` flag (Plan
07 made it repeatable, not exclusive), so nothing there is factually wrong
— but add a second example showing `--new-role admin --new-role
secrets_manager` so the repeatable form is discoverable from the README,
not just `docs/cli-guide.md`.

- [ ] **Step 7: Commit**

```bash
git add cmd/root.go cmd/root_test.go docs/release-notes/v4.4.0-multi-role-user-assignment.md docs/admin-manual.html README.md
git commit -m "fix(cli): resolveAuthentication carries Roles through cache/refresh, completeness grep clean

Also adds v4.4.0 release notes, fixes admin-manual.html's stale single-role
API examples, and adds a repeatable --new-role example to README.md, per
the design spec's locked release-notes requirement (not previously
assigned to any task in this series)."
```

---

### Task 3: End-to-end multi-role verification

**Files:**
- No new source files — verification only, mirrors Plan 07 Task 3's shape
  but exercises paths that plan doesn't reach (per-vault data actions, the
  RBAC-mapped HTTP endpoints Plan 09 fixed, self-promotion).

- [ ] **Step 1: Boot a scratch instance and create a multi-role admin**

```bash
go build -o rocketvault-test .
export RV_MASTER_KEY=$(openssl rand -base64 32)
export RV_BOOTSTRAP_TOKEN=$(openssl rand -base64 32)
# configure a scratch .rocketvault.yaml per CLAUDE.md's Development section
./rocketvault-test users admin --admin-username=admin --admin-password=Testpass123! --bootstrap-token="$RV_BOOTSTRAP_TOKEN"
```

- [ ] **Step 2: Create a multi-role user and confirm both roles are honored**

```bash
./rocketvault-test users login --username admin --password Testpass123! --totp-code <code>
./rocketvault-test users create --new-username=multi --new-password=Testpass123! --new-role=secrets_manager --new-role=crypto_manager
./rocketvault-test users login --username multi --password Testpass123! --totp-code <code>
# As "multi": secrets create must succeed (secrets_manager grants it)...
./rocketvault-test secrets create test-secret test-value --username multi --password Testpass123! --totp-code <code>
# ...and so must a crypto_manager-gated key operation, proving BOTH roles
# are honored from the same account, not just whichever one a
# strict-equality check happened to compare against first.
./rocketvault-test keys create --name test-key --type RSA --bits 2048 --username multi --password Testpass123! --totp-code <code>
```

Expected: both commands succeed.

- [ ] **Step 3: Confirm the RBAC-endpoint fix from Plan 09**

```bash
# "multi" holds no admin role -- must be denied.
./rocketvault-test users list --username multi --password Testpass123! --totp-code <code>
```

Expected: denied (`forbidden`/`permission denied`), proving the fix didn't
overshoot into granting access it shouldn't.

- [ ] **Step 4: Confirm the self-promotion guard still holds**

```bash
./rocketvault-test users update <multi-user-id> --new-role=admin --new-role=secrets_manager --username multi --password Testpass123! --totp-code <code>
```

Expected: denied — "multi" (non-admin) attempting to add `admin` to its own
role list must still be blocked, the exact regression class Plan 05 Task 2
targeted.

- [ ] **Step 5: Confirm admin can grant it instead**

```bash
./rocketvault-test users update <multi-user-id> --new-role=admin --new-role=secrets_manager --username admin --password Testpass123! --totp-code <code>
./rocketvault-test users list --username multi --password Testpass123! --totp-code <code>
```

Expected: the update succeeds (admin performing it), and "multi" (now
holding admin) can subsequently list users.

- [ ] **Step 6: Clean up**

```bash
rm rocketvault-test
# remove the scratch DB file and any scratch config created for this test
```

- [ ] **Step 7: No commit for this task**

Verification only. If any step fails, the fix belongs in whichever earlier
plan's file owns the broken behavior — do not patch it here without tracing
it back to the right plan/commit.
