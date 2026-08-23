# Multi-Role: CLI Authorization Call-Site Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every remaining `cmd/` authorization check that reads
`claims.Role` (string) moves to `claims.Roles` (`[]string`) — 17 files
already using `common.HasRequiredRole` (mechanical signature-shape update,
no logic change) plus 4 files still doing strict equality (`claims.Role !=
model.RoleAdmin`, converted to `common.HasAnyRole`).

**Architecture:** Pure mechanical migration — every file in this plan
already has the exact right *logic*; only the type feeding it changes
(`claims.Role` → `claims.Roles`, `HasRequiredRole` → `HasAnyRole`, or a
strict `!=`/`==` comparison → a `HasAnyRole` call). No new behavior anywhere
in this plan.

**Tech Stack:** Go.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- Depends on Plan 03 (`common.HasAnyRole`) and Plan 04 (`model.Claims.Roles`).
- Every file in this plan gets the exact same two-part transform:
  `common.HasRequiredRole(claims.Role, ...)` → `common.HasAnyRole(claims.Roles, ...)`,
  or (for the 4 strict-equality files) `claims.Role != model.RoleAdmin` →
  `!common.HasAnyRole(claims.Roles, model.RoleAdmin)`.
- Do not change any required-role *list* (e.g. `model.RoleAdmin,
  model.RoleCryptoManager`) — only the function name and its first argument.

---

### Task 1: `cmd/keys/*.go` (8 files)

**Files:**
- Modify: `cmd/keys/delete.go:67`, `cmd/keys/rotate.go:73`,
  `cmd/keys/unwrap.go:78`, `cmd/keys/update.go:79`, `cmd/keys/create.go:79`,
  `cmd/keys/verify.go:84`, `cmd/keys/sign.go:78`, `cmd/keys/wrap.go:78`
- Test: each file's corresponding `_test.go`

**Interfaces:**
- Consumes: `common.HasAnyRole` (Plan 03), `model.Claims.Roles` (Plan 04).

- [ ] **Step 1: Write the failing test**

Pick one representative file, `cmd/keys/create_test.go` — find its existing
role-gate test (there is one; this exact gate is already tested today) and
change its fixture claims from `Role: "user"` to `Roles: []string{"user"}`
(and whatever role IS expected to pass, e.g. `Roles: []string{"admin"}`).
Apply the identical fixture-literal change to the other 7 files' test
counterparts in this same step, before touching any source file — this
makes all 8 tests fail together for the same reason (compile error), which
is the correct starting state for this task.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/keys/... -v 2>&1 | head -60`
Expected: FAIL — compile errors, `model.Claims.Role` undefined (or `Roles`
undefined if the test file was written referencing the old shape)

- [ ] **Step 3: Apply the transform to all 8 files**

Each file has exactly one line matching this pattern (shown here for
`create.go:79`; apply identically to the other 7, changing only the
required-role list to match what's already there):

Before:
```go
	if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCryptoManager) {
```

After:
```go
	if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCryptoManager) {
```

Exact required-role lists per file (confirm each against the file itself
before editing — do not assume all 8 are identical):
- `delete.go:67`, `rotate.go:73`, `unwrap.go:78`, `update.go:79`,
  `create.go:79`, `verify.go:84`, `sign.go:78`, `wrap.go:78` — all 8 use
  `model.RoleAdmin, model.RoleCryptoManager` per the investigation; verify
  this is still true at edit time in case the file has changed since.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/keys/... -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/keys/
git commit -m "fix(cli): migrate cmd/keys authorization gates to claims.Roles/HasAnyRole"
```

---

### Task 2: `cmd/certificates/*.go` (4 files) + `cmd/secrets/*.go` (5 files)

**Files:**
- Modify: `cmd/certificates/delete.go:51`, `cmd/certificates/update.go:61`,
  `cmd/certificates/renew.go:62`, `cmd/certificates/create.go:74`,
  `cmd/secrets/export.go:107`, `cmd/secrets/delete.go:76`,
  `cmd/secrets/update.go:88`, `cmd/secrets/create.go:87`,
  `cmd/secrets/import.go:99`
- Test: each file's corresponding `_test.go`

**Interfaces:**
- Same as Task 1.

- [ ] **Step 1: Write the failing test**

Same approach as Task 1, Step 1 — update the fixture claims literal
(`Role:` → `Roles: []string{...}`) in each of the 9 files' existing
role-gate tests before touching source.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/certificates/... ./cmd/secrets/... -v 2>&1 | head -80`
Expected: FAIL — compile errors

- [ ] **Step 3: Apply the transform**

Certificates (all 4 use `model.RoleAdmin, model.RoleCertificateManager` —
verify at edit time):

Before (shown for `create.go:74`):
```go
	if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCertificateManager) {
```
After:
```go
	if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleCertificateManager) {
```

Secrets (all 5 use `model.RoleAdmin, model.RoleSecretsManager` — verify at
edit time):

Before (shown for `create.go:87`):
```go
	if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleSecretsManager) {
```
After:
```go
	if !common.HasAnyRole(claims.Roles, model.RoleAdmin, model.RoleSecretsManager) {
```

Apply the identical shape to all 9 files.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/certificates/... ./cmd/secrets/... -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/certificates/ cmd/secrets/
git commit -m "fix(cli): migrate cmd/certificates and cmd/secrets authorization gates to claims.Roles/HasAnyRole"
```

---

### Task 3: Strict-equality gates — `master_key.go`, `backup.go`, `users/list.go`, `audit/authz.go`

**Files:**
- Modify: `cmd/master_key.go:144`, `cmd/backup.go:53`,
  `cmd/users/list.go:64`, `cmd/audit/authz.go:29`
- Test: each file's corresponding `_test.go`

**Interfaces:**
- Consumes: `common.HasAnyRole`.

- [ ] **Step 1: Write the failing test**

Add or update a role-gate test in each of the 4 files' test counterparts —
a caller with `Roles: []string{"secrets_manager", "admin"}` (multi-role,
admin included but not first) must pass; a caller with `Roles:
[]string{"secrets_manager"}` (no admin) must be denied.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/... -run "MasterKey|Backup|ListUsers|Audit" -v 2>&1 | head -60`
Expected: FAIL — compile errors or wrong-behavior failures

- [ ] **Step 3: Apply the transform**

`cmd/master_key.go` (`requireMasterKeyAdmin`, line 144):
```go
	if !common.HasAnyRole(claims.Roles, model.RoleAdmin) {
```

`cmd/backup.go` (`requireBackupAdmin`, line 53): identical shape.

`cmd/users/list.go` (line 64): identical shape.

`cmd/audit/authz.go` (line 29): identical shape. Also update the comment at
line 5 ("identical `claims.Role != model.RoleAdmin` restriction api/audit.go
enforces") to read `claims.Roles`/`HasAnyRole` — Plan 09 makes the matching
change in `api/audit.go` if that file has the same pattern (check it during
Plan 09; if it's not in Plan 09's file list, flag that as a gap to add
there).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/... -run "MasterKey|Backup|ListUsers|Audit" -v`
Expected: all PASS

- [ ] **Step 5: Full `cmd/` package build and test**

Run: `go build ./cmd/... && go test ./cmd/... -v 2>&1 | tail -40`
Expected: clean build, all tests pass — this is the last file in `cmd/`
referencing `claims.Role` (singular) anywhere; confirm with:

Run: `grep -rn "claims\.Role\b" cmd/ --include="*.go" | grep -v _test.go`
Expected: zero hits.

- [ ] **Step 6: Commit**

```bash
git add cmd/master_key.go cmd/backup.go cmd/users/list.go cmd/audit/authz.go
git commit -m "fix(cli): convert remaining strict-equality role gates to HasAnyRole"
```
