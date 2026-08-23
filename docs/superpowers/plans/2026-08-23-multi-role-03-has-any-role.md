# Multi-Role: HasAnyRole Helper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `common.HasAnyRole(userRoles []string, requiredRoles ...string) bool`,
the single canonical authorization check every later plan in this series
converts its call sites to use, replacing `HasRequiredRole`.

**Architecture:** Straight port of `HasRequiredRole`'s logic (nested loop,
any-match) to a `[]string` first parameter instead of a comma-string that got
split internally — the comma-splitting is no longer needed because callers
now pass a real slice. `HasRequiredRole` is deleted outright (internal
helper, not a public API, no deprecation period).

**Tech Stack:** Go.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- This plan can run independently of Plans 01/02 (pure function, no DB/model
  dependency) but every later plan (05 onward) depends on it.
- `HasRequiredRole` must be fully removed, not left as a deprecated wrapper —
  it has exactly one caller pattern (`claims.Role`) that won't exist once
  `Claims.Roles []string` lands in Plan 04.

---

### Task 1: Implement `HasAnyRole` and port the existing test suite

**Files:**
- Modify: `common/auth_helper.go` (replace `HasRequiredRole` with `HasAnyRole`)
- Modify: `common/auth_helper_test.go` (port all 20 existing test cases)

**Interfaces:**
- Produces: `func HasAnyRole(userRoles []string, requiredRoles ...string) bool`

- [ ] **Step 1: Write the failing test**

Replace the entire contents of `common/auth_helper_test.go` with:

```go
package common

import "testing"

func TestHasAnyRole(t *testing.T) {
	tests := []struct {
		name          string
		userRoles     []string
		requiredRoles []string
		want          bool
	}{
		{"single role exact match", []string{"admin"}, []string{"admin"}, true},
		{"single role no match", []string{"user"}, []string{"admin"}, false},
		{"single role matches one of multiple required", []string{"secrets_manager"}, []string{"admin", "secrets_manager"}, true},
		{"multiple roles - first matches", []string{"secrets_manager", "crypto_manager"}, []string{"secrets_manager"}, true},
		{"multiple roles - second matches", []string{"secrets_manager", "crypto_manager"}, []string{"crypto_manager"}, true},
		{"multiple roles - matches one of required", []string{"secrets_manager", "crypto_manager"}, []string{"admin", "secrets_manager", "certificate_manager"}, true},
		{"multiple roles - no match", []string{"secrets_manager", "crypto_manager"}, []string{"admin", "user"}, false},
		{"empty user roles", []string{}, []string{"admin"}, false},
		{"nil user roles", nil, []string{"admin"}, false},
		{"empty required roles", []string{"admin"}, []string{}, false},
		{"both empty", []string{}, []string{}, false},
		{"three roles - matches middle one", []string{"user", "secrets_manager", "crypto_manager"}, []string{"secrets_manager"}, true},
		{"real scenario - user with secrets_manager and crypto_manager", []string{"secrets_manager", "crypto_manager"}, []string{"admin", "secrets_manager"}, true},
		{"certificate manager role check", []string{"certificate_manager", "crypto_manager"}, []string{"admin", "certificate_manager"}, true},
		{"duplicate roles in user roles", []string{"admin", "admin"}, []string{"admin"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasAnyRole(tt.userRoles, tt.requiredRoles...)
			if got != tt.want {
				t.Errorf("HasAnyRole(%v, %v...) = %v, want %v", tt.userRoles, tt.requiredRoles, got, tt.want)
			}
		})
	}
}
```

(This ports all 15 original `TestHasRequiredRole` cases plus the 5
`TestHasRequiredRole_BackwardCompatibility` cases, deduplicated since several
were equivalent once expressed as `[]string` instead of a comma-string, plus
one new case — duplicate roles in the slice — that's meaningless for a
comma-string but worth covering for a slice.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./common/... -run TestHasAnyRole -v`
Expected: FAIL — compile error, `HasAnyRole` undefined

- [ ] **Step 3: Implement `HasAnyRole`, delete `HasRequiredRole`**

Replace `common/auth_helper.go`'s entire `HasRequiredRole` function (and its
`"strings"` import, no longer needed) with:

```go
package common

// HasAnyRole reports whether userRoles contains at least one of
// requiredRoles.
//
// Parameters:
//   - userRoles: the roles a principal actually holds
//   - requiredRoles: the roles that would grant the operation being checked
//
// Returns true if userRoles and requiredRoles share at least one entry.
func HasAnyRole(userRoles []string, requiredRoles ...string) bool {
	if len(userRoles) == 0 || len(requiredRoles) == 0 {
		return false
	}

	for _, required := range requiredRoles {
		for _, role := range userRoles {
			if role == required {
				return true
			}
		}
	}

	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./common/... -run TestHasAnyRole -v`
Expected: PASS

- [ ] **Step 5: Confirm nothing else in the package still references the deleted function**

Run: `grep -rn "HasRequiredRole" --include="*.go" .`
Expected: zero hits inside `common/`. Hits elsewhere in the repo are expected
at this point — they're the ~35 call sites Plans 05-09 convert; this plan
does not touch them.

- [ ] **Step 6: Commit**

```bash
git add common/auth_helper.go common/auth_helper_test.go
git commit -m "feat(common): add HasAnyRole, replacing HasRequiredRole's comma-split with a real slice"
```
