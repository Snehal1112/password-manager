# Azure Role Data Model — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the data-model foundation (new `DataAction` constants and four new built-in role bundles) for RocketVault's four newly-implementable Azure Key Vault roles, and pin down that the fifth (Release User) is deliberately not grantable.

**Architecture:** Pure additions to `model/azure_roles.go` — new `DataAction` string constants, new role-name constants, and new entries in the existing `azureRoleDataActions` map. No behavior in any other file changes yet; this plan only makes the new roles *representable*, not *reachable* through any HTTP or CLI path (that comes in later plans).

**Tech Stack:** Go, standard library `testing`, `github.com/stretchr/testify/assert`.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md` — read §4, §5, §6 before starting.
- `Key Vault Crypto Service Release User` is explicitly **not** added to `azureRoleDataActions` (design §6) — do not add it in this plan or any later one without a new design.
- Every new `DataAction` string must match Azure's real data-action string exactly (verified against Microsoft Learn's Key Vault RBAC guide, 2026-07-17 revision, during design).
- `go build ./...` and `go vet ./...` must pass after every task.

---

### Task 1: New `DataAction` constants

**Files:**
- Modify: `model/azure_roles.go:69-92` (end of the Key data actions const block through the end of the Certificate data actions const block — insert a new const block immediately after)
- Test: `model/azure_roles_test.go` (new file)

**Interfaces:**
- Produces: `model.ActionVaultPurge`, `model.ActionRoleAssignmentsWrite`, `model.ActionRoleAssignmentsDelete` — all `model.DataAction` (a `string` type, `model/azure_roles.go:9`).

- [ ] **Step 1: Write the failing test**

Create `model/azure_roles_test.go`:

```go
package model

import "testing"

func TestNewDataActionConstants_MatchAzureStrings(t *testing.T) {
	cases := []struct {
		name string
		got  DataAction
		want DataAction
	}{
		{"vault purge", ActionVaultPurge, "Microsoft.KeyVault/vaults/purge/action"},
		{"role assignments write", ActionRoleAssignmentsWrite, "Microsoft.Authorization/roleAssignments/write"},
		{"role assignments delete", ActionRoleAssignmentsDelete, "Microsoft.Authorization/roleAssignments/delete"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("got %q, want %q", c.got, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/... -run TestNewDataActionConstants_MatchAzureStrings -v`
Expected: FAIL — `undefined: ActionVaultPurge` (compile error, since the constants don't exist yet).

- [ ] **Step 3: Add the constants**

In `model/azure_roles.go`, immediately after the closing `)` of the Certificate data actions const block (the block ending with `ActionCertificatesPurge DataAction = "Microsoft.KeyVault/vaults/certificates/purge"` — currently ending at line 92), insert:

```go

// Vault-management and role-assignment data actions.
const (
	// ActionVaultPurge permits permanently purging a soft-deleted vault.
	// Unlike the per-object purge actions above, this applies to the vault
	// resource itself, not an object inside it.
	ActionVaultPurge DataAction = "Microsoft.KeyVault/vaults/purge/action"
	// ActionRoleAssignmentsWrite permits granting a role assignment in a vault.
	ActionRoleAssignmentsWrite DataAction = "Microsoft.Authorization/roleAssignments/write"
	// ActionRoleAssignmentsDelete permits revoking a role assignment in a vault.
	ActionRoleAssignmentsDelete DataAction = "Microsoft.Authorization/roleAssignments/delete"
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./model/... -run TestNewDataActionConstants_MatchAzureStrings -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add model/azure_roles.go model/azure_roles_test.go
git commit -m "feat(model): add vault-purge and role-assignment data actions"
```

---

### Task 2: New role constants and bundles (4 roles)

**Files:**
- Modify: `model/azure_roles.go:96-115` (role name const block) and `:120-164` (`azureRoleDataActions` map)
- Modify: `model/azure_roles_test.go` (append tests)

**Interfaces:**
- Consumes: `ActionVaultPurge`, `ActionRoleAssignmentsWrite`, `ActionRoleAssignmentsDelete` (Task 1), and the existing `ActionCertificatesRead`, `ActionKeysRead`, `ActionKeysWrap`, `ActionKeysUnwrap` constants (`model/azure_roles.go:36`, `:62`, `:64`, `:75`).
- Produces: `model.RoleKeyVaultPurgeOperator`, `model.RoleKeyVaultCertificateUser`, `model.RoleKeyVaultCryptoServiceEncryptionUser`, `model.RoleKeyVaultDataAccessAdministrator` — all `string` constants holding the exact Azure role display names. All four become reachable through `model.AzureRoleNames()`, `model.IsAzureRole()`, `model.AzureRoleDataActions()`, `model.RoleGrantsDataAction()` automatically, since those functions iterate the `azureRoleDataActions` map with no per-role special-casing.

- [ ] **Step 1: Write the failing tests**

Append to `model/azure_roles_test.go`:

```go
func TestNewRoles_AreAzureRoles(t *testing.T) {
	for _, role := range []string{
		RoleKeyVaultPurgeOperator,
		RoleKeyVaultCertificateUser,
		RoleKeyVaultCryptoServiceEncryptionUser,
		RoleKeyVaultDataAccessAdministrator,
	} {
		if !IsAzureRole(role) {
			t.Errorf("IsAzureRole(%q) = false, want true", role)
		}
	}
}

func TestRoleKeyVaultPurgeOperator_GrantsOnlyVaultPurge(t *testing.T) {
	actions := AzureRoleDataActions(RoleKeyVaultPurgeOperator)
	if len(actions) != 1 || actions[0] != ActionVaultPurge {
		t.Fatalf("got %v, want [%q]", actions, ActionVaultPurge)
	}
	if RoleGrantsDataAction(RoleKeyVaultPurgeOperator, ActionSecretsGet) {
		t.Fatal("Purge Operator must not grant secret access")
	}
}

func TestRoleKeyVaultCertificateUser_GrantsOnlyCertificatesRead(t *testing.T) {
	actions := AzureRoleDataActions(RoleKeyVaultCertificateUser)
	if len(actions) != 1 || actions[0] != ActionCertificatesRead {
		t.Fatalf("got %v, want [%q]", actions, ActionCertificatesRead)
	}
}

func TestRoleKeyVaultCryptoServiceEncryptionUser_GrantsReadWrapUnwrapOnly(t *testing.T) {
	want := map[DataAction]bool{ActionKeysRead: true, ActionKeysWrap: true, ActionKeysUnwrap: true}
	actions := AzureRoleDataActions(RoleKeyVaultCryptoServiceEncryptionUser)
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %v", len(actions), len(want), actions)
	}
	for _, a := range actions {
		if !want[a] {
			t.Errorf("unexpected action %q", a)
		}
	}
	for _, denied := range []DataAction{ActionKeysEncrypt, ActionKeysDecrypt, ActionKeysSign, ActionKeysVerify} {
		if RoleGrantsDataAction(RoleKeyVaultCryptoServiceEncryptionUser, denied) {
			t.Errorf("Crypto Service Encryption User must not grant %q", denied)
		}
	}
}

func TestRoleKeyVaultDataAccessAdministrator_GrantsRoleAssignmentActionsOnly(t *testing.T) {
	want := map[DataAction]bool{ActionRoleAssignmentsWrite: true, ActionRoleAssignmentsDelete: true}
	actions := AzureRoleDataActions(RoleKeyVaultDataAccessAdministrator)
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %v", len(actions), len(want), actions)
	}
	for _, a := range actions {
		if !want[a] {
			t.Errorf("unexpected action %q", a)
		}
	}
	if RoleGrantsDataAction(RoleKeyVaultDataAccessAdministrator, ActionSecretsGet) {
		t.Fatal("Data Access Administrator must not grant any secrets/keys/certificates action")
	}
}

func TestAzureRoleNames_IncludesAllElevenGrantableRoles(t *testing.T) {
	names := AzureRoleNames()
	if len(names) != 11 {
		t.Fatalf("got %d role names, want 11: %v", len(names), names)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./model/... -run 'TestNewRoles_AreAzureRoles|TestRoleKeyVault|TestAzureRoleNames_IncludesAllElevenGrantableRoles' -v`
Expected: FAIL — compile error, undefined role constants.

- [ ] **Step 3: Add role constants and bundles**

In `model/azure_roles.go`, inside the existing role-name const block (currently ending with `RoleKeyVaultCertificatesOfficer = "Key Vault Certificates Officer"` at line 114, closing `)` at line 115), insert four new lines before the closing `)`:

```go
	// RoleKeyVaultPurgeOperator grants permission to permanently purge a
	// soft-deleted vault.
	RoleKeyVaultPurgeOperator = "Key Vault Purge Operator"
	// RoleKeyVaultCertificateUser grants certificate reads. RocketVault does
	// not yet link a certificate to its key/secret material (deferred to
	// P5), so this currently grants the same ActionCertificatesRead as
	// RoleKeyVaultReader — it exists now for forward compatibility and gains
	// its full Azure semantics once that linkage lands.
	RoleKeyVaultCertificateUser = "Key Vault Certificate User"
	// RoleKeyVaultCryptoServiceEncryptionUser grants read of key metadata
	// plus wrap/unwrap only — narrower than RoleKeyVaultCryptoUser, which
	// also grants encrypt/decrypt/sign/verify.
	RoleKeyVaultCryptoServiceEncryptionUser = "Key Vault Crypto Service Encryption User"
	// RoleKeyVaultDataAccessAdministrator grants the ability to create and
	// revoke role assignments within a vault, without granting any data
	// action on the vault's secrets, keys, or certificates.
	RoleKeyVaultDataAccessAdministrator = "Key Vault Data Access Administrator"
```

Then, inside the `azureRoleDataActions` map literal (currently ending with the `RoleKeyVaultCertificatesOfficer: {...}` entry and its closing `},` around line 163, followed by the map's closing `}` at line 164), insert four new entries before the closing `}`:

```go
	RoleKeyVaultPurgeOperator: {
		ActionVaultPurge,
	},
	RoleKeyVaultCertificateUser: {
		ActionCertificatesRead,
	},
	RoleKeyVaultCryptoServiceEncryptionUser: {
		ActionKeysRead, ActionKeysWrap, ActionKeysUnwrap,
	},
	RoleKeyVaultDataAccessAdministrator: {
		ActionRoleAssignmentsWrite, ActionRoleAssignmentsDelete,
	},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./model/... -v`
Expected: PASS for all tests in the package, including the pre-existing ones (confirms no regression to the 7 existing roles).

- [ ] **Step 5: Commit**

```bash
git add model/azure_roles.go model/azure_roles_test.go
git commit -m "feat(model): add Purge Operator, Certificate User, Crypto Service Encryption User, Data Access Administrator roles"
```

---

### Task 3: Negative control — Release User is not grantable

**Files:**
- Test: `model/azure_roles_test.go` (append)
- Test: `internal/services/authorization/role_assignment_service_test.go` (append)

**Interfaces:**
- Consumes: `model.IsAzureRole` (existing), `authorization.RoleAssignmentService.AssignRole` (existing interface, `internal/services/authorization/role_assignment_service.go:53`), `authorization.ErrInvalidRole` (existing sentinel, `internal/services/authorization/role_assignment_service.go:16`), `newSvc`/`newFakeRoleRepo`/`newFakePolicyRepo`/`fakeUserLookup` test helpers already defined in `role_assignment_service_test.go` (same test package, reused as-is — no changes to those helpers).

- [ ] **Step 1: Write the failing test proving Release User is not an Azure role**

Append to `model/azure_roles_test.go`:

```go
func TestReleaseUser_IsNotAnAzureRole(t *testing.T) {
	if IsAzureRole("Key Vault Crypto Service Release User") {
		t.Fatal("Key Vault Crypto Service Release User must not be grantable: RocketVault has no confidential-compute/TEE attestation flow to gate")
	}
}
```

- [ ] **Step 2: Write the failing test proving `AssignRole` rejects it**

Append to `internal/services/authorization/role_assignment_service_test.go`:

```go
func TestAssignRole_RejectsReleaseUser(t *testing.T) {
	rr := newFakeRoleRepo()
	pr := newFakePolicyRepo()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New()}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice",
		Role:      "Key Vault Crypto Service Release User",
		VaultID:   uuid.New(),
	})
	if !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("got err=%v, want ErrInvalidRole (Release User is not yet implemented, so IsValidRole must reject it)", err)
	}
}
```

- [ ] **Step 3: Run both tests to verify they pass immediately (this is a pure regression/negative-control pair, no production code changes)**

Run: `go test ./model/... -run TestReleaseUser_IsNotAnAzureRole -v && go test ./internal/services/authorization/... -run TestAssignRole_RejectsReleaseUser -v`
Expected: PASS for both, with no changes needed to `roles.go`'s `IsValidRole` — it already returns `false` for any name not in `builtInRoles`, not `"vault-admin"`, and not `model.IsAzureRole(name)`, and Release User satisfies none of those.

If either test fails, stop: it means `IsValidRole` or `IsAzureRole` behaves differently than the design assumed, and the design (or Task 2) needs revisiting before continuing — do not weaken the assertion to force a pass.

- [ ] **Step 4: Run the full test suite for both packages**

Run: `go test ./model/... ./internal/services/authorization/... -v`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add model/azure_roles_test.go internal/services/authorization/role_assignment_service_test.go
git commit -m "test: pin Key Vault Crypto Service Release User as not grantable"
```

---

## Verification Gate (run before considering this plan complete)

```bash
go build ./...
go vet ./...
go test ./model/... ./internal/services/authorization/... -v
```

All must pass. After this plan, `rocketvault vault-access roles` (CLI, unchanged in this plan but automatically reflecting the new data) will list all 11 grantable roles including the four new ones — verify manually with:

```bash
go run main.go vault-access roles
```

Expected output includes `Key Vault Purge Operator`, `Key Vault Certificate User`, `Key Vault Crypto Service Encryption User`, and `Key Vault Data Access Administrator`, each followed by its data actions. `Key Vault Crypto Service Release User` must **not** appear.
