# P2: Azure RBAC Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace RocketVault's per-object ownership authorization with Azure Key Vault's seven built-in data-plane roles assigned per vault, inverting `PolicyMiddleware` to deny-by-default and shipping the upgrade migration that keeps existing deployments working.

**Architecture:** Seven Azure role-name constants and the exact data-action strings they grant live in `model/azure_roles.go` (the real domain package; `internal/domain/` does not exist). `internal/services/authorization/data_actions.go` maps `(method, path)` to a single required data action for both the flat and the vault-scoped URL shapes without collapsing either onto a global permission. `PolicyMiddleware` evaluates that action against the caller's `role_assignments` rows in the vault resolved by `VaultResolutionMiddleware`, denying when no assignment grants it; `access_policies` survives only as an explicit-deny override evaluated first. A one-time idempotent backfill in `migrateSchema()` derives assignments from existing `user_id` ownership so the inversion does not lock anyone out, and `rocketvault vaults preview-migration` prints that derivation without writing.

**Tech Stack:** Go 1.24.2, Gorilla Mux, `github.com/google/uuid`, SQLite (`mattn/go-sqlite3`) and PostgreSQL (`lib/pq`) behind `internal/db.Dialect`, Cobra + `internal/formatter` for the CLI, testify (`assert`/`require`/`mock`).

**Spec:** `docs/superpowers/specs/2026-07-26-vault-scope-azure-parity-design.md` — §6 (target model, upgrade migration, release notes), §7 (error handling), §8 (testing), §9 (risks).

## Global Constraints

- The fail-closed `PolicyMiddleware` inversion (Task 9) and the upgrade migration (Tasks 6-7) MUST land together in one release; inverting without the migration locks out every existing deployment.
- Tasks 6 and 7 land **before** Task 9 in commit order, so the backfill is present and bisectable before the switch is thrown.
- P0, P1 and P2 ship as one release, never incrementally to production (spec §9).
- All new domain types go in `model/`. `internal/domain/` does not exist; `CLAUDE.md` describing it is wrong and is corrected in Task 13.
- Every commit is signed: `git commit -S`.
- Verification gates run `go build ./... && go test ./...`. `go vet` alone is insufficient: `cmd/testutils.MockServiceContainer` stores services as `interface{}` and type-asserts at runtime, so a missing interface method surfaces only as a `go test` panic (spec §4.3).
- Schema changes follow the dual-write migration pattern: update the `CREATE TABLE`/index definition in `createOptimizedSchema` **and** add the idempotent statement to `migrateSchema()`.
- Out-of-scope resources return 404, not 403. No existence oracle (spec §7).
- A principal that is authenticated but holds no role assignment granting the required data action in the resolved vault gets 403 (spec §7).
- Ownership (`user_id`) stays in the schema as provenance and audit metadata. Nothing reads it for an access decision after Task 11.
- Deleting the P0 B6 tests happens in the same commit as the `ScopeOwner` data-plane retirement (Task 11) and in no other commit (spec §8).
- Assumed already landed (P0/P1): `model.Scope` with `ScopeVault`/`ScopeOwner`/`ScopeAdmin`, collapsed `*InVault` method pairs, `scopeFromRequest` and `ownerScopeFromRequest` in `api/context.go`, and the B6 regression tests. Line numbers below are verified against the current tree for files P1 does not rewrite; for P1-authored code, locate by function name.
- **Exact P1 helper signatures** (verified against the P1 plan, Task 23 — use these, not a one-argument form):
  - `func scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool)`
  - `func ownerScopeFromRequest(c *Context, r *http.Request) (model.Scope, bool)`
  Both set `c.Err` and return `false` on failure, so every call site reads `scope, ok := scopeFromRequest(c, r); if !ok { return }`.

---

## File Structure

```
model/
  azure_roles.go                         # NEW  Task 1 — role names, DataAction constants, role→actions table
  azure_roles_test.go                    # NEW  Task 1
internal/services/authorization/
  data_actions.go                        # NEW  Task 2 — (method, path) → model.DataAction
  data_actions_test.go                   # NEW  Task 2
  roles.go                               # MOD  Task 4 — accept the seven Azure role names
  roles_test.go                          # MOD  Task 4
  role_assignment_service.go             # MOD  Task 5 — HasDataAction
  role_assignment_service_test.go        # MOD  Task 5
  rbac_service.go                        # MOD  Task 10 — vault-aware mapEndpointToPermission
  rbac_vault_routes_test.go              # MOD  Task 10
  authorization_matrix_test.go           # NEW  Task 12 — spec §8 (role, operation) matrix
internal/repositories/
  role_assignment_repository.go          # MOD  Task 3 — ListByPrincipalInVault
  role_assignment_repository_test.go     # MOD  Task 3
internal/db/
  db.go                                  # MOD  Tasks 3, 7 — index dual-write, backfill call
  role_backfill.go                       # NEW  Task 6 — PlanRoleBackfill
  role_backfill_test.go                  # NEW  Task 6
  migrate_assignment_test.go             # MOD  Task 7 — fixture gains a users table
  role_backfill_migration_test.go        # NEW  Task 7
internal/middleware/
  middleware.go                          # MOD  Task 9 — deny-by-default PolicyMiddleware
  middleware_test.go                     # MOD  Task 9 — mock gains GetRoleAssignmentService
cmd/
  vaults.go                              # MOD  Task 8 — register preview-migration
  vaults/preview_migration.go            # NEW  Task 8
  vaults/preview_migration_test.go       # NEW  Task 8
api/
  context.go                             # MOD  Task 11 — delete ownerScopeFromRequest
  keys.go                                # MOD  Tasks 10, 11
  certificates.go                        # MOD  Task 10
  role_assignments_test.go               # MOD  Task 5 — fake gains HasDataAction
docs/
  release-notes/v4.0.0-azure-rbac.md     # NEW  Task 13
CLAUDE.md                                # MOD  Task 13
.claude/multi-vault.md                   # MOD  Task 13
```

---

### Task 1: Azure Role and Data Action Constants

**Files:**
- Create: `model/azure_roles.go`
- Test: `model/azure_roles_test.go`

**Interfaces:**
- Consumes: nothing (leaf task).
- Produces: `model.DataAction` (string type); the 32 action constants `model.ActionSecrets*`, `model.ActionKeys*`, `model.ActionCertificates*`; the seven role constants `model.RoleKeyVaultAdministrator`, `model.RoleKeyVaultReader`, `model.RoleKeyVaultSecretsUser`, `model.RoleKeyVaultSecretsOfficer`, `model.RoleKeyVaultCryptoUser`, `model.RoleKeyVaultCryptoOfficer`, `model.RoleKeyVaultCertificatesOfficer`; functions `model.AzureRoleNames() []string`, `model.IsAzureRole(string) bool`, `model.AzureRoleDataActions(string) []DataAction`, `model.RoleGrantsDataAction(string, DataAction) bool`.

- [ ] **Step 1: Write the failing test**

Create `model/azure_roles_test.go`:

```go
package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureRoleNames asserts the exact seven built-in data-plane roles, sorted.
func TestAzureRoleNames(t *testing.T) {
	assert.Equal(t, []string{
		"Key Vault Administrator",
		"Key Vault Certificates Officer",
		"Key Vault Crypto Officer",
		"Key Vault Crypto User",
		"Key Vault Reader",
		"Key Vault Secrets Officer",
		"Key Vault Secrets User",
	}, AzureRoleNames())
}

// TestIsAzureRole accepts the seven names and rejects everything else,
// including the legacy vault role vocabulary and case variations.
func TestIsAzureRole(t *testing.T) {
	for _, name := range AzureRoleNames() {
		assert.True(t, IsAzureRole(name), "expected %q to be an Azure role", name)
	}
	for _, name := range []string{"", "vault-admin", "secrets-officer", "admin",
		"key vault administrator", "Key Vault Owner"} {
		assert.False(t, IsAzureRole(name), "expected %q not to be an Azure role", name)
	}
}

// TestAzureRoleDataActions pins the exact grant of every role. Any change to a
// role's bundle must change this table too.
func TestAzureRoleDataActions(t *testing.T) {
	cases := map[string][]DataAction{
		RoleKeyVaultReader: {
			ActionSecretsReadMetadata,
			ActionKeysRead,
			ActionCertificatesRead,
		},
		RoleKeyVaultSecretsUser: {
			ActionSecretsReadMetadata,
			ActionSecretsGet,
		},
		RoleKeyVaultSecretsOfficer: {
			ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
			ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore,
			ActionSecretsRecover, ActionSecretsPurge,
		},
		RoleKeyVaultCryptoUser: {
			ActionKeysRead, ActionKeysEncrypt, ActionKeysDecrypt,
			ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		},
		RoleKeyVaultCryptoOfficer: {
			ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
			ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
			ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
			ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		},
		RoleKeyVaultCertificatesOfficer: {
			ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
			ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
			ActionCertificatesRecover, ActionCertificatesPurge,
		},
	}
	for role, want := range cases {
		assert.ElementsMatch(t, want, AzureRoleDataActions(role), "role %q", role)
	}

	// Administrator holds every action any other role holds, and nothing else.
	var union []DataAction
	seen := map[DataAction]bool{}
	for _, role := range AzureRoleNames() {
		if role == RoleKeyVaultAdministrator {
			continue
		}
		for _, a := range AzureRoleDataActions(role) {
			if !seen[a] {
				seen[a] = true
				union = append(union, a)
			}
		}
	}
	admin := AzureRoleDataActions(RoleKeyVaultAdministrator)
	assert.Len(t, admin, 32, "administrator must grant all 32 data actions")
	for _, a := range union {
		assert.Contains(t, admin, a)
	}
}

// TestAzureRoleDataActionsUnknownRole returns an empty slice, never nil-panics.
func TestAzureRoleDataActionsUnknownRole(t *testing.T) {
	assert.Empty(t, AzureRoleDataActions("vault-admin"))
	assert.Empty(t, AzureRoleDataActions(""))
}

// TestAzureRoleDataActionsIsACopy proves the caller cannot mutate the table.
func TestAzureRoleDataActionsIsACopy(t *testing.T) {
	got := AzureRoleDataActions(RoleKeyVaultSecretsUser)
	require.Len(t, got, 2)
	got[0] = "tampered"
	assert.Equal(t, ActionSecretsReadMetadata, AzureRoleDataActions(RoleKeyVaultSecretsUser)[0])
}

// TestRoleGrantsDataAction covers the allow and deny directions and the
// fail-closed cases: unknown role, empty role, empty action.
func TestRoleGrantsDataAction(t *testing.T) {
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultSecretsUser, ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultSecretsUser, ActionSecretsSet))
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultCryptoUser, ActionKeysSign))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultCryptoUser, ActionKeysCreate))
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ActionCertificatesPurge))
	assert.False(t, RoleGrantsDataAction("vault-admin", ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction("", ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ""))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/ -run 'TestAzureRole|TestIsAzureRole|TestRoleGrantsDataAction'`

Expected: FAIL — `undefined: AzureRoleNames`, `undefined: DataAction`, `undefined: RoleKeyVaultReader` (build failure of the `model` test binary).

- [ ] **Step 3: Write `model/azure_roles.go`**

```go
package model

import "sort"

// DataAction is an Azure Key Vault data-plane action string. It is the unit of
// authorization for every vault resource route: a route maps to exactly one
// action, and a role grants a fixed set of them. The strings match Azure's own
// data actions so Azure documentation and role scripts transfer unchanged.
type DataAction string

// Secret data actions.
const (
	// ActionSecretsReadMetadata permits listing secrets and reading their
	// metadata. It never exposes a secret value.
	ActionSecretsReadMetadata DataAction = "Microsoft.KeyVault/vaults/secrets/readMetadata/action"
	// ActionSecretsGet permits reading a secret value.
	ActionSecretsGet DataAction = "Microsoft.KeyVault/vaults/secrets/getSecret/action"
	// ActionSecretsSet permits creating a secret or writing a new value.
	ActionSecretsSet DataAction = "Microsoft.KeyVault/vaults/secrets/setSecret/action"
	// ActionSecretsDelete permits soft-deleting a secret.
	ActionSecretsDelete DataAction = "Microsoft.KeyVault/vaults/secrets/delete"
	// ActionSecretsBackup permits exporting a secret as a backup blob.
	ActionSecretsBackup DataAction = "Microsoft.KeyVault/vaults/secrets/backup/action"
	// ActionSecretsRestore permits importing a secret from a backup blob.
	ActionSecretsRestore DataAction = "Microsoft.KeyVault/vaults/secrets/restore/action"
	// ActionSecretsRecover permits undeleting a soft-deleted secret.
	ActionSecretsRecover DataAction = "Microsoft.KeyVault/vaults/secrets/recover/action"
	// ActionSecretsPurge permits permanently destroying a soft-deleted secret.
	ActionSecretsPurge DataAction = "Microsoft.KeyVault/vaults/secrets/purge"
)

// Key data actions.
const (
	// ActionKeysRead permits listing keys and reading key metadata and public
	// material. It never exposes private key material.
	ActionKeysRead DataAction = "Microsoft.KeyVault/vaults/keys/read"
	// ActionKeysCreate permits generating a new key.
	ActionKeysCreate DataAction = "Microsoft.KeyVault/vaults/keys/create"
	// ActionKeysUpdate permits changing key attributes and tags.
	ActionKeysUpdate DataAction = "Microsoft.KeyVault/vaults/keys/update"
	// ActionKeysDelete permits soft-deleting a key.
	ActionKeysDelete DataAction = "Microsoft.KeyVault/vaults/keys/delete"
	// ActionKeysBackup permits exporting a key as a backup blob.
	ActionKeysBackup DataAction = "Microsoft.KeyVault/vaults/keys/backup/action"
	// ActionKeysRestore permits importing a key from a backup blob.
	ActionKeysRestore DataAction = "Microsoft.KeyVault/vaults/keys/restore/action"
	// ActionKeysRecover permits undeleting a soft-deleted key.
	ActionKeysRecover DataAction = "Microsoft.KeyVault/vaults/keys/recover/action"
	// ActionKeysPurge permits permanently destroying a soft-deleted key.
	ActionKeysPurge DataAction = "Microsoft.KeyVault/vaults/keys/purge"
	// ActionKeysImport permits importing externally generated key material.
	// No HTTP route maps to it yet; it exists so the Crypto Officer and
	// Administrator bundles match Azure exactly.
	ActionKeysImport DataAction = "Microsoft.KeyVault/vaults/keys/import/action"
	// ActionKeysRotate permits rotating a key to a new version.
	ActionKeysRotate DataAction = "Microsoft.KeyVault/vaults/keys/rotate/action"
	// ActionKeysEncrypt permits encrypting with the key.
	ActionKeysEncrypt DataAction = "Microsoft.KeyVault/vaults/keys/encrypt/action"
	// ActionKeysDecrypt permits decrypting with the key.
	ActionKeysDecrypt DataAction = "Microsoft.KeyVault/vaults/keys/decrypt/action"
	// ActionKeysWrap permits wrapping another key with this key.
	ActionKeysWrap DataAction = "Microsoft.KeyVault/vaults/keys/wrap/action"
	// ActionKeysUnwrap permits unwrapping a key wrapped with this key.
	ActionKeysUnwrap DataAction = "Microsoft.KeyVault/vaults/keys/unwrap/action"
	// ActionKeysSign permits signing with the key.
	ActionKeysSign DataAction = "Microsoft.KeyVault/vaults/keys/sign/action"
	// ActionKeysVerify permits verifying a signature with the key.
	ActionKeysVerify DataAction = "Microsoft.KeyVault/vaults/keys/verify/action"
)

// Certificate data actions.
const (
	// ActionCertificatesRead permits listing certificates and reading a
	// certificate and its policy.
	ActionCertificatesRead DataAction = "Microsoft.KeyVault/vaults/certificates/read"
	// ActionCertificatesCreate permits issuing a new certificate.
	ActionCertificatesCreate DataAction = "Microsoft.KeyVault/vaults/certificates/create"
	// ActionCertificatesUpdate permits changing a certificate's attributes,
	// tags, or policy.
	ActionCertificatesUpdate DataAction = "Microsoft.KeyVault/vaults/certificates/update"
	// ActionCertificatesDelete permits soft-deleting a certificate.
	ActionCertificatesDelete DataAction = "Microsoft.KeyVault/vaults/certificates/delete"
	// ActionCertificatesBackup permits exporting a certificate as a backup blob.
	ActionCertificatesBackup DataAction = "Microsoft.KeyVault/vaults/certificates/backup/action"
	// ActionCertificatesRestore permits importing a certificate from a backup blob.
	ActionCertificatesRestore DataAction = "Microsoft.KeyVault/vaults/certificates/restore/action"
	// ActionCertificatesRecover permits undeleting a soft-deleted certificate.
	ActionCertificatesRecover DataAction = "Microsoft.KeyVault/vaults/certificates/recover/action"
	// ActionCertificatesPurge permits permanently destroying a soft-deleted
	// certificate.
	ActionCertificatesPurge DataAction = "Microsoft.KeyVault/vaults/certificates/purge"
)

// Azure built-in data-plane role names. A role is granted to a principal within
// a single vault via the role_assignments table; there is no tenant-wide grant.
const (
	// RoleKeyVaultAdministrator grants every data-plane action on every object type.
	RoleKeyVaultAdministrator = "Key Vault Administrator"
	// RoleKeyVaultReader grants metadata reads only: no secret values, no key material.
	RoleKeyVaultReader = "Key Vault Reader"
	// RoleKeyVaultSecretsUser grants get and list on secrets, including values.
	RoleKeyVaultSecretsUser = "Key Vault Secrets User"
	// RoleKeyVaultSecretsOfficer grants full control of secrets.
	RoleKeyVaultSecretsOfficer = "Key Vault Secrets Officer"
	// RoleKeyVaultCryptoUser grants use of key material: encrypt, decrypt, sign,
	// verify, wrap, unwrap.
	RoleKeyVaultCryptoUser = "Key Vault Crypto User"
	// RoleKeyVaultCryptoOfficer grants full control of keys, including create,
	// import, delete, and rotation.
	RoleKeyVaultCryptoOfficer = "Key Vault Crypto Officer"
	// RoleKeyVaultCertificatesOfficer grants full control of certificates.
	// RocketVault does not yet model a certificate as a linked key plus secret,
	// so this role grants no key or secret actions. That linkage is deferred to P5.
	RoleKeyVaultCertificatesOfficer = "Key Vault Certificates Officer"
)

// azureRoleDataActions is the single source of truth for what each role grants.
// Every bundle is written out in full: no bundle is derived from another, so a
// reader can see a role's exact authority without following a union.
var azureRoleDataActions = map[string][]DataAction{
	RoleKeyVaultAdministrator: {
		ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
		ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore,
		ActionSecretsRecover, ActionSecretsPurge,
		ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
		ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
		ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
		ActionCertificatesRecover, ActionCertificatesPurge,
	},
	RoleKeyVaultReader: {
		ActionSecretsReadMetadata,
		ActionKeysRead,
		ActionCertificatesRead,
	},
	RoleKeyVaultSecretsUser: {
		ActionSecretsReadMetadata,
		ActionSecretsGet,
	},
	RoleKeyVaultSecretsOfficer: {
		ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
		ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore,
		ActionSecretsRecover, ActionSecretsPurge,
	},
	RoleKeyVaultCryptoUser: {
		ActionKeysRead,
		ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap,
		ActionKeysSign, ActionKeysVerify,
	},
	RoleKeyVaultCryptoOfficer: {
		ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
		ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
	},
	RoleKeyVaultCertificatesOfficer: {
		ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
		ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
		ActionCertificatesRecover, ActionCertificatesPurge,
	},
}

// AzureRoleNames returns the seven built-in role names in sorted order.
func AzureRoleNames() []string {
	names := make([]string, 0, len(azureRoleDataActions))
	for name := range azureRoleDataActions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// IsAzureRole reports whether name is one of the seven built-in roles. The
// comparison is exact: role names are stored verbatim in role_assignments.role.
func IsAzureRole(name string) bool {
	_, ok := azureRoleDataActions[name]
	return ok
}

// AzureRoleDataActions returns a copy of the data actions role grants. An
// unknown role yields an empty slice, so an unrecognised assignment grants
// nothing rather than defaulting open.
func AzureRoleDataActions(role string) []DataAction {
	actions, ok := azureRoleDataActions[role]
	if !ok {
		return []DataAction{}
	}
	out := make([]DataAction, len(actions))
	copy(out, actions)
	return out
}

// RoleGrantsDataAction reports whether role grants action. An empty role, an
// unknown role, or an empty action always yields false.
func RoleGrantsDataAction(role string, action DataAction) bool {
	if role == "" || action == "" {
		return false
	}
	for _, a := range azureRoleDataActions[role] {
		if a == action {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./model/`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add model/azure_roles.go model/azure_roles_test.go
git commit -S -m "feat(model): add Azure Key Vault built-in roles and data actions

Introduce model.DataAction and the 32 Azure data-action strings RocketVault
enforces, plus the seven built-in data-plane role names and the exact action
bundle each grants. Every bundle is written out in full so a role's authority
is readable without following a union.

Refs spec 2026-07-26 section 6.2."
```

---

### Task 2: Route to Data Action Mapping

**Files:**
- Create: `internal/services/authorization/data_actions.go`
- Test: `internal/services/authorization/data_actions_test.go`

**Interfaces:**
- Consumes: `model.DataAction` and every `model.Action*` constant from Task 1.
- Produces: `authorization.RouteKind` with `authorization.RouteUnmanaged` and `authorization.RouteVaultData`; `authorization.MapRouteToDataAction(method, path string) (model.DataAction, RouteKind)`.

- [ ] **Step 1: Write the failing test**

Create `internal/services/authorization/data_actions_test.go`:

```go
package authorization

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

// TestMapRouteToDataAction covers every registered resource route in both its
// flat and its vault-scoped shape. Both shapes map to the same action: the
// vault identity comes from the resolved vault in the request context, never
// from this string. The pre-P2 behaviour collapsed the vault-scoped shape onto
// a global permission, which is exactly what this replaces.
func TestMapRouteToDataAction(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		want   model.DataAction
		kind   RouteKind
	}{
		// Secrets.
		{"list secrets", http.MethodGet, "/api/v1/secrets", model.ActionSecretsReadMetadata, RouteVaultData},
		{"create secret", http.MethodPost, "/api/v1/secrets", model.ActionSecretsSet, RouteVaultData},
		{"get secret", http.MethodGet, "/api/v1/secrets/abc", model.ActionSecretsGet, RouteVaultData},
		{"update secret", http.MethodPut, "/api/v1/secrets/abc", model.ActionSecretsSet, RouteVaultData},
		{"delete secret", http.MethodDelete, "/api/v1/secrets/abc", model.ActionSecretsDelete, RouteVaultData},
		{"generate secret", http.MethodPost, "/api/v1/secrets/generate", model.ActionSecretsSet, RouteVaultData},
		{"import secrets", http.MethodPost, "/api/v1/secrets/import", model.ActionSecretsSet, RouteVaultData},
		{"export secrets", http.MethodPost, "/api/v1/secrets/export", model.ActionSecretsGet, RouteVaultData},
		{"list secret versions", http.MethodGet, "/api/v1/secrets/abc/versions", model.ActionSecretsReadMetadata, RouteVaultData},
		{"get secret version", http.MethodGet, "/api/v1/secrets/abc/versions/3", model.ActionSecretsGet, RouteVaultData},
		{"get latest secret version", http.MethodGet, "/api/v1/secrets/abc/versions/latest", model.ActionSecretsGet, RouteVaultData},
		{"backup secret", http.MethodPost, "/api/v1/secrets/abc/backup", model.ActionSecretsBackup, RouteVaultData},
		{"restore secret", http.MethodPost, "/api/v1/secrets/restore", model.ActionSecretsRestore, RouteVaultData},
		{"list deleted secrets", http.MethodGet, "/api/v1/deleted/secrets", model.ActionSecretsReadMetadata, RouteVaultData},
		{"recover secret", http.MethodPost, "/api/v1/deleted/secrets/abc/restore", model.ActionSecretsRecover, RouteVaultData},
		{"purge secret", http.MethodDelete, "/api/v1/deleted/secrets/abc/purge", model.ActionSecretsPurge, RouteVaultData},

		// Keys.
		{"list keys", http.MethodGet, "/api/v1/keys", model.ActionKeysRead, RouteVaultData},
		{"create key", http.MethodPost, "/api/v1/keys", model.ActionKeysCreate, RouteVaultData},
		{"get key", http.MethodGet, "/api/v1/keys/abc", model.ActionKeysRead, RouteVaultData},
		{"update key", http.MethodPut, "/api/v1/keys/abc", model.ActionKeysUpdate, RouteVaultData},
		{"delete key", http.MethodDelete, "/api/v1/keys/abc", model.ActionKeysDelete, RouteVaultData},
		{"rotate key", http.MethodPost, "/api/v1/keys/abc/rotate", model.ActionKeysRotate, RouteVaultData},
		{"list key versions", http.MethodGet, "/api/v1/keys/abc/versions", model.ActionKeysRead, RouteVaultData},
		{"wrap", http.MethodPost, "/api/v1/keys/abc/wrap", model.ActionKeysWrap, RouteVaultData},
		{"unwrap", http.MethodPost, "/api/v1/keys/abc/unwrap", model.ActionKeysUnwrap, RouteVaultData},
		{"sign", http.MethodPost, "/api/v1/keys/abc/sign", model.ActionKeysSign, RouteVaultData},
		{"verify", http.MethodPost, "/api/v1/keys/abc/verify", model.ActionKeysVerify, RouteVaultData},
		{"encrypt", http.MethodPost, "/api/v1/keys/abc/encrypt", model.ActionKeysEncrypt, RouteVaultData},
		{"decrypt", http.MethodPost, "/api/v1/keys/abc/decrypt", model.ActionKeysDecrypt, RouteVaultData},
		{"backup key", http.MethodPost, "/api/v1/keys/abc/backup", model.ActionKeysBackup, RouteVaultData},
		{"restore key", http.MethodPost, "/api/v1/keys/restore", model.ActionKeysRestore, RouteVaultData},
		{"list deleted keys", http.MethodGet, "/api/v1/deleted/keys", model.ActionKeysRead, RouteVaultData},
		{"get deleted key", http.MethodGet, "/api/v1/deleted/keys/abc", model.ActionKeysRead, RouteVaultData},
		{"recover key", http.MethodPost, "/api/v1/deleted/keys/abc/restore", model.ActionKeysRecover, RouteVaultData},
		{"purge key", http.MethodDelete, "/api/v1/deleted/keys/abc/purge", model.ActionKeysPurge, RouteVaultData},

		// Certificates.
		{"list certificates", http.MethodGet, "/api/v1/certificates", model.ActionCertificatesRead, RouteVaultData},
		{"create certificate", http.MethodPost, "/api/v1/certificates", model.ActionCertificatesCreate, RouteVaultData},
		{"get certificate", http.MethodGet, "/api/v1/certificates/abc", model.ActionCertificatesRead, RouteVaultData},
		{"update certificate", http.MethodPut, "/api/v1/certificates/abc", model.ActionCertificatesUpdate, RouteVaultData},
		{"delete certificate", http.MethodDelete, "/api/v1/certificates/abc", model.ActionCertificatesDelete, RouteVaultData},
		{"get certificate policy", http.MethodGet, "/api/v1/certificates/abc/policy", model.ActionCertificatesRead, RouteVaultData},
		{"upsert certificate policy", http.MethodPut, "/api/v1/certificates/abc/policy", model.ActionCertificatesUpdate, RouteVaultData},
		{"delete certificate policy", http.MethodDelete, "/api/v1/certificates/abc/policy", model.ActionCertificatesUpdate, RouteVaultData},
		{"backup certificate", http.MethodPost, "/api/v1/certificates/abc/backup", model.ActionCertificatesBackup, RouteVaultData},
		{"restore certificate", http.MethodPost, "/api/v1/certificates/restore", model.ActionCertificatesRestore, RouteVaultData},
		{"list deleted certificates", http.MethodGet, "/api/v1/deleted/certificates", model.ActionCertificatesRead, RouteVaultData},
		{"recover certificate", http.MethodPost, "/api/v1/deleted/certificates/abc/restore", model.ActionCertificatesRecover, RouteVaultData},
		{"purge certificate", http.MethodDelete, "/api/v1/deleted/certificates/abc/purge", model.ActionCertificatesPurge, RouteVaultData},

		// Non-data-plane routes.
		{"vault list", http.MethodGet, "/api/v1/vaults", "", RouteUnmanaged},
		{"vault get", http.MethodGet, "/api/v1/vaults/prod", "", RouteUnmanaged},
		{"vault delete", http.MethodDelete, "/api/v1/vaults/prod", "", RouteUnmanaged},
		{"role assignments", http.MethodPost, "/api/v1/vaults/prod/role-assignments", "", RouteUnmanaged},
		{"users", http.MethodGet, "/api/v1/users", "", RouteUnmanaged},
		{"health", http.MethodGet, "/api/v1/health", "", RouteUnmanaged},
		{"audit", http.MethodGet, "/api/v1/audit/logs", "", RouteUnmanaged},
	}

	for _, c := range cases {
		t.Run(c.name+" (flat)", func(t *testing.T) {
			gotAction, gotKind := MapRouteToDataAction(c.method, c.path)
			assert.Equal(t, c.want, gotAction)
			assert.Equal(t, c.kind, gotKind)
		})
	}

	// Every data-plane route must map identically under the vault-scoped shape.
	for _, c := range cases {
		if c.kind != RouteVaultData {
			continue
		}
		scoped := "/api/v1/vaults/prod" + trimAPIPrefixForTest(c.path)
		t.Run(c.name+" (vault-scoped)", func(t *testing.T) {
			gotAction, gotKind := MapRouteToDataAction(c.method, scoped)
			assert.Equal(t, c.want, gotAction)
			assert.Equal(t, RouteVaultData, gotKind)
		})
	}
}

// trimAPIPrefixForTest strips the "/api/v1" prefix so a flat path can be
// rewritten into its vault-scoped equivalent.
func trimAPIPrefixForTest(path string) string {
	const prefix = "/api/v1"
	if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
		return path[len(prefix):]
	}
	return path
}

// TestMapRouteToDataActionUnmappedMethodFailsClosed asserts that a data-plane
// path with a method no route serves yields RouteVaultData and an empty action,
// which the middleware must treat as a denial rather than a pass-through.
func TestMapRouteToDataActionUnmappedMethodFailsClosed(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPatch, "/api/v1/secrets/abc"},
		{http.MethodPut, "/api/v1/keys"},
		{http.MethodDelete, "/api/v1/certificates/abc/backup"},
		{http.MethodPost, "/api/v1/deleted/secrets/abc/unknown"},
		{http.MethodGet, "/api/v1/vaults/prod/secrets/abc/unknown"},
	}
	for _, c := range cases {
		action, kind := MapRouteToDataAction(c.method, c.path)
		assert.Equal(t, RouteVaultData, kind, "%s %s", c.method, c.path)
		assert.Equal(t, model.DataAction(""), action, "%s %s", c.method, c.path)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/ -run TestMapRouteToDataAction`

Expected: FAIL — `undefined: MapRouteToDataAction`, `undefined: RouteVaultData`, `undefined: RouteUnmanaged`.

- [ ] **Step 3: Write `internal/services/authorization/data_actions.go`**

```go
package authorization

import (
	"net/http"
	"strings"

	"rocketvault/model"
)

// RouteKind classifies a request path for authorization purposes.
type RouteKind uint8

const (
	// RouteUnmanaged is a route that carries no vault data-plane authorization:
	// health probes, login, user management, vault management, role assignments,
	// access policies, and audit. These keep their existing gates.
	RouteUnmanaged RouteKind = iota
	// RouteVaultData is a vault data-plane resource route. Access requires a role
	// assignment in the resolved vault granting the mapped data action. A
	// RouteVaultData result with an empty action means "no mapping exists", which
	// callers MUST treat as a denial.
	RouteVaultData
)

// MapRouteToDataAction maps an HTTP method and path to the single Azure data
// action required to perform it.
//
// The flat shape ("/api/v1/secrets/{id}") and the vault-scoped shape
// ("/api/v1/vaults/{name}/secrets/{id}") map to the same action on purpose: the
// vault the action is evaluated against comes from the vault resolved into the
// request context, never from this string. That is the whole difference from
// the pre-P2 mapEndpointToPermission, which stripped the vault prefix and then
// checked a single vault-agnostic global permission, letting any principal with
// that permission operate on any vault by name.
//
// Returns RouteUnmanaged for paths that are not vault data-plane routes.
func MapRouteToDataAction(method, path string) (model.DataAction, RouteKind) {
	p := normalizeAuthPath(path)

	// A leading "vaults/{name}/" segment only locates the resource. Dropping it
	// does not widen the check: the caller evaluates the returned action against
	// the resolved vault.
	if rest, found := strings.CutPrefix(p, "vaults/"); found {
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			// "vaults" or "vaults/{name}" — vault management, not data plane.
			return "", RouteUnmanaged
		}
		p = parts[1]
	} else if p == "vaults" {
		return "", RouteUnmanaged
	}

	switch {
	case p == "deleted":
		return "", RouteUnmanaged
	case strings.HasPrefix(p, "deleted/"):
		return mapDeletedAction(method, strings.TrimPrefix(p, "deleted/"))
	case p == "secrets" || strings.HasPrefix(p, "secrets/"):
		return mapSecretAction(method, strings.TrimPrefix(strings.TrimPrefix(p, "secrets"), "/"))
	case p == "keys" || strings.HasPrefix(p, "keys/"):
		return mapKeyAction(method, strings.TrimPrefix(strings.TrimPrefix(p, "keys"), "/"))
	case p == "certificates" || strings.HasPrefix(p, "certificates/"):
		return mapCertificateAction(method, strings.TrimPrefix(strings.TrimPrefix(p, "certificates"), "/"))
	}
	return "", RouteUnmanaged
}

// normalizeAuthPath strips the API version prefix and the surrounding slashes so
// the mappers below see a bare "resource/segments" string.
func normalizeAuthPath(path string) string {
	p := strings.TrimPrefix(path, "/api/v1")
	return strings.Trim(p, "/")
}

// mapSecretAction maps the segments after "secrets" to a secret data action.
func mapSecretAction(method, rest string) (model.DataAction, RouteKind) {
	switch rest {
	case "":
		switch method {
		case http.MethodGet:
			return model.ActionSecretsReadMetadata, RouteVaultData
		case http.MethodPost:
			return model.ActionSecretsSet, RouteVaultData
		}
		return "", RouteVaultData
	case "generate", "import":
		if method == http.MethodPost {
			return model.ActionSecretsSet, RouteVaultData
		}
		return "", RouteVaultData
	case "export":
		if method == http.MethodPost {
			return model.ActionSecretsGet, RouteVaultData
		}
		return "", RouteVaultData
	case "restore":
		if method == http.MethodPost {
			return model.ActionSecretsRestore, RouteVaultData
		}
		return "", RouteVaultData
	}

	seg := strings.Split(rest, "/")
	switch {
	case len(seg) == 1:
		switch method {
		case http.MethodGet:
			return model.ActionSecretsGet, RouteVaultData
		case http.MethodPut:
			return model.ActionSecretsSet, RouteVaultData
		case http.MethodDelete:
			return model.ActionSecretsDelete, RouteVaultData
		}
	case len(seg) == 2 && seg[1] == "backup" && method == http.MethodPost:
		return model.ActionSecretsBackup, RouteVaultData
	case len(seg) == 2 && seg[1] == "versions" && method == http.MethodGet:
		// Listing versions exposes metadata only.
		return model.ActionSecretsReadMetadata, RouteVaultData
	case len(seg) == 3 && seg[1] == "versions" && method == http.MethodGet:
		// A specific version, or "latest", returns the value.
		return model.ActionSecretsGet, RouteVaultData
	}
	return "", RouteVaultData
}

// mapKeyAction maps the segments after "keys" to a key data action.
func mapKeyAction(method, rest string) (model.DataAction, RouteKind) {
	switch rest {
	case "":
		switch method {
		case http.MethodGet:
			return model.ActionKeysRead, RouteVaultData
		case http.MethodPost:
			return model.ActionKeysCreate, RouteVaultData
		}
		return "", RouteVaultData
	case "restore":
		if method == http.MethodPost {
			return model.ActionKeysRestore, RouteVaultData
		}
		return "", RouteVaultData
	}

	seg := strings.Split(rest, "/")
	if len(seg) == 1 {
		switch method {
		case http.MethodGet:
			return model.ActionKeysRead, RouteVaultData
		case http.MethodPut:
			return model.ActionKeysUpdate, RouteVaultData
		case http.MethodDelete:
			return model.ActionKeysDelete, RouteVaultData
		}
		return "", RouteVaultData
	}
	if len(seg) == 2 {
		if seg[1] == "versions" && method == http.MethodGet {
			return model.ActionKeysRead, RouteVaultData
		}
		if method == http.MethodPost {
			switch seg[1] {
			case "rotate":
				return model.ActionKeysRotate, RouteVaultData
			case "backup":
				return model.ActionKeysBackup, RouteVaultData
			case "wrap":
				return model.ActionKeysWrap, RouteVaultData
			case "unwrap":
				return model.ActionKeysUnwrap, RouteVaultData
			case "sign":
				return model.ActionKeysSign, RouteVaultData
			case "verify":
				return model.ActionKeysVerify, RouteVaultData
			case "encrypt":
				return model.ActionKeysEncrypt, RouteVaultData
			case "decrypt":
				return model.ActionKeysDecrypt, RouteVaultData
			}
		}
	}
	return "", RouteVaultData
}

// mapCertificateAction maps the segments after "certificates" to a certificate
// data action. Writing or clearing a certificate's policy is an update of the
// certificate, matching Azure, which has no separate policy data action.
func mapCertificateAction(method, rest string) (model.DataAction, RouteKind) {
	switch rest {
	case "":
		switch method {
		case http.MethodGet:
			return model.ActionCertificatesRead, RouteVaultData
		case http.MethodPost:
			return model.ActionCertificatesCreate, RouteVaultData
		}
		return "", RouteVaultData
	case "restore":
		if method == http.MethodPost {
			return model.ActionCertificatesRestore, RouteVaultData
		}
		return "", RouteVaultData
	}

	seg := strings.Split(rest, "/")
	if len(seg) == 1 {
		switch method {
		case http.MethodGet:
			return model.ActionCertificatesRead, RouteVaultData
		case http.MethodPut:
			return model.ActionCertificatesUpdate, RouteVaultData
		case http.MethodDelete:
			return model.ActionCertificatesDelete, RouteVaultData
		}
		return "", RouteVaultData
	}
	if len(seg) == 2 {
		switch seg[1] {
		case "policy":
			switch method {
			case http.MethodGet:
				return model.ActionCertificatesRead, RouteVaultData
			case http.MethodPut, http.MethodDelete:
				return model.ActionCertificatesUpdate, RouteVaultData
			}
		case "backup":
			if method == http.MethodPost {
				return model.ActionCertificatesBackup, RouteVaultData
			}
		case "renew":
			if method == http.MethodPost {
				return model.ActionCertificatesCreate, RouteVaultData
			}
		}
	}
	return "", RouteVaultData
}

// mapDeletedAction maps the soft-delete routes. rest is everything after
// "deleted/", i.e. "{resource}", "{resource}/{id}", or "{resource}/{id}/{op}".
func mapDeletedAction(method, rest string) (model.DataAction, RouteKind) {
	seg := strings.Split(rest, "/")
	if seg[0] != "secrets" && seg[0] != "keys" && seg[0] != "certificates" {
		return "", RouteUnmanaged
	}

	switch len(seg) {
	case 1: // GET /deleted/{resource}
		if method == http.MethodGet {
			switch seg[0] {
			case "secrets":
				return model.ActionSecretsReadMetadata, RouteVaultData
			case "keys":
				return model.ActionKeysRead, RouteVaultData
			case "certificates":
				return model.ActionCertificatesRead, RouteVaultData
			}
		}
	case 2: // GET /deleted/{resource}/{id}
		if method == http.MethodGet {
			switch seg[0] {
			case "secrets":
				return model.ActionSecretsGet, RouteVaultData
			case "keys":
				return model.ActionKeysRead, RouteVaultData
			case "certificates":
				return model.ActionCertificatesRead, RouteVaultData
			}
		}
	case 3: // /deleted/{resource}/{id}/restore | /purge
		switch {
		case seg[2] == "restore" && method == http.MethodPost:
			switch seg[0] {
			case "secrets":
				return model.ActionSecretsRecover, RouteVaultData
			case "keys":
				return model.ActionKeysRecover, RouteVaultData
			case "certificates":
				return model.ActionCertificatesRecover, RouteVaultData
			}
		case seg[2] == "purge" && method == http.MethodDelete:
			switch seg[0] {
			case "secrets":
				return model.ActionSecretsPurge, RouteVaultData
			case "keys":
				return model.ActionKeysPurge, RouteVaultData
			case "certificates":
				return model.ActionCertificatesPurge, RouteVaultData
			}
		}
	}
	return "", RouteVaultData
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/authorization/`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/data_actions.go internal/services/authorization/data_actions_test.go
git commit -S -m "feat(authorization): map every resource route to an Azure data action

MapRouteToDataAction resolves (method, path) to the single data action a
request requires, for both the flat and the vault-scoped URL shapes. Unlike
mapEndpointToPermission it does not collapse a vault-scoped route onto a
global permission; the caller evaluates the action against the resolved vault.

An unrecognised method on a data-plane path returns RouteVaultData with an
empty action so callers fail closed.

Refs spec 2026-07-26 section 6.2."
```

---

### Task 3: Per-Vault Role Assignment Lookup

**Files:**
- Modify: `internal/repositories/role_assignment_repository.go:15-22` (interface), append method after `ListByVault` (`:52-69`)
- Modify: `internal/db/db.go:645-656` (`role_assignments` block inside `createOptimizedSchema`)
- Modify: `internal/db/db.go:832-834` (`idx_role_assignments_vault` creation inside `migrateSchema`)
- Test: `internal/repositories/role_assignment_repository_test.go`
- Test: `internal/db/migrate_assignment_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `repositories.RoleAssignmentRepositoryInterface.ListByPrincipalInVault(ctx context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error)`; SQL index `idx_role_assignments_principal_vault`.

The `role_assignments` table already carries `vault_id TEXT NOT NULL` with `UNIQUE (principal_id, role, vault_id)` and a foreign key to `vaults(id)` (verified at `internal/db/db.go:645-656`). No column is added; only the lookup path and its supporting index.

- [ ] **Step 1: Write the failing repository test**

Append to `internal/repositories/role_assignment_repository_test.go`:

```go
// TestRoleAssignment_ListByPrincipalInVault returns only the assignments held by
// the given principal in the given vault. Assignments held by another principal,
// or by the same principal in another vault, must not leak into the result:
// this query is the authorization lookup, so a leak is a privilege escalation.
func TestRoleAssignment_ListByPrincipalInVault(t *testing.T) {
	repo := newRoleAssignmentRepo(t)
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	alice, bob := uuid.New(), uuid.New()

	seed := []*model.RoleAssignment{
		{ID: uuid.New(), PrincipalID: alice, PrincipalType: model.PrincipalTypeUser,
			Role: model.RoleKeyVaultSecretsOfficer, VaultID: vaultA, CreatedBy: uuid.New()},
		{ID: uuid.New(), PrincipalID: alice, PrincipalType: model.PrincipalTypeUser,
			Role: model.RoleKeyVaultCryptoUser, VaultID: vaultA, CreatedBy: uuid.New()},
		{ID: uuid.New(), PrincipalID: alice, PrincipalType: model.PrincipalTypeUser,
			Role: model.RoleKeyVaultAdministrator, VaultID: vaultB, CreatedBy: uuid.New()},
		{ID: uuid.New(), PrincipalID: bob, PrincipalType: model.PrincipalTypeUser,
			Role: model.RoleKeyVaultAdministrator, VaultID: vaultA, CreatedBy: uuid.New()},
	}
	for _, ra := range seed {
		if err := repo.Create(ctx, ra); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	got, err := repo.ListByPrincipalInVault(ctx, alice, vaultA)
	if err != nil {
		t.Fatalf("ListByPrincipalInVault: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 assignments, got %d", len(got))
	}
	roles := map[string]bool{}
	for _, ra := range got {
		if ra.PrincipalID != alice || ra.VaultID != vaultA {
			t.Fatalf("leaked assignment: principal=%s vault=%s", ra.PrincipalID, ra.VaultID)
		}
		roles[ra.Role] = true
	}
	if !roles[model.RoleKeyVaultSecretsOfficer] || !roles[model.RoleKeyVaultCryptoUser] {
		t.Fatalf("unexpected roles: %v", roles)
	}

	// A principal with no assignment in the vault gets an empty, non-error result.
	none, err := repo.ListByPrincipalInVault(ctx, uuid.New(), vaultA)
	if err != nil {
		t.Fatalf("ListByPrincipalInVault (absent principal): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("want 0 assignments for an unknown principal, got %d", len(none))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestRoleAssignment_ListByPrincipalInVault`

Expected: FAIL — `repo.ListByPrincipalInVault undefined (type RoleAssignmentRepositoryInterface has no field or method ListByPrincipalInVault)`.

- [ ] **Step 3: Add the interface method and implementation**

In `internal/repositories/role_assignment_repository.go`, add to the interface (after `ListByVault`, line 19):

```go
	// ListByPrincipalInVault returns every role assignment the principal holds in
	// the given vault. It is the authorization lookup: the middleware turns the
	// returned roles into data actions. An empty result means no access.
	ListByPrincipalInVault(ctx context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
```

And add the implementation after `ListByVault` (after line 69):

```go
func (r *roleAssignmentRepository) ListByPrincipalInVault(ctx context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, role, vault_id, created_by, created_at
		 FROM role_assignments WHERE principal_id = ? AND vault_id = ?`,
		principalID.String(), vaultID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.RoleAssignment
	for rows.Next() {
		ra, err := scanRoleAssignmentRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ra)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repositories/ -run TestRoleAssignment_ListByPrincipalInVault`

Expected: PASS

- [ ] **Step 5: Write the failing index test**

Append to `internal/db/migrate_assignment_test.go`:

```go
// TestMigrate_CreatesPrincipalVaultIndex verifies that migrateSchema creates the
// composite index backing the per-vault authorization lookup. The index must be
// created in migrateSchema as well as in createOptimizedSchema so that upgraded
// databases get it too.
func TestMigrate_CreatesPrincipalVaultIndex(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Exec(`
		CREATE TABLE secrets (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE keys (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE certificates (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE audit_logs (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.migrateSchema(conn))
	require.NoError(t, repo.migrateSchema(conn), "second run must be idempotent")

	var name string
	row := conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_role_assignments_principal_vault'`)
	require.NoError(t, row.Scan(&name), "idx_role_assignments_principal_vault missing after migrate")
	require.Equal(t, "idx_role_assignments_principal_vault", name)
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestMigrate_CreatesPrincipalVaultIndex`

Expected: FAIL — `idx_role_assignments_principal_vault missing after migrate: sql: no rows in result set`.

- [ ] **Step 7: Add the index to both schema paths (dual-write)**

In `internal/db/db.go`, inside `createOptimizedSchema`, immediately after line 656:

```go
		CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id);
		CREATE INDEX IF NOT EXISTS idx_role_assignments_principal_vault ON role_assignments(principal_id, vault_id);
```

In `internal/db/db.go`, inside `migrateSchema`, immediately after the `idx_role_assignments_vault` block (line 832-834):

```go
	// Composite index for the per-vault authorization lookup
	// (RoleAssignmentRepository.ListByPrincipalInVault), which runs on every
	// data-plane request.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_role_assignments_principal_vault ON role_assignments(principal_id, vault_id)`); err != nil {
		return fmt.Errorf("index role_assignments principal/vault: %w", err)
	}
```

- [ ] **Step 8: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/repositories/role_assignment_repository.go internal/repositories/role_assignment_repository_test.go internal/db/db.go internal/db/migrate_assignment_test.go
git commit -S -m "feat(repositories): look up role assignments per principal and vault

ListByPrincipalInVault is the authorization lookup for the deny-by-default
policy middleware: it returns the roles a principal holds in one specific
vault. Back it with a composite (principal_id, vault_id) index, written into
both createOptimizedSchema and migrateSchema so fresh and upgraded databases
agree.

Refs spec 2026-07-26 section 6.2."
```

---

### Task 4: Accept the Azure Role Names in the Role Vocabulary

**Files:**
- Modify: `internal/services/authorization/roles.go:60-69` (`BuiltInRoleNames`), `:84-91` (`IsValidRole`), `:93-114` (`bundle`), `:116-140` (`ExpandRole`)
- Test: `internal/services/authorization/roles_test.go`

**Interfaces:**
- Consumes: `model.AzureRoleNames()`, `model.IsAzureRole()` from Task 1.
- Produces: `authorization.IsValidRole` accepting the seven Azure names; `authorization.ExpandRole` returning an empty policy slice for them; `authorization.BuiltInRoleNames()` listing legacy plus Azure names.

Rationale: `RoleAssignmentService.AssignRole` rejects unknown roles via `IsValidRole` and then calls `ExpandRole` to materialise `access_policies` rows. Azure roles are evaluated **directly** from `role_assignments` by the new data-action check, so they must be accepted as valid but must expand to zero policies — materialising allow-policies for them would create a second, drifting source of truth for the same grant.

- [ ] **Step 1: Write the failing test**

Append to `internal/services/authorization/roles_test.go`:

```go
// TestIsValidRole_AcceptsAzureRoles asserts the seven Azure built-in role names
// are grantable alongside the legacy vault role vocabulary.
func TestIsValidRole_AcceptsAzureRoles(t *testing.T) {
	for _, role := range []string{
		model.RoleKeyVaultAdministrator,
		model.RoleKeyVaultReader,
		model.RoleKeyVaultSecretsUser,
		model.RoleKeyVaultSecretsOfficer,
		model.RoleKeyVaultCryptoUser,
		model.RoleKeyVaultCryptoOfficer,
		model.RoleKeyVaultCertificatesOfficer,
	} {
		if !IsValidRole(role) {
			t.Fatalf("IsValidRole(%q) = false, want true", role)
		}
	}
	if IsValidRole("Key Vault Owner") {
		t.Fatal("IsValidRole should reject an unknown Azure-looking role")
	}
}

// TestExpandRole_AzureRolesProduceNoPolicies asserts Azure roles materialise no
// access_policies rows. They are evaluated directly from role_assignments; a
// second materialised copy of the same grant could drift.
func TestExpandRole_AzureRolesProduceNoPolicies(t *testing.T) {
	for _, role := range model.AzureRoleNames() {
		policies, err := ExpandRole(role, uuid.New(), model.PrincipalTypeUser, uuid.New(), uuid.New())
		if err != nil {
			t.Fatalf("ExpandRole(%q): %v", role, err)
		}
		if len(policies) != 0 {
			t.Fatalf("ExpandRole(%q) produced %d policies, want 0", role, len(policies))
		}
	}
}

// TestBuiltInRoleNames_IncludesAzureRoles asserts the CLI-facing role list
// covers both vocabularies.
func TestBuiltInRoleNames_IncludesAzureRoles(t *testing.T) {
	names := BuiltInRoleNames()
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, n := range append(model.AzureRoleNames(),
		"vault-admin", "vault-reader", "secrets-user", "secrets-officer",
		"crypto-user", "crypto-officer", "certificates-officer") {
		if !have[n] {
			t.Fatalf("BuiltInRoleNames missing %q", n)
		}
	}
	if len(names) != 14 {
		t.Fatalf("want 14 role names (7 legacy + 7 Azure), got %d: %v", len(names), names)
	}
}

// TestRolePermissions_AzureRoleIsEmpty asserts the display helper reports no
// (resource, operation) pairs for an Azure role, since those roles are not
// expressed in the legacy permission vocabulary.
func TestRolePermissions_AzureRoleIsEmpty(t *testing.T) {
	perms, err := RolePermissions(model.RoleKeyVaultAdministrator)
	if err != nil {
		t.Fatalf("RolePermissions: %v", err)
	}
	if len(perms) != 0 {
		t.Fatalf("want 0 legacy permissions for an Azure role, got %d", len(perms))
	}
}
```

Ensure `roles_test.go` imports `"github.com/google/uuid"` and `"rocketvault/model"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/ -run 'TestIsValidRole_AcceptsAzureRoles|TestExpandRole_AzureRolesProduceNoPolicies|TestBuiltInRoleNames_IncludesAzureRoles|TestRolePermissions_AzureRoleIsEmpty'`

Expected: FAIL — `IsValidRole("Key Vault Administrator") = false, want true`.

- [ ] **Step 3: Update `internal/services/authorization/roles.go`**

Replace `BuiltInRoleNames` (lines 60-69):

```go
// BuiltInRoleNames returns the sorted list of grantable role names: the legacy
// vault roles plus the seven Azure built-in data-plane roles.
func BuiltInRoleNames() []string {
	names := make([]string, 0, len(builtInRoles)+1+len(model.AzureRoleNames()))
	for n := range builtInRoles {
		names = append(names, n)
	}
	names = append(names, "vault-admin")
	names = append(names, model.AzureRoleNames()...)
	sort.Strings(names)
	return names
}
```

Replace `RolePermissions` (lines 71-82):

```go
// RolePermissions returns the (resource, operation) pairs for display. Azure
// built-in roles are not expressed in this legacy permission vocabulary; they
// grant data actions instead, so they report an empty set. Use
// model.AzureRoleDataActions for those.
func RolePermissions(role string) ([][2]string, error) {
	if model.IsAzureRole(role) {
		return [][2]string{}, nil
	}
	perms, err := bundle(role)
	if err != nil {
		return nil, err
	}
	out := make([][2]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, [2]string{string(p.Resource), string(p.Operation)})
	}
	return out, nil
}
```

Replace `IsValidRole` (lines 84-91):

```go
// IsValidRole reports whether name is a grantable role: a legacy vault role or
// one of the seven Azure built-in data-plane roles.
func IsValidRole(name string) bool {
	if name == "vault-admin" || model.IsAzureRole(name) {
		return true
	}
	_, ok := builtInRoles[name]
	return ok
}
```

Replace the opening of `ExpandRole` (lines 116-121) so Azure roles short-circuit:

```go
// ExpandRole turns a role grant into the access_policies rows it implies.
//
// Azure built-in roles expand to nothing: they are evaluated directly from the
// role_assignments row by MapRouteToDataAction plus model.RoleGrantsDataAction.
// Materialising a second, derived copy of the same grant in access_policies
// would create two sources of truth that can drift, and access_policies is
// retained only as an explicit-deny override.
func ExpandRole(role string, principalID uuid.UUID, principalType model.PrincipalType, vaultID, assignmentID uuid.UUID) ([]*model.AccessPolicy, error) {
	if model.IsAzureRole(role) {
		return nil, nil
	}
	perms, err := bundle(role)
	if err != nil {
		return nil, err
	}
```

The remainder of `ExpandRole` is unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./internal/services/authorization/`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/roles.go internal/services/authorization/roles_test.go
git commit -S -m "feat(authorization): make the seven Azure roles grantable

IsValidRole and BuiltInRoleNames now accept the Azure built-in data-plane role
names so they can be assigned through the existing role-assignment API. They
expand to zero access_policies rows: the deny-by-default middleware reads the
role_assignments row directly, and a materialised second copy of the same
grant could drift from it.

Refs spec 2026-07-26 section 6.2."
```

---

### Task 5: Data Action Check on the Role Assignment Service

**Files:**
- Modify: `internal/services/authorization/role_assignment_service.go:21-27` (`roleAssignmentRepo`), `:48-54` (`RoleAssignmentService`), append method after `ListAssignments` (`:139-141`)
- Modify: `api/role_assignments_test.go` (`mockRoleAssignmentService` gains the method)
- Modify: `internal/services/authorization/role_assignment_service_test.go` (existing fake repo gains `ListByPrincipalInVault`)

**Interfaces:**
- Consumes: `repositories.RoleAssignmentRepositoryInterface.ListByPrincipalInVault` (Task 3), `model.RoleGrantsDataAction` (Task 1).
- Produces: `authorization.RoleAssignmentService.HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error)`.

- [ ] **Step 1: Write the failing test**

Append to `internal/services/authorization/role_assignment_service_test.go`:

```go
// fakeVaultRoleRepo serves a fixed set of assignments keyed by (principal, vault).
type fakeVaultRoleRepo struct {
	byPrincipalVault map[string][]*model.RoleAssignment
	err              error
	calls            int
}

func (f *fakeVaultRoleRepo) Create(context.Context, *model.RoleAssignment) error { return nil }
func (f *fakeVaultRoleRepo) GetByID(context.Context, uuid.UUID) (*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) ListByVault(context.Context, uuid.UUID) ([]*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) FindByTuple(context.Context, uuid.UUID, string, uuid.UUID) (*model.RoleAssignment, error) {
	return nil, nil
}
func (f *fakeVaultRoleRepo) Delete(context.Context, uuid.UUID) error { return nil }
func (f *fakeVaultRoleRepo) ListByPrincipalInVault(_ context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.byPrincipalVault[principalID.String()+"|"+vaultID.String()], nil
}

// TestHasDataAction covers the grant, the denial, the wrong-vault case, and the
// fail-closed inputs. A principal holding Secrets User in vault A must not be
// able to read a secret in vault B.
func TestHasDataAction(t *testing.T) {
	alice := uuid.New()
	vaultA, vaultB := uuid.New(), uuid.New()

	repo := &fakeVaultRoleRepo{byPrincipalVault: map[string][]*model.RoleAssignment{
		alice.String() + "|" + vaultA.String(): {
			{PrincipalID: alice, VaultID: vaultA, Role: model.RoleKeyVaultSecretsUser},
		},
	}}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	ctx := context.Background()

	cases := []struct {
		name      string
		principal uuid.UUID
		vault     uuid.UUID
		action    model.DataAction
		want      bool
	}{
		{"granted action in the right vault", alice, vaultA, model.ActionSecretsGet, true},
		{"action the role does not grant", alice, vaultA, model.ActionSecretsSet, false},
		{"same role, different vault", alice, vaultB, model.ActionSecretsGet, false},
		{"unknown principal", uuid.New(), vaultA, model.ActionSecretsGet, false},
		{"nil principal", uuid.Nil, vaultA, model.ActionSecretsGet, false},
		{"nil vault", alice, uuid.Nil, model.ActionSecretsGet, false},
		{"empty action", alice, vaultA, model.DataAction(""), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := svc.HasDataAction(ctx, c.principal, c.vault, c.action)
			if err != nil {
				t.Fatalf("HasDataAction: %v", err)
			}
			if got != c.want {
				t.Fatalf("HasDataAction = %v, want %v", got, c.want)
			}
		})
	}
}

// TestHasDataActionMultipleRolesUnion asserts the grants of every assignment a
// principal holds in the vault are unioned.
func TestHasDataActionMultipleRolesUnion(t *testing.T) {
	alice := uuid.New()
	vault := uuid.New()
	repo := &fakeVaultRoleRepo{byPrincipalVault: map[string][]*model.RoleAssignment{
		alice.String() + "|" + vault.String(): {
			{PrincipalID: alice, VaultID: vault, Role: model.RoleKeyVaultSecretsUser},
			{PrincipalID: alice, VaultID: vault, Role: model.RoleKeyVaultCryptoUser},
		},
	}}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	ctx := context.Background()

	for _, action := range []model.DataAction{model.ActionSecretsGet, model.ActionKeysSign} {
		ok, err := svc.HasDataAction(ctx, alice, vault, action)
		if err != nil || !ok {
			t.Fatalf("HasDataAction(%s) = %v, %v; want true, nil", action, ok, err)
		}
	}
	ok, err := svc.HasDataAction(ctx, alice, vault, model.ActionKeysCreate)
	if err != nil || ok {
		t.Fatalf("HasDataAction(keys/create) = %v, %v; want false, nil", ok, err)
	}
}

// TestHasDataActionRepositoryErrorPropagates asserts a lookup failure surfaces
// as an error rather than a silent false, so the middleware can answer 500
// instead of masking a database outage as a permission denial.
func TestHasDataActionRepositoryErrorPropagates(t *testing.T) {
	repo := &fakeVaultRoleRepo{err: errors.New("database is locked")}
	svc := NewRoleAssignmentService(repo, nil, nil, nil)
	got, err := svc.HasDataAction(context.Background(), uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil {
		t.Fatal("want an error when the lookup fails")
	}
	if got {
		t.Fatal("want false alongside the error")
	}
}
```

Ensure the test file imports `"errors"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/ -run TestHasDataAction`

Expected: FAIL — `svc.HasDataAction undefined (type RoleAssignmentService has no field or method HasDataAction)` and `*fakeVaultRoleRepo does not implement roleAssignmentRepo`.

- [ ] **Step 3: Add the method**

In `internal/services/authorization/role_assignment_service.go`, add to the `roleAssignmentRepo` interface (after line 25):

```go
	ListByPrincipalInVault(ctx context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
```

Add to the `RoleAssignmentService` interface (after line 53):

```go
	// HasDataAction reports whether the principal holds a role assignment in the
	// given vault that grants the data action. It is the fail-closed
	// authorization decision for every vault data-plane route: an empty
	// assignment list is a denial, and a lookup failure is an error, never a
	// silent false.
	HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error)
```

Add the implementation after `ListAssignments`:

```go
func (s *roleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	// Reject the degenerate inputs before touching the database. A nil principal
	// or vault can only come from a malformed context, and an empty action means
	// the route had no mapping; all three must deny.
	if principalID == uuid.Nil || vaultID == uuid.Nil || action == "" {
		return false, nil
	}
	assignments, err := s.roleRepo.ListByPrincipalInVault(ctx, principalID, vaultID)
	if err != nil {
		return false, fmt.Errorf("list role assignments: %w", err)
	}
	for _, ra := range assignments {
		if model.RoleGrantsDataAction(ra.Role, action) {
			return true, nil
		}
	}
	return false, nil
}
```

- [ ] **Step 4: Update the HTTP-layer fake**

In `api/role_assignments_test.go`, add to `mockRoleAssignmentService`:

```go
func (m *mockRoleAssignmentService) HasDataAction(_ context.Context, _, _ uuid.UUID, _ model.DataAction) (bool, error) {
	return false, nil
}
```

- [ ] **Step 5: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/services/authorization/role_assignment_service.go internal/services/authorization/role_assignment_service_test.go api/role_assignments_test.go
git commit -S -m "feat(authorization): add HasDataAction for per-vault role checks

HasDataAction unions the data actions granted by every role the principal
holds in one vault and reports whether the requested action is among them.
Nil principal, nil vault and empty action deny without a query; a lookup
failure returns an error so callers answer 500 rather than masking a database
outage as a permission denial.

Refs spec 2026-07-26 section 6.2."
```

---

### Task 6: Derive the Upgrade Migration Plan

**Files:**
- Create: `internal/db/role_backfill.go`
- Test: `internal/db/role_backfill_test.go`

**Interfaces:**
- Consumes: `model.RoleKeyVaultSecretsOfficer`, `model.RoleKeyVaultCryptoOfficer`, `model.RoleKeyVaultCertificatesOfficer`, `model.RoleKeyVaultAdministrator` (Task 1); `model.RoleAdmin`; `db.DBTX`; `db.Dialect.ColumnExists`.
- Produces: `db.RoleBackfillGrant{PrincipalID, VaultID, VaultName, Role, Source string}`; `db.PlanRoleBackfill(ctx context.Context, q DBTX, dialect Dialect) ([]RoleBackfillGrant, error)`.

This is the highest-risk artifact in the spec, so the derivation is separated from the write. Both the migration (Task 7) and `preview-migration` (Task 8) call the same pure function, so an operator's preview is the same computation the migration performs. `PlanRoleBackfill` writes nothing.

Column guards matter: `migrateSchema` runs against arbitrary old database shapes, and `secrets.user_id` predates `secrets.vault_id`. A source table whose `user_id` or `vault_id` column is absent is skipped rather than erroring, which is also what keeps the existing `migrate_assignment_test.go` fixtures valid.

- [ ] **Step 1: Write the failing test**

Create `internal/db/role_backfill_test.go`:

```go
package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// seedPreMigrationDB builds a database in the pre-P2 shape: two vaults, three
// users (one a global admin), and objects owned across both vaults.
func seedPreMigrationDB(t *testing.T) (*sql.DB, map[string]string) {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	_, err = conn.Exec(`
		CREATE TABLE users (
			id       TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			role     TEXT NOT NULL
		);
		CREATE TABLE vaults (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		);
		CREATE TABLE secrets (
			id       TEXT PRIMARY KEY,
			user_id  TEXT NOT NULL,
			vault_id TEXT NOT NULL
		);
		CREATE TABLE keys (
			id       TEXT PRIMARY KEY,
			user_id  TEXT NOT NULL,
			vault_id TEXT NOT NULL
		);
		CREATE TABLE certificates (
			id       TEXT PRIMARY KEY,
			user_id  TEXT NOT NULL,
			vault_id TEXT NOT NULL
		);
		CREATE TABLE role_assignments (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			role           TEXT NOT NULL,
			vault_id       TEXT NOT NULL,
			created_by     TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (principal_id, role, vault_id)
		);
	`)
	require.NoError(t, err)

	ids := map[string]string{
		"admin":  "11111111-1111-1111-1111-111111111111",
		"alice":  "22222222-2222-2222-2222-222222222222",
		"bob":    "33333333-3333-3333-3333-333333333333",
		"vaultA": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"vaultB": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
	}

	_, err = conn.Exec(`INSERT INTO users (id, username, role) VALUES (?, 'root', 'admin'), (?, 'alice', 'user'), (?, 'bob', 'user')`,
		ids["admin"], ids["alice"], ids["bob"])
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO vaults (id, name) VALUES (?, 'prod'), (?, 'staging')`,
		ids["vaultA"], ids["vaultB"])
	require.NoError(t, err)

	// Alice owns two secrets in vault A (one principal, one grant) and a key in B.
	_, err = conn.Exec(`INSERT INTO secrets (id, user_id, vault_id) VALUES ('s1', ?, ?), ('s2', ?, ?), ('s3', ?, ?)`,
		ids["alice"], ids["vaultA"], ids["alice"], ids["vaultA"], ids["bob"], ids["vaultB"])
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO keys (id, user_id, vault_id) VALUES ('k1', ?, ?)`,
		ids["alice"], ids["vaultB"])
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO certificates (id, user_id, vault_id) VALUES ('c1', ?, ?)`,
		ids["bob"], ids["vaultA"])
	require.NoError(t, err)

	return conn, ids
}

// TestPlanRoleBackfill asserts the exact derivation: secrets owners become
// Secrets Officer in the owning vault, keys owners Crypto Officer, certificates
// owners Certificates Officer, and every global admin becomes Key Vault
// Administrator in every vault.
func TestPlanRoleBackfill(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)

	grants, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)

	type want struct{ principal, vault, role string }
	got := make([]want, 0, len(grants))
	for _, g := range grants {
		got = append(got, want{g.PrincipalID, g.VaultID, g.Role})
	}

	assert.ElementsMatch(t, []want{
		{ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer},
		{ids["bob"], ids["vaultB"], model.RoleKeyVaultSecretsOfficer},
		{ids["alice"], ids["vaultB"], model.RoleKeyVaultCryptoOfficer},
		{ids["bob"], ids["vaultA"], model.RoleKeyVaultCertificatesOfficer},
		{ids["admin"], ids["vaultA"], model.RoleKeyVaultAdministrator},
		{ids["admin"], ids["vaultB"], model.RoleKeyVaultAdministrator},
	}, got)

	// Vault names are resolved for readable preview output and summary logging.
	names := map[string]string{}
	for _, g := range grants {
		names[g.VaultID] = g.VaultName
	}
	assert.Equal(t, "prod", names[ids["vaultA"]])
	assert.Equal(t, "staging", names[ids["vaultB"]])
}

// TestPlanRoleBackfillIsStable asserts the output order is deterministic so a
// preview run and the migration report the same thing in the same sequence.
func TestPlanRoleBackfillIsStable(t *testing.T) {
	conn, _ := seedPreMigrationDB(t)
	first, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	second, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	assert.Equal(t, first, second)
}

// TestPlanRoleBackfillSkipsUnknownVault asserts an object whose vault_id has no
// vaults row produces no grant. role_assignments has a foreign key to vaults, so
// such a grant would fail to insert on PostgreSQL.
func TestPlanRoleBackfillSkipsUnknownVault(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	_, err := conn.Exec(`INSERT INTO secrets (id, user_id, vault_id) VALUES ('orphan', ?, 'cccccccc-cccc-cccc-cccc-cccccccccccc')`,
		ids["alice"])
	require.NoError(t, err)

	grants, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	for _, g := range grants {
		assert.NotEqual(t, "cccccccc-cccc-cccc-cccc-cccccccccccc", g.VaultID)
	}
}

// TestPlanRoleBackfillSkipsMissingColumns asserts a source table lacking the
// ownership columns is skipped rather than failing the whole migration. Old
// databases predate secrets.vault_id.
func TestPlanRoleBackfillSkipsMissingColumns(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Exec(`
		CREATE TABLE vaults (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT NOT NULL);
		INSERT INTO vaults (id, name) VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'prod');
	`)
	require.NoError(t, err)

	grants, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	assert.Empty(t, grants)
}

// TestPlanRoleBackfillNoVaults returns nothing when the vaults table is empty.
func TestPlanRoleBackfillNoVaults(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Exec(`CREATE TABLE vaults (id TEXT PRIMARY KEY, name TEXT NOT NULL)`)
	require.NoError(t, err)

	grants, err := PlanRoleBackfill(context.Background(), NewConn(conn, SQLite), SQLite)
	require.NoError(t, err)
	assert.Empty(t, grants)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestPlanRoleBackfill`

Expected: FAIL — `undefined: PlanRoleBackfill`.

- [ ] **Step 3: Write `internal/db/role_backfill.go`**

```go
package db

import (
	"context"
	"fmt"
	"sort"

	"rocketvault/model"
)

// RoleBackfillGrant is one (principal, role, vault) assignment the P2 upgrade
// migration would create. Source records which ownership table implied it, so
// an operator reviewing a preview can tell a derived grant from an admin grant.
type RoleBackfillGrant struct {
	PrincipalID string
	VaultID     string
	VaultName   string
	Role        string
	Source      string
}

// ownershipBackfillSource pairs an ownership table with the Azure role its
// owners receive in the vault holding the objects they own.
type ownershipBackfillSource struct {
	Table string
	Role  string
}

// ownershipBackfillSources is the mapping from spec section 6.3 steps 1 and 2.
var ownershipBackfillSources = []ownershipBackfillSource{
	{Table: "secrets", Role: model.RoleKeyVaultSecretsOfficer},
	{Table: "keys", Role: model.RoleKeyVaultCryptoOfficer},
	{Table: "certificates", Role: model.RoleKeyVaultCertificatesOfficer},
}

// PlanRoleBackfill derives the role assignments the P2 upgrade migration would
// create from existing object ownership. It writes nothing, so the migration and
// the "rocketvault vaults preview-migration" command run the same computation
// and an operator's preview is exactly what the upgrade will do.
//
// Derivation, per spec section 6.3:
//  1. Each distinct secrets.user_id owning rows in a vault -> Key Vault Secrets Officer there.
//  2. Same for keys -> Key Vault Crypto Officer and certificates -> Key Vault Certificates Officer.
//  3. Every user holding the global admin role -> Key Vault Administrator in every vault.
//
// A source table missing its ownership columns is skipped: migrateSchema runs
// against arbitrary old shapes, and secrets.user_id predates secrets.vault_id.
// A vault_id with no vaults row is skipped too, because role_assignments has a
// foreign key to vaults(id).
//
// The result is sorted by (vault name, role, principal) so output is stable.
func PlanRoleBackfill(ctx context.Context, q DBTX, dialect Dialect) ([]RoleBackfillGrant, error) {
	vaultNames, err := vaultNamesByID(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(vaultNames) == 0 {
		return nil, nil
	}

	type grantKey struct{ principal, vault, role string }
	seen := map[grantKey]bool{}
	var grants []RoleBackfillGrant

	add := func(principal, vault, role, source string) {
		name, known := vaultNames[vault]
		if principal == "" || vault == "" || !known {
			return
		}
		k := grantKey{principal, vault, role}
		if seen[k] {
			return
		}
		seen[k] = true
		grants = append(grants, RoleBackfillGrant{
			PrincipalID: principal,
			VaultID:     vault,
			VaultName:   name,
			Role:        role,
			Source:      source,
		})
	}

	for _, src := range ownershipBackfillSources {
		usable, err := hasOwnershipColumns(ctx, q, dialect, src.Table)
		if err != nil {
			return nil, err
		}
		if !usable {
			continue
		}
		if err := scanOwnership(ctx, q, src, add); err != nil {
			return nil, err
		}
	}

	adminIDs, err := globalAdminIDs(ctx, q, dialect)
	if err != nil {
		return nil, err
	}
	for _, adminID := range adminIDs {
		for vaultID := range vaultNames {
			add(adminID, vaultID, model.RoleKeyVaultAdministrator, "global-admin")
		}
	}

	sort.Slice(grants, func(i, j int) bool {
		if grants[i].VaultName != grants[j].VaultName {
			return grants[i].VaultName < grants[j].VaultName
		}
		if grants[i].Role != grants[j].Role {
			return grants[i].Role < grants[j].Role
		}
		return grants[i].PrincipalID < grants[j].PrincipalID
	})
	return grants, nil
}

// vaultNamesByID returns every vault id mapped to its name.
func vaultNamesByID(ctx context.Context, q DBTX) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name FROM vaults`)
	if err != nil {
		return nil, fmt.Errorf("list vaults for role backfill: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan vault for role backfill: %w", err)
		}
		out[id] = name
	}
	return out, rows.Err()
}

// hasOwnershipColumns reports whether the table carries both ownership columns
// the backfill reads. A table missing either is skipped, not an error.
func hasOwnershipColumns(ctx context.Context, q DBTX, dialect Dialect, table string) (bool, error) {
	hasUser, err := dialect.ColumnExists(ctx, q, table, "user_id")
	if err != nil {
		return false, fmt.Errorf("inspect %s.user_id: %w", table, err)
	}
	if !hasUser {
		return false, nil
	}
	hasVault, err := dialect.ColumnExists(ctx, q, table, "vault_id")
	if err != nil {
		return false, fmt.Errorf("inspect %s.vault_id: %w", table, err)
	}
	return hasVault, nil
}

// scanOwnership walks the distinct (owner, vault) pairs in one source table.
// The table name is a compile-time constant from ownershipBackfillSources, never
// caller input, so interpolating it introduces no injection surface.
func scanOwnership(ctx context.Context, q DBTX, src ownershipBackfillSource,
	add func(principal, vault, role, source string)) error {
	query := fmt.Sprintf(
		`SELECT DISTINCT user_id, vault_id FROM %s WHERE user_id IS NOT NULL AND user_id <> ''`, src.Table)
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("scan %s ownership: %w", src.Table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var userID, vaultID string
		if err := rows.Scan(&userID, &vaultID); err != nil {
			return fmt.Errorf("scan %s ownership row: %w", src.Table, err)
		}
		add(userID, vaultID, src.Role, src.Table)
	}
	return rows.Err()
}

// globalAdminIDs returns the ids of users holding the legacy global admin role.
// A database with no users table yields no admins rather than an error.
func globalAdminIDs(ctx context.Context, q DBTX, dialect Dialect) ([]string, error) {
	hasRole, err := dialect.ColumnExists(ctx, q, "users", "role")
	if err != nil {
		return nil, fmt.Errorf("inspect users.role: %w", err)
	}
	if !hasRole {
		return nil, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT id FROM users WHERE role = ?`, model.RoleAdmin)
	if err != nil {
		return nil, fmt.Errorf("list global admins: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan global admin: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/ -run TestPlanRoleBackfill`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/db/role_backfill.go internal/db/role_backfill_test.go
git commit -S -m "feat(db): derive Azure role assignments from existing ownership

PlanRoleBackfill computes the (principal, role, vault) grants the P2 upgrade
implies: secrets owners become Key Vault Secrets Officer in the owning vault,
keys owners Crypto Officer, certificates owners Certificates Officer, and
global admins become Key Vault Administrator in every vault. It writes
nothing, so the migration and the preview command share one computation.

Source tables missing their ownership columns and vault ids with no vaults row
are skipped: migrateSchema runs against arbitrary old shapes and
role_assignments has a foreign key to vaults.

Refs spec 2026-07-26 section 6.3."
```

---

### Task 7: Apply the Backfill in migrateSchema

**Files:**
- Modify: `internal/db/db.go:817-841` (end of `migrateSchema`, after the `role_assignments` table and index statements)
- Modify: `internal/db/role_backfill.go` (add the writer)
- Modify: `internal/db/migrate_assignment_test.go:29-54` and `:88-113` (both fixtures gain a `users` table)
- Test: `internal/db/role_backfill_migration_test.go`

**Interfaces:**
- Consumes: `db.PlanRoleBackfill` (Task 6), `DBRepository.seedDefaultVault` (`internal/db/db.go:928-946`).
- Produces: `(*DBRepository).backfillRoleAssignments(db *sql.DB) error`, called from `migrateSchema`.

Ordering note: `SetupSchema` (`internal/db/db.go:191-217`) calls `seedDefaultVault` **after** `migrateSchema`, but `role_assignments.vault_id` has a foreign key to `vaults(id)`. The backfill therefore calls the idempotent `seedDefaultVault` itself before writing, so the default vault row exists on PostgreSQL where the foreign key is enforced.

- [ ] **Step 1: Write the failing test**

Create `internal/db/role_backfill_migration_test.go`:

```go
package db

import (
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// TestBackfillRoleAssignments_CreatesDerivedGrants runs the migration writer
// against a seeded pre-migration database and asserts the exact rows produced.
func TestBackfillRoleAssignments_CreatesDerivedGrants(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	repo := NewRepository(logging.InitLogger())

	require.NoError(t, repo.backfillRoleAssignments(conn))

	type row struct{ principal, vault, role string }
	var got []row
	rows, err := conn.Query(`SELECT principal_id, vault_id, role FROM role_assignments`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var r row
		require.NoError(t, rows.Scan(&r.principal, &r.vault, &r.role))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())

	assert.ElementsMatch(t, []row{
		{ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer},
		{ids["bob"], ids["vaultB"], model.RoleKeyVaultSecretsOfficer},
		{ids["alice"], ids["vaultB"], model.RoleKeyVaultCryptoOfficer},
		{ids["bob"], ids["vaultA"], model.RoleKeyVaultCertificatesOfficer},
		{ids["admin"], ids["vaultA"], model.RoleKeyVaultAdministrator},
		{ids["admin"], ids["vaultB"], model.RoleKeyVaultAdministrator},
	}, got)

	// Every backfilled row is attributed to the system actor and typed as a user.
	var nonSystem int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM role_assignments WHERE created_by <> ? OR principal_type <> ?`,
		"00000000-0000-0000-0000-000000000000", string(model.PrincipalTypeUser),
	).Scan(&nonSystem))
	assert.Zero(t, nonSystem)
}

// TestBackfillRoleAssignments_IsIdempotent asserts re-running creates nothing
// new. An upgrade migration runs on every startup.
func TestBackfillRoleAssignments_IsIdempotent(t *testing.T) {
	conn, _ := seedPreMigrationDB(t)
	repo := NewRepository(logging.InitLogger())

	require.NoError(t, repo.backfillRoleAssignments(conn))
	var first int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM role_assignments`).Scan(&first))
	require.Equal(t, 6, first)

	require.NoError(t, repo.backfillRoleAssignments(conn))
	require.NoError(t, repo.backfillRoleAssignments(conn))
	var second int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM role_assignments`).Scan(&second))
	assert.Equal(t, first, second, "re-running the backfill must be a no-op")
}

// TestBackfillRoleAssignments_PreservesOperatorGrants asserts a hand-made
// assignment is neither duplicated nor removed.
func TestBackfillRoleAssignments_PreservesOperatorGrants(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	_, err := conn.Exec(
		`INSERT INTO role_assignments (id, principal_id, principal_type, role, vault_id, created_by)
		 VALUES ('operator-grant', ?, 'user', ?, ?, ?)`,
		ids["alice"], model.RoleKeyVaultSecretsOfficer, ids["vaultA"], ids["admin"])
	require.NoError(t, err)

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.backfillRoleAssignments(conn))

	var n int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM role_assignments WHERE principal_id = ? AND vault_id = ? AND role = ?`,
		ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer).Scan(&n))
	assert.Equal(t, 1, n, "the pre-existing grant must not be duplicated")

	var createdBy string
	require.NoError(t, conn.QueryRow(
		`SELECT created_by FROM role_assignments WHERE id = 'operator-grant'`).Scan(&createdBy))
	assert.Equal(t, ids["admin"], createdBy, "the operator grant must be untouched")
}

// TestMigrateSchema_RunsRoleBackfill asserts the backfill is wired into
// migrateSchema, not merely callable, and stays idempotent through it.
func TestMigrateSchema_RunsRoleBackfill(t *testing.T) {
	conn, ids := seedPreMigrationDB(t)
	// migrateSchema also touches audit_logs and access_policies; provide them.
	_, err := conn.Exec(`
		CREATE TABLE audit_logs (id TEXT PRIMARY KEY);
		CREATE TABLE access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.migrateSchema(conn))
	require.NoError(t, repo.migrateSchema(conn))

	var n int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM role_assignments WHERE principal_id = ? AND vault_id = ? AND role = ?`,
		ids["alice"], ids["vaultA"], model.RoleKeyVaultSecretsOfficer).Scan(&n))
	assert.Equal(t, 1, n)

	// migrateSchema seeds the default vault before the backfill so the foreign
	// key from role_assignments to vaults is satisfiable.
	var defaults int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM vaults WHERE id = ?`, model.DefaultVaultID).Scan(&defaults))
	assert.Equal(t, 1, defaults)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/ -run 'TestBackfillRoleAssignments|TestMigrateSchema_RunsRoleBackfill'`

Expected: FAIL — `repo.backfillRoleAssignments undefined (type *DBRepository has no field or method backfillRoleAssignments)`.

- [ ] **Step 3: Add the writer to `internal/db/role_backfill.go`**

Append to `internal/db/role_backfill.go` (and extend its imports with `"database/sql"`, `"time"`, and `"github.com/google/uuid"`):

```go
// backfillActor is the created_by value stamped on assignments the upgrade
// migration generates. It distinguishes derived grants from operator grants in
// the audit trail.
const backfillActor = "00000000-0000-0000-0000-000000000000"

// backfillRoleAssignments materialises the plan from PlanRoleBackfill. It is
// idempotent: each insert is guarded by a lookup on the same
// (principal_id, role, vault_id) tuple the table's UNIQUE constraint covers, so
// re-running on every startup creates nothing new and never touches a grant an
// operator made by hand.
//
// It runs inside migrateSchema because the fail-closed authorization introduced
// with it would otherwise lock out every existing deployment: before this
// migration no role assignment exists, and after the PolicyMiddleware inversion
// no role assignment means no access.
func (d *DBRepository) backfillRoleAssignments(db *sql.DB) error {
	ctx := context.Background()

	// SetupSchema seeds the default vault after migrateSchema, but
	// role_assignments has a foreign key to vaults(id). Seed it here first; the
	// call is idempotent.
	if err := d.seedDefaultVault(db); err != nil {
		return fmt.Errorf("seed default vault before role backfill: %w", err)
	}

	grants, err := PlanRoleBackfill(ctx, NewConn(db, d.dialect), d.dialect)
	if err != nil {
		return fmt.Errorf("plan role backfill: %w", err)
	}
	if len(grants) == 0 {
		return nil
	}

	created := map[string]int{}
	examined := map[string]int{}
	names := map[string]string{}
	for _, g := range grants {
		examined[g.VaultID]++
		names[g.VaultID] = g.VaultName

		var existing int
		if err := db.QueryRow(d.dialect.Rebind(
			`SELECT COUNT(*) FROM role_assignments WHERE principal_id = ? AND role = ? AND vault_id = ?`),
			g.PrincipalID, g.Role, g.VaultID).Scan(&existing); err != nil {
			return fmt.Errorf("check existing assignment for %s in %s: %w", g.PrincipalID, g.VaultID, err)
		}
		if existing > 0 {
			continue
		}
		if _, err := db.Exec(d.dialect.Rebind(
			`INSERT INTO role_assignments (id, principal_id, principal_type, role, vault_id, created_by, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`),
			uuid.NewString(), g.PrincipalID, string(model.PrincipalTypeUser),
			g.Role, g.VaultID, backfillActor, time.Now().UTC(),
		); err != nil {
			return fmt.Errorf("insert backfilled assignment for %s in %s: %w", g.PrincipalID, g.VaultID, err)
		}
		created[g.VaultID]++
	}

	// One summary line per vault, so an upgrade leaves an auditable record of
	// exactly what authority it handed out.
	vaultIDs := make([]string, 0, len(examined))
	for id := range examined {
		vaultIDs = append(vaultIDs, id)
	}
	sort.Strings(vaultIDs)
	for _, id := range vaultIDs {
		d.log.Info(fmt.Sprintf(
			"Role backfill: vault=%s (%s) grants_examined=%d assignments_created=%d",
			names[id], id, examined[id], created[id]))
	}
	return nil
}
```

- [ ] **Step 4: Call it from `migrateSchema`**

In `internal/db/db.go`, immediately after the `idx_role_assignments_principal_vault` block added in Task 3 and before `d.log.Info("Schema migration completed")`:

```go
	// P2 upgrade: derive per-vault Azure role assignments from existing object
	// ownership. Must run before the deny-by-default PolicyMiddleware takes
	// effect, or every existing deployment loses access to its own data.
	if err := d.backfillRoleAssignments(db); err != nil {
		return fmt.Errorf("backfill role assignments: %w", err)
	}
```

- [ ] **Step 5: Extend the two existing migration fixtures**

In `internal/db/migrate_assignment_test.go`, add a `users` table to the fixture in `TestMigrateSchema_AddsAssignmentIDIdempotent` (lines 29-54) and in `TestMigrate_CreatesRoleAssignmentsTable` (lines 88-113), so `seedDefaultVault` and the admin lookup have a table to read:

```sql
		CREATE TABLE users (
			id       TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			role     TEXT NOT NULL
		);
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/db/`

Expected: PASS

- [ ] **Step 7: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/db/role_backfill.go internal/db/role_backfill_migration_test.go internal/db/db.go internal/db/migrate_assignment_test.go
git commit -S -m "feat(db): backfill Azure role assignments during schema migration

migrateSchema now materialises the derivation from PlanRoleBackfill so that a
deployment upgrading into fail-closed authorization keeps the access it had.
Each insert is guarded by the (principal_id, role, vault_id) tuple, so
re-running on every startup is a no-op and operator-made grants are untouched.
One summary line per vault records grants examined and assignments created.

The default vault is seeded before the backfill because role_assignments has a
foreign key to vaults and SetupSchema seeds it after migrateSchema.

Refs spec 2026-07-26 section 6.3."
```

---

### Task 8: The `vaults preview-migration` Command

**Files:**
- Create: `cmd/vaults/preview_migration.go`
- Create: `cmd/vaults/preview_migration_test.go`
- Modify: `cmd/vaults.go:47-57` (`init`)
- Modify: `cmd/root.go:140-151` (`systemCmds` map)

**Interfaces:**
- Consumes: `db.PlanRoleBackfill`, `db.RoleBackfillGrant` (Task 6); `db.NewRepository`, `(*db.DBRepository).LoadDatabaseConfig`, `(*db.DBRepository).OpenDatabase`, `db.NewConn`, `db.DialectFromDriver`.
- Produces: `vaults.InitVaultsPreviewMigration(vaultsCmd *cobra.Command) *cobra.Command`; `vaults.previewMigrationRows(grants []rvdb.RoleBackfillGrant) ([]string, [][]string)`.

The command must not trigger the migration it previews. `persistentPreRun` in `cmd/root.go` calls `database.InitializeDB()` for every command, which runs `SetupSchema` and therefore the backfill. Cobra lets a child command replace the inherited `PersistentPreRunE`, so this command installs its own that sets up only the logger and the output formatter and never opens the schema path.

- [ ] **Step 1: Write the failing test**

Create `cmd/vaults/preview_migration_test.go`:

```go
package vaults

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/model"
)

// TestPreviewMigrationRows renders one row per grant, in the order
// PlanRoleBackfill produced, with the vault name first so an operator can scan
// per vault.
func TestPreviewMigrationRows(t *testing.T) {
	grants := []rvdb.RoleBackfillGrant{
		{PrincipalID: "22222222-2222-2222-2222-222222222222", VaultID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			VaultName: "prod", Role: model.RoleKeyVaultSecretsOfficer, Source: "secrets"},
		{PrincipalID: "11111111-1111-1111-1111-111111111111", VaultID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			VaultName: "prod", Role: model.RoleKeyVaultAdministrator, Source: "global-admin"},
	}

	headers, rows := previewMigrationRows(grants)
	assert.Equal(t, []string{"Vault", "VaultID", "Principal", "Role", "DerivedFrom"}, headers)
	require.Len(t, rows, 2)
	assert.Equal(t, []string{
		"prod", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"22222222-2222-2222-2222-222222222222",
		model.RoleKeyVaultSecretsOfficer, "secrets",
	}, rows[0])
	assert.Equal(t, []string{
		"prod", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"11111111-1111-1111-1111-111111111111",
		model.RoleKeyVaultAdministrator, "global-admin",
	}, rows[1])
}

// TestPreviewMigrationRowsEmpty returns headers and no rows, never nil rows,
// so the formatter renders an empty table instead of failing.
func TestPreviewMigrationRowsEmpty(t *testing.T) {
	headers, rows := previewMigrationRows(nil)
	assert.Len(t, headers, 5)
	assert.NotNil(t, rows)
	assert.Empty(t, rows)
}

// TestInitVaultsPreviewMigrationRegisters asserts the command is attached with
// its own PersistentPreRunE, so the root pre-run does not initialise (and
// therefore migrate) the database before the preview reads it.
func TestInitVaultsPreviewMigrationRegisters(t *testing.T) {
	root := &cobra.Command{Use: "vaults"}
	InitVaultsPreviewMigration(root)

	var found *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "preview-migration" {
			found = c
		}
	}
	require.NotNil(t, found, "preview-migration must be registered under vaults")
	assert.NotNil(t, found.PersistentPreRunE,
		"preview-migration must override the root pre-run so it does not migrate the database")
	assert.NotNil(t, found.RunE)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/vaults/ -run 'TestPreviewMigrationRows|TestInitVaultsPreviewMigrationRegisters'`

Expected: FAIL — `undefined: previewMigrationRows`, `undefined: InitVaultsPreviewMigration`.

- [ ] **Step 3: Write `cmd/vaults/preview_migration.go`**

```go
package vaults

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/common"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
)

// previewMigrationCmd prints the role assignments the P2 upgrade would create.
var previewMigrationCmd = &cobra.Command{
	Use:   "preview-migration",
	Short: "Preview the role assignments the authorization upgrade would create",
	Long: `Print the per-vault Azure role assignments the authorization upgrade would
derive from existing object ownership, without writing anything.

The upgrade inverts authorization to deny-by-default: a principal holding no
role assignment in a vault is refused access to every object in it. Run this
first and confirm that every principal that needs access appears in the output
for the vaults it needs.

Derivation:
  secrets owners       -> Key Vault Secrets Officer in the owning vault
  keys owners          -> Key Vault Crypto Officer in the owning vault
  certificates owners  -> Key Vault Certificates Officer in the owning vault
  global admins        -> Key Vault Administrator in every vault`,
	Example: `  # Preview the assignments the upgrade would create
  rocketvault vaults preview-migration

  # Machine-readable output
  rocketvault vaults preview-migration --output json`,
	// Replace the root PersistentPreRunE. The root pre-run calls InitializeDB,
	// which runs the very migration this command exists to preview, so inheriting
	// it would make the preview report an already-applied state.
	PersistentPreRunE: previewMigrationPreRun,
	RunE:              runPreviewMigration,
}

// previewMigrationPreRun installs the logger and output formatter without
// opening or migrating the database.
func previewMigrationPreRun(cmd *cobra.Command, _ []string) error {
	log := logging.InitLogger()

	outputFlag, _ := cmd.Flags().GetString("output")
	fmtr, err := formatter.New(formatter.Format(outputFlag))
	if err != nil {
		return fmt.Errorf("invalid --output value %q: must be table, json, or yaml", outputFlag)
	}

	ctx := context.WithValue(cmd.Context(), common.LogKey, log)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
	cmd.SetContext(ctx)
	return nil
}

// runPreviewMigration opens the configured database read-only in effect (it
// issues no writes), derives the plan, and renders it.
func runPreviewMigration(cmd *cobra.Command, _ []string) error {
	log := logging.InitLogger()
	repository := rvdb.NewRepository(log)

	dbConfig, err := repository.LoadDatabaseConfig()
	if err != nil {
		return fmt.Errorf("failed to load database config: %w", err)
	}
	database, err := repository.OpenDatabase(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	dialect := rvdb.DialectFromDriver(dbConfig.DriverName)
	grants, err := rvdb.PlanRoleBackfill(ctx, rvdb.NewConn(database, dialect), dialect)
	if err != nil {
		return fmt.Errorf("failed to plan role backfill: %w", err)
	}

	fmtr, ok := cmd.Context().Value(common.OutputFormatterKey).(formatter.Formatter)
	if !ok {
		return fmt.Errorf("output formatter not available in context")
	}
	headers, rows := previewMigrationRows(grants)
	return fmtr.Write(cmd.OutOrStdout(), headers, rows)
}

// previewMigrationRows renders the plan as a table. The order is the order
// PlanRoleBackfill produced, which is sorted by vault name, then role, then
// principal, so the preview and the migration's summary agree.
func previewMigrationRows(grants []rvdb.RoleBackfillGrant) ([]string, [][]string) {
	headers := []string{"Vault", "VaultID", "Principal", "Role", "DerivedFrom"}
	rows := make([][]string, 0, len(grants))
	for _, g := range grants {
		rows = append(rows, []string{g.VaultName, g.VaultID, g.PrincipalID, g.Role, g.Source})
	}
	return headers, rows
}

// InitVaultsPreviewMigration registers the preview-migration command under the
// vaults command group.
func InitVaultsPreviewMigration(vaultsCmd *cobra.Command) *cobra.Command {
	vaultsCmd.AddCommand(previewMigrationCmd)
	return vaultsCmd
}
```

- [ ] **Step 4: Register the command**

In `cmd/vaults.go`, add to `init()` after `vaults.InitVaultsPurge(vaultsCmd)`:

```go
	vaults.InitVaultsPreviewMigration(vaultsCmd)
```

In `cmd/root.go`, add to the `systemCmds` map so the command needs no credentials:

```go
		"preview-migration": true, // Reads ownership to plan role assignments; no auth, no writes
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go build ./... && go test ./cmd/vaults/`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add cmd/vaults/preview_migration.go cmd/vaults/preview_migration_test.go cmd/vaults.go cmd/root.go
git commit -S -m "feat(cmd): add vaults preview-migration

Print the per-vault role assignments the authorization upgrade would derive
from existing ownership, so an operator can confirm nobody loses access before
the deny-by-default middleware takes effect. It writes nothing and shares one
derivation with the migration itself.

The command installs its own PersistentPreRunE: the root pre-run calls
InitializeDB, which would apply the very migration being previewed.

Refs spec 2026-07-26 section 6.3."
```

---

### Task 9: Invert PolicyMiddleware to Deny-by-Default

**Files:**
- Modify: `internal/middleware/middleware.go:46-55` (`Container` interface), `:397-463` (`PolicyMiddleware`)
- Test: `internal/middleware/middleware_test.go:30-76` (mock container), append new tests

**Interfaces:**
- Consumes: `authorization.MapRouteToDataAction`, `authorization.RouteVaultData`, `authorization.RouteUnmanaged` (Task 2); `authorization.RoleAssignmentService.HasDataAction` (Task 5); `model.DefaultVaultID`.
- Produces: `Container.GetRoleAssignmentService() authzServices.RoleAssignmentService`; the inverted `PolicyMiddleware`.

Evaluation order, per spec §6.2: the `access_policies` explicit-deny override is checked **first**, then the deny-by-default role-assignment allow decision. Routes that are not vault data-plane routes keep today's `AccessFallback` pass-through, because their gates live in the handlers (`requireVaultManage`) and in `AuthorizationMiddleware`.

This task and Tasks 6-7 must ship in the same release.

- [ ] **Step 1: Write the failing test**

Append to `internal/middleware/middleware_test.go`:

```go
// MockRoleAssignmentService is a mock implementation of RoleAssignmentService.
type MockRoleAssignmentService struct {
	mock.Mock
}

func (m *MockRoleAssignmentService) AssignRole(ctx context.Context, in authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error {
	args := m.Called(ctx, assignmentID, vaultID)
	return args.Error(0)
}

func (m *MockRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	args := m.Called(ctx, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	args := m.Called(ctx, principalID, vaultID, action)
	return args.Bool(0), args.Error(1)
}

// setupDataPlaneMiddlewareTest wires middleware with both authorization services.
func setupDataPlaneMiddlewareTest(t *testing.T) (*Middleware, *MockAccessPolicyService, *MockRoleAssignmentService) {
	t.Helper()
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)

	mockContainer := &MockServiceContainer{logger: logger}
	mockPolicySvc := &MockAccessPolicyService{}
	mockRoleSvc := &MockRoleAssignmentService{}
	mockContainer.On("GetAccessPolicyService").Return(mockPolicySvc)
	mockContainer.On("GetRoleAssignmentService").Return(mockRoleSvc)

	return NewMiddleware(mockContainer), mockPolicySvc, mockRoleSvc
}

// dataPlaneRequest builds an authenticated request carrying a resolved vault.
func dataPlaneRequest(method, path string, userID, vaultID uuid.UUID) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), common.UserIDKey, userID.String())
	ctx = context.WithValue(ctx, common.VaultIDKey, vaultID.String())
	return req.WithContext(ctx)
}

// TestPolicyMiddleware_DeniesWithoutRoleAssignment is the core inversion: a
// principal with no role assignment granting the action in the resolved vault
// gets 403, where before P2 the absence of any policy row let the request
// through.
func TestPolicyMiddleware_DeniesWithoutRoleAssignment(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionSecretsGet).
		Return(false, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(next).ServeHTTP(rr, dataPlaneRequest(http.MethodGet, "/api/v1/secrets/abc", userID, vaultID))

	assert.False(t, nextCalled, "a principal with no role assignment must not reach the handler")
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestPolicyMiddleware_AllowsWithRoleAssignment asserts the granted path.
func TestPolicyMiddleware_AllowsWithRoleAssignment(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionSecretsGet).
		Return(true, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(next).ServeHTTP(rr, dataPlaneRequest(http.MethodGet, "/api/v1/secrets/abc", userID, vaultID))

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestPolicyMiddleware_ExplicitDenyBeatsRoleAssignment asserts access_policies
// survives as an explicit-deny override evaluated before the allow decision:
// the role check is never even reached.
func TestPolicyMiddleware_ExplicitDenyBeatsRoleAssignment(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessDenied, nil)

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rr, dataPlaneRequest(http.MethodGet, "/api/v1/secrets/abc", userID, vaultID))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestPolicyMiddleware_LookupErrorDeniesWith500 asserts a role lookup failure
// fails closed with 500 rather than being read as a permission denial or,
// worse, a pass-through.
func TestPolicyMiddleware_LookupErrorDeniesWith500(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, vaultID, model.ActionSecretsGet).
		Return(false, fmt.Errorf("database is locked"))

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(next).ServeHTTP(rr, dataPlaneRequest(http.MethodGet, "/api/v1/secrets/abc", userID, vaultID))

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestPolicyMiddleware_UnmappedDataPlaneMethodDenies asserts a data-plane path
// with no action mapping is refused rather than allowed.
func TestPolicyMiddleware_UnmappedDataPlaneMethodDenies(t *testing.T) {
	t.Parallel()
	mw, policySvc, _ := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, vaultID).
		Return(authzServices.AccessFallback, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(next).ServeHTTP(rr, dataPlaneRequest(http.MethodPatch, "/api/v1/secrets/abc", userID, vaultID))

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// TestPolicyMiddleware_FlatRouteUsesDefaultVault asserts a legacy flat route
// with no resolved vault in context is evaluated against the default vault, so
// flat and vault-scoped routes carry identical semantics.
func TestPolicyMiddleware_FlatRouteUsesDefaultVault(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID := uuid.New()
	defaultVault := uuid.MustParse(model.DefaultVaultID)
	policySvc.On("CheckAccess", mock.Anything, userID, mock.Anything, mock.Anything, defaultVault).
		Return(authzServices.AccessFallback, nil)
	roleSvc.On("HasDataAction", mock.Anything, userID, defaultVault, model.ActionSecretsReadMetadata).
		Return(true, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	req = req.WithContext(context.WithValue(req.Context(), common.UserIDKey, userID.String()))

	nextCalled := false
	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
	roleSvc.AssertCalled(t, "HasDataAction", mock.Anything, userID, defaultVault, model.ActionSecretsReadMetadata)
}

// TestPolicyMiddleware_VaultManagementKeepsFallback asserts non-data-plane
// managed routes are unchanged: their gates are requireVaultManage and the RBAC
// middleware, not per-vault role assignments.
func TestPolicyMiddleware_VaultManagementKeepsFallback(t *testing.T) {
	t.Parallel()
	mw, policySvc, roleSvc := setupDataPlaneMiddlewareTest(t)

	userID, vaultID := uuid.New(), uuid.New()
	policySvc.On("CheckAccess", mock.Anything, userID, model.PolicyResourceVaults, model.OpManage, vaultID).
		Return(authzServices.AccessFallback, nil)

	nextCalled := false
	rr := httptest.NewRecorder()
	mw.PolicyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, dataPlaneRequest(http.MethodDelete, "/api/v1/vaults/prod", userID, vaultID))

	assert.True(t, nextCalled, "vault management keeps AccessFallback pass-through")
	assert.Equal(t, http.StatusOK, rr.Code)
	roleSvc.AssertNotCalled(t, "HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

Also update the existing pre-P2 tests that assert pass-through on data-plane routes. `TestPolicyMiddleware_FallbackPassesThrough` (`:900-924`) and `TestPolicyMiddleware_ExplicitAllowPassesThrough` (`:950-973`) use `/api/v1/secrets/some-id`; the inversion is exactly what makes those pass-throughs wrong. Rewrite both to point at `/api/v1/vaults/prod` (a management route, still fallback-governed) and keep their assertions unchanged, so the pre-existing fallback semantics stay pinned where they still apply.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/middleware/ -run TestPolicyMiddleware`

Expected: FAIL — `*MockServiceContainer does not implement Container (missing method GetRoleAssignmentService)`.

- [ ] **Step 3: Extend the Container interface and the mock**

In `internal/middleware/middleware.go`, add to `Container` (after line 52):

```go
	GetRoleAssignmentService() authzServices.RoleAssignmentService
```

In `internal/middleware/middleware_test.go`, add to `MockServiceContainer`:

```go
func (m *MockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(authzServices.RoleAssignmentService)
}
```

- [ ] **Step 4: Rewrite PolicyMiddleware**

Replace `internal/middleware/middleware.go:397-463` with:

```go
// PolicyMiddleware authorizes every request against the vault resolved by
// VaultResolutionMiddleware. It must run after AuthenticationMiddleware so that
// common.UserIDKey is set.
//
// Vault data-plane routes are DENY-BY-DEFAULT: the route maps to a single Azure
// data action, and the caller must hold a role assignment granting that action
// in that specific vault. No matching assignment is a 403. This is the P2
// inversion; before it, zero matching policy rows meant "continue".
//
// access_policies survives only as an explicit-deny override and is evaluated
// FIRST, so a deny cannot be outvoted by a role grant.
//
// Routes that are not vault data-plane routes (vault management, role
// assignments, users, audit) keep the previous AccessFallback pass-through:
// their gates are requireVaultManage in the handlers and AuthorizationMiddleware.
func (m *Middleware) PolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceType, op := resolvePolicy(r.Method, r.URL.Path)
		action, routeKind := authzServices.MapRouteToDataAction(r.Method, r.URL.Path)

		// Unmanaged by both mechanisms — health probes and the like.
		if (resourceType == "" || op == "") && routeKind == authzServices.RouteUnmanaged {
			next.ServeHTTP(w, r)
			return
		}

		// Extract caller identity set by AuthenticationMiddleware.
		userIDStr, ok := r.Context().Value(common.UserIDKey).(string)
		if !ok || userIDStr == "" {
			m.logger.LogAuditError("", "policy", "failed", "Missing user ID in context for policy check", nil)
			http.Error(w, "Forbidden: missing identity", http.StatusForbidden)
			return
		}
		principalID, err := uuid.Parse(userIDStr)
		if err != nil {
			m.logger.LogAuditError(userIDStr, "policy", "failed", "Invalid user ID format", err)
			http.Error(w, "Forbidden: invalid identity", http.StatusForbidden)
			return
		}

		// Resolve the target vault. VaultResolutionMiddleware sets this for every
		// route it covers; a legacy flat route with no value resolves to the
		// default vault so flat and vault-scoped routes carry identical semantics.
		vaultIDStr, _ := r.Context().Value(common.VaultIDKey).(string)
		if vaultIDStr == "" {
			vaultIDStr = model.DefaultVaultID
		}
		vaultID, err := uuid.Parse(vaultIDStr)
		if err != nil {
			m.logger.LogAuditError(userIDStr, "policy", "failed", "Invalid vault ID in context", err)
			http.Error(w, "Forbidden: invalid vault", http.StatusForbidden)
			return
		}

		// Use the route template for richer audit logs when available.
		routeTemplate := r.URL.Path
		if route := mux.CurrentRoute(r); route != nil {
			if tmpl, err2 := route.GetPathTemplate(); err2 == nil {
				routeTemplate = tmpl
			}
		}

		// 1. Explicit-deny override, evaluated before any allow decision.
		decision := authzServices.AccessFallback
		if resourceType != "" && op != "" {
			decision, err = m.container.GetAccessPolicyService().
				CheckAccess(r.Context(), principalID, resourceType, op, vaultID)
			if err != nil {
				m.logger.LogAuditError(userIDStr, "policy", "error",
					"Access policy check failed — denying request", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if decision == authzServices.AccessDenied {
				m.logger.LogAuditError(userIDStr, "policy", "denied",
					fmt.Sprintf("Access denied by explicit policy: %s %s (resource=%s op=%s)",
						r.Method, routeTemplate, resourceType, op), nil)
				http.Error(w, "Forbidden: access policy denied", http.StatusForbidden)
				return
			}
		}

		// 2. Deny-by-default for vault data-plane routes.
		if routeKind == authzServices.RouteVaultData {
			if action == "" {
				// A data-plane path with no mapped action. Refusing keeps an
				// unrecognised route from becoming an unauthorized one.
				m.logger.LogAuditError(userIDStr, "policy", "denied",
					fmt.Sprintf("No data action mapped for %s %s", r.Method, routeTemplate), nil)
				http.Error(w, "Forbidden: unsupported operation", http.StatusForbidden)
				return
			}
			allowed, err := m.container.GetRoleAssignmentService().
				HasDataAction(r.Context(), principalID, vaultID, action)
			if err != nil {
				m.logger.LogAuditError(userIDStr, "policy", "error",
					"Role assignment lookup failed — denying request", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !allowed {
				m.logger.LogAuditError(userIDStr, "policy", "denied",
					fmt.Sprintf("Access denied: %s %s (action=%s vault=%s)",
						r.Method, routeTemplate, action, vaultID), nil)
				http.Error(w, "Forbidden: no role assignment grants this operation in this vault",
					http.StatusForbidden)
				return
			}
			m.logger.LogAuditInfo(userIDStr, "policy", "allowed",
				fmt.Sprintf("Access allowed: %s %s (action=%s vault=%s)",
					r.Method, routeTemplate, action, vaultID))
			next.ServeHTTP(w, r)
			return
		}

		// 3. Non-data-plane managed routes keep the previous semantics.
		if decision == authzServices.AccessAllowed {
			m.logger.LogAuditInfo(userIDStr, "policy", "allowed",
				fmt.Sprintf("Access allowed: %s %s (resource=%s op=%s)",
					r.Method, routeTemplate, resourceType, op))
		}
		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/middleware/`

Expected: PASS

- [ ] **Step 6: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS. API-level tests that exercise the full middleware chain and previously relied on pass-through will now need a role assignment; update them to seed one rather than to weaken the middleware.

- [ ] **Step 7: Commit**

```bash
git add internal/middleware/middleware.go internal/middleware/middleware_test.go
git commit -S -m "feat(middleware): deny vault data-plane requests without a role assignment

PolicyMiddleware now maps every resource route to an Azure data action and
requires a role assignment granting it in the resolved vault. No assignment is
a 403, where before zero matching policy rows meant continue, which is how any
principal with a global permission could operate on any vault by name.

access_policies is retained as an explicit-deny override and is evaluated
first, so a deny cannot be outvoted by a role grant. A lookup failure answers
500. Flat routes resolve to the default vault and carry identical semantics.

This commit is only safe alongside the role-assignment backfill in
migrateSchema; shipping it alone locks out every existing deployment.

Refs spec 2026-07-26 section 6.2."
```

---

### Task 10: Make mapEndpointToPermission Vault-Aware

**Files:**
- Modify: `internal/services/authorization/rbac_service.go:220-312` (`mapEndpointToPermission`)
- Modify: `internal/services/authorization/rbac_vault_routes_test.go`
- Modify: `api/keys.go:246-252` (`createKey` role guard)
- Modify: `api/certificates.go:131-138` (`createCertificate` role guard)
- Test: `internal/services/authorization/rbac_vault_routes_test.go`

**Interfaces:**
- Consumes: `authorization.MapRouteToDataAction`, `authorization.RouteVaultData` (Task 2).
- Produces: `mapEndpointToPermission` returning `""` for vault data-plane routes and `PermissionManageVaults` for vault management routes.

Today `mapEndpointToPermission` strips `vaults/{name}/` and maps the route onto the same **global** permission as its flat equivalent, which is precisely why RBAC is vault-agnostic by construction (spec §6.1). After Task 9 those routes are authorized by the per-vault data-action check, so the global role gate on them must go: keeping it would deny a `Key Vault Crypto Officer` in vault X the ability to create a key there merely because their global role is `user`. Vault management and user management keep their global permissions.

The two handler-level guards are the same contradiction one layer up: `createKey` requires the global `admin` or `secrets_manager` role and `createCertificate` requires `admin` or `certificate_manager`, so a per-vault Crypto Officer or Certificates Officer could never create anything. Both are removed here; the per-vault role assignment is now the authoritative gate.

- [ ] **Step 1: Write the failing test**

Replace the body of `TestValidateEndpointAccess_VaultScopedResourceRoutes` in `internal/services/authorization/rbac_vault_routes_test.go` with:

```go
// TestValidateEndpointAccess_DataPlaneRoutesDelegate asserts that vault
// data-plane routes no longer consult the caller's global role. They are
// authorized by PolicyMiddleware against the caller's role assignments in the
// resolved vault, so the global RBAC layer must not second-guess that decision:
// a Key Vault Crypto Officer whose global role is "user" must be able to create
// a key in the vault they hold the role in.
func TestValidateEndpointAccess_DataPlaneRoutesDelegate(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	paths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/vaults/prod/secrets"},
		{"DELETE", "/api/v1/vaults/prod/secrets/abc"},
		{"PUT", "/api/v1/vaults/prod/keys/abc"},
		{"POST", "/api/v1/vaults/prod/keys"},
		{"DELETE", "/api/v1/vaults/prod/certificates/abc"},
		{"POST", "/api/v1/vaults/prod/keys/abc/sign"},
		{"DELETE", "/api/v1/vaults/prod/deleted/secrets/abc/purge"},
		{"POST", "/api/v1/secrets"},
		{"GET", "/api/v1/secrets/abc"},
		{"POST", "/api/v1/keys"},
		{"DELETE", "/api/v1/certificates/abc"},
	}
	roles := []string{
		model.RoleUser, model.RoleServiceAccount, model.RoleSecretsManager,
		model.RoleCryptoManager, model.RoleCertificateManager, model.RoleAdmin,
	}

	for _, p := range paths {
		for _, role := range roles {
			t.Run(role+" "+p.method+" "+p.path, func(t *testing.T) {
				if err := svc.ValidateEndpointAccess(role, p.method, p.path); err != nil {
					t.Fatalf("data-plane routes must not be gated by the global role, got %v", err)
				}
			})
		}
	}
}

// TestMapEndpointToPermission_DataPlaneReturnsEmpty pins the mapping directly,
// so a future edit cannot reintroduce a global permission on a data-plane route
// without failing here.
func TestMapEndpointToPermission_DataPlaneReturnsEmpty(t *testing.T) {
	svc := NewRBACService(logging.InitLogger()).(*rbacService)
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/vaults/prod/secrets"},
		{"GET", "/api/v1/vaults/prod/keys"},
		{"PUT", "/api/v1/certificates/abc"},
		{"GET", "/api/v1/deleted/secrets"},
	} {
		if got := svc.mapEndpointToPermission(c.method, c.path); got != "" {
			t.Fatalf("mapEndpointToPermission(%s, %s) = %q, want empty", c.method, c.path, got)
		}
	}
}
```

`TestValidateEndpointAccess_VaultManagementRoutes` is unchanged and must keep passing: vault management is still gated by `vaults:manage`. Add to it:

```go
	// User management keeps its global permissions; it is not a vault data plane.
	if err := svc.ValidateEndpointAccess(model.RoleUser, "POST", "/api/v1/users"); err == nil {
		t.Fatal("user creation must still require the global users:create permission")
	}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/ -run 'TestValidateEndpointAccess_DataPlaneRoutesDelegate|TestMapEndpointToPermission_DataPlaneReturnsEmpty'`

Expected: FAIL — `data-plane routes must not be gated by the global role, got insufficient permissions: secrets:create required`.

- [ ] **Step 3: Rewrite mapEndpointToPermission**

Replace `internal/services/authorization/rbac_service.go:220-312` with:

```go
// mapEndpointToPermission maps HTTP endpoints to the global permission they
// require. It deliberately answers "" for every vault data-plane route.
//
// Before P2 this function stripped the "vaults/{name}/" prefix and returned the
// same global permission as the flat equivalent, which made RBAC vault-agnostic
// by construction: any principal holding a global permission could operate on
// any vault by name. Those routes are now authorized by PolicyMiddleware
// against the caller's role assignments in the resolved vault, and a second,
// vault-blind gate here would only contradict that decision — a Key Vault
// Crypto Officer in one vault would be refused for holding the global "user"
// role.
//
// Vault management and user management are not data-plane routes and keep their
// global permissions.
func (s *rbacService) mapEndpointToPermission(method, path string) Permission {
	// Vault data-plane routes are authorized per vault, not per global role.
	if _, kind := MapRouteToDataAction(method, path); kind == RouteVaultData {
		return ""
	}

	// Normalize path for comparison.
	path = strings.TrimPrefix(path, "/api/v1")
	path = strings.TrimPrefix(path, "/")

	// A bare "vaults" or "vaults/{name}" path is vault management.
	if strings.HasPrefix(path, "vaults") {
		return PermissionManageVaults
	}

	// Users endpoints.
	if strings.HasPrefix(path, "users") {
		switch method {
		case "POST":
			return PermissionCreateUser
		case "GET":
			if strings.Contains(path, "/") {
				return PermissionReadUser
			}
			return PermissionListUsers
		case "PUT":
			return PermissionUpdateUser
		case "DELETE":
			return PermissionDeleteUser
		}
	}

	// Health and other endpoints don't require specific permissions.
	return ""
}
```

Note: `vaults/{name}/role-assignments` reaches the `strings.HasPrefix(path, "vaults")` branch and requires `vaults:manage`, matching the `requireVaultManage` gate the handlers already apply.

- [ ] **Step 4: Remove the two contradicting handler guards**

In `api/keys.go`, delete lines 247-252 (the `HasRequiredRole(claims, model.RoleAdmin, model.RoleSecretsManager)` block) and replace with:

```go
	// Authorization happens in PolicyMiddleware: creating a key requires the
	// Microsoft.KeyVault/vaults/keys/create data action, granted by Key Vault
	// Crypto Officer or Key Vault Administrator in this vault. A second gate on
	// the caller's global role would contradict that per-vault decision.
```

In `api/certificates.go`, delete lines 133-138 (the `HasRequiredRole(roleStr, model.RoleAdmin, model.RoleCertificateManager)` block) and replace with:

```go
	// Authorization happens in PolicyMiddleware: creating a certificate requires
	// the Microsoft.KeyVault/vaults/certificates/create data action, granted by
	// Key Vault Certificates Officer or Key Vault Administrator in this vault.
```

Remove any import of `rocketvault/common` or `rocketvault/model` from those files that becomes unused. Update the handler tests that assert 403 for a non-admin creator (`api/keys_crud_test.go`, `api/certificates_test.go`): those cases now belong to the middleware and are covered by Task 9's tests, so delete them rather than inverting them.

- [ ] **Step 5: Run test to verify it passes**

Run: `go build ./... && go test ./internal/services/authorization/ ./api/`

Expected: PASS

- [ ] **Step 6: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/services/authorization/rbac_service.go internal/services/authorization/rbac_vault_routes_test.go api/keys.go api/certificates.go api/keys_crud_test.go api/certificates_test.go
git commit -S -m "feat(authorization): stop gating vault data-plane routes on the global role

mapEndpointToPermission no longer strips the vaults/{name}/ prefix and no
longer maps a data-plane route onto a global permission. Those routes are
authorized per vault by PolicyMiddleware, and a second vault-blind gate would
refuse a Key Vault Crypto Officer for holding the global user role.

Remove the same contradiction from createKey and createCertificate, whose
global admin/manager role checks would have made the per-vault officer roles
unusable. Vault and user management keep their global permissions.

Refs spec 2026-07-26 section 6.2."
```

---

### Task 11: Retire ScopeOwner from the Data Plane and Delete the B6 Tests

**Files:**
- Modify: `api/context.go` (delete `ownerScopeFromRequest`; locate by name, added in P1)
- Modify: `api/keys.go` (`signKey`, `verifyKey`, `encryptKey`, `decryptKey`, `wrapKey`, `unwrapKey`, `deleteKey` — the seven `ownerScopeFromRequest` call sites)
- Delete: the P0 B6 regression tests (locate with the grep in Step 1)
- Test: `api/vault_scoped_keys_certs_test.go`

**Interfaces:**
- Consumes: `scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool)` from P1 Task 23.
- Produces: no `ownerScopeFromRequest` symbol anywhere; every resource handler builds `model.ScopeVault`.

Spec §8: the B6 deletion must be its own commit **with** the policy change, never bundled into a refactor commit. This task is therefore exactly one commit containing both the handler change and the test deletion, and nothing else.

`model.ScopeOwner` and its branch in `scopePredicate` are **not** removed: they remain reachable only from `model/scope_test.go` and `internal/repositories/scope_predicate_test.go`, and Step 5 adds a grep gate proving no production call site constructs an owner scope. `model.ScopeAdmin` remains in use for the vault cascade, backup/restore, and the rotation scheduler.

- [ ] **Step 1: Enumerate the call sites and the B6 tests**

Run:

```bash
grep -rn "ownerScopeFromRequest\|NewOwnerScope" --include="*.go" .
grep -rln "B6" --include="*_test.go" api/
```

Record the exact files. Expect seven `ownerScopeFromRequest` call sites in `api/keys.go` (the six crypto operations plus key delete) and the B6 test file(s) added in P0.

- [ ] **Step 2: Write the failing test**

Append to `api/vault_scoped_keys_certs_test.go`:

```go
// TestCryptoOperationsUseVaultScope asserts the crypto handlers authorize by
// vault membership, not by key ownership. This is the deliberate B6 policy
// change: under Azure parity, crypto operations are gated by Key Vault Crypto
// User at vault scope, and the P0 tests that pinned owner-gating are deleted in
// the same commit.
func TestCryptoOperationsUseVaultScope(t *testing.T) {
	owner, caller := uuid.New(), uuid.New()
	vaultID := uuid.New()

	for _, op := range []string{"sign", "verify", "encrypt", "decrypt", "wrap", "unwrap"} {
		t.Run(op, func(t *testing.T) {
			svc := newScopeRecordingKeyService(t)
			c, w, r := newVaultScopedKeyRequest(t, svc, op, owner, caller, vaultID)

			dispatchKeyCryptoHandler(t, op, c, w, r)

			got := svc.lastScope()
			assert.Equal(t, model.ScopeVault, got.Kind(),
				"crypto operations must build a vault scope, not an owner scope")
			assert.Equal(t, vaultID, got.VaultID())
			assert.Equal(t, caller, got.ActorID())
			_, isOwnerScoped := got.OwnerID()
			assert.False(t, isOwnerScoped, "no owner predicate may remain on the data plane")
		})
	}
}

// TestDeleteKeyUsesVaultScope asserts key delete follows the same change.
func TestDeleteKeyUsesVaultScope(t *testing.T) {
	owner, caller := uuid.New(), uuid.New()
	vaultID := uuid.New()

	svc := newScopeRecordingKeyService(t)
	c, w, r := newVaultScopedKeyRequest(t, svc, "delete", owner, caller, vaultID)
	deleteKey(c, w, r)

	got := svc.lastScope()
	assert.Equal(t, model.ScopeVault, got.Kind())
	assert.Equal(t, vaultID, got.VaultID())
	_, isOwnerScoped := got.OwnerID()
	assert.False(t, isOwnerScoped)
}
```

`newScopeRecordingKeyService`, `newVaultScopedKeyRequest` and `dispatchKeyCryptoHandler` are test helpers introduced by P1's handler tests in this file; reuse them. If P1 named them differently, adapt the names — do not add a second recording fake.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./api/ -run 'TestCryptoOperationsUseVaultScope|TestDeleteKeyUsesVaultScope'`

Expected: FAIL — `crypto operations must build a vault scope, not an owner scope: expected ScopeVault, got ScopeOwner`.

- [ ] **Step 4: Switch the handlers and delete `ownerScopeFromRequest`**

In `api/keys.go`, replace every `ownerScopeFromRequest(c, r)` with `scopeFromRequest(c, r)` in `signKey`, `verifyKey`, `encryptKey`, `decryptKey`, `wrapKey`, `unwrapKey`, and `deleteKey`. Both helpers share the signature `(c *Context, r *http.Request) (model.Scope, bool)`, so each call site changes only the function name — the `scope, ok := ...; if !ok { return }` shape is unchanged.

In `api/context.go`, delete the `ownerScopeFromRequest` function entirely and add this note above `scopeFromRequest`:

```go
// scopeFromRequest builds the authorization scope for a resource operation. It
// is the only scope constructor on the data plane: ownership is provenance and
// audit metadata, never an access predicate. Crypto operations are gated by the
// Key Vault Crypto User role at vault scope, not by who created the key.
```

- [ ] **Step 5: Delete the B6 tests and add the CI gate**

Delete the P0 B6 regression tests enumerated in Step 1 in full — the file if it exists solely for B6, otherwise the individual test functions.

Add a gate to the `Build & Test` job in `.github/workflows/go.yml`, immediately before the existing `Build` step (`go.yml:23-24`):

```yaml
      - name: No owner scope on the data plane
        run: |
          if grep -rn "NewOwnerScope\|ownerScopeFromRequest" --include="*.go" . \
               | grep -v "model/scope.go" \
               | grep -v "model/scope_test.go" \
               | grep -v "internal/repositories/scope_predicate_test.go"; then
            echo "owner scope reached the data plane; P2 retired it" >&2
            exit 1
          fi
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go build ./... && go test ./...`

Expected: PASS

- [ ] **Step 7: Commit (one commit: policy change plus test deletion)**

Stage the handler change, the new vault-scope assertions, the CI gate, and the B6 deletions together. Use `git rm` for a file that existed solely for B6; use `git add` for a file from which individual B6 functions were removed. The file list comes from Step 1's grep.

```bash
git add api/context.go api/keys.go api/vault_scoped_keys_certs_test.go .github/workflows/go.yml
git add -u api/          # stages the B6 test deletions enumerated in Step 1
git commit -S -m "feat(api)!: gate crypto operations by vault role, not key ownership

Every resource route now builds a vault scope. ownerScopeFromRequest, which
existed only to mark the owner-gated crypto handlers during the scope refactor,
is deleted along with its seven call sites in sign, verify, encrypt, decrypt,
wrap, unwrap and key delete.

Delete the B6 regression tests in the same commit: they pinned the owner-gating
this change deliberately removes, and the spec requires their deletion to
travel with the policy change rather than hide in a refactor.

BREAKING CHANGE: key crypto operations are authorized by Key Vault Crypto User
at vault scope. A key's creator has no special authority over it.

Refs spec 2026-07-26 sections 6.2 and 8."
```

---

### Task 12: The Authorization Matrix Test

**Files:**
- Create: `internal/services/authorization/authorization_matrix_test.go`

**Interfaces:**
- Consumes: `authorization.MapRouteToDataAction`, `authorization.RouteVaultData` (Task 2); `model.RoleGrantsDataAction` and the seven role constants (Task 1).
- Produces: nothing consumed by later tasks.

Spec §8 requires, for each Azure role, the **exact** set of allowed and denied operations. The table lists every data-plane operation once with the route that reaches it, and each role names its allowed operations in full; everything not named is asserted denied. Adding a route without adding it here leaves the route unlisted, which Step 1's completeness check catches.

- [ ] **Step 1: Write the test**

Create `internal/services/authorization/authorization_matrix_test.go`:

```go
package authorization

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// matrixOp is one data-plane operation, named and addressed by the route that
// performs it. Paths use the vault-scoped shape; the flat shape maps identically.
type matrixOp struct {
	name   string
	method string
	path   string
}

// matrixOps lists every vault data-plane operation exactly once.
var matrixOps = []matrixOp{
	{"secrets.list", http.MethodGet, "/api/v1/vaults/prod/secrets"},
	{"secrets.get", http.MethodGet, "/api/v1/vaults/prod/secrets/abc"},
	{"secrets.create", http.MethodPost, "/api/v1/vaults/prod/secrets"},
	{"secrets.update", http.MethodPut, "/api/v1/vaults/prod/secrets/abc"},
	{"secrets.delete", http.MethodDelete, "/api/v1/vaults/prod/secrets/abc"},
	{"secrets.generate", http.MethodPost, "/api/v1/vaults/prod/secrets/generate"},
	{"secrets.export", http.MethodPost, "/api/v1/vaults/prod/secrets/export"},
	{"secrets.import", http.MethodPost, "/api/v1/vaults/prod/secrets/import"},
	{"secrets.listVersions", http.MethodGet, "/api/v1/vaults/prod/secrets/abc/versions"},
	{"secrets.getVersion", http.MethodGet, "/api/v1/vaults/prod/secrets/abc/versions/3"},
	{"secrets.getLatestVersion", http.MethodGet, "/api/v1/vaults/prod/secrets/abc/versions/latest"},
	{"secrets.backup", http.MethodPost, "/api/v1/vaults/prod/secrets/abc/backup"},
	{"secrets.restore", http.MethodPost, "/api/v1/vaults/prod/secrets/restore"},
	{"secrets.listDeleted", http.MethodGet, "/api/v1/vaults/prod/deleted/secrets"},
	{"secrets.recover", http.MethodPost, "/api/v1/vaults/prod/deleted/secrets/abc/restore"},
	{"secrets.purge", http.MethodDelete, "/api/v1/vaults/prod/deleted/secrets/abc/purge"},

	{"keys.list", http.MethodGet, "/api/v1/vaults/prod/keys"},
	{"keys.get", http.MethodGet, "/api/v1/vaults/prod/keys/abc"},
	{"keys.create", http.MethodPost, "/api/v1/vaults/prod/keys"},
	{"keys.update", http.MethodPut, "/api/v1/vaults/prod/keys/abc"},
	{"keys.delete", http.MethodDelete, "/api/v1/vaults/prod/keys/abc"},
	{"keys.rotate", http.MethodPost, "/api/v1/vaults/prod/keys/abc/rotate"},
	{"keys.listVersions", http.MethodGet, "/api/v1/vaults/prod/keys/abc/versions"},
	{"keys.sign", http.MethodPost, "/api/v1/vaults/prod/keys/abc/sign"},
	{"keys.verify", http.MethodPost, "/api/v1/vaults/prod/keys/abc/verify"},
	{"keys.encrypt", http.MethodPost, "/api/v1/vaults/prod/keys/abc/encrypt"},
	{"keys.decrypt", http.MethodPost, "/api/v1/vaults/prod/keys/abc/decrypt"},
	{"keys.wrap", http.MethodPost, "/api/v1/vaults/prod/keys/abc/wrap"},
	{"keys.unwrap", http.MethodPost, "/api/v1/vaults/prod/keys/abc/unwrap"},
	{"keys.backup", http.MethodPost, "/api/v1/vaults/prod/keys/abc/backup"},
	{"keys.restore", http.MethodPost, "/api/v1/vaults/prod/keys/restore"},
	{"keys.listDeleted", http.MethodGet, "/api/v1/vaults/prod/deleted/keys"},
	{"keys.getDeleted", http.MethodGet, "/api/v1/vaults/prod/deleted/keys/abc"},
	{"keys.recover", http.MethodPost, "/api/v1/vaults/prod/deleted/keys/abc/restore"},
	{"keys.purge", http.MethodDelete, "/api/v1/vaults/prod/deleted/keys/abc/purge"},

	{"certs.list", http.MethodGet, "/api/v1/vaults/prod/certificates"},
	{"certs.get", http.MethodGet, "/api/v1/vaults/prod/certificates/abc"},
	{"certs.create", http.MethodPost, "/api/v1/vaults/prod/certificates"},
	{"certs.update", http.MethodPut, "/api/v1/vaults/prod/certificates/abc"},
	{"certs.delete", http.MethodDelete, "/api/v1/vaults/prod/certificates/abc"},
	{"certs.getPolicy", http.MethodGet, "/api/v1/vaults/prod/certificates/abc/policy"},
	{"certs.setPolicy", http.MethodPut, "/api/v1/vaults/prod/certificates/abc/policy"},
	{"certs.deletePolicy", http.MethodDelete, "/api/v1/vaults/prod/certificates/abc/policy"},
	{"certs.backup", http.MethodPost, "/api/v1/vaults/prod/certificates/abc/backup"},
	{"certs.restore", http.MethodPost, "/api/v1/vaults/prod/certificates/restore"},
	{"certs.listDeleted", http.MethodGet, "/api/v1/vaults/prod/deleted/certificates"},
	{"certs.recover", http.MethodPost, "/api/v1/vaults/prod/deleted/certificates/abc/restore"},
	{"certs.purge", http.MethodDelete, "/api/v1/vaults/prod/deleted/certificates/abc/purge"},
}

// allSecretOps, allKeyOps and allCertOps are named once so the officer roles
// below read as "everything for this object type".
var (
	allSecretOps = []string{
		"secrets.list", "secrets.get", "secrets.create", "secrets.update",
		"secrets.delete", "secrets.generate", "secrets.export", "secrets.import",
		"secrets.listVersions", "secrets.getVersion", "secrets.getLatestVersion",
		"secrets.backup", "secrets.restore", "secrets.listDeleted",
		"secrets.recover", "secrets.purge",
	}
	allKeyOps = []string{
		"keys.list", "keys.get", "keys.create", "keys.update", "keys.delete",
		"keys.rotate", "keys.listVersions", "keys.sign", "keys.verify",
		"keys.encrypt", "keys.decrypt", "keys.wrap", "keys.unwrap",
		"keys.backup", "keys.restore", "keys.listDeleted", "keys.getDeleted",
		"keys.recover", "keys.purge",
	}
	allCertOps = []string{
		"certs.list", "certs.get", "certs.create", "certs.update", "certs.delete",
		"certs.getPolicy", "certs.setPolicy", "certs.deletePolicy",
		"certs.backup", "certs.restore", "certs.listDeleted",
		"certs.recover", "certs.purge",
	}
)

// matrixAllowed names, per role, the exact operations that role permits.
// Every operation absent from a role's list is asserted denied.
var matrixAllowed = map[string][]string{
	model.RoleKeyVaultAdministrator: append(append(append([]string{},
		allSecretOps...), allKeyOps...), allCertOps...),

	model.RoleKeyVaultReader: {
		"secrets.list", "secrets.listVersions", "secrets.listDeleted",
		"keys.list", "keys.get", "keys.listVersions", "keys.listDeleted", "keys.getDeleted",
		"certs.list", "certs.get", "certs.getPolicy", "certs.listDeleted",
	},

	model.RoleKeyVaultSecretsUser: {
		"secrets.list", "secrets.get", "secrets.export",
		"secrets.listVersions", "secrets.getVersion", "secrets.getLatestVersion",
		"secrets.listDeleted",
	},

	model.RoleKeyVaultSecretsOfficer: allSecretOps,

	model.RoleKeyVaultCryptoUser: {
		"keys.list", "keys.get", "keys.listVersions", "keys.listDeleted", "keys.getDeleted",
		"keys.sign", "keys.verify", "keys.encrypt", "keys.decrypt",
		"keys.wrap", "keys.unwrap",
	},

	model.RoleKeyVaultCryptoOfficer: allKeyOps,

	model.RoleKeyVaultCertificatesOfficer: allCertOps,
}

// TestAuthorizationMatrix asserts, for every (role, operation) pair, that the
// role's data actions permit exactly the operations named for it and no others.
func TestAuthorizationMatrix(t *testing.T) {
	require.Len(t, matrixAllowed, 7, "all seven Azure roles must appear in the matrix")

	for _, role := range model.AzureRoleNames() {
		allowedNames, ok := matrixAllowed[role]
		require.True(t, ok, "role %q missing from the matrix", role)
		allowed := map[string]bool{}
		for _, n := range allowedNames {
			allowed[n] = true
		}

		for _, op := range matrixOps {
			action, kind := MapRouteToDataAction(op.method, op.path)
			require.Equal(t, RouteVaultData, kind, "%s must be a data-plane route", op.name)
			require.NotEmpty(t, action, "%s must map to a data action", op.name)

			got := model.RoleGrantsDataAction(role, action)
			want := allowed[op.name]
			assert.Equal(t, want, got,
				"role %q, operation %s (%s %s, action %s): got allowed=%v want %v",
				role, op.name, op.method, op.path, action, got, want)
		}
	}
}

// TestAuthorizationMatrixCoversEveryOperation asserts the operation list has no
// duplicates and that the officer bundles reference only listed operations, so
// a typo in a role's allow-list cannot silently widen the denied set.
func TestAuthorizationMatrixCoversEveryOperation(t *testing.T) {
	known := map[string]bool{}
	for _, op := range matrixOps {
		require.False(t, known[op.name], "duplicate operation %q", op.name)
		known[op.name] = true
	}
	assert.Len(t, matrixOps, 48)

	for role, names := range matrixAllowed {
		for _, n := range names {
			assert.True(t, known[n], "role %q allows unknown operation %q", role, n)
		}
	}
}

// TestAuthorizationMatrixNoRoleGrantsEverythingButAdministrator asserts only the
// Administrator role covers all three object types.
func TestAuthorizationMatrixNoRoleGrantsEverythingButAdministrator(t *testing.T) {
	for role, names := range matrixAllowed {
		if role == model.RoleKeyVaultAdministrator {
			assert.Len(t, names, 48)
			continue
		}
		assert.Less(t, len(names), 48, "only Key Vault Administrator may grant every operation")
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./internal/services/authorization/ -run TestAuthorizationMatrix -v`

Expected: PASS. This test is written after the implementation it verifies (Tasks 1 and 2) on purpose: it is a specification lock, not a driver. If it fails, the defect is in the role bundles or the route map, not in the test.

- [ ] **Step 3: Commit**

```bash
git add internal/services/authorization/authorization_matrix_test.go
git commit -S -m "test(authorization): lock the (role, operation) authorization matrix

Assert, for all seven Azure roles across all 48 data-plane operations, the
exact allowed and denied set. Each role names its permitted operations in full
and everything unnamed is asserted denied, so widening a role or a route map
cannot pass unnoticed.

Refs spec 2026-07-26 section 8."
```

---

### Task 13: Release Notes and Documentation Corrections

**Files:**
- Create: `docs/release-notes/v4.0.0-azure-rbac.md`
- Modify: `CLAUDE.md` (architecture diagram and the `internal/domain/` section)
- Modify: `.claude/multi-vault.md` (the false "no vault-scoped route silently ignores its vault" claim)

**Interfaces:**
- Consumes: everything above.
- Produces: documentation only.

- [ ] **Step 1: Write the release notes**

Create `docs/release-notes/v4.0.0-azure-rbac.md`:

```markdown
# v4.0.0 — Azure Key Vault RBAC authorization

Authorization moves from per-object ownership to Azure Key Vault's built-in
data-plane roles, assigned per vault. Object ownership (`user_id`) is retained
as provenance and audit metadata and is no longer read for any access decision.

## Breaking changes

### 1. Users see every object in a vault they hold a role in

Previously a user saw only the objects they created. Now a role assignment in a
vault grants the actions of that role over **every** object in it. A user who
held only implicit access to their own secrets in the default vault will, after
the upgrade migration, hold `Key Vault Secrets Officer` there and see every
secret in that vault.

Review the output of `rocketvault vaults preview-migration` before upgrading and
revoke any assignment that grants more than intended, using
`DELETE /api/v1/vaults/{vault}/role-assignments/{id}`.

### 2. Out-of-scope resources return 404 where some previously returned 403

Requesting a resource that exists in another vault now returns `404 Not Found`
rather than `403 Forbidden` with "access denied". The two are indistinguishable
by design: a 403 told the caller the object existed. Clients that branch on the
status code must treat 404 as "absent or not yours".

`403` is now reserved for: authenticated but holding no role assignment granting
the required action in this vault; a disabled vault; and a resource outside its
validity window.

### 3. Key crypto operations are gated by role, not by ownership

`sign`, `verify`, `encrypt`, `decrypt`, `wrapkey`, `unwrapkey`, and key delete
now require the corresponding data action from `Key Vault Crypto User` or
`Key Vault Crypto Officer` in the key's vault. Creating a key confers no
special authority over it.

## The roles

| Role | Grants |
|---|---|
| Key Vault Administrator | All data-plane operations on all object types |
| Key Vault Reader | Metadata only; no secret values or key material |
| Key Vault Secrets User | Get and list secrets, including values |
| Key Vault Secrets Officer | Full secret control |
| Key Vault Crypto User | Use key material: encrypt, decrypt, sign, verify, wrap, unwrap |
| Key Vault Crypto Officer | Full key control including create, import, delete, rotation |
| Key Vault Certificates Officer | Full certificate control |

Grant one with:

```bash
curl -X POST https://host/api/v1/vaults/prod/role-assignments \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"principal":"alice","role":"Key Vault Secrets Officer"}'
```

## Upgrade procedure

1. Back up the database.
2. Run `rocketvault vaults preview-migration` with the new binary. It writes
   nothing and prints every assignment the upgrade would create.
3. Confirm every principal that needs access appears for the vaults it needs.
4. Start the new binary. The migration runs inside schema migration, is
   idempotent, and logs one summary line per vault recording grants examined and
   assignments created.

The migration derives assignments as follows:

| Existing state | Assignment created |
|---|---|
| Owns rows in `secrets` for a vault | `Key Vault Secrets Officer` in that vault |
| Owns rows in `keys` for a vault | `Key Vault Crypto Officer` in that vault |
| Owns rows in `certificates` for a vault | `Key Vault Certificates Officer` in that vault |
| Holds the global `admin` role | `Key Vault Administrator` in every vault |

## Notes

- A newly created vault has **no** data-plane role assignments, matching Azure.
  A global admin or a principal holding `vaults:manage` must grant them before
  anyone can read or write objects in it.
- `access_policies` is retained only as an explicit-deny override. It is
  evaluated before the role decision, so a deny cannot be outvoted by a grant.
  Existing allow-policies no longer grant data-plane access on their own.
- Audit-log consumers: `audit_logs.user_id` now carries the acting principal on
  vault-scoped key and secret updates, where it previously carried a vault UUID
  or the object owner. Re-check any query keyed on those values.
```

- [ ] **Step 2: Correct CLAUDE.md**

In `CLAUDE.md`, replace the `internal/domain/` block in the architecture diagram with:

```
│   ├── (domain types live in model/ at the repository root — there is no
│   │    internal/domain package)
```

and replace the "Domain Types" bullets under "Perfect Domain-Driven Design Implementation" with:

```markdown
- **Domain Types**: `model/` at the repository root holds `User`, `Claims`, `Secret`, `Key`, `Certificate`, `Vault`, `Scope`, and the Azure role and data-action constants. It depends only on the standard library plus `uuid`. There is no `internal/domain` package; earlier revisions of this file described one that never existed.
```

Add to the "Authorization" section:

```markdown
### Authorization (`internal/services/authorization/`)
- **RBACService**: global role permissions for vault and user management only
- **AccessPolicyService**: explicit-deny override, evaluated before role grants
- **RoleAssignmentService**: per-vault Azure role grants and the `HasDataAction` authorization decision
- Vault data-plane routes are deny-by-default: see `docs/release-notes/v4.0.0-azure-rbac.md`
```

- [ ] **Step 3: Correct `.claude/multi-vault.md`**

Replace the claim "no vault-scoped route silently ignores its vault" with:

```markdown
Most vault-scoped routes honour their vault, but three do not and are fixed in
P3: `PUT /vaults/{n}/certificates/{id}` (no vault-scoped update path exists at
all), `POST /vaults/{n}/keys/{id}/rotate`, and
`GET /vaults/{n}/keys/{id}/versions`. Do not rely on this claim being universal.
```

- [ ] **Step 4: Verify**

Run: `go build ./... && go test ./...`

Expected: PASS (documentation-only change; the gate confirms nothing regressed).

- [ ] **Step 5: Commit**

```bash
git add docs/release-notes/v4.0.0-azure-rbac.md CLAUDE.md .claude/multi-vault.md
git commit -S -m "docs: document the Azure RBAC breaking changes and upgrade path

Record the three breaking changes: vault-wide visibility replacing per-object
ownership, 404 replacing 403 for out-of-scope resources, and crypto operations
gated by Key Vault Crypto User rather than key ownership. Document the upgrade
procedure and the exact derivation the migration performs.

Correct two documentation errors the spec calls out: CLAUDE.md described an
internal/domain package that does not exist, and multi-vault.md claimed no
vault-scoped route ignores its vault, which is false for three routes.

Refs spec 2026-07-26 sections 3 and 6.4."
```

---

## Completion Checklist

- [ ] `go build ./... && go test ./...` passes.
- [ ] `grep -rn "NewOwnerScope\|ownerScopeFromRequest" --include="*.go" .` matches nothing outside `model/scope.go`, `model/scope_test.go`, and `internal/repositories/scope_predicate_test.go`.
- [ ] The B6 tests were deleted in exactly one commit, together with the handler policy change (Task 11), and in no other commit.
- [ ] The backfill (Tasks 6-7) is committed **before** the middleware inversion (Task 9).
- [ ] `rocketvault vaults preview-migration` runs against a copy of a production database and its output matches the migration's per-vault summary.
- [ ] `docs/release-notes/v4.0.0-azure-rbac.md` lists all three breaking changes from spec §6.4.
