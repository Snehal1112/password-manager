# Vault-Scoped User Access (Role Assignments) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin grant a global identity vault-scoped access in one call via Azure-style role assignments that expand into the existing `access_policies` engine.

**Architecture:** A new `role_assignments` table records "principal P has role R in vault V". On assign, the service expands a built-in role (code-level `map[Role][]Permission`) into N `access_policies` rows, each tagged with the new `access_policies.assignment_id` column. Revoke deletes by tag. Authorization evaluation (`CheckAccess`) is untouched — role assignments only write `effect=allow`, so deny-overrides precedence is preserved. New vault-scoped HTTP routes `/vaults/{vault_name}/role-assignments` and a `vault-access` CLI group provide the ergonomics.

**Tech Stack:** Go 1.24.2, Gorilla Mux, SQLite/PostgreSQL, Cobra CLI, testify/mock. GPG-signed commits (key `61D246B30285ED35`).

**Spec:** `docs/superpowers/specs/2026-06-06-vault-scoped-users-design.md`

---

## Ground-truth references (verified against the codebase)

These exact names/signatures are used throughout the plan. Do not invent variants.

- Operations enum (`model/access_policy.go:36-54`): `OpGet OpList OpSet OpCreate OpDelete OpBackup OpRestore OpPurge OpRecover OpRotate OpSign OpVerify OpEncrypt OpDecrypt OpImport OpRenew OpManage`. **There is no `wrap`/`unwrap` operation** — `crypto-user` uses sign/verify/encrypt/decrypt only.
- Resource types (`model/access_policy.go:27-32`): `PolicyResourceSecrets PolicyResourceKeys PolicyResourceCertificates PolicyResourceVaults`.
- Principal types (`model/access_policy.go:14-16`): `PrincipalTypeUser`, `PrincipalTypeServiceAccount`.
- Routes struct is named `Routes` (`api/api.go:16`); vault-scoped subrouter is `r.VaultScoped` = `r.Vaults.PathPrefix("/{vault_name:[a-z0-9-]+}").Subrouter()` (`api/api.go:82`). Init funcs called in `api/api.go:123-135`.
- Params struct is `ApiParams` (`api/params.go:13`), populated by `ApiParamsFromRequest(r)` reading `mux.Vars(r)`.
- Vault id from context: `vaultIDFromRequest(r)` (`api/context.go:44`) reads `common.VaultIDKey` (string), defaults `model.DefaultVaultID`.
- Container wiring for policies: `internal/container/service_container.go:375-378`; getter `GetAccessPolicyService()` at `:585`; `GetUserRepository()` at `:545`; cascade wiring at `:261-262`.
- Policy service: `AccessPolicyService` interface + `NewAccessPolicyService(repo)` (`internal/services/authorization/access_policy_service.go:27-48`).
- Policy repo: `AccessPolicyRepositoryInterface` + `NewAccessPolicyRepository(db)` (`internal/repositories/access_policy_repository.go:15-34`). The `access_policies` INSERT is at `:44`, `scanAccessPolicy`/`scanAccessPolicies` at `:115`/`:146`.
- User repo: `UserRepositoryInterface.ReadByUsername(ctx, username) (model.User, error)` (`internal/repositories/user_repository.go`).
- DB: `CREATE TABLE access_policies` at `internal/db/db.go:583`; `migrateSchema(db *sql.DB)` at `:629` uses a `migrations []string` slice executed with an `isDuplicateColumnError(err)` guard at `:746`.
- Cascade: `vaultContentRepo` interface has `SoftDeleteVaultContents`/`RecoverVaultContents` only (`internal/services/vaults/cascade_adapter.go:11`). `PurgeVault` at `internal/services/vaults/vault_service.go:209` calls `s.repo.Purge(ctx, v.ID)`.
- Admin gate in a handler: `roleStr, _ := c.Claims["role"].(string); if !common.HasRequiredRole(roleStr, model.RoleAdmin) { c.SetPermissionError("...") ; return }` (`api/oauth2.go:140`). `common.HasRequiredRole` at `common/auth_helper.go:44`.
- CLI: each command group exposes `InitXxx(parent *cobra.Command)` funcs registered from a `cmd/<group>.go` `init()` (see `cmd/secrets.go:40`). Vault resolution: `common.ResolveVaultName(cmd)` (`common/vault_selector.go:12`); `resolveVaultID(ctx, cmd, sc)` (`cmd/secrets/vault.go:14`).

---

## File Structure

**Create:**
- `model/role_assignment.go` — `RoleAssignment`, request/response DTOs.
- `internal/services/authorization/roles.go` — built-in role → permission bundles + `ExpandRole`.
- `internal/services/authorization/role_assignment_service.go` — assign/revoke/list orchestration.
- `internal/repositories/role_assignment_repository.go` — `role_assignments` CRUD + tx-aware policy writes.
- `api/role_assignments.go` — vault-scoped HTTP handlers + `InitRoleAssignments`.
- `cmd/vault-access/grant.go`, `list.go`, `revoke.go`, `roles.go`, `vault.go` — CLI group.
- `cmd/vault_access.go` — registers the CLI group in `rootCmd`.
- `internal/db/migrations/20260606000001_add_role_assignments.sql` — migrate-CLI path.

**Modify:**
- `model/access_policy.go` — add `AssignmentID *uuid.UUID` to `AccessPolicy`.
- `internal/repositories/access_policy_repository.go` — `assignment_id` in INSERT/scan; add `ListByVault`, `DeleteByAssignmentID`, `DeleteByVault`.
- `internal/db/db.go` — `role_assignments` table + `assignment_id` column in `createOptimizedSchema`; idempotent ALTER + table create in `migrateSchema`.
- `internal/container/service_container.go` — construct + expose role-assignment repo/service; expose policy repo if needed.
- `api/params.go` — add `VaultName`, `AssignmentID` params.
- `api/api.go` — add `RoleAssignments`/`RoleAssignment` subrouters + call `InitRoleAssignments()`.
- `internal/services/vaults/vault_service.go` — purge also deletes vault-scoped policies (orphan cleanup).
- `internal/container/service_container.go` — pass policy repo into vault service for purge cleanup (see Task 12).
- `internal/testutils/mocks.go` — mocks for new repo/service methods.

---

## Task 1: Add `assignment_id` to the AccessPolicy model

**Files:**
- Modify: `model/access_policy.go:56-67`

- [ ] **Step 1: Add the field to the struct**

In `model/access_policy.go`, add `AssignmentID` to `AccessPolicy` (after `VaultID`):

```go
type AccessPolicy struct {
	ID            uuid.UUID          `json:"id"`
	PrincipalID   uuid.UUID          `json:"principal_id"`
	PrincipalType PrincipalType      `json:"principal_type"`
	ResourceType  PolicyResourceType `json:"resource_type"`
	Operation     PolicyOperation    `json:"operation"`
	Effect        PolicyEffect       `json:"effect"`
	// VaultID scopes the policy to a single vault. A nil VaultID means the
	// policy is GLOBAL and applies in any vault.
	VaultID *uuid.UUID `json:"vault_id,omitempty"`
	// AssignmentID links this policy to a role assignment. Nil means the policy
	// was created directly (hand-written), not via a role grant.
	AssignmentID *uuid.UUID `json:"assignment_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}
```

- [ ] **Step 2: Build to verify it compiles**

Run: `go build ./model/...`
Expected: success, no output.

- [ ] **Step 3: Commit**

```bash
git add model/access_policy.go
git commit -S -m "feat(model): add AssignmentID to AccessPolicy for role-assignment linkage"
```

---

## Task 2: Persist and read `assignment_id` in the access-policy repository

**Files:**
- Modify: `internal/repositories/access_policy_repository.go`
- Test: `internal/repositories/access_policy_repository_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/access_policy_repository_test.go` (reuse the existing test DB setup helper in that file — it already builds an `accessPolicyRepository`; copy the setup the other tests use):

```go
func TestAccessPolicy_AssignmentIDRoundTrip(t *testing.T) {
	repo, _ := newTestAccessPolicyRepo(t) // use whatever setup helper the file already defines
	ctx := context.Background()

	assignID := uuid.New()
	vaultID := uuid.New()
	p := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceSecrets,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
		VaultID:       &vaultID,
		AssignmentID:  &assignID,
	}
	if err := repo.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AssignmentID == nil || *got.AssignmentID != assignID {
		t.Fatalf("assignment_id not round-tripped: got %v", got.AssignmentID)
	}
}
```

> If the file has no `newTestAccessPolicyRepo` helper, mirror the inline `sql.Open("sqlite3", ...)` + `createOptimizedSchema` setup already present in the other tests in this file. Do not add a new framework.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestAccessPolicy_AssignmentIDRoundTrip -v`
Expected: FAIL — column `assignment_id` does not exist / not scanned.

- [ ] **Step 3: Add the column to INSERT and all SELECTs/scans**

In `internal/repositories/access_policy_repository.go`:

Update `Create` (the INSERT at `:44`):

```go
func (r *accessPolicyRepository) Create(ctx context.Context, p *model.AccessPolicy) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	var vaultArg any
	if p.VaultID != nil {
		vaultArg = p.VaultID.String()
	}
	var assignArg any
	if p.AssignmentID != nil {
		assignArg = p.AssignmentID.String()
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID.String(), p.PrincipalID.String(), string(p.PrincipalType),
		string(p.ResourceType), string(p.Operation), string(p.Effect), vaultArg, assignArg, p.CreatedAt,
	)
	return err
}
```

Update the four SELECT statements (`GetByID:55`, `List:62`, `ListByPrincipal:73`, `FindEffects:84`) to add `assignment_id` to the column list, immediately after `vault_id`. Example for `GetByID`:

```go
	row := r.db.QueryRowContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at
		 FROM access_policies WHERE id = ?`, id.String())
```

Apply the identical column addition to `List`, `ListByPrincipal`, and `FindEffects`.

Update `scanAccessPolicy` (`:115`) and `scanAccessPolicies` (`:146`) to scan the new column. In both, add `var assignStr sql.NullString` and include `&assignStr` in `row.Scan`/`rows.Scan` between `&vaultStr` and `&p.CreatedAt`, then after the vault-parse block add:

```go
	if assignStr.Valid && assignStr.String != "" {
		aid, err := uuid.Parse(assignStr.String)
		if err != nil {
			return nil, fmt.Errorf("invalid assignment id: %w", err)
		}
		p.AssignmentID = &aid
	}
```

(In `scanAccessPolicies` this block goes before `results = append(...)`.)

- [ ] **Step 4: Add the column to the fresh-DB schema**

In `internal/db/db.go`, the `CREATE TABLE IF NOT EXISTS access_policies` block (`:583`) add `assignment_id TEXT NULL` after `vault_id`:

```sql
CREATE TABLE IF NOT EXISTS access_policies (
	id             TEXT PRIMARY KEY,
	principal_id   TEXT NOT NULL,
	principal_type TEXT NOT NULL,
	resource_type  TEXT NOT NULL,
	operation      TEXT NOT NULL,
	effect         TEXT NOT NULL,
	vault_id       TEXT NULL,
	assignment_id  TEXT NULL,
	created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/repositories/ -run TestAccessPolicy_AssignmentIDRoundTrip -v`
Expected: PASS.

- [ ] **Step 6: Run the full repositories package to check no scan regressions**

Run: `go test ./internal/repositories/ -count=1`
Expected: PASS (all existing access-policy tests still pass with the new column).

- [ ] **Step 7: Commit**

```bash
git add internal/repositories/access_policy_repository.go internal/repositories/access_policy_repository_test.go internal/db/db.go
git commit -S -m "feat(repo): persist assignment_id on access_policies"
```

---

## Task 3: Migrate existing databases to add `assignment_id`

**Files:**
- Modify: `internal/db/db.go` (`migrateSchema`, `:629`)
- Test: `internal/db/db_test.go` (or the existing migration test file in `internal/db/`)

- [ ] **Step 1: Write the failing test**

Add to the migration test file in `internal/db/` (mirror an existing migrate test — they open a DB, create an OLD schema without the column, run `migrateSchema`, then assert the column exists). If no such test exists, create `internal/db/migrate_assignment_test.go`:

```go
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestMigrate_AddsAssignmentIDColumn(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Old-shape access_policies without assignment_id.
	_, err = conn.Exec(`CREATE TABLE access_policies (
		id TEXT PRIMARY KEY, principal_id TEXT, principal_type TEXT,
		resource_type TEXT, operation TEXT, effect TEXT, vault_id TEXT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatal(err)
	}

	d := &DBRepository{}
	if err := d.migrateSchema(conn); err != nil {
		t.Fatalf("migrateSchema: %v", err)
	}
	// Running twice must be idempotent.
	if err := d.migrateSchema(conn); err != nil {
		t.Fatalf("migrateSchema rerun: %v", err)
	}

	var name string
	row := conn.QueryRow(`SELECT name FROM pragma_table_info('access_policies') WHERE name='assignment_id'`)
	if err := row.Scan(&name); err != nil {
		t.Fatalf("assignment_id column missing after migrate: %v", err)
	}
}
```

> If `DBRepository{}` cannot be constructed bare (migrateSchema dereferences fields), use the same construction the existing migration tests use.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestMigrate_AddsAssignmentIDColumn -v`
Expected: FAIL — column missing after migrate.

- [ ] **Step 3: Add the migration statement**

In `internal/db/db.go`, inside `migrateSchema`, append to the `migrations []string` slice (the `isDuplicateColumnError` guard at `:746` already handles re-runs):

```go
		// Feature: vault-scoped role assignments — link policies to a grant.
		"ALTER TABLE access_policies ADD COLUMN assignment_id TEXT NULL",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/ -run TestMigrate_AddsAssignmentIDColumn -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/db.go internal/db/*_test.go
git commit -S -m "feat(db): migrate access_policies to add assignment_id idempotently"
```

---

## Task 4: Create the `role_assignments` table (fresh + migrate)

**Files:**
- Modify: `internal/db/db.go` (`createOptimizedSchema` + `migrateSchema`)
- Create: `internal/db/migrations/20260606000001_add_role_assignments.sql`
- Test: `internal/db/migrate_assignment_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/db/migrate_assignment_test.go`:

```go
func TestMigrate_CreatesRoleAssignmentsTable(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	d := &DBRepository{}
	if err := d.migrateSchema(conn); err != nil {
		t.Fatalf("migrateSchema: %v", err)
	}
	var name string
	row := conn.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='role_assignments'`)
	if err := row.Scan(&name); err != nil {
		t.Fatalf("role_assignments table missing: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestMigrate_CreatesRoleAssignmentsTable -v`
Expected: FAIL — table missing.

- [ ] **Step 3: Add the table to `migrateSchema`**

`ALTER TABLE` lives in the `migrations []string` slice, but `CREATE TABLE` should run unconditionally and idempotently. In `migrateSchema`, after the migrations loop (near `:751`), add:

```go
	// Feature: vault-scoped role assignments table (idempotent).
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS role_assignments (
		id             TEXT PRIMARY KEY,
		principal_id   TEXT NOT NULL,
		principal_type TEXT NOT NULL,
		role           TEXT NOT NULL,
		vault_id       TEXT NOT NULL,
		created_by     TEXT NOT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (principal_id, role, vault_id),
		FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create role_assignments: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id)`); err != nil {
		return fmt.Errorf("index role_assignments vault: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_access_policies_assignment ON access_policies(assignment_id)`); err != nil {
		return fmt.Errorf("index access_policies assignment: %w", err)
	}
```

> The `idx_access_policies_assignment` index is created here (after Task 3 adds the column), respecting the "indexes after the column exists" ordering rule.

- [ ] **Step 4: Add the same table + indexes to `createOptimizedSchema`**

In `createOptimizedSchema`, after the `access_policies` block, add the identical `CREATE TABLE IF NOT EXISTS role_assignments (...)` and the two `CREATE INDEX IF NOT EXISTS` statements (so fresh DBs match migrated DBs).

- [ ] **Step 5: Create the standalone migration file**

Create `internal/db/migrations/20260606000001_add_role_assignments.sql`:

```sql
-- Vault-scoped role assignments. Links a tenant-global principal to a role within a vault.
ALTER TABLE access_policies ADD COLUMN assignment_id TEXT NULL;

CREATE TABLE IF NOT EXISTS role_assignments (
    id             TEXT PRIMARY KEY,
    principal_id   TEXT NOT NULL,
    principal_type TEXT NOT NULL,
    role           TEXT NOT NULL,
    vault_id       TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (principal_id, role, vault_id),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_assignment ON access_policies(assignment_id);
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/db/ -count=1`
Expected: PASS (both new migration tests + existing).

- [ ] **Step 7: Commit**

```bash
git add internal/db/db.go internal/db/migrations/20260606000001_add_role_assignments.sql internal/db/migrate_assignment_test.go
git commit -S -m "feat(db): add role_assignments table (fresh schema + migration)"
```

---

## Task 5: Role-assignment domain model

**Files:**
- Create: `model/role_assignment.go`
- Test: `model/role_assignment_test.go`

- [ ] **Step 1: Write the failing test**

Create `model/role_assignment_test.go`:

```go
package model

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAssignRoleRequestFromJson(t *testing.T) {
	body := `{"principal":"alice","principal_type":"user","role":"secrets-user"}`
	req, err := AssignRoleRequestFromJson(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.Principal != "alice" || req.Role != "secrets-user" || req.PrincipalType != "user" {
		t.Fatalf("unexpected: %+v", req)
	}
}

func TestRoleAssignmentResponseToJson(t *testing.T) {
	resp := RoleAssignmentResponse{ID: uuid.New().String(), Role: "secrets-user"}
	if !strings.Contains(resp.ToJson(), "secrets-user") {
		t.Fatalf("ToJson missing role: %s", resp.ToJson())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./model/ -run TestAssignRoleRequest -v`
Expected: FAIL — undefined `AssignRoleRequestFromJson`.

- [ ] **Step 3: Write the model**

Create `model/role_assignment.go`:

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// RoleAssignment records that a principal holds a built-in role within a vault.
type RoleAssignment struct {
	ID            uuid.UUID     `json:"id"`
	PrincipalID   uuid.UUID     `json:"principal_id"`
	PrincipalType PrincipalType `json:"principal_type"`
	Role          string        `json:"role"`
	VaultID       uuid.UUID     `json:"vault_id"`
	CreatedBy     uuid.UUID     `json:"created_by"`
	CreatedAt     time.Time     `json:"created_at"`
}

// AssignRoleRequest is the body for granting a role in a vault.
// Principal accepts either a username or a UUID; the server resolves it.
type AssignRoleRequest struct {
	Principal     string `json:"principal"`
	PrincipalType string `json:"principal_type,omitempty"`
	Role          string `json:"role"`
}

func AssignRoleRequestFromJson(data io.Reader) (*AssignRoleRequest, error) {
	var r AssignRoleRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

// RoleAssignmentResponse is the API representation of an assignment.
type RoleAssignmentResponse struct {
	ID                  string `json:"id"`
	PrincipalID         string `json:"principal_id"`
	PrincipalUsername   string `json:"principal_username,omitempty"`
	PrincipalType       string `json:"principal_type"`
	Role                string `json:"role"`
	VaultID             string `json:"vault_id"`
	VaultName           string `json:"vault_name,omitempty"`
	CreatedAt           string `json:"created_at"`
	ExpandedPolicyCount int    `json:"expanded_policy_count,omitempty"`
}

func (r *RoleAssignmentResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListRoleAssignmentsResponse struct {
	RoleAssignments []RoleAssignmentResponse `json:"role_assignments"`
	Total           int                      `json:"total"`
}

func (r *ListRoleAssignmentsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./model/ -run "TestAssignRoleRequest|TestRoleAssignmentResponse" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add model/role_assignment.go model/role_assignment_test.go
git commit -S -m "feat(model): add RoleAssignment types and DTOs"
```

---

## Task 6: Built-in role definitions and expansion

**Files:**
- Create: `internal/services/authorization/roles.go`
- Test: `internal/services/authorization/roles_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/services/authorization/roles_test.go`:

```go
package authorization

import (
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

func TestIsValidRole(t *testing.T) {
	if !IsValidRole("secrets-user") {
		t.Fatal("secrets-user should be valid")
	}
	if IsValidRole("nope") {
		t.Fatal("nope should be invalid")
	}
}

func TestExpandRole_SecretsUser(t *testing.T) {
	vid := uuid.New()
	pid := uuid.New()
	aid := uuid.New()
	policies, err := ExpandRole("secrets-user", pid, model.PrincipalTypeUser, vid, aid)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(policies) != 2 { // get, list
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	for _, p := range policies {
		if p.ResourceType != model.PolicyResourceSecrets || p.Effect != model.PolicyEffectAllow {
			t.Fatalf("bad policy: %+v", p)
		}
		if p.VaultID == nil || *p.VaultID != vid {
			t.Fatalf("vault not set: %+v", p)
		}
		if p.AssignmentID == nil || *p.AssignmentID != aid {
			t.Fatalf("assignment not set: %+v", p)
		}
	}
}

func TestExpandRole_VaultAdminIncludesManage(t *testing.T) {
	policies, err := ExpandRole("vault-admin", uuid.New(), model.PrincipalTypeUser, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	found := false
	for _, p := range policies {
		if p.ResourceType == model.PolicyResourceVaults && p.Operation == model.OpManage {
			found = true
		}
	}
	if !found {
		t.Fatal("vault-admin must include vaults/manage")
	}
}

func TestExpandRole_Unknown(t *testing.T) {
	if _, err := ExpandRole("nope", uuid.New(), model.PrincipalTypeUser, uuid.New(), uuid.New()); err == nil {
		t.Fatal("expected error for unknown role")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/ -run "TestIsValidRole|TestExpandRole" -v`
Expected: FAIL — undefined `IsValidRole`/`ExpandRole`.

- [ ] **Step 3: Write the role definitions**

Create `internal/services/authorization/roles.go`:

```go
package authorization

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// permission is one (resource_type, operation) pair within a role bundle.
type permission struct {
	Resource  model.PolicyResourceType
	Operation model.PolicyOperation
}

// builtInRoles maps each built-in vault role to its permission bundle.
// Only operations defined in model/access_policy.go are used (no wrap/unwrap).
var builtInRoles = map[string][]permission{
	"vault-reader": {
		{model.PolicyResourceSecrets, model.OpGet}, {model.PolicyResourceSecrets, model.OpList},
		{model.PolicyResourceKeys, model.OpGet}, {model.PolicyResourceKeys, model.OpList},
		{model.PolicyResourceCertificates, model.OpGet}, {model.PolicyResourceCertificates, model.OpList},
	},
	"secrets-user": {
		{model.PolicyResourceSecrets, model.OpGet}, {model.PolicyResourceSecrets, model.OpList},
	},
	"secrets-officer": {
		{model.PolicyResourceSecrets, model.OpGet}, {model.PolicyResourceSecrets, model.OpList},
		{model.PolicyResourceSecrets, model.OpSet}, {model.PolicyResourceSecrets, model.OpDelete},
		{model.PolicyResourceSecrets, model.OpBackup}, {model.PolicyResourceSecrets, model.OpRestore},
		{model.PolicyResourceSecrets, model.OpRecover}, {model.PolicyResourceSecrets, model.OpPurge},
	},
	"crypto-user": {
		{model.PolicyResourceKeys, model.OpGet}, {model.PolicyResourceKeys, model.OpList},
		{model.PolicyResourceKeys, model.OpSign}, {model.PolicyResourceKeys, model.OpVerify},
		{model.PolicyResourceKeys, model.OpEncrypt}, {model.PolicyResourceKeys, model.OpDecrypt},
	},
	"crypto-officer": {
		{model.PolicyResourceKeys, model.OpGet}, {model.PolicyResourceKeys, model.OpList},
		{model.PolicyResourceKeys, model.OpCreate}, {model.PolicyResourceKeys, model.OpDelete},
		{model.PolicyResourceKeys, model.OpRotate}, {model.PolicyResourceKeys, model.OpBackup},
		{model.PolicyResourceKeys, model.OpRestore}, {model.PolicyResourceKeys, model.OpRecover},
		{model.PolicyResourceKeys, model.OpPurge}, {model.PolicyResourceKeys, model.OpImport},
	},
	"certificates-officer": {
		{model.PolicyResourceCertificates, model.OpGet}, {model.PolicyResourceCertificates, model.OpList},
		{model.PolicyResourceCertificates, model.OpCreate}, {model.PolicyResourceCertificates, model.OpDelete},
		{model.PolicyResourceCertificates, model.OpRenew}, {model.PolicyResourceCertificates, model.OpBackup},
		{model.PolicyResourceCertificates, model.OpRestore}, {model.PolicyResourceCertificates, model.OpRecover},
		{model.PolicyResourceCertificates, model.OpPurge},
	},
}

// vaultAdminExtra is the additional management permission for vault-admin.
var vaultAdminExtra = permission{model.PolicyResourceVaults, model.OpManage}

// BuiltInRoleNames returns the sorted list of built-in role names.
func BuiltInRoleNames() []string {
	names := make([]string, 0, len(builtInRoles)+1)
	for n := range builtInRoles {
		names = append(names, n)
	}
	names = append(names, "vault-admin")
	sort.Strings(names)
	return names
}

// RolePermissions returns the (resource, operation) pairs for display.
func RolePermissions(role string) ([][2]string, error) {
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

// IsValidRole reports whether name is a known built-in role.
func IsValidRole(name string) bool {
	if name == "vault-admin" {
		return true
	}
	_, ok := builtInRoles[name]
	return ok
}

// bundle returns the full permission set for a role, including vault-admin's union.
func bundle(role string) ([]permission, error) {
	if role == "vault-admin" {
		seen := map[permission]bool{}
		var all []permission
		for _, perms := range builtInRoles {
			for _, p := range perms {
				if !seen[p] {
					seen[p] = true
					all = append(all, p)
				}
			}
		}
		all = append(all, vaultAdminExtra)
		return all, nil
	}
	perms, ok := builtInRoles[role]
	if !ok {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	return perms, nil
}

// ExpandRole turns a role grant into the access_policies rows it implies.
func ExpandRole(role string, principalID uuid.UUID, principalType model.PrincipalType, vaultID, assignmentID uuid.UUID) ([]*model.AccessPolicy, error) {
	perms, err := bundle(role)
	if err != nil {
		return nil, err
	}
	v := vaultID
	a := assignmentID
	now := time.Now().UTC()
	policies := make([]*model.AccessPolicy, 0, len(perms))
	for _, p := range perms {
		policies = append(policies, &model.AccessPolicy{
			ID:            uuid.New(),
			PrincipalID:   principalID,
			PrincipalType: principalType,
			ResourceType:  p.Resource,
			Operation:     p.Operation,
			Effect:        model.PolicyEffectAllow,
			VaultID:       &v,
			AssignmentID:  &a,
			CreatedAt:     now,
		})
	}
	return policies, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/authorization/ -run "TestIsValidRole|TestExpandRole" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/authorization/roles.go internal/services/authorization/roles_test.go
git commit -S -m "feat(authz): built-in vault roles and ExpandRole"
```

---

## Task 7: Extend the access-policy repository (ListByVault, DeleteByAssignmentID, DeleteByVault)

**Files:**
- Modify: `internal/repositories/access_policy_repository.go`
- Test: `internal/repositories/access_policy_repository_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/repositories/access_policy_repository_test.go`:

```go
func TestAccessPolicy_DeleteByAssignmentID(t *testing.T) {
	repo, _ := newTestAccessPolicyRepo(t)
	ctx := context.Background()
	aid := uuid.New()
	vid := uuid.New()
	for i := 0; i < 3; i++ {
		_ = repo.Create(ctx, &model.AccessPolicy{
			ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
			ResourceType: model.PolicyResourceSecrets, Operation: model.OpGet,
			Effect: model.PolicyEffectAllow, VaultID: &vid, AssignmentID: &aid,
		})
	}
	// One unrelated hand-written policy (nil assignment) must survive.
	keep := &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceSecrets, Operation: model.OpGet,
		Effect: model.PolicyEffectAllow, VaultID: &vid,
	}
	_ = repo.Create(ctx, keep)

	if err := repo.DeleteByAssignmentID(ctx, aid); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ := repo.ListByVault(ctx, vid)
	if len(got) != 1 || got[0].ID != keep.ID {
		t.Fatalf("expected only the hand-written policy to remain, got %d", len(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestAccessPolicy_DeleteByAssignmentID -v`
Expected: FAIL — undefined `DeleteByAssignmentID`/`ListByVault`.

- [ ] **Step 3: Add interface methods and implementations**

In `internal/repositories/access_policy_repository.go`, add to `AccessPolicyRepositoryInterface`:

```go
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.AccessPolicy, error)
	DeleteByAssignmentID(ctx context.Context, assignmentID uuid.UUID) error
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
```

Add implementations:

```go
func (r *accessPolicyRepository) ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at
		 FROM access_policies WHERE vault_id = ? ORDER BY created_at DESC`, vaultID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAccessPolicies(rows)
}

func (r *accessPolicyRepository) DeleteByAssignmentID(ctx context.Context, assignmentID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM access_policies WHERE assignment_id = ?`, assignmentID.String())
	return err
}

func (r *accessPolicyRepository) DeleteByVault(ctx context.Context, vaultID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM access_policies WHERE vault_id = ?`, vaultID.String())
	return err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repositories/ -run TestAccessPolicy_DeleteByAssignmentID -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/access_policy_repository.go internal/repositories/access_policy_repository_test.go
git commit -S -m "feat(repo): ListByVault, DeleteByAssignmentID, DeleteByVault on access policies"
```

---

## Task 8: Role-assignment repository

**Files:**
- Create: `internal/repositories/role_assignment_repository.go`
- Test: `internal/repositories/role_assignment_repository_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/repositories/role_assignment_repository_test.go` (mirror the sqlite setup used by the access-policy tests, and create the `role_assignments` table via the shared schema or inline DDL):

```go
package repositories

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"rocketvault/model"
)

func newRoleAssignmentRepo(t *testing.T) RoleAssignmentRepositoryInterface {
	conn, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(`CREATE TABLE role_assignments (
		id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
		role TEXT NOT NULL, vault_id TEXT NOT NULL, created_by TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (principal_id, role, vault_id))`)
	if err != nil {
		t.Fatal(err)
	}
	return NewRoleAssignmentRepository(conn)
}

func TestRoleAssignment_CreateGetListDelete(t *testing.T) {
	repo := newRoleAssignmentRepo(t)
	ctx := context.Background()
	vid := uuid.New()
	ra := &model.RoleAssignment{
		ID: uuid.New(), PrincipalID: uuid.New(), PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: vid, CreatedBy: uuid.New(),
	}
	if err := repo.Create(ctx, ra); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByID(ctx, ra.ID)
	if err != nil || got.Role != "secrets-user" {
		t.Fatalf("get: %v %+v", err, got)
	}
	list, err := repo.ListByVault(ctx, vid)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	if err := repo.Delete(ctx, ra.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, ra.ID); err == nil {
		t.Fatal("expected not-found after delete")
	}
}

func TestRoleAssignment_FindDuplicate(t *testing.T) {
	repo := newRoleAssignmentRepo(t)
	ctx := context.Background()
	vid := uuid.New()
	pid := uuid.New()
	ra := &model.RoleAssignment{
		ID: uuid.New(), PrincipalID: pid, PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: vid, CreatedBy: uuid.New(),
	}
	_ = repo.Create(ctx, ra)
	dup, err := repo.FindByTuple(ctx, pid, "secrets-user", vid)
	if err != nil || dup == nil || dup.ID != ra.ID {
		t.Fatalf("FindByTuple should return existing: %v %+v", err, dup)
	}
	none, err := repo.FindByTuple(ctx, uuid.New(), "secrets-user", vid)
	if err != nil {
		t.Fatalf("FindByTuple err: %v", err)
	}
	if none != nil {
		t.Fatal("expected nil for non-existent tuple")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/ -run TestRoleAssignment -v`
Expected: FAIL — undefined `NewRoleAssignmentRepository` / interface.

- [ ] **Step 3: Write the repository**

Create `internal/repositories/role_assignment_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// RoleAssignmentRepositoryInterface is the data-access contract for role assignments.
type RoleAssignmentRepositoryInterface interface {
	Create(ctx context.Context, ra *model.RoleAssignment) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.RoleAssignment, error)
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
	FindByTuple(ctx context.Context, principalID uuid.UUID, role string, vaultID uuid.UUID) (*model.RoleAssignment, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type roleAssignmentRepository struct {
	db *sql.DB
}

// NewRoleAssignmentRepository creates a RoleAssignmentRepository.
func NewRoleAssignmentRepository(db *sql.DB) RoleAssignmentRepositoryInterface {
	return &roleAssignmentRepository{db: db}
}

func (r *roleAssignmentRepository) Create(ctx context.Context, ra *model.RoleAssignment) error {
	if ra.CreatedAt.IsZero() {
		ra.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO role_assignments (id, principal_id, principal_type, role, vault_id, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ra.ID.String(), ra.PrincipalID.String(), string(ra.PrincipalType),
		ra.Role, ra.VaultID.String(), ra.CreatedBy.String(), ra.CreatedAt)
	return err
}

func (r *roleAssignmentRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.RoleAssignment, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, principal_id, principal_type, role, vault_id, created_by, created_at
		 FROM role_assignments WHERE id = ?`, id.String())
	return scanRoleAssignment(row)
}

func (r *roleAssignmentRepository) ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, role, vault_id, created_by, created_at
		 FROM role_assignments WHERE vault_id = ? ORDER BY created_at DESC`, vaultID.String())
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

func (r *roleAssignmentRepository) FindByTuple(ctx context.Context, principalID uuid.UUID, role string, vaultID uuid.UUID) (*model.RoleAssignment, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, principal_id, principal_type, role, vault_id, created_by, created_at
		 FROM role_assignments WHERE principal_id = ? AND role = ? AND vault_id = ?`,
		principalID.String(), role, vaultID.String())
	ra, err := scanRoleAssignment(row)
	if err != nil {
		if err.Error() == "role assignment not found" {
			return nil, nil // not found is not an error for a duplicate check
		}
		return nil, err
	}
	return ra, nil
}

func (r *roleAssignmentRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM role_assignments WHERE id = ?`, id.String())
	return err
}

func scanRoleAssignment(row *sql.Row) (*model.RoleAssignment, error) {
	var ra model.RoleAssignment
	var idStr, pidStr, vidStr, cbStr string
	err := row.Scan(&idStr, &pidStr, &ra.PrincipalType, &ra.Role, &vidStr, &cbStr, &ra.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role assignment not found")
	}
	if err != nil {
		return nil, err
	}
	return parseRoleAssignmentIDs(&ra, idStr, pidStr, vidStr, cbStr)
}

func scanRoleAssignmentRows(rows *sql.Rows) (*model.RoleAssignment, error) {
	var ra model.RoleAssignment
	var idStr, pidStr, vidStr, cbStr string
	if err := rows.Scan(&idStr, &pidStr, &ra.PrincipalType, &ra.Role, &vidStr, &cbStr, &ra.CreatedAt); err != nil {
		return nil, err
	}
	return parseRoleAssignmentIDs(&ra, idStr, pidStr, vidStr, cbStr)
}

func parseRoleAssignmentIDs(ra *model.RoleAssignment, idStr, pidStr, vidStr, cbStr string) (*model.RoleAssignment, error) {
	var err error
	if ra.ID, err = uuid.Parse(idStr); err != nil {
		return nil, fmt.Errorf("invalid assignment id: %w", err)
	}
	if ra.PrincipalID, err = uuid.Parse(pidStr); err != nil {
		return nil, fmt.Errorf("invalid principal id: %w", err)
	}
	if ra.VaultID, err = uuid.Parse(vidStr); err != nil {
		return nil, fmt.Errorf("invalid vault id: %w", err)
	}
	if ra.CreatedBy, err = uuid.Parse(cbStr); err != nil {
		return nil, fmt.Errorf("invalid created_by: %w", err)
	}
	return ra, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repositories/ -run TestRoleAssignment -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/repositories/role_assignment_repository.go internal/repositories/role_assignment_repository_test.go
git commit -S -m "feat(repo): role_assignments repository"
```

---

## Task 9: Role-assignment service (assign / revoke / list)

**Files:**
- Create: `internal/services/authorization/role_assignment_service.go`
- Test: `internal/services/authorization/role_assignment_service_test.go`

Note on transactions: the access-policy and role-assignment repos each wrap a `*sql.DB`, not a shared `*sql.Tx`, and there is no existing cross-repo tx helper. To keep this change localized and consistent with the codebase, the service writes the assignment row first, then the policy rows, and on policy-write failure it rolls back by calling `DeleteByAssignmentID` + `roleRepo.Delete`. This is a compensating cleanup, not a DB transaction. The test simulates a policy-write failure via a mock and asserts no rows remain.

- [ ] **Step 1: Write the failing test**

Create `internal/services/authorization/role_assignment_service_test.go`:

```go
package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// --- minimal fakes ---

type fakeRoleRepo struct {
	rows    map[uuid.UUID]*model.RoleAssignment
	byTuple *model.RoleAssignment
}

func newFakeRoleRepo() *fakeRoleRepo { return &fakeRoleRepo{rows: map[uuid.UUID]*model.RoleAssignment{}} }
func (f *fakeRoleRepo) Create(_ context.Context, ra *model.RoleAssignment) error {
	f.rows[ra.ID] = ra
	return nil
}
func (f *fakeRoleRepo) GetByID(_ context.Context, id uuid.UUID) (*model.RoleAssignment, error) {
	ra, ok := f.rows[id]
	if !ok {
		return nil, errors.New("role assignment not found")
	}
	return ra, nil
}
func (f *fakeRoleRepo) ListByVault(_ context.Context, v uuid.UUID) ([]*model.RoleAssignment, error) {
	var out []*model.RoleAssignment
	for _, ra := range f.rows {
		if ra.VaultID == v {
			out = append(out, ra)
		}
	}
	return out, nil
}
func (f *fakeRoleRepo) FindByTuple(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (*model.RoleAssignment, error) {
	return f.byTuple, nil
}
func (f *fakeRoleRepo) Delete(_ context.Context, id uuid.UUID) error { delete(f.rows, id); return nil }

type fakePolicyRepo struct {
	created   []*model.AccessPolicy
	failWrite bool
	deleted   map[uuid.UUID]bool
}

func newFakePolicyRepo() *fakePolicyRepo { return &fakePolicyRepo{deleted: map[uuid.UUID]bool{}} }
func (f *fakePolicyRepo) Create(_ context.Context, p *model.AccessPolicy) error {
	if f.failWrite {
		return errors.New("boom")
	}
	f.created = append(f.created, p)
	return nil
}
func (f *fakePolicyRepo) DeleteByAssignmentID(_ context.Context, aid uuid.UUID) error {
	f.deleted[aid] = true
	var keep []*model.AccessPolicy
	for _, p := range f.created {
		if p.AssignmentID == nil || *p.AssignmentID != aid {
			keep = append(keep, p)
		}
	}
	f.created = keep
	return nil
}

type fakeUserLookup struct{ users map[string]model.User }

func (f *fakeUserLookup) ReadByUsername(_ context.Context, name string) (model.User, error) {
	u, ok := f.users[name]
	if !ok {
		return model.User{}, errors.New("not found")
	}
	return u, nil
}

func newSvc(rr *fakeRoleRepo, pr *fakePolicyRepo, ul *fakeUserLookup) RoleAssignmentService {
	return NewRoleAssignmentService(rr, pr, ul)
}

func TestAssignRole_HappyPath(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser,
		Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if ra.PrincipalID != uid {
		t.Fatalf("principal not resolved from username")
	}
	if len(pr.created) != 2 { // secrets-user = get,list
		t.Fatalf("expected 2 policy rows, got %d", len(pr.created))
	}
	if len(rr.rows) != 1 {
		t.Fatalf("expected 1 assignment row")
	}
}

func TestAssignRole_UnknownRole(t *testing.T) {
	svc := newSvc(newFakeRoleRepo(), newFakePolicyRepo(),
		&fakeUserLookup{users: map[string]model.User{"alice": {ID: uuid.New(), Username: "alice"}}})
	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: "nope", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("expected ErrInvalidRole, got %v", err)
	}
}

func TestAssignRole_UnknownPrincipal(t *testing.T) {
	svc := newSvc(newFakeRoleRepo(), newFakePolicyRepo(), &fakeUserLookup{users: map[string]model.User{}})
	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "ghost", PrincipalType: model.PrincipalTypeUser, Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("expected ErrPrincipalNotFound, got %v", err)
	}
}

func TestAssignRole_Idempotent(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	existing := &model.RoleAssignment{ID: uuid.New(), Role: "secrets-user"}
	rr.byTuple = existing
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	ra, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if ra.ID != existing.ID {
		t.Fatalf("idempotent assign should return existing")
	}
	if len(pr.created) != 0 {
		t.Fatalf("idempotent assign must not write new policies")
	}
}

func TestAssignRole_RollbackOnPolicyFailure(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	pr.failWrite = true
	uid := uuid.New()
	ul := &fakeUserLookup{users: map[string]model.User{"alice": {ID: uid, Username: "alice"}}}
	svc := newSvc(rr, pr, ul)

	_, err := svc.AssignRole(context.Background(), AssignRoleInput{
		Principal: "alice", PrincipalType: model.PrincipalTypeUser, Role: "secrets-user", VaultID: uuid.New(), CreatedBy: uuid.New(),
	})
	if err == nil {
		t.Fatal("expected error on policy write failure")
	}
	if len(rr.rows) != 0 {
		t.Fatalf("assignment row must be rolled back, have %d", len(rr.rows))
	}
}

func TestRevokeAssignment_CrossVault(t *testing.T) {
	rr, pr := newFakeRoleRepo(), newFakePolicyRepo()
	ra := &model.RoleAssignment{ID: uuid.New(), VaultID: uuid.New(), Role: "secrets-user"}
	rr.rows[ra.ID] = ra
	svc := newSvc(rr, pr, &fakeUserLookup{users: map[string]model.User{}})

	otherVault := uuid.New()
	err := svc.RevokeAssignment(context.Background(), ra.ID, otherVault)
	if !errors.Is(err, ErrAssignmentNotFound) {
		t.Fatalf("cross-vault revoke should be not-found, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/authorization/ -run "TestAssignRole|TestRevoke" -v`
Expected: FAIL — undefined service types.

- [ ] **Step 3: Write the service**

Create `internal/services/authorization/role_assignment_service.go`:

```go
package authorization

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/model"
)

var (
	ErrInvalidRole        = errors.New("invalid role")
	ErrPrincipalNotFound  = errors.New("principal not found")
	ErrAssignmentNotFound = errors.New("role assignment not found")
)

// roleAssignmentRepo is the subset of the role-assignment repository the service needs.
type roleAssignmentRepo interface {
	Create(ctx context.Context, ra *model.RoleAssignment) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.RoleAssignment, error)
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
	FindByTuple(ctx context.Context, principalID uuid.UUID, role string, vaultID uuid.UUID) (*model.RoleAssignment, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// policyWriter is the subset of the access-policy repository the service needs.
type policyWriter interface {
	Create(ctx context.Context, p *model.AccessPolicy) error
	DeleteByAssignmentID(ctx context.Context, assignmentID uuid.UUID) error
}

// userLookup resolves a username to a user.
type userLookup interface {
	ReadByUsername(ctx context.Context, username string) (model.User, error)
}

// AssignRoleInput carries the resolved request to AssignRole.
type AssignRoleInput struct {
	Principal     string // username or UUID string
	PrincipalType model.PrincipalType
	Role          string
	VaultID       uuid.UUID
	CreatedBy     uuid.UUID
}

// RoleAssignmentService grants, revokes, and lists vault-scoped role assignments.
type RoleAssignmentService interface {
	AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error)
	RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error
	ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
}

type roleAssignmentService struct {
	roleRepo   roleAssignmentRepo
	policyRepo policyWriter
	users      userLookup
}

// NewRoleAssignmentService constructs the service.
func NewRoleAssignmentService(rr roleAssignmentRepo, pr policyWriter, ul userLookup) RoleAssignmentService {
	return &roleAssignmentService{roleRepo: rr, policyRepo: pr, users: ul}
}

func (s *roleAssignmentService) AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error) {
	if !IsValidRole(in.Role) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRole, in.Role)
	}
	pType := in.PrincipalType
	if pType == "" {
		pType = model.PrincipalTypeUser
	}

	principalID, err := s.resolvePrincipal(ctx, in.Principal)
	if err != nil {
		return nil, err
	}

	// Idempotency: an identical (principal, role, vault) returns the existing row.
	if existing, err := s.roleRepo.FindByTuple(ctx, principalID, in.Role, in.VaultID); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}

	assignmentID := uuid.New()
	ra := &model.RoleAssignment{
		ID:            assignmentID,
		PrincipalID:   principalID,
		PrincipalType: pType,
		Role:          in.Role,
		VaultID:       in.VaultID,
		CreatedBy:     in.CreatedBy,
	}
	if err := s.roleRepo.Create(ctx, ra); err != nil {
		return nil, fmt.Errorf("create assignment: %w", err)
	}

	policies, err := ExpandRole(in.Role, principalID, pType, in.VaultID, assignmentID)
	if err != nil {
		_ = s.roleRepo.Delete(ctx, assignmentID) // compensating cleanup
		return nil, err
	}
	for _, p := range policies {
		if err := s.policyRepo.Create(ctx, p); err != nil {
			// Compensating rollback: remove any policies written + the assignment.
			_ = s.policyRepo.DeleteByAssignmentID(ctx, assignmentID)
			_ = s.roleRepo.Delete(ctx, assignmentID)
			return nil, fmt.Errorf("expand role policies: %w", err)
		}
	}
	return ra, nil
}

func (s *roleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error {
	ra, err := s.roleRepo.GetByID(ctx, assignmentID)
	if err != nil {
		return ErrAssignmentNotFound
	}
	if ra.VaultID != vaultID {
		return ErrAssignmentNotFound // cannot revoke another vault's grant
	}
	if err := s.policyRepo.DeleteByAssignmentID(ctx, assignmentID); err != nil {
		return fmt.Errorf("delete policies: %w", err)
	}
	if err := s.roleRepo.Delete(ctx, assignmentID); err != nil {
		return fmt.Errorf("delete assignment: %w", err)
	}
	return nil
}

func (s *roleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	return s.roleRepo.ListByVault(ctx, vaultID)
}

// resolvePrincipal accepts a UUID string or a username and returns the principal UUID.
func (s *roleAssignmentService) resolvePrincipal(ctx context.Context, principal string) (uuid.UUID, error) {
	if id, err := uuid.Parse(principal); err == nil {
		return id, nil
	}
	u, err := s.users.ReadByUsername(ctx, principal)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %s", ErrPrincipalNotFound, principal)
	}
	return u.ID, nil
}
```

> The fake `fakePolicyRepo` in the test omits `DeleteByVault`; the `policyWriter` interface above intentionally only needs `Create` + `DeleteByAssignmentID`, so the fakes satisfy it. The full repo still implements the wider `AccessPolicyRepositoryInterface`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/services/authorization/ -run "TestAssignRole|TestRevoke" -v`
Expected: PASS.

- [ ] **Step 5: Run the whole authorization package**

Run: `go test ./internal/services/authorization/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/services/authorization/role_assignment_service.go internal/services/authorization/role_assignment_service_test.go
git commit -S -m "feat(authz): role assignment service with assign/revoke/list"
```

---

## Task 10: Wire repo + service into the DI container

**Files:**
- Modify: `internal/container/service_container.go`

- [ ] **Step 1: Add fields**

Near the access-policy fields (`:159-160`), add:

```go
	roleAssignmentRepository repositories.RoleAssignmentRepositoryInterface
	roleAssignmentService    authzServices.RoleAssignmentService
```

- [ ] **Step 2: Construct them**

In the authorization init block (`:375-378`), after `c.accessPolicyService = ...`, add:

```go
	c.roleAssignmentRepository = repositories.NewRoleAssignmentRepository(c.db)
	c.roleAssignmentService = authzServices.NewRoleAssignmentService(
		c.roleAssignmentRepository,
		c.accessPolicyRepository,
		c.userRepository,
	)
```

> `c.userRepository` is already constructed earlier in the container; confirm it appears before this block. If not, move these two lines to just after the user repository is built.

- [ ] **Step 3: Add the getter**

Near `GetAccessPolicyService()` (`:585`), add:

```go
// GetRoleAssignmentService returns the role assignment service.
func (c *ServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return c.roleAssignmentService
}
```

- [ ] **Step 4: Add to the container interface**

Find the `ServiceContainerInterface` definition (same package or `internal/container/interface*.go`) and add:

```go
	GetRoleAssignmentService() authzServices.RoleAssignmentService
```

- [ ] **Step 5: Build**

Run: `go build ./...`
Expected: success. (If the interface mock in `internal/testutils/mocks.go` implements `ServiceContainerInterface`, it will now fail to compile — that is fixed in Task 13. If the build breaks only there, proceed; otherwise fix here.)

- [ ] **Step 6: Commit**

```bash
git add internal/container/service_container.go
git commit -S -m "feat(container): wire role assignment repo and service"
```

---

## Task 11: HTTP handlers + vault-scoped routes

**Files:**
- Modify: `api/params.go` (add `VaultName`, `AssignmentID`)
- Modify: `api/api.go` (subrouters + Init call)
- Create: `api/role_assignments.go`
- Test: `api/role_assignments_test.go`

- [ ] **Step 1: Add params**

In `api/params.go`, add to `ApiParams`:

```go
	VaultName    string
	AssignmentID string
```

And in `ApiParamsFromRequest`, add to the struct literal:

```go
		VaultName:    vars["vault_name"],
		AssignmentID: vars["assignment_id"],
```

- [ ] **Step 2: Add subrouters and Init call in api.go**

In the `Routes` struct (`api/api.go:16`), add:

```go
	RoleAssignments *mux.Router // /api/v1/vaults/{vault_name}/role-assignments
	RoleAssignment  *mux.Router // /api/v1/vaults/{vault_name}/role-assignments/{assignment_id}
```

Where `r.VaultScoped` is built (`:82`), add after it:

```go
	r.RoleAssignments = r.VaultScoped.PathPrefix("/role-assignments").Subrouter()
	r.RoleAssignment = r.RoleAssignments.PathPrefix("/{assignment_id:[A-Fa-f0-9-]+}").Subrouter()
```

In the Init list (`:123-135`), add:

```go
	api.InitRoleAssignments()
```

- [ ] **Step 3: Write the failing test**

Create `api/role_assignments_test.go`. Mirror the existing `api/access_policies_test.go` harness (it builds an `*API` with a mock service container; copy that setup, add a `GetRoleAssignmentService` to the mock container returning a fake service). Minimum cases:

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoleAssignments_GrantRequiresAdmin(t *testing.T) {
	api, _ := newTestAPIWithRoleService(t) // build like access_policies_test
	// Non-admin role in context → 403.
	req := httptest.NewRequest("POST", "/api/v1/vaults/prod/role-assignments",
		strings.NewReader(`{"principal":"alice","role":"secrets-user"}`))
	req = withSessionContext(req, "non-admin-user-id", "alice", "user") // helper from existing tests
	rec := httptest.NewRecorder()
	api.Router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", rec.Code)
	}
}
```

> Use whatever session-context + router-build helpers `api/access_policies_test.go` already provides. Do not invent a new harness. If those helpers have different names, match them.

- [ ] **Step 4: Run test to verify it fails**

Run: `go test ./api/ -run TestRoleAssignments -v`
Expected: FAIL — `InitRoleAssignments`/handlers undefined.

- [ ] **Step 5: Write the handlers**

Create `api/role_assignments.go`:

```go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
	"rocketvault/common"
)

// InitRoleAssignments registers vault-scoped role-assignment routes.
func (api *API) InitRoleAssignments() {
	r := api.BaseRoutes.RoleAssignments
	one := api.BaseRoutes.RoleAssignment
	r.Handle("", ApiSessionRequired(api.App, listRoleAssignments)).Methods("GET")
	r.Handle("", ApiSessionRequired(api.App, createRoleAssignment)).Methods("POST")
	one.Handle("", ApiSessionRequired(api.App, getRoleAssignment)).Methods("GET")
	one.Handle("", ApiSessionRequired(api.App, deleteRoleAssignment)).Methods("DELETE")
}

// requireVaultManage gates assignment management to global admins or vault managers.
func requireVaultManage(c *Context, r *http.Request, vaultID uuid.UUID) bool {
	role, _ := c.Claims["role"].(string)
	if common.HasRequiredRole(role, string(model.RoleAdmin)) {
		return true
	}
	userIDStr, _ := c.Claims["user_id"].(string)
	pid, err := uuid.Parse(userIDStr)
	if err != nil {
		return false
	}
	dec, err := c.App.ServiceContainer.GetAccessPolicyService().
		CheckAccess(r.Context(), pid, model.PolicyResourceVaults, model.OpManage, vaultID)
	if err != nil {
		return false
	}
	return dec == authzServices.AccessAllowed
}

func createRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	if !requireVaultManage(c, r, vaultID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	req, err := model.AssignRoleRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Principal == "" || req.Role == "" {
		c.SetInvalidParam("principal and role are required")
		return
	}
	pType := model.PrincipalType(req.PrincipalType)
	if pType == "" {
		pType = model.PrincipalTypeUser
	}

	callerID, _ := uuid.Parse(func() string { s, _ := c.Claims["user_id"].(string); return s }())

	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	ra, err := svc.AssignRole(r.Context(), authzServices.AssignRoleInput{
		Principal:     req.Principal,
		PrincipalType: pType,
		Role:          req.Role,
		VaultID:       vaultID,
		CreatedBy:     callerID,
	})
	if err != nil {
		switch {
		case err == authzServices.ErrInvalidRole || errorsIs(err, authzServices.ErrInvalidRole):
			c.SetInvalidParam("role")
		case errorsIs(err, authzServices.ErrPrincipalNotFound):
			c.SetNotFound("principal")
		default:
			c.SetInternalError(err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ra)
}

func listRoleAssignments(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	list, err := svc.ListAssignments(r.Context(), vaultID)
	if err != nil {
		c.SetInternalError(err)
		return
	}
	if list == nil {
		list = []*model.RoleAssignment{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"role_assignments": list, "total": len(list)})
}

func getRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	id, err := uuid.Parse(c.Params.AssignmentID)
	if err != nil {
		c.SetInvalidParam("assignment_id")
		return
	}
	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	list, err := svc.ListAssignments(r.Context(), vaultID)
	if err != nil {
		c.SetInternalError(err)
		return
	}
	for _, ra := range list {
		if ra.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ra)
			return
		}
	}
	c.SetNotFound("role assignment")
}

func deleteRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	if !requireVaultManage(c, r, vaultID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}
	id, err := uuid.Parse(c.Params.AssignmentID)
	if err != nil {
		c.SetInvalidParam("assignment_id")
		return
	}
	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	if err := svc.RevokeAssignment(r.Context(), id, vaultID); err != nil {
		if errorsIs(err, authzServices.ErrAssignmentNotFound) {
			c.SetNotFound("role assignment")
			return
		}
		c.SetInternalError(err)
		return
	}
	ReturnStatusOK(w)
}
```

Add a small local helper for `errors.Is` if the file does not already import `errors` (or import `errors` and call `errors.Is` directly — preferred):

Replace `errorsIs(...)` calls with `errors.Is(...)` and add `"errors"` to the import block. (The helper name in the snippet is a placeholder; use the standard library.)

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./api/ -run TestRoleAssignments -v`
Expected: PASS.

- [ ] **Step 7: Build the whole api package**

Run: `go build ./api/...`
Expected: success.

- [ ] **Step 8: Commit**

```bash
git add api/params.go api/api.go api/role_assignments.go api/role_assignments_test.go
git commit -S -m "feat(api): vault-scoped role-assignment endpoints"
```

---

## Task 12: Purge cleanup — delete vault-scoped policies on PurgeVault

**Files:**
- Modify: `internal/services/vaults/vault_service.go`
- Modify: `internal/container/service_container.go` (pass policy repo into vault service)
- Test: `internal/services/vaults/vault_service_test.go`

Background: `role_assignments` rows are removed by the `ON DELETE CASCADE` FK when the vault row is purged, but `access_policies` has no FK to `vaults`, so vault-scoped policy rows would orphan. PurgeVault must delete them explicitly.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/vaults/vault_service_test.go` (mirror the existing vault-service test setup; it already builds a `vaultService` with a fake repo + cascade). Introduce a fake policy-cleaner and assert it is called on purge:

```go
func TestPurgeVault_DeletesVaultPolicies(t *testing.T) {
	// Build vaultService with a fake repo that returns a purgeable vault,
	// a no-op cascade, and a fake policyCleaner. Mirror existing test setup.
	cleaner := &fakePolicyCleaner{}
	svc := newVaultServiceForTest(t, withPolicyCleaner(cleaner)) // adapt to existing helpers

	if err := svc.PurgeVault(context.Background(), "prod"); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if !cleaner.called {
		t.Fatal("expected vault policies to be deleted on purge")
	}
}

type fakePolicyCleaner struct{ called bool }

func (f *fakePolicyCleaner) DeleteByVault(_ context.Context, _ uuid.UUID) error {
	f.called = true
	return nil
}
```

> If the existing vault-service tests construct the service inline rather than via helpers, replicate that inline construction and pass the new optional cleaner. Keep the cleaner OPTIONAL (nil-safe) so existing call sites that do not supply it still compile.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/services/vaults/ -run TestPurgeVault_DeletesVaultPolicies -v`
Expected: FAIL — service has no policy cleaner.

- [ ] **Step 3: Add an optional policy-cleaner dependency**

In `internal/services/vaults/vault_service.go`, define:

```go
// PolicyCleaner removes access policies scoped to a vault (used on purge).
type PolicyCleaner interface {
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
}
```

Add a field `policies PolicyCleaner` to `vaultService` and a setter or extended constructor. To avoid breaking the existing `NewVaultService` signature, add:

```go
// WithPolicyCleaner attaches an optional policy cleaner used during purge.
func (s *vaultService) WithPolicyCleaner(p PolicyCleaner) *vaultService {
	s.policies = p
	return s
}
```

In `PurgeVault` (`:226`), after `s.repo.Purge(ctx, v.ID)` succeeds, add:

```go
	if s.policies != nil {
		if err := s.policies.DeleteByVault(ctx, v.ID); err != nil {
			return fmt.Errorf("delete vault policies: %w", err)
		}
	}
```

- [ ] **Step 4: Wire the cleaner in the container**

In `internal/container/service_container.go` where the vault service is built (`:261-262`), attach the cleaner. Since `NewVaultService` returns the `VaultService` interface, expose the setter on the interface OR type-assert. Cleanest: change the construction to:

```go
	vaultCascade := vaultServices.NewCascadeAdapter(c.secretRepository, c.keyRepository, c.certificateRepository)
	vs := vaultServices.NewVaultService(c.vaultRepository, vaultCascade, c.logger)
	if withCleaner, ok := vs.(interface {
		WithPolicyCleaner(vaultServices.PolicyCleaner) *vaultServices.vaultService
	}); ok {
		_ = withCleaner // see note
	}
	c.vaultService = vs
```

> `vaultService` is unexported, so the type assertion above cannot name it. Instead, add an EXPORTED setter to the `VaultService` interface: add `SetPolicyCleaner(PolicyCleaner)` to the `VaultService` interface in `vault_service.go`, implement it on `*vaultService`, and call `c.vaultService.SetPolicyCleaner(c.accessPolicyRepository)` in the container. Use `SetPolicyCleaner` (not the chained `WithPolicyCleaner`) to keep the interface clean. Update Step 3 to implement `SetPolicyCleaner` on `*vaultService` instead of the chained helper.

Resulting container code:

```go
	c.vaultService = vaultServices.NewVaultService(c.vaultRepository, vaultCascade, c.logger)
	c.vaultService.SetPolicyCleaner(c.accessPolicyRepository)
```

And in `vault_service.go`, add to the `VaultService` interface:

```go
	SetPolicyCleaner(p PolicyCleaner)
```

with implementation:

```go
func (s *vaultService) SetPolicyCleaner(p PolicyCleaner) { s.policies = p }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/services/vaults/ -run TestPurgeVault_DeletesVaultPolicies -v`
Expected: PASS.

- [ ] **Step 6: Build + run vaults package**

Run: `go build ./... && go test ./internal/services/vaults/ -count=1`
Expected: success + PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/services/vaults/vault_service.go internal/services/vaults/vault_service_test.go internal/container/service_container.go
git commit -S -m "feat(vaults): purge deletes orphaned vault-scoped access policies"
```

---

## Task 13: Update container mock to satisfy the interface

**Files:**
- Modify: `internal/testutils/mocks.go`

- [ ] **Step 1: Add the mock method**

If `internal/testutils/mocks.go` has a mock implementing `ServiceContainerInterface`, add:

```go
// GetRoleAssignmentService returns the mocked role assignment service.
func (m *MockServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	args := m.Called()
	if v, ok := args.Get(0).(authzServices.RoleAssignmentService); ok {
		return v
	}
	return nil
}
```

> Match the receiver type and import alias the file already uses for the authorization package. If the mock uses a different style (struct fields, not testify), follow that style.

- [ ] **Step 2: Build everything**

Run: `go build ./...`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add internal/testutils/mocks.go
git commit -S -m "test(mocks): add GetRoleAssignmentService to container mock"
```

---

## Task 14: CLI `vault-access` command group

**Files:**
- Create: `cmd/vault-access/vault.go`, `grant.go`, `list.go`, `revoke.go`, `roles.go`
- Create: `cmd/vault_access.go`
- Test: `cmd/vault-access/roles_test.go`

The CLI talks to the in-process service container (same pattern as `cmd/secrets/`), reading `common.ServiceContainerKey`, `common.UserIDKey`, `common.OutputFormatterKey` from context, and resolving the vault with `common.ResolveVaultName` / a local `resolveVaultID`.

- [ ] **Step 1: Write the failing test (roles command — no service needed)**

Create `cmd/vault-access/roles_test.go`:

```go
package vaultaccess

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRolesCommand_ListsBuiltInRoles(t *testing.T) {
	parent := &cobra.Command{Use: "vault-access"}
	InitVaultAccessRoles(parent)

	var buf bytes.Buffer
	parent.SetOut(&buf)
	parent.SetArgs([]string{"roles"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"secrets-user", "crypto-user", "vault-admin"} {
		if !strings.Contains(out, want) {
			t.Fatalf("roles output missing %q: %s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/vault-access/ -run TestRolesCommand -v`
Expected: FAIL — package/func undefined.

- [ ] **Step 3: Write the vault resolution helper**

Create `cmd/vault-access/vault.go`:

```go
package vaultaccess

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// resolveVaultID resolves the --vault selection to a vault id via the service container.
func resolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error) {
	name := common.ResolveVaultName(cmd)
	v, err := sc.GetVaultService().GetVault(ctx, name)
	if err != nil {
		return uuid.Nil, fmt.Errorf("vault %q not found: %w", name, err)
	}
	return v.ID, nil
}

// addVaultFlag registers the shared --vault flag on a command.
func addVaultFlag(cmd *cobra.Command) {
	cmd.Flags().String("vault", "", "vault name (default: ROCKETVAULT_VAULT env, config, or \"default\")")
}
```

> Confirm `GetVaultService().GetVault(ctx, name)` returns a value with an `.ID` field — mirror `cmd/secrets/vault.go:14` exactly (it does). If the return type differs, match it.

- [ ] **Step 4: Write the roles command**

Create `cmd/vault-access/roles.go`:

```go
package vaultaccess

import (
	"fmt"

	"github.com/spf13/cobra"

	authz "rocketvault/internal/services/authorization"
)

// InitVaultAccessRoles registers the `roles` subcommand.
func InitVaultAccessRoles(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "List built-in vault roles and their permissions",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			for _, name := range authz.BuiltInRoleNames() {
				perms, err := authz.RolePermissions(name)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%s\n", name)
				for _, p := range perms {
					fmt.Fprintf(out, "  %s/%s\n", p[0], p[1])
				}
			}
			return nil
		},
	}
	parent.AddCommand(cmd)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./cmd/vault-access/ -run TestRolesCommand -v`
Expected: PASS.

- [ ] **Step 6: Write grant / list / revoke commands**

Create `cmd/vault-access/grant.go`:

```go
package vaultaccess

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// InitVaultAccessGrant registers the `grant` subcommand.
func InitVaultAccessGrant(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:     "grant <principal>",
		Short:   "Grant a built-in role to a principal in a vault",
		Example: "rocketvault vault-access grant alice --role secrets-user --vault prod",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			principal := args[0]
			role, _ := cmd.Flags().GetString("role")
			if role == "" {
				return fmt.Errorf("--role is required")
			}
			ptype, _ := cmd.Flags().GetString("principal-type")
			if ptype == "" {
				ptype = string(model.PrincipalTypeUser)
			}

			ctx := cmd.Context()
			callerID, _ := ctx.Value(common.UserIDKey).(uuid.UUID)
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := resolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}

			ra, err := sc.GetRoleAssignmentService().AssignRole(ctx, authz.AssignRoleInput{
				Principal:     principal,
				PrincipalType: model.PrincipalType(ptype),
				Role:          role,
				VaultID:       vaultID,
				CreatedBy:     callerID,
			})
			if err != nil {
				return fmt.Errorf("grant failed: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "granted %s to %s in vault (assignment %s)\n", role, principal, ra.ID)
			return nil
		},
	}
	cmd.Flags().String("role", "", "built-in role (see `vault-access roles`)")
	cmd.Flags().String("principal-type", "user", "principal type: user or service_account")
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
```

Create `cmd/vault-access/list.go`:

```go
package vaultaccess

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// InitVaultAccessList registers the `list` subcommand.
func InitVaultAccessList(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List role assignments in a vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := resolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			list, err := sc.GetRoleAssignmentService().ListAssignments(ctx, vaultID)
			if err != nil {
				return fmt.Errorf("list failed: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%-38s %-20s %s\n", "ASSIGNMENT-ID", "ROLE", "PRINCIPAL-ID")
			for _, ra := range list {
				fmt.Fprintf(out, "%-38s %-20s %s\n", ra.ID, ra.Role, ra.PrincipalID)
			}
			return nil
		},
	}
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
```

Create `cmd/vault-access/revoke.go`:

```go
package vaultaccess

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// InitVaultAccessRevoke registers the `revoke` subcommand.
func InitVaultAccessRevoke(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "revoke <assignment-id>",
		Short: "Revoke a role assignment in a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid assignment id: %w", err)
			}
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := resolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			if err := sc.GetRoleAssignmentService().RevokeAssignment(ctx, id, vaultID); err != nil {
				return fmt.Errorf("revoke failed: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked assignment %s\n", id)
			return nil
		},
	}
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
```

- [ ] **Step 7: Register the group**

Create `cmd/vault_access.go` (mirror `cmd/secrets.go:40`):

```go
package cmd

import (
	"github.com/spf13/cobra"

	vaultaccess "rocketvault/cmd/vault-access"
)

var vaultAccessCmd = &cobra.Command{
	Use:   "vault-access",
	Short: "Manage vault-scoped role assignments",
}

func init() {
	rootCmd.AddCommand(vaultAccessCmd)
	vaultaccess.InitVaultAccessGrant(vaultAccessCmd)
	vaultaccess.InitVaultAccessList(vaultAccessCmd)
	vaultaccess.InitVaultAccessRevoke(vaultAccessCmd)
	vaultaccess.InitVaultAccessRoles(vaultAccessCmd)
}
```

> Confirm the root command variable is named `rootCmd` (it is, per `cmd/secrets.go`). Confirm the module import path prefix is `rocketvault/` (per existing imports).

- [ ] **Step 8: Build + run CLI tests**

Run: `go build ./... && go test ./cmd/vault-access/ -count=1`
Expected: success + PASS.

- [ ] **Step 9: Commit**

```bash
git add cmd/vault-access/ cmd/vault_access.go
git commit -S -m "feat(cli): vault-access grant/list/revoke/roles commands"
```

---

## Task 15: Full verification gate

**Files:** none (verification only)

- [ ] **Step 1: Build**

Run: `go build ./...`
Expected: success, no output.

- [ ] **Step 2: Vet**

Run: `go vet ./...`
Expected: no findings related to new code.

- [ ] **Step 3: gofmt on touched files**

Run:
```bash
gofmt -l model/role_assignment.go model/access_policy.go \
  internal/services/authorization/roles.go internal/services/authorization/role_assignment_service.go \
  internal/repositories/role_assignment_repository.go internal/repositories/access_policy_repository.go \
  api/role_assignments.go api/params.go api/api.go \
  internal/services/vaults/vault_service.go internal/container/service_container.go \
  cmd/vault_access.go cmd/vault-access/*.go internal/db/db.go
```
Expected: empty output (no files need formatting). If any listed, run `gofmt -w` on them and re-commit.

- [ ] **Step 4: Full test suite**

Run: `go test ./... -count=1`
Expected: PASS across all packages.

- [ ] **Step 5: Coverage on new packages**

Run: `go test ./internal/services/authorization/ ./internal/repositories/ -cover`
Expected: ≥80% for the authorization package. If below, add cases for uncovered branches (e.g. `crypto-officer` expansion count, `RevokeAssignment` happy path with policy deletion).

- [ ] **Step 6: Final commit if any formatting/coverage fixes were made**

```bash
git add -A
git commit -S -m "chore: format and coverage fixes for vault-scoped role assignments"
```

---

## Self-Review notes (resolved)

- **Spec coverage:** §1 model/roles → Tasks 1,5,6. §2 API/routes → Tasks 11. §3 CLI → Task 14. §4 service logic (assign/revoke/list, idempotency, rollback, deny-precedence untouched, purge cleanup, vault-admin gate) → Tasks 9,11,12. §5 migration → Tasks 2,3,4. §6 testing → embedded per task + Task 15.
- **`wrap`/`unwrap`:** confirmed absent from the operation enum; `crypto-user` uses sign/verify/encrypt/decrypt only. Spec's conditional resolved.
- **Transactions:** the codebase has no cross-repo tx helper; the plan uses compensating cleanup (documented in Task 9) instead of inventing one. Test asserts no orphan rows on failure.
- **Purge orphan policies:** `access_policies` has no FK to `vaults`, so Task 12 adds explicit `DeleteByVault` on purge (role_assignments rows are handled by their FK cascade).
- **Type consistency:** `RoleAssignmentService`, `AssignRoleInput`, `ExpandRole(role, principalID, principalType, vaultID, assignmentID)`, `ListByVault`, `DeleteByAssignmentID`, `DeleteByVault`, `GetRoleAssignmentService`, `SetPolicyCleaner` are used identically across tasks.
- **Known follow-up not blocking this plan:** the API `getRoleAssignment` does a list-and-filter rather than a direct `GetByID` through the service (the service exposes list, not get-by-id-scoped-to-vault). Acceptable for the audit-view use case; a direct getter can be added later if needed.
