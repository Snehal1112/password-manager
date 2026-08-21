# Destructive Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register the four destructive tools — `delete_item`, `purge_item`, `revoke_vault_role` and `purge_vault` — completing the destructive tier.

**Architecture:** Plan 21's tool shape with `TierDestructive`, plus a `requireConfirmation` call before every action. The only per-tool variation is *what* gets confirmed, which differs because what identifies the target differs.

**Tech Stack:** Go 1.25, `github.com/modelcontextprotocol/go-sdk/mcp` v1.7.0, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Destructive tier".

**Plan-of-plans:** This is plan 25 of 31, completing Group G. Requires plans 23 and 24 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **`registerIf(s, TierDestructive, ...)`** — absent unless `allow_destructive` is set.
- **Every tool calls `requireConfirmation` before acting**, and no tool may skip it.
- **`Destructive: true` on all four annotations.** A host relies on this to prompt; understating it here would silently remove the operator's last check.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## What each tool confirms, and why it differs

| Tool | Confirms | Because |
|---|---|---|
| `delete_item` | the item name | That is what the caller named. |
| `purge_item` | the item name | Same, and this one is irreversible. |
| `purge_vault` | the vault name | The vault is the target. |
| `revoke_vault_role` | the assignment id | A principal can hold several roles in a vault, so only the id identifies which grant is being removed. |

Confirming a principal name for `revoke_vault_role` would be actively misleading: a caller could confirm `"alice"` while removing whichever of alice's three roles the id happened to point at. The id is the only unambiguous target.

## `delete_item` is destructive despite being reversible

A soft-deleted item is recoverable until its retention period elapses, so `delete_item` is less final than `purge_item`. It is still annotated and gated as destructive, for two reasons: it removes access to a live secret immediately, which can break a running system regardless of recoverability; and a tier that included "delete" under writes would make `allow_write` a much larger grant than its name suggests.

The distinction between the two is carried in the descriptions instead, where it is useful to a caller choosing between them.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/tools_destructive.go` (new) | `registerDestructiveTools` and all four tools |
| `internal/mcpserver/tools_destructive_test.go` (new) | All four over the real protocol |
| `internal/mcpserver/register.go` (modify) | Add the registration call |

---

### Task 1: `delete_item` and `purge_item`

**Files:**
- Create: `internal/mcpserver/tools_destructive.go`
- Create: `internal/mcpserver/tools_destructive_test.go`
- Modify: `internal/mcpserver/register.go`

**Interfaces:**
- Consumes: `vaultapi.Client.DeleteItem`, `PurgeItem` (plan 23); `requireConfirmation` (plan 24); `parseDeletedKind` (plan 14).
- Produces: `func registerDestructiveTools(s *Server)`, `deleteItemArgs`, `deleteItemResult`, `purgeItemArgs`, `purgeItemResult`.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/tools_destructive_test.go`:

```go
package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeleteItem_IsAbsentWithoutAllowDestructive(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true // Write alone must not unlock deletion.
	s := f.server(t, cfg)
	registerDestructiveTools(s)

	require.Empty(t, s.RegisteredTools(),
		"allow_write must not be a larger grant than its name suggests")
}

func TestDeleteItem_SoftDeletesTheItem(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	var got deleteItemResult
	structured(t, callTool(t, s, "delete_item", map[string]any{
		"type": "secrets", "name": "db-password", "confirm": "db-password",
	}), &got)

	require.Equal(t, "db-password", got.Name)
	require.True(t, got.Recoverable, "a soft-deleted item can still be restored")
	require.True(t, f.hit("/api/v1/vaults/default/secrets/"+dbSecretUUID))
}

func TestDeleteItem_RefusesWithoutConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "delete_item", map[string]any{"type": "secrets", "name": "db-password"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "confirm")
	require.Empty(t, f.requested, "an unconfirmed call must make no request at all")
}

func TestDeleteItem_RefusesAMismatchedConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "delete_item", map[string]any{
		"type": "secrets", "name": "db-password", "confirm": "api-key",
	})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestDeleteItem_SkipsConfirmationWhenDisabled(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	f.writeResponse = `{"status":"OK"}`

	cfg := destructiveConfig()
	cfg.ConfirmDestructive = false
	s := f.server(t, cfg)
	registerDestructiveTools(s)

	result := callTool(t, s, "delete_item", map[string]any{"type": "secrets", "name": "db-password"})
	require.False(t, result.IsError)
}

func TestPurgeItem_PermanentlyRemovesTheItem(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"old-password"}],"total":1}`,
	})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	var got purgeItemResult
	structured(t, callTool(t, s, "purge_item", map[string]any{
		"type": "secrets", "name": "old-password", "confirm": "old-password",
	}), &got)

	require.Equal(t, "old-password", got.Name)
	require.True(t, f.hit("/api/v1/vaults/default/deleted/secrets/"+dbSecretUUID+"/purge"))
}

func TestPurgeItem_ResolvesAgainstTheDeletedListing(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	_ = callTool(t, s, "purge_item", map[string]any{
		"type": "secrets", "name": "gone", "confirm": "gone",
	})
	require.False(t, f.hit("/api/v1/vaults/default/secrets"),
		"only an already-deleted item can be purged")
}

func TestPurgeItem_RefusesWithoutConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_item", map[string]any{"type": "secrets", "name": "gone"})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestPurgeItem_DescriptionSaysItIsIrreversible(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	var deleteDesc, purgeDesc string
	for _, tool := range tools.Tools {
		switch tool.Name {
		case "delete_item":
			deleteDesc = tool.Description
		case "purge_item":
			purgeDesc = tool.Description
		}
	}

	require.Contains(t, purgeDesc, "annot be undone")
	require.Contains(t, deleteDesc, "recover",
		"the difference between the two is what a caller choosing between them needs")
}

func TestDeleteAndPurge_AreAnnotatedDestructive(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	seen := 0
	for _, tool := range tools.Tools {
		if tool.Name != "delete_item" && tool.Name != "purge_item" {
			continue
		}
		seen++
		require.False(t, tool.Annotations.ReadOnlyHint)
		require.NotNil(t, tool.Annotations.DestructiveHint)
		require.True(t, *tool.Annotations.DestructiveHint,
			"a host relies on this to prompt; understating it removes the operator's last check")
	}
	require.Equal(t, 2, seen)
}

func TestPurgeItem_ProtectionRefusalIsSurfaced(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	f.failWith("/api/v1/vaults/default/deleted/secrets/"+dbSecretUUID+"/purge", http.StatusForbidden)
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_item", map[string]any{
		"type": "secrets", "name": "gone", "confirm": "gone",
	})
	require.True(t, result.IsError,
		"purge protection is enforced server-side and its refusal must reach the caller")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestDeleteItem_|TestPurgeItem_|TestDeleteAndPurge_' -v`
Expected: FAIL — `undefined: registerDestructiveTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_destructive.go`:

```go
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type deleteItemArgs struct {
	Type    string `json:"type" jsonschema:"which kind of item to delete: secrets, keys or certificates"`
	Name    string `json:"name" jsonschema:"the item's name, or its id"`
	Confirm string `json:"confirm,omitempty" jsonschema:"repeat the item's name exactly to confirm the deletion"`
	Vault   string `json:"vault,omitempty" jsonschema:"the vault holding the item; defaults to the server's configured vault"`
}

type deleteItemResult struct {
	Vault string `json:"vault"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	// Recoverable states that the item can still be restored, which is the
	// difference between this tool and purge_item.
	Recoverable bool `json:"recoverable"`
}

type purgeItemArgs struct {
	Type    string `json:"type" jsonschema:"which kind of item to purge: secrets, keys or certificates"`
	Name    string `json:"name" jsonschema:"the deleted item's name, or its id; list_deleted shows what can be purged"`
	Confirm string `json:"confirm,omitempty" jsonschema:"repeat the item's name exactly to confirm this permanent deletion"`
	Vault   string `json:"vault,omitempty" jsonschema:"the vault holding the item; defaults to the server's configured vault"`
}

type purgeItemResult struct {
	Vault string `json:"vault"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	// Purged is always true on success, and exists so the result reads as a
	// statement of what happened rather than an empty object.
	Purged bool `json:"purged"`
}

// registerDestructiveTools adds the tools that remove things.
//
// delete_item is gated here rather than under writes despite being
// reversible: it removes access to a live secret immediately, which can break
// a running system whatever the retention policy says, and folding deletion
// into allow_write would make that flag a much larger grant than its name
// suggests.
func registerDestructiveTools(s *Server) {
	registerIf(s, TierDestructive, "delete_item",
		"Soft-delete a secret, key or certificate. The item stops working immediately but can be restored with "+
			"recover_deleted until its retention period ends. Requires confirm to repeat the item's name.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: true},
		s.handleDeleteItem)

	registerIf(s, TierDestructive, "purge_item",
		"Permanently destroy a soft-deleted secret, key or certificate. This cannot be undone and the item is not "+
			"recoverable afterwards. Requires confirm to repeat the item's name.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: true},
		s.handlePurgeItem)
}

func (s *Server) handleDeleteItem(ctx context.Context, _ *mcp.CallToolRequest, args deleteItemArgs) (*mcp.CallToolResult, deleteItemResult, error) {
	kind, err := parseDeletedKind(args.Type)
	if err != nil {
		return errorResult("%s", err), deleteItemResult{}, nil
	}
	if args.Name == "" {
		return errorResult("delete_item requires a name"), deleteItemResult{}, nil
	}
	if refusal := s.requireConfirmation("delete_item", args.Name, args.Confirm); refusal != nil {
		return refusal, deleteItemResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), deleteItemResult{}, nil
	}

	if err := s.client.DeleteItem(ctx, vault, kind, args.Name); err != nil {
		return errorResult("could not delete %s %q in vault %q: %s",
			args.Type, args.Name, vault, err), deleteItemResult{}, nil
	}

	return nil, deleteItemResult{
		Vault:       vault,
		Type:        args.Type,
		Name:        args.Name,
		Recoverable: true,
	}, nil
}

func (s *Server) handlePurgeItem(ctx context.Context, _ *mcp.CallToolRequest, args purgeItemArgs) (*mcp.CallToolResult, purgeItemResult, error) {
	kind, err := parseDeletedKind(args.Type)
	if err != nil {
		return errorResult("%s", err), purgeItemResult{}, nil
	}
	if args.Name == "" {
		return errorResult("purge_item requires a name"), purgeItemResult{}, nil
	}
	if refusal := s.requireConfirmation("purge_item", args.Name, args.Confirm); refusal != nil {
		return refusal, purgeItemResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), purgeItemResult{}, nil
	}

	if err := s.client.PurgeItem(ctx, vault, kind, args.Name); err != nil {
		return errorResult("could not purge %s %q in vault %q: %s",
			args.Type, args.Name, vault, err), purgeItemResult{}, nil
	}

	return nil, purgeItemResult{Vault: vault, Type: args.Type, Name: args.Name, Purged: true}, nil
}
```

Add `registerDestructiveTools(s)` to `RegisterAllTools`.

Note the ordering inside each handler: **confirmation is checked before `ResolveVault` and before any network call.** An unconfirmed call must cost nothing and reveal nothing.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run 'TestDeleteItem_|TestPurgeItem_|TestDeleteAndPurge_' -v`
Expected: PASS — all eleven tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_destructive.go internal/mcpserver/tools_destructive_test.go internal/mcpserver/register.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the delete_item and purge_item tools

delete_item is gated as destructive despite being reversible. It removes
access to a live secret immediately, which can break a running system whatever
the retention policy says, and folding deletion into allow_write would make
that flag a much larger grant than its name suggests. The reversibility
difference is carried in the descriptions, where a caller choosing between the
two can use it.

Confirmation is checked before resolving the vault and before any network
call, so an unconfirmed call costs nothing and reveals nothing."
```

---

### Task 2: `purge_vault`

**Files:**
- Modify: `internal/mcpserver/tools_destructive.go`
- Modify: `internal/mcpserver/tools_destructive_test.go` (append)

**Interfaces:**
- Consumes: `vaultapi.Client.PurgeVault` (plan 23), `requireConfirmation` (plan 24).
- Produces: `purgeVaultArgs`, `purgeVaultResult`.

**This is the most destructive tool in the server**, and two things follow from that:

- **The vault is a required argument with no default.** Every other tool falls back to `mcp.vault` when none is given. This one does not: defaulting the target of an irreversible whole-vault deletion to whatever the config happens to say is exactly the kind of convenience that produces a catastrophe. The caller must name it.
- **The allowlist still applies**, through `ResolveVault`, so a pinned server cannot purge a vault outside its scope.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/tools_destructive_test.go`:

```go
func TestPurgeVault_PurgesTheNamedVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	var got purgeVaultResult
	structured(t, callTool(t, s, "purge_vault", map[string]any{
		"vault": "default", "confirm": "default",
	}), &got)

	require.Equal(t, "default", got.Vault)
	require.True(t, got.Purged)
	require.True(t, f.hit("/api/v1/vaults/default/purge"))
}

func TestPurgeVault_RequiresAnExplicitVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_vault", map[string]any{"confirm": "default"})
	require.True(t, result.IsError,
		"defaulting the target of an irreversible whole-vault deletion would be reckless")
	require.Contains(t, renderContent(result), "vault")
	require.Empty(t, f.requested)
}

func TestPurgeVault_RefusesWithoutConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_vault", map[string]any{"vault": "default"})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestPurgeVault_ConfirmsTheVaultName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_vault", map[string]any{
		"vault": "default", "confirm": "some-other-vault",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "default")
	require.Empty(t, f.requested)
}

func TestPurgeVault_RespectsTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := destructiveConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerDestructiveTools(s)

	result := callTool(t, s, "purge_vault", map[string]any{"vault": "prod", "confirm": "prod"})
	require.True(t, result.IsError,
		"a pinned server must not be able to purge a vault outside its scope")
	require.Empty(t, f.requested)
}

func TestPurgeVault_DescriptionSaysItIsIrreversible(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "purge_vault" {
			require.Contains(t, tool.Description, "annot be undone")
			require.True(t, *tool.Annotations.DestructiveHint)
			return
		}
	}
	t.Fatal("purge_vault was not registered")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestPurgeVault_ -v`
Expected: FAIL — `purge_vault` is not registered.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/mcpserver/tools_destructive.go`:

```go
// purgeVaultArgs are the arguments to purge_vault.
//
// Vault is required and has no default. Every other tool falls back to
// mcp.vault when none is given; this one does not, because defaulting the
// target of an irreversible whole-vault deletion to whatever the
// configuration happens to say is exactly the convenience that produces a
// catastrophe.
type purgeVaultArgs struct {
	Vault   string `json:"vault" jsonschema:"the name of the vault to purge; there is no default for this tool"`
	Confirm string `json:"confirm,omitempty" jsonschema:"repeat the vault's name exactly to confirm this permanent deletion"`
}

type purgeVaultResult struct {
	Vault  string `json:"vault"`
	Purged bool   `json:"purged"`
}

func (s *Server) handlePurgeVault(ctx context.Context, _ *mcp.CallToolRequest, args purgeVaultArgs) (*mcp.CallToolResult, purgeVaultResult, error) {
	if args.Vault == "" {
		return errorResult(
			"purge_vault requires an explicit vault: this permanently destroys a vault and everything in it, " +
				"so it does not fall back to the configured default"), purgeVaultResult{}, nil
	}
	if refusal := s.requireConfirmation("purge_vault", args.Vault, args.Confirm); refusal != nil {
		return refusal, purgeVaultResult{}, nil
	}

	// The allowlist still applies, so a pinned server cannot reach outside
	// its scope even with a confirmed call.
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), purgeVaultResult{}, nil
	}

	if err := s.client.PurgeVault(ctx, vault); err != nil {
		return errorResult("could not purge vault %q: %s", vault, err), purgeVaultResult{}, nil
	}
	return nil, purgeVaultResult{Vault: vault, Purged: true}, nil
}
```

Register it in `registerDestructiveTools`:

```go
	registerIf(s, TierDestructive, "purge_vault",
		"Permanently destroy a soft-deleted vault and everything it contains. This cannot be undone. "+
			"The vault must be named explicitly and confirm must repeat it.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: true},
		s.handlePurgeVault)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestPurgeVault_ -v`
Expected: PASS — all six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_destructive.go internal/mcpserver/tools_destructive_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the purge_vault tool

The vault is required with no default. Every other tool falls back to
mcp.vault; this one does not, because defaulting the target of an irreversible
whole-vault deletion to whatever the configuration happens to say is exactly
the convenience that produces a catastrophe.

The allowlist still applies after confirmation, so a pinned server cannot
purge a vault outside its scope even with a correctly confirmed call."
```

---

### Task 3: `revoke_vault_role`

**Files:**
- Modify: `internal/mcpserver/tools_destructive.go`
- Modify: `internal/mcpserver/tools_destructive_test.go` (append)

**Interfaces:**
- Consumes: `vaultapi.Client.DeleteRoleAssignment` (plan 23), `requireConfirmation` (plan 24).
- Produces: `revokeVaultRoleArgs`, `revokeVaultRoleResult`.

**It takes an assignment id, and the description must say so.** Plan 23's `DeleteRoleAssignment` rejects a principal name with an explanatory error, but a model asked to "revoke alice's access" will pass `"alice"` unless told otherwise, then have to recover from a failure it could have avoided. The description names `list_role_assignments` as where the id comes from.

**It confirms the assignment id, not the principal name.** Confirming `"alice"` would be misleading: a principal can hold several roles in a vault, and the confirmation would appear to authorise removing "alice's access" while actually removing whichever single grant the id pointed at.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/tools_destructive_test.go`:

```go
func TestRevokeVaultRole_RevokesByAssignmentID(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"status":"OK"}`
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	var got revokeVaultRoleResult
	structured(t, callTool(t, s, "revoke_vault_role", map[string]any{
		"assignment_id": assignmentID, "confirm": assignmentID,
	}), &got)

	require.Equal(t, assignmentID, got.AssignmentID)
	require.True(t, got.Revoked)
	require.True(t, f.hit("/api/v1/vaults/default/role-assignments/"+assignmentID))
}

func TestRevokeVaultRole_RejectsAPrincipalName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "revoke_vault_role", map[string]any{
		"assignment_id": "alice", "confirm": "alice",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "assignment id")
	require.Empty(t, f.requested)
}

func TestRevokeVaultRole_DescriptionPointsAtListRoleAssignments(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "revoke_vault_role" {
			require.Contains(t, tool.Description, "list_role_assignments",
				"a model asked to revoke alice's access needs to know where the id comes from")
			require.Contains(t, tool.Description, "assignment")
			return
		}
	}
	t.Fatal("revoke_vault_role was not registered")
}

func TestRevokeVaultRole_ConfirmsTheAssignmentIDNotAPrincipal(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "revoke_vault_role", map[string]any{
		"assignment_id": assignmentID, "confirm": "alice",
	})
	require.True(t, result.IsError,
		"a principal can hold several roles, so confirming a name would authorise the wrong thing")
	require.Empty(t, f.requested)
}

func TestRevokeVaultRole_RefusesWithoutConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "revoke_vault_role", map[string]any{"assignment_id": assignmentID})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestRevokeVaultRole_ForbiddenNamesTheDataAccessAdminRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults/default/role-assignments/"+assignmentID, http.StatusForbidden)
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	result := callTool(t, s, "revoke_vault_role", map[string]any{
		"assignment_id": assignmentID, "confirm": assignmentID,
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Data Access Administrator")
}

func TestDestructiveTier_HasExactlyFourTools(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())
	registerDestructiveTools(s)

	require.Equal(t,
		[]string{"delete_item", "purge_item", "purge_vault", "revoke_vault_role"},
		s.RegisteredTools())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestRevokeVaultRole_|TestDestructiveTier_' -v`
Expected: FAIL — `revoke_vault_role` is not registered.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/mcpserver/tools_destructive.go`:

```go
// revokeVaultRoleArgs are the arguments to revoke_vault_role.
//
// The target is an assignment id, not a principal. One principal can hold
// several roles in a vault, so a name would not identify which grant to
// remove -- and confirming a name would appear to authorise removing "alice's
// access" while actually removing whichever single grant the id pointed at.
type revokeVaultRoleArgs struct {
	AssignmentID string `json:"assignment_id" jsonschema:"the role assignment's id, from list_role_assignments"`
	Confirm      string `json:"confirm,omitempty" jsonschema:"repeat the assignment id exactly to confirm the revocation"`
	Vault        string `json:"vault,omitempty" jsonschema:"the vault holding the assignment; defaults to the server's configured vault"`
}

type revokeVaultRoleResult struct {
	Vault        string `json:"vault"`
	AssignmentID string `json:"assignment_id"`
	Revoked      bool   `json:"revoked"`
}

func (s *Server) handleRevokeVaultRole(ctx context.Context, _ *mcp.CallToolRequest, args revokeVaultRoleArgs) (*mcp.CallToolResult, revokeVaultRoleResult, error) {
	if args.AssignmentID == "" {
		return errorResult(
			"revoke_vault_role requires an assignment id: use list_role_assignments to find it"), revokeVaultRoleResult{}, nil
	}
	if refusal := s.requireConfirmation("revoke_vault_role", args.AssignmentID, args.Confirm); refusal != nil {
		return refusal, revokeVaultRoleResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), revokeVaultRoleResult{}, nil
	}

	if err := s.client.DeleteRoleAssignment(ctx, vault, args.AssignmentID); err != nil {
		return errorResult("could not revoke assignment %q in vault %q: %s",
			args.AssignmentID, vault, err), revokeVaultRoleResult{}, nil
	}

	return nil, revokeVaultRoleResult{Vault: vault, AssignmentID: args.AssignmentID, Revoked: true}, nil
}
```

Register it in `registerDestructiveTools`:

```go
	registerIf(s, TierDestructive, "revoke_vault_role",
		"Revoke a role assignment in a vault, removing that principal's access under that role. "+
			"Takes the assignment's id, which list_role_assignments provides -- not a username, since one principal "+
			"can hold several roles. Requires confirm to repeat the assignment id.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: true},
		s.handleRevokeVaultRole)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_destructive.go internal/mcpserver/tools_destructive_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the revoke_vault_role tool

It takes an assignment id and its description says so, naming
list_role_assignments as the source -- a model asked to revoke alice's access
will otherwise pass a username and have to recover from an avoidable failure.

Confirmation echoes the assignment id rather than a principal name. A
principal can hold several roles in a vault, so confirming a name would appear
to authorise removing all of alice's access while actually removing whichever
single grant the id pointed at."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ -race -v
go vet ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

The destructive tier is complete at four tools. Confirm the counts:

```bash
go test ./internal/mcpserver/ -run 'TestDestructiveTier_HasExactlyFourTools|TestRegisterAllTools_' -v
```

Surface by configuration at this point:

| Configuration | Tools |
|---|---|
| default | 10 |
| `allow_write` | 19 |
| `allow_write` + `allow_destructive` | 23 |

Confirm that no destructive tool can act without confirmation:

```bash
go test ./internal/mcpserver/ -run 'RefusesWithoutConfirmation|RefusesAMismatched|ConfirmsThe' -v
```

Every one of those tests asserts `f.requested` is empty, so a refusal costs no
request and reveals nothing about whether the target exists.

## Notes for the next plan

Group G is complete. Plans 26 and 27 add the crypto tier, bringing the surface
to 27.

Two things carry forward:

- **`decrypt` is gated twice** — on `allow_crypto` for the tier, and
  additionally on `allow_secret_values`, because its output *is* plaintext.
  Plan 27 must not treat the tier flag as sufficient.
- **Crypto tools need no confirmation.** They mutate nothing. The reason they
  are gated at all is that they use the vault's private key on the caller's
  behalf, which is a distinct authority from reading or writing — not because
  they destroy anything.
