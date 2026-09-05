# vault-access Remote Adapter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `rocketvault vault-access grant/list/revoke` work against a remote server, and establish the adapter pattern the remaining five resource groups will copy.

**Architecture:** Each command keeps its existing `RunE` and gains an early remote branch that pulls the `*vaultapi.Client` from context, resolves the vault name, calls the typed method, converts the result to `model.*`, and prints exactly what local mode prints. The three shared pieces it builds on — vault resolution, error mapping, type conversion — land in `03a`.

**Tech Stack:** Go 1.24, cobra, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`

**Depends on:**
- `2026-09-03-cli-remote-vaultapi-03a-adapter-primitives.md` — `ResolveRemoteVault`, `CLIError` and `RoleAssignmentFromAPI` must all exist.
- `2026-09-03-cli-remote-vaultapi-02b-remote-login.md` — Task 3 adds an entry to the `remoteCapableCommands` map that `02b` Task 2 creates, and Task 3 Step 5's verification logs in with `rocketvault users login`, which `02b` unblocks. `02b` in turn depends on `02a` for `common.RemoteClientKey`.

**This is the pattern proof.** If the shape here is wrong, it is far cheaper to learn it now than after keys, certificates, audit and vaults have copied it. Review this plan's output before starting plan 04.

## Global Constraints

- Local mode must remain byte-for-byte unchanged for any invocation that sets none of `--server`, `ROCKETVAULT_ADDR`, or a current context.
- A command that resolves a remote target must never silently fall back to operating on the local instance.
- Remote output must be identical to local output for the same command.
- Remote mode performs no client-side authorization check. The server owns that decision; the CLI maps its 401/403 into readable text.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Remote branch for `vault-access grant`

**Files:**
- Modify: `cmd/vault-access/grant.go`
- Test: `cmd/vault-access/grant_remote_test.go`

**Interfaces:**
- Consumes: `cliclient.ResolveRemoteVault`, `cliclient.CLIError`, `cliclient.RoleAssignmentFromAPI`, `common.RemoteClientKey`, `common.RemoteTargetKey`.
- Produces: `func runGrantRemote(cmd *cobra.Command, client *vaultapi.Client, target *cliclient.Target, principal, role, ptype string) error` — the shape later groups copy.

- [ ] **Step 1: Write the failing test**

Create `cmd/vault-access/grant_remote_test.go`:

```go
package vaultaccess

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/vaultapi"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func TestGrantRemote_PostsToTheVaultScopedRoute(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody vaultapi.GrantRoleRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                 uuid.New().String(),
			"principal_id":       uuid.New().String(),
			"principal_username": "alice",
			"principal_type":     "user",
			"role":               "Key Vault Administrator",
			"vault_name":         "payments",
			"created_at":         "2026-09-03T10:00:00Z",
		})
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "", "")
	require.NoError(t, cmd.Flags().Set("vault", "payments"))
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetContext(context.Background())

	err = runGrantRemote(cmd, client, &cliclient.Target{Server: srv.URL},
		"alice", "Key Vault Administrator", "user")
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/vaults/payments/role-assignments", gotPath)
	assert.Equal(t, "Bearer tok", gotAuth)
	assert.Equal(t, "alice", gotBody.Principal)
	assert.Equal(t, "Key Vault Administrator", gotBody.Role)
	assert.Equal(t, "user", gotBody.PrincipalType)
	assert.Contains(t, out.String(), "granted Key Vault Administrator to alice")
}

func TestGrantRemote_ForbiddenIsReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "", "")
	require.NoError(t, cmd.Flags().Set("vault", "payments"))
	cmd.SetContext(context.Background())

	err = runGrantRemote(cmd, client, &cliclient.Target{Server: srv.URL},
		"alice", "Key Vault Administrator", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment")
}
```

Add `"bytes"` to the import block.

Two things about the test setup that are load-bearing, not style:

- **`Set` the vault flag; do not give it a default.** `ResolveRemoteVault` only reads the flag when `cmd.Flags().Changed("vault")` is true (`03a` Task 1 Step 3, pinned by its own `TestResolveRemoteVault_UnchangedFlagDefaultLosesToEnv`). A flag declared as `String("vault", "payments", "")` and never `Set` leaves `Changed` false, so resolution falls through to `model.DefaultVaultName` and every path assertion in this file fails on `/api/v1/vaults/default/...`.
- **Neutralise the environment.** Add `t.Setenv("ROCKETVAULT_VAULT", "")` at the top of each test. `ResolveRemoteVault` consults that variable, so without this the suite passes or fails depending on the developer's shell.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/vault-access/ -run TestGrantRemote -v`
Expected: FAIL — `undefined: runGrantRemote`.

- [ ] **Step 3: Add the remote function and the dispatch branch**

Add to `cmd/vault-access/grant.go`:

```go
// runGrantRemote grants a role against a remote server. Remote mode runs no
// client-side authorization check: the server owns that decision, and its
// 403 is mapped into readable text rather than pre-empted here.
func runGrantRemote(
	cmd *cobra.Command,
	client *vaultapi.Client,
	target *cliclient.Target,
	principal, role, ptype string,
) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	ra, err := client.CreateRoleAssignment(cmd.Context(), vault, vaultapi.GrantRoleRequest{
		Principal:     principal,
		PrincipalType: ptype,
		Role:          role,
	})
	if err != nil {
		return cliclient.CLIError("grant a role", err)
	}

	resp := cliclient.RoleAssignmentFromAPI(ra)
	fmt.Fprintf(cmd.OutOrStdout(), "granted %s to %s in vault (assignment %s)\n", //nolint:errcheck
		resp.Role, principal, resp.ID)
	return nil
}
```

In the existing `RunE`, insert the branch **immediately after the `ctx := cmd.Context()` already declared at `grant.go:52`**, and after `ptype` is defaulted. Reuse that `ctx` — do not redeclare it, or the file stops compiling with "no new variables on left side of `:=`":

```go
			if client, ok := ctx.Value(common.RemoteClientKey).(*vaultapi.Client); ok && client != nil {
				target, _ := ctx.Value(common.RemoteTargetKey).(*cliclient.Target)
				return runGrantRemote(cmd, client, target, principal, role, ptype)
			}
```

The local path below it is unchanged, including its `requireCanManageRoleAssignments` check (`grant.go:62`) — the remote branch returns before reaching it, and the server runs the equivalent check itself (`api/role_assignments.go:70`).

`grant.go` imports neither `rocketvault/internal/cliclient` nor `rocketvault/internal/vaultapi` today; add both.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/vault-access/ -run TestGrantRemote -v`
Expected: PASS, both.

- [ ] **Step 5: Confirm local mode is untouched**

Run: `go test ./cmd/vault-access/...`
Expected: PASS, including the pre-existing `authz_test.go` and `roles_test.go`.

- [ ] **Step 6: Commit**

```bash
git add cmd/vault-access/grant.go cmd/vault-access/grant_remote_test.go
git commit -S -m "feat(cli): grant vault roles against a remote server

vault-access grant gains a remote branch calling vaultapi's
CreateRoleAssignment, which has existed since the MCP server shipped but
was unreachable from the CLI. Local dispatch is unchanged."
```

---

### Task 2: Remote branches for `list` and `revoke`

**Files:**
- Modify: `cmd/vault-access/list.go`, `cmd/vault-access/revoke.go`
- Test: `cmd/vault-access/list_remote_test.go`, `cmd/vault-access/revoke_remote_test.go`

**Interfaces:**
- Produces: `runListRemote(cmd, client, target) error`, `runRevokeRemote(cmd, client, target, assignmentID string) error`.

- [ ] **Step 1: Write the failing tests**

The same two setup rules from Task 1 Step 1 apply to every test here: `Set` the vault flag rather than defaulting it, and `t.Setenv("ROCKETVAULT_VAULT", "")` at the top. Both are load-bearing — see the reasoning there.

`list_remote_test.go` asserts the GET path and that output matches local's column layout:

```go
func TestListRemote_PrintsSameColumnsAsLocal(t *testing.T) {
	id, principalID := uuid.New(), uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vaults/payments/role-assignments", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"role_assignments": []map[string]any{{
				"id": id.String(), "principal_id": principalID.String(),
				"principal_type": "user", "role": "Key Vault Administrator",
				"vault_name": "payments", "created_at": "2026-09-03T10:00:00Z",
			}},
			"total": 1,
		})
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "", "")
	require.NoError(t, cmd.Flags().Set("vault", "payments"))
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetContext(context.Background())

	require.NoError(t, runListRemote(cmd, client, &cliclient.Target{Server: srv.URL}))

	got := out.String()
	assert.Contains(t, got, "ASSIGNMENT-ID")
	assert.Contains(t, got, "ROLE")
	assert.Contains(t, got, "PRINCIPAL-ID")
	assert.Contains(t, got, id.String())
	assert.Contains(t, got, "Key Vault Administrator")
}
```

`revoke_remote_test.go` asserts the DELETE path and that a non-UUID argument is rejected before any request is made:

```go
func TestRevokeRemote_DeletesByAssignmentID(t *testing.T) {
	id := uuid.New()
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "", "")
	require.NoError(t, cmd.Flags().Set("vault", "payments"))
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetContext(context.Background())

	require.NoError(t, runRevokeRemote(cmd, client, &cliclient.Target{Server: srv.URL}, id.String()))
	assert.Equal(t, "/api/v1/vaults/payments/role-assignments/"+id.String(), gotPath)
	assert.Equal(t, http.MethodDelete, gotMethod)
	assert.Contains(t, out.String(), "revoked assignment "+id.String())
}

func TestRevokeRemote_RejectsPrincipalName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("no request should be made for a non-UUID argument")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "", "")
	require.NoError(t, cmd.Flags().Set("vault", "payments"))
	cmd.SetContext(context.Background())

	err = runRevokeRemote(cmd, client, &cliclient.Target{Server: srv.URL}, "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assignment id")
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/vault-access/ -run "TestListRemote|TestRevokeRemote" -v`
Expected: FAIL — both functions undefined.

- [ ] **Step 3: Implement both**

In `cmd/vault-access/list.go`:

```go
// runListRemote lists role assignments from a remote server, printing the
// same columns the local path prints.
func runListRemote(cmd *cobra.Command, client *vaultapi.Client, target *cliclient.Target) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	list, _, err := client.ListRoleAssignments(cmd.Context(), vault, 0)
	if err != nil {
		return cliclient.CLIError("list role assignments", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%-38s %-20s %s\n", "ASSIGNMENT-ID", "ROLE", "PRINCIPAL-ID") //nolint:errcheck
	for i := range list {
		ra := cliclient.RoleAssignmentFromAPI(&list[i])
		fmt.Fprintf(out, "%-38s %-20s %s\n", ra.ID, ra.Role, ra.PrincipalID) //nolint:errcheck
	}
	return nil
}
```

In `cmd/vault-access/revoke.go`:

```go
// runRevokeRemote revokes one role assignment on a remote server.
// DeleteRoleAssignment rejects a non-UUID argument before issuing a request,
// since one principal can hold several roles in a vault and a name is
// ambiguous.
func runRevokeRemote(
	cmd *cobra.Command,
	client *vaultapi.Client,
	target *cliclient.Target,
	assignmentID string,
) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	if err := client.DeleteRoleAssignment(cmd.Context(), vault, assignmentID); err != nil {
		return cliclient.CLIError("revoke a role assignment", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "revoked assignment %s\n", assignmentID) //nolint:errcheck
	return nil
}
```

Add the same dispatch branch used in Task 1 Step 3 to both commands' `RunE`, reusing the `ctx := cmd.Context()` each already declares (`list.go:34`, `revoke.go:38`) rather than redeclaring it, and placing the branch before the service-container lookup. The call differs per command:

```go
	// list.go -- immediately after ctx is declared
	return runListRemote(cmd, client, target)

	// revoke.go -- after the existing uuid.Parse at revoke.go:34-37, so the
	// local "invalid assignment id" check also guards remote input and `id`
	// is in scope
	return runRevokeRemote(cmd, client, target, id.String())
```

Placing revoke's branch after the parse means `DeleteRoleAssignment`'s own non-UUID rejection (`internal/vaultapi/destructive.go:92-96`) is reachable only from the unit test. That is fine — the test still pins the client's contract — but it is deliberate, not an oversight.

Both files need `rocketvault/internal/cliclient` and `rocketvault/internal/vaultapi` added to their imports. `list_remote_test.go` and `revoke_remote_test.go` use the same import block as `grant_remote_test.go` (including `"bytes"`), minus anything they do not reference; the `staticToken` helper is declared once in `grant_remote_test.go` and shared across the package, so do not redeclare it.

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./cmd/vault-access/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/vault-access/list.go cmd/vault-access/revoke.go cmd/vault-access/list_remote_test.go cmd/vault-access/revoke_remote_test.go
git commit -S -m "feat(cli): list and revoke vault roles against a remote server"
```

---

### Task 3: Let vault-access through the remote guard

Until this task, all three commands still fail with "not yet supported" — the guard runs before their `RunE`.

**Files:**
- Modify: `cmd/root.go` — the `remoteCapableCommands` map introduced by `02b` Task 2
- Test: `cmd/root_test.go`

**Interfaces:**
- Consumes: `remoteCapableCommands` from `02b` Task 2. This task adds one entry to it and produces nothing importable.

**Stop and check first.** This task edits a map that `02b` Task 2 creates. If `cmd/root.go` still contains `remoteCapableSecretsCommands` (a `map[string]bool`) rather than `remoteCapableCommands` (a `map[string]map[string]bool`), `02b` has not run — stop and run it first. Rewriting the map wholesale from this plan would drop `02b`'s `"users"` entry, reopen B54, and fail `TestRemoteGuard_AllowsUsersLoginAndLogout`.

- [ ] **Step 1: Write the failing test**

```go
func TestIsRemoteCapableCommand_VaultAccess(t *testing.T) {
	parent := &cobra.Command{Use: "vault-access"}
	for _, name := range []string{"grant", "list", "revoke"} {
		child := &cobra.Command{Use: name}
		parent.AddCommand(child)
		assert.Truef(t, isRemoteCapableCommand(child), "vault-access %s must be remote-capable", name)
	}
}

// roles is local-only: it reads compiled-in definitions and never calls a
// server, so it must not be routed through the remote pre-run.
func TestIsRemoteCapableCommand_VaultAccessRolesIsNot(t *testing.T) {
	parent := &cobra.Command{Use: "vault-access"}
	child := &cobra.Command{Use: "roles"}
	parent.AddCommand(child)
	assert.False(t, isRemoteCapableCommand(child))
}
```

Do not add a `keys`-still-guarded case: `02b`'s `TestRemoteGuard_StillBlocksUnmigratedGroups` and the existing `TestIsRemoteCapableCommand` (`cmd/root_test.go:587`) already assert exactly that.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/ -run TestIsRemoteCapableCommand -v`
Expected: FAIL on the `vault-access` cases.

- [ ] **Step 3: Add one entry to the allowlist**

Add a `vault-access` entry to the existing `remoteCapableCommands` map in `cmd/root.go`, leaving the `secrets` and `users` entries and both helper functions (`isRemoteCapableCommand`, `isRemoteUnauthenticatedCommand`) untouched:

```go
	"vault-access": {
		"grant": true, "list": true, "revoke": true,
	},
```

Extend the map's existing doc comment with the reason one subcommand is missing:

```go
// "vault-access roles" is deliberately absent: it reads compiled-in role
// definitions and never contacts a server, so isLocalOnlyCommand handles it.
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/... -v`
Expected: PASS, including the existing secrets remote-capability tests.

- [ ] **Step 5: Verify end to end against a real server**

```bash
go build -o rocketvault .
./rocketvault serve &
./rocketvault context use numericlabs
./rocketvault users login --username admin --password <pw> --totp-code <code>

./rocketvault vault-access grant admin --role "Key Vault Administrator" --vault payments
./rocketvault vault-access list --vault payments
./rocketvault vault-access revoke <assignment-id> --vault payments
```

Expected: the grant that opened this work now succeeds. Confirm `vault-access list` output matches the local run's columns exactly:

```bash
./rocketvault context unset
./rocketvault vault-access list --vault payments   # local
```

- [ ] **Step 6: Verify ROCKETVAULT_VAULT now applies**

```bash
./rocketvault context use numericlabs
ROCKETVAULT_VAULT=payments ./rocketvault vault-access list
```

Expected: lists `payments`, not the default vault — the defect `03a` Task 1 fixes, now reaching a command. Note this holds for `vault-access` only; the `secrets` remote branches keep their old flag → `target.Vault` precedence until plan 07 migrates them.

- [ ] **Step 7: Commit**

```bash
git add cmd/root.go cmd/root_test.go
git commit -S -m "feat(cli): route vault-access through remote mode

vault-access joins the guard's allowlist, so grant/list/revoke now reach
a remote server; roles stays local-only.

This is the pattern the remaining groups copy: resolve the vault, call
vaultapi, convert to model types, print what local prints."
```


## Self-Review

**Spec coverage:** This plan implements spec phase 2's command surface. The spec's remaining phases (3–8) are out of scope by design — this is the pattern proof they depend on.

**Placeholder scan:** No TBDs. Task 1's test needs `"bytes"` added to its imports, which is stated.

**Deferred spec item, stated rather than silently skipped:** the spec's testing strategy (§3) asks for a per-group integration test against an in-process server, on the grounds that "mocks that agree with the client prove nothing". The tests here are hand-rolled `httptest` handlers returning JSON the test author wrote — the same pattern that concern is about. Two things reduce the risk: plan 01's route-contract test proves every path this plan calls is a registered route, so the 404 class is caught, and Step 5's manual run exercises the real server. What remains uncovered is response-*shape* drift: if the API changes a field name, these tests keep passing. Closing that properly means standing the server up in-process and driving `rootCmd.ExecuteContext`, which is a test-harness piece no plan currently owns. It should be built once, for all groups, before plan 04 copies this pattern five more times — not bolted onto this plan.

**Type consistency:** `ResolveRemoteVault`, `CLIError` and `RoleAssignmentFromAPI` are all defined in `03a` and consumed here with the signatures that plan produces. `RoleAssignmentFromAPI` takes `*vaultapi.RoleAssignment`, so Task 2 passes `&list[i]` — `ListRoleAssignments` returns a `[]RoleAssignment` by value.

**Ordering:** Task 1 establishes the adapter shape; Task 2 copies it twice; Task 3 removes the guard that keeps all three unreachable. Task 3 must be last — landing it earlier would expose commands whose remote branches do not exist yet.

**Open question for review after execution:** whether `runXRemote` functions should take the client and target as parameters (as here) or pull them from the context themselves. Parameters make them directly testable without building a context, which is why they are used here — but if the six-argument `runGrantRemote` signature grows awkward in the keys group, that is the signal to revisit before plan 04 copies it.

---

## Post-Execution Review (2026-09-05)

This plan asked to be reviewed before plan 04 copies its shape across `keys`,
`certificates`, `audit` and `vaults`. That review is done. **The shape is
sound and plan 04 should adopt it — with the three amendments below, which are
binding on plan 04, not optional polish.**

Reviewed against the merged code on `v-4.0.0` (`661a4d6`).

### Amendment 1 — pass command input as a struct, not positionally

The open question above resolves **against** the positional form, at the first
command plan 04 touches.

`runGrantRemote` takes six parameters and reads fine. But `cmd/keys/create.go`
registers six flags (`name`, `type`, `bits`, `curve`, `tags`,
`purge-protection`), so the same style yields:

```go
// Do NOT do this.
func runKeysCreateRemote(cmd *cobra.Command, client *vaultapi.Client, target *cliclient.Target,
    name, keyType string, bits int, curve, tags string, purgeProtection bool) error
```

Nine parameters, four same-typed strings adjacent — a silent-transposition
hazard that no test catches, because every wrong ordering still compiles.

**Keep** the `(cmd, client, target)` prefix: that is what makes these functions
testable without assembling a context, and it is the genuinely good part of the
shape. **Change** the tail to a single request struct, preferring the
`vaultapi` request type where one exists (`GrantRoleRequest` already does):

```go
func runKeysCreateRemote(cmd *cobra.Command, client *vaultapi.Client, target *cliclient.Target,
    req vaultapi.CreateKeyRequest) error
```

`runGrantRemote` itself may stay positional — it is under the threshold and
rewriting it buys nothing. The rule starts at `keys`.

### Amendment 2 — list adapters must go through the formatter

`runListRemote` hand-rolls fixed-width columns with `fmt.Fprintf`. That was
**correct for this plan**, whose constraint was byte-identical parity with the
local path — and `vault-access list`'s local path hand-rolls them too
(`list.go:25-28`).

It is **wrong as a template.** `cmd/keys/list.go:110-127` resolves
`common.OutputFormatterKey` and calls `fmtr.Write(...)`, so it honours
`--output json|yaml`. A `runKeysListRemote` copied from `runListRemote` would
silently drop output-format support that `keys` already has in local mode —
breaking this plan's own "remote output must be identical to local output"
constraint in the opposite direction.

**Every list adapter in plan 04 goes through `formatter.Formatter`.** Copy the
local path's output mechanism, not this plan's.

*Separately:* `vault-access list --output json` silently ignoring the flag is a
pre-existing local-mode gap, not something this plan introduced. Worth its own
small fix; out of scope for the adapter work.

### Amendment 3 — name the canonical shape in the code

Two adapter conventions now coexist in `cmd/`:

| | `vault-access` (this plan) | `secrets` (pre-existing) |
|---|---|---|
| Signature | `(cmd, client, target, ...)` | `(cmd, ctx, target, ...)` |
| Transport | `*vaultapi.Client` parameter | pulls `TokenKey` + `RemoteHTTPClientKey` from ctx |
| Failure mode | cannot compile without a client | three runtime `not available in context` checks |

This plan's is better — the dependency is in the type signature rather than in
three lookups that can only fail at runtime. But **plan 08** is what converts
`secrets` over, and until it runs, a reader of `cmd/` finds two patterns with
nothing saying which is current.

Add a comment on `runGrantRemote` naming it the canonical shape and pointing at
plan 08 for the `secrets` migration, so plan 04 does not copy the wrong
neighbour.

### Confirmed good — replicate as-is

- **Dispatch branches** are identical across all three commands: same
  `RemoteClientKey` type assertion, same nil check, same early return placed
  before the service-container lookup. Mechanical to replicate.
- **`revoke` places its branch after `uuid.Parse`**, so the local
  "invalid assignment id" check guards remote input too.
- **No client-side authorization in the remote path.** The server owns the
  decision and `CLIError` maps its 403. Replicating checks like
  `requireCanManageRoleAssignments` client-side would drift from the server.

### Unchanged and still blocking-ish

The response-shape gap described above stands: these `httptest` handlers return
JSON the test author wrote, so a renamed API field keeps them green. Plan 01's
route-contract test catches wrong *paths*, not wrong *shapes*. **Sequence the
in-process harness before plan 04**, not after — it is the difference between
building it once and retrofitting it across five groups.

**Closed 2026-09-05.** The harness landed as `internal/apitest`
(`docs/superpowers/specs/2026-09-05-in-process-api-test-harness-design.md`,
plans `2026-09-05-api-test-harness-01-core.md` and `-02-migrate-vault-access.md`),
and `vault-access`'s three remote tests were migrated onto it. Plan 04 should
use `apitest.New` from the start for `keys`, adding an `Options` field for the
key service rather than hand-writing a handler.
