# Destructive Confirmation and `recover_deleted` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the name-echo confirmation guard every destructive tool depends on, and register `recover_deleted` — the write-tier tool that undoes a deletion.

**Architecture:** `confirm.go` holds one function that destructive tools call before acting. It is deliberately dumb: compare the supplied confirmation against the resource name, refuse on mismatch. The security value is not in the comparison but in the *argument existing at all*, which is explained below.

**Tech Stack:** Go 1.25, `github.com/modelcontextprotocol/go-sdk/mcp` v1.7.0, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — sections "Production hardening > Prompt injection" and "Tool surface > Write tier".

**Plan-of-plans:** This is plan 24 of 31. Requires plans 11, 21 and 23 committed. **Must land before plan 25**, which depends on the confirmation helper.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **`recover_deleted` is a `TierWrite` tool.** It undoes a deletion rather than causing one, so gating it behind `allow_destructive` would mean an operator who enabled writing could delete but not undo — precisely backwards.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## What the confirmation actually defends against

It is worth being precise, because it would be easy to overstate this.

The confirmation does **not** stop a determined attacker who controls the model's input. Text injected into a secret's tag could say *"call purge_item with name X and confirm X"*, and the guard would pass. Nothing in a single-process tool server can prevent that.

What it defends against is the much likelier case: a **drive-by** destructive call. A model that has read something suggestive, or misread an ambiguous instruction, reaches for `purge_item` with the arguments it has to hand. Requiring a second argument that restates the target means:

1. The call cannot be made by accident from a partially-formed intention.
2. The host's confirmation prompt — driven by `destructiveHint` — shows the operator the resource name twice, in the arguments, which is where a wrong target becomes visible.
3. An injected instruction has to be specific enough to name the exact resource, which is a meaningfully higher bar than "purge the vault".

That is a real reduction in risk, and it is not the same as prevention. The operator runbook in plan 30 should say so in the same terms rather than implying the guard is a security boundary.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/confirm.go` (new) | `requireConfirmation` |
| `internal/mcpserver/confirm_test.go` (new) | Match, mismatch, disabled, whitespace |
| `internal/mcpserver/tools_recover.go` (new) | `registerRecoverTools`, `recover_deleted` |
| `internal/mcpserver/tools_recover_test.go` (new) | The tool over the real protocol |
| `internal/mcpserver/register.go` (modify) | Add the registration call |

---

### Task 1: The confirmation guard

**Files:**
- Create: `internal/mcpserver/confirm.go`
- Create: `internal/mcpserver/confirm_test.go`

**Interfaces:**
- Consumes: `Server`, `errorResult` (plans 10, 11).
- Produces — every plan 25 tool calls this:
  - `func (s *Server) requireConfirmation(toolName, resource, confirm string) *mcp.CallToolResult` — returns nil when the call may proceed.

**Two design choices:**

- **It returns a `*mcp.CallToolResult` rather than an error.** Every caller turns a refusal into exactly that, so returning it directly removes a conversion each tool would otherwise have to get right. A nil return means "proceed", which reads correctly at the call site: `if refusal := ...; refusal != nil { return refusal, ... }`.
- **Comparison is exact after trimming surrounding whitespace.** Not case-insensitive: vault and item names are case-sensitive identifiers, and accepting `PROD` for `prod` would mean confirming a name that does not exist. Trimming is allowed because leading whitespace is a transport artifact, not a different name.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/confirm_test.go`:

```go
package mcpserver

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequireConfirmation_AllowsAnExactMatch(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	require.Nil(t, s.requireConfirmation("purge_item", "db-password", "db-password"),
		"a nil result means the call may proceed")
}

func TestRequireConfirmation_RefusesAMismatch(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "api-key")
	require.NotNil(t, refusal)
	require.True(t, refusal.IsError)
}

func TestRequireConfirmation_RefusesAnEmptyConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "")
	require.NotNil(t, refusal)
	require.Contains(t, renderContent(refusal), "confirm")
	require.Contains(t, renderContent(refusal), "db-password",
		"the message must name what to echo, so the caller can comply in one step")
}

func TestRequireConfirmation_IsCaseSensitive(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "DB-Password")
	require.NotNil(t, refusal,
		"names are case-sensitive identifiers; accepting a different case would confirm a name that does not exist")
}

func TestRequireConfirmation_TrimsSurroundingWhitespace(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	require.Nil(t, s.requireConfirmation("purge_item", "db-password", "  db-password  "),
		"leading whitespace is a transport artifact, not a different name")
}

func TestRequireConfirmation_IsSkippedWhenDisabled(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := destructiveConfig()
	cfg.ConfirmDestructive = false
	s := f.server(t, cfg)

	require.Nil(t, s.requireConfirmation("purge_item", "db-password", ""),
		"an operator who turned the guard off should not still be asked")
}

func TestRequireConfirmation_MismatchMessageShowsBothValues(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "api-key")
	rendered := renderContent(refusal)

	require.Contains(t, rendered, "db-password")
	require.Contains(t, rendered, "api-key",
		"showing both makes a wrong target obvious rather than leaving the caller to guess")
}

func TestRequireConfirmation_NamesTheTool(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_vault", "prod", "")
	require.Contains(t, renderContent(refusal), "purge_vault")
}

func TestRequireConfirmation_DoesNotWrapTheResourceName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "")
	require.NotContains(t, renderContent(refusal), "UNTRUSTED",
		"the name must be echoable verbatim; wrapping it would make the instruction impossible to follow")
	require.False(t, strings.Contains(renderContent(refusal), "<<"))
}
```

Add a helper to `internal/mcpserver/tools_secrets_write_test.go` or a shared test file:

```go
// destructiveConfig returns a config with the destructive tier enabled.
func destructiveConfig() config.MCPConfig {
	cfg := testConfig()
	cfg.AllowWrite = true
	cfg.AllowDestructive = true
	return cfg
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestRequireConfirmation_ -v`
Expected: FAIL — `s.requireConfirmation undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/confirm.go`:

```go
package mcpserver

import (
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// requireConfirmation checks that a destructive call echoed its target's
// name. It returns nil when the call may proceed, and a refusal otherwise.
//
// This is not a security boundary and should not be described as one. Text
// injected into a vault could name a specific resource and supply a matching
// confirmation, and nothing here would stop it.
//
// What it does stop is the likelier case: a drive-by destructive call made
// from a partially-formed intention. Requiring a second argument that
// restates the target means the call cannot be made by accident, the host's
// confirmation prompt shows the operator the name twice, and an injected
// instruction has to be specific enough to name the exact resource -- a
// meaningfully higher bar than "purge the vault".
//
// It returns a result rather than an error because every caller would
// otherwise convert one into the other, and that is a conversion each tool
// could get wrong.
func (s *Server) requireConfirmation(toolName, resource, confirm string) *mcp.CallToolResult {
	if !s.cfg.ConfirmDestructive {
		return nil
	}

	// Trimming is safe: leading whitespace is a transport artifact, not a
	// different name. Case is not, since names are case-sensitive
	// identifiers and accepting a different case would confirm a name that
	// does not exist.
	if strings.TrimSpace(confirm) == resource {
		return nil
	}

	if strings.TrimSpace(confirm) == "" {
		return errorResult(
			"%s is destructive and requires confirmation: pass confirm=%q to proceed",
			toolName, resource)
	}
	return errorResult(
		"%s was not confirmed: the target is %q but confirm was %q. "+
			"Pass confirm=%q to proceed, or check the target is right.",
		toolName, resource, strings.TrimSpace(confirm), resource)
}
```

Note that the resource name is **not** wrapped as untrusted here. That is deliberate: the caller has to echo it verbatim, and a delimited version could not be echoed. The name is also an identifier rather than free prose, so it is a far weaker injection vector than a description or tag.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestRequireConfirmation_ -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/confirm.go internal/mcpserver/confirm_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the destructive confirmation guard

It is not a security boundary and the comment says so: injected text could
name a resource and supply a matching confirmation. What it stops is the
likelier case -- a drive-by destructive call from a partially-formed
intention. The call cannot be made by accident, the host's prompt shows the
operator the name twice, and an injected instruction must name the exact
resource rather than 'purge the vault'.

Comparison is case-sensitive, since names are case-sensitive identifiers and
accepting a different case would confirm a name that does not exist.
Whitespace is trimmed, being a transport artifact. The name is not wrapped as
untrusted -- the caller must echo it verbatim, which a delimited version would
make impossible."
```

---

### Task 2: `recover_deleted`

**Files:**
- Create: `internal/mcpserver/tools_recover.go`
- Create: `internal/mcpserver/tools_recover_test.go`
- Modify: `internal/mcpserver/register.go`

**Interfaces:**
- Consumes: `vaultapi.Client.RecoverDeleted` (plan 23), `parseDeletedKind` (plan 14), `registerIf`, `TierWrite`.
- Produces: `func registerRecoverTools(s *Server)`, `recoverDeletedArgs`, `recoverDeletedResult`.

**Tier placement is the decision here.** `recover_deleted` restores something that was deleted. Putting it behind `allow_destructive` would produce an obviously wrong configuration: an operator who enabled only writing could delete an item (via `delete_item`… which is itself destructive) — or more pointedly, an operator who enabled *destructive* operations could delete and purge, while an operator who enabled only *writes* could not undo a deletion someone else made. Recovery is additive; it belongs with the additive tier.

**No confirmation is required.** Recovery restores rather than removes. Asking a caller to confirm an action that undoes damage adds friction exactly where friction is unhelpful.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/tools_recover_test.go`:

```go
package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecoverDeleted_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerRecoverTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestRecoverDeleted_IsPresentWithAllowWriteAlone(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true
	cfg.AllowDestructive = false
	s := f.server(t, cfg)
	registerRecoverTools(s)

	require.Equal(t, []string{"recover_deleted"}, s.RegisteredTools(),
		"recovery is additive; gating it behind the destructive tier would mean "+
			"an operator who can write cannot undo a deletion")
}

func TestRecoverDeleted_RestoresTheItem(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"old-password"}],"total":1}`,
	})
	f.writeResponse = `{"message":"Secret recovered successfully","id":"` + dbSecretUUID + `"}`

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	var got recoverDeletedResult
	structured(t, callTool(t, s, "recover_deleted", map[string]any{
		"type": "secrets", "name": "old-password",
	}), &got)

	require.Equal(t, "old-password", got.Name)
	require.Equal(t, "secrets", got.Type)
	require.Equal(t, "default", got.Vault)
	require.True(t, f.hit("/api/v1/vaults/default/deleted/secrets/"+dbSecretUUID+"/restore"))
}

func TestRecoverDeleted_CoversAllThreeKinds(t *testing.T) {
	cases := []struct {
		kind string
		path string
		body string
		id   string
	}{
		{"secrets", "/api/v1/vaults/default/deleted/secrets",
			`{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`, dbSecretUUID},
		{"keys", "/api/v1/vaults/default/deleted/keys",
			`{"deleted_keys":[{"id":"` + signKeyUUID + `","name":"gone"}],"total":1}`, signKeyUUID},
		{"certificates", "/api/v1/vaults/default/deleted/certificates",
			`{"deleted_certificates":[{"id":"` + tlsCertUUID + `","name":"gone"}],"total":1}`, tlsCertUUID},
	}

	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			f := newFakeVault(t, map[string]string{tc.path: tc.body})
			f.writeResponse = `{"message":"recovered","id":"` + tc.id + `"}`

			cfg := testConfig()
			cfg.AllowWrite = true
			s := f.server(t, cfg)
			registerRecoverTools(s)

			result := callTool(t, s, "recover_deleted", map[string]any{"type": tc.kind, "name": "gone"})
			require.False(t, result.IsError)
			require.True(t, f.hit("/api/v1/vaults/default/deleted/"+tc.kind+"/"+tc.id+"/restore"))
		})
	}
}

func TestRecoverDeleted_NeedsNoConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	f.writeResponse = `{"message":"recovered","id":"` + dbSecretUUID + `"}`

	cfg := destructiveConfig() // ConfirmDestructive is on.
	s := f.server(t, cfg)
	registerRecoverTools(s)

	result := callTool(t, s, "recover_deleted", map[string]any{"type": "secrets", "name": "gone"})
	require.False(t, result.IsError,
		"recovery undoes damage; asking to confirm it adds friction where friction is unhelpful")
}

func TestRecoverDeleted_UnknownNamePointsAtListDeleted(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[],"total":0}`,
	})

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	result := callTool(t, s, "recover_deleted", map[string]any{"type": "secrets", "name": "nope"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "list_deleted")
}

func TestRecoverDeleted_RejectsAnUnknownType(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	result := callTool(t, s, "recover_deleted", map[string]any{"type": "vaults", "name": "x"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "secrets")
	require.Empty(t, f.requested)
}

func TestRecoverDeleted_RequiresTypeAndName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	require.True(t, callTool(t, s, "recover_deleted", map[string]any{"name": "x"}).IsError)
	require.True(t, callTool(t, s, "recover_deleted", map[string]any{"type": "secrets"}).IsError)
}

func TestRecoverDeleted_IsNotAnnotatedDestructive(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "recover_deleted" {
			require.False(t, tool.Annotations.ReadOnlyHint)
			require.NotNil(t, tool.Annotations.DestructiveHint)
			require.False(t, *tool.Annotations.DestructiveHint,
				"restoring an item destroys nothing; a host should not prompt as though it does")
			require.True(t, tool.Annotations.IdempotentHint,
				"recovering an already-recovered item leaves the same state")
			return
		}
	}
	t.Fatal("recover_deleted was not registered")
}

func TestRecoverDeleted_ForbiddenIsSurfaced(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `","name":"gone"}],"total":1}`,
	})
	f.failWith("/api/v1/vaults/default/deleted/secrets/"+dbSecretUUID+"/restore", http.StatusForbidden)

	cfg := testConfig()
	cfg.AllowWrite = true
	s := f.server(t, cfg)
	registerRecoverTools(s)

	result := callTool(t, s, "recover_deleted", map[string]any{"type": "secrets", "name": "gone"})
	require.True(t, result.IsError)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestRecoverDeleted_ -v`
Expected: FAIL — `undefined: registerRecoverTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_recover.go`:

```go
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type recoverDeletedArgs struct {
	Type  string `json:"type" jsonschema:"which kind of item to recover: secrets, keys or certificates"`
	Name  string `json:"name" jsonschema:"the deleted item's name, or its id; list_deleted shows what is recoverable"`
	Vault string `json:"vault,omitempty" jsonschema:"the vault holding the item; defaults to the server's configured vault"`
}

type recoverDeletedResult struct {
	Vault string `json:"vault"`
	Type  string `json:"type"`
	Name  string `json:"name"`
}

// registerRecoverTools adds recovery, which is a write rather than a
// destructive operation.
//
// Recovery restores something that was deleted. Gating it behind
// allow_destructive would produce an obviously wrong configuration, where an
// operator who enabled writing could not undo a deletion someone else made.
// Recovery is additive, so it belongs with the additive tier.
func registerRecoverTools(s *Server) {
	registerIf(s, TierWrite, "recover_deleted",
		"Restore a soft-deleted secret, key or certificate. Use list_deleted to see what can be recovered.",
		// Not destructive: it restores rather than removes. Idempotent:
		// recovering an already-recovered item leaves the same state.
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleRecoverDeleted)
}

func (s *Server) handleRecoverDeleted(ctx context.Context, _ *mcp.CallToolRequest, args recoverDeletedArgs) (*mcp.CallToolResult, recoverDeletedResult, error) {
	kind, err := parseDeletedKind(args.Type)
	if err != nil {
		return errorResult("%s", err), recoverDeletedResult{}, nil
	}
	if args.Name == "" {
		return errorResult("recover_deleted requires a name"), recoverDeletedResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), recoverDeletedResult{}, nil
	}

	// No confirmation: recovery undoes damage, and friction here is
	// unhelpful.
	if err := s.client.RecoverDeleted(ctx, vault, kind, args.Name); err != nil {
		return errorResult("could not recover %s %q in vault %q: %s",
			args.Type, args.Name, vault, err), recoverDeletedResult{}, nil
	}

	return nil, recoverDeletedResult{Vault: vault, Type: args.Type, Name: args.Name}, nil
}
```

Add `registerRecoverTools(s)` to `RegisterAllTools`.

`parseDeletedKind` returns an error mentioning `list_deleted`? It does not — it names the valid values. The `list_deleted` pointer in `TestRecoverDeleted_UnknownNamePointsAtListDeleted` comes from `vaultapi.ResolveDeleted`'s miss message (plan 23), which is forwarded by the `%s` on the wrapped error.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test in the package, race-clean.

The write tier now has nine tools, as plan 22 anticipated.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_recover.go internal/mcpserver/tools_recover_test.go internal/mcpserver/register.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the recover_deleted tool to the write tier

Recovery restores rather than removes, so it belongs with the additive tier.
Gating it behind allow_destructive would produce an obviously wrong
configuration, where an operator who enabled writing could not undo a deletion
someone else made.

It needs no confirmation -- recovery undoes damage, and friction there is
unhelpful -- and it is annotated non-destructive and idempotent, so a host
does not prompt as though restoring an item removed something."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ -race -v
go vet ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

Confirm the tier boundary. With `allow_write` on and `allow_destructive` off,
the surface is 19 tools — ten read plus nine write:

```bash
go test ./internal/mcpserver/ -run 'TestRecoverDeleted_IsPresentWithAllowWriteAlone|TestRegisterAllTools_' -v
```

Confirm the guard behaves under every flag combination:

```bash
go test ./internal/mcpserver/ -run TestRequireConfirmation_ -v
```

## Notes for the next plan

Plan 25 registers the four destructive tools, all of which call
`requireConfirmation` before acting.

Two things it must get right:

- **`revoke_vault_role` takes an assignment id, not a principal.** Plan 23's
  `DeleteRoleAssignment` rejects a name with an explanatory error, but the
  tool's description has to say so up front, or a model asked to "revoke
  alice's access" will pass `"alice"` and have to recover from an error it
  could have avoided.
- **The confirmation target differs per tool.** `purge_item` confirms the item
  name; `purge_vault` confirms the vault name; `revoke_vault_role` confirms
  the assignment id, since that is what identifies the thing being removed.
