# Write-Tier Tools: Secrets, Vaults and Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register the first three mutating tools — `set_secret`, `create_vault` and `grant_vault_role` — all gated behind `mcp.allow_write`.

**Architecture:** Plan 13's tool shape, with `TierWrite` instead of `TierRead` and non-read-only annotations. Nothing new is invented; the gating, deadline, rate limit and vault guard already apply through `registerIf`.

**Tech Stack:** Go 1.25, `github.com/modelcontextprotocol/go-sdk/mcp` v1.7.0, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Write tier".

**Plan-of-plans:** This is plan 21 of 31. Requires plans 11, 13 and 18 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **`registerIf(s, TierWrite, ...)`** — every tool here is absent unless `allow_write` is set.
- **Annotations must be honest.** These tools are not read-only. `set_secret` is not idempotent in the sense that matters (it creates a new version each time), so it must not claim to be.
- `s.ResolveVault` for the vault; `Wrap`/`WrapAll` on free text in results.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Writing a value is not disclosing one

`set_secret` takes a `value` argument **regardless of `allow_secret_values`**. That flag governs whether the server will *show* a secret to the model; it has nothing to do with whether the model may supply one.

Conflating the two would be a real usability bug — an operator who enables writing but not disclosure would find `set_secret` unable to set anything. Keep the two concerns separate:

- `allow_write` — may the model change the vault?
- `allow_secret_values` — may the model be shown existing plaintext?

The result of `set_secret` never echoes the value back, whatever either flag says. There is no reason to: the caller supplied it.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/tools_secrets_write.go` (new) | `registerSecretsWriteTools`, `set_secret` |
| `internal/mcpserver/tools_vaults_write.go` (new) | `registerVaultsWriteTools`, `create_vault` |
| `internal/mcpserver/tools_access_write.go` (new) | `registerAccessWriteTools`, `grant_vault_role` |
| `internal/mcpserver/register.go` (modify) | Add the three registration calls |
| `internal/mcpserver/*_write_test.go` (new) | One per tool |

---

### Task 1: `set_secret`

**Files:**
- Create: `internal/mcpserver/tools_secrets_write.go`
- Create: `internal/mcpserver/tools_secrets_write_test.go`
- Modify: `internal/mcpserver/register.go`

**Interfaces:**
- Consumes: `vaultapi.Client.SetSecret`, `SetSecretRequest` (plan 18); `registerIf`, `TierWrite` (plan 11).
- Produces:
  - `func registerSecretsWriteTools(s *Server)`
  - `type setSecretArgs struct { Name, Value, Vault, ContentType string; Tags []string; ExpiresAt string; Enabled *bool }`
  - `type setSecretResult struct { Vault, Name, ID string; Version int; Created bool }`

**Annotation choice:** `ReadOnly: false`, `Idempotent: false`, `Destructive: false`.

`Idempotent` is false deliberately. Calling `set_secret` twice with the same arguments produces two versions, not one — the second call has an additional effect on the vault, which is exactly what `IdempotentHint` denies. Claiming otherwise would let a host retry it safely when it is not safe.

`Destructive` is false because an update creates a new version rather than removing the old one; the previous value remains recoverable through version history.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/tools_secrets_write_test.go`:

```go
package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeConfig returns a config with the write tier enabled.
func writeConfig() config.MCPConfig {
	cfg := testConfig()
	cfg.AllowWrite = true
	return cfg
}

func TestSetSecret_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerSecretsWriteTools(s)

	require.Empty(t, s.RegisteredTools(),
		"a write tool must not exist at all when the tier is off")
}

func TestSetSecret_CreatesANewSecret(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"api-key","version":1}`
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	var got setSecretResult
	structured(t, callTool(t, s, "set_secret", map[string]any{
		"name": "api-key", "value": "s3cr3t",
	}), &got)

	require.True(t, got.Created)
	require.Equal(t, "api-key", got.Name)
	require.Equal(t, 1, got.Version)
	require.Equal(t, "default", got.Vault)
}

func TestSetSecret_UpdatesAnExistingSecret(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"db-password","version":5}`
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	var got setSecretResult
	structured(t, callTool(t, s, "set_secret", map[string]any{
		"name": "db-password", "value": "new-value",
	}), &got)

	require.False(t, got.Created, "an existing name is an update")
	require.Equal(t, 5, got.Version)
}

func TestSetSecret_NeverEchoesTheValueBack(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"api-key","value":"s3cr3t-echo","version":1}`
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{"name": "api-key", "value": "s3cr3t-echo"})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	require.NotContains(t, string(encoded), "s3cr3t-echo",
		"the caller supplied the value; there is no reason to send it back")
}

func TestSetSecret_WorksWithDisclosureDisabled(t *testing.T) {
	// Supplying a value is not the same as being shown one.
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"api-key","version":1}`

	cfg := writeConfig()
	cfg.AllowSecretValues = false
	s := f.server(t, cfg)
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{"name": "api-key", "value": "s3cr3t"})
	require.False(t, result.IsError,
		"allow_secret_values governs reading, not writing")
}

func TestSetSecret_AcceptsOptionalMetadata(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.writeResponse = `{"id":"` + dbSecretUUID + `","name":"api-key","version":1}`
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{
		"name": "api-key", "value": "s3cr3t",
		"tags": []any{"prod"}, "content_type": "text/plain",
		"expires_at": "2027-01-01T00:00:00Z",
	})
	require.False(t, result.IsError)
	require.Equal(t, "text/plain", f.lastWriteBody["content_type"])
	require.NotNil(t, f.lastWriteBody["expires_at"])
}

func TestSetSecret_RejectsAnUnparseableExpiry(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{
		"name": "api-key", "value": "s3cr3t", "expires_at": "next tuesday",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "RFC3339",
		"the error must say what format is expected, so the model can retry correctly")
}

func TestSetSecret_RequiresANameAndValue(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	require.True(t, callTool(t, s, "set_secret", map[string]any{"value": "v"}).IsError)
	require.True(t, callTool(t, s, "set_secret", map[string]any{"name": "n"}).IsError)
}

func TestSetSecret_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := writeConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{
		"name": "api-key", "value": "v", "vault": "prod",
	})
	require.True(t, result.IsError)
	require.Empty(t, f.requested, "a refused vault must produce no request at all")
}

func TestSetSecret_AnnotationsAreHonest(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "set_secret" {
			continue
		}
		require.False(t, tool.Annotations.ReadOnlyHint)
		require.False(t, tool.Annotations.IdempotentHint,
			"calling it twice creates two versions, so it is not idempotent")
		require.NotNil(t, tool.Annotations.DestructiveHint)
		require.False(t, *tool.Annotations.DestructiveHint,
			"an update adds a version rather than removing the old one")
		return
	}
	t.Fatal("set_secret was not registered")
}

func TestSetSecret_ForbiddenSurfacesTheOfficerRoleHint(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[],"total":0}`,
	})
	f.failWith("/api/v1/vaults/default/secrets", http.StatusForbidden)
	s := f.server(t, writeConfig())
	registerSecretsWriteTools(s)

	result := callTool(t, s, "set_secret", map[string]any{"name": "api-key", "value": "v"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Secrets Officer")
}
```

Add `"rocketvault/config"` to the test imports.

The `fakeVault` helper needs two additions for write tests. In `vaultfake_test.go`, add fields and handling:

```go
	// writeResponse is returned for non-GET requests.
	writeResponse string
	// lastWriteBody records the decoded body of the most recent write.
	lastWriteBody map[string]any
```

and in the handler, before the route lookup:

```go
		if r.Method != http.MethodGet {
			_ = json.NewDecoder(r.Body).Decode(&f.lastWriteBody)
			if code, ok := f.status[r.URL.Path]; ok {
				w.WriteHeader(code)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if f.writeResponse != "" {
				_, _ = w.Write([]byte(f.writeResponse))
			}
			return
		}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestSetSecret_ -v`
Expected: FAIL — `undefined: registerSecretsWriteTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_secrets_write.go`:

```go
package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

// setSecretArgs are the arguments to set_secret.
//
// Value is present regardless of allow_secret_values. That flag governs
// whether the server will show an existing secret to the model; it has
// nothing to do with whether the model may supply one. Conflating them would
// leave an operator who enabled writing but not disclosure unable to write.
type setSecretArgs struct {
	Name        string   `json:"name" jsonschema:"the secret's name"`
	Value       string   `json:"value" jsonschema:"the secret value to store"`
	Vault       string   `json:"vault,omitempty" jsonschema:"the vault to write to; defaults to the server's configured vault"`
	Tags        []string `json:"tags,omitempty" jsonschema:"tags to attach to the secret"`
	ContentType string   `json:"content_type,omitempty" jsonschema:"a MIME type describing the value, such as text/plain"`
	ExpiresAt   string   `json:"expires_at,omitempty" jsonschema:"expiry as an RFC3339 timestamp, such as 2027-01-01T00:00:00Z"`
	Enabled     *bool    `json:"enabled,omitempty" jsonschema:"whether the secret is usable"`
}

// setSecretResult reports what happened.
//
// It deliberately does not echo the value: the caller supplied it, so
// returning it would put a plaintext secret in the transcript for no reason.
type setSecretResult struct {
	Vault   string `json:"vault"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Version int    `json:"version"`
	// Created distinguishes a new secret from a new version of an existing
	// one, which the caller usually cannot tell in advance.
	Created bool `json:"created"`
}

// registerSecretsWriteTools adds the write-tier secret tools.
func registerSecretsWriteTools(s *Server) {
	registerIf(s, TierWrite, "set_secret",
		"Create a secret, or store a new version of an existing one. "+
			"Returns metadata only; the value is never echoed back.",
		// Not idempotent: calling this twice stores two versions, so a host
		// must not treat a retry as free.
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleSetSecret)
}

// parseOptionalTime parses an RFC3339 timestamp, treating "" as unset.
func parseOptionalTime(field, value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be an RFC3339 timestamp such as 2027-01-01T00:00:00Z, got %q", field, value)
	}
	return &parsed, nil
}

func (s *Server) handleSetSecret(ctx context.Context, _ *mcp.CallToolRequest, args setSecretArgs) (*mcp.CallToolResult, setSecretResult, error) {
	if args.Name == "" {
		return errorResult("set_secret requires a name"), setSecretResult{}, nil
	}
	if args.Value == "" {
		return errorResult("set_secret requires a value"), setSecretResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), setSecretResult{}, nil
	}

	expiresAt, err := parseOptionalTime("expires_at", args.ExpiresAt)
	if err != nil {
		return errorResult("%s", err), setSecretResult{}, nil
	}

	secret, created, err := s.client.SetSecret(ctx, vault, vaultapi.SetSecretRequest{
		Name:        args.Name,
		Value:       vaultapi.SecretValue(args.Value),
		Tags:        args.Tags,
		ContentType: args.ContentType,
		Enabled:     args.Enabled,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		return errorResult("could not set secret %q in vault %q: %s", args.Name, vault, err), setSecretResult{}, nil
	}

	return nil, setSecretResult{
		Vault:   vault,
		Name:    secret.Name,
		ID:      secret.ID.String(),
		Version: secret.Version,
		Created: created,
	}, nil
}
```

Add the registration to `internal/mcpserver/register.go`:

```go
	registerSecretsWriteTools(s)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestSetSecret_ -v`
Expected: PASS — all eleven tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_secrets_write.go internal/mcpserver/tools_secrets_write_test.go internal/mcpserver/vaultfake_test.go internal/mcpserver/register.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the set_secret tool

Takes a value regardless of allow_secret_values. That flag governs whether the
server shows an existing secret to the model, not whether the model may supply
one -- conflating them would leave an operator who enabled writing but not
disclosure unable to write anything.

The result never echoes the value: the caller supplied it, so returning it
would put a plaintext secret in the transcript for nothing. The tool is
annotated non-idempotent, because calling it twice stores two versions and a
host must not treat a retry as free."
```

---

### Task 2: `create_vault`

**Files:**
- Create: `internal/mcpserver/tools_vaults_write.go`
- Create: `internal/mcpserver/tools_vaults_write_test.go`
- Modify: `internal/mcpserver/register.go`

**Interfaces:**
- Consumes: `vaultapi.Client.CreateVault`, `CreateVaultRequest` (plan 18).
- Produces: `func registerVaultsWriteTools(s *Server)`, `createVaultArgs`, `createVaultResult`.

**Two decisions specific to this tool:**

1. **It does not call `ResolveVault`.** It creates a vault; there is nothing to resolve. But it *does* check the new name against `allowed_vaults` — creating a vault the server is then forbidden to touch would be a strange thing to permit, and refusing is cheaper than explaining afterwards.
2. **`purge_protection` defaults to unset, not false.** The pointer passes straight through to `vaultapi`, so an omitted flag means "server default" — consistent with plan 18 and with what an operator would expect from a security setting they did not mention.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/tools_vaults_write_test.go`:

```go
package mcpserver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateVault_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerVaultsWriteTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestCreateVault_CreatesTheVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + prodVaultID + `","name":"analytics","enabled":true,"retention_days":90}`
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	var got createVaultResult
	structured(t, callTool(t, s, "create_vault", map[string]any{"name": "analytics"}), &got)

	require.Equal(t, "analytics", got.Name)
	require.Equal(t, 90, got.RetentionDays)
	require.Equal(t, "analytics", f.lastWriteBody["name"])
}

func TestCreateVault_OmitsUnsetSecuritySettings(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + prodVaultID + `","name":"analytics"}`
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	_ = callTool(t, s, "create_vault", map[string]any{"name": "analytics"})

	_, present := f.lastWriteBody["purge_protection"]
	require.False(t, present,
		"an unmentioned security setting must mean 'server default', not 'off'")
}

func TestCreateVault_SendsExplicitSecuritySettings(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + prodVaultID + `","name":"analytics"}`
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	_ = callTool(t, s, "create_vault", map[string]any{
		"name": "analytics", "purge_protection": true, "retention_days": 30,
	})

	require.Equal(t, true, f.lastWriteBody["purge_protection"])
	require.EqualValues(t, 30, f.lastWriteBody["retention_days"])
}

func TestCreateVault_RefusesANameOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := writeConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerVaultsWriteTools(s)

	result := callTool(t, s, "create_vault", map[string]any{"name": "analytics"})
	require.True(t, result.IsError,
		"creating a vault this server is then forbidden to touch would be odd to permit")
	require.Empty(t, f.requested)
}

func TestCreateVault_RequiresAName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	require.True(t, callTool(t, s, "create_vault", map[string]any{}).IsError)
}

func TestCreateVault_ConflictIsExplained(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults", http.StatusConflict)
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	result := callTool(t, s, "create_vault", map[string]any{"name": "prod"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "already exists",
		"a duplicate name is the likeliest failure and should read as one")
}

func TestCreateVault_AnnotationsAreHonest(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerVaultsWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "create_vault" {
			require.False(t, tool.Annotations.ReadOnlyHint)
			require.False(t, *tool.Annotations.DestructiveHint)
			return
		}
	}
	t.Fatal("create_vault was not registered")
}
```

Add `"context"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestCreateVault_ -v`
Expected: FAIL — `undefined: registerVaultsWriteTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_vaults_write.go`:

```go
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type createVaultArgs struct {
	Name            string            `json:"name" jsonschema:"the new vault's name; lowercase letters, digits and hyphens"`
	Enabled         *bool             `json:"enabled,omitempty" jsonschema:"whether the vault is usable immediately"`
	PurgeProtection *bool             `json:"purge_protection,omitempty" jsonschema:"prevent permanent deletion of items before their retention period ends"`
	RetentionDays   *int              `json:"retention_days,omitempty" jsonschema:"how long soft-deleted items remain recoverable"`
	Tags            map[string]string `json:"tags,omitempty" jsonschema:"tags to attach to the vault"`
}

type createVaultResult struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	Enabled         bool   `json:"enabled"`
	PurgeProtection bool   `json:"purge_protection"`
	RetentionDays   int    `json:"retention_days"`
}

// registerVaultsWriteTools adds the write-tier vault tools.
func registerVaultsWriteTools(s *Server) {
	registerIf(s, TierWrite, "create_vault",
		"Create a new vault. Each vault is an isolated boundary with its own secrets, keys, certificates and role assignments.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleCreateVault)
}

func (s *Server) handleCreateVault(ctx context.Context, _ *mcp.CallToolRequest, args createVaultArgs) (*mcp.CallToolResult, createVaultResult, error) {
	if args.Name == "" {
		return errorResult("create_vault requires a name"), createVaultResult{}, nil
	}

	// This tool creates a vault, so there is nothing to resolve -- but the
	// allowlist still applies. Creating a vault this server would then be
	// forbidden to touch is a strange thing to permit, and refusing now is
	// cheaper than explaining afterwards.
	if !s.vaultPermitted(args.Name) {
		return errorResult(
			"this server is not permitted to operate on a vault named %q, so creating it would leave it unusable here",
			args.Name), createVaultResult{}, nil
	}

	vault, err := s.client.CreateVault(ctx, vaultapi.CreateVaultRequest{
		Name:            args.Name,
		Enabled:         args.Enabled,
		PurgeProtection: args.PurgeProtection,
		RetentionDays:   args.RetentionDays,
		Tags:            args.Tags,
	})
	if err != nil {
		return errorResult("could not create vault %q: %s", args.Name, err), createVaultResult{}, nil
	}

	return nil, createVaultResult{
		Name:            vault.Name,
		ID:              vault.ID.String(),
		Enabled:         vault.Enabled,
		PurgeProtection: vault.PurgeProtection,
		RetentionDays:   vault.RetentionDays,
	}, nil
}
```

Add `registerVaultsWriteTools(s)` to `RegisterAllTools`.

`TestCreateVault_ConflictIsExplained` relies on plan 01's conflict hint, which reads *"a resource with that name already exists…"*. If the assertion fails, check that hint rather than weakening the test.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestCreateVault_ -v`
Expected: PASS — all eight tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_vaults_write.go internal/mcpserver/tools_vaults_write_test.go internal/mcpserver/register.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the create_vault tool

It creates a vault rather than acting on one, so there is nothing to resolve
-- but the allowlist still applies to the new name. Creating a vault this
server would then be forbidden to touch is a strange thing to permit, and
refusing up front is cheaper than explaining afterwards.

Unmentioned security settings are omitted rather than sent as false, so an
operator who did not mention purge protection gets the server's default rather
than it silently off."
```

---

### Task 3: `grant_vault_role`

**Files:**
- Create: `internal/mcpserver/tools_access_write.go`
- Create: `internal/mcpserver/tools_access_write_test.go`
- Modify: `internal/mcpserver/register.go`

**Interfaces:**
- Consumes: `vaultapi.Client.CreateRoleAssignment`, `GrantRoleRequest` (plan 18).
- Produces: `func registerAccessWriteTools(s *Server)`, `grantVaultRoleArgs`, `grantVaultRoleResult`.

**Why this belongs in the write tier and not the destructive one:** granting a role adds access rather than removing it, so it cannot destroy anything. It is nonetheless the most consequential tool in this plan — a role grant changes who can reach the vault — which is why its description names the permission it requires and its result restates exactly what was granted to whom.

**Revoking** is the destructive counterpart and lands in plan 25.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/tools_access_write_test.go`:

```go
package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGrantVaultRole_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerAccessWriteTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestGrantVaultRole_GrantsTheRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + assignmentID + `","principal_id":"` + dbSecretUUID + `",
		"principal_username":"mcp-agent","principal_type":"service_account",
		"role":"Key Vault Secrets User","vault_name":"default"}`
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	var got grantVaultRoleResult
	structured(t, callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "mcp-agent", "role": "Key Vault Secrets User",
		"principal_type": "service_account",
	}), &got)

	require.Equal(t, "Key Vault Secrets User", got.Role)
	require.Equal(t, "default", got.Vault)
	require.Equal(t, "mcp-agent", f.lastWriteBody["principal"])
	require.Equal(t, "service_account", f.lastWriteBody["principal_type"])
}

func TestGrantVaultRole_DefaultsPrincipalTypeToUser(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + assignmentID + `","role":"Key Vault Reader"}`
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	_ = callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "alice", "role": "Key Vault Reader",
	})

	_, present := f.lastWriteBody["principal_type"]
	require.False(t, present, "the server defaults it; sending nothing is correct")
}

func TestGrantVaultRole_RestatesWhatWasGranted(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + assignmentID + `","principal_username":"alice",
		"principal_type":"user","role":"Key Vault Administrator"}`
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	var got grantVaultRoleResult
	structured(t, callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "alice", "role": "Key Vault Administrator",
	}), &got)

	require.Equal(t, "Key Vault Administrator", got.Role)
	require.NotEmpty(t, got.AssignmentID,
		"the assignment id is what a later revoke needs")
}

func TestGrantVaultRole_RequiresPrincipalAndRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	require.True(t, callTool(t, s, "grant_vault_role", map[string]any{"role": "Key Vault Reader"}).IsError)
	require.True(t, callTool(t, s, "grant_vault_role", map[string]any{"principal": "alice"}).IsError)
}

func TestGrantVaultRole_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := writeConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerAccessWriteTools(s)

	result := callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "alice", "role": "Key Vault Reader", "vault": "prod",
	})
	require.True(t, result.IsError)
	require.Empty(t, f.requested)
}

func TestGrantVaultRole_ForbiddenNamesTheDataAccessAdminRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults/default/role-assignments", http.StatusForbidden)
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	result := callTool(t, s, "grant_vault_role", map[string]any{
		"principal": "alice", "role": "Key Vault Reader",
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Data Access Administrator")
}

func TestGrantVaultRole_DescriptionNamesItsRequirement(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerAccessWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "grant_vault_role" {
			require.Contains(t, tool.Description, "Data Access Administrator",
				"a role grant changes who can reach the vault; the requirement should be visible up front")
			require.False(t, tool.Annotations.ReadOnlyHint)
			return
		}
	}
	t.Fatal("grant_vault_role was not registered")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestGrantVaultRole_ -v`
Expected: FAIL — `undefined: registerAccessWriteTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_access_write.go`:

```go
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type grantVaultRoleArgs struct {
	Principal     string `json:"principal" jsonschema:"the username or id of the user or service account to grant to"`
	Role          string `json:"role" jsonschema:"a built-in role name, such as Key Vault Secrets User; list_role_assignments shows roles already in use"`
	PrincipalType string `json:"principal_type,omitempty" jsonschema:"user or service_account; defaults to user"`
	Vault         string `json:"vault,omitempty" jsonschema:"the vault to grant in; defaults to the server's configured vault"`
}

// grantVaultRoleResult restates the grant.
//
// It repeats the role and principal deliberately: a grant changes who can
// reach the vault, and an operator reading the transcript should be able to
// see exactly what was given to whom without re-reading the request.
type grantVaultRoleResult struct {
	Vault             string    `json:"vault"`
	AssignmentID      string    `json:"assignment_id"`
	Role              string    `json:"role"`
	PrincipalID       string    `json:"principal_id,omitempty"`
	PrincipalUsername Untrusted `json:"principal_username,omitempty"`
	PrincipalType     string    `json:"principal_type,omitempty"`
}

// registerAccessWriteTools adds the write-tier access tools.
//
// Granting is a write rather than a destructive operation: it adds access and
// removes nothing. Revoking is its destructive counterpart and lives in the
// destructive tier.
func registerAccessWriteTools(s *Server) {
	registerIf(s, TierWrite, "grant_vault_role",
		"Grant a built-in role to a user or service account in a vault. "+
			"Requires admin, vaults/manage, or the Key Vault Data Access Administrator role in that vault.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleGrantVaultRole)
}

func (s *Server) handleGrantVaultRole(ctx context.Context, _ *mcp.CallToolRequest, args grantVaultRoleArgs) (*mcp.CallToolResult, grantVaultRoleResult, error) {
	if args.Principal == "" {
		return errorResult("grant_vault_role requires a principal"), grantVaultRoleResult{}, nil
	}
	if args.Role == "" {
		return errorResult("grant_vault_role requires a role"), grantVaultRoleResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), grantVaultRoleResult{}, nil
	}

	assignment, err := s.client.CreateRoleAssignment(ctx, vault, vaultapi.GrantRoleRequest{
		Principal:     args.Principal,
		PrincipalType: args.PrincipalType,
		Role:          args.Role,
	})
	if err != nil {
		return errorResult("could not grant %q to %q in vault %q: %s",
			args.Role, args.Principal, vault, err), grantVaultRoleResult{}, nil
	}

	return nil, grantVaultRoleResult{
		Vault:             vault,
		AssignmentID:      assignment.ID.String(),
		Role:              assignment.Role,
		PrincipalID:       assignment.PrincipalID.String(),
		PrincipalUsername: Wrap(assignment.PrincipalUsername),
		PrincipalType:     assignment.PrincipalType,
	}, nil
}
```

Add `registerAccessWriteTools(s)` to `RegisterAllTools`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_access_write.go internal/mcpserver/tools_access_write_test.go internal/mcpserver/register.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the grant_vault_role tool

Granting belongs in the write tier rather than the destructive one: it adds
access and removes nothing. It is still the most consequential tool here,
since a grant changes who can reach the vault, so its description names the
permission it needs and its result restates exactly what was granted to whom
-- including the assignment id a later revoke will need."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ -race -v
go vet ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

Confirm the tier boundary holds. With `allow_write` off, the ten read tools;
with it on, thirteen:

```bash
go test ./internal/mcpserver/ -run 'TestRegisterAllTools_|IsAbsentWithoutAllowWrite' -v
```

Note that `TestRegisterAllTools_DefaultConfigExposesExactlyTheReadTier` still
passes: these tools are gated, so a default configuration is unchanged. Plan 28
extends that test to the full matrix.

## Notes for the next plan

Plan 22 adds the five key and certificate write tools, completing the write
tier at nine.

**The decision plan 20 deferred, resolved:** `set_key_rotation_policy` and
`set_certificate_policy` wrap a full replacement, not a merge. Plan 22 makes
every policy field **required** in the tool schema rather than optional. A
required field cannot be accidentally omitted, so the replacement semantics
become safe without a read-then-merge round trip and without a TOCTOU window.
The tool description tells the caller to read the current policy first — which
`get_key` and `get_certificate` already return.
