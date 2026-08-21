# Write-Tier Tools: Keys and Certificates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register the remaining five write-tier tools — `create_key`, `rotate_key`, `set_key_rotation_policy`, `create_certificate` and `set_certificate_policy` — completing the write tier at nine.

**Architecture:** Plan 21's shape. The one substantive design decision is how the two policy tools handle the server's replacement semantics, resolved below.

**Tech Stack:** Go 1.25, `github.com/modelcontextprotocol/go-sdk/mcp` v1.7.0, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Write tier".

**Plan-of-plans:** This is plan 22 of 31, completing Group F. Requires plans 19, 20 and 21 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **`registerIf(s, TierWrite, ...)`** for all five tools.
- **No tool may return private key material**, and no result type here has a field for it.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## The policy-replacement decision, resolved

Plans 19 and 20 established that `UpsertKeyRotationPolicyRequest` and `UpsertCertificatePolicyRequest` have **no pointer fields**: an upsert is a full replacement, and omitting a value sets it to zero. Plan 20 left the tool-level handling to be decided explicitly. It is decided here:

**Every policy field is required in the tool schema.**

Two alternatives were considered and rejected:

- *Optional fields, documented as a replacement.* A model that reads "replaces the policy" and still sends only `rotate_after_days` silently zeroes `expiry_days`. Relying on the model to read carefully is not a safety property.
- *Read the current policy, merge, write back.* Friendlier, but it hides that the underlying operation is a replacement, and it opens a TOCTOU window between the read and the write — on a policy that governs key rotation, that is a real if small risk.

Required fields make the replacement safe by construction: a field that cannot be omitted cannot be accidentally zeroed. The cost is that a caller changing one setting must supply the other three — which is why both tool descriptions tell the caller to read the current policy first, and why `get_key` and `get_certificate` already return it.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/tools_keys_write.go` (new) | `registerKeysWriteTools` and its three tools |
| `internal/mcpserver/tools_certificates_write.go` (new) | `registerCertificatesWriteTools` and its two tools |
| `internal/mcpserver/register.go` (modify) | Add both registration calls |
| `internal/mcpserver/*_write_test.go` (new) | One per file |

---

### Task 1: `create_key` and `rotate_key`

**Files:**
- Create: `internal/mcpserver/tools_keys_write.go`
- Create: `internal/mcpserver/tools_keys_write_test.go`
- Modify: `internal/mcpserver/register.go`

**Interfaces:**
- Consumes: `vaultapi.Client.CreateKey`, `CreateKeyRequest`, `RotateKey` (plan 19).
- Produces: `func registerKeysWriteTools(s *Server)`, `createKeyArgs`, `createKeyResult`, `rotateKeyArgs`, `rotateKeyResult`.

**`rotate_key`'s annotation is the interesting one.** It is not destructive — rotation adds a version and leaves the previous one intact — but it is emphatically not idempotent: each call creates another version. A host that treated it as safe to retry would quietly multiply key versions.

**`create_key`'s description must mention the OCT/HSM rule**, because a model asked for "an AES key" will otherwise pick `OCT` and get a server error it cannot interpret.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/tools_keys_write_test.go`:

```go
package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateKey_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerKeysWriteTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestCreateKey_CreatesAnRSAKey(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"signing-key","type":"RSA","bits":2048,"enabled":true}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got createKeyResult
	structured(t, callTool(t, s, "create_key", map[string]any{
		"name": "signing-key", "type": "RSA", "bits": 2048,
	}), &got)

	require.Equal(t, "signing-key", got.Name)
	require.Equal(t, "RSA", got.Type)
	require.Equal(t, 2048, got.Bits)
	require.EqualValues(t, 2048, f.lastWriteBody["bits"])
}

func TestCreateKey_CreatesAnECDSAKey(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"ec-key","type":"ECDSA","curve":"P-256"}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got createKeyResult
	structured(t, callTool(t, s, "create_key", map[string]any{
		"name": "ec-key", "type": "ECDSA", "curve": "P-256",
	}), &got)

	require.Equal(t, "P-256", got.Curve)
	require.Equal(t, "P-256", f.lastWriteBody["curve"])
}

func TestCreateKey_RejectsTheWrongECTypeName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "create_key", map[string]any{"name": "k", "type": "EC"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "ECDSA")
	require.Empty(t, f.requested, "a known-bad type must not reach the server")
}

func TestCreateKey_DescriptionMentionsTheHSMRuleForOCT(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "create_key" {
			require.Contains(t, tool.Description, "HSM",
				"a model asked for an AES key will pick OCT and needs to know it requires an HSM")
			return
		}
	}
	t.Fatal("create_key was not registered")
}

func TestCreateKey_ReturnsNoPrivateMaterial(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"k","type":"RSA",
		"value":"-----BEGIN PRIVATE KEY-----LEAKED"}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "create_key", map[string]any{"name": "k", "type": "RSA", "bits": 2048})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}

func TestCreateKey_RequiresNameAndType(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	require.True(t, callTool(t, s, "create_key", map[string]any{"type": "RSA"}).IsError)
	require.True(t, callTool(t, s, "create_key", map[string]any{"name": "k"}).IsError)
}

func TestRotateKey_CreatesANewVersion(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	f.writeResponse = `{"id":"` + signKeyUUID + `","name":"signing-key","type":"RSA"}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got rotateKeyResult
	structured(t, callTool(t, s, "rotate_key", map[string]any{"name": "signing-key"}), &got)

	require.Equal(t, "signing-key", got.Name)
	require.True(t, f.hit("/api/v1/vaults/default/keys/"+signKeyUUID+"/rotate"))
}

func TestRotateKey_IsNotAnnotatedIdempotent(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "rotate_key" {
			continue
		}
		require.False(t, tool.Annotations.IdempotentHint,
			"each call creates another version; a host must not treat a retry as free")
		require.NotNil(t, tool.Annotations.DestructiveHint)
		require.False(t, *tool.Annotations.DestructiveHint,
			"rotation adds a version and leaves the previous one intact")
		return
	}
	t.Fatal("rotate_key was not registered")
}

func TestRotateKey_UnknownNameIsActionable(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "rotate_key", map[string]any{"name": "signing-ky"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "did you mean")
}

func TestRotateKey_ForbiddenNamesTheCryptoOfficerRole(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	f.failWith("/api/v1/vaults/default/keys/"+signKeyUUID+"/rotate", http.StatusForbidden)
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "rotate_key", map[string]any{"name": "signing-key"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Crypto Officer")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestCreateKey_|TestRotateKey_' -v`
Expected: FAIL — `undefined: registerKeysWriteTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_keys_write.go`:

```go
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type createKeyArgs struct {
	Name  string   `json:"name" jsonschema:"the new key's name"`
	Type  string   `json:"type" jsonschema:"RSA, ECDSA or OCT"`
	Bits  int      `json:"bits,omitempty" jsonschema:"key size for RSA (2048, 3072, 4096) or OCT (128, 192, 256)"`
	Curve string   `json:"curve,omitempty" jsonschema:"curve for ECDSA, such as P-256, P-384 or P-521"`
	Tags  []string `json:"tags,omitempty" jsonschema:"tags to attach to the key"`
	Vault string   `json:"vault,omitempty" jsonschema:"the vault to create in; defaults to the server's configured vault"`
}

// createKeyResult describes the created key. It has no field for private
// material, and none may be added.
type createKeyResult struct {
	Vault   string `json:"vault"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Type    string `json:"type"`
	Bits    int    `json:"bits,omitempty"`
	Curve   string `json:"curve,omitempty"`
	Enabled bool   `json:"enabled"`
}

type rotateKeyArgs struct {
	Name  string `json:"name" jsonschema:"the key's name, or its id"`
	Vault string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type rotateKeyResult struct {
	Vault string `json:"vault"`
	Name  string `json:"name"`
	ID    string `json:"id"`
	Type  string `json:"type"`
}

// registerKeysWriteTools adds the write-tier key tools.
func registerKeysWriteTools(s *Server) {
	registerIf(s, TierWrite, "create_key",
		"Create a cryptographic key. Type must be RSA, ECDSA or OCT. "+
			"OCT (symmetric, AES) keys require the server to have an HSM configured, matching Azure Key Vault. "+
			"Never returns private key material.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleCreateKey)

	registerIf(s, TierWrite, "rotate_key",
		"Create a new version of an existing key. Previous versions remain and stay usable for verification and decryption.",
		// Not idempotent: each call creates another version.
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleRotateKey)
}

func (s *Server) handleCreateKey(ctx context.Context, _ *mcp.CallToolRequest, args createKeyArgs) (*mcp.CallToolResult, createKeyResult, error) {
	if args.Name == "" {
		return errorResult("create_key requires a name"), createKeyResult{}, nil
	}
	if args.Type == "" {
		return errorResult("create_key requires a type: RSA, ECDSA or OCT"), createKeyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), createKeyResult{}, nil
	}

	key, err := s.client.CreateKey(ctx, vault, vaultapi.CreateKeyRequest{
		Name:  args.Name,
		Type:  args.Type,
		Bits:  args.Bits,
		Curve: args.Curve,
		Tags:  args.Tags,
	})
	if err != nil {
		return errorResult("could not create key %q in vault %q: %s", args.Name, vault, err), createKeyResult{}, nil
	}

	return nil, createKeyResult{
		Vault:   vault,
		Name:    key.Name,
		ID:      key.ID.String(),
		Type:    key.Type,
		Bits:    key.Bits,
		Curve:   key.Curve,
		Enabled: key.Enabled,
	}, nil
}

func (s *Server) handleRotateKey(ctx context.Context, _ *mcp.CallToolRequest, args rotateKeyArgs) (*mcp.CallToolResult, rotateKeyResult, error) {
	if args.Name == "" {
		return errorResult("rotate_key requires a name"), rotateKeyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), rotateKeyResult{}, nil
	}

	key, err := s.client.RotateKey(ctx, vault, args.Name)
	if err != nil {
		return errorResult("could not rotate key %q in vault %q: %s", args.Name, vault, err), rotateKeyResult{}, nil
	}

	return nil, rotateKeyResult{
		Vault: vault,
		Name:  key.Name,
		ID:    key.ID.String(),
		Type:  key.Type,
	}, nil
}
```

Add `registerKeysWriteTools(s)` to `RegisterAllTools`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run 'TestCreateKey_|TestRotateKey_' -v`
Expected: PASS — all eleven tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_keys_write.go internal/mcpserver/tools_keys_write_test.go internal/mcpserver/register.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the create_key and rotate_key tools

create_key's description names the OCT/HSM rule, because a model asked for an
AES key will otherwise pick OCT and get a server error it cannot interpret.

rotate_key is annotated non-idempotent: each call creates another version, so
a host treating a retry as free would quietly multiply key versions. It is not
destructive, since previous versions remain usable for verification and
decryption."
```

---

### Task 2: `set_key_rotation_policy`

**Files:**
- Modify: `internal/mcpserver/tools_keys_write.go`
- Modify: `internal/mcpserver/tools_keys_write_test.go` (append)

**Interfaces:**
- Consumes: `vaultapi.Client.UpsertKeyRotationPolicy`, `SetKeyRotationPolicyRequest` (plan 19).
- Produces: `setKeyRotationPolicyArgs`, `setKeyRotationPolicyResult`.

**All four policy fields are required**, per the decision above. The `jsonschema` tags carry no `omitempty`, so the inferred schema marks them required, and a caller cannot omit one and silently zero it.

`Enabled` is a `*bool` in the args despite being required, so that "false" and "not supplied" stay distinguishable — a missing value is rejected rather than read as `false`.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/tools_keys_write_test.go`:

```go
func TestSetKeyRotationPolicy_ReplacesThePolicy(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","rotate_after_days":90,
		"notify_before_expiry_days":14,"expiry_days":365,"enabled":true,
		"next_rotation_at":"2026-11-01T00:00:00Z"}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	var got setKeyRotationPolicyResult
	structured(t, callTool(t, s, "set_key_rotation_policy", map[string]any{
		"name": "signing-key", "rotate_after_days": 90,
		"notify_before_expiry_days": 14, "expiry_days": 365, "enabled": true,
	}), &got)

	require.Equal(t, 90, got.RotateAfterDays)
	require.Equal(t, 365, got.ExpiryDays)
	require.True(t, got.Enabled)
	require.EqualValues(t, 90, f.lastWriteBody["rotate_after_days"])
}

func TestSetKeyRotationPolicy_AllFieldsAreRequiredInTheSchema(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "set_key_rotation_policy" {
			continue
		}
		encoded, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(encoded, &schema))

		required, _ := schema["required"].([]any)
		var names []string
		for _, item := range required {
			names = append(names, item.(string))
		}

		for _, field := range []string{"rotate_after_days", "notify_before_expiry_days", "expiry_days", "enabled"} {
			require.Contains(t, names, field,
				"this operation replaces the policy, so an omittable field could silently zero itself")
		}
		return
	}
	t.Fatal("set_key_rotation_policy was not registered")
}

func TestSetKeyRotationPolicy_RejectsAMissingField(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "set_key_rotation_policy", map[string]any{
		"name": "signing-key", "rotate_after_days": 90,
	})
	require.True(t, result.IsError,
		"a partial policy must be refused, not sent with the rest zeroed")
	require.Empty(t, f.requested)
}

func TestSetKeyRotationPolicy_DistinguishesFalseFromMissing(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key"}]}`,
	})
	f.writeResponse = `{"key_id":"` + signKeyUUID + `","enabled":false}`
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	result := callTool(t, s, "set_key_rotation_policy", map[string]any{
		"name": "signing-key", "rotate_after_days": 90,
		"notify_before_expiry_days": 14, "expiry_days": 365, "enabled": false,
	})
	require.False(t, result.IsError, "an explicit false is a supplied value")
	require.Equal(t, false, f.lastWriteBody["enabled"])
}

func TestSetKeyRotationPolicy_DescriptionSaysItReplaces(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "set_key_rotation_policy" {
			require.Contains(t, tool.Description, "Replaces",
				"the caller must know this is not a partial update")
			require.Contains(t, tool.Description, "get_key",
				"and where to read the current values from")
			return
		}
	}
	t.Fatal("set_key_rotation_policy was not registered")
}

func TestSetKeyRotationPolicy_IsAnnotatedIdempotent(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerKeysWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "set_key_rotation_policy" {
			require.True(t, tool.Annotations.IdempotentHint,
				"a full replacement applied twice leaves the same state")
			return
		}
	}
	t.Fatal("set_key_rotation_policy was not registered")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestSetKeyRotationPolicy_ -v`
Expected: FAIL — the tool is not registered.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/mcpserver/tools_keys_write.go`:

```go
// setKeyRotationPolicyArgs are the arguments to set_key_rotation_policy.
//
// Every policy field is required, with no omitempty, so the inferred schema
// marks it so. The underlying operation is a full replacement -- the server's
// request type has no pointer fields -- and a field that cannot be omitted
// cannot be accidentally zeroed. That makes replacement safe by construction,
// without a read-then-merge round trip or the TOCTOU window it would open.
//
// Enabled is a pointer despite being required, so that a missing value is
// rejected rather than read as false.
type setKeyRotationPolicyArgs struct {
	Name                   string `json:"name" jsonschema:"the key's name, or its id"`
	RotateAfterDays        int    `json:"rotate_after_days" jsonschema:"how many days after creation a version is rotated"`
	NotifyBeforeExpiryDays int    `json:"notify_before_expiry_days" jsonschema:"how many days before expiry to notify"`
	ExpiryDays             int    `json:"expiry_days" jsonschema:"how many days a version remains valid"`
	Enabled                *bool  `json:"enabled" jsonschema:"whether automatic rotation is active"`
	Vault                  string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type setKeyRotationPolicyResult struct {
	Vault                  string `json:"vault"`
	KeyName                string `json:"key_name"`
	RotateAfterDays        int    `json:"rotate_after_days"`
	NotifyBeforeExpiryDays int    `json:"notify_before_expiry_days"`
	ExpiryDays             int    `json:"expiry_days"`
	Enabled                bool   `json:"enabled"`
	NextRotationAt         string `json:"next_rotation_at,omitempty"`
}

func (s *Server) handleSetKeyRotationPolicy(ctx context.Context, _ *mcp.CallToolRequest, args setKeyRotationPolicyArgs) (*mcp.CallToolResult, setKeyRotationPolicyResult, error) {
	if args.Name == "" {
		return errorResult("set_key_rotation_policy requires a name"), setKeyRotationPolicyResult{}, nil
	}
	if args.Enabled == nil {
		return errorResult(
			"set_key_rotation_policy requires enabled: this call replaces the whole policy, " +
				"so every field must be supplied. Read the current values with get_key first."), setKeyRotationPolicyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), setKeyRotationPolicyResult{}, nil
	}

	policy, err := s.client.UpsertKeyRotationPolicy(ctx, vault, args.Name, vaultapi.SetKeyRotationPolicyRequest{
		RotateAfterDays:        args.RotateAfterDays,
		NotifyBeforeExpiryDays: args.NotifyBeforeExpiryDays,
		ExpiryDays:             args.ExpiryDays,
		Enabled:                *args.Enabled,
	})
	if err != nil {
		return errorResult("could not set the rotation policy for key %q in vault %q: %s",
			args.Name, vault, err), setKeyRotationPolicyResult{}, nil
	}

	result := setKeyRotationPolicyResult{
		Vault:                  vault,
		KeyName:                args.Name,
		RotateAfterDays:        policy.RotateAfterDays,
		NotifyBeforeExpiryDays: policy.NotifyBeforeExpiryDays,
		ExpiryDays:             policy.ExpiryDays,
		Enabled:                policy.Enabled,
	}
	if !policy.NextRotationAt.IsZero() {
		result.NextRotationAt = policy.NextRotationAt.Format(time.RFC3339)
	}
	return nil, result, nil
}
```

Add `"time"` to the imports, and register it in `registerKeysWriteTools`:

```go
	registerIf(s, TierWrite, "set_key_rotation_policy",
		"Replaces a key's entire rotation policy. Every field is required, and any value not supplied would be lost, "+
			"so read the current policy with get_key first and pass all four values.",
		// A full replacement applied twice leaves the same state.
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleSetKeyRotationPolicy)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestSetKeyRotationPolicy_ -v`
Expected: PASS — all six tests.

If `TestSetKeyRotationPolicy_AllFieldsAreRequiredInTheSchema` fails, the schema inference is treating a field as optional. Check that no `jsonschema` tag on a required field carries `omitempty` in its **json** tag — that is what drives optionality.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_keys_write.go internal/mcpserver/tools_keys_write_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add set_key_rotation_policy with required fields

The underlying upsert is a full replacement -- the server's request type has
no pointer fields -- so an omitted value is set to zero rather than left
alone. Making every field required means a value that cannot be omitted cannot
be accidentally zeroed: replacement becomes safe by construction, without a
read-then-merge round trip or the TOCTOU window that would open.

enabled is a pointer despite being required, so a missing value is rejected
rather than read as false. The description says the call replaces rather than
updates, and points at get_key for the current values."
```

---

### Task 3: `create_certificate` and `set_certificate_policy`

**Files:**
- Create: `internal/mcpserver/tools_certificates_write.go`
- Create: `internal/mcpserver/tools_certificates_write_test.go`
- Modify: `internal/mcpserver/register.go`

**Interfaces:**
- Consumes: `vaultapi.Client.CreateCertificate`, `UpsertCertificatePolicy` (plan 20).
- Produces: `func registerCertificatesWriteTools(s *Server)` plus its arg and result types.

**`create_certificate` must say it needs an existing key.** Plan 20 flagged this: a model asked to "create a TLS certificate" will otherwise call it without one and get a resolution error it cannot act on. The description names the requirement and points at `create_key` and `list_keys`.

**`set_certificate_policy` follows the same required-fields rule** as Task 2, for the same reason. `key_size` and `curve` stay optional, since exactly one applies per key type and requiring both would be impossible to satisfy.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/tools_certificates_write_test.go`:

```go
package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateCertificate_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerCertificatesWriteTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestCreateCertificate_IssuesAgainstAnExistingKey(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"tls-key"}]}`,
	})
	f.writeResponse = `{"id":"` + tlsCertUUID + `","name":"tls-cert","auto_renew":true,"renewal_days":30}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	var got createCertificateResult
	structured(t, callTool(t, s, "create_certificate", map[string]any{
		"name": "tls-cert", "key_name": "tls-key", "validity_days": 365,
		"auto_renew": true, "renewal_days": 30,
	}), &got)

	require.Equal(t, "tls-cert", got.Name)
	require.True(t, got.AutoRenew)
	require.Equal(t, signKeyUUID, f.lastWriteBody["key_id"])
}

func TestCreateCertificate_DescriptionSaysAKeyIsRequired(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "create_certificate" {
			require.Contains(t, tool.Description, "existing key",
				"a model asked for a TLS certificate will otherwise try this without one")
			require.Contains(t, tool.Description, "create_key")
			return
		}
	}
	t.Fatal("create_certificate was not registered")
}

func TestCreateCertificate_UnknownKeyIsActionable(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"tls-key"}]}`,
	})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	result := callTool(t, s, "create_certificate", map[string]any{
		"name": "tls-cert", "key_name": "no-such-key", "validity_days": 365,
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "no keys named")
}

func TestCreateCertificate_RequiresNameKeyAndValidity(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	require.True(t, callTool(t, s, "create_certificate", map[string]any{
		"key_name": "k", "validity_days": 365}).IsError)
	require.True(t, callTool(t, s, "create_certificate", map[string]any{
		"name": "c", "validity_days": 365}).IsError)
	require.True(t, callTool(t, s, "create_certificate", map[string]any{
		"name": "c", "key_name": "k"}).IsError)
}

func TestCreateCertificate_ReturnsNoPrivateMaterial(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"tls-key"}]}`,
	})
	f.writeResponse = `{"id":"` + tlsCertUUID + `","name":"tls-cert",
		"private_key":"-----BEGIN PRIVATE KEY-----LEAKED"}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	result := callTool(t, s, "create_certificate", map[string]any{
		"name": "tls-cert", "key_name": "tls-key", "validity_days": 365,
	})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}

func TestSetCertificatePolicy_ReplacesThePolicy(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/certificates": `{"certificates":[{"id":"` + tlsCertUUID + `","name":"tls-cert"}]}`,
	})
	f.writeResponse = `{"certificate_id":"` + tlsCertUUID + `","validity_months":12,"key_type":"RSA",
		"key_size":2048,"subject":"CN=example.com","auto_renew":true,"days_before_expiry":30}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	var got setCertificatePolicyResult
	structured(t, callTool(t, s, "set_certificate_policy", map[string]any{
		"name": "tls-cert", "validity_months": 12, "key_type": "RSA", "key_size": 2048,
		"subject": "CN=example.com", "auto_renew": true, "days_before_expiry": 30,
	}), &got)

	require.Equal(t, 12, got.ValidityMonths)
	require.Equal(t, "CN=example.com", got.Subject.Text())
	require.Equal(t, "CN=example.com", f.lastWriteBody["subject"])
}

func TestSetCertificatePolicy_WrapsSubjectInTheResult(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/certificates": `{"certificates":[{"id":"` + tlsCertUUID + `","name":"tls-cert"}]}`,
	})
	f.writeResponse = `{"certificate_id":"` + tlsCertUUID + `","subject":"CN=example.com"}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	result := callTool(t, s, "set_certificate_policy", map[string]any{
		"name": "tls-cert", "validity_months": 12, "key_type": "RSA",
		"subject": "CN=example.com", "auto_renew": true, "days_before_expiry": 30,
	})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "UNTRUSTED-VAULT-DATA",
		"the subject echoed back is still vault-resident free text")
}

func TestSetCertificatePolicy_KeySizeAndCurveStayOptional(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "set_certificate_policy" {
			continue
		}
		encoded, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(encoded, &schema))

		required, _ := schema["required"].([]any)
		var names []string
		for _, item := range required {
			names = append(names, item.(string))
		}

		require.Contains(t, names, "validity_months")
		require.Contains(t, names, "subject")
		require.NotContains(t, names, "key_size",
			"exactly one of key_size and curve applies, so requiring both is unsatisfiable")
		require.NotContains(t, names, "curve")
		return
	}
	t.Fatal("set_certificate_policy was not registered")
}

func TestSetCertificatePolicy_DescriptionSaysItReplaces(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "set_certificate_policy" {
			require.Contains(t, tool.Description, "Replaces")
			require.Contains(t, tool.Description, "get_certificate")
			return
		}
	}
	t.Fatal("set_certificate_policy was not registered")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestCreateCertificate_|TestSetCertificatePolicy_' -v`
Expected: FAIL — `undefined: registerCertificatesWriteTools`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_certificates_write.go`:

```go
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type createCertificateArgs struct {
	Name         string   `json:"name" jsonschema:"the new certificate's name"`
	KeyName      string   `json:"key_name" jsonschema:"the name of an existing key in this vault to issue against"`
	ValidityDays int      `json:"validity_days" jsonschema:"how many days the certificate is valid for"`
	AutoRenew    bool     `json:"auto_renew,omitempty" jsonschema:"renew automatically before expiry"`
	RenewalDays  int      `json:"renewal_days,omitempty" jsonschema:"how many days before expiry to renew"`
	Tags         []string `json:"tags,omitempty" jsonschema:"tags to attach to the certificate"`
	CAKeyName    string   `json:"ca_key_name,omitempty" jsonschema:"the name of an issuing CA key, if this is not self-signed"`
	CACertName   string   `json:"ca_cert_name,omitempty" jsonschema:"the name of an issuing CA certificate"`
	Vault        string   `json:"vault,omitempty" jsonschema:"the vault to create in; defaults to the server's configured vault"`
}

// createCertificateResult describes the issued certificate. It has no field
// for a PEM or a private key.
type createCertificateResult struct {
	Vault       string `json:"vault"`
	Name        string `json:"name"`
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	AutoRenew   bool   `json:"auto_renew"`
	RenewalDays int    `json:"renewal_days"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// setCertificatePolicyArgs replaces a certificate's issuance policy.
//
// The required fields follow the same rule as the key rotation policy: the
// underlying upsert is a full replacement, so a field that cannot be omitted
// cannot be accidentally zeroed. key_size and curve stay optional because
// exactly one applies per key type, and requiring both would be
// unsatisfiable.
type setCertificatePolicyArgs struct {
	Name             string `json:"name" jsonschema:"the certificate's name, or its id"`
	ValidityMonths   int    `json:"validity_months" jsonschema:"how many months an issued certificate is valid for"`
	KeyType          string `json:"key_type" jsonschema:"RSA or ECDSA"`
	Subject          string `json:"subject" jsonschema:"the distinguished name, such as CN=example.com"`
	AutoRenew        *bool  `json:"auto_renew" jsonschema:"renew automatically before expiry"`
	DaysBeforeExpiry int    `json:"days_before_expiry" jsonschema:"how many days before expiry to renew"`
	KeySize          int    `json:"key_size,omitempty" jsonschema:"key size for RSA"`
	Curve            string `json:"curve,omitempty" jsonschema:"curve for ECDSA"`
	SANs             string `json:"sans,omitempty" jsonschema:"comma-separated subject alternative names"`
	IssuerName       string `json:"issuer_name,omitempty" jsonschema:"the issuer to request from"`
	Vault            string `json:"vault,omitempty" jsonschema:"the vault holding the certificate; defaults to the server's configured vault"`
}

type setCertificatePolicyResult struct {
	Vault            string    `json:"vault"`
	CertificateName  string    `json:"certificate_name"`
	ValidityMonths   int       `json:"validity_months"`
	KeyType          string    `json:"key_type"`
	KeySize          int       `json:"key_size,omitempty"`
	Curve            string    `json:"curve,omitempty"`
	Subject          Untrusted `json:"subject"`
	SANs             Untrusted `json:"sans,omitempty"`
	AutoRenew        bool      `json:"auto_renew"`
	DaysBeforeExpiry int       `json:"days_before_expiry"`
}

// registerCertificatesWriteTools adds the write-tier certificate tools.
func registerCertificatesWriteTools(s *Server) {
	registerIf(s, TierWrite, "create_certificate",
		"Issue a certificate against an existing key in the vault. The key must already exist -- "+
			"use list_keys to find one or create_key to make one first. Never returns private key material.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleCreateCertificate)

	registerIf(s, TierWrite, "set_certificate_policy",
		"Replaces a certificate's entire issuance policy. Every required field is applied as given, and anything "+
			"not supplied would be lost, so read the current policy with get_certificate first.",
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleSetCertificatePolicy)
}

func (s *Server) handleCreateCertificate(ctx context.Context, _ *mcp.CallToolRequest, args createCertificateArgs) (*mcp.CallToolResult, createCertificateResult, error) {
	if args.Name == "" {
		return errorResult("create_certificate requires a name"), createCertificateResult{}, nil
	}
	if args.KeyName == "" {
		return errorResult(
			"create_certificate requires key_name: a certificate is issued against an existing key. " +
				"Use list_keys to find one, or create_key to make one."), createCertificateResult{}, nil
	}
	if args.ValidityDays <= 0 {
		return errorResult("create_certificate requires a positive validity_days"), createCertificateResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), createCertificateResult{}, nil
	}

	certificate, err := s.client.CreateCertificate(ctx, vault, vaultapi.CreateCertificateRequest{
		Name:         args.Name,
		KeyName:      args.KeyName,
		ValidityDays: args.ValidityDays,
		Tags:         args.Tags,
		AutoRenew:    args.AutoRenew,
		RenewalDays:  args.RenewalDays,
		CAKeyName:    args.CAKeyName,
		CACertName:   args.CACertName,
	})
	if err != nil {
		return errorResult("could not create certificate %q in vault %q: %s",
			args.Name, vault, err), createCertificateResult{}, nil
	}

	result := createCertificateResult{
		Vault:       vault,
		Name:        certificate.Name,
		ID:          certificate.ID.String(),
		Enabled:     certificate.Enabled,
		AutoRenew:   certificate.AutoRenew,
		RenewalDays: certificate.RenewalDays,
	}
	if certificate.ExpiresAt != nil {
		result.ExpiresAt = certificate.ExpiresAt.Format(time.RFC3339)
	}
	return nil, result, nil
}

func (s *Server) handleSetCertificatePolicy(ctx context.Context, _ *mcp.CallToolRequest, args setCertificatePolicyArgs) (*mcp.CallToolResult, setCertificatePolicyResult, error) {
	if args.Name == "" {
		return errorResult("set_certificate_policy requires a name"), setCertificatePolicyResult{}, nil
	}
	if args.AutoRenew == nil {
		return errorResult(
			"set_certificate_policy requires auto_renew: this call replaces the whole policy, " +
				"so every field must be supplied. Read the current values with get_certificate first."), setCertificatePolicyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), setCertificatePolicyResult{}, nil
	}

	policy, err := s.client.UpsertCertificatePolicy(ctx, vault, args.Name, vaultapi.SetCertificatePolicyRequest{
		ValidityMonths:   args.ValidityMonths,
		KeyType:          args.KeyType,
		KeySize:          args.KeySize,
		Curve:            args.Curve,
		Subject:          args.Subject,
		SANs:             args.SANs,
		AutoRenew:        *args.AutoRenew,
		DaysBeforeExpiry: args.DaysBeforeExpiry,
		IssuerName:       args.IssuerName,
	})
	if err != nil {
		return errorResult("could not set the policy for certificate %q in vault %q: %s",
			args.Name, vault, err), setCertificatePolicyResult{}, nil
	}

	return nil, setCertificatePolicyResult{
		Vault:            vault,
		CertificateName:  args.Name,
		ValidityMonths:   policy.ValidityMonths,
		KeyType:          policy.KeyType,
		KeySize:          policy.KeySize,
		Curve:            policy.Curve,
		Subject:          Wrap(policy.Subject),
		SANs:             Wrap(policy.SANs),
		AutoRenew:        policy.AutoRenew,
		DaysBeforeExpiry: policy.DaysBeforeExpiry,
	}, nil
}
```

Add `"time"` to the imports, and add `registerCertificatesWriteTools(s)` to `RegisterAllTools`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_certificates_write.go internal/mcpserver/tools_certificates_write_test.go internal/mcpserver/register.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add create_certificate and set_certificate_policy

create_certificate's description says a key must already exist and names both
list_keys and create_key, because a model asked to create a TLS certificate
will otherwise call this without one and get a resolution error it cannot act
on.

set_certificate_policy follows the same required-field rule as the key
rotation policy, since the upsert is a replacement. key_size and curve stay
optional: exactly one applies per key type, so requiring both would be
unsatisfiable. The subject echoed back is wrapped -- it is still
vault-resident free text on the way out."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ -race -v
go vet ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

The write tier is complete at nine tools. Confirm the counts move as expected:

```bash
go test ./internal/mcpserver/ -run 'TestRegisterAllTools_|IsAbsentWithoutAllowWrite' -v
```

With `allow_write` off: 10 tools. With it on: 19 — the ten read tools plus
`set_secret`, `create_vault`, `grant_vault_role`, `create_key`, `rotate_key`,
`set_key_rotation_policy`, `create_certificate`, `set_certificate_policy`, and
`recover_deleted`, which plan 24 adds.

**Until plan 24 lands, the write tier has eight tools, not nine.** Plan 28's
gating table is what pins the final number; do not adjust
`TestRegisterAllTools_DefaultConfigExposesExactlyTheReadTier`, which only
covers the default configuration and is unaffected.

## Notes for the next plan

Group F is complete. Plans 23-25 add the destructive tier.

Plan 24 adds `recover_deleted`, which belongs to the **write** tier despite
living in the destructive group's plans — it undoes a deletion rather than
causing one. That is what brings the write tier to nine.

Plan 24 also introduces the confirmation mechanism the destructive tools
depend on, so it must come before plan 25.
