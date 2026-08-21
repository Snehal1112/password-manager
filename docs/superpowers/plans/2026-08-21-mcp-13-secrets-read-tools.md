# Secrets Read Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register the first two MCP tools — `list_secrets` and `get_secret` — including the conditional argument schema that makes `include_value` *structurally absent* when disclosure is disabled.

**Architecture:** Tools are thin: resolve the vault, call `vaultapi`, wrap untrusted text, return a typed result. Everything cross-cutting was settled in plans 10-12. `get_secret` is registered from one of two handlers with different argument types, so the flag changes the tool's schema rather than its runtime behavior.

**Tech Stack:** Go 1.25, `github.com/modelcontextprotocol/go-sdk/mcp` v1.7.0, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Read tier".

**Plan-of-plans:** This is plan 13 of 31. Requires plans 05, 11 and 12 committed. Sets the pattern plans 14 and 15 copy.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Every tool registers through `registerIf`** with its tier named. Reaching for `register` or `mcp.AddTool` loses the deadline, recovery, correlation ID, log line, rate limit and correct annotations at once.
- **Every tool resolves its vault through `s.ResolveVault`.** Reading `s.cfg.Vault` directly bypasses the `allowed_vaults` guard.
- **Every free-text field is wrapped** with `Wrap` or `WrapAll`.
- **`s.discloseValue` is the only route to a plaintext value.**
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Testing approach: a fake vault, not a fake client

`vaultapi.Client` is a concrete struct, not an interface, so `mcpserver` tests cannot inject a mock of it. Rather than introduce an interface purely for testing — which would add indirection to production code to serve a test — the tests stand up an `httptest.Server` speaking the real API shapes and point a real `vaultapi.Client` at it.

This is the better trade: it exercises the actual decode path, so a wrong wrapper key or field name fails here rather than in production. The helper is written once in this plan and reused by plans 14, 15, 21, 22, 25 and 27.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/tools_secrets.go` (new) | `registerSecretsReadTools`, argument and result types, handlers |
| `internal/mcpserver/tools_secrets_test.go` (new) | Both tools over the real protocol |
| `internal/mcpserver/vaultfake_test.go` (new) | `fakeVault` helper, reused by later plans |

---

### Task 1: The `fakeVault` test harness and `list_secrets`

**Files:**
- Create: `internal/mcpserver/vaultfake_test.go`
- Create: `internal/mcpserver/tools_secrets.go`
- Create: `internal/mcpserver/tools_secrets_test.go`

**Interfaces:**
- Consumes: `registerIf`, `TierRead`, `Annotations`, `ResolveVault`, `Wrap`, `WrapAll` (plans 10-12); `vaultapi.Client.ListSecrets` (plan 05).
- Produces — plans 14, 15, 21, 22, 25 and 27 all use the harness and the registration pattern:
  - `type fakeVault struct { ... }` with `func newFakeVault(t *testing.T, routes map[string]string) *fakeVault`
  - `func (f *fakeVault) server(t *testing.T, cfg config.MCPConfig) *Server`
  - `func registerSecretsReadTools(s *Server)`
  - `type listSecretsArgs struct { Vault string; Limit int }`
  - `type listSecretsResult struct { Vault string; Secrets []secretSummaryResult; Truncated bool; Note string }`

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/vaultfake_test.go`:

```go
package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

// fakeVault serves canned API responses so tests exercise the real vaultapi
// decode path.
//
// vaultapi.Client is a concrete struct rather than an interface, and adding
// an interface purely so tests could mock it would put indirection into
// production code to serve a test. Standing up the real shapes instead means
// a wrong wrapper key or field name fails here rather than in production.
type fakeVault struct {
	srv *httptest.Server
	// routes maps a request path to its JSON response body.
	routes map[string]string
	// requested records every path that was hit, in order.
	requested []string
	// status overrides the response status for a given path.
	status map[string]int
}

func newFakeVault(t *testing.T, routes map[string]string) *fakeVault {
	t.Helper()

	f := &fakeVault{routes: routes, status: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requested = append(f.requested, r.URL.Path)

		if code, ok := f.status[r.URL.Path]; ok {
			w.WriteHeader(code)
			return
		}
		body, ok := f.routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// failWith makes path respond with the given status.
func (f *fakeVault) failWith(path string, code int) { f.status[path] = code }

// hit reports whether path was requested.
func (f *fakeVault) hit(path string) bool {
	for _, p := range f.requested {
		if p == path {
			return true
		}
	}
	return false
}

// server builds an mcpserver wired to this fake vault.
func (f *fakeVault) server(t *testing.T, cfg config.MCPConfig) *Server {
	t.Helper()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:      f.srv.URL,
		HTTPClient:   f.srv.Client(),
		Tokens:       staticTestToken("test-token"),
		DisableRetry: true,
	})
	require.NoError(t, err)

	s, err := New(Deps{Client: client, Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)
	return s
}

// staticTestToken is a vaultapi.TokenSource returning a fixed token.
type staticTestToken string

func (s staticTestToken) Token(ctx context.Context) (string, error) { return string(s), nil }

// structured decodes a tool result's StructuredContent into target.
func structured(t *testing.T, result *mcp.CallToolResult, target any) {
	t.Helper()
	require.False(t, result.IsError, "tool returned an error: %s", renderContent(result))

	encoded, err := json.Marshal(result.StructuredContent)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, target))
}

// renderContent flattens a result's text content, for assertions on errors.
func renderContent(result *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			sb.WriteString(text.Text)
		}
	}
	return sb.String()
}
```

Add `"context"`, `"encoding/json"` and the SDK import to that file.

Create `internal/mcpserver/tools_secrets_test.go`:

```go
package mcpserver

import (
	"context"
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

const secretsListBody = `{"secrets":[
	{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","name":"db-password","version":3,
	 "tags":["prod","db"],"created_at":"2026-08-01T00:00:00Z"},
	{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3302","name":"api-key","version":1,
	 "created_at":"2026-08-02T00:00:00Z"}
],"total":2}`

// callTool invokes name with args and returns the raw result.
func callTool(t *testing.T, s *Server, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	return result
}

func TestListSecrets_ReturnsSummaries(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got listSecretsResult
	structured(t, callTool(t, s, "list_secrets", map[string]any{}), &got)

	require.Equal(t, "default", got.Vault)
	require.Len(t, got.Secrets, 2)
	require.Equal(t, "db-password", got.Secrets[0].Name)
	require.Equal(t, 3, got.Secrets[0].Version)
	require.False(t, got.Truncated)
}

func TestListSecrets_NeverReturnsValues(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "list_secrets", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "value",
		"listing is metadata only; no value field may appear at all")
}

func TestListSecrets_WrapsTagsAsUntrusted(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "list_secrets", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "UNTRUSTED-VAULT-DATA",
		"tags are user-written and must be marked")
}

func TestListSecrets_UsesTheRequestedVault(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/prod/secrets": secretsListBody})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got listSecretsResult
	structured(t, callTool(t, s, "list_secrets", map[string]any{"vault": "prod"}), &got)
	require.Equal(t, "prod", got.Vault)
	require.True(t, f.hit("/api/v1/vaults/prod/secrets"))
}

func TestListSecrets_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/prod/secrets": secretsListBody})

	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging"}
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	result := callTool(t, s, "list_secrets", map[string]any{"vault": "prod"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "not permitted")
	require.Empty(t, f.requested, "a refused vault must not produce a request")
}

func TestListSecrets_AppliesTheConfiguredMaxResults(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})

	cfg := testConfig()
	cfg.MaxResults = 1
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	var got listSecretsResult
	structured(t, callTool(t, s, "list_secrets", map[string]any{}), &got)

	require.Len(t, got.Secrets, 1)
	require.True(t, got.Truncated)
	require.NotEmpty(t, got.Note, "a truncated list must say so rather than look complete")
}

func TestListSecrets_CapsAnOversizedRequestedLimit(t *testing.T) {
	f := newFakeVault(t, map[string]string{"/api/v1/vaults/default/secrets": secretsListBody})

	cfg := testConfig()
	cfg.MaxResults = 1
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	var got listSecretsResult
	structured(t, callTool(t, s, "list_secrets", map[string]any{"limit": 500}), &got)
	require.Len(t, got.Secrets, 1,
		"a model asking for more than the configured cap gets the cap, not its request")
}

func TestListSecrets_SurfacesAForbiddenWithItsHint(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	f.failWith("/api/v1/vaults/default/secrets", http.StatusForbidden)
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "list_secrets", map[string]any{})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "Key Vault Secrets User",
		"the 403 hint must reach the model so the operator learns which grant is missing")
}

func TestListSecrets_IsAnnotatedReadOnly(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "list_secrets" {
			require.True(t, tool.Annotations.ReadOnlyHint)
			require.False(t, *tool.Annotations.DestructiveHint)
			return
		}
	}
	t.Fatal("list_secrets was not registered")
}
```

Add `"encoding/json"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestListSecrets_ -v`
Expected: FAIL — `undefined: registerSecretsReadTools`, `undefined: listSecretsResult`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/tools_secrets.go`:

```go
package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// listSecretsArgs are the arguments to list_secrets.
type listSecretsArgs struct {
	Vault string `json:"vault,omitempty" jsonschema:"the vault to list; defaults to the server's configured vault"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of secrets to return; capped by the server"`
}

// secretSummaryResult is one secret's metadata. It has no value field: the
// list route returns none, and this type could not carry one if it did.
type secretSummaryResult struct {
	Name      string      `json:"name"`
	ID        string      `json:"id"`
	Version   int         `json:"version"`
	Tags      []Untrusted `json:"tags,omitempty"`
	CreatedAt string      `json:"created_at,omitempty"`
}

// listSecretsResult is what list_secrets returns.
type listSecretsResult struct {
	Vault     string                `json:"vault"`
	Secrets   []secretSummaryResult `json:"secrets"`
	Truncated bool                  `json:"truncated"`
	Note      string                `json:"note,omitempty"`
}

// effectiveLimit reconciles a requested limit with the configured cap.
//
// A model that asks for more than the cap gets the cap. Silently returning
// fewer results than requested without saying so is what makes a partial view
// look complete.
func (s *Server) effectiveLimit(requested int) int {
	if requested <= 0 || requested > s.cfg.MaxResults {
		return s.cfg.MaxResults
	}
	return requested
}

// truncationNote explains a cut-short list, or returns "" when complete.
func truncationNote(truncated bool, limit int) string {
	if !truncated {
		return ""
	}
	return fmt.Sprintf("Results were truncated to %d entries. Narrow the query or raise mcp.max_results to see more.", limit)
}

// registerSecretsReadTools adds the read-tier secret tools.
func registerSecretsReadTools(s *Server) {
	registerIf(s, TierRead, "list_secrets",
		"List the secrets in a vault. Returns names, versions and tags only, never secret values.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleListSecrets)
}

// handleListSecrets implements list_secrets.
func (s *Server) handleListSecrets(ctx context.Context, _ *mcp.CallToolRequest, args listSecretsArgs) (*mcp.CallToolResult, listSecretsResult, error) {
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), listSecretsResult{}, nil
	}

	limit := s.effectiveLimit(args.Limit)
	summaries, truncated, err := s.client.ListSecrets(ctx, vault, limit)
	if err != nil {
		return errorResult("could not list secrets in vault %q: %s", vault, err), listSecretsResult{}, nil
	}

	secrets := make([]secretSummaryResult, 0, len(summaries))
	for _, summary := range summaries {
		secrets = append(secrets, secretSummaryResult{
			Name:      summary.Name,
			ID:        summary.ID.String(),
			Version:   summary.Version,
			Tags:      WrapAll(summary.Tags),
			CreatedAt: summary.CreatedAt,
		})
	}

	return nil, listSecretsResult{
		Vault:     vault,
		Secrets:   secrets,
		Truncated: truncated,
		Note:      truncationNote(truncated, limit),
	}, nil
}
```

Note: `secretSummaryResult.Name` is intentionally **not** wrapped. Names are constrained identifiers used for addressing, and wrapping them would break a model's ability to pass one back to `get_secret`. Tags and descriptions are the free-text fields.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestListSecrets_ -v`
Expected: PASS — all nine tests.

`TestListSecrets_NeverReturnsValues` asserts the substring `value` is absent. If the truncation note or a tag happens to contain it, adjust the fixture rather than the assertion.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_secrets.go internal/mcpserver/tools_secrets_test.go internal/mcpserver/vaultfake_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the list_secrets tool

Tests stand up a real API-shaped httptest server and point a real
vaultapi.Client at it, rather than introducing an interface purely so tests
could mock a concrete struct. A wrong wrapper key or field name therefore
fails here rather than in production.

A requested limit above the configured cap gets the cap, and truncation is
stated in the result -- silently returning fewer results than asked for is
what makes a partial view look complete. Names stay unwrapped so a model can
pass one back to get_secret; tags are free text and are marked."
```

---

### Task 2: `get_secret` with metadata and version history

**Files:**
- Modify: `internal/mcpserver/tools_secrets.go`
- Modify: `internal/mcpserver/tools_secrets_test.go` (append)

**Interfaces:**
- Consumes: `vaultapi.Client.GetSecret` and `.GetSecretVersions` (plan 05).
- Produces:
  - `type getSecretArgs struct { Name, Vault string }`
  - `type getSecretResult struct { ... }` — shared by both registration variants.
  - `func (s *Server) handleGetSecret(...)`

This task registers the **no-value** variant only. Task 3 adds the disclosure variant and the conditional registration.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/tools_secrets_test.go`:

```go
const (
	dbSecretUUID   = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	secretGetBody  = `{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","name":"db-password",
		"value":"hunter2-super-secret","version":3,"tags":["prod"],"content_type":"text/plain",
		"enabled":true,"created_at":"2026-08-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z"}`
	secretVersionsBody = `[{"version":1,"created_at":"2026-06-01T00:00:00Z","enabled":false},
		{"version":3,"created_at":"2026-08-01T00:00:00Z","enabled":true}]`
)

// secretRoutes returns the routes get_secret needs.
func secretRoutes() map[string]string {
	return map[string]string{
		"/api/v1/vaults/default/secrets":                              secretsListBody,
		"/api/v1/vaults/default/secrets/" + dbSecretUUID:              secretGetBody,
		"/api/v1/vaults/default/secrets/" + dbSecretUUID + "/versions": secretVersionsBody,
	}
}

func TestGetSecret_ReturnsMetadata(t *testing.T) {
	f := newFakeVault(t, secretRoutes())
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got getSecretResult
	structured(t, callTool(t, s, "get_secret", map[string]any{"name": "db-password"}), &got)

	require.Equal(t, "db-password", got.Name)
	require.Equal(t, 3, got.Version)
	require.Equal(t, "text/plain", got.ContentType)
	require.True(t, got.Enabled)
	require.NotEmpty(t, got.ExpiresAt)
	require.Equal(t, "default", got.Vault)
}

func TestGetSecret_IncludesVersionHistory(t *testing.T) {
	f := newFakeVault(t, secretRoutes())
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got getSecretResult
	structured(t, callTool(t, s, "get_secret", map[string]any{"name": "db-password"}), &got)

	require.Len(t, got.Versions, 2)
	require.Equal(t, 1, got.Versions[0].Version)
	require.False(t, got.Versions[0].Enabled)
	require.Equal(t, 3, got.Versions[1].Version)
}

func TestGetSecret_WithholdsTheValueByDefault(t *testing.T) {
	f := newFakeVault(t, secretRoutes())
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "get_secret", map[string]any{"name": "db-password"})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	require.NotContains(t, string(encoded), "hunter2-super-secret",
		"the server returns the plaintext regardless; nothing may forward it")
}

func TestGetSecret_ResolvesTheNameThroughTheListRoute(t *testing.T) {
	f := newFakeVault(t, secretRoutes())
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got getSecretResult
	structured(t, callTool(t, s, "get_secret", map[string]any{"name": "db-password"}), &got)

	require.True(t, f.hit("/api/v1/vaults/default/secrets"))
	require.True(t, f.hit("/api/v1/vaults/default/secrets/"+dbSecretUUID))
}

func TestGetSecret_AcceptsAUUIDDirectly(t *testing.T) {
	f := newFakeVault(t, secretRoutes())
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got getSecretResult
	structured(t, callTool(t, s, "get_secret", map[string]any{"name": dbSecretUUID}), &got)
	require.Equal(t, "db-password", got.Name)
}

func TestGetSecret_UnknownNameIsAnActionableError(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `","name":"db-password"}],"total":1}`,
	})
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "get_secret", map[string]any{"name": "db-passwrd"})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "did you mean",
		"a near miss lets the model correct itself without another round trip")
}

func TestGetSecret_RequiresAName(t *testing.T) {
	f := newFakeVault(t, secretRoutes())
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	result := callTool(t, s, "get_secret", map[string]any{})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "name")
}

func TestGetSecret_MissingVersionHistoryIsNotFatal(t *testing.T) {
	routes := secretRoutes()
	delete(routes, "/api/v1/vaults/default/secrets/"+dbSecretUUID+"/versions")

	f := newFakeVault(t, routes)
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	var got getSecretResult
	structured(t, callTool(t, s, "get_secret", map[string]any{"name": "db-password"}), &got)
	require.Equal(t, "db-password", got.Name,
		"version history is supplementary; losing it must not lose the secret's metadata")
	require.Empty(t, got.Versions)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestGetSecret_ -v`
Expected: FAIL — `undefined: getSecretResult`, and `get_secret` is not registered.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/mcpserver/tools_secrets.go`:

```go
// getSecretArgs are the arguments to get_secret when values are withheld.
type getSecretArgs struct {
	Name  string `json:"name" jsonschema:"the secret's name, or its id"`
	Vault string `json:"vault,omitempty" jsonschema:"the vault to read from; defaults to the server's configured vault"`
}

// secretVersionResult is one entry of a secret's version history.
type secretVersionResult struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at,omitempty"`
	Enabled   bool   `json:"enabled"`
}

// getSecretResult is what get_secret returns, under either registration.
type getSecretResult struct {
	Vault       string                `json:"vault"`
	Name        string                `json:"name"`
	ID          string                `json:"id"`
	Version     int                   `json:"version"`
	Tags        []Untrusted           `json:"tags,omitempty"`
	ContentType string                `json:"content_type,omitempty"`
	Enabled     bool                  `json:"enabled"`
	ExpiresAt   string                `json:"expires_at,omitempty"`
	NotBefore   string                `json:"not_before,omitempty"`
	Versions    []secretVersionResult `json:"versions,omitempty"`

	// Value is present only when the server discloses values.
	Value string `json:"value,omitempty"`
	// ValueDisclosed says whether Value holds the real plaintext, so a
	// placeholder is never mistaken for the value itself.
	ValueDisclosed bool `json:"value_disclosed"`
}

// fetchSecret gathers a secret's metadata and version history.
//
// Version history is supplementary: if that call fails, the metadata is still
// worth returning rather than failing the whole tool.
func (s *Server) fetchSecret(ctx context.Context, vault, name string) (getSecretResult, *mcp.CallToolResult) {
	secret, err := s.client.GetSecret(ctx, vault, name)
	if err != nil {
		return getSecretResult{}, errorResult("could not get secret %q in vault %q: %s", name, vault, err)
	}

	result := getSecretResult{
		Vault:       vault,
		Name:        secret.Name,
		ID:          secret.ID.String(),
		Version:     secret.Version,
		Tags:        WrapAll(secret.Tags),
		ContentType: secret.ContentType,
		Enabled:     secret.Enabled,
	}
	if secret.ExpiresAt != nil {
		result.ExpiresAt = secret.ExpiresAt.Format(time.RFC3339)
	}
	if secret.NotBefore != nil {
		result.NotBefore = secret.NotBefore.Format(time.RFC3339)
	}

	if versions, err := s.client.GetSecretVersions(ctx, vault, name); err == nil {
		for _, version := range versions {
			result.Versions = append(result.Versions, secretVersionResult{
				Version:   version.Version,
				CreatedAt: version.CreatedAt,
				Enabled:   version.Enabled,
			})
		}
	}
	return result, nil
}

// handleGetSecret implements get_secret when values are withheld.
func (s *Server) handleGetSecret(ctx context.Context, _ *mcp.CallToolRequest, args getSecretArgs) (*mcp.CallToolResult, getSecretResult, error) {
	if args.Name == "" {
		return errorResult("get_secret requires a name"), getSecretResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), getSecretResult{}, nil
	}

	result, failure := s.fetchSecret(ctx, vault, args.Name)
	if failure != nil {
		return failure, getSecretResult{}, nil
	}
	// The value is deliberately never populated here.
	return nil, result, nil
}
```

Add `"time"` to the file's imports, and register the tool in `registerSecretsReadTools`:

```go
	registerIf(s, TierRead, "get_secret",
		"Get a secret's metadata, tags, expiry and version history. Does not return the secret value.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleGetSecret)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestGetSecret_ -v`
Expected: PASS — all eight tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_secrets.go internal/mcpserver/tools_secrets_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add the get_secret tool

Returns metadata, tags, expiry and version history. The server returns the
plaintext value on every get and offers no way to suppress it, so this tool
simply never populates the value field.

Version history is supplementary: if that call fails the metadata is still
returned, since losing the history should not lose the secret."
```

---

### Task 3: The conditional `include_value` schema

**Files:**
- Modify: `internal/mcpserver/tools_secrets.go`
- Modify: `internal/mcpserver/tools_secrets_test.go` (append)

**Interfaces:**
- Consumes: `s.MayDiscloseValues`, `s.discloseValue` (plan 12).
- Produces:
  - `type getSecretArgsWithValue struct { Name, Vault string; IncludeValue bool }`
  - `func (s *Server) handleGetSecretWithValue(...)`

**Why two argument types rather than one flag:** `mcp.AddTool` infers the input schema from the `In` type, so registering a different type produces a genuinely different advertised schema. With disclosure off, `include_value` is not a parameter the model can even name — the schema has no such property. That is stronger than accepting the argument and refusing it: there is nothing to refuse, and nothing for injected text to ask for.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/tools_secrets_test.go`:

```go
// getSecretSchema returns get_secret's advertised input schema as a map.
func getSecretSchema(t *testing.T, s *Server) map[string]any {
	t.Helper()

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "get_secret" {
			continue
		}
		encoded, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(encoded, &schema))
		return schema
	}
	t.Fatal("get_secret was not registered")
	return nil
}

func TestGetSecret_SchemaOmitsIncludeValueWhenDisclosureIsOff(t *testing.T) {
	f := newFakeVault(t, secretRoutes())
	s := f.server(t, testConfig())
	registerSecretsReadTools(s)

	schema := getSecretSchema(t, s)
	properties, ok := schema["properties"].(map[string]any)
	require.True(t, ok)

	_, present := properties["include_value"]
	require.False(t, present,
		"with disclosure off the parameter must not exist at all, so there is nothing to ask for")
	require.Contains(t, properties, "name")
}

func TestGetSecret_SchemaOffersIncludeValueWhenDisclosureIsOn(t *testing.T) {
	f := newFakeVault(t, secretRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	schema := getSecretSchema(t, s)
	properties, ok := schema["properties"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, properties, "include_value")
}

func TestGetSecret_ReturnsTheValueWhenAskedAndAllowed(t *testing.T) {
	f := newFakeVault(t, secretRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	var got getSecretResult
	structured(t, callTool(t, s, "get_secret", map[string]any{
		"name": "db-password", "include_value": true,
	}), &got)

	require.Equal(t, "hunter2-super-secret", got.Value)
	require.True(t, got.ValueDisclosed)
}

func TestGetSecret_WithholdsTheValueUnlessAsked(t *testing.T) {
	f := newFakeVault(t, secretRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	result := callTool(t, s, "get_secret", map[string]any{"name": "db-password"})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	require.NotContains(t, string(encoded), "hunter2-super-secret",
		"permitting disclosure is not the same as disclosing by default")
}

func TestGetSecret_ValueDisclosedIsFalseWhenWithheld(t *testing.T) {
	f := newFakeVault(t, secretRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	var got getSecretResult
	structured(t, callTool(t, s, "get_secret", map[string]any{"name": "db-password"}), &got)
	require.False(t, got.ValueDisclosed)
	require.Empty(t, got.Value)
}

func TestGetSecret_DescriptionMentionsValueBehaviour(t *testing.T) {
	f := newFakeVault(t, secretRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true
	s := f.server(t, cfg)
	registerSecretsReadTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "get_secret" {
			require.Contains(t, tool.Description, "include_value",
				"the description must tell the model how to ask, since the schema alone is terse")
			return
		}
	}
	t.Fatal("get_secret was not registered")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestGetSecret_Schema|TestGetSecret_Returns|TestGetSecret_Withholds|TestGetSecret_ValueDisclosed|TestGetSecret_Description' -v`
Expected: FAIL — the schema never contains `include_value`, since only one variant is registered.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/mcpserver/tools_secrets.go`:

```go
// getSecretArgsWithValue are get_secret's arguments when the server is
// configured to disclose values.
//
// This is a separate type rather than a flag on getSecretArgs because
// mcp.AddTool infers the input schema from the argument type. Registering
// this type means include_value is a property the model can see and name;
// registering the other means no such property exists at all. That is
// stronger than accepting the argument and refusing it — there is nothing to
// refuse, and nothing for injected text to ask for.
type getSecretArgsWithValue struct {
	Name         string `json:"name" jsonschema:"the secret's name, or its id"`
	Vault        string `json:"vault,omitempty" jsonschema:"the vault to read from; defaults to the server's configured vault"`
	IncludeValue bool   `json:"include_value,omitempty" jsonschema:"set true to return the secret's plaintext value"`
}

// handleGetSecretWithValue implements get_secret when disclosure is enabled.
func (s *Server) handleGetSecretWithValue(ctx context.Context, _ *mcp.CallToolRequest, args getSecretArgsWithValue) (*mcp.CallToolResult, getSecretResult, error) {
	if args.Name == "" {
		return errorResult("get_secret requires a name"), getSecretResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), getSecretResult{}, nil
	}

	result, failure := s.fetchSecret(ctx, vault, args.Name)
	if failure != nil {
		return failure, getSecretResult{}, nil
	}

	// Permitting disclosure is not the same as disclosing by default: the
	// caller still has to ask.
	if args.IncludeValue {
		secret, err := s.client.GetSecret(ctx, vault, args.Name)
		if err != nil {
			return errorResult("could not read the value of %q in vault %q: %s", args.Name, vault, err), getSecretResult{}, nil
		}
		value, disclosed := s.discloseValue(secret.Value)
		result.Value, result.ValueDisclosed = value, disclosed
	}
	return nil, result, nil
}
```

Replace the `get_secret` registration in `registerSecretsReadTools` with the conditional pair:

```go
	// The two variants advertise different schemas. With disclosure off,
	// include_value is not a property the model can name.
	if s.MayDiscloseValues() {
		registerIf(s, TierRead, "get_secret",
			"Get a secret's metadata, tags, expiry and version history. Pass include_value to also return its plaintext value.",
			Annotations{ReadOnly: true, Idempotent: true}, s.handleGetSecretWithValue)
	} else {
		registerIf(s, TierRead, "get_secret",
			"Get a secret's metadata, tags, expiry and version history. Does not return the secret value.",
			Annotations{ReadOnly: true, Idempotent: true}, s.handleGetSecret)
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/tools_secrets.go internal/mcpserver/tools_secrets_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): make include_value structurally absent unless enabled

get_secret registers one of two handlers with different argument types, and
AddTool infers the schema from the type. With disclosure off, include_value is
not a property the model can see or name -- stronger than accepting the
argument and refusing it, because there is nothing to refuse and nothing for
injected text to ask for.

Permitting disclosure is still not disclosing by default: the caller has to
ask, and value_disclosed reports what actually happened so a placeholder is
never mistaken for the value."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ -race -v
go vet ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

The schema property is the one that matters most here:

```bash
go test ./internal/mcpserver/ -run TestGetSecret_Schema -v
```

Confirm the egress point is still singular:

```bash
grep -rn "\.Reveal()" --include="*.go" internal/mcpserver/ | grep -v _test
```

Expected: exactly one hit, in `redact.go`.

## Notes for the next plan

Plans 14 and 15 copy this plan's shape. What carries over to every tool:

- `registerIf(s, TierRead, ...)` with the tier named.
- `s.ResolveVault(args.Vault)` first, returning `errorResult` on refusal.
- `s.effectiveLimit(args.Limit)` and `truncationNote` on every list.
- `WrapAll` on tags, `Wrap` on any single free-text field.
- Identifiers and names left unwrapped, so a model can pass them back.
- `errorResult` for every failure, never a returned Go error.

What does **not** carry over: the conditional-schema pattern. `get_secret` is
the only tool whose schema changes with configuration.
