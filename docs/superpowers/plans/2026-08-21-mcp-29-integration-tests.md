# Integration Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the MCP server against a **real RocketVault instance** — real handlers, real middleware, real authorization, real database — and prove the tool surface works end to end.

**Architecture:** A build-tagged suite that builds the binary, boots `rocketvault serve` against a scratch SQLite database on a free port, provisions an admin, and drives `internal/mcpserver` through the real protocol against it.

**Tech Stack:** Go 1.25, `os/exec`, `net`, `//go:build integration`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Testing strategy > Integration".

**Plan-of-plans:** This is plan 29 of 31. Requires the full surface (plans 13-28) committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **`//go:build integration`**, matching `internal/repositories/pg_integration_test.go`. A plain `go test ./...` must not run these.
- **Every run is hermetic**: a scratch directory, a scratch database, a generated config, a free port. Nothing touches the developer's real instance or `~/.rocketvault`.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## The blind spot this closes

The unit suite is thorough, but it shares one weakness: **every fake response was written by the same person who wrote the code that reads it.** If I misread a wrapper key, the fake has the same wrong key and the test passes.

That is not hypothetical here. This project's routes use three different list wrappers (`secrets`, `keys`, `certificates`), three more for deleted items (`deleted_secrets`, `deleted_keys`, `deleted_certificates`), a bare array for secret versions, a flat embedded shape for key versions, and string-typed timestamps on vaults alone. Each was read from source while writing the plans — but reading is exactly the step that can go wrong silently.

These tests are the check on that. They are worth their setup cost *because* the unit coverage is good: they catch the class of error good unit tests cannot.

## Why a real subprocess rather than an in-process router

`api.InitForTest` wires a minimal router with **no middleware and no auth** (`api/api.go:164`). Authorization is the property most worth testing here, so a harness that skips it would test the least interesting half.

Building the binary and running `serve` gets the real thing: `PolicyMiddleware`, real JWT validation, real role checks, real vault scoping. The cost is a build and a few seconds of startup per suite, paid once.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/integration_harness_test.go` (new) | Build, boot, provision, teardown |
| `internal/mcpserver/integration_test.go` (new) | Read, write and authorization flows |

---

### Task 1: The harness

**Files:**
- Create: `internal/mcpserver/integration_harness_test.go`

**Interfaces:**
- Consumes: the `rocketvault` binary, `vaultapi`, `mcpserver`.
- Produces — Tasks 2 and 3 use these:
  - `type liveVault struct { BaseURL, Token string }`
  - `func startLiveVault(t *testing.T) *liveVault`
  - `func (l *liveVault) mcpServer(t *testing.T, cfg config.MCPConfig) *Server`

**Four things the harness must get right, each of which makes tests flaky if it does not:**

1. **A free port**, obtained by binding `:0` and reading the result. A hardcoded port collides with the developer's own server, and the failure looks like an authorization error rather than a port clash.
2. **A generated config** with fresh `master_key` and `bootstrap_token`, in a scratch directory. Reusing the repo's `.rocketvault.yaml` would run tests against real data.
3. **A real readiness wait**, polling `/health` rather than sleeping. A fixed sleep is either slow or flaky, and usually both across machines.
4. **Guaranteed teardown**, including on panic, so a failed run does not leave a server holding a port.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/integration_harness_test.go`:

```go
//go:build integration

// The MCP integration suite runs the server against a real RocketVault
// instance -- real handlers, real middleware, real authorization, real
// database. Run with:
//
//	go test -tags=integration ./internal/mcpserver/...
//
// It builds the rocketvault binary and boots `serve` against a scratch
// SQLite database on a free port. A plain `go test ./...` skips this file.
//
// These tests exist to catch what the unit suite structurally cannot: every
// fake response there was written by the same person who wrote the code
// reading it, so a misread wrapper key or field name is invisible. Here the
// real server supplies the shapes.
package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

// liveVault is a running RocketVault instance for one test suite.
type liveVault struct {
	BaseURL string
	// Token is an admin session token, for provisioning fixtures.
	Token string
}

// freePort asks the OS for an unused port.
//
// A hardcoded port would collide with the developer's own server, and the
// resulting failure looks like an authorization error rather than a clash.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close() //nolint:errcheck

	return listener.Addr().(*net.TCPAddr).Port
}

// randomSecret generates a base64 key for the scratch config.
func randomSecret(t *testing.T) string {
	t.Helper()

	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(buf)
}

// buildBinary compiles rocketvault into dir and returns its path.
func buildBinary(t *testing.T, dir string) string {
	t.Helper()

	binary := filepath.Join(dir, "rocketvault")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = repoRoot(t)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "build rocketvault: %s", output)
	return binary
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root")
	return ""
}

// startLiveVault boots a RocketVault server and provisions an admin.
func startLiveVault(t *testing.T) *liveVault {
	t.Helper()

	dir := t.TempDir()
	binary := buildBinary(t, dir)
	port := freePort(t)

	configPath := filepath.Join(dir, ".rocketvault.yaml")
	bootstrapToken := randomSecret(t)
	writeScratchConfig(t, configPath, dir, port, bootstrapToken)

	// Start the server. Output goes to the test log, so a startup failure is
	// diagnosable rather than silent.
	serve := exec.Command(binary, "serve", "--config", configPath)
	serve.Dir = dir
	serve.Stdout = &testLogWriter{t: t, prefix: "serve out"}
	serve.Stderr = &testLogWriter{t: t, prefix: "serve err"}
	require.NoError(t, serve.Start())

	// Teardown runs even on panic, so a failed run never leaves a server
	// holding the port.
	t.Cleanup(func() {
		if serve.Process != nil {
			_ = serve.Process.Kill()
			_, _ = serve.Process.Wait()
		}
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForHealth(t, baseURL)

	// Provision an admin using the bootstrap token.
	admin := exec.Command(binary, "users", "admin",
		"--config", configPath,
		"--admin-username", "itadmin",
		"--admin-password", "Integration-Test-Pass-1",
		"--bootstrap-token", bootstrapToken)
	admin.Dir = dir
	output, err := admin.CombinedOutput()
	require.NoError(t, err, "create admin: %s", output)

	return &liveVault{BaseURL: baseURL, Token: loginToken(t, baseURL)}
}

// writeScratchConfig writes a minimal config for the scratch instance.
//
// It is generated per run rather than copied from the repo, so no test can
// touch real data or a real master key.
func writeScratchConfig(t *testing.T, path, dir string, port int, bootstrapToken string) {
	t.Helper()

	contents := fmt.Sprintf(`
master_key: %q
bootstrap_token: %q

server:
  listen_addr: ":%d"
  read_timeout: "30s"
  write_timeout: "30s"

database:
  type: "sqlite"
  path: %q

jwt:
  expiry: "15m"
  key_source: "file"
  key_path: %q

oidc:
  enabled: false

monitoring:
  enable_metrics: false
`,
		randomSecret(t), bootstrapToken, port,
		filepath.Join(dir, "test.db"),
		filepath.Join(dir, "jwt-signing.key"),
	)
	require.NoError(t, os.WriteFile(path, []byte(strings.TrimSpace(contents)), 0o600))
}

// waitForHealth polls until the server answers, rather than sleeping.
//
// A fixed sleep is either slow or flaky, and usually both across machines.
func waitForHealth(t *testing.T, baseURL string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/api/v1/health") //nolint:gosec,noctx
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < http.StatusInternalServerError {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become healthy within 30s", baseURL)
}

// loginToken authenticates as the provisioned admin and returns its token.
func loginToken(t *testing.T, baseURL string) string {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"username": "itadmin",
		"password": "Integration-Test-Pass-1",
	})
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/api/v1/users/login", //nolint:gosec,noctx
		"application/json", strings.NewReader(string(body)))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	require.Equal(t, http.StatusOK, resp.StatusCode, "admin login should succeed")

	var decoded struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	require.NotEmpty(t, decoded.Token)
	return decoded.Token
}

// staticLiveToken is a TokenSource returning the harness's admin token.
type staticLiveToken string

func (s staticLiveToken) Token(context.Context) (string, error) { return string(s), nil }

// mcpServer builds an MCP server pointed at this live instance.
func (l *liveVault) mcpServer(t *testing.T, cfg config.MCPConfig) *Server {
	t.Helper()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:    l.BaseURL,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		Tokens:     staticLiveToken(l.Token),
	})
	require.NoError(t, err)

	s, err := New(Deps{Client: client, Config: cfg, Logger: discardLogger(), Version: "integration"})
	require.NoError(t, err)
	RegisterAllTools(s)
	return s
}

// testLogWriter routes subprocess output into the test log.
type testLogWriter struct {
	t      *testing.T
	prefix string
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("[%s] %s", w.prefix, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func TestHarness_BootsAndAuthenticates(t *testing.T) {
	live := startLiveVault(t)

	require.NotEmpty(t, live.BaseURL)
	require.NotEmpty(t, live.Token, "the harness must produce a usable admin session")
}

func TestHarness_ServerAnswersHealth(t *testing.T) {
	live := startLiveVault(t)

	resp, err := http.Get(live.BaseURL + "/api/v1/health") //nolint:gosec,noctx
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Less(t, resp.StatusCode, http.StatusInternalServerError)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags=integration ./internal/mcpserver/ -run TestHarness_ -v`
Expected: the file does not exist yet, so this fails to build.

Once written, this is where the config shape gets validated. **The `database` and `jwt` blocks above are the likeliest thing to be wrong** — check them against `.rocketvault.yaml.example` and fix the harness to match. A server that fails to start will say why in the captured output.

- [ ] **Step 3: Write minimal implementation**

The harness itself is the implementation. If the server refuses to start, read the captured `serve err` lines and correct `writeScratchConfig` — do not work around it by pointing at the repo's real config.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -tags=integration ./internal/mcpserver/ -run TestHarness_ -v`
Expected: PASS — both tests, in under a minute including the build.

Confirm the tag actually excludes it from a normal run:

```bash
go test ./internal/mcpserver/ -run TestHarness_ -v
```
Expected: `no tests to run`.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/integration_harness_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "test(mcpserver): add the live-server integration harness

Builds the binary and boots serve against a scratch SQLite database on a free
port, then provisions an admin. Every run is hermetic: scratch directory,
scratch database, generated master key, nothing touching real data.

It runs a real subprocess rather than an in-process router because
api.InitForTest wires no middleware and no auth -- and authorization is the
property most worth testing here, so a harness that skipped it would test the
least interesting half.

A free port is requested from the OS rather than hardcoded, since a collision
with the developer's own server surfaces as an authorization error rather than
a port clash. Readiness is polled rather than slept on."
```

---

### Task 2: Read and write flows against real data

**Files:**
- Create: `internal/mcpserver/integration_test.go`

**Interfaces:**
- Consumes: the harness from Task 1.
- Produces: no code surface.

**These tests assert on shapes the fakes asserted on too.** That is the point: if a wrapper key was misread, the unit test and the fake agree and both are wrong, while this one fails.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/integration_test.go`:

```go
//go:build integration

package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

// liveConfig returns a config with every tier enabled, for exercising the
// full surface against a real server.
func liveConfig() config.MCPConfig {
	cfg := testConfig()
	cfg.AllowWrite = true
	cfg.AllowDestructive = true
	cfg.AllowCrypto = true
	cfg.AllowSecretValues = true
	cfg.ConfirmDestructive = true
	return cfg
}

// callLive invokes a tool and requires success, reporting the tool's own
// error text on failure.
func callLive(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	require.False(t, result.IsError, "%s failed: %s", name, renderContent(result))
	return result
}

func TestLive_ListVaultsSeesTheDefaultVault(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	var got listVaultsResult
	structured(t, callLive(t, cs, "list_vaults", map[string]any{}), &got)

	var names []string
	for _, vault := range got.Vaults {
		names = append(names, vault.Name)
	}
	require.Contains(t, names, "default",
		"every deployment ships a default vault")
}

func TestLive_SetThenGetSecretRoundTrips(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	var set setSecretResult
	structured(t, callLive(t, cs, "set_secret", map[string]any{
		"name": "integration-secret", "value": "integration-value",
	}), &set)
	require.True(t, set.Created)

	var got getSecretResult
	structured(t, callLive(t, cs, "get_secret", map[string]any{
		"name": "integration-secret", "include_value": true,
	}), &got)

	require.Equal(t, "integration-secret", got.Name)
	require.Equal(t, "integration-value", got.Value,
		"a real round trip through encryption, storage and decryption")
	require.True(t, got.ValueDisclosed)
}

func TestLive_SetSecretTwiceCreatesASecondVersion(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	var first setSecretResult
	structured(t, callLive(t, cs, "set_secret", map[string]any{
		"name": "versioned", "value": "v1",
	}), &first)
	require.True(t, first.Created)

	var second setSecretResult
	structured(t, callLive(t, cs, "set_secret", map[string]any{
		"name": "versioned", "value": "v2",
	}), &second)
	require.False(t, second.Created, "the second call is an update")
	require.Greater(t, second.Version, first.Version)
}

func TestLive_ListSecretsUsesTheRealWrapperKey(t *testing.T) {
	// This is the class of failure the unit suite cannot catch: if the
	// wrapper key were misread, the fake would carry the same wrong key and
	// both would agree.
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "listed", "value": "x"})

	var got listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{}), &got)

	require.NotEmpty(t, got.Secrets, "a decoded empty list would mean the wrapper key is wrong")
	require.Equal(t, "listed", got.Secrets[0].Name)
}

func TestLive_ListSecretsNeverCarriesValues(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "hidden", "value": "must-not-appear"})

	result := callLive(t, cs, "list_secrets", map[string]any{})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "must-not-appear",
		"the real list route omits values, and this proves it rather than assuming")
}

func TestLive_CreateAndGetKeyReturnsPublicComponents(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_key", map[string]any{
		"name": "integration-key", "type": "RSA", "bits": 2048,
	})

	var got getKeyResult
	structured(t, callLive(t, cs, "get_key", map[string]any{"name": "integration-key"}), &got)

	require.Equal(t, "RSA", got.Type)
	require.True(t, got.HasPublicComponents,
		"a software RSA key must expose n and e; empty components would mean the JWK path is broken")
	require.NotEmpty(t, got.PublicJWK.N)
	require.NotEmpty(t, got.PublicJWK.E)
}

func TestLive_GetKeyNeverReturnsPrivateMaterial(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_key", map[string]any{
		"name": "private-check", "type": "RSA", "bits": 2048,
	})

	result := callLive(t, cs, "get_key", map[string]any{"name": "private-check"})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)

	require.NotContains(t, string(encoded), "PRIVATE KEY")
	require.NotContains(t, string(encoded), "BEGIN RSA")
}

func TestLive_SignThenVerifyRoundTrips(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_key", map[string]any{
		"name": "sign-key", "type": "RSA", "bits": 2048,
	})

	data := base64.StdEncoding.EncodeToString([]byte("integration payload"))

	var signed signResult
	structured(t, callLive(t, cs, "sign", map[string]any{
		"key_name": "sign-key", "data_base64": data,
	}), &signed)
	require.NotEmpty(t, signed.SignatureBase64)

	var checked verifyResult
	structured(t, callLive(t, cs, "verify", map[string]any{
		"key_name": "sign-key", "data_base64": data,
		"signature_base64": signed.SignatureBase64,
		"algorithm":        signed.Algorithm,
	}), &checked)

	require.True(t, checked.Valid,
		"a signature this server produced must verify against it")
}

func TestLive_VerifyRejectsATamperedSignature(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_key", map[string]any{
		"name": "tamper-key", "type": "RSA", "bits": 2048,
	})

	data := base64.StdEncoding.EncodeToString([]byte("payload"))
	var signed signResult
	structured(t, callLive(t, cs, "sign", map[string]any{
		"key_name": "tamper-key", "data_base64": data,
	}), &signed)

	var checked verifyResult
	structured(t, callLive(t, cs, "verify", map[string]any{
		"key_name": "tamper-key",
		"data_base64": base64.StdEncoding.EncodeToString([]byte("different payload")),
		"signature_base64": signed.SignatureBase64,
		"algorithm":        signed.Algorithm,
	}), &checked)

	require.False(t, checked.Valid, "different data must not verify")
}

func TestLive_DeleteThenRecoverRestoresTheSecret(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "doomed", "value": "x"})

	callLive(t, cs, "delete_item", map[string]any{
		"type": "secrets", "name": "doomed", "confirm": "doomed",
	})

	var deleted listDeletedResult
	structured(t, callLive(t, cs, "list_deleted", map[string]any{"type": "secrets"}), &deleted)

	var names []string
	for _, item := range deleted.Items {
		names = append(names, item.Name)
	}
	require.Contains(t, names, "doomed",
		"the deleted listing is a different route with a different wrapper key")

	callLive(t, cs, "recover_deleted", map[string]any{"type": "secrets", "name": "doomed"})

	var listed listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{}), &listed)

	var liveNames []string
	for _, secret := range listed.Secrets {
		liveNames = append(liveNames, secret.Name)
	}
	require.Contains(t, liveNames, "doomed", "recovery must return it to the live listing")
}

func TestLive_UnconfirmedDeleteChangesNothing(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "survivor", "value": "x"})

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "delete_item", Arguments: map[string]any{"type": "secrets", "name": "survivor"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)

	var listed listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{}), &listed)

	var names []string
	for _, secret := range listed.Secrets {
		names = append(names, secret.Name)
	}
	require.Contains(t, names, "survivor",
		"a refused confirmation must leave the vault untouched")
}
```

Add `"encoding/base64"` and `"encoding/json"` to the imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags=integration ./internal/mcpserver/ -run TestLive_ -v`
Expected: the file is new, so it fails to build first. Once building, **any failure here is a real defect** — it means a plan misread the API.

Fix the reading code, not the test.

- [ ] **Step 3: Write minimal implementation**

None expected. If `TestLive_ListSecretsUsesTheRealWrapperKey` returns an empty list, a wrapper key is wrong in `vaultapi` — exactly the failure this suite exists to surface.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -tags=integration ./internal/mcpserver/ -v`
Expected: PASS — the harness plus eleven flow tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/integration_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "test(mcpserver): exercise the tool surface against a real server

Round-trips secrets, keys, signing, and delete-then-recover through real
handlers, real middleware and a real database.

These assert on shapes the unit tests also assert on, which is the point: if a
wrapper key was misread, the fake carries the same wrong key and both agree
while this one fails. The deleted-item listing is a particularly good check,
being a different route with a different wrapper key from the live one."
```

---

### Task 3: Authorization, and a CI job

**Files:**
- Modify: `internal/mcpserver/integration_test.go` (append)
- Modify: `.github/workflows/go.yml`

**Interfaces:**
- Consumes: the harness.
- Produces: an `mcp-integration` CI job.

**Authorization is the reason this suite runs a real server**, so it deserves explicit tests rather than being assumed from the flows above. A least-privileged principal must be genuinely refused by `PolicyMiddleware`, and the 403 hint must name a role that would actually help.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/integration_test.go`:

```go
func TestLive_AllowlistRefusesAnUnpermittedVault(t *testing.T) {
	live := startLiveVault(t)

	cfg := liveConfig()
	cfg.Vault = "default"
	cfg.AllowedVaults = []string{"default"}
	cs := connect(t, live.mcpServer(t, cfg))

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "list_secrets", Arguments: map[string]any{"vault": "some-other-vault"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "not permitted",
		"the guard refuses locally, before the server is even asked")
}

func TestLive_CreateVaultThenUseIt(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "create_vault", map[string]any{"name": "integration-vault"})

	callLive(t, cs, "set_secret", map[string]any{
		"name": "scoped", "value": "x", "vault": "integration-vault",
	})

	var listed listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{"vault": "integration-vault"}), &listed)
	require.Len(t, listed.Secrets, 1)

	// The default vault must not see it: vault scoping is a real boundary.
	var defaultListed listSecretsResult
	structured(t, callLive(t, cs, "list_secrets", map[string]any{"vault": "default"}), &defaultListed)

	for _, secret := range defaultListed.Secrets {
		require.NotEqual(t, "scoped", secret.Name,
			"a secret in one vault must not appear in another")
	}
}

func TestLive_GrantThenListRoleAssignment(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	var granted grantVaultRoleResult
	structured(t, callLive(t, cs, "grant_vault_role", map[string]any{
		"principal": "itadmin", "role": "Key Vault Secrets User",
	}), &granted)
	require.NotEmpty(t, granted.AssignmentID)

	var listed listRoleAssignmentsResult
	structured(t, callLive(t, cs, "list_role_assignments", map[string]any{}), &listed)

	var ids []string
	for _, assignment := range listed.Assignments {
		ids = append(ids, assignment.ID)
	}
	require.Contains(t, ids, granted.AssignmentID,
		"the id a grant returns must be the one a revoke can use")
}

func TestLive_ToolsListMatchesTheGatingTable(t *testing.T) {
	live := startLiveVault(t)

	// Default configuration against a real server: exactly the read tier.
	cs := connect(t, live.mcpServer(t, testConfig()))
	require.Len(t, toolNames(t, cs), 10)

	full := connect(t, live.mcpServer(t, liveConfig()))
	require.Len(t, toolNames(t, full), 27)
}

func TestLive_UnknownSecretGivesAnActionableError(t *testing.T) {
	live := startLiveVault(t)
	cs := connect(t, live.mcpServer(t, liveConfig()))

	callLive(t, cs, "set_secret", map[string]any{"name": "db-password", "value": "x"})

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "get_secret", Arguments: map[string]any{"name": "db-passwrd"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "did you mean",
		"near-miss suggestions must work against real data, not just fixtures")
	require.Contains(t, renderContent(result), "db-password")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -tags=integration ./internal/mcpserver/ -run TestLive_ -v`
Expected: the new tests fail to build until written; then they should pass.

If `TestLive_ToolsListMatchesTheGatingTable` disagrees with plan 28's table, one of the two is wrong — reconcile before proceeding, since both claim to describe the same thing.

- [ ] **Step 3: Write the CI job**

Add to `.github/workflows/go.yml`, after `mcp-gate`:

```yaml
  mcp-integration:
    name: MCP Integration
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      # Runs the MCP server against a real RocketVault instance. The unit
      # suite cannot catch a misread wrapper key or field name, because its
      # fakes were written by whoever wrote the code reading them -- both
      # would carry the same mistake and agree. This is the check on that.
      - name: MCP integration suite
        run: go test -tags=integration ./internal/mcpserver/ -v -timeout 10m
```

The 10-minute timeout accommodates the binary build plus a server boot per test. If that proves tight, the harness should be reworked to share one server across the suite rather than the timeout being raised — a suite slow enough to need more than ten minutes is one nobody will run locally.

- [ ] **Step 4: Run test to verify it passes**

```bash
go test -tags=integration ./internal/mcpserver/ -v -timeout 10m
go test ./... 2>&1 | tail -5
```

Expected: the integration suite passes, and the normal run is unaffected — the build tag keeps these out of it.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/integration_test.go .github/workflows/go.yml
git commit -S --gpg-sign=61D246B30285ED35 -m "test(mcpserver): cover authorization end to end, and wire up CI

Vault scoping is asserted as a real boundary: a secret written to one vault
must not appear in another. The allowlist guard is confirmed to refuse locally
before the server is asked, and a grant's returned assignment id is confirmed
to be the one a revoke could use.

The tools/list count is checked against a real server too, so plan 28's gating
table and reality cannot drift apart while both claim to describe the same
thing."
```

---

## Verification

```bash
go build ./...
go test ./... -race
go test -tags=integration ./internal/mcpserver/ -v -timeout 10m
```

Expected: everything passes, and the untagged run does not attempt the
integration suite.

Confirm hermeticity — this must pass with no RocketVault config or session
anywhere:

```bash
HOME=$(mktemp -d) go test -tags=integration ./internal/mcpserver/ -run TestLive_SetThenGet -v
```

If it fails under a fresh `HOME`, the harness is reaching something it should
not.

## Notes for the next plan

Plan 30 writes the operator runbook: least-privilege role recommendations per
use case, the threat-model summary, and the audit-attribution guidance.

**Three things it must carry, each recorded during earlier plans:**

- **`query_audit_log` requires a global admin principal**, which no per-vault
  grant provides. An operator running the recommended least-privilege service
  account will find that tool unusable, and should be told so rather than
  discovering it.
- **The confirmation guard is not a security boundary.** Plan 24 documented
  what it does and does not defend against; the runbook must use the same
  framing rather than implying it stops a determined attacker.
- **There is no CLI command to create a service account.** Plan 17 recorded
  this: the recommended production posture is reachable only through `curl`
  against the API.
