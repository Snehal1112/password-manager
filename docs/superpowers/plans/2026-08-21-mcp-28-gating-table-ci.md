# Gating Table and CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pin the exact tool set exposed by every capability-flag combination, sweep every tool's output for leaked plaintext, and wire both into CI.

**Architecture:** One table test enumerating all 16 flag combinations against the full 27-tool surface, plus a leak sweep that calls every registered tool and searches the serialized result for secret material in **both raw and base64 form**. A new CI job runs them alongside `scope-gate`.

**Tech Stack:** Go 1.25, `github.com/stretchr/testify`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Testing strategy".

**Plan-of-plans:** This is plan 28 of 31, opening Group I. Requires plans 13-15, 21-22, 24-25 and 27 committed — the whole tool surface.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **The table is exhaustive, not representative.** Sampling a few combinations would let exactly the mistake this exists to catch slip through.
- **Assertions are on the exact set**, not on membership. `require.Contains` would pass for a server exposing a destructive tool it should not.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Why this test exists

Every other test in this project checks one tool's behavior. This one checks a **global invariant**: that the configuration an operator wrote produces exactly the capability surface they expect.

That invariant is the one most likely to break silently. A future contributor adding a tool will register it somewhere in `RegisterAllTools`, and if they pass the wrong tier — or reach for `register` instead of `registerIf` — nothing else in the suite notices. The tool simply appears in a default-configured server, and the first person to find out is whoever is running it.

The table makes that a compile-visible failure: adding a tool without updating the expected sets fails immediately, which forces the tier decision to be made deliberately rather than by omission.

## Base64 is not redaction

The leak sweep searches for secret material in **two forms**: the raw string, and its base64 encoding.

This is not paranoia. Three crypto tools return base64 throughout, and `decrypt` returns base64 whenever the plaintext is not valid UTF-8. A sweep that searched only for `"hunter2-super-secret"` would pass cleanly while `aHVudGVyMi1zdXBlci1zZWNyZXQ=` sat in the payload — trivially decodable by anyone reading the transcript.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/gating_table_test.go` (new) | The exhaustive flag-combination table |
| `internal/mcpserver/leak_sweep_test.go` (new) | Every tool's output, both encodings |
| `.github/workflows/go.yml` (modify) | New `mcp-gate` job |

---

### Task 1: The exhaustive gating table

**Files:**
- Create: `internal/mcpserver/gating_table_test.go`

**Interfaces:**
- Consumes: `RegisterAllTools` (plan 16), `config.MCPConfig` (plan 09).
- Produces: no code surface. This is the test every future tool must satisfy.

**The expected sets are written out in full**, not computed. A computed expectation would derive from the same logic under test and pass regardless of whether that logic is right.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/gating_table_test.go`:

```go
package mcpserver

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

// The four tiers, written out in full rather than computed. A computed
// expectation would derive from the same logic under test and pass whether
// or not that logic is right.
var (
	readTools = []string{
		"get_certificate", "get_key", "get_secret",
		"list_certificates", "list_deleted", "list_keys",
		"list_role_assignments", "list_secrets", "list_vaults",
		"query_audit_log",
	}
	writeTools = []string{
		"create_certificate", "create_key", "create_vault",
		"grant_vault_role", "recover_deleted", "rotate_key",
		"set_certificate_policy", "set_key_rotation_policy", "set_secret",
	}
	destructiveTools = []string{
		"delete_item", "purge_item", "purge_vault", "revoke_vault_role",
	}
	// decrypt is absent here: it needs allow_secret_values as well.
	cryptoTools = []string{"encrypt", "sign", "verify"}
	// disclosureTools appear only when allow_secret_values is set, and
	// then only if their tier is enabled too.
	cryptoDisclosureTools = []string{"decrypt"}
)

// expectedTools assembles the set for a flag combination.
func expectedTools(write, destructive, crypto, values bool) []string {
	tools := append([]string{}, readTools...)
	if write {
		tools = append(tools, writeTools...)
	}
	if destructive {
		tools = append(tools, destructiveTools...)
	}
	if crypto {
		tools = append(tools, cryptoTools...)
		if values {
			tools = append(tools, cryptoDisclosureTools...)
		}
	}
	sort.Strings(tools)
	return tools
}

// configFor builds a config with the four flags set as given.
func configFor(write, destructive, crypto, values bool) config.MCPConfig {
	cfg := testConfig()
	cfg.AllowWrite = write
	cfg.AllowDestructive = destructive
	cfg.AllowCrypto = crypto
	cfg.AllowSecretValues = values
	return cfg
}

func TestGatingTable_EveryFlagCombination(t *testing.T) {
	// All 16 combinations. Exhaustive rather than representative: sampling
	// would let through exactly the mistake this exists to catch.
	for _, write := range []bool{false, true} {
		for _, destructive := range []bool{false, true} {
			for _, crypto := range []bool{false, true} {
				for _, values := range []bool{false, true} {
					name := combinationName(write, destructive, crypto, values)
					t.Run(name, func(t *testing.T) {
						f := newFakeVault(t, map[string]string{})
						s := f.server(t, configFor(write, destructive, crypto, values))
						RegisterAllTools(s)

						require.Equal(t, expectedTools(write, destructive, crypto, values),
							s.RegisteredTools(),
							"the exposed surface must match the configuration exactly")
					})
				}
			}
		}
	}
}

// combinationName renders a readable subtest name.
func combinationName(write, destructive, crypto, values bool) string {
	name := ""
	for _, part := range []struct {
		on    bool
		label string
	}{
		{write, "write"}, {destructive, "destructive"},
		{crypto, "crypto"}, {values, "values"},
	} {
		if part.on {
			if name != "" {
				name += "+"
			}
			name += part.label
		}
	}
	if name == "" {
		return "default"
	}
	return name
}

func TestGatingTable_CountsMatchTheDocumentedSurface(t *testing.T) {
	cases := []struct {
		write, destructive, crypto, values bool
		want                               int
	}{
		{false, false, false, false, 10},
		{true, false, false, false, 19},
		{true, true, false, false, 23},
		{true, true, true, false, 26},
		{true, true, true, true, 27},
	}

	for _, tc := range cases {
		t.Run(combinationName(tc.write, tc.destructive, tc.crypto, tc.values), func(t *testing.T) {
			f := newFakeVault(t, map[string]string{})
			s := f.server(t, configFor(tc.write, tc.destructive, tc.crypto, tc.values))
			RegisterAllTools(s)

			require.Len(t, s.RegisteredTools(), tc.want,
				"docs/mcp-server.md and the --check output quote these numbers")
		})
	}
}

func TestGatingTable_DecryptNeedsBothCryptoAndValues(t *testing.T) {
	cases := []struct {
		crypto, values bool
		want           bool
	}{
		{false, false, false},
		{true, false, false},
		{false, true, false},
		{true, true, true},
	}

	for _, tc := range cases {
		f := newFakeVault(t, map[string]string{})
		s := f.server(t, configFor(false, false, tc.crypto, tc.values))
		RegisterAllTools(s)

		present := contains(s.RegisteredTools(), "decrypt")
		require.Equal(t, tc.want, present,
			"decrypt returns plaintext, so allow_crypto alone must not expose it (crypto=%v values=%v)",
			tc.crypto, tc.values)
	}
}

func TestGatingTable_NoDestructiveToolUnderWriteAlone(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, configFor(true, false, false, false))
	RegisterAllTools(s)

	for _, name := range destructiveTools {
		require.False(t, contains(s.RegisteredTools(), name),
			"allow_write must never expose %q", name)
	}
}

func TestGatingTable_RecoverIsAWriteToolNotADestructiveOne(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	writeOnly := f.server(t, configFor(true, false, false, false))
	RegisterAllTools(writeOnly)
	require.True(t, contains(writeOnly.RegisteredTools(), "recover_deleted"),
		"an operator who can write must be able to undo a deletion")

	destructiveOnly := f.server(t, configFor(false, true, false, false))
	RegisterAllTools(destructiveOnly)
	require.False(t, contains(destructiveOnly.RegisteredTools(), "recover_deleted"),
		"recovery is additive and does not belong to the destructive tier")
}

func TestGatingTable_EveryToolIsAccountedFor(t *testing.T) {
	// The union of the tier lists must equal the fully-enabled surface. This
	// is what fails when a tool is added without a tier decision.
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, configFor(true, true, true, true))
	RegisterAllTools(s)

	all := append([]string{}, readTools...)
	all = append(all, writeTools...)
	all = append(all, destructiveTools...)
	all = append(all, cryptoTools...)
	all = append(all, cryptoDisclosureTools...)
	sort.Strings(all)

	require.Equal(t, all, s.RegisteredTools(),
		"a tool missing from the tier lists above has no deliberate tier assignment")
}

func TestGatingTable_ReadToolsAreAlwaysPresent(t *testing.T) {
	for _, write := range []bool{false, true} {
		for _, destructive := range []bool{false, true} {
			f := newFakeVault(t, map[string]string{})
			s := f.server(t, configFor(write, destructive, false, false))
			RegisterAllTools(s)

			for _, name := range readTools {
				require.True(t, contains(s.RegisteredTools(), name),
					"read tools are unconditional; %q was missing", name)
			}
		}
	}
}

func TestGatingTable_MatchesWhatTheProtocolExposes(t *testing.T) {
	// RegisteredTools is bookkeeping; tools/list is what a host actually
	// sees. They must agree, or --check would report a surface that is not
	// the real one.
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, configFor(true, true, true, true))
	RegisterAllTools(s)

	cs := connect(t, s)
	require.Equal(t, s.RegisteredTools(), toolNames(t, cs))
}

// contains reports whether values includes target.
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

var _ = context.Background
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestGatingTable_ -v`
Expected: PASS if plans 13-27 landed correctly. **A failure here is a real defect**, not a test to adjust — it means a tool is registered under the wrong tier, or `RegisterAllTools` is missing a call.

Before treating any failure as expected, check which combination failed and which tool is misplaced.

- [ ] **Step 3: Write minimal implementation**

None expected. If a combination fails, fix the registration in the relevant `tools_*.go`, not the table.

The one legitimate reason to edit this file is adding a new tool: put it in the tier list it belongs to, having decided that deliberately.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestGatingTable_ -race -v`
Expected: PASS — 16 subtests plus the seven property tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/gating_table_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "test(mcpserver): pin the exact tool surface for every flag combination

Every other test checks one tool's behavior; this checks a global invariant --
that the configuration an operator wrote produces exactly the capability
surface they expect.

That invariant breaks silently. A contributor adding a tool with the wrong
tier, or reaching for register instead of registerIf, gets a tool that appears
in a default-configured server with nothing else noticing. The table makes
that an immediate failure, forcing the tier decision to be deliberate rather
than made by omission.

All 16 combinations, asserted on the exact set rather than membership: a
Contains check would pass for a server exposing a destructive tool it should
not."
```

---

### Task 2: The leak sweep

**Files:**
- Create: `internal/mcpserver/leak_sweep_test.go`

**Interfaces:**
- Consumes: the whole tool surface, `fakeVault`.
- Produces: no code surface.

**This sweep calls every registered tool** against a fake vault whose every response contains a marker secret, then searches the full serialized result for that secret in raw and base64 form. It is deliberately blunt: it does not know which fields should carry values, only that none should carry this one.

The blunt approach is the point. A targeted assertion checks the field its author thought of; this catches the field they did not.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/leak_sweep_test.go`:

```go
package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// leakMarker appears in every field of every fake response. No tool output
// may contain it while allow_secret_values is off.
const leakMarker = "LEAKMARKER-hunter2-super-secret"

// leakRoutes returns responses that stuff the marker into every value-ish
// field the API could plausibly return.
func leakRoutes() map[string]string {
	encoded := base64.StdEncoding.EncodeToString([]byte(leakMarker))
	return map[string]string{
		"/api/v1/vaults": `{"vaults":[{"id":"` + prodVaultID + `","name":"default",
			"tags":{"note":"` + leakMarker + `"}}],"total":1}`,

		"/api/v1/vaults/default/secrets": `{"secrets":[{"id":"` + dbSecretUUID + `",
			"name":"db-password","value":"` + leakMarker + `","tags":["` + leakMarker + `"]}],"total":1}`,

		"/api/v1/vaults/default/secrets/" + dbSecretUUID: `{"id":"` + dbSecretUUID + `",
			"name":"db-password","value":"` + leakMarker + `","tags":["` + leakMarker + `"],
			"content_type":"` + leakMarker + `"}`,

		"/api/v1/vaults/default/secrets/" + dbSecretUUID + "/versions": `[{"version":1,
			"value":"` + leakMarker + `"}]`,

		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"signing-key",
			"type":"RSA","value":"` + leakMarker + `","tags":["` + leakMarker + `"]}]}`,

		"/api/v1/vaults/default/keys/" + signKeyUUID: `{"id":"` + signKeyUUID + `",
			"name":"signing-key","type":"RSA","value":"` + leakMarker + `"}`,

		"/api/v1/vaults/default/certificates": `{"certificates":[{"id":"` + tlsCertUUID + `",
			"name":"tls-cert","private_key":"` + leakMarker + `","tags":["` + leakMarker + `"]}]}`,

		"/api/v1/vaults/default/certificates/" + tlsCertUUID: `{"id":"` + tlsCertUUID + `",
			"name":"tls-cert","private_key":"` + leakMarker + `"}`,

		"/api/v1/vaults/default/deleted/secrets": `{"deleted_secrets":[{"id":"` + dbSecretUUID + `",
			"name":"old","value":"` + leakMarker + `"}],"total":1}`,

		"/api/v1/vaults/default/role-assignments": `{"role_assignments":[{"id":"` + assignmentID + `",
			"principal_username":"` + leakMarker + `","role":"Key Vault Reader"}],"total":1}`,

		"/api/v1/audit/logs": `{"logs":[{"id":"1","action":"secret.read",
			"details":"` + leakMarker + `"}],"total":1,"integrity_ok":true}`,

		// Crypto responses carry the marker base64-encoded, which is how a
		// leak would actually look on these routes.
		"__write__": `{"key_id":"` + signKeyUUID + `","value":"` + encoded + `","status":"OK"}`,
	}
}

// sweepArgs supplies plausible arguments per tool, so each one runs rather
// than failing validation before it can leak.
func sweepArgs(name string) map[string]any {
	base := map[string]any{}
	switch name {
	case "get_secret", "get_key", "get_certificate":
		base["name"] = "db-password"
	case "list_deleted":
		base["type"] = "secrets"
	case "query_audit_log", "list_secrets", "list_keys", "list_certificates",
		"list_vaults", "list_role_assignments":
		// No arguments needed.
	}
	if name == "get_key" {
		base["name"] = "signing-key"
	}
	if name == "get_certificate" {
		base["name"] = "tls-cert"
	}
	return base
}

func TestLeakSweep_NoReadToolLeaksSecretMaterial(t *testing.T) {
	f := newFakeVault(t, leakRoutes())
	f.writeResponse = leakRoutes()["__write__"]

	// Disclosure off: no tool may return the marker in any form.
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	cs := connect(t, s)
	encoded := base64.StdEncoding.EncodeToString([]byte(leakMarker))

	for _, name := range s.RegisteredTools() {
		t.Run(name, func(t *testing.T) {
			result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
				Name: name, Arguments: sweepArgs(name),
			})
			require.NoError(t, err)

			serialized, err := json.Marshal(result)
			require.NoError(t, err)

			require.NotContains(t, string(serialized), leakMarker,
				"%s leaked secret material in plain form", name)
			require.NotContains(t, string(serialized), encoded,
				"%s leaked secret material base64-encoded -- base64 is an encoding, not protection", name)
		})
	}
}

func TestLeakSweep_CoversEveryReadTool(t *testing.T) {
	f := newFakeVault(t, leakRoutes())
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	require.Len(t, s.RegisteredTools(), 10,
		"the sweep must cover the whole default surface, not a subset")
}

func TestLeakSweep_MarkerWouldBeDetectedIfPresent(t *testing.T) {
	// A sweep that cannot fail proves nothing. Confirm the assertion catches
	// the marker when it genuinely is present.
	f := newFakeVault(t, leakRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true
	s := f.server(t, cfg)
	RegisterAllTools(s)

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "get_secret", Arguments: map[string]any{"name": "db-password", "include_value": true},
	})
	require.NoError(t, err)

	serialized, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(serialized), leakMarker,
		"with disclosure explicitly enabled and requested, the value should appear -- "+
			"otherwise the sweep above is vacuous")
}

func TestLeakSweep_UntrustedTextIsMarkedNotStripped(t *testing.T) {
	f := newFakeVault(t, leakRoutes())
	s := f.server(t, testConfig())
	RegisterAllTools(s)

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "query_audit_log", Arguments: map[string]any{},
	})
	require.NoError(t, err)

	serialized, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(serialized), "UNTRUSTED-VAULT-DATA",
		"audit details are vault-resident free text and must be marked")
}

func TestLeakSweep_LogsCarryNoSecretMaterial(t *testing.T) {
	var logs strings.Builder
	f := newFakeVault(t, leakRoutes())

	cfg := testConfig()
	cfg.AllowSecretValues = true // Even with disclosure on, logs stay clean.
	s := f.serverWithLogger(t, cfg, &logs)
	RegisterAllTools(s)

	cs := connect(t, s)
	for _, name := range []string{"list_secrets", "get_secret"} {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: name, Arguments: sweepArgs(name),
		})
		require.NoError(t, err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(leakMarker))
	require.NotContains(t, logs.String(), leakMarker)
	require.NotContains(t, logs.String(), encoded,
		"a value disclosed to the model must still never reach a log line")
}
```

This needs one addition to `vaultfake_test.go`:

```go
// serverWithLogger is server() with diagnostics captured, for tests that
// assert on log output.
func (f *fakeVault) serverWithLogger(t *testing.T, cfg config.MCPConfig, out io.Writer) *Server {
	t.Helper()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:      f.srv.URL,
		HTTPClient:   f.srv.Client(),
		Tokens:       staticTestToken("test-token"),
		DisableRetry: true,
	})
	require.NoError(t, err)

	logger := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := New(Deps{Client: client, Config: cfg, Logger: logger, Version: "test"})
	require.NoError(t, err)
	return s
}
```

Add `"io"` and `"log/slog"` to that file's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestLeakSweep_ -v`
Expected: `undefined: serverWithLogger` until the helper is added. After that, PASS — **a leak failure is a real defect**, not a test to relax.

`TestLeakSweep_MarkerWouldBeDetectedIfPresent` is the control: if it fails, the sweep is not actually capable of detecting a leak and every other assertion in the file is worthless.

- [ ] **Step 3: Write minimal implementation**

Only the `serverWithLogger` helper. If a tool genuinely leaks, fix the tool.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/leak_sweep_test.go internal/mcpserver/vaultfake_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "test(mcpserver): sweep every tool's output for leaked secret material

Calls every registered tool against a vault whose every response carries a
marker, then searches the full serialized result. Deliberately blunt: it does
not know which fields should carry values, only that none should carry this
one. A targeted assertion checks the field its author thought of; this catches
the field they did not.

It searches for the marker raw AND base64-encoded. Three crypto tools return
base64 throughout and decrypt does so for binary plaintext, so a raw-only
sweep would pass while an encoded secret sat in the payload -- base64 is an
encoding, not protection.

A control test confirms the sweep can actually detect a leak when one is
present, since a sweep that cannot fail proves nothing."
```

---

### Task 3: The CI job

**Files:**
- Modify: `.github/workflows/go.yml`

**Interfaces:**
- Consumes: the tests from Tasks 1 and 2.
- Produces: an `mcp-gate` job.

**Why a separate job rather than relying on `Build & Test`:** the existing job runs the whole suite, so these tests do run there. A dedicated job makes a gating or leak failure **legible on the PR** — the check name says which invariant broke, instead of one failure among hundreds in a general test run. `scope-gate` exists for the same reason and is the precedent.

The job also runs under `-race`, which the spec requires for this package specifically.

- [ ] **Step 1: Write the failing test**

There is no unit test for a workflow file. The check is that the job runs and fails when it should:

- [ ] The job appears in the workflow and is named clearly.
- [ ] It runs the gating table and leak sweep under `-race`.
- [ ] Temporarily breaking a tier assignment makes it fail.

- [ ] **Step 2: Verify the gap**

```bash
grep -c "mcp-gate" .github/workflows/go.yml || echo "absent"
```
Expected: `absent`.

- [ ] **Step 3: Write the job**

Add to `.github/workflows/go.yml`, after the `scope-gate` job:

```yaml
  mcp-gate:
    name: MCP Capability Gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      # The exposed tool surface must match the configuration exactly, for
      # every flag combination. This is the invariant that breaks silently
      # when a tool is added under the wrong tier: nothing else in the suite
      # notices, and the first person to find out is whoever runs the server.
      - name: Capability gating table
        run: go test ./internal/mcpserver/ -run TestGatingTable_ -race -v

      # No tool may return secret material while allow_secret_values is off,
      # in raw or base64 form.
      - name: Secret-material leak sweep
        run: go test ./internal/mcpserver/ -run TestLeakSweep_ -race -v

      # register() sets the MCP annotations that let a host prompt before a
      # destructive call. A tool added through mcp.AddTool directly would
      # bypass that, along with the deadline, rate limit and correlation id.
      - name: No direct mcp.AddTool calls outside register
        run: |
          if grep -rn "mcp\.AddTool(" --include="*.go" internal/mcpserver/ \
              | grep -v "_test.go" \
              | grep -v "server.go"; then
            echo "mcp.AddTool must only be called from register() in server.go."
            echo "Direct calls lose the deadline, panic recovery, correlation id,"
            echo "rate limit and destructive annotations all at once."
            exit 1
          fi

      # discloseValue is the single egress point for secret values.
      - name: Only redact.go reveals secret values
        run: |
          if grep -rn "\.Reveal()" --include="*.go" internal/mcpserver/ \
              | grep -v "_test.go" \
              | grep -v "redact.go" \
              | grep -v "tools_crypto.go"; then
            echo "SecretValue.Reveal() may only be called from redact.go, and from"
            echo "tools_crypto.go's decrypt handler, which is gated on both"
            echo "allow_crypto and allow_secret_values."
            exit 1
          fi
```

The two `grep` gates are the same shape as `scope-gate`'s existing checks. They are cheap and they catch the two mistakes that would silently undo the design: registering a tool outside `register`, and revealing a value outside the egress point.

Note the `tools_crypto.go` exception on the second gate. That is a real, deliberate second call site — `decrypt` reveals its plaintext — and it is safe only because the tool is not registered unless both flags are set. The exception is narrow and named rather than the gate being dropped.

- [ ] **Step 4: Verify the job**

Locally, run what CI will run:

```bash
go test ./internal/mcpserver/ -run TestGatingTable_ -race -v
go test ./internal/mcpserver/ -run TestLeakSweep_ -race -v
grep -rn "mcp\.AddTool(" --include="*.go" internal/mcpserver/ | grep -v "_test.go" | grep -v "server.go"
grep -rn "\.Reveal()" --include="*.go" internal/mcpserver/ | grep -v "_test.go" | grep -v "redact.go" | grep -v "tools_crypto.go"
```

Expected: both tests pass; both greps return nothing.

Then confirm the gate actually bites. Temporarily change one `registerIf(s, TierDestructive, "purge_vault", …)` to `TierWrite`, re-run the table test, and check it fails naming the combination. **Revert the change.**

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/go.yml
git commit -S --gpg-sign=61D246B30285ED35 -m "ci: add the MCP capability gate

The suite already runs these tests, but a dedicated job makes a gating or leak
failure legible on the PR -- the check name says which invariant broke rather
than burying it among hundreds of results. scope-gate exists for the same
reason.

Two grep gates catch the mistakes that would silently undo the design:
registering a tool outside register(), which loses the deadline, recovery,
correlation id, rate limit and destructive annotations at once; and revealing
a secret value outside the single egress point. The decrypt handler is a
named exception on the second, safe because that tool is not registered unless
both allow_crypto and allow_secret_values are set."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ -race -v
go vet ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

The two gates, run as CI runs them:

```bash
go test ./internal/mcpserver/ -run 'TestGatingTable_|TestLeakSweep_' -race -v
```

And a deliberate break, to prove the table is load-bearing:

1. Change `purge_vault`'s tier to `TierWrite`.
2. `go test ./internal/mcpserver/ -run TestGatingTable_` — must fail, naming the `write` combination.
3. Revert.

If step 2 passes, the table is not testing what it claims and must be fixed
before this plan is considered done.

## Notes for the next plan

Plan 29 adds integration tests against a real server via `testcontainers`,
which is the first time any of this runs against actual RocketVault rather
than a fake.

The unit suite is comprehensive but shares one blind spot: **every fake
response was written by the same person who wrote the code reading it.** A
wrong assumption about a wrapper key or field name is invisible to it. Plan 29
is what catches that class of error, and it is the reason the integration
tests are worth their setup cost despite the unit coverage.
