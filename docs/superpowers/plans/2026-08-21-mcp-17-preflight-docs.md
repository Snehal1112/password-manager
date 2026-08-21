# `--check` Preflight and Install Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `runMCPCheck` stub with a real preflight that validates configuration, connectivity and authentication and prints exactly what would be exposed — then document how to install the server in Claude Code and Claude Desktop.

**Architecture:** `--check` reuses the same `buildMCPServer` path the real run uses, so it validates the actual configuration rather than a parallel approximation of it. It then makes one live API call to prove the credentials work, and prints a report.

**Tech Stack:** Go 1.25, `github.com/spf13/cobra`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — sections "Production hardening > Preflight" and "> Audit attributability".

**Plan-of-plans:** This is plan 17 of 31, completing Group E. Requires plan 16 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **`--check` prints its report to stdout and exits.** This is the one time stdout is not the protocol channel, because no session is being served — but the code must make that distinction explicit rather than incidental.
- **A failing check exits non-zero**, so it is usable in a script.
- Documentation goes in `docs/`, per the project's convention for user-facing guides.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Why this exists

Without a preflight, a misconfigured server fails inside Claude Code as an opaque handshake error. The host reports that the server did not start; it does not report *why*, because the failure happened before any protocol exchange. Debugging that means guessing.

`--check` turns that into a message. It answers the four questions that actually go wrong: which server am I talking to, who am I acting as, does that credential work, and what would I expose.

## File structure

| File | Responsibility |
|---|---|
| `cmd/mcp_check.go` (new) | `runMCPCheck` and its report |
| `cmd/mcp_check_test.go` (new) | Report contents, exit behavior, secret safety |
| `docs/mcp-server.md` (new) | Install and configuration guide |

---

### Task 1: The preflight report

**Files:**
- Create: `cmd/mcp_check.go`
- Create: `cmd/mcp_check_test.go`
- Modify: `cmd/mcp.go` (delete the `runMCPCheck` stub)

**Interfaces:**
- Consumes: `buildMCPServer`, `mcpserver.Server.RegisteredTools` (plan 16); `vaultapi.Client.ListVaults` (plan 07).
- Produces:
  - `func runMCPCheck(cmd *cobra.Command, server *mcpserver.Server, identity string) error`
  - `func writeMCPCheckReport(w io.Writer, report mcpCheckReport)`
  - `type mcpCheckReport struct { ... }`

**Why the connectivity probe is `ListVaults`:** it is the one read every identity can attempt, it needs no arguments, and its failure modes are exactly the ones worth distinguishing — unreachable server, bad credentials, or a principal with no grants. A probe that needed a vault name would fail for an uninteresting reason on a fresh install.

**The audit-attribution warning:** when the identity is a cached session, the report says so plainly. Under a session the agent acts as the operator, and its actions are indistinguishable from theirs in the audit log — that is a fact worth stating at the moment someone is setting the thing up, not buried in a document.

- [ ] **Step 1: Write the failing test**

Create `cmd/mcp_check_test.go`:

```go
package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteMCPCheckReport_ListsTheEssentials(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		BaseURL:     "https://vault.example.com",
		Identity:    `service account "mcp-agent"`,
		Vault:       "prod",
		Reachable:   true,
		VaultCount:  3,
		Tools:       []string{"list_secrets", "get_secret"},
		Tiers:       []string{"read"},
		MaxResults:  50,
		ValuesShown: false,
	})

	rendered := out.String()
	require.Contains(t, rendered, "https://vault.example.com")
	require.Contains(t, rendered, "mcp-agent")
	require.Contains(t, rendered, "prod")
	require.Contains(t, rendered, "list_secrets")
	require.Contains(t, rendered, "get_secret")
}

func TestWriteMCPCheckReport_StatesTheToolCount(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Tools: []string{"a", "b", "c"},
		Tiers: []string{"read"},
	})

	require.Contains(t, out.String(), "3",
		"the count is what an operator checks against their expectation")
}

func TestWriteMCPCheckReport_SaysWhenValuesAreWithheld(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{Tools: []string{"a"}, ValuesShown: false})

	rendered := strings.ToLower(out.String())
	require.Contains(t, rendered, "secret values")
	require.Contains(t, rendered, "not")
}

func TestWriteMCPCheckReport_SaysWhenValuesAreExposed(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{Tools: []string{"a"}, ValuesShown: true})

	require.Contains(t, strings.ToLower(out.String()), "secret values can be returned",
		"enabling disclosure is worth stating plainly, not implying")
}

func TestWriteMCPCheckReport_WarnsWhenActingAsASession(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Identity:    `cached session for "admin"`,
		IsSession:   true,
		Tools:       []string{"a"},
	})

	rendered := out.String()
	require.Contains(t, rendered, "audit log",
		"under a session the agent's actions are indistinguishable from the operator's")
	require.Contains(t, rendered, "require_service_account")
}

func TestWriteMCPCheckReport_NoWarningForAServiceAccount(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Identity:  `service account "mcp-agent"`,
		IsSession: false,
		Tools:     []string{"a"},
	})

	require.NotContains(t, out.String(), "require_service_account")
}

func TestWriteMCPCheckReport_ReportsUnreachability(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		BaseURL:   "https://vault.example.com",
		Reachable: false,
		Failure:   "connection refused",
		Tools:     []string{"a"},
	})

	rendered := out.String()
	require.Contains(t, rendered, "connection refused")
	require.Contains(t, strings.ToUpper(rendered), "FAIL")
}

func TestWriteMCPCheckReport_NeverIncludesASecret(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Identity: `service account "mcp-agent"`,
		Tools:    []string{"a"},
	})

	require.NotContains(t, out.String(), "client_secret")
	require.NotContains(t, out.String(), "ROCKETVAULT_MCP_CLIENT_SECRET=")
}

func TestWriteMCPCheckReport_ListsEnabledTiers(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Tools: []string{"a"},
		Tiers: []string{"read", "write"},
	})

	rendered := out.String()
	require.Contains(t, rendered, "read")
	require.Contains(t, rendered, "write")
}

func TestWriteMCPCheckReport_ToolsAreListedOnePerLine(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{Tools: []string{"alpha", "beta", "gamma"}})

	for _, name := range []string{"alpha", "beta", "gamma"} {
		require.Contains(t, out.String(), name)
	}
	require.GreaterOrEqual(t, strings.Count(out.String(), "\n"), 3,
		"a scannable list beats a comma-joined blob")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestWriteMCPCheckReport_ -v`
Expected: FAIL — `undefined: writeMCPCheckReport`, `undefined: mcpCheckReport`.

- [ ] **Step 3: Write minimal implementation**

Create `cmd/mcp_check.go` with the MIT header, then:

```go
package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/internal/mcpserver"
)

// mcpCheckReport is what --check prints.
type mcpCheckReport struct {
	BaseURL  string
	Identity string
	// IsSession reports that the identity is a cached CLI session rather
	// than a service account.
	IsSession bool
	Vault     string

	// Reachable and Failure record the live connectivity probe.
	Reachable  bool
	VaultCount int
	Failure    string

	Tools       []string
	Tiers       []string
	MaxResults  int
	ValuesShown bool
}

// writeMCPCheckReport renders the report.
//
// Tools are listed one per line rather than comma-joined: an operator is
// checking this against an expectation, and a scannable list makes a missing
// or unexpected entry obvious.
func writeMCPCheckReport(w io.Writer, report mcpCheckReport) {
	fmt.Fprintf(w, "RocketVault MCP server preflight\n\n")

	fmt.Fprintf(w, "  Server:    %s\n", report.BaseURL)
	fmt.Fprintf(w, "  Identity:  %s\n", report.Identity)
	fmt.Fprintf(w, "  Vault:     %s\n", report.Vault)

	if report.Reachable {
		fmt.Fprintf(w, "  Reachable: yes (%d vault(s) visible)\n", report.VaultCount)
	} else {
		fmt.Fprintf(w, "  Reachable: FAIL - %s\n", report.Failure)
	}

	fmt.Fprintf(w, "\n  Enabled tiers: %s\n", strings.Join(report.Tiers, ", "))
	fmt.Fprintf(w, "  Max results per list: %d\n", report.MaxResults)

	if report.ValuesShown {
		fmt.Fprintf(w, "  Secret values CAN be returned to the model (allow_secret_values is on).\n")
	} else {
		fmt.Fprintf(w, "  Secret values are not returned to the model.\n")
	}

	// Under a session the agent acts as the operator, so its actions are
	// indistinguishable from theirs in the audit log. That is worth saying at
	// setup time rather than leaving in a document.
	if report.IsSession {
		fmt.Fprintf(w, "\n  Note: this server acts as your own logged-in user, so its actions\n")
		fmt.Fprintf(w, "  are indistinguishable from yours in the audit log. For anything\n")
		fmt.Fprintf(w, "  beyond local use, configure a service account and set\n")
		fmt.Fprintf(w, "  mcp.require_service_account.\n")
	}

	fmt.Fprintf(w, "\n  Exposed tools (%d):\n", len(report.Tools))
	for _, name := range report.Tools {
		fmt.Fprintf(w, "    %s\n", name)
	}
}

// runMCPCheck validates the configuration and prints what would be exposed.
//
// It reuses the server built by the normal startup path, so it checks the
// real configuration rather than a parallel approximation that could drift.
//
// The report goes to stdout. That is safe only because --check serves no
// session: no protocol stream exists to corrupt.
func runMCPCheck(cmd *cobra.Command, server *mcpserver.Server, identity string) error {
	cfg, err := loadMCPConfigForCheck()
	if err != nil {
		return err
	}

	report := mcpCheckReport{
		BaseURL:     server.BaseURL(),
		Identity:    identity,
		IsSession:   strings.HasPrefix(identity, "cached session"),
		Vault:       cfg.Vault,
		Tools:       server.RegisteredTools(),
		Tiers:       server.EnabledTiers(),
		MaxResults:  cfg.MaxResults,
		ValuesShown: cfg.AllowSecretValues,
	}

	// One live call proves the credentials work. ListVaults is the right
	// probe: every identity may attempt it, it needs no arguments, and its
	// failures are the ones worth telling apart -- unreachable server, bad
	// credentials, or a principal with no grants.
	vaults, _, probeErr := server.ProbeVaults(cmd.Context())
	if probeErr != nil {
		report.Failure = probeErr.Error()
	} else {
		report.Reachable = true
		report.VaultCount = len(vaults)
	}

	writeMCPCheckReport(os.Stdout, report)

	if !report.Reachable {
		// Exit non-zero so the check is usable in a script.
		return fmt.Errorf("preflight failed: the server could not be reached with this identity")
	}
	return nil
}
```

This needs three small additions to `internal/mcpserver`. Add to `server.go`:

```go
// BaseURL reports which server this instance talks to.
func (s *Server) BaseURL() string { return s.baseURL }

// EnabledTiers names the capability tiers this configuration enables.
func (s *Server) EnabledTiers() []string {
	tiers := []string{TierRead.String()}
	for _, tier := range []Tier{TierWrite, TierDestructive, TierCrypto} {
		if s.TierEnabled(tier) {
			tiers = append(tiers, tier.String())
		}
	}
	return tiers
}

// ProbeVaults makes one live call, to verify connectivity and credentials.
func (s *Server) ProbeVaults(ctx context.Context) ([]vaultapi.Vault, bool, error) {
	return s.client.ListVaults(ctx, false, 0)
}
```

Add a `baseURL` field to `Server` and to `Deps`, set in `New`, and pass it from `buildMCPServer` in `cmd/mcp.go`. Also add a small helper there:

```go
// loadMCPConfigForCheck re-reads the configuration for the report. It is
// already known valid, since buildMCPServer loaded it first.
func loadMCPConfigForCheck() (config.MCPConfig, error) {
	return config.LoadMCPConfig()
}
```

Finally, delete the `runMCPCheck` stub at the bottom of `cmd/mcp.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/ ./internal/mcpserver/ -race -v`
Expected: PASS — all ten new tests plus the existing suites.

Then confirm it runs against a live server:

```bash
go build -o rocketvault . && ./rocketvault serve &
./rocketvault users login --username admin
./rocketvault mcp --check
```
Expected: a report naming the server, the identity, ten tools, and `Reachable: yes`.

Confirm the failure path exits non-zero:

```bash
./rocketvault mcp --check --server https://127.0.0.1:1 ; echo "exit=$?"
```
Expected: a `FAIL` line and a non-zero exit code.

- [ ] **Step 5: Commit**

```bash
git add cmd/mcp_check.go cmd/mcp_check_test.go cmd/mcp.go internal/mcpserver/server.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(cmd): implement the mcp --check preflight

Without it a misconfiguration fails inside the host as an opaque handshake
error: the host reports that the server did not start, not why, because the
failure happened before any protocol exchange.

The check reuses the real startup path rather than a parallel approximation
that could drift, and makes one live ListVaults call to prove the credentials
work. It exits non-zero on failure so it is usable in a script, and it warns
when running as a cached session, since the agent's actions are then
indistinguishable from the operator's in the audit log."
```

---

### Task 2: The install guide

**Files:**
- Create: `docs/mcp-server.md`
- Modify: `CLAUDE.md` (add the doc to the Additional Documentation list)

**Interfaces:**
- Consumes: nothing.
- Produces: no code surface.

**Scope note:** this is the *install* guide — get it running, understand the tiers, know what `--check` tells you. The full operator runbook, with least-privilege role recommendations per use case and the threat-model summary, is plan 30. This task deliberately stops short of that so the phase-2 milestone is usable without waiting for it.

**Framing note:** RocketVault is a single-maintainer project. The guide is written for one operator running their own vault, not for a team handing work between people.

### A gap this task exposes rather than hides

**There is no CLI command to create a service account.** `cmd/` has no
`service-accounts` group — the capability exists only as
`POST /api/v1/service-accounts` (`api/service_accounts.go`). Yet a service
account is the posture this design recommends for anything beyond local use,
and what `mcp.require_service_account` demands.

So the setup path for the recommended configuration currently runs through
`curl`. The guide shows that honestly rather than inventing a command that
does not exist, but it is a rough edge worth recording: **a
`rocketvault service-accounts create` command would make this materially
easier**, and is a reasonable follow-up outside this plan's scope.

Two related details the guide must get right, both verified against the code:

- `vault-access grant` takes the principal **positionally**, not as a flag:
  `rocketvault vault-access grant <principal> --role "..."`
  (`cmd/vault-access/grant.go:18`).
- A service account needs `--principal-type service_account`; the flag
  defaults to `user` (`grant.go:86`).

- [ ] **Step 1: Write the failing test**

There is no test for a markdown file. Instead, this step is a checklist the content must satisfy — verify each by reading the finished file:

- [ ] Every command shown has been run and its output matches.
- [ ] The Claude Code config JSON uses an absolute path and is valid JSON.
- [ ] The tier table lists all four flags with their tool counts.
- [ ] The `query_audit_log` admin requirement is stated, since it is the one tool that fails under the recommended posture.
- [ ] No real secret appears anywhere.
- [ ] The service-account setup steps are complete enough to follow start to finish.

- [ ] **Step 2: Verify the gap**

```bash
test -f docs/mcp-server.md && echo "exists" || echo "missing"
```
Expected: `missing`.

- [ ] **Step 3: Write the guide**

Create `docs/mcp-server.md`:

````markdown
# RocketVault MCP Server

`rocketvault mcp` serves your vault to an MCP client such as Claude Code or
Claude Desktop, so an assistant can answer questions like *"which secrets in
prod expire this month?"* or *"who was granted Crypto Officer last week?"*
without you pasting output into a chat window.

It talks to a RocketVault API server over HTTP, so every call is authorized by
the same middleware any other API client goes through, and every call lands in
the audit log.

## Quick start

The server needs a running RocketVault instance and an identity.

```bash
# 1. Start the API server, if it is not already running.
rocketvault serve &

# 2. Log in. The session is cached under ~/.rocketvault/sessions/.
rocketvault users login --username admin

# 3. Confirm the MCP server can start and see the vault.
rocketvault mcp --check
```

`--check` prints the server it will talk to, the identity it will act as,
whether that identity works, and the exact list of tools it would expose. If
something is wrong, this is where you find out — a misconfiguration otherwise
surfaces inside the host as an unexplained startup failure.

Then register it with Claude Code, in `~/.claude.json` or your project's
`.mcp.json`:

```json
{
  "mcpServers": {
    "rocketvault": {
      "command": "/absolute/path/to/rocketvault",
      "args": ["mcp"]
    }
  }
}
```

The path must be absolute — the host does not resolve it against your shell's
`PATH`.

## What it exposes by default

Ten read-only tools, and no secret values:

| Tool | What it does |
|---|---|
| `list_secrets` | Names, versions and tags. Never values. |
| `get_secret` | Metadata, expiry, tags and version history. |
| `list_keys` | Key names, types and status. |
| `get_key` | Metadata, public JWK components, versions, rotation policy. |
| `list_certificates` | Certificates with expiry and renewal settings. |
| `get_certificate` | Metadata and issuance policy. |
| `list_deleted` | Soft-deleted secrets, keys or certificates. |
| `list_vaults` | Vaults with retention and purge-protection settings. |
| `list_role_assignments` | Who holds which role in a vault. |
| `query_audit_log` | Audit entries, filterable by time, action or outcome. |

Nothing here can change your vault. Every mutating capability is off until you
turn it on.

## Enabling more

Capability tiers live in the `mcp` section of `.rocketvault.yaml`. Each is
independent, and all default to `false`:

| Flag | Adds | Tools |
|---|---|---|
| `allow_write` | Create and update | 9 |
| `allow_destructive` | Delete, purge, revoke | 4 |
| `allow_crypto` | Sign, verify, encrypt, decrypt | 4 |
| `allow_secret_values` | `get_secret` can return plaintext | 0 (changes an existing tool) |

```yaml
mcp:
  vault: default
  allow_write: true
  allow_destructive: false
  allow_crypto: false
  allow_secret_values: false
```

Run `rocketvault mcp --check` after any change to confirm the tool count moved
the way you expected.

These flags only ever **narrow** what the authenticated principal could already
do. They cannot grant access the vault's role assignments do not — a tool that
passes the local gate can still get a 403.

### Pinning the blast radius

`allowed_vaults` restricts the server to a set of vaults, regardless of what
the principal could otherwise reach:

```yaml
mcp:
  vault: prod
  allowed_vaults: ["prod"]
```

Vaults outside the list are hidden from `list_vaults` and refused before any
request is made.

### Destructive confirmation

With `confirm_destructive: true` (the default), `delete_item`, `purge_item`,
`purge_vault` and `revoke_vault_role` require the caller to echo the exact
resource name. Leave it on. It costs one argument and it stops a destructive
call triggered by text the model read out of your vault.

## Identity

The server holds one identity for its whole lifetime. There is no per-user
authentication — the server is a child process of your MCP client, running as
you.

**Cached session** (the default, and fine for local use): whatever
`rocketvault users login` cached. The agent then acts as *you*, which means its
actions are indistinguishable from yours in the audit log.

**Service account** (use this for anything else): a dedicated principal with
its own role grants, so agent activity is attributable and its permissions are
exactly what you chose.

There is **no CLI command to create a service account** — the only way is the
REST API. Create one against a running server, authenticated as an admin:

```bash
# Log in, then read the cached session token. The `current` pointer holds
# "<serverKey>|<username>"; the session file is named "<serverKey>__<username>.json".
rocketvault users login --username admin

SESSIONS="$HOME/.rocketvault/sessions"
TOKEN=$(jq -r .token "$SESSIONS/$(sed 's/|/__/' "$SESSIONS/current").json")

curl -sS -X POST http://127.0.0.1:8774/api/v1/service-accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mcp-agent"}'
```

The response contains `client_id` and `client_secret`. **The secret is shown
once and never again** — copy it now.

Then grant the account only what it needs. Note that the principal is a
positional argument, and a service account needs `--principal-type`:

```bash
rocketvault vault-access grant mcp-agent \
  --role "Key Vault Reader" \
  --principal-type service_account \
  --vault prod
```

Run `rocketvault vault-access roles` to see the available role names.

Then configure it, keeping the secret out of the config file:

```yaml
mcp:
  client_id: "<the client_id printed above>"
  require_service_account: true
```

```bash
export ROCKETVAULT_MCP_CLIENT_SECRET='<the client_secret printed above>'
```

The environment variable takes precedence over `mcp.client_secret` in the YAML.
`require_service_account: true` makes the server refuse to fall back to your
session, so it cannot quietly start as you.

## Remote servers

```bash
rocketvault mcp --server https://vault.example.com
```

`ROCKETVAULT_ADDR` and named contexts (`rocketvault context use prod`) work
too. With none of them set, the server talks to `http://127.0.0.1` on the port
from `server.listen_addr`, and says so on stderr at startup.

## Known limitation: audit logs need admin

`query_audit_log` calls a route that requires the **global admin role**. No
per-vault role grants it — not `Key Vault Reader`, not even
`Key Vault Data Access Administrator`.

So a least-privilege service account, which is otherwise the right setup, will
get a permission error from that one tool every time. That is the API's design,
not a bug in the MCP server.

You have two honest options, and the second is often the better one:

1. Run the server as an admin principal, accepting a much broader grant than
   the other nine tools need.
2. Leave `query_audit_log` unusable and read audit logs with the CLI when you
   need them.

## Troubleshooting

**The client says the server failed to start.** Run `rocketvault mcp --check`.
It reports the actual cause; the host cannot, because the failure happens
before any protocol exchange.

**"no identity is configured".** Either run `rocketvault users login`, or set
`mcp.client_id` and `ROCKETVAULT_MCP_CLIENT_SECRET`.

**A tool returns a permission error.** The message names the missing data
action and a role that would grant it. Grant that role in that vault:

```bash
rocketvault vault-access grant mcp-agent \
  --role "Key Vault Secrets User" \
  --principal-type service_account \
  --vault prod
```

**A tool you expected is missing.** Its tier is off. `--check` lists the
enabled tiers and every exposed tool.

**Everything is being rate limited.** `mcp.rate_limit` bounds calls per minute
— 120 reads and 20 writes by default. A loop trips it. The limits are there so
a runaway agent degrades its own calls rather than your vault.

## Diagnostics

The server writes structured logs to stderr, one line per tool call, with the
tool name, outcome, duration and a correlation ID. That ID travels to the API
as a request header, so a tool call can be traced through to the audit entry it
produced.

Tool arguments are never logged: they can carry secret values.
````

- [ ] **Step 4: Verify the guide**

Work through the checklist from Step 1. In particular, actually run the
commands:

```bash
go build -o rocketvault .
./rocketvault mcp --check
./rocketvault mcp --help
```

Confirm the tool table matches what `--check` prints, and that the
`service-accounts create` and `vault-access grant` commands shown really exist
with those flags:

```bash
./rocketvault service-accounts --help
./rocketvault vault-access grant --help
```

If a flag differs, fix the guide — a setup guide with a command that does not
work is worse than no guide.

Add the entry to `CLAUDE.md` under **Additional Documentation > Developer
Resources**:

```markdown
- **[MCP Server Guide](docs/mcp-server.md)**: Running `rocketvault mcp` for Claude Code and Claude Desktop, capability tiers, and service-account setup
```

- [ ] **Step 5: Commit**

```bash
git add docs/mcp-server.md CLAUDE.md
git commit -S --gpg-sign=61D246B30285ED35 -m "docs(mcp): add the MCP server install guide

Covers quick start, the ten default tools, capability tiers, service-account
setup and troubleshooting.

States the audit-log limitation plainly rather than hiding it: query_audit_log
needs the global admin role, which no per-vault grant provides, so a
least-privilege service account cannot use it. Both options are given,
including simply leaving that tool unusable.

The full operator runbook with per-use-case role recommendations is plan 30;
this stops at what is needed to get running."
```

---

## Verification

```bash
go build ./...
go test ./cmd/ ./internal/mcpserver/ -race -v
go vet ./cmd/ ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

End to end, against a live server:

```bash
./rocketvault serve &
./rocketvault users login --username admin
./rocketvault mcp --check
```

Expected: a report showing `Reachable: yes`, ten tools, and the session
warning.

Confirm the non-zero exit on failure:

```bash
./rocketvault mcp --check --server https://127.0.0.1:1 ; echo "exit=$?"
```

Expected: a `FAIL` line and a non-zero exit code.

Finally, register with Claude Code and confirm the ten tools appear and are
callable.

## Notes for the next plan

Group E is complete, and the milestone is reached: `rocketvault mcp` is a
working, documented, diagnosable read-only server.

Plans 18-27 add the remaining tiers. Each adds `vaultapi` methods, then tools,
and each new `register*Tools` function is added to `RegisterAllTools` — the one
place the tool surface is defined.

Two things to carry forward:

- **`docs/mcp-server.md` is touched again in plan 30**, which adds the
  per-use-case role runbook and threat-model summary.
- **Every new tier changes `--check`'s output.** The tier table in the guide
  and the counts in it must be updated as tiers land, or the guide starts
  lying.
