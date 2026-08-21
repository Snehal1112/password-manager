# Capability Gating and Rate Limiting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decide which tools exist based on the configured capability tiers, refuse vaults outside `allowed_vaults` before any request leaves the process, and bound how fast tools may be called.

**Architecture:** Gating is *registration-time*, not call-time: a disabled tier's tools are never added to the server, so they cost nothing in the host's context and cannot be invoked at all. The vault guard and rate limiter are call-time, applied inside the same `withLifecycle` wrapper plan 10 established, so no tool can opt out.

**Tech Stack:** Go 1.25, `golang.org/x/time/rate` (already a direct dependency, used by `internal/middleware`), `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — sections "Tool surface", "Vault scoping" and "Production hardening > Resource consumption".

**Plan-of-plans:** This is plan 11 of 31. Requires plans 09 and 10 committed.

## Global Constraints

- Go 1.25.0. **No new dependency** — `golang.org/x/time/rate` is already in `go.mod` and used at `internal/middleware/middleware.go:79`.
- **Gating happens at registration.** A disabled tool must be absent from `tools/list`, not present-but-refusing.
- **Config narrows, never widens.** Passing a gate does not mean the call will succeed: the server still enforces RBAC, and a 403 is a normal outcome.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## File structure

| File | Responsibility |
|---|---|
| `internal/mcpserver/gating.go` (new) | `Tier`, `tierEnabled`, `registerIf`, `ResolveVault` |
| `internal/mcpserver/ratelimit.go` (new) | `limiter`, per-class buckets |
| `internal/mcpserver/gating_test.go` (new) | Tier registration, vault guard |
| `internal/mcpserver/ratelimit_test.go` (new) | Bucket behavior, refusal, class separation |

---

### Task 1: Tier gating and the `allowed_vaults` guard

**Files:**
- Create: `internal/mcpserver/gating.go`
- Create: `internal/mcpserver/gating_test.go`

**Interfaces:**
- Consumes: `Server`, `register`, `Annotations` (plan 10); `config.MCPConfig` (plan 09).
- Produces — every tool plan registers through `registerIf`, and every tool resolves its vault through `ResolveVault`:
  - `type Tier int` with `TierRead`, `TierWrite`, `TierDestructive`, `TierCrypto`
  - `func (s *Server) TierEnabled(t Tier) bool`
  - `func registerIf[In, Out any](s *Server, tier Tier, name, description string, ann Annotations, h mcp.ToolHandlerFor[In, Out])`
  - `func (s *Server) ResolveVault(requested string) (string, error)`

**Why `TierRead` is still a tier despite always being enabled:** it makes every registration site state its tier explicitly. A tool added with no tier would silently land in whatever the default was, which is precisely the mistake the gating table test in plan 28 exists to catch. Naming it costs one word and removes the failure mode.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/gating_test.go`:

```go
package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

// serverWithTiers builds a server whose four capability flags are set as
// given, then registers one tool per tier.
func serverWithTiers(t *testing.T, write, destructive, crypto bool) *Server {
	t.Helper()

	cfg := testConfig()
	cfg.AllowWrite = write
	cfg.AllowDestructive = destructive
	cfg.AllowCrypto = crypto

	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	noop := func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
		return nil, pingOut{}, nil
	}
	registerIf(s, TierRead, "read_tool", "A read tool.", Annotations{ReadOnly: true}, noop)
	registerIf(s, TierWrite, "write_tool", "A write tool.", Annotations{}, noop)
	registerIf(s, TierDestructive, "destructive_tool", "A destructive tool.", Annotations{Destructive: true}, noop)
	registerIf(s, TierCrypto, "crypto_tool", "A crypto tool.", Annotations{}, noop)
	return s
}

func TestGating_ReadTierIsAlwaysRegistered(t *testing.T) {
	s := serverWithTiers(t, false, false, false)
	require.Equal(t, []string{"read_tool"}, s.RegisteredTools())
}

func TestGating_DisabledTiersAreAbsentFromToolsList(t *testing.T) {
	s := serverWithTiers(t, false, false, false)
	cs := connect(t, s)

	require.Equal(t, []string{"read_tool"}, toolNames(t, cs),
		"a disabled tool must be absent, not present-but-refusing: absent costs no context")
}

func TestGating_EachFlagEnablesOnlyItsOwnTier(t *testing.T) {
	cases := []struct {
		name                        string
		write, destructive, crypto  bool
		want                        []string
	}{
		{"none", false, false, false, []string{"read_tool"}},
		{"write only", true, false, false, []string{"read_tool", "write_tool"}},
		{"destructive only", false, true, false, []string{"destructive_tool", "read_tool"}},
		{"crypto only", false, false, true, []string{"crypto_tool", "read_tool"}},
		{"all", true, true, true, []string{"crypto_tool", "destructive_tool", "read_tool", "write_tool"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := serverWithTiers(t, tc.write, tc.destructive, tc.crypto)
			require.Equal(t, tc.want, s.RegisteredTools())
		})
	}
}

func TestGating_DisabledToolCannotBeCalledAtAll(t *testing.T) {
	s := serverWithTiers(t, false, false, false)
	cs := connect(t, s)

	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "destructive_tool", Arguments: map[string]any{"message": "x"},
	})
	require.Error(t, err, "an unregistered tool is a protocol-level unknown-tool error")
}

func TestTierEnabled_ReportsTheConfiguredTiers(t *testing.T) {
	s := serverWithTiers(t, true, false, true)
	require.True(t, s.TierEnabled(TierRead))
	require.True(t, s.TierEnabled(TierWrite))
	require.False(t, s.TierEnabled(TierDestructive))
	require.True(t, s.TierEnabled(TierCrypto))
}

func TestResolveVault_FallsBackToTheConfiguredDefault(t *testing.T) {
	s := newTestServer(t)
	got, err := s.ResolveVault("")
	require.NoError(t, err)
	require.Equal(t, "default", got)
}

func TestResolveVault_PrefersAnExplicitRequest(t *testing.T) {
	cfg := testConfig()
	cfg.Vault = "default"
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	got, err := s.ResolveVault("prod")
	require.NoError(t, err)
	require.Equal(t, "prod", got)
}

func TestResolveVault_RefusesAVaultOutsideTheAllowlist(t *testing.T) {
	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging", "dev"}
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	_, err = s.ResolveVault("prod")
	require.ErrorContains(t, err, "prod")
	require.ErrorContains(t, err, "not permitted")
}

func TestResolveVault_AllowsAVaultInsideTheAllowlist(t *testing.T) {
	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging", "prod"}
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	got, err := s.ResolveVault("prod")
	require.NoError(t, err)
	require.Equal(t, "prod", got)
}

func TestResolveVault_EmptyAllowlistPermitsAnyVault(t *testing.T) {
	s := newTestServer(t)
	got, err := s.ResolveVault("anything-at-all")
	require.NoError(t, err)
	require.Equal(t, "anything-at-all", got,
		"an empty allowlist defers to RBAC, which already bounds what the principal can reach")
}

func TestResolveVault_ErrorNamesThePermittedVaults(t *testing.T) {
	cfg := testConfig()
	cfg.Vault = "staging"
	cfg.AllowedVaults = []string{"staging", "dev"}
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	_, err = s.ResolveVault("prod")
	require.ErrorContains(t, err, "staging")
	require.ErrorContains(t, err, "dev",
		"naming the permitted set lets the model correct itself instead of guessing")
}

var _ = config.MCPConfig{}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestGating_|TestTierEnabled_|TestResolveVault_' -v`
Expected: FAIL — `undefined: registerIf`, `undefined: TierRead`, `s.ResolveVault undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/gating.go`:

```go
package mcpserver

import (
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tier is a capability group that config enables as a unit.
type Tier int

const (
	// TierRead is always enabled. It is still named explicitly at every
	// registration site, so a tool can never land in a default tier by
	// omission.
	TierRead Tier = iota
	TierWrite
	TierDestructive
	TierCrypto
)

// String names the tier, for diagnostics and --check output.
func (t Tier) String() string {
	switch t {
	case TierWrite:
		return "write"
	case TierDestructive:
		return "destructive"
	case TierCrypto:
		return "crypto"
	default:
		return "read"
	}
}

// TierEnabled reports whether the configuration enables tier.
func (s *Server) TierEnabled(t Tier) bool {
	switch t {
	case TierWrite:
		return s.cfg.AllowWrite
	case TierDestructive:
		return s.cfg.AllowDestructive
	case TierCrypto:
		return s.cfg.AllowCrypto
	default:
		return true
	}
}

// registerIf adds a tool only when its tier is enabled.
//
// Gating happens here, at registration, rather than inside the handler. A
// disabled tool is therefore absent from tools/list entirely: it costs the
// host no context and cannot be invoked at all, which is a stronger property
// than a tool that exists and refuses.
func registerIf[In, Out any](s *Server, tier Tier, name, description string, ann Annotations, h mcp.ToolHandlerFor[In, Out]) {
	if !s.TierEnabled(tier) {
		return
	}
	register(s, name, description, ann, h)
}

// ResolveVault decides which vault a call targets.
//
// Precedence is the explicit request, then the configured default. When
// allowed_vaults is set, anything outside it is refused here, before any
// request leaves the process — the guard bounds blast radius regardless of
// what the principal's role assignments would otherwise permit.
func (s *Server) ResolveVault(requested string) (string, error) {
	vault := strings.TrimSpace(requested)
	if vault == "" {
		vault = s.cfg.Vault
	}
	if vault == "" {
		return "", fmt.Errorf("no vault was given and no default is configured")
	}

	if len(s.cfg.AllowedVaults) == 0 {
		// Deferring to RBAC is deliberate: it already bounds what the
		// principal can reach.
		return vault, nil
	}
	for _, allowed := range s.cfg.AllowedVaults {
		if allowed == vault {
			return vault, nil
		}
	}
	// Naming the permitted set lets the model correct itself rather than
	// guess at another name.
	return "", fmt.Errorf("vault %q is not permitted by this server; permitted vaults are: %s",
		vault, strings.Join(s.cfg.AllowedVaults, ", "))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run 'TestGating_|TestTierEnabled_|TestResolveVault_' -v`
Expected: PASS — all eleven tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/gating.go internal/mcpserver/gating_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): gate tools by capability tier and guard allowed_vaults

Gating happens at registration, not in the handler, so a disabled tool is
absent from tools/list entirely -- it costs the host no context and cannot be
invoked at all, which is stronger than a tool that exists and refuses.

TierRead is named explicitly at every site despite always being enabled, so a
tool can never land in a default tier by omission. The vault guard refuses
before any request leaves the process and names the permitted set, so the
model can correct itself rather than guess."
```

---

### Task 2: Per-class token-bucket rate limiting

**Files:**
- Create: `internal/mcpserver/ratelimit.go`
- Create: `internal/mcpserver/ratelimit_test.go`

**Interfaces:**
- Consumes: `config.MCPRateLimit` (plan 09), `Tier` (Task 1).
- Produces:
  - `type limiter struct { ... }`
  - `func newLimiter(cfg config.MCPRateLimit) *limiter`
  - `func (l *limiter) allow(tier Tier) bool`

**Two decisions worth stating:**

1. **Refuse rather than queue.** `rate.Limiter.Wait` would block the call until a token frees, which under a looping agent means an ever-growing queue of goroutines each holding a deadline. `Allow` refuses immediately, the model sees an error it can back off from, and nothing accumulates.
2. **Reads and writes are separate buckets.** A burst of listing must not exhaust the budget that would have let a legitimate `set_secret` through, and the write budget is much smaller because a runaway write loop does real damage where a read loop only wastes time.

Burst is set to the per-minute rate, so a short flurry is permitted and only sustained hammering trips the limit.

- [ ] **Step 1: Write the failing test**

Create `internal/mcpserver/ratelimit_test.go`:

```go
package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
)

func TestLimiter_AllowsUpToTheBurst(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 5, WritesPerMinute: 2})

	for i := 0; i < 5; i++ {
		require.True(t, l.allow(TierRead), "call %d should be permitted", i+1)
	}
}

func TestLimiter_RefusesBeyondTheBurst(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 3, WritesPerMinute: 2})

	for i := 0; i < 3; i++ {
		require.True(t, l.allow(TierRead))
	}
	require.False(t, l.allow(TierRead),
		"a looping agent must degrade its own calls rather than the vault")
}

func TestLimiter_ReadsAndWritesHaveSeparateBudgets(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 2, WritesPerMinute: 2})

	require.True(t, l.allow(TierRead))
	require.True(t, l.allow(TierRead))
	require.False(t, l.allow(TierRead), "the read budget is now spent")

	require.True(t, l.allow(TierWrite),
		"a burst of reads must not consume the budget a legitimate write needs")
}

func TestLimiter_DestructiveAndCryptoDrawOnTheWriteBudget(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 10, WritesPerMinute: 2})

	require.True(t, l.allow(TierDestructive))
	require.True(t, l.allow(TierCrypto))
	require.False(t, l.allow(TierWrite),
		"the three non-read tiers share one budget, since all three are consequential")
}

func TestLimiter_RefusalDoesNotBlock(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 1, WritesPerMinute: 1})
	require.True(t, l.allow(TierRead))

	done := make(chan bool, 1)
	go func() { done <- l.allow(TierRead) }()

	select {
	case allowed := <-done:
		require.False(t, allowed)
	case <-time.After(time.Second):
		t.Fatal("allow() blocked; it must refuse immediately rather than queue")
	}
}

func TestLimiter_IsSafeUnderConcurrency(t *testing.T) {
	l := newLimiter(config.MCPRateLimit{ReadsPerMinute: 100, WritesPerMinute: 100})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.allow(TierRead)
			l.allow(TierWrite)
		}()
	}
	wg.Wait()
}
```

Add `"sync"` and `"time"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run TestLimiter_ -race -v`
Expected: FAIL — `undefined: newLimiter`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/mcpserver/ratelimit.go`:

```go
package mcpserver

import (
	"golang.org/x/time/rate"

	"rocketvault/config"
)

// limiter bounds how fast tools may be called.
//
// Reads and everything else get separate budgets: a burst of listing must not
// exhaust the allowance a legitimate write needs, and the write budget is
// deliberately much smaller, because a runaway write loop does real damage
// where a runaway read loop only wastes time.
type limiter struct {
	reads  *rate.Limiter
	writes *rate.Limiter
}

// newLimiter builds the per-class buckets.
//
// Burst equals the per-minute rate, so a short flurry of calls is permitted
// and only sustained hammering trips the limit.
func newLimiter(cfg config.MCPRateLimit) *limiter {
	perMinute := func(n int) *rate.Limiter {
		return rate.NewLimiter(rate.Limit(float64(n)/60.0), n)
	}
	return &limiter{
		reads:  perMinute(cfg.ReadsPerMinute),
		writes: perMinute(cfg.WritesPerMinute),
	}
}

// allow reports whether a call in tier may proceed.
//
// It refuses immediately rather than waiting for a token. Blocking would
// leave a looping agent with an ever-growing queue of goroutines, each
// holding a deadline; refusing lets the model see an error and back off.
func (l *limiter) allow(tier Tier) bool {
	if tier == TierRead {
		return l.reads.Allow()
	}
	// Write, destructive and crypto share one budget: all three are
	// consequential in a way reads are not.
	return l.writes.Allow()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -run TestLimiter_ -race -v`
Expected: PASS — all six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/ratelimit.go internal/mcpserver/ratelimit_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): add per-class token-bucket rate limiting

Reuses golang.org/x/time/rate, already a direct dependency at
middleware.go:79. Reads get their own budget so a burst of listing cannot
exhaust the allowance a legitimate write needs; write, destructive and crypto
share a much smaller one, since all three are consequential where reads only
waste time.

allow() refuses immediately rather than waiting for a token: blocking would
leave a looping agent with an ever-growing queue of goroutines each holding a
deadline."
```

---

### Task 3: Wire the limiter into every tool call

**Files:**
- Modify: `internal/mcpserver/server.go` (`Server` gains a limiter; `register` takes a tier)
- Modify: `internal/mcpserver/gating.go` (`registerIf` passes the tier through)
- Modify: `internal/mcpserver/lifecycle.go` (`withLifecycle` checks the limiter)
- Modify: `internal/mcpserver/ratelimit_test.go` (append end-to-end tests)

**Interfaces:**
- Consumes: everything above.
- Produces: `register` and `withLifecycle` gain a `tier Tier` parameter. Call sites in `gating.go` and `server_test.go` are updated accordingly.

**Where the check goes and why:** inside `withLifecycle`, *before* the handler runs. Putting it in each handler would make it forgettable; putting it after the handler would defeat the purpose. It must also come before the vault guard and any network call, so a refused call costs nothing.

- [ ] **Step 1: Write the failing test**

Append to `internal/mcpserver/ratelimit_test.go`:

```go
func TestRegister_RefusesCallsBeyondTheRateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.RateLimit = config.MCPRateLimit{ReadsPerMinute: 2, WritesPerMinute: 2}

	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	var calls int
	registerIf(s, TierRead, "ping", "Echoes.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			calls++
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	call := func() *mcp.CallToolResult {
		result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "ping", Arguments: map[string]any{"message": "x"},
		})
		require.NoError(t, err)
		return result
	}

	require.False(t, call().IsError)
	require.False(t, call().IsError)

	refused := call()
	require.True(t, refused.IsError, "the third call exceeds the budget")
	require.Equal(t, 2, calls, "a refused call must not reach the handler at all")
}

func TestRegister_RateLimitMessageIsActionable(t *testing.T) {
	cfg := testConfig()
	cfg.RateLimit = config.MCPRateLimit{ReadsPerMinute: 1, WritesPerMinute: 1}

	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	registerIf(s, TierRead, "ping", "Echoes.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
			return nil, pingOut{}, nil
		})

	cs := connect(t, s)
	for i := 0; i < 2; i++ {
		_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "ping", Arguments: map[string]any{"message": "x"},
		})
		require.NoError(t, err)
	}

	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ping", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)

	var rendered strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			rendered.WriteString(text.Text)
		}
	}
	require.Contains(t, strings.ToLower(rendered.String()), "rate limit",
		"the model should be able to tell this apart from a permission failure and back off")
}

func TestRegister_ReadBurstDoesNotStarveWrites(t *testing.T) {
	cfg := testConfig()
	cfg.AllowWrite = true
	cfg.RateLimit = config.MCPRateLimit{ReadsPerMinute: 1, WritesPerMinute: 1}

	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)

	noop := func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, pingOut, error) {
		return nil, pingOut{}, nil
	}
	registerIf(s, TierRead, "read_tool", "Reads.", Annotations{ReadOnly: true}, noop)
	registerIf(s, TierWrite, "write_tool", "Writes.", Annotations{}, noop)

	cs := connect(t, s)
	callTool := func(name string) *mcp.CallToolResult {
		result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: name, Arguments: map[string]any{"message": "x"},
		})
		require.NoError(t, err)
		return result
	}

	require.False(t, callTool("read_tool").IsError)
	require.True(t, callTool("read_tool").IsError, "the read budget is spent")
	require.False(t, callTool("write_tool").IsError, "the write budget is untouched")
}
```

Add `"strings"` and `"github.com/modelcontextprotocol/go-sdk/mcp"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestRegister_Refuses|TestRegister_RateLimit|TestRegister_ReadBurst' -v`
Expected: FAIL — every call succeeds, since nothing checks the limiter yet.

- [ ] **Step 3: Write minimal implementation**

In `internal/mcpserver/server.go`, add the field to `Server`:

```go
	// limits bounds how fast tools may be called.
	limits *limiter
```

Build it in `New`, alongside the other fields:

```go
	return &Server{
		cfg:       deps.Config,
		client:    deps.Client,
		logger:    logger,
		mcpServer: mcpServer,
		limits:    newLimiter(deps.Config.RateLimit),
	}, nil
```

Change `register` to take a tier and pass it on:

```go
func register[In, Out any](s *Server, tier Tier, name, description string, ann Annotations, h mcp.ToolHandlerFor[In, Out]) {
	...
	mcp.AddTool(s.mcpServer, tool, withLifecycle(s, tier, name, h))
	s.registered = append(s.registered, name)
}
```

In `internal/mcpserver/gating.go`, pass the tier through:

```go
	register(s, tier, name, description, ann, h)
```

In `internal/mcpserver/lifecycle.go`, change the signature and add the check as the first thing after recovery is installed:

```go
func withLifecycle[In, Out any](s *Server, tier Tier, name string, h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (result *mcp.CallToolResult, out Out, err error) {
		// The limit is checked before the handler, before the vault guard,
		// and before any network call, so a refused call costs nothing.
		if !s.limits.allow(tier) {
			var zero Out
			s.logger.Warn("tool call refused by rate limit", "tool", name, "tier", tier.String())
			return errorResult(
				"%s was refused by the rate limit for %s operations; wait before retrying",
				name, tier.String()), zero, nil
		}

		ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
		...
```

Finally, update the direct `register(...)` call sites in `internal/mcpserver/server_test.go` and `lifecycle_test.go` to pass a tier — `TierRead` for the read-only fixtures, `TierDestructive` for the `purge` fixture in `TestRegister_DestructiveToolIsAdvertisedAsSuch`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/mcpserver/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver/
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(mcpserver): enforce the rate limit on every tool call

The check lives in withLifecycle, before the handler, before the vault guard
and before any network call, so a refused call costs nothing and no tool can
forget to make it. The message names the tier and says to wait, so the model
can tell a rate limit apart from a permission failure and back off rather than
retry immediately."
```

---

## Verification

```bash
go build ./...
go test ./internal/mcpserver/ -race -v
go vet ./internal/mcpserver/
```

Expected: all tests pass, race-clean, no vet findings.

The gating property is the security-critical one. Confirm a default-configured
server exposes exactly the read tier:

```bash
go test ./internal/mcpserver/ -run TestGating_ -v
```

## Notes for the next plan

Plan 12 adds redaction and the untrusted-content envelope, completing the
mcpserver foundation. After it, plans 13-15 register the actual read tools.

Two invariants later plans depend on:

- **`registerIf` is how every tool is added**, with its tier named explicitly.
  Plan 28's gating table asserts the exact registered set per flag
  combination, and a tool registered by any other route will fail it.
- **`ResolveVault` is how every tool decides its vault.** A tool that reads
  `s.cfg.Vault` directly bypasses the allowlist guard.
