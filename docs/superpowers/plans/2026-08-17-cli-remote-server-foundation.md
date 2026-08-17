# CLI Remote Server Support — Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundation that lets the RocketVault CLI target a remote server — server-aware session cache, named contexts, target resolution, a TLS-aware remote HTTP client, and a local-only refusal helper — without touching any resource command (`secrets`, `keys`, `certificates`, `vaults`) yet.

**Architecture:** Dual-mode resolution: if `--server`/`ROCKETVAULT_ADDR`/a current named context resolves to a server, the CLI is in remote mode; otherwise it's local mode (today's unchanged behavior). This plan builds every shared piece that mode decision depends on. Resource-group command wiring (secrets, keys, certificates, vaults, vault-access, users, audit) is deliberately out of scope — see Scope Note below.

**Tech Stack:** Go, Cobra, Viper, standard library `net/http`/`crypto/tls`.

**Spec:** `docs/superpowers/specs/2026-08-17-cli-remote-server-support-design.md`

## Scope Note

The design spec covers 7 resource groups and 22+ command files. Per the
writing-plans scope-check guidance, this plan covers only the shared
foundation those resource groups all depend on — each resource group's
dual-mode adapter (e.g. "secrets works in remote mode") is independently
shippable and testable once this foundation exists, so it belongs in its own
follow-on plan rather than one unwieldy plan covering everything. This plan
alone changes zero command behavior for existing users — it adds new,
inert capability (a `context` command group, new global flags) without
wiring any resource command to use it yet.

## Global Constraints

- Local mode must remain byte-for-byte unchanged for any invocation that sets
  none of `--server`, `ROCKETVAULT_ADDR`, or a current context. (Spec Goal 2.)
- TLS verification defaults to on; `--insecure-skip-verify` must print a
  warning to stderr every time it's used, never silently. (Spec §5.)
- A command that resolves a remote target must never silently fall back to
  operating on the local instance. (Spec §6.)
- Existing local-mode session cache files must keep working without forcing
  a re-login. (Spec Goal 4 / §2.)

---

### Task 1: Server-aware session cache with non-breaking migration

**Files:**
- Modify: `common/session.go`
- Test: `common/session_test.go`

**Interfaces:**
- Produces: `common.LocalServerKey` (const `"local"`), `common.SanitizeServerKey(server string) string`, `common.SessionCache.ServerKey` (new field), `common.LoadSessionForServer(serverKey, username string) (*SessionCache, error)`, `common.DeleteSessionForServer(serverKey, username string) error`. Existing `LoadSession(username)`/`DeleteSession(username)`/`SaveSession(session)` keep their exact current signatures and behavior for local-mode callers — this task is additive, not a breaking rename.

- [ ] **Step 1: Write the failing tests**

```go
// common/session_test.go — add to the existing file

func TestSanitizeServerKey(t *testing.T) {
	cases := map[string]string{
		"":                                          LocalServerKey,
		LocalServerKey:                               LocalServerKey,
		"https://vault.prod.example.com":             "vault.prod.example.com",
		"https://vault.prod.example.com:8443":        "vault.prod.example.com_8443",
		"http://localhost:8774":                      "localhost_8774",
	}
	for in, want := range cases {
		if got := SanitizeServerKey(in); got != want {
			t.Errorf("SanitizeServerKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadSessionForServer_DifferentServers_DoNotCollide(t *testing.T) {
	SessionBaseDir = t.TempDir()

	prod := &SessionCache{Username: "admin", Token: "prod-token", ServerKey: SanitizeServerKey("https://vault.prod.example.com")}
	staging := &SessionCache{Username: "admin", Token: "staging-token", ServerKey: SanitizeServerKey("https://vault.staging.example.com")}

	if err := SaveSession(prod); err != nil {
		t.Fatalf("SaveSession(prod): %v", err)
	}
	if err := SaveSession(staging); err != nil {
		t.Fatalf("SaveSession(staging): %v", err)
	}

	gotProd, err := LoadSessionForServer(SanitizeServerKey("https://vault.prod.example.com"), "admin")
	if err != nil || gotProd == nil || gotProd.Token != "prod-token" {
		t.Fatalf("LoadSessionForServer(prod) = %+v, %v; want token prod-token", gotProd, err)
	}
	gotStaging, err := LoadSessionForServer(SanitizeServerKey("https://vault.staging.example.com"), "admin")
	if err != nil || gotStaging == nil || gotStaging.Token != "staging-token" {
		t.Fatalf("LoadSessionForServer(staging) = %+v, %v; want token staging-token", gotStaging, err)
	}
}

func TestLoadSession_FallsBackToLegacyFormat_AndMigrates(t *testing.T) {
	SessionBaseDir = t.TempDir()
	os.MkdirAll(SessionBaseDir, 0700)

	// Simulate a pre-remote-mode session file: bare "<username>.json", no
	// server key at all.
	legacy := &SessionCache{Username: "admin", Token: "legacy-token"}
	data, _ := json.Marshal(legacy)
	os.WriteFile(filepath.Join(SessionBaseDir, "admin.json"), data, 0600)

	got, err := LoadSession("admin")
	if err != nil || got == nil || got.Token != "legacy-token" {
		t.Fatalf("LoadSession(admin) = %+v, %v; want fallback to legacy-token", got, err)
	}

	// It should have migrated: the new-format file now exists too.
	if _, err := os.Stat(filepath.Join(SessionBaseDir, LocalServerKey+"__admin.json")); err != nil {
		t.Fatalf("expected new-format file to exist after migration: %v", err)
	}
}

func TestLoadCurrentSession_ParsesLegacyAndNewPointerFormats(t *testing.T) {
	SessionBaseDir = t.TempDir()
	os.MkdirAll(SessionBaseDir, 0700)

	remote := &SessionCache{Username: "admin", Token: "remote-token", ServerKey: "vault.prod.example.com"}
	if err := SaveSession(remote); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	got, err := LoadCurrentSession()
	if err != nil || got == nil || got.Token != "remote-token" {
		t.Fatalf("LoadCurrentSession() = %+v, %v; want remote-token", got, err)
	}

	// Legacy pointer format: bare username, no "|".
	os.WriteFile(filepath.Join(SessionBaseDir, "current"), []byte("admin"), 0600)
	legacySession := &SessionCache{Username: "admin", Token: "legacy-current-token"}
	data, _ := json.Marshal(legacySession)
	os.WriteFile(filepath.Join(SessionBaseDir, "admin.json"), data, 0600)

	got2, err := LoadCurrentSession()
	if err != nil || got2 == nil || got2.Token != "legacy-current-token" {
		t.Fatalf("LoadCurrentSession() legacy pointer = %+v, %v; want legacy-current-token", got2, err)
	}
}

func TestDeleteSessionForServer_ClearsCurrentPointerOnlyForMatchingServer(t *testing.T) {
	SessionBaseDir = t.TempDir()

	prodKey := SanitizeServerKey("https://vault.prod.example.com")
	if err := SaveSession(&SessionCache{Username: "admin", Token: "t", ServerKey: prodKey}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	if err := DeleteSessionForServer(prodKey, "admin"); err != nil {
		t.Fatalf("DeleteSessionForServer: %v", err)
	}

	if s, err := LoadCurrentSession(); err != nil || s != nil {
		t.Fatalf("LoadCurrentSession() after delete = %+v, %v; want nil, nil", s, err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./common/... -run 'TestSanitizeServerKey|TestLoadSessionForServer|TestLoadSession_FallsBack|TestLoadCurrentSession_Parses|TestDeleteSessionForServer' -v`
Expected: FAIL — `LocalServerKey`, `SanitizeServerKey`, `LoadSessionForServer`, `DeleteSessionForServer` undefined.

- [ ] **Step 3: Implement**

Replace the full contents of `common/session.go` with:

```go
package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SessionBaseDir is the directory holding per-user CLI session cache files.
// Overridable in tests.
var SessionBaseDir = defaultSessionBaseDir()

func defaultSessionBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".rocketvault", "sessions")
	}
	return filepath.Join(home, ".rocketvault", "sessions")
}

// LocalServerKey is the reserved server key representing local mode — no
// remote target resolved. Every session cached before remote-server support
// existed is implicitly a local-mode session.
const LocalServerKey = "local"

// SessionCache is the on-disk representation of a CLI-authenticated session.
type SessionCache struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       uuid.UUID `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
	// ServerKey identifies which server this session belongs to:
	// LocalServerKey for local mode, or SanitizeServerKey(serverURL) for a
	// remote target. Empty is treated as LocalServerKey.
	ServerKey string `json:"server_key,omitempty"`
}

var usernameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
var serverKeySanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// sanitizeUsername converts an arbitrary username into a safe filename
// component. Usernames in this codebase are typically emails
// (user14@exchange4all.local) or simple local names (admin) — both pass
// through unchanged; anything else is replaced with "_".
func sanitizeUsername(username string) string {
	return usernameSanitizer.ReplaceAllString(username, "_")
}

// SanitizeServerKey converts a server URL into a safe filename component:
// the scheme is stripped, the result is lowercased, and anything unsafe in
// a filename becomes "_". LocalServerKey and "" both pass through as
// LocalServerKey.
func SanitizeServerKey(server string) string {
	if server == "" || server == LocalServerKey {
		return LocalServerKey
	}
	s := strings.TrimPrefix(server, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.ToLower(s)
	return serverKeySanitizer.ReplaceAllString(s, "_")
}

func sessionFilePath(serverKey, username string) string {
	return filepath.Join(SessionBaseDir, serverKey+"__"+sanitizeUsername(username)+".json")
}

// legacySessionFilePath is the pre-remote-mode filename format: username
// only, implicitly local mode. Only ever read, never written, going forward.
func legacySessionFilePath(username string) string {
	return filepath.Join(SessionBaseDir, sanitizeUsername(username)+".json")
}

func currentPointerPath() string {
	return filepath.Join(SessionBaseDir, "current")
}

// SaveSession writes session to disk and marks it as the current session —
// the one commands run without --username fall back to. A blank
// session.ServerKey is treated as LocalServerKey.
func SaveSession(session *SessionCache) error {
	if session.ServerKey == "" {
		session.ServerKey = LocalServerKey
	}

	if err := os.MkdirAll(SessionBaseDir, 0700); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := os.WriteFile(sessionFilePath(session.ServerKey, session.Username), data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	pointer := session.ServerKey + "|" + session.Username
	if err := os.WriteFile(currentPointerPath(), []byte(pointer), 0600); err != nil {
		return fmt.Errorf("failed to update current-session pointer: %w", err)
	}

	return nil
}

// LoadSession loads username's cached local-mode session — equivalent to
// LoadSessionForServer(LocalServerKey, username). Unaffected by remote-mode
// support.
func LoadSession(username string) (*SessionCache, error) {
	return LoadSessionForServer(LocalServerKey, username)
}

// LoadSessionForServer loads a specific (serverKey, username) session. A
// missing file returns (nil, nil) — "no session" is not an error. For
// serverKey == LocalServerKey, falls back to the pre-remote-mode filename
// format if the new-format file doesn't exist, and lazily rewrites it in the
// new format so the fallback is only ever needed once.
func LoadSessionForServer(serverKey, username string) (*SessionCache, error) {
	if serverKey == "" {
		serverKey = LocalServerKey
	}

	data, err := os.ReadFile(sessionFilePath(serverKey, username))
	if os.IsNotExist(err) && serverKey == LocalServerKey {
		data, err = os.ReadFile(legacySessionFilePath(username))
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var session SessionCache
	if err := json.Unmarshal(data, &session); err != nil {
		// A corrupt cache file is treated as "no session", not a hard error.
		return nil, nil
	}
	if session.ServerKey == "" {
		session.ServerKey = LocalServerKey
	}

	// Lazily migrate: rewrite under the new filename so the legacy fallback
	// above is only ever needed once per user.
	if session.ServerKey == LocalServerKey {
		if _, newErr := os.Stat(sessionFilePath(LocalServerKey, username)); os.IsNotExist(newErr) {
			_ = SaveSession(&session)
		}
	}

	return &session, nil
}

// LoadCurrentSession loads whichever session the pointer file currently
// references. Returns (nil, nil) if there is no pointer or no matching
// session file. Handles both the new "serverKey|username" pointer format and
// the pre-remote-mode bare-username format.
func LoadCurrentSession() (*SessionCache, error) {
	data, err := os.ReadFile(currentPointerPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read current-session pointer: %w", err)
	}

	serverKey, username := LocalServerKey, string(data)
	if parts := strings.SplitN(string(data), "|", 2); len(parts) == 2 {
		serverKey, username = parts[0], parts[1]
	}

	return LoadSessionForServer(serverKey, username)
}

// DeleteSession removes username's cached local-mode session — equivalent
// to DeleteSessionForServer(LocalServerKey, username). Unaffected by
// remote-mode support.
func DeleteSession(username string) error {
	return DeleteSessionForServer(LocalServerKey, username)
}

// DeleteSessionForServer removes the (serverKey, username) session file,
// including the legacy-format file when serverKey is LocalServerKey. If it
// was the current pointer's target, the pointer is cleared too. Deleting a
// non-existent session is not an error.
func DeleteSessionForServer(serverKey, username string) error {
	if serverKey == "" {
		serverKey = LocalServerKey
	}

	if err := os.Remove(sessionFilePath(serverKey, username)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete session file: %w", err)
	}
	if serverKey == LocalServerKey {
		if err := os.Remove(legacySessionFilePath(username)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete legacy session file: %w", err)
		}
	}

	current, err := os.ReadFile(currentPointerPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read current-session pointer: %w", err)
	}

	currentServerKey, currentUsername := LocalServerKey, string(current)
	if parts := strings.SplitN(string(current), "|", 2); len(parts) == 2 {
		currentServerKey, currentUsername = parts[0], parts[1]
	}

	if currentServerKey == serverKey && currentUsername == username {
		if err := os.Remove(currentPointerPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to clear current-session pointer: %w", err)
		}
	}

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./common/... -v`
Expected: PASS — all new tests plus every pre-existing test in `common/session_test.go`.

- [ ] **Step 5: Commit**

```bash
git add common/session.go common/session_test.go
git commit -m "feat(cli): make session cache server-aware with non-breaking migration"
```

---

### Task 2: Named context store

**Files:**
- Create: `common/context.go`
- Test: `common/context_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `common.Context{Server, Username, Vault string}`, `common.AddContext(name string, ctx Context) error`, `common.ListContexts() (map[string]Context, currentName string, error)`, `common.UseContext(name string) error`, `common.CurrentContext() (*Context, name string, error)`, `common.RemoveContext(name string) error`.

- [ ] **Step 1: Write the failing tests**

```go
// common/context_test.go
package common

import (
	"path/filepath"
	"testing"
)

func withTempContextsDir(t *testing.T) {
	t.Helper()
	SessionBaseDir = filepath.Join(t.TempDir(), "sessions")
}

func TestAddAndListContexts(t *testing.T) {
	withTempContextsDir(t)

	if err := AddContext("prod", Context{Server: "https://vault.prod.example.com", Username: "admin"}); err != nil {
		t.Fatalf("AddContext: %v", err)
	}

	contexts, current, err := ListContexts()
	if err != nil {
		t.Fatalf("ListContexts: %v", err)
	}
	if current != "" {
		t.Errorf("current = %q, want empty (nothing set as current yet)", current)
	}
	got, ok := contexts["prod"]
	if !ok || got.Server != "https://vault.prod.example.com" || got.Username != "admin" {
		t.Errorf("contexts[prod] = %+v, ok=%v; want server/username set", got, ok)
	}
}

func TestUseAndCurrentContext(t *testing.T) {
	withTempContextsDir(t)
	AddContext("staging", Context{Server: "https://vault.staging.example.com"})

	if err := UseContext("staging"); err != nil {
		t.Fatalf("UseContext: %v", err)
	}

	ctx, name, err := CurrentContext()
	if err != nil || ctx == nil || name != "staging" {
		t.Fatalf("CurrentContext() = %+v, %q, %v; want staging", ctx, name, err)
	}
}

func TestUseContext_UnknownName_Errors(t *testing.T) {
	withTempContextsDir(t)
	if err := UseContext("does-not-exist"); err == nil {
		t.Fatal("UseContext(unknown) = nil error, want an error")
	}
}

func TestRemoveContext_ClearsCurrentIfActive(t *testing.T) {
	withTempContextsDir(t)
	AddContext("prod", Context{Server: "https://vault.prod.example.com"})
	UseContext("prod")

	if err := RemoveContext("prod"); err != nil {
		t.Fatalf("RemoveContext: %v", err)
	}

	ctx, name, err := CurrentContext()
	if err != nil || ctx != nil || name != "" {
		t.Fatalf("CurrentContext() after remove = %+v, %q, %v; want nil, \"\", nil", ctx, name, err)
	}
}

func TestCurrentContext_NoneSet_ReturnsNil(t *testing.T) {
	withTempContextsDir(t)
	ctx, name, err := CurrentContext()
	if err != nil || ctx != nil || name != "" {
		t.Fatalf("CurrentContext() = %+v, %q, %v; want nil, \"\", nil", ctx, name, err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./common/... -run 'TestAddAndListContexts|TestUseAndCurrentContext|TestUseContext_UnknownName|TestRemoveContext|TestCurrentContext_NoneSet' -v`
Expected: FAIL — `Context`, `AddContext`, `ListContexts`, `UseContext`, `CurrentContext`, `RemoveContext` undefined.

- [ ] **Step 3: Implement**

```go
// common/context.go
package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// contextsFilePath sits alongside the sessions/ directory, at
// ~/.rocketvault/contexts.json.
func contextsFilePath() string {
	return filepath.Join(filepath.Dir(SessionBaseDir), "contexts.json")
}

// Context is a named pointer to a remote RocketVault server. It holds no
// credentials — those live in the session cache, keyed by
// SanitizeServerKey(Server).
type Context struct {
	Server   string `json:"server"`
	Username string `json:"username,omitempty"`
	Vault    string `json:"vault,omitempty"`
}

type contextStore struct {
	Current  string             `json:"current,omitempty"`
	Contexts map[string]Context `json:"contexts"`
}

func loadContextStore() (*contextStore, error) {
	data, err := os.ReadFile(contextsFilePath())
	if os.IsNotExist(err) {
		return &contextStore{Contexts: map[string]Context{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read contexts file: %w", err)
	}
	var store contextStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse contexts file: %w", err)
	}
	if store.Contexts == nil {
		store.Contexts = map[string]Context{}
	}
	return &store, nil
}

func saveContextStore(store *contextStore) error {
	if err := os.MkdirAll(filepath.Dir(contextsFilePath()), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal contexts: %w", err)
	}
	if err := os.WriteFile(contextsFilePath(), data, 0600); err != nil {
		return fmt.Errorf("failed to write contexts file: %w", err)
	}
	return nil
}

// AddContext creates or overwrites a named context.
func AddContext(name string, ctx Context) error {
	store, err := loadContextStore()
	if err != nil {
		return err
	}
	store.Contexts[name] = ctx
	return saveContextStore(store)
}

// ListContexts returns all saved contexts and the name of the current one
// ("" if none is set).
func ListContexts() (map[string]Context, string, error) {
	store, err := loadContextStore()
	if err != nil {
		return nil, "", err
	}
	return store.Contexts, store.Current, nil
}

// UseContext marks name as current. Returns an error if name doesn't exist.
func UseContext(name string) error {
	store, err := loadContextStore()
	if err != nil {
		return err
	}
	if _, ok := store.Contexts[name]; !ok {
		return fmt.Errorf("context %q not found", name)
	}
	store.Current = name
	return saveContextStore(store)
}

// CurrentContext returns the current context and its name. Returns
// (nil, "", nil) if no context is set as current, or if the current
// pointer references a context that no longer exists.
func CurrentContext() (*Context, string, error) {
	store, err := loadContextStore()
	if err != nil {
		return nil, "", err
	}
	if store.Current == "" {
		return nil, "", nil
	}
	ctx, ok := store.Contexts[store.Current]
	if !ok {
		return nil, "", nil
	}
	return &ctx, store.Current, nil
}

// RemoveContext deletes a named context. If it was the current context, the
// current pointer is cleared too. Removing a non-existent context is not an
// error.
func RemoveContext(name string) error {
	store, err := loadContextStore()
	if err != nil {
		return err
	}
	delete(store.Contexts, name)
	if store.Current == name {
		store.Current = ""
	}
	return saveContextStore(store)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./common/... -v`
Expected: PASS — all new tests plus Task 1's tests still passing.

- [ ] **Step 5: Commit**

```bash
git add common/context.go common/context_test.go
git commit -m "feat(cli): add named remote-server context store"
```

---

### Task 3: Target resolver + root.go wiring

**Files:**
- Create: `internal/cliclient/resolve.go`
- Test: `internal/cliclient/resolve_test.go`
- Modify: `cmd/root.go`
- Test: `cmd/root_test.go`

**Interfaces:**
- Consumes: `common.CurrentContext()` (Task 2).
- Produces: `cliclient.Target{Server, Username, Vault string}`, `cliclient.ResolveTarget(serverFlag string) (*Target, error)`. Later plans (resource-group adapters) call this with their own `--server` flag value to decide local vs. remote per command.

- [ ] **Step 1: Write the failing test**

```go
// internal/cliclient/resolve_test.go
package cliclient

import (
	"testing"

	"rocketvault/common"
)

func TestResolveTarget_FlagWins(t *testing.T) {
	t.Setenv("ROCKETVAULT_ADDR", "https://env.example.com")
	target, err := ResolveTarget("https://flag.example.com")
	if err != nil || target == nil || target.Server != "https://flag.example.com" {
		t.Fatalf("ResolveTarget(flag) = %+v, %v; want flag.example.com", target, err)
	}
}

func TestResolveTarget_EnvWinsOverContext(t *testing.T) {
	common.SessionBaseDir = t.TempDir() + "/sessions"
	common.AddContext("prod", common.Context{Server: "https://ctx.example.com"})
	common.UseContext("prod")
	t.Setenv("ROCKETVAULT_ADDR", "https://env.example.com")

	target, err := ResolveTarget("")
	if err != nil || target == nil || target.Server != "https://env.example.com" {
		t.Fatalf("ResolveTarget(\"\") = %+v, %v; want env.example.com", target, err)
	}
}

func TestResolveTarget_FallsBackToContext(t *testing.T) {
	common.SessionBaseDir = t.TempDir() + "/sessions"
	common.AddContext("prod", common.Context{Server: "https://ctx.example.com", Username: "admin", Vault: "prod-vault"})
	common.UseContext("prod")

	target, err := ResolveTarget("")
	if err != nil || target == nil || target.Server != "https://ctx.example.com" || target.Username != "admin" || target.Vault != "prod-vault" {
		t.Fatalf("ResolveTarget(\"\") = %+v, %v; want ctx.example.com/admin/prod-vault", target, err)
	}
}

func TestResolveTarget_NoneConfigured_ReturnsNil(t *testing.T) {
	common.SessionBaseDir = t.TempDir() + "/sessions"
	target, err := ResolveTarget("")
	if err != nil || target != nil {
		t.Fatalf("ResolveTarget(\"\") = %+v, %v; want nil, nil (local mode)", target, err)
	}
}
```

```go
// cmd/root_test.go — add to the existing file

func TestInitConfig_RemoteMode_DoesNotPanicWithoutConfigFile(t *testing.T) {
	dir := t.TempDir() // no .rocketvault.yaml here
	origWd, _ := os.Getwd()
	defer os.Chdir(origWd)
	os.Chdir(dir)

	t.Setenv("ROCKETVAULT_ADDR", "https://vault.prod.example.com")
	viper.Reset()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("initConfig() panicked in remote mode without a config file: %v", r)
		}
	}()
	initConfig()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cliclient/... ./cmd/... -run 'TestResolveTarget|TestInitConfig_RemoteMode' -v`
Expected: FAIL — `internal/cliclient` package doesn't exist yet; `TestInitConfig_RemoteMode_DoesNotPanicWithoutConfigFile` fails because `initConfig()` still panics unconditionally.

- [ ] **Step 3: Implement the resolver**

```go
// internal/cliclient/resolve.go
package cliclient

import (
	"os"

	"rocketvault/common"
)

// Target describes the resolved remote server this invocation should talk
// to. A nil *Target (with a nil error) means local mode.
type Target struct {
	Server   string
	Username string // default username from a context, if any; command flags still win
	Vault    string // default vault from a context, if any; --vault still wins
}

// ResolveTarget applies the precedence chain: an explicit --server flag
// value (pass "" if the flag wasn't set or is empty), then the
// ROCKETVAULT_ADDR environment variable, then the current named context.
// Returns (nil, nil) if none resolve — the caller is in local mode.
func ResolveTarget(serverFlag string) (*Target, error) {
	if serverFlag != "" {
		return &Target{Server: serverFlag}, nil
	}
	if server := os.Getenv("ROCKETVAULT_ADDR"); server != "" {
		return &Target{Server: server}, nil
	}
	ctx, _, err := common.CurrentContext()
	if err != nil {
		return nil, err
	}
	if ctx != nil {
		return &Target{Server: ctx.Server, Username: ctx.Username, Vault: ctx.Vault}, nil
	}
	return nil, nil
}
```

- [ ] **Step 4: Wire root.go — add the `--server` flag and guard the config panic**

In `cmd/root.go`, add to the `import` block:

```go
	"rocketvault/internal/cliclient"
```

In `func init()`, immediately after the existing `rootCmd.PersistentFlags().String("vault", ...)` block:

```go
	rootCmd.PersistentFlags().String("server", "", "Remote RocketVault server URL (default: local mode against .rocketvault.yaml)")
```

Replace the body of `initConfig()`'s config-read error handling:

```go
	// If a config file is found, read it in. A missing/unreadable config
	// file is fatal in local mode (today's behavior, unchanged) but not in
	// remote mode — remote mode needs no local database or crypto config at
	// all, only a target server.
	if err := viper.ReadInConfig(); err != nil {
		serverFlag, _ := rootCmd.PersistentFlags().GetString("server")
		target, targetErr := cliclient.ResolveTarget(serverFlag)
		if targetErr != nil || target == nil {
			log.Panicf("Error reading config file: %v (%s)", err, viper.ConfigFileUsed())
		}
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/cliclient/... ./cmd/... -v`
Expected: PASS — all new tests, plus every pre-existing test in `cmd/root_test.go` (local-mode-without-config-file behavior is unchanged: `ROCKETVAULT_ADDR` unset in those tests, so the panic still fires for local mode exactly as before).

- [ ] **Step 6: Commit**

```bash
git add internal/cliclient/resolve.go internal/cliclient/resolve_test.go cmd/root.go cmd/root_test.go
git commit -m "feat(cli): add remote-target resolver, --server flag, and config-panic guard"
```

---

### Task 4: Shared remote HTTP client with TLS trust

**Files:**
- Create: `internal/cliclient/httpclient.go`
- Test: `internal/cliclient/httpclient_test.go`
- Modify: `cmd/root.go`

**Interfaces:**
- Consumes: nothing from earlier tasks (standalone).
- Produces: `cliclient.HTTPClientOptions{CACertPath, InsecureSkipVerify}`, `cliclient.NewHTTPClient(opts) (*http.Client, error)`, `cliclient.WarnIfInsecure(opts)`. Follow-on resource-group plans use `NewHTTPClient` to build every `remote*Client`'s transport.

- [ ] **Step 1: Write the failing tests**

```go
// internal/cliclient/httpclient_test.go
package cliclient

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewHTTPClient_DefaultVerification_RejectsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	client, err := NewHTTPClient(HTTPClientOptions{})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := client.Get(srv.URL); err == nil {
		t.Fatal("expected TLS verification error against a self-signed server, got nil")
	}
}

func TestNewHTTPClient_CACertPath_AcceptsMatchingServer(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	certPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := srv.Certificate().Raw
	os.WriteFile(certPath, pemEncode(pemBytes), 0600)

	client, err := NewHTTPClient(HTTPClientOptions{CACertPath: certPath})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := client.Get(srv.URL); err != nil {
		t.Fatalf("expected success trusting the test server's own cert, got: %v", err)
	}
}

func TestNewHTTPClient_InsecureSkipVerify_AcceptsAnything(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	client, err := NewHTTPClient(HTTPClientOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := client.Get(srv.URL); err != nil {
		t.Fatalf("expected success with InsecureSkipVerify, got: %v", err)
	}
}
```

Add this small test helper to the same file (encodes a raw DER cert as PEM for the CA-cert test above):

```go
func pemEncode(der []byte) []byte {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(block)
}
```

Add `"encoding/pem"` to the test file's imports.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cliclient/... -run TestNewHTTPClient -v`
Expected: FAIL — `HTTPClientOptions`, `NewHTTPClient` undefined.

- [ ] **Step 3: Implement**

```go
// internal/cliclient/httpclient.go
package cliclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// HTTPClientOptions configures the shared remote HTTP client's TLS trust.
type HTTPClientOptions struct {
	CACertPath         string // --ca-cert / ROCKETVAULT_CA_CERT
	InsecureSkipVerify bool   // --insecure-skip-verify
}

// NewHTTPClient builds the *http.Client every remote*Client implementation
// uses, honoring the TLS trust options above. A non-empty CACertPath is
// added to the system trust pool. InsecureSkipVerify disables certificate
// verification entirely — callers must have already warned the user via
// WarnIfInsecure before calling this.
func NewHTTPClient(opts HTTPClientOptions) (*http.Client, error) {
	tlsConfig := &tls.Config{}

	if opts.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if opts.CACertPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pemBytes, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert %q: %w", opts.CACertPath, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid certificates found in %q", opts.CACertPath)
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

// WarnIfInsecure prints a prominent warning to stderr when
// InsecureSkipVerify is set. Must be called once per invocation before any
// request is made — never silently.
func WarnIfInsecure(opts HTTPClientOptions) {
	if opts.InsecureSkipVerify {
		fmt.Fprintln(os.Stderr, "WARNING: TLS certificate verification is DISABLED (--insecure-skip-verify). Do not use against an untrusted network.")
	}
}
```

- [ ] **Step 4: Wire root.go — add `--ca-cert` and `--insecure-skip-verify` flags**

In `func init()`, immediately after the `--server` flag added in Task 3:

```go
	rootCmd.PersistentFlags().String("ca-cert", "", "Path to an additional CA certificate to trust for remote server connections (or set ROCKETVAULT_CA_CERT)")
	rootCmd.PersistentFlags().Bool("insecure-skip-verify", false, "Disable TLS certificate verification for remote server connections (unsafe — dev/test only)")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/cliclient/... ./cmd/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cliclient/httpclient.go internal/cliclient/httpclient_test.go cmd/root.go
git commit -m "feat(cli): add TLS-aware remote HTTP client and trust flags"
```

---

### Task 5: Local-only refusal helper

**Files:**
- Create: `internal/cliclient/localonly.go`
- Test: `internal/cliclient/localonly_test.go`

**Interfaces:**
- Consumes: `cliclient.ResolveTarget` (Task 3).
- Produces: `cliclient.RequireLocal(serverFlag, commandName string) error`. Follow-on plans call this as the first line of `backup create/restore`, `master-key rotate`, `vaults purge`, `vaults recover`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/cliclient/localonly_test.go
package cliclient

import (
	"strings"
	"testing"
)

func TestRequireLocal_NoTarget_ReturnsNil(t *testing.T) {
	t.Setenv("ROCKETVAULT_ADDR", "")
	if err := RequireLocal("", "master-key rotate"); err != nil {
		t.Fatalf("RequireLocal() = %v, want nil (local mode)", err)
	}
}

func TestRequireLocal_ServerFlagSet_ReturnsError(t *testing.T) {
	err := RequireLocal("https://vault.prod.example.com", "master-key rotate")
	if err == nil {
		t.Fatal("RequireLocal() = nil, want an error when a remote target is resolved")
	}
	for _, want := range []string{"master-key rotate", "local-only", "--server"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message %q missing expected substring %q", err.Error(), want)
		}
	}
}

func TestRequireLocal_EnvSet_ReturnsError(t *testing.T) {
	t.Setenv("ROCKETVAULT_ADDR", "https://vault.prod.example.com")
	if err := RequireLocal("", "backup create"); err == nil {
		t.Fatal("RequireLocal() = nil, want an error when ROCKETVAULT_ADDR is set")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cliclient/... -run TestRequireLocal -v`
Expected: FAIL — `RequireLocal` undefined.

- [ ] **Step 3: Implement**

```go
// internal/cliclient/localonly.go
package cliclient

import "fmt"

// RequireLocal returns an error if a remote target is configured, for
// commands with no server-side HTTP route to call: backup create/restore,
// master-key rotate, vaults purge/recover (see the design doc's Command
// Support Matrix). commandName is used in the error message, e.g.
// "master-key rotate". Returns nil in local mode.
func RequireLocal(serverFlag, commandName string) error {
	target, err := ResolveTarget(serverFlag)
	if err != nil {
		return err
	}
	if target != nil {
		return fmt.Errorf(
			"%s is a local-only operation and cannot target a remote server; "+
				"unset --server / ROCKETVAULT_ADDR / the active context to run it "+
				"against this machine's own instance",
			commandName,
		)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cliclient/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cliclient/localonly.go internal/cliclient/localonly_test.go
git commit -m "feat(cli): add explicit local-only refusal helper for unremotable commands"
```

*(Wiring `RequireLocal` into `cmd/backup.go`, `cmd/master_key.go`, `cmd/vaults/purge.go`, and `cmd/vaults/recover.go` is deferred to the follow-on vaults/backup/master-key plan — this task only builds and tests the helper itself.)*

---

### Task 6: `context` CLI command group

**Files:**
- Create: `cmd/context/add.go`, `cmd/context/list.go`, `cmd/context/use.go`, `cmd/context/current.go`, `cmd/context/remove.go`
- Create: `cmd/context.go` (parent command, package `cmd`, mirrors the existing `cmd/vault_access.go` pattern)
- Test: `cmd/context/add_test.go`, `cmd/context/use_test.go`

**Interfaces:**
- Consumes: `common.AddContext`/`ListContexts`/`UseContext`/`CurrentContext`/`RemoveContext` (Task 2); the persistent `--server` flag registered on `rootCmd` (Task 3), inherited by `context add`.

Package name note: the directory is `cmd/context/` but the package is declared `contextcli`, not `context` — avoiding a same-name collision with the standard library `context` package that any future addition to these files would otherwise hit. This mirrors the existing precedent of `cmd/vault-access/` declaring `package vaultaccess`.

- [ ] **Step 1: Write the failing tests**

```go
// cmd/context/add_test.go
package contextcli

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

func TestContextAdd_RequiresServerFlag(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	parent := &cobra.Command{Use: "context"}
	parent.PersistentFlags().String("server", "", "")
	InitContextAdd(parent)

	parent.SetArgs([]string{"add", "prod"})
	if err := parent.Execute(); err == nil {
		t.Fatal("expected an error when --server is not provided")
	}
}

func TestContextAdd_SavesContext(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	parent := &cobra.Command{Use: "context"}
	parent.PersistentFlags().String("server", "", "")
	InitContextAdd(parent)

	parent.SetArgs([]string{"add", "prod", "--server", "https://vault.prod.example.com", "--default-username", "admin"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	contexts, _, err := common.ListContexts()
	if err != nil {
		t.Fatalf("ListContexts: %v", err)
	}
	got, ok := contexts["prod"]
	if !ok || got.Server != "https://vault.prod.example.com" || got.Username != "admin" {
		t.Fatalf("contexts[prod] = %+v, ok=%v; want server/username set", got, ok)
	}
}
```

```go
// cmd/context/use_test.go
package contextcli

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

func TestContextUse_SetsCurrent(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")
	common.AddContext("staging", common.Context{Server: "https://vault.staging.example.com"})

	parent := &cobra.Command{Use: "context"}
	InitContextUse(parent)

	parent.SetArgs([]string{"use", "staging"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	_, name, err := common.CurrentContext()
	if err != nil || name != "staging" {
		t.Fatalf("CurrentContext() name = %q, %v; want staging", name, err)
	}
}

func TestContextUse_UnknownName_Errors(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	parent := &cobra.Command{Use: "context"}
	InitContextUse(parent)

	parent.SetArgs([]string{"use", "does-not-exist"})
	if err := parent.Execute(); err == nil {
		t.Fatal("expected an error using an unknown context name")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/context/... -v`
Expected: FAIL — package `contextcli` and its `InitContextAdd`/`InitContextUse` don't exist yet.

- [ ] **Step 3: Implement all five subcommands**

```go
// cmd/context/add.go
package contextcli

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

var addCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Save a named remote server context",
	Example: `  rocketvault context add prod --server https://vault.prod.example.com --default-username admin`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		server, _ := cmd.Flags().GetString("server")
		username, _ := cmd.Flags().GetString("default-username")
		vault, _ := cmd.Flags().GetString("default-vault")
		if server == "" {
			return fmt.Errorf("--server is required")
		}
		return common.AddContext(args[0], common.Context{Server: server, Username: username, Vault: vault})
	},
}

// InitContextAdd wires the "add" subcommand onto parent (rocketvault
// context's --server flag is inherited from the persistent flag on rootCmd).
func InitContextAdd(parent *cobra.Command) *cobra.Command {
	parent.AddCommand(addCmd)
	addCmd.Flags().String("default-username", "", "Default username for this context")
	addCmd.Flags().String("default-vault", "", "Default vault for this context")
	return parent
}
```

```go
// cmd/context/list.go
package contextcli

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/formatter"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List saved server contexts",
	RunE: func(cmd *cobra.Command, args []string) error {
		contexts, current, err := common.ListContexts()
		if err != nil {
			return err
		}

		fmtr, ok := cmd.Context().Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"Name", "Server", "Default Username", "Default Vault", "Current"}
		rows := make([][]string, 0, len(contexts))
		for name, ctx := range contexts {
			marker := ""
			if name == current {
				marker = "*"
			}
			rows = append(rows, []string{name, ctx.Server, ctx.Username, ctx.Vault, marker})
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
	},
}

func InitContextList(parent *cobra.Command) *cobra.Command {
	parent.AddCommand(listCmd)
	return parent
}
```

```go
// cmd/context/use.go
package contextcli

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

var useCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Set the current server context",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return common.UseContext(args[0])
	},
}

func InitContextUse(parent *cobra.Command) *cobra.Command {
	parent.AddCommand(useCmd)
	return parent
}
```

```go
// cmd/context/current.go
package contextcli

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

var currentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the current server context",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, name, err := common.CurrentContext()
		if err != nil {
			return err
		}
		if ctx == nil {
			fmt.Fprintln(cmd.OutOrStdout(), "no current context set (local mode)")
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s -> %s\n", name, ctx.Server)
		return nil
	},
}

func InitContextCurrent(parent *cobra.Command) *cobra.Command {
	parent.AddCommand(currentCmd)
	return parent
}
```

```go
// cmd/context/remove.go
package contextcli

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

var removeCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Delete a saved server context",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return common.RemoveContext(args[0])
	},
}

func InitContextRemove(parent *cobra.Command) *cobra.Command {
	parent.AddCommand(removeCmd)
	return parent
}
```

```go
// cmd/context.go
package cmd

import (
	"github.com/spf13/cobra"

	contextcli "rocketvault/cmd/context"
)

// contextCmd is the command group for named remote-server contexts.
var contextCmd = &cobra.Command{
	Use:   "context",
	Short: "Manage named remote RocketVault server contexts",
	Example: `  # Save and switch to a context
  rocketvault context add prod --server https://vault.prod.example.com --default-username admin
  rocketvault context use prod

  # See what's saved / active
  rocketvault context list
  rocketvault context current`,
}

func init() {
	rootCmd.AddCommand(contextCmd)
	contextcli.InitContextAdd(contextCmd)
	contextcli.InitContextList(contextCmd)
	contextcli.InitContextUse(contextCmd)
	contextcli.InitContextCurrent(contextCmd)
	contextcli.InitContextRemove(contextCmd)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/... -v`
Expected: PASS — all new tests, plus every pre-existing `cmd/` test unaffected.

- [ ] **Step 5: Build the whole binary to catch any wiring mistakes**

Run: `go build ./...`
Expected: succeeds with no errors.

- [ ] **Step 6: Commit**

```bash
git add cmd/context.go cmd/context/
git commit -m "feat(cli): add 'rocketvault context' command group"
```

---

## Plan Self-Review

**Spec coverage:**
- Server-aware session cache + non-breaking migration (spec §2) → Task 1. ✅
- Named contexts (spec §3) → Task 2, Task 6. ✅
- Target resolution precedence (spec §1) → Task 3. ✅
- Non-breaking backward compatibility, config-panic guard (spec Goals 2 & 4) → Task 3 Step 4. ✅
- TLS trust (spec §5) → Task 4. ✅
- Explicit local-only refusal (spec §6) → Task 5 (helper only; command wiring deferred and explicitly called out, not silently dropped). ✅
- Authentication in remote mode (spec §4), the adapter pattern and per-resource-group clients (spec Architecture section and Command Support Matrix) → explicitly out of scope for this plan, deferred to follow-on plans per the Scope Note. Not a gap — a deliberate boundary stated up front.

**Placeholder scan:** no TBD/TODO markers; every step has real, complete code; no "similar to Task N" shortcuts — Task 6's five subcommands are each written out in full despite their similarity.

**Type consistency:** `common.Context`, `common.LoadSessionForServer`, `common.SanitizeServerKey`, `cliclient.Target`, `cliclient.ResolveTarget`, `cliclient.HTTPClientOptions`, `cliclient.NewHTTPClient`, `cliclient.RequireLocal` are each defined exactly once (Tasks 1–5) and used with matching signatures in every later task and test that references them.

## Follow-on plans (not part of this plan)

Once this foundation lands, each resource group becomes its own plan,
repeating the now-proven adapter pattern (spec's "Component design" +
"Command support matrix" sections):

1. `secrets` remote adapter — the first, since it validates the whole
   pattern end-to-end against a real running server.
2. `keys` remote adapter.
3. `certificates` remote adapter.
4. `vaults` remote adapter (create/list/get/update/delete only) + wiring
   `RequireLocal` into `vaults purge`/`vaults recover`.
5. `vault-access` remote adapter.
6. `users` remote adapter (login, CRUD) + OIDC login's target-resolution
   update.
7. `audit` remote adapter.
8. Wiring `RequireLocal` into `backup create`/`restore` and `master-key
   rotate`.
