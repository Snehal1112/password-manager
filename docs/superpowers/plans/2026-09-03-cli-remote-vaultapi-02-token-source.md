# CLI Remote Auth on vaultapi TokenSource — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move CLI remote authentication onto `vaultapi`'s `TokenSource`, delete `internal/cliclient/auth.go`, and expose the service-account credentials flow that already exists but no CLI flag reaches.

**Architecture:** `remotePersistentPreRun` stops producing a bearer token string and starts producing a `*vaultapi.Client`. `resolveRemoteAuthentication` becomes a token-source selector: `ServiceAccountSource` when client credentials are supplied, `SessionSource` otherwise. Both already exist and are exercised by `rocketvault mcp`.

**Tech Stack:** Go 1.24, cobra, viper, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`

**Depends on:** `2026-09-03-cli-remote-vaultapi-01-refresh-fix-and-route-contract.md` — the route-contract test must exist before auth paths move, so a wrong path cannot be reintroduced silently.

## Global Constraints

- Local mode must remain byte-for-byte unchanged for any invocation that sets none of `--server`, `ROCKETVAULT_ADDR`, or a current context.
- A command that resolves a remote target must never silently fall back to operating on the local instance.
- Existing local-mode session cache files must keep working without forcing a re-login.
- `--insecure-skip-verify` must print a warning to stderr every time it is used, never silently.
- A cached "current" session belonging to a different server must never be used against this target (`cmd/root.go:446-448`).
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Client-credential flags and env fallback

**Files:**
- Modify: `cmd/root.go:150-165` (persistent flag registration)
- Test: `cmd/root_test.go`

**Interfaces:**
- Produces: `func clientCredentials(cmd *cobra.Command) (id, secret string)` in `cmd/root.go` — returns flag values, falling back to `ROCKETVAULT_CLIENT_ID` / `ROCKETVAULT_CLIENT_SECRET`. Returns two empty strings when neither source supplies a value. Task 2 consumes it.

- [ ] **Step 1: Write the failing test**

Add to `cmd/root_test.go`:

```go
func TestClientCredentials_FlagsWinOverEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "env-id")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "env-secret")

	c := &cobra.Command{}
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")
	require.NoError(t, c.Flags().Set("client-id", "flag-id"))
	require.NoError(t, c.Flags().Set("client-secret", "flag-secret"))

	id, secret := clientCredentials(c)
	assert.Equal(t, "flag-id", id)
	assert.Equal(t, "flag-secret", secret)
}

func TestClientCredentials_FallsBackToEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "env-id")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "env-secret")

	c := &cobra.Command{}
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	id, secret := clientCredentials(c)
	assert.Equal(t, "env-id", id)
	assert.Equal(t, "env-secret", secret)
}

func TestClientCredentials_UnsetIsEmpty(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "")

	c := &cobra.Command{}
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	id, secret := clientCredentials(c)
	assert.Empty(t, id)
	assert.Empty(t, secret)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/ -run TestClientCredentials -v`
Expected: FAIL — `undefined: clientCredentials`.

- [ ] **Step 3: Register the flags and add the helper**

In `cmd/root.go`, alongside the existing `--ca-cert` / `--insecure-skip-verify` registrations:

```go
	rootCmd.PersistentFlags().String("client-id", "",
		"Service-account client ID for unattended remote auth (or set ROCKETVAULT_CLIENT_ID)")
	rootCmd.PersistentFlags().String("client-secret", "",
		"Service-account client secret for unattended remote auth (or set ROCKETVAULT_CLIENT_SECRET)")
```

And the helper:

```go
// clientCredentials returns the service-account credentials for remote mode,
// preferring flags over the environment. Both values must be present for the
// service-account path to be selected; a half-configured pair is treated as
// unset so the caller can report it as a usage error rather than silently
// falling back to an interactive session.
func clientCredentials(cmd *cobra.Command) (string, string) {
	id, _ := cmd.Flags().GetString("client-id")
	if id == "" {
		id = os.Getenv("ROCKETVAULT_CLIENT_ID")
	}
	secret, _ := cmd.Flags().GetString("client-secret")
	if secret == "" {
		secret = os.Getenv("ROCKETVAULT_CLIENT_SECRET")
	}
	return id, secret
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/ -run TestClientCredentials -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/root.go cmd/root_test.go
git commit -S -m "feat(cli): add service-account credential flags

--client-id/--client-secret, with ROCKETVAULT_CLIENT_ID and
ROCKETVAULT_CLIENT_SECRET as the env fallback CI uses. Nothing consumes
them yet; the token-source selector lands next."
```

---

### Task 2: Token-source selector

Replaces `resolveRemoteAuthentication`'s hand-rolled login/refresh with a `vaultapi.TokenSource`.

**Files:**
- Modify: `cmd/root.go:402-491` (replace `resolveRemoteAuthentication`)
- Test: `cmd/root_test.go`

**Interfaces:**
- Consumes: `clientCredentials` from Task 1; `vaultapi.NewServiceAccountSource(vaultapi.ServiceAccountConfig{BaseURL, ClientID, ClientSecret, HTTPClient})`; `vaultapi.NewSessionSource(vaultapi.SessionConfig{BaseURL, HTTPClient, LoadSession, SaveSession})`.
- Produces: `func resolveRemoteTokenSource(cmd *cobra.Command, target *cliclient.Target, httpClient *http.Client) (vaultapi.TokenSource, error)`. Task 3 consumes it.

- [ ] **Step 1: Write the failing tests**

Add to `cmd/root_test.go`:

```go
func TestResolveRemoteTokenSource_ClientCredentials_UsesServiceAccount(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "svc-id")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "svc-secret")
	common.SessionBaseDir = t.TempDir() // no session cached at all

	target := &cliclient.Target{Server: "https://vault.example.com"}
	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	src, err := resolveRemoteTokenSource(c, target, http.DefaultClient)
	require.NoError(t, err, "service-account auth must not require a cached session")
	assert.IsType(t, &vaultapi.ServiceAccountSource{}, src)
}

func TestResolveRemoteTokenSource_NoCredentials_UsesSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	serverKey := common.SanitizeServerKey("https://vault.example.com")
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "tok", RefreshToken: "refresh", Username: "admin",
		ServerKey: serverKey, ExpiresAt: time.Now().Add(time.Hour),
	}))

	target := &cliclient.Target{Server: "https://vault.example.com"}
	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	src, err := resolveRemoteTokenSource(c, target, http.DefaultClient)
	require.NoError(t, err)
	assert.IsType(t, &vaultapi.SessionSource{}, src)
}

// A cached session for a different server must never be used against this
// target -- the "current" pointer is global across servers.
func TestResolveRemoteTokenSource_CurrentSession_WrongServer_Refused(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "other-server-tok", Username: "admin",
		ServerKey: common.SanitizeServerKey("https://other.example.com"),
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	target := &cliclient.Target{Server: "https://vault.prod.example.com"}
	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	_, err := resolveRemoteTokenSource(c, target, http.DefaultClient)
	require.Error(t, err, "a cached session for a different server must not be reused")
}

func TestResolveRemoteTokenSource_HalfCredentials_IsUsageError(t *testing.T) {
	t.Setenv("ROCKETVAULT_CLIENT_ID", "svc-id")
	t.Setenv("ROCKETVAULT_CLIENT_SECRET", "")
	common.SessionBaseDir = t.TempDir()

	target := &cliclient.Target{Server: "https://vault.example.com"}
	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	_, err := resolveRemoteTokenSource(c, target, http.DefaultClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client-secret")
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/ -run TestResolveRemoteTokenSource -v`
Expected: FAIL — `undefined: resolveRemoteTokenSource`.

- [ ] **Step 3: Implement the selector**

Add to `cmd/root.go`, leaving the old `resolveRemoteAuthentication` in place for now (Task 3 deletes it):

```go
// resolveRemoteTokenSource picks how the CLI authenticates against target.
//
// Service-account credentials take precedence: they are the unattended CI
// path and write nothing to disk. Otherwise the cached CLI session is used,
// which refreshes itself through vaultapi.SessionSource.
//
// The "current" session pointer is global across servers (see
// common/session.go), so a cached current session is only accepted when it
// belongs to this target -- otherwise a different server's token could leak
// into a request against this one.
func resolveRemoteTokenSource(
	cmd *cobra.Command,
	target *cliclient.Target,
	httpClient *http.Client,
) (vaultapi.TokenSource, error) {
	clientID, clientSecret := clientCredentials(cmd)
	switch {
	case clientID != "" && clientSecret != "":
		return vaultapi.NewServiceAccountSource(vaultapi.ServiceAccountConfig{
			BaseURL:      target.Server,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			HTTPClient:   httpClient,
		})
	case clientID != "":
		return nil, fmt.Errorf("--client-id given without --client-secret (or ROCKETVAULT_CLIENT_SECRET)")
	case clientSecret != "":
		return nil, fmt.Errorf("--client-secret given without --client-id (or ROCKETVAULT_CLIENT_ID)")
	}

	serverKey := common.SanitizeServerKey(target.Server)
	username, _ := cmd.Flags().GetString("username")
	if username == "" {
		username = target.Username
	}

	load := func() (*common.SessionCache, error) {
		if username != "" {
			return common.LoadSessionForServer(serverKey, username)
		}
		cached, err := common.LoadCurrentSession()
		if err != nil {
			return nil, err
		}
		if cached != nil && cached.ServerKey != serverKey {
			return nil, fmt.Errorf(
				"the current session belongs to a different server; run 'rocketvault users login' against %s or pass --username",
				target.Server)
		}
		return cached, nil
	}

	src, err := vaultapi.NewSessionSource(vaultapi.SessionConfig{
		BaseURL:     target.Server,
		HTTPClient:  httpClient,
		LoadSession: load,
	})
	if err != nil {
		if errors.Is(err, vaultapi.ErrNoSession) {
			return nil, fmt.Errorf(
				"no cached session for server %s; run 'rocketvault users login' or pass --client-id/--client-secret",
				target.Server)
		}
		return nil, err
	}
	return src, nil
}
```

`SessionConfig.SaveSession` is left nil deliberately: the default is `common.SaveSession`, which is what the current code calls after a refresh.

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./cmd/ -run TestResolveRemoteTokenSource -v`
Expected: PASS, all four.

- [ ] **Step 5: Commit**

```bash
git add cmd/root.go cmd/root_test.go
git commit -S -m "feat(cli): select a vaultapi TokenSource for remote auth

Service-account credentials take the client-credentials grant; otherwise
the cached CLI session is used through vaultapi.SessionSource, which
refreshes against the route that exists. The wrong-server guard on the
global current-session pointer is preserved.

Nothing calls this yet -- remotePersistentPreRun moves over next."
```

---

### Task 3: Build a vaultapi.Client in the remote pre-run

**Files:**
- Modify: `cmd/root.go:493-537` (`remotePersistentPreRun`)
- Modify: `cmd/root.go:402-491` (delete `resolveRemoteAuthentication`)
- Modify: `common/context_keys.go` (or wherever `RemoteTargetKey` is declared) — add `RemoteClientKey`
- Test: `cmd/root_test.go`

**Interfaces:**
- Consumes: `resolveRemoteTokenSource` from Task 2.
- Produces: `common.RemoteClientKey` — context key carrying a `*vaultapi.Client`. Plan 03's adapters read it.

- [ ] **Step 1: Write the failing test**

```go
func TestRemotePersistentPreRun_StashesVaultapiClient(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	serverKey := common.SanitizeServerKey("https://vault.example.com")
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "tok", RefreshToken: "refresh", Username: "admin",
		ServerKey: serverKey, ExpiresAt: time.Now().Add(time.Hour),
	}))

	c := newAuthTestCmd("", "", "")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")
	c.Flags().String("ca-cert", "", "")
	c.Flags().Bool("insecure-skip-verify", false, "")
	c.SetContext(context.Background())

	target := &cliclient.Target{Server: "https://vault.example.com"}
	require.NoError(t, remotePersistentPreRun(c, target))

	client, ok := c.Context().Value(common.RemoteClientKey).(*vaultapi.Client)
	require.True(t, ok, "remote pre-run must stash a *vaultapi.Client")
	require.NotNil(t, client)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/ -run TestRemotePersistentPreRun_StashesVaultapiClient -v`
Expected: FAIL — `undefined: common.RemoteClientKey`.

- [ ] **Step 3: Add the context key**

Next to the existing `RemoteTargetKey` / `RemoteHTTPClientKey` declarations in `common`:

```go
	// RemoteClientKey carries the *vaultapi.Client a remote-mode command uses
	// for every API call. It replaces reading TokenKey and RemoteHTTPClientKey
	// separately: the client owns the token source and the transport.
	RemoteClientKey contextKey = "remote_client"
```

Match the surrounding declarations' type and style exactly — if the existing keys are a different type than `contextKey`, use theirs.

- [ ] **Step 4: Rewrite remotePersistentPreRun**

```go
// remotePersistentPreRun is the remote-mode counterpart of persistentPreRun
// for commands with their own remote adapter (see isRemoteCapableCommand).
// It never boots the local DB or service container: it configures a TLS
// trust-aware HTTP client, picks a token source, and stashes a vaultapi
// client in the command's context for the adapter to use.
func remotePersistentPreRun(cmd *cobra.Command, target *cliclient.Target) error {
	caCertPath, _ := cmd.Flags().GetString("ca-cert")
	if caCertPath == "" {
		caCertPath = os.Getenv("ROCKETVAULT_CA_CERT")
	}
	insecureSkipVerify, _ := cmd.Flags().GetBool("insecure-skip-verify")

	opts := cliclient.HTTPClientOptions{CACertPath: caCertPath, InsecureSkipVerify: insecureSkipVerify}
	cliclient.WarnIfInsecure(opts)
	httpClient, err := cliclient.NewHTTPClient(opts)
	if err != nil {
		return fmt.Errorf("failed to configure remote TLS trust: %w", err)
	}

	tokens, err := resolveRemoteTokenSource(cmd, target, httpClient)
	if err != nil {
		cmd.PrintErrln("Error: remote authentication failed -", err.Error())
		return errors.New("remote authentication failed")
	}

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:    target.Server,
		HTTPClient: httpClient,
		Tokens:     tokens,
	})
	if err != nil {
		return fmt.Errorf("failed to build remote API client: %w", err)
	}

	outputFlag, _ := cmd.Flags().GetString("output")
	fmtr, fmtrErr := formatter.New(formatter.Format(outputFlag))
	if fmtrErr != nil {
		return fmt.Errorf("invalid --output value %q: must be table, json, or yaml", outputFlag)
	}

	ctx := context.WithValue(cmd.Context(), common.RemoteTargetKey, target)
	ctx = context.WithValue(ctx, common.RemoteClientKey, client)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
	cmd.SetContext(ctx)

	logrus.WithFields(logrus.Fields{
		"command": cmd.Short,
		"server":  target.Server,
	}).Info("Authenticated against remote server")
	return nil
}
```

Note what is deliberately gone: `common.TokenKey`, `common.UserIDKey`, and `common.RemoteHTTPClientKey` are no longer set on the remote path. The token lives inside the client's token source, and `UserIDKey` was only read by local-mode authorization checks that remote mode does not run — the server authorizes instead.

- [ ] **Step 5: Update the secrets adapters to the new keys**

`cmd/secrets/*.go` currently read `common.TokenKey` and `common.RemoteHTTPClientKey` (e.g. `cmd/secrets/get.go:129-136`). They keep calling `cliclient.*SecretsRemote` for now — plan 08 migrates them — so they still need a token and an HTTP client. Reconstruct both from the client's inputs by keeping the two old keys set alongside the new one during this transitional phase:

```go
	ctx = context.WithValue(ctx, common.RemoteHTTPClientKey, httpClient)
	token, tokErr := tokens.Token(cmd.Context())
	if tokErr != nil {
		cmd.PrintErrln("Error: remote authentication failed -", tokErr.Error())
		return errors.New("remote authentication failed")
	}
	ctx = context.WithValue(ctx, common.TokenKey, token)
```

Add this to the context assembly in Step 4, with a comment marking it transitional and naming plan 08 as the removal point. Without it, every `secrets` remote command breaks at this task.

- [ ] **Step 6: Delete resolveRemoteAuthentication and its tests**

Remove `resolveRemoteAuthentication` (`cmd/root.go:402-491`) and the tests that exercise it directly, including `TestResolveRemoteAuthentication_CurrentSession_WrongServer_NotUsed` and `TestResolveRemoteAuthentication_ExpiredCache_RefreshesTransparently` — Task 2's `TestResolveRemoteTokenSource_*` tests cover the same behaviours against the new selector.

- [ ] **Step 7: Delete internal/cliclient/auth.go**

`LoginRemote` and `RefreshRemote` now have no callers. Confirm before deleting:

Run: `grep -rn "LoginRemote\|RefreshRemote" --include="*.go" . | grep -v "_test.go"`
Expected: no results outside `internal/cliclient/auth.go` itself.

Then remove `internal/cliclient/auth.go` and `internal/cliclient/auth_test.go`.

- [ ] **Step 8: Run the full suite**

Run: `go build ./... && go test ./... && golangci-lint run`
Expected: PASS. The route-contract test from plan 01 still passes; its `cliclient.RefreshRemote` caller annotation should be updated to name `vaultapi.SessionSource.refresh` alone.

- [ ] **Step 9: Verify remote secrets still work end to end**

```bash
go build -o rocketvault .
./rocketvault serve &
./rocketvault context use numericlabs
./rocketvault users login --username admin --password <pw> --totp-code <code>
./rocketvault secrets list
```

Expected: the list succeeds. Then verify the service-account path against a configured service account:

```bash
ROCKETVAULT_CLIENT_ID=<id> ROCKETVAULT_CLIENT_SECRET=<secret> ./rocketvault secrets list
```

Expected: succeeds with no session file read or written.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -S -m "refactor(cli): authenticate remote mode through vaultapi

remotePersistentPreRun now builds a *vaultapi.Client and stashes it,
rather than threading a bearer token and a bare http.Client through the
context. Token acquisition moves to vaultapi's TokenSource, which the MCP
server has been using against this same session cache.

cliclient's LoginRemote/RefreshRemote are deleted; their only remaining
caller was the code this replaces. Secrets adapters keep receiving a
token and HTTP client transitionally until they move to vaultapi.

Service accounts now work from the CLI: --client-id/--client-secret take
the client-credentials grant and touch no session file."
```

---

### Task 4: Validate the server URL in `context add`

Small, and it belongs here: a context saved without a scheme fails at request time with an opaque transport error, which is confusing precisely when someone is first setting up remote mode.

**Files:**
- Modify: `cmd/context/add.go:42-44`
- Test: `cmd/context/add_test.go`

**Interfaces:**
- Produces: nothing importable.

- [ ] **Step 1: Write the failing test**

```go
func TestContextAdd_RejectsServerWithoutScheme(t *testing.T) {
	common.ContextFilePath = filepath.Join(t.TempDir(), "contexts.json")

	cmd := newAddCmdForTest(t)
	cmd.SetArgs([]string{"prod", "--server", "vault.example.com"})
	err := cmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheme")
}

func TestContextAdd_AcceptsHTTPS(t *testing.T) {
	common.ContextFilePath = filepath.Join(t.TempDir(), "contexts.json")

	cmd := newAddCmdForTest(t)
	cmd.SetArgs([]string{"prod", "--server", "https://vault.example.com"})
	require.NoError(t, cmd.Execute())
}
```

Match `newAddCmdForTest` to however the existing tests in `cmd/context/` construct a command; if no such helper exists, build the command with `InitContextAdd` onto a fresh parent.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/context/ -run TestContextAdd_Rejects -v`
Expected: FAIL — the malformed server is accepted.

- [ ] **Step 3: Validate**

In `cmd/context/add.go`, replace the non-empty check:

```go
			if server == "" {
				return fmt.Errorf("--server is required")
			}
			parsed, err := url.Parse(server)
			if err != nil {
				return fmt.Errorf("--server %q is not a valid URL: %w", server, err)
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				return fmt.Errorf(
					"--server %q needs an http:// or https:// scheme (got %q)", server, parsed.Scheme)
			}
			if parsed.Host == "" {
				return fmt.Errorf("--server %q has no host", server)
			}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/context/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/context/add.go cmd/context/add_test.go
git commit -S -m "fix(cli): validate the server URL in context add

A context saved as 'vault.example.com' was accepted and then failed at
request time with an opaque transport error, which is confusing exactly
when someone is first configuring remote mode."
```

---

### Task 5: Correct the stale help text and docs

**Files:**
- Modify: `cmd/context/use.go:16-17`
- Modify: `docs/usage-guide.md` (the remote-target guard paragraph)

- [ ] **Step 1: Fix the help text**

`cmd/context/use.go` claims "no other command yet acts on the current context", which the secrets adapters made false. Replace with a statement of what is actually true after this plan:

```go
		Long: `Mark a saved context as current, so later commands target its server.

Commands with a remote adapter act on it directly. Every other command
refuses to run while a context is current, rather than silently operating
on the local instance -- run 'context unset' to return to local mode.`,
```

- [ ] **Step 2: Fix the usage guide**

In `docs/usage-guide.md`, the paragraph beginning "A remote-target guard now blocks nearly every command" states "no resource command (`secrets`, `keys`, `certificate`, `users`, etc.) actually talks to a remote server yet". That has been false since the secrets adapter landed on 2026-08-24. Replace it with an accurate statement naming which groups are remote-capable at this commit.

- [ ] **Step 3: Verify**

Run: `go build ./... && ./rocketvault context use --help`
Expected: the new text, with no claim that nothing acts on the context.

- [ ] **Step 4: Commit**

```bash
git add cmd/context/use.go docs/usage-guide.md
git commit -S -m "docs(cli): correct stale claims about remote mode

Both the 'context use' help text and the usage guide stated that no
command acts on the current context, which stopped being true when the
secrets adapter landed on 2026-08-24."
```

---

## Self-Review

**Spec coverage:** This plan implements spec phase 1 (token source selection, service-account flags, deleting `cliclient/auth.go`) plus the `context add` validation and two of the three documentation corrections the spec lists. The KB correction (`known-issues-gotchas.md`) is outside this repo and is left to the `kb-refresh` skill.

**Placeholder scan:** Two steps intentionally defer to surrounding code rather than prescribing it — the `contextKey` type in Task 3 Step 3 and `newAddCmdForTest` in Task 4 Step 1 — because both must match existing local convention that varies by file. Each says so explicitly and states what to match. No TBDs.

**Type consistency:** `resolveRemoteTokenSource` returns `vaultapi.TokenSource` in Task 2 and is consumed as such in Task 3. `clientCredentials` returns `(string, string)` in Task 1 and is destructured that way in Task 2. `common.RemoteClientKey` carries `*vaultapi.Client` in Task 3 and is read as that type in plan 03.

**Known risk:** Task 3 Step 5 keeps `TokenKey`/`RemoteHTTPClientKey` alive transitionally so the secrets adapters keep working. If plan 08 is never executed, that transitional code becomes permanent. The comment naming plan 08 is the only thing marking it — worth a `known-bugs.md` entry if phases 3–7 stall.
