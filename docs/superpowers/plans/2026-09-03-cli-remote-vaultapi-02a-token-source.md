# CLI Remote Auth on vaultapi TokenSource — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the CLI's hand-rolled remote login/refresh with a `vaultapi.TokenSource`, and expose the service-account credentials flow that already exists but no CLI flag reaches — without losing the `--username/--password/--totp-code` login that is remote mode's only working entry point today.

**Architecture:** `resolveRemoteAuthentication` becomes `resolveRemoteTokenSource`, a three-tier selector: service-account credentials, then a fresh credential login, then the cached session. All three tiers are `vaultapi` types. `vaultapi.Login` gains the ability to persist the session it creates, which is what lets the middle tier replace `cliclient.LoginRemote` without behaviour loss.

**Tech Stack:** Go 1.24, cobra, viper, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`

**Depends on:** `2026-09-03-cli-remote-vaultapi-01-refresh-fix-and-route-contract.md` — the route-contract test must exist before auth paths move, so a wrong path cannot be reintroduced silently.

**Followed by:** `…-02b-remote-login.md` (the pre-run rewrite and the `users` front door, closing B54), then `…-02c-context-validation-and-docs.md`. Phase 2 was split so no plan carries more than three tasks; run them in that order.

## Global Constraints

- Local mode must remain byte-for-byte unchanged for any invocation that sets none of `--server`, `ROCKETVAULT_ADDR`, or a current context.
- A command that resolves a remote target must never silently fall back to operating on the local instance.
- **No remote authentication path may be removed.** `--username/--password/--totp-code` against a remote target works today and must keep working: until `02b` lands, it is the only way a human can create a remote session (B54).
- Existing local-mode session cache files must keep working without forcing a re-login.
- `--insecure-skip-verify` must print a warning to stderr every time it is used, never silently.
- A cached "current" session belonging to a different server must never be used against this target (`cmd/root.go:446-448`).
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Let `vaultapi.Login` persist the session it creates

`Client.Login` returns a `TokenSource` and a `LoginIdentity`, neither of which exposes the access or refresh token, and it seeds the source through `NewSessionSourceFromCache`, whose `SaveSession` defaults to a **no-op** on purpose (`internal/vaultapi/sessionsource.go:98-101` — the MCP in-chat login is deliberately memory-only). So no caller can persist the session it just created. Task 3's fresh-login tier cannot exist until this does.

**Files:**
- Modify: `internal/vaultapi/login.go`
- Modify: `internal/mcpserver/tools_login.go:44` (only production caller)
- Test: `internal/vaultapi/login_test.go`

**Interfaces:**
- Produces: `vaultapi.LoginOptions{Expiry time.Duration; SaveSession func(*common.SessionCache) error}` — replaces `Client.Login`'s trailing `expiry time.Duration` parameter. Task 3 consumes it, as does `02b` Task 3.

- [ ] **Step 1: Write the failing test**

Add to `internal/vaultapi/login_test.go`. Use the file's existing helpers — `newTestClient(t, srv.URL, srv.Client())` for the client and `stubTokenSource{}` (`swappablesource_test.go:12`) or `staticToken` (`testhelpers_test.go:7`) for a token source — rather than inventing new ones. The file currently imports neither `assert` nor `rocketvault/common`; both are needed.

```go
func TestLogin_PersistsSessionWhenSaveSessionSupplied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "tok", "refresh_token": "refresh",
			"user_id":  "0f2b6f1e-0000-0000-0000-000000000001",
			"username": "admin", "roles": []string{"admin"},
		})
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, srv.Client())

	var saved *common.SessionCache
	_, identity, err := client.Login(context.Background(), "admin", "pw", "123456", LoginOptions{
		Expiry:      time.Hour,
		SaveSession: func(s *common.SessionCache) error { saved = s; return nil },
	})
	require.NoError(t, err)
	assert.Equal(t, "admin", identity.Username)

	require.NotNil(t, saved, "Login must persist through the supplied hook")
	assert.Equal(t, "tok", saved.Token)
	assert.Equal(t, "refresh", saved.RefreshToken)
	assert.Equal(t, common.SanitizeServerKey(srv.URL), saved.ServerKey)
}
```

Add a second test, `TestLogin_NilSaveSessionWritesNothing`, pinning the MCP contract: with `LoginOptions{Expiry: time.Hour}` and `common.SessionBaseDir` pointed at a `t.TempDir()`, the login succeeds and the directory stays empty.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestLogin_ -v`
Expected: FAIL — `undefined: LoginOptions`.

- [ ] **Step 3: Add LoginOptions**

In `internal/vaultapi/login.go`:

```go
// LoginOptions carries the caller-specific parts of a login: how long the
// access token lives, and whether the resulting session is persisted.
//
// SaveSession is nil for an in-memory login (the MCP server's in-chat
// login tool) and common.SaveSession for the CLI, which caches the session
// so later commands run without credentials. It is called once with the
// session Login creates, and again by the SessionSource on every refresh,
// so the two paths cannot drift.
type LoginOptions struct {
	// Expiry is the access-token lifetime (jwt.expiry). Zero or negative
	// uses defaultLoginExpiry -- which is what a caller with no config
	// file loaded passes, so the session is not born already expired.
	Expiry time.Duration
	// SaveSession persists the session. Nil means this login is
	// memory-only and writes nothing.
	SaveSession func(*common.SessionCache) error
}
```

Change the signature to
`func (c *Client) Login(ctx context.Context, username, password, totpCode string, opts LoginOptions) (TokenSource, LoginIdentity, error)`,
read `opts.Expiry` where `expiry` is read today, and after the `session` value is built:

```go
	if opts.SaveSession != nil {
		if err := opts.SaveSession(session); err != nil {
			return nil, LoginIdentity{}, fmt.Errorf("vaultapi: authenticated but failed to cache session: %w", err)
		}
	}

	source, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL:     c.baseURL,
		HTTPClient:  c.http,
		SaveSession: opts.SaveSession, // nil keeps the no-op default
	}, session)
```

The explicit save matters: `SessionSource` only writes on refresh, so without it nothing reaches disk until the first token expiry.

- [ ] **Step 4: Update every caller**

Four existing tests pass `time.Hour` positionally and must become `LoginOptions{Expiry: time.Hour}`: `TestClientLogin_Success`, `TestClientLogin_RejectionDoesNotEchoBody`, `TestClientLogin_MissingTokenInResponseIsAnError`, `TestClientLogin_SendsNoAuthorizationHeader` (`internal/vaultapi/login_test.go:46,65,79,93`).

The one production caller, `internal/mcpserver/tools_login.go:44`, becomes:

```go
	source, identity, err := s.client.Login(ctx, args.Username, args.Password, args.TOTPCode,
		vaultapi.LoginOptions{Expiry: s.jwtExpiry})
```

Passing no `SaveSession` preserves today's memory-only behaviour exactly. No mcpserver *test* calls `client.Login` directly — `tools_login_test.go` drives the tool through `CallTool` — so do not go looking for ones to update there.

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/vaultapi/... ./internal/mcpserver/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/vaultapi/login.go internal/vaultapi/login_test.go internal/mcpserver/tools_login.go
git commit -S -m "feat(vaultapi): let Login persist the session it creates

Login returned a TokenSource and a LoginIdentity, neither of which
exposes a token, and seeded the source with the no-op SaveSession that
keeps the MCP server's in-chat login memory-only. No caller could cache
the session, which blocks the CLI's credential-login path from moving
off cliclient.

The trailing expiry parameter becomes LoginOptions{Expiry, SaveSession}.
The MCP server passes no hook and is unchanged in behaviour."
```

---

### Task 2: Client-credential flags and env fallback

**Files:**
- Modify: `cmd/root.go:150-165` (persistent flag registration)
- Test: `cmd/root_test.go`

**Interfaces:**
- Produces: `func clientCredentials(cmd *cobra.Command) (id, secret string)` in `cmd/root.go` — returns flag values, falling back to `ROCKETVAULT_CLIENT_ID` / `ROCKETVAULT_CLIENT_SECRET`. Returns two empty strings when neither source supplies a value. Task 3 consumes it.

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

### Task 3: Token-source selector

Replaces `resolveRemoteAuthentication`'s hand-rolled login/refresh with a `vaultapi.TokenSource`, preserving all three of its authentication tiers.

**Files:**
- Modify: `cmd/root.go:402-491` (add alongside `resolveRemoteAuthentication`; `02b` Task 1 deletes the old one)
- Test: `cmd/root_test.go`

**Interfaces:**
- Consumes: `clientCredentials` from Task 2; `vaultapi.LoginOptions` from Task 1; `vaultapi.NewServiceAccountSource(vaultapi.ServiceAccountConfig{BaseURL, ClientID, ClientSecret, HTTPClient})`; `vaultapi.NewSessionSource(vaultapi.SessionConfig{BaseURL, HTTPClient, LoadSession, SaveSession})`.
- Produces: `func resolveRemoteTokenSource(cmd *cobra.Command, target *cliclient.Target, httpClient *http.Client) (vaultapi.TokenSource, error)`. `02b` Task 1 consumes it.
- Produces: `type unauthenticatedSource struct{}` in `cmd/root.go`. `02b` Task 2 reuses it for the `users login`/`logout` pre-run branch.

**Precedence — do not change it.** Today's `resolveRemoteAuthentication` (`cmd/root.go:411-491`) is: fresh login when `--username` and `--password` are both set, else a cached session for an explicit `--username`, else whichever session is "current" (rejected if it belongs to another server). This task adds service accounts *above* that and re-expresses the rest in `vaultapi` types. Dropping the fresh-login tier would break `TestPersistentPreRun_RemoteTarget_SecretsList_UsesRemoteAdapter` (`cmd/root_test.go:736-789`), which drives `secrets list --server … --username … --password … --totp-code …` and asserts the server's `/api/v1/users/login` endpoint was called — and would leave no way to authenticate remotely at all until `02b` lands.

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

// The credential tier must survive the move to vaultapi: it is the only way
// to authenticate remotely until users login is unguarded in 02b.
func TestResolveRemoteTokenSource_UsernamePassword_LogsInAndCaches(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	var loginHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		loginHit = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "tok", "refresh_token": "refresh",
			"user_id":  "0f2b6f1e-0000-0000-0000-000000000001",
			"username": "admin", "roles": []string{"admin"},
		})
	}))
	defer srv.Close()

	target := &cliclient.Target{Server: srv.URL}
	c := newAuthTestCmd("admin", "pass123", "123456")
	c.Flags().String("client-id", "", "")
	c.Flags().String("client-secret", "", "")

	src, err := resolveRemoteTokenSource(c, target, srv.Client())
	require.NoError(t, err)
	assert.True(t, loginHit, "credentials must produce a real login call")

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "tok", tok)

	cached, err := common.LoadSessionForServer(common.SanitizeServerKey(srv.URL), "admin")
	require.NoError(t, err)
	require.NotNil(t, cached, "a credential login must cache its session")
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

`newAuthTestCmd(username, password, totpCode)` already exists in `cmd/root_test.go` and registers those three flags; confirm its signature before use.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/ -run TestResolveRemoteTokenSource -v`
Expected: FAIL — `undefined: resolveRemoteTokenSource`.

- [ ] **Step 3: Implement the selector**

Add to `cmd/root.go`, leaving the old `resolveRemoteAuthentication` in place for now (`02b` Task 1 deletes it):

```go
// unauthenticatedSource is the token source for a client that must not send
// a bearer token: the credential-login bootstrap below, and the users
// login/logout pre-run branch in 02b. vaultapi.Config requires a non-nil
// Tokens (internal/vaultapi/client.go:82-84), and Client.Login is the one
// method that never consults it (login.go:53-66, pinned by
// TestClientLogin_SendsNoAuthorizationHeader). Any other call on such a
// client fails here loudly rather than sending an empty Authorization
// header.
type unauthenticatedSource struct{}

func (unauthenticatedSource) Token(context.Context) (string, error) {
	return "", errors.New("this command runs unauthenticated; run 'rocketvault users login' first")
}

// resolveRemoteTokenSource picks how the CLI authenticates against target.
//
// Three tiers, in precedence order:
//
//  1. Service-account credentials -- the unattended CI path. Writes nothing
//     to disk.
//  2. An explicit --username/--password -- the user asking to re-authenticate.
//     Caches the resulting session, exactly as the pre-vaultapi code did.
//  3. The cached CLI session, which refreshes itself through
//     vaultapi.SessionSource.
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
		username = target.Username // context's default username, if any
	}

	if password, _ := cmd.Flags().GetString("password"); username != "" && password != "" {
		totpCode, _ := cmd.Flags().GetString("totp-code")
		client, err := vaultapi.New(vaultapi.Config{
			BaseURL:    target.Server,
			HTTPClient: httpClient,
			Tokens:     unauthenticatedSource{},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to build login client: %w", err)
		}
		src, _, err := client.Login(cmd.Context(), username, password, totpCode, vaultapi.LoginOptions{
			Expiry:      viper.GetDuration("jwt.expiry"),
			SaveSession: common.SaveSession,
		})
		return src, err
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
				"no cached session for server %s; run 'rocketvault users login' or pass --username/--password/--totp-code or --client-id/--client-secret",
				target.Server)
		}
		return nil, err
	}
	return src, nil
}
```

Two notes for the implementer:

- `SessionConfig.SaveSession` is left nil deliberately in the third tier: the default is `common.SaveSession`, which is what the current code calls after a refresh.
- `viper.GetDuration("jwt.expiry")` is 0 when no config file is loaded, which is normal in remote mode. `LoginOptions` falls back to `defaultLoginExpiry` for exactly that case, so the session is not born expired.

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./cmd/ -run TestResolveRemoteTokenSource -v`
Expected: PASS, all five.

- [ ] **Step 5: Commit**

```bash
git add cmd/root.go cmd/root_test.go
git commit -S -m "feat(cli): select a vaultapi TokenSource for remote auth

Three tiers, preserving today's precedence and adding service accounts
above it: client credentials take the client-credentials grant;
--username/--password performs a real login through vaultapi.Login and
caches the session; otherwise the cached session is used through
vaultapi.SessionSource, which refreshes against the route that exists.
The wrong-server guard on the global current-session pointer is
preserved.

Nothing calls this yet -- remotePersistentPreRun moves over in 02b."
```

---

## Self-Review

**Spec coverage:** This plan implements spec phase 1's authentication core: the `Login` persistence hook, the service-account flags, and the token-source selector. The pre-run rewrite and the deletion of `internal/cliclient/auth.go` move to `02b`, which is where the code that calls this selector is rewritten. `02c` carries the phase's `context add` validation and documentation corrections.

**Placeholder scan:** Two steps state test intent rather than full code — Task 1 Step 1's second test, and the `newAuthTestCmd` signature check in Task 3 Step 1 — because both depend on helper names in files whose conventions vary. Each names the behaviour to pin and the file to match. No TBDs.

**Type consistency:** `LoginOptions` is produced in Task 1 Step 3 and consumed in Task 3 Step 3 and in `02b` Task 3. `clientCredentials` returns `(string, string)` in Task 2 and is destructured that way in Task 3. `resolveRemoteTokenSource` returns `vaultapi.TokenSource` and is consumed as such in `02b` Task 1. `unauthenticatedSource` is defined in Task 3 and reused in `02b` Task 2 — it is defined here rather than there because the credential tier needs it first.

**Ordering:** Task 1 is independent of the rest and could ship alone. Task 2 is independent of Task 1. Task 3 needs both. The whole plan leaves `remotePersistentPreRun` untouched, so remote mode behaves exactly as it does today at every commit boundary — `resolveRemoteTokenSource` is dead code until `02b` Task 1 wires it in. That makes this plan safe to stop after.

**Known risk:** the credential tier is now the only thing keeping remote authentication reachable between this plan and `02b` Task 3. Its test (`TestResolveRemoteTokenSource_UsernamePassword_LogsInAndCaches`) and the pre-existing `TestPersistentPreRun_RemoteTarget_SecretsList_UsesRemoteAdapter` are both load-bearing; do not weaken either while making the suite pass.
