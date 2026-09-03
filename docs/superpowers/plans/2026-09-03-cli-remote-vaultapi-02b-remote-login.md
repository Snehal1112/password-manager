# Remote Client Wiring and the `users` Front Door — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `remotePersistentPreRun` produce a `*vaultapi.Client`, delete `internal/cliclient/auth.go`, and give remote mode a front door — closing `.claude/known-bugs.md` § B54 by letting `users login` and `users logout` through the remote-target guard, and fixing the server-key defect in `logout` that the guard has been hiding.

**Architecture:** The pre-run stops threading a bearer token and a bare `http.Client` through the context and stashes a client instead. On top of that, `users login` inverts the pre-run contract every other remote command follows: the rest authenticate in the pre-run and then run; `login` *is* the authentication, so it cannot require a token before it starts. The pre-run therefore grows an unauthenticated branch that builds a client with no usable token source. `logout` takes the same branch — it only deletes a cached session file.

**Tech Stack:** Go 1.24, cobra, viper, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`

**Depends on:** `2026-09-03-cli-remote-vaultapi-02a-token-source.md` — `resolveRemoteTokenSource`, `vaultapi.LoginOptions` and `unauthenticatedSource` must all exist.

**Scope note:** The spec lists `users` under Non-goals. That exclusion was written about the `users` *resource* surface — CRUD and bootstrap admin, which `vaultapi` genuinely does not cover — not about authentication, which phase 2 already owns and for which `vaultapi.Login` exists. Only `login` and `logout` move here; the resource commands stay deferred to the `users` spec.

## Global Constraints

- Local mode must remain byte-for-byte unchanged for any invocation that sets none of `--server`, `ROCKETVAULT_ADDR`, or a current context, apart from the one deliberate output change in Task 3 (the JWT is no longer printed). In particular, local OIDC login must keep writing its audit record.
- A remote session must never be written over a local one, or vice versa: every session write and delete carries an explicit server key.
- The MCP server's in-chat login must stay memory-only — it must never write to `~/.rocketvault/sessions`.
- A command that resolves a remote target must never silently fall back to operating on the local instance.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Build a vaultapi.Client in the remote pre-run

**Files:**
- Modify: `cmd/root.go:493-537` (`remotePersistentPreRun`)
- Modify: `cmd/root.go:402-491` (delete `resolveRemoteAuthentication`)
- Modify: `common/context.go` — add `RemoteClientKey`
- Delete: `internal/cliclient/auth.go`, `internal/cliclient/auth_test.go`
- Test: `cmd/root_test.go`

**Interfaces:**
- Consumes: `resolveRemoteTokenSource` from `02a` Task 3.
- Produces: `common.RemoteClientKey` — context key carrying a `*vaultapi.Client`. Task 2, Task 3 and plans `03a`/`03b` read it.

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
	c.Flags().String("output", "table", "") // required: see below
	c.SetContext(context.Background())

	target := &cliclient.Target{Server: "https://vault.example.com"}
	require.NoError(t, remotePersistentPreRun(c, target))

	client, ok := c.Context().Value(common.RemoteClientKey).(*vaultapi.Client)
	require.True(t, ok, "remote pre-run must stash a *vaultapi.Client")
	require.NotNil(t, client)
}
```

The `output` flag is not optional. `remotePersistentPreRun` calls `cmd.Flags().GetString("output")`, which returns `""` for an unregistered flag, and `formatter.New("")` reports "unsupported output format" (`internal/formatter/formatter.go:32-33`) — so without it the test fails with `invalid --output value ""` and the real assertion is never reached. Do not "fix" the pre-run to accommodate that.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/ -run TestRemotePersistentPreRun_StashesVaultapiClient -v`
Expected: FAIL — `undefined: common.RemoteClientKey`.

- [ ] **Step 3: Add the context key**

Keys in `common/context.go` are pointer vars in one `var (...)` block (`context.go:12-41`), not string constants. Add alongside `RemoteTargetKey`/`RemoteHTTPClientKey` (`context.go:36,40`):

```go
	// RemoteClientKey carries the *vaultapi.Client a remote-mode command uses
	// for every API call. It replaces reading TokenKey and RemoteHTTPClientKey
	// separately: the client owns the token source and the transport.
	RemoteClientKey = &contextKey{"remote_client"}
```

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

Note what is deliberately gone: `common.TokenKey`, `common.UserIDKey`, and `common.RemoteHTTPClientKey` are no longer set by this function body. The token lives inside the client's token source, and `UserIDKey` was only read by local-mode authorization checks that remote mode does not run — the server authorizes instead. (Verified safe: `cmd/secrets/get.go:78-82` and its siblings read `UserIDKey` only after the remote branch has already returned.)

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

One thing worth knowing rather than debugging: for the service-account tier this `Token()` call performs the client-credentials POST inside the pre-run. That is correct, not a bug — it is the same network call the first API request would otherwise make.

- [ ] **Step 6: Delete resolveRemoteAuthentication and its tests**

Remove `resolveRemoteAuthentication` (`cmd/root.go:402-491`) and **all five** tests that call it directly, or the package will not compile:

- `TestResolveRemoteAuthentication_UsernamePassword_Success` (`cmd/root_test.go:623`)
- `TestResolveRemoteAuthentication_UsernameOnly_LoadsNamedCachedSession` (`:653`)
- `TestResolveRemoteAuthentication_CurrentSession_WrongServer_NotUsed` (`:672`)
- `TestResolveRemoteAuthentication_ExpiredCache_RefreshesTransparently` (`:687`)
- `TestResolveRemoteAuthentication_NoCredsNoCache_ReturnsError` (`:720`)

`02a` Task 3's `TestResolveRemoteTokenSource_*` tests cover the same five behaviours against the new selector.

Do **not** delete `TestPersistentPreRun_RemoteTarget_SecretsList_UsesRemoteAdapter` (`:736-789`). It drives the credential path end to end and must still pass: `cliclient.LoginRemote` and `vaultapi.Login` both POST `/api/v1/users/login` (`internal/cliclient/auth.go:25`, `internal/vaultapi/login.go:54`), so the test's handler sees the same request either way.

- [ ] **Step 7: Delete internal/cliclient/auth.go**

`LoginRemote` and `RefreshRemote` now have no callers. Confirm before deleting:

Run: `grep -rn "LoginRemote\|RefreshRemote" --include="*.go" . | grep -v "_test.go"`
Expected: no results outside `internal/cliclient/auth.go` itself.

Then remove `internal/cliclient/auth.go` and `internal/cliclient/auth_test.go`. `internal/cliclient/secrets.go` has no dependency on either, so the deletion is clean.

- [ ] **Step 8: Run the full suite**

Run: `go build ./... && go test ./... && golangci-lint run`
Expected: PASS. The route-contract test from plan 01 still passes; update **both** caller annotations in `api/route_contract_test.go:25-26` — line 25 credits `cliclient.LoginRemote` and line 26 `cliclient.RefreshRemote`. After this task both routes are reached only by `vaultapi` (`Client.Login` and `SessionSource.refresh`). The surrounding comments at lines 21, 60 and 63 also describe `internal/cliclient` as a caller; correct them too. Strings only — no compile effect, which is exactly why they will be missed otherwise.

- [ ] **Step 9: Verify remote secrets still work end to end**

```bash
go build -o rocketvault .
./rocketvault serve &
./rocketvault context use numericlabs
# `users login` is still refused by the remote-target guard here -- Task 2
# and Task 3 unblock it. The credential tier from 02a Task 3 is what makes
# this work in the meantime.
./rocketvault secrets list --username admin --password <pw> --totp-code <code>
./rocketvault secrets list
```

Expected: both succeed, the second with no credentials. Then verify the service-account path against a configured service account:

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
token and HTTP client transitionally until they move to vaultapi."
```

---

### Task 2: Let `users login`/`logout` through the remote-target guard

**Files:**
- Modify: `cmd/root.go:219-240` (`remoteCapableSecretsCommands`, `isRemoteCapableCommand`)
- Modify: `cmd/root.go` (`remotePersistentPreRun`, as rewritten in Task 1)
- Test: `cmd/root_test.go`

**Interfaces:**
- Consumes: `common.RemoteClientKey` (Task 1), `unauthenticatedSource` (`02a` Task 3).
- Produces: `remoteCapableCommands` (group-keyed allowlist) and `func isRemoteUnauthenticatedCommand(cmd *cobra.Command) bool` in `cmd/root.go`. Plan `03b` adds its own entry to that map.

- [ ] **Step 1: Write the failing test**

Add to `cmd/root_test.go`:

```go
func TestRemoteGuard_AllowsUsersLoginAndLogout(t *testing.T) {
	for _, name := range []string{"login", "logout"} {
		users := &cobra.Command{Use: "users"}
		sub := &cobra.Command{Use: name}
		users.AddCommand(sub)
		assert.True(t, isRemoteCapableCommand(sub), "%q must reach its remote adapter", name)
		assert.True(t, isRemoteUnauthenticatedCommand(sub), "%q must not be pre-authenticated", name)
	}
}

func TestRemoteGuard_StillBlocksUnmigratedGroups(t *testing.T) {
	keys := &cobra.Command{Use: "keys"}
	sub := &cobra.Command{Use: "list"}
	keys.AddCommand(sub)
	assert.False(t, isRemoteCapableCommand(sub))
}
```

Add a third test asserting that the unauthenticated pre-run stashes a `*vaultapi.Client` under `common.RemoteClientKey` **with no session cached on disk and no credentials passed** — the exact situation B54 describes, where today the pre-run fails before the command body runs. Register the same flags Task 1 Step 1's test does, `output` included.

The existing `TestIsRemoteCapableCommand` (`cmd/root_test.go:587`) keeps passing across this change; leave it alone.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/ -run TestRemoteGuard -v`
Expected: FAIL — `undefined: isRemoteUnauthenticatedCommand`.

- [ ] **Step 3: Widen the allowlist**

Replace `remoteCapableSecretsCommands` (`cmd/root.go:219-240`) with a group-keyed map, since the list is no longer secrets-only:

```go
// remoteCapableCommands maps a command group to the subcommands within it
// that have their own remote-mode adapter. Everything else still goes
// through the remote-target guard until its group's adapter plan lands, so
// adding a group here without writing its adapter exposes a command that
// will fail at the first API call.
var remoteCapableCommands = map[string]map[string]bool{
	"secrets": {"list": true, "get": true, "create": true, "update": true,
		"delete": true, "export": true, "import": true},
	"users": {"login": true, "logout": true},
}

func isRemoteCapableCommand(cmd *cobra.Command) bool {
	if cmd.Parent() == nil {
		return false
	}
	return remoteCapableCommands[cmd.Parent().Name()][cmd.Name()]
}

// isRemoteUnauthenticatedCommand reports whether cmd is remote-capable but
// must not be authenticated by the pre-run. "login" is what creates the
// session, so requiring one first is circular -- that circularity is B54.
// "logout" only deletes a cached session file and must keep working even
// when that session is expired or broken.
func isRemoteUnauthenticatedCommand(cmd *cobra.Command) bool {
	if cmd.Parent() == nil || cmd.Parent().Name() != "users" {
		return false
	}
	return cmd.Name() == "login" || cmd.Name() == "logout"
}
```

- [ ] **Step 4: Add the unauthenticated branch to the pre-run**

In `remotePersistentPreRun`, return early after the HTTP client is built and before `resolveRemoteTokenSource`:

```go
	if isRemoteUnauthenticatedCommand(cmd) {
		client, err := vaultapi.New(vaultapi.Config{
			BaseURL:    target.Server,
			HTTPClient: httpClient,
			Tokens:     unauthenticatedSource{},
		})
		if err != nil {
			return fmt.Errorf("failed to build remote API client: %w", err)
		}
		ctx := context.WithValue(cmd.Context(), common.RemoteTargetKey, target)
		ctx = context.WithValue(ctx, common.RemoteClientKey, client)
		ctx = context.WithValue(ctx, common.RemoteHTTPClientKey, httpClient)
		cmd.SetContext(ctx)
		return nil
	}
```

`Tokens` is not optional: `vaultapi.New` rejects a nil token source outright (`internal/vaultapi/client.go:82-84`). `unauthenticatedSource` from `02a` Task 3 is the right value — `Client.Login` never consults `c.tokens` (`login.go:53-66`, pinned by `TestClientLogin_SendsNoAuthorizationHeader`), so login works while any other call on this client fails loudly instead of sending an empty `Authorization` header.

`RemoteHTTPClientKey` is set here because Task 3's OIDC exchange needs the CA-aware transport. That is the one use that must outlive plan 08's removal of this key, or be converted to a `vaultapi` method at that point.

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./cmd/ -v`
Expected: PASS. `users login` now reaches its `RunE` with a context active; the command body still runs the local path, which Task 3 fixes.

- [ ] **Step 6: Commit**

```bash
git add cmd/root.go cmd/root_test.go
git commit -S -m "feat(cli): admit users login/logout to remote mode

The remote-capable allowlist was secrets-shaped; it becomes a map keyed
by command group. login and logout take a new unauthenticated pre-run
branch: login is what produces a session, so requiring one first is
circular, and logout only deletes a cached one.

The command bodies still run their local path -- the adapters land next."
```

---

### Task 3: Point `login`, `--oidc` and `logout` at the target

**Files:**
- Modify: `cmd/users/login.go`, `cmd/users/login_oidc.go`, `cmd/users/logout.go`
- Test: `cmd/users/login_password_test.go`, `cmd/users/logout_test.go`, `cmd/users/login_oidc_test.go`
- Modify: `.claude/known-bugs.md` (B54 → Fixed)

**Interfaces:**
- Consumes: `vaultapi.LoginOptions` (`02a` Task 1), `common.RemoteClientKey`/`RemoteTargetKey`/`RemoteHTTPClientKey` (Task 1, Task 2).
- Changes: `runLogout(username string)` → `runLogout(serverKey, username string)` in `cmd/users/logout.go`.
- Changes: `exchangeOIDCCode`'s signature gains an `*http.Client`.

- [ ] **Step 1: Write the failing tests**

Three behaviours, each currently wrong:

1. A remote password login writes `srv_<host>__<user>.json` and points `current` at it, leaving any local session file untouched.
2. A remote logout deletes the server-scoped file and leaves the local one intact; a local logout does the reverse.
3. `runLogout(remoteServerKey, "")` with a *local* current-session pointer reports "No cached session to log out of" rather than deleting the local session.

Point `common.SessionBaseDir` at a `t.TempDir()` in each, as the existing session tests do.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/users/ -v`
Expected: FAIL — the logout tests delete the wrong file; the login test has no remote path to exercise.

- [ ] **Step 3: Remote password login**

In `cmd/users/login.go`, branch **before** the service-container lookup at l.57-60 — remote mode has no container:

```go
	if target, ok := ctx.Value(common.RemoteTargetKey).(*cliclient.Target); ok && target != nil {
		return runRemoteLogin(cmd, target)
	}
```

`runRemoteLogin` reads the `*vaultapi.Client` from `common.RemoteClientKey`, honours `--oidc` by delegating to the OIDC path in Step 4, and otherwise:

```go
	username := viper.GetString("username")
	if username == "" {
		username = target.Username // context's default username, if any
	}
	_, identity, err := client.Login(ctx, username, password, totpCode, vaultapi.LoginOptions{
		Expiry:      viper.GetDuration("jwt.expiry"),
		SaveSession: common.SaveSession,
	})
```

The `target.Username` fallback matters: `cliclient.Target.Username` is documented as "default username from a context, if any; command flags still win" (`internal/cliclient/resolve.go:17`), and `02a`'s selector honours it. Without the fallback, `users login --password … --totp-code …` under a context that carries a username fails the "username, password, and totp-code are required" check.

`Login` already stamps `ServerKey` from the client's base URL (`internal/vaultapi/login.go:105`), so the session lands in the server-scoped file and the `current` pointer follows it — no extra wiring.

Then apply the agreed output change to **both** modes: replace
`fmt.Printf("Login successful, JWT token: %s\n", session.Token)` (`cmd/users/login.go:84`) with
`fmt.Printf("Login successful as %s.\n", session.Username)` locally, and the `identity.Username` equivalent on the remote path — the remote branch has no `session` variable, only the `LoginIdentity` that `Login` returns. A bearer token on stdout lands in shell history and CI logs for no benefit; the session is already cached. This matches what the `--oidc` path has always printed (`login_oidc.go:211`). No existing test asserts either the old or the new string, so nothing needs updating for it — do not go hunting.

- [ ] **Step 4: Make OIDC login target-aware**

`runOIDCLogin` (`cmd/users/login_oidc.go:177`) already speaks HTTP to a base URL rather than the service container, so this is small:

- Base URL becomes `target.Server` when a remote target is present, falling back to `frontend.public_api_url` in local mode. Keep the existing "not configured" error for the local case only.
- `exchangeOIDCCode` (`login_oidc.go:130-142`) uses `http.DefaultClient`, which ignores `--ca-cert` and `--insecure-skip-verify`. Thread the client from `common.RemoteHTTPClientKey` through as a parameter, defaulting to `http.DefaultClient` for local mode. This breaks three tests that call it directly — `TestExchangeOIDCCode_Success`, `TestExchangeOIDCCode_NonOKStatus_ReturnsError`, `TestExchangeOIDCCode_InvalidUserID_ReturnsError` (`login_oidc_test.go:100,127,138`) — which need the new argument.
- Stamp `ServerKey: common.SanitizeServerKey(baseURL)` on the session before `common.SaveSession`, or the remote OIDC session overwrites the local one.
- `exchangeOIDCCode` computes `ExpiresAt` from `viper.GetDuration("jwt.expiry")` (`login_oidc.go:168`), which is 0 in remote mode with no config file — the session would be born expired. Mirror `vaultapi.Login`'s fallback (`login.go:42-44`) and use a sane default when the duration is not positive.
- **Keep the service-container logger when the container is in context**, and use `logrus` only when it is absent. Do not drop it unconditionally: `LogAuditInfo` (`login_oidc.go:209`) persists an audit row through `auditPersister` (`internal/logging/logging.go:170-181`), so replacing it everywhere would silently stop local OIDC logins from being audited — a second local-mode behaviour change, which the constraints do not allow.

- [ ] **Step 5: Make logout server-scoped**

A second, latent bug, not recorded in B54's original entry: `runLogout` calls `common.DeleteSession(username)`, which is hardcoded to `LocalServerKey` (`common/session.go:263-265`), and its no-username path takes whatever `LoadCurrentSession` returns with no server check. Merely exempting `logout` from the guard would make it delete the **local** session while a context is active — the wrong file, silently, leaving the remote session it was asked to clear in place.

```go
// runLogout resolves which cached session to remove -- an explicit username,
// or whichever the current-session pointer references -- within one server's
// namespace, and deletes it. serverKey is common.LocalServerKey in local mode
// and SanitizeServerKey(target.Server) in remote mode: without it, logging out
// of a remote target would delete the local session instead.
func runLogout(serverKey, username string) error {
	if username == "" {
		current, err := common.LoadCurrentSession()
		if err != nil {
			return fmt.Errorf("failed to read current session: %w", err)
		}
		if current == nil || current.ServerKey != serverKey {
			fmt.Println("No cached session to log out of.")
			return nil
		}
		username = current.Username
	}

	if err := common.DeleteSessionForServer(serverKey, username); err != nil {
		return fmt.Errorf("failed to log out: %w", err)
	}
	fmt.Printf("Logged out %s.\n", username)
	return nil
}
```

There is one production call site — the `RunE` at `logout.go:50` — which derives `serverKey` from `ctx.Value(common.RemoteTargetKey)`, using `common.LocalServerKey` when absent.

Three existing tests call `runLogout` with one argument and need `common.LocalServerKey` prepended: `TestRunLogout_ExplicitUsername_DeletesThatSession`, `TestRunLogout_NoUsername_DeletesCurrentSession`, `TestRunLogout_NoUsernameNoCurrentSession_NoError` (`cmd/users/logout_test.go:17,28,38`). Their behaviour is unchanged — `LoadSessionForServer` normalises a blank key to `"local"` (`session.go:222-224`).

- [ ] **Step 6: Run the full suite**

Run: `go build ./... && go test ./... && golangci-lint run`
Expected: PASS.

- [ ] **Step 7: Verify end to end**

```bash
go build -o rocketvault .
./rocketvault serve &
./rocketvault context use numericlabs
./rocketvault users login --username admin --password <pw> --totp-code <code>
ls ~/.rocketvault/sessions/          # srv_<host>__admin.json, and `current` pointing at it
./rocketvault secrets list           # bare command, no credentials
./rocketvault users logout
./rocketvault secrets list           # must now fail with "no cached session"
```

Then confirm the local session was untouched throughout: `./rocketvault context unset` and run `./rocketvault secrets list` against the local instance.

- [ ] **Step 8: Close B54 and commit**

Move B54 in `.claude/known-bugs.md` to Fixed with this commit's hash, and record the `runLogout` server-key defect found while fixing it — the original entry describes only the `login` half.

```bash
git add -A
git commit -S -m "fix(cli): open the front door for remote login

users login now runs against a remote target instead of being refused by
the remote-target guard, so a remote session no longer has to be created
as a side effect of an unrelated secrets command. --oidc follows the
target too, and uses the CA-aware HTTP client rather than
http.DefaultClient.

logout becomes server-scoped: it deleted the local session regardless of
the active target, which would have been the wrong file the moment it was
let through the guard.

The JWT is no longer printed on successful login in either mode; the
session is cached, and a bearer token on stdout only leaks into shell
history and CI logs.

Fixes B54."
```

---

## Self-Review

**Spec coverage:** Task 1 completes spec phase 1 (the pre-run rewrite and `cliclient/auth.go`'s deletion). Tasks 2 and 3 cover the authentication half of the spec's deferred `users` group; the resource half has no `vaultapi` coverage at all and stays deferred, as the scope note records.

**Placeholder scan:** Task 2 Step 1's third test and Task 3 Step 1's three cases state intent rather than full code, because their assertions depend on helper names that vary by file; each names the behaviour to pin. No TBDs.

**Type consistency:** `common.RemoteClientKey` carries `*vaultapi.Client` in Task 1 and is read as that type in Tasks 2 and 3 and in plan `03b`. `unauthenticatedSource` satisfies `vaultapi.TokenSource` (`Token(context.Context) (string, error)`, `client.go:39-41`). `runLogout`'s signature changes in Task 3 Step 5 with its one production call site and three tests named.

**Ordering:** Task 1 must be first — Tasks 2 and 3 both consume `RemoteClientKey`. Between Task 2 and Task 3 the tree is consistent but `users login` with a context active runs the *local* login path; that is a transient state within one plan, not a shippable stopping point.

**Known risk:** Task 1 keeps `TokenKey`/`RemoteHTTPClientKey` alive transitionally so the secrets adapters keep working, and Task 2 Step 4 adds a second, non-transitional use of `RemoteHTTPClientKey` for the OIDC exchange. If plan 08 is never executed, the transitional code becomes permanent; when it is executed, the OIDC use must be converted rather than deleted. Worth a `known-bugs.md` entry if phases 3–7 stall.
