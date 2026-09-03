# vault-access Remote Adapter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `rocketvault vault-access grant/list/revoke` work against a remote server, and establish the adapter pattern the remaining five resource groups will copy.

**Architecture:** Each command keeps its existing `RunE` and gains an early remote branch that pulls the `*vaultapi.Client` from context, resolves the vault name, calls the typed method, converts the result to `model.*`, and prints exactly what local mode prints. Three shared pieces land here because every later group needs them: a vault resolver that honours `ROCKETVAULT_VAULT`, a type-conversion file, and a CLI-phrased error mapper.

**Tech Stack:** Go 1.24, cobra, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`

**Depends on:** `2026-09-03-cli-remote-vaultapi-02-token-source.md` — `common.RemoteClientKey` must exist and carry a `*vaultapi.Client`.

**This is the pattern proof.** If the shape here is wrong, it is far cheaper to learn it now than after keys, certificates, audit and vaults have copied it. Review this plan's output before starting plan 04.

## Global Constraints

- Local mode must remain byte-for-byte unchanged for any invocation that sets none of `--server`, `ROCKETVAULT_ADDR`, or a current context.
- A command that resolves a remote target must never silently fall back to operating on the local instance.
- Remote output must be identical to local output for the same command.
- Remote mode performs no client-side authorization check. The server owns that decision; the CLI maps its 401/403 into readable text.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Vault resolution that honours ROCKETVAULT_VAULT

Remote commands today resolve the vault as flag → `target.Vault` → `""` (`cmd/secrets/get.go:142-145` and five siblings), skipping the `ROCKETVAULT_VAULT` environment variable that local mode honours through `common.ResolveVaultName` (`common/vault_selector.go:15-28`). The same command therefore hits a different vault depending on mode.

**Files:**
- Create: `internal/cliclient/vault.go`
- Test: `internal/cliclient/vault_test.go`

**Interfaces:**
- Produces: `func ResolveRemoteVault(cmd *cobra.Command, target *Target) string`. Every later adapter calls it.

- [ ] **Step 1: Write the failing tests**

Create `internal/cliclient/vault_test.go`:

```go
package cliclient

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vaultTestCmd builds a command with a --vault flag, setting it only when
// flagValue is non-empty so Flags().Changed reflects real usage. It also
// clears any viper "vault" key so a developer's .rocketvault.yaml cannot
// change the result.
func vaultTestCmd(t *testing.T, flagValue string) *cobra.Command {
	t.Helper()
	viper.Set("vault", "")
	t.Cleanup(func() { viper.Set("vault", "") })

	c := &cobra.Command{}
	c.Flags().String("vault", "", "")
	if flagValue != "" {
		require.NoError(t, c.Flags().Set("vault", flagValue))
	}
	return c
}

func TestResolveRemoteVault_FlagWins(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "from-env")
	target := &Target{Vault: "from-context"}
	assert.Equal(t, "from-flag", ResolveRemoteVault(vaultTestCmd(t, "from-flag"), target))
}

func TestResolveRemoteVault_EnvBeatsContext(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "from-env")
	target := &Target{Vault: "from-context"}
	assert.Equal(t, "from-env", ResolveRemoteVault(vaultTestCmd(t, ""), target))
}

func TestResolveRemoteVault_ContextWhenNoFlagOrEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "")
	target := &Target{Vault: "from-context"}
	assert.Equal(t, "from-context", ResolveRemoteVault(vaultTestCmd(t, ""), target))
}

func TestResolveRemoteVault_DefaultsWhenNothingSet(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "")
	assert.Equal(t, "default", ResolveRemoteVault(vaultTestCmd(t, ""), &Target{}))
}

func TestResolveRemoteVault_NilTarget(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "")
	assert.Equal(t, "default", ResolveRemoteVault(vaultTestCmd(t, ""), nil))
}

// A flag left at a non-empty default is not an explicit choice, so an
// exported ROCKETVAULT_VAULT must still win. This mirrors
// common.ResolveVaultName's Flags().Changed test.
func TestResolveRemoteVault_UnchangedFlagDefaultLosesToEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "from-env")
	viper.Set("vault", "")
	t.Cleanup(func() { viper.Set("vault", "") })

	c := &cobra.Command{}
	c.Flags().String("vault", "flag-default", "")

	assert.Equal(t, "from-env", ResolveRemoteVault(c, &Target{}))
}

func TestResolveRemoteVault_ConfigBeatsOnlyTheDefault(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "")
	viper.Set("vault", "from-config")
	t.Cleanup(func() { viper.Set("vault", "") })

	c := &cobra.Command{}
	c.Flags().String("vault", "", "")

	assert.Equal(t, "from-config", ResolveRemoteVault(c, &Target{}))
	assert.Equal(t, "from-context", ResolveRemoteVault(c, &Target{Vault: "from-context"}))
}
```

Add `"github.com/spf13/viper"` to the test imports.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/cliclient/ -run TestResolveRemoteVault -v`
Expected: FAIL — `undefined: ResolveRemoteVault`.

- [ ] **Step 3: Implement**

Create `internal/cliclient/vault.go`:

```go
package cliclient

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/model"
)

// ResolveRemoteVault picks the vault a remote command operates on:
//
//	--vault flag > ROCKETVAULT_VAULT > the current context's default vault >
//	config "vault" key > "default"
//
// This is common.ResolveVaultName's precedence (common/vault_selector.go:15-28)
// with the context's default vault inserted after the environment variable. An
// exported variable is a narrower, more intentional statement than a default
// saved into a context months earlier, so it wins; the config file is a
// machine-wide default and loses to both.
//
// Remote commands previously resolved --vault then the context default and
// skipped the environment variable entirely, so the same command could address
// different vaults in the two modes.
//
// The flag test is Flags().Changed, matching ResolveVaultName: a flag left at a
// non-empty *default* must not outrank an explicitly exported variable.
func ResolveRemoteVault(cmd *cobra.Command, target *Target) string {
	if cmd != nil && cmd.Flags().Changed("vault") {
		if v, _ := cmd.Flags().GetString("vault"); v != "" {
			return v
		}
	}
	if v := os.Getenv("ROCKETVAULT_VAULT"); v != "" {
		return v
	}
	if target != nil && target.Vault != "" {
		return target.Vault
	}
	if v := viper.GetString("vault"); v != "" {
		return v
	}
	return model.DefaultVaultName
}
```

`model.DefaultVaultName` is `"default"` (`model/vault.go:14`) — use the constant, never the literal.

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/cliclient/ -run TestResolveRemoteVault -v`
Expected: PASS, all five.

- [ ] **Step 5: Commit**

```bash
git add internal/cliclient/vault.go internal/cliclient/vault_test.go
git commit -S -m "feat(cli): resolve the remote vault from the environment too

Remote commands resolved --vault then the context's default, skipping
ROCKETVAULT_VAULT, which local mode honours. The same command could
therefore address different vaults in the two modes."
```

---

### Task 2: CLI-phrased error mapping

`vaultapi.APIError` carries an operator-facing `Hint` derived only from the request line — it never reads the response body, so a secret value cannot leak into an error string. CLI copy differs: the current `secretsAPIError` tells the user which flags to re-run with.

**Files:**
- Create: `internal/cliclient/apierror.go`
- Test: `internal/cliclient/apierror_test.go`

**Interfaces:**
- Produces: `func CLIError(op string, err error) error` — wraps a `*vaultapi.APIError` in CLI-phrased text, passing any other error through unchanged.

- [ ] **Step 1: Write the failing tests**

```go
package cliclient

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultapi"
)

func TestCLIError_Unauthorized_TellsUserHowToReauthenticate(t *testing.T) {
	err := CLIError("grant a role", &vaultapi.APIError{
		StatusCode: http.StatusUnauthorized,
		Kind:       vaultapi.KindUnauthorized,
		Method:     http.MethodPost,
		Path:       "/api/v1/vaults/payments/role-assignments",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "grant a role")
	assert.Contains(t, err.Error(), "--username")
}

func TestCLIError_Forbidden_NamesTheAuthorizationCause(t *testing.T) {
	err := CLIError("grant a role", &vaultapi.APIError{
		StatusCode: http.StatusForbidden,
		Kind:       vaultapi.KindForbidden,
		Method:     http.MethodPost,
		Path:       "/api/v1/vaults/payments/role-assignments",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment")
}

func TestCLIError_NotFound(t *testing.T) {
	err := CLIError("list role assignments", &vaultapi.APIError{
		StatusCode: http.StatusNotFound,
		Kind:       vaultapi.KindNotFound,
		Method:     http.MethodGet,
		Path:       "/api/v1/vaults/nope/role-assignments",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCLIError_NonAPIError_PassesThrough(t *testing.T) {
	original := errors.New("dial tcp: connection refused")
	err := CLIError("grant a role", original)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestCLIError_Nil(t *testing.T) {
	assert.NoError(t, CLIError("grant a role", nil))
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/cliclient/ -run TestCLIError -v`
Expected: FAIL — `undefined: CLIError`.

- [ ] **Step 3: Implement**

```go
package cliclient

import (
	"errors"
	"fmt"

	"rocketvault/internal/vaultapi"
)

// CLIError turns a vaultapi error into text phrased for a CLI user. vaultapi's
// own Hint is written for an operator reading a server log; a person at a
// terminal needs to know which flag to reach for instead.
//
// Any error that is not a *vaultapi.APIError passes through with op for
// context -- transport failures already read clearly.
func CLIError(op string, err error) error {
	if err == nil {
		return nil
	}

	var apiErr *vaultapi.APIError
	if !errors.As(err, &apiErr) {
		return fmt.Errorf("failed to %s: %w", op, err)
	}

	switch apiErr.Kind {
	case vaultapi.KindUnauthorized:
		return fmt.Errorf(
			"failed to %s: the session token was rejected; re-run with --username/--password/--totp-code to re-authenticate, or run 'rocketvault users login'", op)
	case vaultapi.KindForbidden:
		return fmt.Errorf(
			"failed to %s: no role assignment in this vault grants the required action", op)
	case vaultapi.KindNotFound:
		return fmt.Errorf("failed to %s: not found", op)
	case vaultapi.KindConflict:
		return fmt.Errorf("failed to %s: it already exists", op)
	case vaultapi.KindServer:
		return fmt.Errorf("failed to %s: the server returned an error (HTTP %d)", op, apiErr.StatusCode)
	default:
		return fmt.Errorf("failed to %s: %w", op, err)
	}
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/cliclient/ -run TestCLIError -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cliclient/apierror.go internal/cliclient/apierror_test.go
git commit -S -m "feat(cli): phrase vaultapi errors for a terminal user

vaultapi's Hint is written for an operator reading a server log. Someone
at a prompt needs to know which flag to reach for, so map ErrorKind onto
CLI copy, preserving the wording the secrets adapter uses today."
```

---

### Task 3: Role-assignment type conversion

**Files:**
- Create: `internal/cliclient/convert.go`
- Test: `internal/cliclient/convert_test.go`

**Interfaces:**
- Produces: `func RoleAssignmentFromAPI(r *vaultapi.RoleAssignment) model.RoleAssignmentResponse`. Later plans add `SecretFromAPI`, `KeyFromAPI`, `CertificateFromAPI`, `VaultFromAPI` to this same file.

- [ ] **Step 1: Write the failing tests**

```go
package cliclient

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/vaultapi"
	"rocketvault/model"
)

func TestRoleAssignmentFromAPI_MapsEveryField(t *testing.T) {
	id, principalID := uuid.New(), uuid.New()
	got := RoleAssignmentFromAPI(&vaultapi.RoleAssignment{
		ID:                id,
		PrincipalID:       principalID,
		PrincipalUsername: "alice",
		PrincipalType:     "user",
		Role:              "Key Vault Administrator",
		VaultName:         "payments",
		CreatedAt:         "2026-09-03T10:00:00Z",
	})

	assert.Equal(t, id.String(), got.ID)
	assert.Equal(t, principalID.String(), got.PrincipalID)
	assert.Equal(t, "alice", got.PrincipalUsername)
	assert.Equal(t, "user", got.PrincipalType)
	assert.Equal(t, "Key Vault Administrator", got.Role)
	assert.Equal(t, "payments", got.VaultName)
	assert.Equal(t, "2026-09-03T10:00:00Z", got.CreatedAt)
}

// unmappedRoleAssignmentFields are the model fields the API response cannot
// supply. Each needs a reason. Adding a field to RoleAssignmentResponse
// without mapping it fails this test rather than silently dropping it from
// remote output.
var unmappedRoleAssignmentFields = map[string]string{
	"VaultID":             "the API returns vault_name, not the id; the CLI addresses vaults by name in remote mode",
	"ExpandedPolicyCount": "server-side derived field, not present in the role-assignments response",
}

func TestRoleAssignmentFromAPI_EveryModelFieldIsAccountedFor(t *testing.T) {
	populated := RoleAssignmentFromAPI(&vaultapi.RoleAssignment{
		ID:                uuid.New(),
		PrincipalID:       uuid.New(),
		PrincipalUsername: "alice",
		PrincipalType:     "user",
		Role:              "Key Vault Administrator",
		VaultName:         "payments",
		CreatedAt:         "2026-09-03T10:00:00Z",
	})

	v := reflect.ValueOf(populated)
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if _, expected := unmappedRoleAssignmentFields[name]; expected {
			continue
		}
		assert.Falsef(t, v.Field(i).IsZero(),
			"model.RoleAssignmentResponse.%s is not set by RoleAssignmentFromAPI; map it, or add it to unmappedRoleAssignmentFields with a reason",
			name)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/cliclient/ -run TestRoleAssignmentFromAPI -v`
Expected: FAIL — `undefined: RoleAssignmentFromAPI`.

- [ ] **Step 3: Implement**

```go
package cliclient

import (
	"rocketvault/internal/vaultapi"
	"rocketvault/model"
)

// RoleAssignmentFromAPI converts the API client's role assignment into the
// model type the CLI's output code already formats, so remote and local
// output are identical.
//
// VaultID is left empty: the API returns vault_name and the CLI addresses
// vaults by name in remote mode. See unmappedRoleAssignmentFields in the
// test for the full accounting.
func RoleAssignmentFromAPI(r *vaultapi.RoleAssignment) model.RoleAssignmentResponse {
	if r == nil {
		return model.RoleAssignmentResponse{}
	}
	return model.RoleAssignmentResponse{
		ID:                r.ID.String(),
		PrincipalID:       r.PrincipalID.String(),
		PrincipalUsername: r.PrincipalUsername,
		PrincipalType:     r.PrincipalType,
		Role:              r.Role,
		VaultName:         r.VaultName,
		CreatedAt:         r.CreatedAt,
	}
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/cliclient/ -run TestRoleAssignmentFromAPI -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cliclient/convert.go internal/cliclient/convert_test.go
git commit -S -m "feat(cli): convert vaultapi role assignments to model types

Keeps command output code untouched so local and remote print
identically. A completeness test fails when a model field is added
without being mapped, rather than dropping it from remote output."
```

---

### Task 4: Remote branch for `vault-access grant`

**Files:**
- Modify: `cmd/vault-access/grant.go`
- Test: `cmd/vault-access/grant_remote_test.go`

**Interfaces:**
- Consumes: `cliclient.ResolveRemoteVault`, `cliclient.CLIError`, `cliclient.RoleAssignmentFromAPI`, `common.RemoteClientKey`, `common.RemoteTargetKey`.
- Produces: `func runGrantRemote(cmd *cobra.Command, client *vaultapi.Client, target *cliclient.Target, principal, role, ptype string) error` — the shape later groups copy.

- [ ] **Step 1: Write the failing test**

Create `cmd/vault-access/grant_remote_test.go`:

```go
package vaultaccess

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/vaultapi"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

func TestGrantRemote_PostsToTheVaultScopedRoute(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody vaultapi.GrantRoleRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                 uuid.New().String(),
			"principal_id":       uuid.New().String(),
			"principal_username": "alice",
			"principal_type":     "user",
			"role":               "Key Vault Administrator",
			"vault_name":         "payments",
			"created_at":         "2026-09-03T10:00:00Z",
		})
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "payments", "")
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetContext(context.Background())

	err = runGrantRemote(cmd, client, &cliclient.Target{Server: srv.URL},
		"alice", "Key Vault Administrator", "user")
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/vaults/payments/role-assignments", gotPath)
	assert.Equal(t, "Bearer tok", gotAuth)
	assert.Equal(t, "alice", gotBody.Principal)
	assert.Equal(t, "Key Vault Administrator", gotBody.Role)
	assert.Equal(t, "user", gotBody.PrincipalType)
	assert.Contains(t, out.String(), "granted Key Vault Administrator to alice")
}

func TestGrantRemote_ForbiddenIsReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "payments", "")
	cmd.SetContext(context.Background())

	err = runGrantRemote(cmd, client, &cliclient.Target{Server: srv.URL},
		"alice", "Key Vault Administrator", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment")
}
```

Add `"bytes"` to the import block.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/vault-access/ -run TestGrantRemote -v`
Expected: FAIL — `undefined: runGrantRemote`.

- [ ] **Step 3: Add the remote function and the dispatch branch**

Add to `cmd/vault-access/grant.go`:

```go
// runGrantRemote grants a role against a remote server. Remote mode runs no
// client-side authorization check: the server owns that decision, and its
// 403 is mapped into readable text rather than pre-empted here.
func runGrantRemote(
	cmd *cobra.Command,
	client *vaultapi.Client,
	target *cliclient.Target,
	principal, role, ptype string,
) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	ra, err := client.CreateRoleAssignment(cmd.Context(), vault, vaultapi.GrantRoleRequest{
		Principal:     principal,
		PrincipalType: ptype,
		Role:          role,
	})
	if err != nil {
		return cliclient.CLIError("grant a role", err)
	}

	resp := cliclient.RoleAssignmentFromAPI(ra)
	fmt.Fprintf(cmd.OutOrStdout(), "granted %s to %s in vault (assignment %s)\n", //nolint:errcheck
		resp.Role, principal, resp.ID)
	return nil
}
```

In the existing `RunE`, immediately after `ptype` is defaulted and before `callerID` is read:

```go
			ctx := cmd.Context()
			if client, ok := ctx.Value(common.RemoteClientKey).(*vaultapi.Client); ok && client != nil {
				target, _ := ctx.Value(common.RemoteTargetKey).(*cliclient.Target)
				return runGrantRemote(cmd, client, target, principal, role, ptype)
			}
```

The local path below it is unchanged.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/vault-access/ -run TestGrantRemote -v`
Expected: PASS, both.

- [ ] **Step 5: Confirm local mode is untouched**

Run: `go test ./cmd/vault-access/...`
Expected: PASS, including the pre-existing `authz_test.go` and `roles_test.go`.

- [ ] **Step 6: Commit**

```bash
git add cmd/vault-access/grant.go cmd/vault-access/grant_remote_test.go
git commit -S -m "feat(cli): grant vault roles against a remote server

vault-access grant gains a remote branch calling vaultapi's
CreateRoleAssignment, which has existed since the MCP server shipped but
was unreachable from the CLI. Local dispatch is unchanged."
```

---

### Task 5: Remote branches for `list` and `revoke`

**Files:**
- Modify: `cmd/vault-access/list.go`, `cmd/vault-access/revoke.go`
- Test: `cmd/vault-access/list_remote_test.go`, `cmd/vault-access/revoke_remote_test.go`

**Interfaces:**
- Produces: `runListRemote(cmd, client, target) error`, `runRevokeRemote(cmd, client, target, assignmentID string) error`.

- [ ] **Step 1: Write the failing tests**

`list_remote_test.go` asserts the GET path and that output matches local's column layout:

```go
func TestListRemote_PrintsSameColumnsAsLocal(t *testing.T) {
	id, principalID := uuid.New(), uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vaults/payments/role-assignments", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"role_assignments": []map[string]any{{
				"id": id.String(), "principal_id": principalID.String(),
				"principal_type": "user", "role": "Key Vault Administrator",
				"vault_name": "payments", "created_at": "2026-09-03T10:00:00Z",
			}},
			"total": 1,
		})
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "payments", "")
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetContext(context.Background())

	require.NoError(t, runListRemote(cmd, client, &cliclient.Target{Server: srv.URL}))

	got := out.String()
	assert.Contains(t, got, "ASSIGNMENT-ID")
	assert.Contains(t, got, "ROLE")
	assert.Contains(t, got, "PRINCIPAL-ID")
	assert.Contains(t, got, id.String())
	assert.Contains(t, got, "Key Vault Administrator")
}
```

`revoke_remote_test.go` asserts the DELETE path and that a non-UUID argument is rejected before any request is made:

```go
func TestRevokeRemote_DeletesByAssignmentID(t *testing.T) {
	id := uuid.New()
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "payments", "")
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetContext(context.Background())

	require.NoError(t, runRevokeRemote(cmd, client, &cliclient.Target{Server: srv.URL}, id.String()))
	assert.Equal(t, "/api/v1/vaults/payments/role-assignments/"+id.String(), gotPath)
	assert.Equal(t, http.MethodDelete, gotMethod)
	assert.Contains(t, out.String(), "revoked assignment "+id.String())
}

func TestRevokeRemote_RejectsPrincipalName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("no request should be made for a non-UUID argument")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "payments", "")
	cmd.SetContext(context.Background())

	err = runRevokeRemote(cmd, client, &cliclient.Target{Server: srv.URL}, "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assignment id")
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/vault-access/ -run "TestListRemote|TestRevokeRemote" -v`
Expected: FAIL — both functions undefined.

- [ ] **Step 3: Implement both**

In `cmd/vault-access/list.go`:

```go
// runListRemote lists role assignments from a remote server, printing the
// same columns the local path prints.
func runListRemote(cmd *cobra.Command, client *vaultapi.Client, target *cliclient.Target) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	list, _, err := client.ListRoleAssignments(cmd.Context(), vault, 0)
	if err != nil {
		return cliclient.CLIError("list role assignments", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%-38s %-20s %s\n", "ASSIGNMENT-ID", "ROLE", "PRINCIPAL-ID") //nolint:errcheck
	for i := range list {
		ra := cliclient.RoleAssignmentFromAPI(&list[i])
		fmt.Fprintf(out, "%-38s %-20s %s\n", ra.ID, ra.Role, ra.PrincipalID) //nolint:errcheck
	}
	return nil
}
```

In `cmd/vault-access/revoke.go`:

```go
// runRevokeRemote revokes one role assignment on a remote server.
// DeleteRoleAssignment rejects a non-UUID argument before issuing a request,
// since one principal can hold several roles in a vault and a name is
// ambiguous.
func runRevokeRemote(
	cmd *cobra.Command,
	client *vaultapi.Client,
	target *cliclient.Target,
	assignmentID string,
) error {
	vault := cliclient.ResolveRemoteVault(cmd, target)

	if err := client.DeleteRoleAssignment(cmd.Context(), vault, assignmentID); err != nil {
		return cliclient.CLIError("revoke a role assignment", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "revoked assignment %s\n", assignmentID) //nolint:errcheck
	return nil
}
```

Add the same dispatch branch used in Task 4 Step 3 to both commands' `RunE`, placed before any service-container lookup.

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./cmd/vault-access/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/vault-access/list.go cmd/vault-access/revoke.go cmd/vault-access/list_remote_test.go cmd/vault-access/revoke_remote_test.go
git commit -S -m "feat(cli): list and revoke vault roles against a remote server"
```

---

### Task 6: Let vault-access through the remote guard

Until this task, all three commands still fail with "not yet supported" — the guard runs before their `RunE`.

**Files:**
- Modify: `cmd/root.go:219-240` (`remoteCapableSecretsCommands`, `isRemoteCapableCommand`)
- Test: `cmd/root_test.go`

**Interfaces:**
- Produces: `isRemoteCapableCommand` generalized from one group to a per-group allowlist.

- [ ] **Step 1: Write the failing test**

```go
func TestIsRemoteCapableCommand_VaultAccess(t *testing.T) {
	parent := &cobra.Command{Use: "vault-access"}
	for _, name := range []string{"grant", "list", "revoke"} {
		child := &cobra.Command{Use: name}
		parent.AddCommand(child)
		assert.Truef(t, isRemoteCapableCommand(child), "vault-access %s must be remote-capable", name)
	}
}

// roles is local-only: it reads compiled-in definitions and never calls a
// server, so it must not be routed through the remote pre-run.
func TestIsRemoteCapableCommand_VaultAccessRolesIsNot(t *testing.T) {
	parent := &cobra.Command{Use: "vault-access"}
	child := &cobra.Command{Use: "roles"}
	parent.AddCommand(child)
	assert.False(t, isRemoteCapableCommand(child))
}

func TestIsRemoteCapableCommand_KeysStillGuarded(t *testing.T) {
	parent := &cobra.Command{Use: "keys"}
	child := &cobra.Command{Use: "list"}
	parent.AddCommand(child)
	assert.False(t, isRemoteCapableCommand(child), "keys has no adapter yet")
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/ -run TestIsRemoteCapableCommand -v`
Expected: FAIL on the `vault-access` cases.

- [ ] **Step 3: Generalize the allowlist**

Replace `remoteCapableSecretsCommands` and `isRemoteCapableCommand` in `cmd/root.go`:

```go
// remoteCapableCommands maps a command group to the subcommands within it
// that have a remote-mode adapter. A group appears here only once its
// commands call vaultapi; everything absent is refused by the remote-target
// guard rather than silently run against the local instance.
//
// "vault-access roles" is deliberately absent: it reads compiled-in role
// definitions and never contacts a server, so isLocalOnlyCommand handles it.
var remoteCapableCommands = map[string]map[string]bool{
	"secrets": {
		"list": true, "get": true, "create": true, "update": true,
		"delete": true, "export": true, "import": true,
	},
	"vault-access": {
		"grant": true, "list": true, "revoke": true,
	},
}

// isRemoteCapableCommand reports whether cmd has its own remote-mode adapter
// and should be let through the remote-target guard instead of rejected by it.
func isRemoteCapableCommand(cmd *cobra.Command) bool {
	if cmd.Parent() == nil {
		return false
	}
	return remoteCapableCommands[cmd.Parent().Name()][cmd.Name()]
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./cmd/... -v`
Expected: PASS, including the existing secrets remote-capability tests.

- [ ] **Step 5: Verify end to end against a real server**

```bash
go build -o rocketvault .
./rocketvault serve &
./rocketvault context use numericlabs
./rocketvault users login --username admin --password <pw> --totp-code <code>

./rocketvault vault-access grant admin --role "Key Vault Administrator" --vault payments
./rocketvault vault-access list --vault payments
./rocketvault vault-access revoke <assignment-id> --vault payments
```

Expected: the grant that opened this work now succeeds. Confirm `vault-access list` output matches the local run's columns exactly:

```bash
./rocketvault context unset
./rocketvault vault-access list --vault payments   # local
```

- [ ] **Step 6: Verify ROCKETVAULT_VAULT now applies**

```bash
./rocketvault context use numericlabs
ROCKETVAULT_VAULT=payments ./rocketvault vault-access list
```

Expected: lists `payments`, not the default vault. This is the defect fixed in Task 1.

- [ ] **Step 7: Commit**

```bash
git add cmd/root.go cmd/root_test.go
git commit -S -m "feat(cli): route vault-access through remote mode

The guard's allowlist becomes a per-group map rather than a secrets-only
special case, so each group joins as its adapter lands. vault-access
grant/list/revoke now reach a remote server; roles stays local-only.

This is the pattern the remaining groups copy: resolve the vault, call
vaultapi, convert to model types, print what local prints."
```

---

## Self-Review

**Spec coverage:** This plan implements spec phase 2 plus the three shared pieces the spec's §2 and §3 describe (conversion, vault resolution, error mapping). The spec's remaining phases (3–8) are out of scope by design — this is the pattern proof they depend on.

**Placeholder scan:** No TBDs. Task 1 Step 3 notes a fallback if `model.DefaultVaultName` does not exist, naming the source of truth to match rather than inventing a literal. Task 4's test needs `"bytes"` added to its imports, which is stated.

**Type consistency:** `ResolveRemoteVault(cmd, target) string` is defined in Task 1 and called in Tasks 4 and 5. `CLIError(op string, err error) error` is defined in Task 2 and called in Tasks 4 and 5. `RoleAssignmentFromAPI` returns `model.RoleAssignmentResponse` by value in Task 3 and is used that way in Tasks 4 and 5, taking `*vaultapi.RoleAssignment` — note Task 5 passes `&list[i]` because `ListRoleAssignments` returns a `[]RoleAssignment` by value.

**Open question for review after execution:** whether `runXRemote` functions should take the client and target as parameters (as here) or pull them from the context themselves. Parameters make them directly testable without building a context, which is why they are used here — but if the six-argument `runGrantRemote` signature grows awkward in the keys group, that is the signal to revisit before plan 04 copies it.
