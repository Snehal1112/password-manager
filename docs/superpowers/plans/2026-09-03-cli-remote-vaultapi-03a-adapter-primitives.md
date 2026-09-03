# Remote Adapter Primitives — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three shared pieces every remote resource adapter needs, before the first adapter uses them: a vault resolver that honours `ROCKETVAULT_VAULT`, a CLI-phrased error mapper, and type conversion from `vaultapi` types to `model.*`.

**Architecture:** No command changes here. Each remote command branch will pull the `*vaultapi.Client` from context, resolve the vault name, call the typed method, convert the result to `model.*` and print exactly what local mode prints — this plan supplies the second, third and fourth of those steps as reusable functions. `03b` is the first consumer.

**Tech Stack:** Go 1.24, cobra, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-cli-remote-vaultapi-consolidation-design.md`

**Depends on:** `2026-09-03-cli-remote-vaultapi-02a-token-source.md` — `common.RemoteClientKey` must exist and carry a `*vaultapi.Client`.

**Followed by:** `…-03b-vault-access-adapter.md`, which wires these three into `vault-access grant/list/revoke`.

## Global Constraints

- Local mode must remain byte-for-byte unchanged for any invocation that sets none of `--server`, `ROCKETVAULT_ADDR`, or a current context.
- A command that resolves a remote target must never silently fall back to operating on the local instance.
- Remote output must be identical to local output for the same command.
- Remote mode performs no client-side authorization check. The server owns that decision; the CLI maps its 401/403 into readable text.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Vault resolution that honours ROCKETVAULT_VAULT

Remote commands today resolve the vault as flag → `target.Vault` → `""` (`cmd/secrets/get.go:141-144` and five siblings), skipping the `ROCKETVAULT_VAULT` environment variable that local mode honours through `common.ResolveVaultName` (`common/vault_selector.go:15-28`). The same command therefore hits a different vault depending on mode.

This helper fixes that for every group that adopts it, starting with `vault-access` in `03b`. The six `cmd/secrets/*` remote branches keep their old precedence until plan 07 migrates them, so the inconsistency is narrowed here, not eliminated — say so rather than claiming the defect is closed.

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
Expected: PASS, all seven.

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
## Self-Review

**Spec coverage:** This plan lands the three shared pieces the spec's §2 and §3 describe — vault resolution, error mapping, type conversion. They are split out from the `vault-access` commands themselves (`03b`) because every later resource group depends on these three and on none of the command wiring, and because no plan should carry more than three tasks.

**Placeholder scan:** No TBDs. `model.DefaultVaultName` exists (`model/vault.go:14`), so Task 1 Step 3 can use it directly.

**Divergence from the spec, deliberate:** the spec (§2, line 139) writes `RoleAssignmentFromAPI` as returning `*model.RoleAssignmentResponse`; Task 3 returns it by value, and `03b` consumes it by value. The value form is right — the struct is small, and a nil pointer would be a second failure mode for a pure conversion that cannot fail. Plan 04's `KeyFromAPI`/`CertificateFromAPI` should follow the value form here, not the spec's pointer form, so the family stays consistent.

**Type consistency:** `ResolveRemoteVault(cmd, target) string` (Task 1), `CLIError(op string, err error) error` (Task 2) and `RoleAssignmentFromAPI(*vaultapi.RoleAssignment) model.RoleAssignmentResponse` (Task 3) are all consumed by `03b`, which passes `&list[i]` to the last of them because `ListRoleAssignments` returns a `[]RoleAssignment` by value.

**Ordering:** The three tasks are independent of each other and may be executed in any order or in parallel. All three must land before `03b`.

**Known risk:** These primitives are written against `vault-access`'s needs and generalized on inspection, not on evidence. The first group to copy them (`keys`, plan 04) is where a wrong generalization will show up. Review them after `03b` rather than after this plan.
