# Grant CLI Surface — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rocketvault vault-provisioning grant|revoke|list`, so an operator can issue grants without curl.

**Architecture:** A new `cmd/vault-provisioning/` package mirroring `cmd/vault-webhook/`: a package-local authz helper first, then the commands built on it. The helper exists because the CLI calls the service layer directly and never passes through `PolicyMiddleware` — a command that skips it bypasses authorization entirely.

**Tech Stack:** Go 1.24, cobra, viper, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §4

**Depends on:** `…-06-admin-http-surface.md` — the HTTP semantics these commands mirror.
**Followed by:** `…-08-diagnostic-and-docs.md`.

## Global Constraints

- **The CLI bypasses `PolicyMiddleware` entirely.** The package-local authz helper is the only enforcement point on this path; a command that skips it bypasses authorization completely. This is the gap recorded in `cmd/vault-access/authz.go`'s header comment.
- Admin-only and non-delegable, identical to the HTTP tier.
- A grantee may be an OAuth2 service account, which is not a `users` row — so the principal argument must accept a **UUID**, not only a username. `resolvePrincipal` (`role_assignment_service.go:233`) resolves usernames only and cannot be the sole path.
- Commands follow `.claude/cli-help-conventions.md` for flag naming and help text.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Package-local authorization helper

**Files:**
- Create: `cmd/vault-provisioning/authz.go`
- Create: `cmd/vault-provisioning/authz_test.go`

**Interfaces:**
- Produces:
  - `func callerIdentity(ctx context.Context) (roles []string, principalID uuid.UUID, err error)`
  - `func requireGrantAdmin(ctx context.Context) (uuid.UUID, error)` — returns the acting principal's ID so commands can attribute the change in the audit trail
  - Tasks 2 and 3 consume `requireGrantAdmin`.

Returning the principal ID is not incidental. The CLI has no middleware to stamp an actor, so a command that discards this value produces an audit record naming nobody — the same reasoning recorded in `cmd/vault-webhook/authz.go`'s `requireCanManageVault`.

- [ ] **Step 1: Write the failing test**

Create `cmd/vault-provisioning/authz_test.go`:

```go
package vaultprovisioning

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/model"
)

func ctxWithClaims(userID uuid.UUID, roles []string) context.Context {
	return context.WithValue(context.Background(), common.ClaimsKey,
		&model.Claims{UserID: userID, Roles: roles})
}

func TestRequireGrantAdmin_AllowsAdmin(t *testing.T) {
	id := uuid.New()

	got, err := requireGrantAdmin(ctxWithClaims(id, []string{string(model.RoleAdmin)}))

	require.NoError(t, err)
	require.Equal(t, id, got, "the acting principal must be returned so the audit entry names somebody")
}

func TestRequireGrantAdmin_DeniesNonAdmin(t *testing.T) {
	_, err := requireGrantAdmin(ctxWithClaims(uuid.New(), []string{"user"}))

	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestRequireGrantAdmin_DeniesVaultManageHolder(t *testing.T) {
	// A principal with vault-management rights is still not a grant admin:
	// this tier is deliberately non-delegable.
	_, err := requireGrantAdmin(ctxWithClaims(uuid.New(), []string{"vault-admin"}))

	require.Error(t, err)
}

func TestRequireGrantAdmin_MissingClaimsIsAnError(t *testing.T) {
	_, err := requireGrantAdmin(context.Background())

	require.Error(t, err, "reaching this helper unauthenticated is a wiring bug, not a permission denial")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/vault-provisioning/ -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Write the helper**

Create `cmd/vault-provisioning/authz.go`:

```go
// Package vaultprovisioning — authz.go provides the authorization check for
// the CLI vault-provisioning commands (grant/revoke/list). The CLI calls the
// service layer directly and bypasses PolicyMiddleware entirely, so this is
// the only authorization enforcement point on this path -- a command that
// skips it bypasses authorization completely. It mirrors
// cmd/vault-access/authz.go, whose header comment records the
// privilege-escalation gap that arose from omitting exactly this check.
package vaultprovisioning

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)

// callerIdentity extracts the acting principal's account roles and user ID
// from the CLI's authenticated context, populated by persistentPreRun in
// cmd/root.go. Returns an error if claims are missing -- a command reaching
// this far without prior authentication indicates a wiring bug, not a
// permission denial.
func callerIdentity(ctx context.Context) (roles []string, principalID uuid.UUID, err error) {
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, uuid.Nil, fmt.Errorf("authenticated claims not available in context")
	}
	return claims.Roles, claims.UserID, nil
}

// requireGrantAdmin authorizes a provisioning-grant operation. Global admin
// only, and deliberately non-delegable: a principal able to amend grants could
// raise its own quota, and the bound the grant exists to impose would be
// decorative. This is why there is no access-policy or role-assignment path
// here, unlike every other CLI authz helper in this tree.
//
// Returns the authorized principal's ID so the caller can attribute the change
// in the audit trail. The CLI has no middleware to stamp an actor for it, so a
// command that discards this value produces an audit record naming nobody.
func requireGrantAdmin(ctx context.Context) (uuid.UUID, error) {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if !common.HasAnyRole(roles, model.RoleAdmin) {
		return uuid.Nil, fmt.Errorf("permission denied: managing vault provisioning grants requires the admin role")
	}
	return principalID, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/vault-provisioning/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/vault-provisioning/
git commit -S -m "feat(cli): add vault-provisioning authorization helper"
```

---

### Task 2: grant, revoke, and list commands

**Files:**
- Create: `cmd/vault-provisioning/provisioning.go` (parent command)
- Create: `cmd/vault-provisioning/grant.go`, `revoke.go`, `list.go`
- Create: `cmd/vault-provisioning/grant_test.go`

**Interfaces:**
- Consumes: `requireGrantAdmin` from task 1; `sc.GetGrantService()` from plan 02.
- Produces: `func NewProvisioningCommand() *cobra.Command`, consumed by task 3.

- [ ] **Step 1: Write the failing test**

```go
func TestResolvePrincipal_AcceptsUUID(t *testing.T) {
	id := uuid.New()

	got, err := resolvePrincipal(context.Background(), nil, id.String())

	require.NoError(t, err)
	require.Equal(t, id, got,
		"a service account is not a users row, so a raw UUID must be accepted")
}

func TestResolvePrincipal_AcceptsUsername(t *testing.T) {
	sc := newMockContainerWithUser(t, "alice", testUserID)

	got, err := resolvePrincipal(context.Background(), sc, "alice")

	require.NoError(t, err)
	require.Equal(t, testUserID, got)
}

func TestResolvePrincipal_UnknownUsernameErrors(t *testing.T) {
	sc := newMockContainerWithUser(t, "alice", testUserID)

	_, err := resolvePrincipal(context.Background(), sc, "nobody")

	require.Error(t, err)
}

func TestGrantCommand_RequiresPositiveQuota(t *testing.T) {
	err := runGrant(ctxWithClaims(uuid.New(), []string{string(model.RoleAdmin)}),
		newMockContainerWithGrantService(t), uuid.New().String(), 0)

	require.Error(t, err, "a zero-quota grant is indistinguishable from no grant")
}

func TestGrantCommand_NonAdminRefused(t *testing.T) {
	err := runGrant(ctxWithClaims(uuid.New(), []string{"user"}),
		newMockContainerWithGrantService(t), uuid.New().String(), 5)

	require.Error(t, err)
	require.Contains(t, err.Error(), "permission denied")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/vault-provisioning/ -v`
Expected: FAIL — `resolvePrincipal` and `runGrant` undefined.

- [ ] **Step 3: Write the principal resolver**

In `cmd/vault-provisioning/grant.go`:

```go
// resolvePrincipal turns the CLI's principal argument into a UUID. A raw UUID
// is accepted directly and takes precedence, because an OAuth2 service
// account -- the identity an MSP's automation authenticates as -- has no
// username to look up. A non-UUID argument is treated as a username.
func resolvePrincipal(ctx context.Context, sc container.ServiceContainerInterface, arg string) (uuid.UUID, error) {
	if id, err := uuid.Parse(arg); err == nil {
		return id, nil
	}
	if sc == nil {
		return uuid.Nil, fmt.Errorf("cannot resolve username %q without a service container", arg)
	}
	u, err := sc.GetUserService().GetUserByUsername(ctx, arg)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve principal %q: %w", arg, err)
	}
	return u.ID, nil
}
```

Adjust the user-lookup call to the real `UserService` method name in this tree.

- [ ] **Step 4: Write the three commands**

`grant.go`:

```go
func runGrant(ctx context.Context, sc container.ServiceContainerInterface, principalArg string, quota int) error {
	issuedBy, err := requireGrantAdmin(ctx)
	if err != nil {
		return err
	}
	principalID, err := resolvePrincipal(ctx, sc, principalArg)
	if err != nil {
		return err
	}
	g, err := sc.GetGrantService().IssueGrant(ctx, principalID, quota, issuedBy)
	if err != nil {
		return err
	}
	fmt.Printf("Provisioning grant issued: principal=%s quota=%d\n", g.PrincipalID, g.Quota)
	return nil
}

func newGrantCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant <principal>",
		Short: "Issue a bounded vault-creation right to a principal",
		Long: `Issue a provisioning grant, letting a principal create up to a fixed
number of vaults without any authority over vaults it did not create.

<principal> is a username or a service-account UUID. Re-issuing for the same
principal changes the quota rather than adding a second grant.

Requires the admin role. This tier is deliberately non-delegable.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			quota, _ := cmd.Flags().GetInt("quota")
			sc, err := serviceContainerFrom(cmd)
			if err != nil {
				return err
			}
			return runGrant(cmd.Context(), sc, args[0], quota)
		},
	}
	cmd.Flags().Int("quota", 0, "maximum number of vaults this principal may create (required, > 0)")
	return cmd
}
```

Write `revoke.go` and `list.go` on the same shape: both call `requireGrantAdmin` first, then `RevokeGrant` / `ListGrants`. `list` prints principal, quota and issued-at in the tabular style the other list commands use.

Resolve the service container using the same accessor the sibling CLI packages use (see `cmd/vault-webhook/`), rather than inventing a new one.

- [ ] **Step 5: Write the parent command**

`provisioning.go`:

```go
// NewProvisioningCommand builds the `vault-provisioning` command group.
func NewProvisioningCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault-provisioning",
		Short: "Manage bounded vault-creation rights",
	}
	cmd.AddCommand(newGrantCommand(), newRevokeCommand(), newListCommand())
	return cmd
}
```

- [ ] **Step 6: Run tests and commit**

Run: `go test ./cmd/vault-provisioning/ -v`
Expected: PASS

```bash
git add cmd/vault-provisioning/
git commit -S -m "feat(cli): add vault-provisioning grant, revoke, list"
```

---

### Task 3: Register the command

**Files:**
- Create: `cmd/vault_provisioning.go`
- Modify: `cmd/root.go` (register the command alongside the other groups)
- Test: `cmd/cmd_test.go`

**Interfaces:**
- Consumes: `NewProvisioningCommand` from task 2.

- [ ] **Step 1: Write the failing test**

```go
func TestRootCommand_HasVaultProvisioning(t *testing.T) {
	var found bool
	for _, c := range rootCmd.Commands() {
		if c.Name() == "vault-provisioning" {
			found = true
			break
		}
	}
	require.True(t, found, "vault-provisioning must be registered on the root command")
}

func TestVaultProvisioning_HasAllThreeSubcommands(t *testing.T) {
	cmd := vaultprovisioning.NewProvisioningCommand()

	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	require.True(t, names["grant"])
	require.True(t, names["revoke"])
	require.True(t, names["list"])
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/ -run TestRootCommand_HasVaultProvisioning -v`
Expected: FAIL

- [ ] **Step 3: Register it**

Create `cmd/vault_provisioning.go` following `cmd/vault_webhook.go` exactly — same registration idiom, same `init()` or explicit-add placement, whichever that file uses.

- [ ] **Step 4: Verify the help text**

Run: `go run main.go vault-provisioning --help` and `go run main.go vault-provisioning grant --help`.

Check both against `.claude/cli-help-conventions.md`. Confirm the `grant` help says the quota must be positive and that the tier is admin-only.

- [ ] **Step 5: Run everything and commit**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: PASS

```bash
git add cmd/
git commit -S -m "feat(cli): register the vault-provisioning command group"
```
