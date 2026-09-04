// Package vaultprovisioning implements the `vault-provisioning` CLI command
// group: grant, revoke, and list bounded vault-creation rights. See
// authz.go for why every command here calls requireGrantAdmin first.
package vaultprovisioning

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// resolvePrincipal turns the CLI's principal argument into a UUID. A raw UUID
// is accepted directly and takes precedence, because an OAuth2 service
// account -- the identity an MSP's automation authenticates as -- is an
// oauth2_clients row, not a users row, so it has no username to look up. A
// non-UUID argument is treated as a username.
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

// runGrant is the grant command's business logic, factored out of RunE so it
// is testable without a cobra.Command. requireGrantAdmin runs first and
// unconditionally: it is the only authorization enforcement point on this
// CLI path.
func runGrant(ctx context.Context, sc container.ServiceContainerInterface, principalArg string, quota int, out io.Writer) error {
	issuedBy, err := requireGrantAdmin(ctx)
	if err != nil {
		return err
	}
	if quota <= 0 {
		return fmt.Errorf("--quota must be a positive integer: a zero-quota grant is indistinguishable from no grant")
	}
	principalID, err := resolvePrincipal(ctx, sc, principalArg)
	if err != nil {
		return err
	}
	g, err := sc.GetGrantService().IssueGrant(ctx, principalID, quota, issuedBy)
	if err != nil {
		return fmt.Errorf("issue provisioning grant failed: %w", err)
	}
	fmt.Fprintf(out, "Provisioning grant issued: principal=%s quota=%d\n", g.PrincipalID, g.Quota) //nolint:errcheck
	return nil
}

// InitVaultProvisioningGrant registers the grant command, which issues a
// bounded vault-creation right to a principal.
func InitVaultProvisioningGrant(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "grant <principal>",
		Short: "Issue a bounded vault-creation right to a principal",
		Long: `Issue a provisioning grant, letting a principal create up to a fixed
number of vaults without any authority over vaults it did not create.

<principal> is a username or a service-account UUID -- an OAuth2 service
account has no username to look up, so a raw UUID is accepted and takes
precedence over a username lookup. Re-issuing a grant for the same
principal changes its quota rather than adding a second grant.

--quota is required and must be a positive integer; a zero or negative
value is refused, since a zero-quota grant is indistinguishable from no
grant at all.

Requires the admin role. This tier is deliberately non-delegable: a
principal able to amend grants could raise its own quota, and the bound
the grant exists to impose would be decorative. Not vault scoped -- a
grant is a global right to create vaults, not a right inside one.`,
		Example: `  # Grant a user a quota of 5 vaults
  rocketvault vault-provisioning grant alice --quota 5

  # Grant a service account (an MSP's automation) a quota of 20
  rocketvault vault-provisioning grant 3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a \
    --quota 20

  # Re-issue for the same principal to change its quota
  rocketvault vault-provisioning grant alice --quota 10`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			quota, _ := cmd.Flags().GetInt("quota")
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			return runGrant(ctx, sc, args[0], quota, cmd.OutOrStdout())
		},
	}
	cmd.Flags().Int("quota", 0, "maximum number of vaults this principal may create (required, must be positive)")
	parent.AddCommand(cmd)
}
