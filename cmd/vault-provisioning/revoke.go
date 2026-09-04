package vaultprovisioning

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// runRevoke is the revoke command's business logic, factored out of RunE so
// it is testable without a cobra.Command. requireGrantAdmin runs first and
// its return value -- the acting principal -- is passed to RevokeGrant as
// revokedBy so the revocation is attributable. The CLI has no middleware to
// stamp an actor for it; this is the only place that identity can come from.
func runRevoke(ctx context.Context, sc container.ServiceContainerInterface, principalArg string, out io.Writer) error {
	revokedBy, err := requireGrantAdmin(ctx)
	if err != nil {
		return err
	}
	principalID, err := resolvePrincipal(ctx, sc, principalArg)
	if err != nil {
		return err
	}
	if err := sc.GetGrantService().RevokeGrant(ctx, principalID, revokedBy); err != nil {
		return fmt.Errorf("revoke provisioning grant failed: %w", err)
	}
	fmt.Fprintf(out, "Provisioning grant revoked: principal=%s\n", principalID) //nolint:errcheck
	return nil
}

// InitVaultProvisioningRevoke registers the revoke command, which removes a
// principal's provisioning grant.
func InitVaultProvisioningRevoke(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "revoke <principal>",
		Short: "Revoke a principal's provisioning grant",
		Long: `Revoke the provisioning grant for a principal, stopping it from creating
any further vaults under that grant.

<principal> is a username or a service-account UUID, resolved the same way
grant resolves it: a raw UUID is accepted directly and takes precedence over
a username lookup.

Revocation does not cascade: it leaves every vault the principal already
created, and that vault's own access grants, untouched. Removing access to
existing vaults is a separate operator action.

Requires the admin role. This tier is deliberately non-delegable. Not
vault scoped -- a grant is a global right to create vaults, not a right
inside one.`,
		Example: `  # Revoke a user's provisioning grant
  rocketvault vault-provisioning revoke alice

  # Revoke a service account's provisioning grant
  rocketvault vault-provisioning revoke 3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			return runRevoke(ctx, sc, args[0], cmd.OutOrStdout())
		},
	}
	parent.AddCommand(cmd)
}
