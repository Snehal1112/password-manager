package vaultprovisioning

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// runList is the list command's business logic, factored out of RunE so it
// is testable without a cobra.Command. requireGrantAdmin runs first, same as
// grant and revoke.
func runList(ctx context.Context, sc container.ServiceContainerInterface, out io.Writer) error {
	if _, err := requireGrantAdmin(ctx); err != nil {
		return err
	}
	grants, err := sc.GetGrantService().ListGrants(ctx)
	if err != nil {
		return fmt.Errorf("list provisioning grants failed: %w", err)
	}
	fmt.Fprintf(out, "%-38s %-8s %s\n", "PRINCIPAL-ID", "QUOTA", "CREATED-AT") //nolint:errcheck
	for _, g := range grants {
		fmt.Fprintf(out, "%-38s %-8d %s\n", g.PrincipalID, g.Quota, g.CreatedAt.Format(time.RFC3339)) //nolint:errcheck
	}
	return nil
}

// InitVaultProvisioningList registers the list command, which lists every
// provisioning grant.
func InitVaultProvisioningList(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List provisioning grants",
		Long: `List every provisioning grant: principal ID, quota, and when it was
issued.

Requires the admin role. This tier is deliberately non-delegable. Not
vault scoped -- a grant is a global right to create vaults, not a right
inside one, so this command lists every grant regardless of vault.`,
		Example: `  # List every provisioning grant
  rocketvault vault-provisioning list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			return runList(ctx, sc, cmd.OutOrStdout())
		},
	}
	parent.AddCommand(cmd)
}
