package vaultaccess

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// InitVaultAccessRevoke registers the revoke command, which removes a role assignment.
func InitVaultAccessRevoke(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "revoke <assignment-id>",
		Short: "Revoke a role assignment in a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid assignment id: %w", err)
			}
			ctx := cmd.Context()
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := resolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			if err := sc.GetRoleAssignmentService().RevokeAssignment(ctx, id, vaultID); err != nil {
				return fmt.Errorf("revoke failed: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked assignment %s\n", id)
			return nil
		},
	}
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
