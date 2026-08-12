package vaultaccess

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// InitVaultAccessGrant registers the grant command, which assigns a built-in role to a principal.
func InitVaultAccessGrant(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "grant <principal>",
		Short: "Grant a built-in role to a principal in a vault",
		Example: `  # Grant a built-in role to a user in a vault
  rocketvault vault-access grant alice --role "Key Vault Secrets User" --vault prod \
    --username admin --password admin123 --totp-code <code>

  # Grant a role to a service account
  rocketvault vault-access grant my-svc --role "Key Vault Crypto User" --principal-type service_account --vault prod \
    --username admin --password admin123 --totp-code <code>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			principal := args[0]
			role, _ := cmd.Flags().GetString("role")
			if role == "" {
				return fmt.Errorf("--role is required")
			}
			ptype, _ := cmd.Flags().GetString("principal-type")
			if ptype == "" {
				ptype = string(model.PrincipalTypeUser)
			}
			ctx := cmd.Context()
			callerID, _ := ctx.Value(common.UserIDKey).(uuid.UUID)
			sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
			if !ok || sc == nil {
				return fmt.Errorf("service container not available in context")
			}
			vaultID, err := resolveVaultID(ctx, cmd, sc)
			if err != nil {
				return err
			}
			if err := requireCanManageRoleAssignments(ctx, sc, vaultID, true); err != nil {
				return err
			}
			ra, err := sc.GetRoleAssignmentService().AssignRole(ctx, authz.AssignRoleInput{
				Principal:     principal,
				PrincipalType: model.PrincipalType(ptype),
				Role:          role,
				VaultID:       vaultID,
				CreatedBy:     callerID,
			})
			if err != nil {
				return fmt.Errorf("grant failed: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "granted %s to %s in vault (assignment %s)\n", role, principal, ra.ID) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().String("role", "", "built-in role (see `vault-access roles`)")
	cmd.Flags().String("principal-type", "user", "principal type: user or service_account")
	addVaultFlag(cmd)
	parent.AddCommand(cmd)
}
