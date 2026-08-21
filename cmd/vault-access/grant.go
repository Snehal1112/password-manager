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
		Long: `Grant a built-in Azure Key Vault role to a principal (user or service
account) in a vault, creating a role assignment that governs its data-plane
access there.

Requires the admin account role, an access-policy allow on (vaults, manage)
for this vault, or a Key Vault Data Access Administrator role assignment
holding Microsoft.Authorization/roleAssignments/write in this vault.

Vault scoped via --vault; defaults to the ROCKETVAULT_VAULT environment
variable, then config, then "default" if none of those is set.

--role must be one of the built-in role names listed by vault-access roles.
--principal-type defaults to "user"; the only other accepted value is
"service_account".`,
		Example: `  # Grant a built-in role to a user in a vault
  rocketvault vault-access grant alice --role "Key Vault Secrets User" \
    --vault prod

  # Grant a role to a service account
  rocketvault vault-access grant my-svc --role "Key Vault Crypto User" \
    --principal-type service_account --vault prod`,
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
			callerRole, _, err := callerIdentity(ctx)
			if err != nil {
				return err
			}
			isGlobalAdmin := common.HasRequiredRole(callerRole, string(model.RoleAdmin))
			ra, err := sc.GetRoleAssignmentService().AssignRole(ctx, authz.AssignRoleInput{
				Principal:           principal,
				PrincipalType:       model.PrincipalType(ptype),
				Role:                role,
				VaultID:             vaultID,
				CreatedBy:           callerID,
				CallerIsGlobalAdmin: isGlobalAdmin,
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
