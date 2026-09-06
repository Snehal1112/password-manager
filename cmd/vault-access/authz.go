// Package vaultaccess — authz.go provides the authorization check for the CLI
// role-assignment commands (grant/revoke), closing a privilege-escalation gap:
// these commands previously called RoleAssignmentService directly with no
// authorization check at all, so any authenticated principal could grant
// themselves any role in any vault. It mirrors cmd/vaults/authz.go.
package vaultaccess

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/cmd/vaultcli"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
)

// requireCanManageRoleAssignments authorizes granting (write=true) or revoking
// (write=false) a role assignment in vaultID, using the same shared primitive
// as the HTTP handlers so CLI and API cannot drift apart.
func requireCanManageRoleAssignments(ctx context.Context, sc container.ServiceContainerInterface, vaultID uuid.UUID, write bool) error {
	roles, principalID, err := vaultcli.CallerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageRoleAssignments(ctx, roles, sc.GetAccessPolicyService(), sc.GetRoleAssignmentService(), principalID, vaultID, write) {
		return fmt.Errorf("permission denied: admin, vaults/manage, or Key Vault Data Access Administrator required for this vault")
	}
	return nil
}
