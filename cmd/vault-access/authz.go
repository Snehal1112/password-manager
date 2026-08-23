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

	"rocketvault/common"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// callerIdentity extracts the acting principal's account role and user ID from
// the CLI's authenticated context, populated by persistentPreRun in
// cmd/root.go. Returns an error if claims are missing — a command reaching
// this far without prior authentication indicates a wiring bug, not a
// permission denial.
func callerIdentity(ctx context.Context) (roles []string, principalID uuid.UUID, err error) {
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok || claims == nil {
		return nil, uuid.Nil, fmt.Errorf("authenticated claims not available in context")
	}
	return claims.Roles, claims.UserID, nil
}

// requireCanManageRoleAssignments authorizes granting (write=true) or revoking
// (write=false) a role assignment in vaultID, using the same shared primitive
// as the HTTP handlers so CLI and API cannot drift apart.
func requireCanManageRoleAssignments(ctx context.Context, sc container.ServiceContainerInterface, vaultID uuid.UUID, write bool) error {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageRoleAssignments(ctx, roles, sc.GetAccessPolicyService(), sc.GetRoleAssignmentService(), principalID, vaultID, write) {
		return fmt.Errorf("permission denied: admin, vaults/manage, or Key Vault Data Access Administrator required for this vault")
	}
	return nil
}
