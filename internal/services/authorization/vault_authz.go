// Package authorization — vault_authz.go provides shared, parameterized
// authorization checks for vault-management operations, callable from both
// the HTTP API (api package) and the CLI (cmd package). They replace the
// single-purpose, api-package-private requireVaultManage: see
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md
// §1 for the design rationale.
package authorization

import (
	"context"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)

// CanManageVault reports whether principalID may perform vault-management
// operations (create, list, get, update, delete) against vaultID: the global
// admin account role, or an access-policy allow on (vaults, manage) scoped
// to vaultID or global. A nil policies service, a service error, or any
// decision other than AccessAllowed denies — this function fails closed.
func CanManageVault(ctx context.Context, accountRoles []string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return true
	}
	if policies == nil {
		return false
	}
	decision, err := policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
	if err != nil {
		return false
	}
	return decision == AccessAllowed
}

// CanPurgeVault reports whether principalID may permanently purge vaultID:
// the global admin account role, or a Key Vault Purge Operator role
// assignment held in vaultID. A nil roles service, a service error, or no
// matching assignment denies — this function fails closed.
func CanPurgeVault(ctx context.Context, accountRoles []string, roles RoleAssignmentService, principalID, vaultID uuid.UUID) bool {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return true
	}
	if roles == nil {
		return false
	}
	allowed, err := roles.HasDataAction(ctx, principalID, vaultID, model.ActionVaultPurge)
	if err != nil {
		return false
	}
	return allowed
}

// CanManageRoleAssignments reports whether principalID may create
// (write=true) or revoke/read (write=false) role assignments in vaultID: the
// global admin account role, an access-policy allow on (vaults, manage)
// scoped to vaultID or global (preserves the pre-existing documented
// behavior), or a Key Vault Data Access Administrator role assignment held
// in vaultID. A nil dependency, a service error, or no matching grant
// denies — this function fails closed.
//
// An explicit access-policy DENY wins outright: it short-circuits false and is
// never outvoted by a role grant, matching PolicyMiddleware's stated invariant
// (see internal/middleware/middleware.go). Only AccessFallback (no matching
// policy row) falls through to the role-assignment check.
func CanManageRoleAssignments(ctx context.Context, accountRoles []string, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, write bool) bool {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return true
	}
	if policies != nil {
		decision, err := policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
		if err == nil {
			if decision == AccessAllowed {
				return true
			}
			if decision == AccessDenied {
				return false
			}
		}
	}
	if roles == nil {
		return false
	}
	action := model.ActionRoleAssignmentsWrite
	if !write {
		action = model.ActionRoleAssignmentsDelete
	}
	allowed, err := roles.HasDataAction(ctx, principalID, vaultID, action)
	if err != nil {
		return false
	}
	return allowed
}
