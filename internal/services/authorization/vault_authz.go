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
func CanManageVault(ctx context.Context, accountRole string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool {
	if common.HasRequiredRole(accountRole, string(model.RoleAdmin)) {
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
