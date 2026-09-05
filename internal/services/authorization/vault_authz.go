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
// operations against vaultID: the global admin account role, or an
// access-policy allow on (vaults, manage).
//
// Which policy check applies depends on vaultID:
//
//   - vaultID == uuid.Nil is the COLLECTION-level decision (create, list).
//     CheckAccess applies, so a global (vault_id NULL) allow satisfies it.
//   - vaultID != uuid.Nil targets ONE vault (get, update, delete).
//     CheckVaultScopedAccess applies, so a global allow does NOT satisfy it,
//     though a global DENY still blocks it.
//
// That split is the narrowing: a global vaults:manage grant means "may create
// and list vaults", never "may manage every vault on the instance".
//
// A nil policies service, a service error, or any decision other than
// AccessAllowed denies — this function fails closed.
func CanManageVault(ctx context.Context, accountRoles []string, policies AccessPolicyService, principalID, vaultID uuid.UUID) bool {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return true
	}
	if policies == nil {
		return false
	}
	var (
		decision AccessDecision
		err      error
	)
	if vaultID == uuid.Nil {
		decision, err = policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
	} else {
		decision, err = policies.CheckVaultScopedAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
	}
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
// scoped to vaultID — a global (vault_id NULL) allow no longer suffices,
// though a global deny still blocks — or a Key Vault Data Access
// Administrator role assignment held in vaultID. A nil dependency, a service
// error, or no matching grant denies — this function fails closed.
//
// An explicit access-policy DENY wins outright: it short-circuits false and is
// never outvoted by a role grant, matching PolicyMiddleware's stated invariant
// (see internal/middleware/middleware.go). Only AccessFallback (no matching
// policy row) falls through to the role-assignment check.
//
// vaultID == uuid.Nil always denies a non-admin caller here, unlike
// CanManageVault's identically shaped guard -- the admin account role still
// short-circuits above and returns true regardless. CanManageVault's
// uuid.Nil branch serves a real collection-level decision (create/list a
// vault). Role assignments have no such collection level -- there is no
// "manage role assignments across every vault" operation -- so this branch
// has no real decision to serve. Routing it to CheckAccess anyway would
// re-widen the exact thing this release narrows: a global vaults:manage
// allow satisfying role-assignment management everywhere. Every call site
// passes a resolved vault ID today, so this is dead code in practice; it
// fails closed rather than mirroring CanManageVault so a future caller can't
// accidentally reopen that widening by passing uuid.Nil.
func CanManageRoleAssignments(ctx context.Context, accountRoles []string, policies AccessPolicyService, roles RoleAssignmentService, principalID, vaultID uuid.UUID, write bool) bool {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return true
	}
	if vaultID == uuid.Nil {
		return false
	}
	if policies != nil {
		// Role assignments always target one vault, so the vault-scoped check
		// applies whenever vaultID is concrete. Narrowing CanManageVault alone
		// would leave the escalation path open: role-assignment management by
		// itself is enough to award oneself Key Vault Administrator anywhere.
		decision, err := policies.CheckVaultScopedAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, vaultID)
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

// CreateRight identifies which authority permitted a vault creation. The
// caller needs to know which, not merely whether: only the provisioning-grant
// path is quota-bounded.
type CreateRight int

const (
	// CreateRightNone means the principal may not create a vault.
	CreateRightNone CreateRight = iota
	// CreateRightAdmin is the global admin account role. Not quota-bounded.
	CreateRightAdmin
	// CreateRightGlobalPolicy is a global (vault_id NULL) vaults:manage allow
	// policy. Not quota-bounded.
	CreateRightGlobalPolicy
	// CreateRightProvisioningGrant is a vault_provisioning_grants row. Quota
	// applies -- the caller MUST enforce it inside the creation transaction.
	CreateRightProvisioningGrant
)

// GrantReader reads a principal's provisioning grant. Declared here rather
// than importing internal/services/provisioning so this package keeps no
// dependency on that one; the container wires the concrete service in.
type GrantReader interface {
	GetGrant(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error)
}

// CanCreateVault reports which right, if any, permits principalID to create a
// vault: the global admin account role, a global vaults:manage allow policy,
// or a provisioning grant -- checked in that order.
//
// An explicit global DENY on (vaults, manage) short-circuits to
// CreateRightNone and is never outvoted by a provisioning grant, matching the
// deny-overrides invariant PolicyMiddleware states and CanManageRoleAssignments
// honours.
//
// A nil dependency or any service error denies -- this function fails closed.
func CanCreateVault(ctx context.Context, accountRoles []string, policies AccessPolicyService, grants GrantReader, principalID uuid.UUID) CreateRight {
	if common.HasAnyRole(accountRoles, string(model.RoleAdmin)) {
		return CreateRightAdmin
	}
	if policies != nil {
		decision, err := policies.CheckAccess(ctx, principalID, model.PolicyResourceVaults, model.OpManage, uuid.Nil)
		if err != nil {
			return CreateRightNone
		}
		if decision == AccessAllowed {
			return CreateRightGlobalPolicy
		}
		if decision == AccessDenied {
			return CreateRightNone
		}
	}
	if grants == nil {
		return CreateRightNone
	}
	g, err := grants.GetGrant(ctx, principalID)
	if err != nil || g == nil {
		return CreateRightNone
	}
	return CreateRightProvisioningGrant
}
