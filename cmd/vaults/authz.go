// Package vaults — authz.go provides shared authorization checks for the CLI
// vault-management commands (create/update/delete/recover/purge), closing a
// pre-existing gap: these commands previously called the service layer
// directly with no authorization check at all. See
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md
// §7.
package vaults

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/container"
	authz "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// callerIdentity extracts the acting principal's account role and user ID
// from the CLI's authenticated context, populated by persistentPreRun in
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

// resolveTargetVaultID finds the ID of the vault named name, whether active
// or soft-deleted. VaultService.GetVault only returns active vaults, and
// recover/purge commonly target a soft-deleted one, so ListVaults(true) is
// used uniformly by every command in this file.
func resolveTargetVaultID(ctx context.Context, svc vaultServices.VaultService, name string) (uuid.UUID, error) {
	vaults, err := svc.ListVaults(ctx, true)
	if err != nil {
		return uuid.Nil, err
	}
	for _, v := range vaults {
		if v.Name == name {
			return v.ID, nil
		}
	}
	return uuid.Nil, vaultServices.ErrVaultNotFound
}

// requireCanCreateVault checks the three-way create decision: the global
// admin role, a global (not vault-specific) vaults:manage grant, or a bounded
// provisioning grant. There is no target vault to resolve yet when creating
// one, so this mirrors the HTTP createVault handler's use of CanCreateVault
// rather than a scoped check.
//
// The CLI bypasses PolicyMiddleware entirely, so this is the only
// authorization enforcement point on this path.
//
// The returned CreateRight is not incidental -- the caller MUST use it to
// decide whether the create is quota-bounded (CreateRightProvisioningGrant is
// the only bounded right; CreateRightAdmin and CreateRightGlobalPolicy are
// not) and pass that decision to VaultService.CreateVaultProvisioned. An
// earlier version of this function returned only an error, and its caller
// discarded the right entirely, always calling the unbounded CreateVault --
// letting a provisioning-grant holder create unlimited vaults, set
// purge_protection, and receive none of the creator's grants. Do not repeat
// that mistake: a caller that checks only "err == nil" and calls the
// unbounded path regardless reopens the same bypass.
func requireCanCreateVault(ctx context.Context, sc container.ServiceContainerInterface) (authz.CreateRight, error) {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return authz.CreateRightNone, err
	}
	right := authz.CanCreateVault(ctx, roles, sc.GetAccessPolicyService(), sc.GetGrantService(), principalID)
	if right == authz.CreateRightNone {
		return authz.CreateRightNone, fmt.Errorf("permission denied: admin, a global vaults/manage grant, or a vault provisioning grant required to create a vault")
	}
	return right, nil
}

// requireCanListVaults checks that the caller may list vaults instance-wide.
// Like create, list has no single target vault, so authorization is checked
// against uuid.Nil — matching HTTP listVaults (api/vault.go's
// authzServices.CanManageVault(..., uuid.Nil)).
func requireCanListVaults(ctx context.Context, sc container.ServiceContainerInterface) error {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, uuid.Nil) {
		return fmt.Errorf("permission denied: admin or vaults/manage required")
	}
	return nil
}

// requireCanManageVault resolves vaultName to an ID and checks CanManageVault
// against it.
func requireCanManageVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) error {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	vaultID, err := resolveTargetVaultID(ctx, sc.GetVaultService(), vaultName)
	if err != nil {
		return fmt.Errorf("resolve vault %q: %w", vaultName, err)
	}
	if !authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, vaultID) {
		return fmt.Errorf("permission denied: admin or vaults/manage required for vault %q", vaultName)
	}
	return nil
}

// requireCanPurgeVault resolves vaultName to an ID and checks CanPurgeVault
// against it.
func requireCanPurgeVault(ctx context.Context, sc container.ServiceContainerInterface, vaultName string) error {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	vaultID, err := resolveTargetVaultID(ctx, sc.GetVaultService(), vaultName)
	if err != nil {
		return fmt.Errorf("resolve vault %q: %w", vaultName, err)
	}
	if !authz.CanPurgeVault(ctx, roles, sc.GetRoleAssignmentService(), principalID, vaultID) {
		return fmt.Errorf("permission denied: admin or Key Vault Purge Operator required for vault %q", vaultName)
	}
	return nil
}
