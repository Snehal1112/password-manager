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

// requireCanCreateVault checks CanManageVault against a global (not
// vault-specific) grant, since there is no target vault to resolve yet when
// creating one — mirrors the HTTP createVault handler's use of uuid.Nil.
func requireCanCreateVault(ctx context.Context, sc container.ServiceContainerInterface) error {
	roles, principalID, err := callerIdentity(ctx)
	if err != nil {
		return err
	}
	if !authz.CanManageVault(ctx, roles, sc.GetAccessPolicyService(), principalID, uuid.Nil) {
		return fmt.Errorf("permission denied: admin or a global vaults/manage grant required to create a vault")
	}
	return nil
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
