package vaultcli

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// ResolveVaultID resolves the --vault selection to a vault id via the service container.
func ResolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error) {
	name := common.ResolveVaultName(cmd)
	v, err := sc.GetVaultService().GetVault(ctx, name)
	if err != nil {
		return uuid.Nil, fmt.Errorf("vault %q not found: %w", name, err)
	}
	return v.ID, nil
}

// RequireDataAction resolves the vault, then checks principalID holds a role
// assignment in it granting action. Returns the resolved vault ID on success
// so callers don't have to resolve twice.
func RequireDataAction(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface, principalID uuid.UUID, action model.DataAction) (uuid.UUID, error) {
	vaultID, err := ResolveVaultID(ctx, cmd, sc)
	if err != nil {
		return uuid.Nil, err
	}
	if err := authorization.RequireDataAction(ctx, sc.GetRoleAssignmentService(), principalID, vaultID, action); err != nil {
		return uuid.Nil, err
	}
	return vaultID, nil
}
