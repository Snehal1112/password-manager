package vaultaccess

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
)

// resolveVaultID resolves the --vault selection to a vault id via the service container.
func resolveVaultID(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface) (uuid.UUID, error) {
	name := common.ResolveVaultName(cmd)
	v, err := sc.GetVaultService().GetVault(ctx, name)
	if err != nil {
		return uuid.Nil, fmt.Errorf("vault %q not found: %w", name, err)
	}
	return v.ID, nil
}

// addVaultFlag adds the --vault selection flag to a command.
func addVaultFlag(cmd *cobra.Command) {
	cmd.Flags().String("vault", "", "vault name (default: ROCKETVAULT_VAULT env, config, or \"default\")")
}
