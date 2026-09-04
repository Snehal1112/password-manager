// Package vaults implements the CLI command group for vault lifecycle management.
// Commands call the vault service in-process via the service container; they do
// not make HTTP requests.
package vaults

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	authz "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// createCmd represents the vaults create command.
var createCmd = &cobra.Command{
	Use:     "create <name>",
	Aliases: []string{"add"},
	Short:   "Create a new vault",
	Long: `Create a new vault: an isolated boundary for secrets, keys, and
certificates, with its own access grants.

Requires the admin account role, or an access-policy allow on (vaults,
manage) scoped globally rather than to a specific vault, since the vault
being created does not exist yet to scope the check to.

The vault name is the positional argument; this command has no --vault
flag.

A new vault is enabled by default with a 90-day soft-delete retention
period. --purge-protection and --retention-days override those defaults at
creation time.`,
	Example: `  # Create a vault with default settings
  rocketvault vaults create <name>

  # Create with purge protection and a 30-day retention window
  rocketvault vaults create <name> --purge-protection --retention-days 30`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		ctx := cmd.Context()
		userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
		if !ok {
			return fmt.Errorf("user ID not available in context")
		}

		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			return fmt.Errorf("service container not available in context")
		}
		right, err := requireCanCreateVault(ctx, serviceContainer)
		if err != nil {
			return err
		}
		vaultService := serviceContainer.GetVaultService()

		req := model.CreateVaultRequest{Name: name}
		if cmd.Flags().Changed("purge-protection") {
			pp, _ := cmd.Flags().GetBool("purge-protection")
			req.PurgeProtection = &pp
		}
		if cmd.Flags().Changed("retention-days") {
			rd, _ := cmd.Flags().GetInt("retention-days")
			req.RetentionDays = &rd
		}

		// Only a provisioning-grant holder is quota-bounded; admins and
		// global-policy holders go through CreateVaultProvisioned's
		// unbounded fallback to the pre-existing CreateVault behaviour.
		vault, err := vaultService.CreateVaultProvisioned(ctx, req, userID,
			right == authz.CreateRightProvisioningGrant)
		if err != nil {
			switch {
			case errors.Is(err, vaultServices.ErrVaultQuotaExceeded):
				return fmt.Errorf("failed to create vault: %w -- delete or purge an existing vault, or ask an administrator to raise your provisioning quota", err)
			case errors.Is(err, vaultServices.ErrPurgeProtectionNotPermitted):
				return fmt.Errorf("failed to create vault: %w -- only an administrator can set --purge-protection", err)
			default:
				return fmt.Errorf("failed to create vault: %w", err)
			}
		}

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}
		headers := []string{"ID", "Name", "Enabled", "PurgeProtection", "RetentionDays", "Created"}
		row := []string{
			vault.ID.String(),
			vault.Name,
			strconv.FormatBool(vault.Enabled),
			strconv.FormatBool(vault.PurgeProtection),
			strconv.Itoa(vault.RetentionDays),
			vault.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitVaultsCreate registers the create command under the vaults command group.
func InitVaultsCreate(vaultsCmd *cobra.Command) *cobra.Command {
	vaultsCmd.AddCommand(createCmd)

	createCmd.Flags().Bool("purge-protection", false, "Protect the vault from being purged")
	createCmd.Flags().Int("retention-days", 0, "Soft-delete retention period in days")

	return vaultsCmd
}
