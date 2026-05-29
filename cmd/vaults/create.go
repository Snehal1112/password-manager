// Package vaults implements the CLI command group for vault lifecycle management.
// Commands call the vault service in-process via the service container; they do
// not make HTTP requests.
package vaults

import (
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

// createCmd represents the vaults create command.
var createCmd = &cobra.Command{
	Use:     "create <name>",
	Aliases: []string{"add"},
	Short:   "Create a new vault",
	Long:    `Create a new vault to hold secrets, keys, and certificates.`,
	Example: `rocketvault vaults create my-vault`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("requires <name> argument")
		}
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

		vault, err := vaultService.CreateVault(ctx, req, userID)
		if err != nil {
			return fmt.Errorf("failed to create vault: %w", err)
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
