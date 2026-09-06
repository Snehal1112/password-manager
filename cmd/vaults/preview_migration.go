package vaults

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/cliclient"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
)

// previewMigrationCmd prints the role assignments the P2 upgrade would create.
var previewMigrationCmd = &cobra.Command{
	Use:   "preview-migration",
	Short: "Preview the role assignments the authorization upgrade would create",
	Long: `Print the per-vault Azure role assignments the authorization upgrade would
derive from existing object ownership, without writing anything.

The upgrade inverts authorization to deny-by-default: a principal holding no
role assignment in a vault is refused access to every object in it. Run this
first and confirm that every principal that needs access appears in the output
for the vaults it needs.

Derivation:
  secrets owners       -> Key Vault Secrets Officer in the owning vault
  keys owners          -> Key Vault Crypto Officer in the owning vault
  certificates owners  -> Key Vault Certificates Officer in the owning vault
  global admins        -> Key Vault Administrator in every vault`,
	Example: `  # Preview the assignments the upgrade would create
  rocketvault vaults preview-migration

  # Machine-readable output
  rocketvault vaults preview-migration --output json`,
	// Replace the root PersistentPreRunE. The root pre-run calls InitializeDB,
	// which runs the very migration this command exists to preview, so inheriting
	// it would make the preview report an already-applied state.
	PersistentPreRunE: previewMigrationPreRun,
	RunE:              runPreviewMigration,
}

// previewMigrationPreRun installs the logger and output formatter without
// opening or migrating the database. Because it replaces the root pre-run
// entirely (see the command's own comment above), it must re-run the
// remote-target refusal itself — this command reads the local database file
// directly and has no server-side route to call, so it must never silently
// preview local state while a remote target is active (see NB2 in the
// 2026-08-17 final review).
func previewMigrationPreRun(cmd *cobra.Command, _ []string) error {
	serverFlag, _ := cmd.Flags().GetString("server")
	if err := cliclient.RequireLocal(serverFlag, "vaults preview-migration"); err != nil {
		return err
	}

	log := logging.InitLogger()

	outputFlag, _ := cmd.Flags().GetString("output")
	fmtr, err := formatter.New(formatter.Format(outputFlag))
	if err != nil {
		return fmt.Errorf("invalid --output value %q: must be table, json, or yaml", outputFlag)
	}

	ctx := context.WithValue(cmd.Context(), common.LogKey, log)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, fmtr)
	cmd.SetContext(ctx)
	return nil
}

// runPreviewMigration opens the configured database read-only in effect (it
// issues no writes), derives the plan, and renders it.
func runPreviewMigration(cmd *cobra.Command, _ []string) error {
	log := logging.InitLogger()
	repository := rvdb.NewRepository(log)

	dbConfig, err := repository.LoadDatabaseConfig()
	if err != nil {
		return fmt.Errorf("failed to load database config: %w", err)
	}
	database, err := repository.OpenDatabase(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer database.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	dialect := rvdb.DialectFromDriver(dbConfig.DriverName)
	grants, err := rvdb.PlanRoleBackfill(ctx, rvdb.NewConn(database, dialect), dialect)
	if err != nil {
		return fmt.Errorf("failed to plan role backfill: %w", err)
	}

	fmtr, ok := cmd.Context().Value(common.OutputFormatterKey).(formatter.Formatter)
	if !ok {
		return fmt.Errorf("output formatter not available in context")
	}
	headers, rows := previewMigrationRows(grants)
	return fmtr.Write(cmd.OutOrStdout(), headers, rows)
}

// previewMigrationRows renders the plan as a table. The order is the order
// PlanRoleBackfill produced, which is sorted by vault name, then role, then
// principal, so the preview and the migration's summary agree.
func previewMigrationRows(grants []rvdb.RoleBackfillGrant) ([]string, [][]string) {
	headers := []string{"Vault", "VaultID", "Principal", "Role", "DerivedFrom"}
	rows := make([][]string, 0, len(grants))
	for _, g := range grants {
		rows = append(rows, []string{g.VaultName, g.VaultID, g.PrincipalID, g.Role, g.Source})
	}
	return headers, rows
}

// InitVaultsPreviewMigration registers the preview-migration command under the
// vaults command group.
func InitVaultsPreviewMigration(vaultsCmd *cobra.Command) {
	vaultsCmd.AddCommand(previewMigrationCmd)
}
