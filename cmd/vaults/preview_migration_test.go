package vaults

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/model"
)

// TestPreviewMigrationRows renders one row per grant, in the order
// PlanRoleBackfill produced, with the vault name first so an operator can scan
// per vault.
func TestPreviewMigrationRows(t *testing.T) {
	grants := []rvdb.RoleBackfillGrant{
		{PrincipalID: "22222222-2222-2222-2222-222222222222", VaultID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			VaultName: "prod", Role: model.RoleKeyVaultSecretsOfficer, Source: "secrets"},
		{PrincipalID: "11111111-1111-1111-1111-111111111111", VaultID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			VaultName: "prod", Role: model.RoleKeyVaultAdministrator, Source: "global-admin"},
	}

	headers, rows := previewMigrationRows(grants)
	assert.Equal(t, []string{"Vault", "VaultID", "Principal", "Role", "DerivedFrom"}, headers)
	require.Len(t, rows, 2)
	assert.Equal(t, []string{
		"prod", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"22222222-2222-2222-2222-222222222222",
		model.RoleKeyVaultSecretsOfficer, "secrets",
	}, rows[0])
	assert.Equal(t, []string{
		"prod", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"11111111-1111-1111-1111-111111111111",
		model.RoleKeyVaultAdministrator, "global-admin",
	}, rows[1])
}

// TestPreviewMigrationRowsEmpty returns headers and no rows, never nil rows,
// so the formatter renders an empty table instead of failing.
func TestPreviewMigrationRowsEmpty(t *testing.T) {
	headers, rows := previewMigrationRows(nil)
	assert.Len(t, headers, 5)
	assert.NotNil(t, rows)
	assert.Empty(t, rows)
}

// TestInitVaultsPreviewMigrationRegisters asserts the command is attached with
// its own PersistentPreRunE, so the root pre-run does not initialise (and
// therefore migrate) the database before the preview reads it.
func TestInitVaultsPreviewMigrationRegisters(t *testing.T) {
	root := &cobra.Command{Use: "vaults"}
	InitVaultsPreviewMigration(root)

	var found *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "preview-migration" {
			found = c
		}
	}
	require.NotNil(t, found, "preview-migration must be registered under vaults")
	assert.NotNil(t, found.PersistentPreRunE,
		"preview-migration must override the root pre-run so it does not migrate the database")
	assert.NotNil(t, found.RunE)
}
