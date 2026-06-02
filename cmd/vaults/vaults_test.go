package vaults

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

// ctxWithFormatter adds a table formatter to the test context so commands that
// write tabular output do not fail with "output formatter not available".
func ctxWithFormatter(ctx context.Context) context.Context {
	fmtr, _ := formatter.New(formatter.FormatTable)
	return context.WithValue(ctx, common.OutputFormatterKey, fmtr)
}

func TestVaultsCreateRequiresName(t *testing.T) {
	tc := testutils.NewTestContext(t)

	cmd := &cobra.Command{Use: "create", Args: createCmd.Args, RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")

	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.Error(t, err)
}

func TestVaultsCreate(t *testing.T) {
	tc := testutils.NewTestContext(t)

	created := &model.Vault{
		ID:            uuid.New(),
		Name:          "my-vault",
		Enabled:       true,
		RetentionDays: 90,
	}
	tc.MockVaultService.On("CreateVault", mock.Anything, mock.MatchedBy(func(r model.CreateVaultRequest) bool {
		return r.Name == "my-vault"
	}), tc.TestUserID).Return(created, nil)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")

	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"my-vault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "my-vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsList(t *testing.T) {
	tc := testutils.NewTestContext(t)

	seeded := []model.Vault{
		{ID: uuid.New(), Name: "default", Enabled: true, RetentionDays: 90},
		{ID: uuid.New(), Name: "my-vault", Enabled: true, RetentionDays: 30},
	}
	tc.MockVaultService.On("ListVaults", mock.Anything, false).Return(seeded, nil)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().Bool("include-deleted", false, "")

	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	output := out.String()
	assert.Contains(t, output, "my-vault")
	assert.Contains(t, output, "default")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsGet(t *testing.T) {
	tc := testutils.NewTestContext(t)

	v := &model.Vault{ID: uuid.New(), Name: "my-vault", Enabled: true, RetentionDays: 90}
	tc.MockVaultService.On("GetVault", mock.Anything, "my-vault").Return(v, nil)

	cmd := &cobra.Command{Use: "get", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"my-vault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "my-vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsDelete(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockVaultService.On("DeleteVault", mock.Anything, "my-vault").Return(nil)

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"my-vault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "deleted successfully")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)

	updated := &model.Vault{ID: uuid.New(), Name: "my-vault", Enabled: false, RetentionDays: 90}
	tc.MockVaultService.On("UpdateVault", mock.Anything, "my-vault", mock.MatchedBy(func(r model.UpdateVaultRequest) bool {
		return r.Enabled != nil && !*r.Enabled
	}), uuid.Nil).Return(updated, nil)

	cmd := &cobra.Command{Use: "update", Args: updateCmd.Args, RunE: updateCmd.RunE}
	cmd.Flags().Bool("enabled", true, "")
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")

	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"my-vault", "--enabled=false"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "my-vault")
	tc.MockVaultService.AssertExpectations(t)
}
