package vaults

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/model"
)

// TestMain registers all Init* functions once to cover their registration
// statements, then delegates to the standard test runner.
func TestMain(m *testing.M) {
	parent := &cobra.Command{Use: "vaults"}
	InitVaultsCreate(parent)
	InitVaultsDelete(parent)
	InitVaultsGet(parent)
	InitVaultsList(parent)
	InitVaultsPurge(parent)
	InitVaultsRecover(parent)
	InitVaultsUpdate(parent)
	os.Exit(m.Run())
}

// ---- helpers ----

func newVltCmd(runE func(*cobra.Command, []string) error, args []string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "test", RunE: runE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	return cmd, &buf
}

// ---- purgeCmd tests ----

func TestPurgeCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("PurgeVault", mock.Anything, "my-vault").Return(nil)

	cmd, buf := newVltCmd(purgeCmd.RunE, []string{"my-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctxWithFormatter(tc.Ctx))

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "purged successfully")
	tc.MockVaultService.AssertExpectations(t)
}

func TestPurgeCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("PurgeVault", mock.Anything, "my-vault").
		Return(fmt.Errorf("cannot purge"))

	cmd, _ := newVltCmd(purgeCmd.RunE, []string{"my-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctxWithFormatter(tc.Ctx))

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to purge vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- recoverCmd tests ----

func TestRecoverCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("RecoverVault", mock.Anything, "my-vault").Return(nil)

	cmd, buf := newVltCmd(recoverCmd.RunE, []string{"my-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctxWithFormatter(tc.Ctx))

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "recovered successfully")
	tc.MockVaultService.AssertExpectations(t)
}

func TestRecoverCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("RecoverVault", mock.Anything, "broken-vault").
		Return(fmt.Errorf("vault not found"))

	cmd, _ := newVltCmd(recoverCmd.RunE, []string{"broken-vault"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctxWithFormatter(tc.Ctx))

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to recover vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- createCmd additional error paths ----

func TestVaultsCreate_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("CreateVault", mock.Anything, mock.Anything, tc.TestUserID).
		Return(nil, fmt.Errorf("vault creation failed"))

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"bad-vault"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsCreate_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	created := &model.Vault{
		ID:            uuid.New(),
		Name:          "nofmt-vault",
		Enabled:       true,
		RetentionDays: 90,
	}
	tc.MockVaultService.On("CreateVault", mock.Anything, mock.Anything, tc.TestUserID).Return(created, nil)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	// Context without formatter.
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"nofmt-vault"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsCreate_WithPurgeProtection(t *testing.T) {
	tc := testutils.NewTestContext(t)
	created := &model.Vault{
		ID:              uuid.New(),
		Name:            "protected-vault",
		Enabled:         true,
		PurgeProtection: true,
		RetentionDays:   30,
	}
	tc.MockVaultService.On("CreateVault", mock.Anything,
		mock.MatchedBy(func(r model.CreateVaultRequest) bool {
			return r.Name == "protected-vault" &&
				r.PurgeProtection != nil && *r.PurgeProtection
		}), tc.TestUserID).Return(created, nil)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"protected-vault", "--purge-protection=true"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "protected-vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsCreate_WithRetentionDays(t *testing.T) {
	tc := testutils.NewTestContext(t)
	created := &model.Vault{
		ID:            uuid.New(),
		Name:          "retention-vault",
		Enabled:       true,
		RetentionDays: 60,
	}
	tc.MockVaultService.On("CreateVault", mock.Anything,
		mock.MatchedBy(func(r model.CreateVaultRequest) bool {
			return r.Name == "retention-vault" &&
				r.RetentionDays != nil && *r.RetentionDays == 60
		}), tc.TestUserID).Return(created, nil)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"retention-vault", "--retention-days=60"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "retention-vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- getCmd additional error paths ----

func TestVaultsGet_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("GetVault", mock.Anything, "missing-vault").
		Return(nil, fmt.Errorf("not found"))

	cmd := &cobra.Command{Use: "get", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"missing-vault"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to retrieve vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsGet_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	v := &model.Vault{ID: uuid.New(), Name: "nofmt-vault", Enabled: true, RetentionDays: 90}
	tc.MockVaultService.On("GetVault", mock.Anything, "nofmt-vault").Return(v, nil)

	cmd := &cobra.Command{Use: "get", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	// No formatter in context.
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"nofmt-vault"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- listCmd additional error paths ----

func TestVaultsList_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, false).
		Return(nil, fmt.Errorf("db error"))

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().Bool("include-deleted", false, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list vaults")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsList_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, false).
		Return([]model.Vault{}, nil)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().Bool("include-deleted", false, "")
	// No formatter.
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsList_IncludeDeleted(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{
			{ID: uuid.New(), Name: "active-vault", Enabled: true},
			{ID: uuid.New(), Name: "deleted-vault", Enabled: false},
		}, nil)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().Bool("include-deleted", false, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"--include-deleted=true"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "active-vault")
	assert.Contains(t, out.String(), "deleted-vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- deleteCmd additional error paths ----

func TestVaultsDelete_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("DeleteVault", mock.Anything, "locked-vault").
		Return(fmt.Errorf("vault is protected"))

	cmd := &cobra.Command{Use: "delete", Args: cobra.ExactArgs(1), RunE: deleteCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"locked-vault"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete vault")
	tc.MockVaultService.AssertExpectations(t)
}

// ---- updateCmd additional error paths ----

func TestVaultsUpdate_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "error-vault"}}, nil)
	tc.MockVaultService.On("UpdateVault", mock.Anything, "error-vault", mock.Anything, tc.TestUserID).
		Return(nil, fmt.Errorf("update rejected"))

	cmd := &cobra.Command{Use: "update", Args: updateCmd.Args, RunE: updateCmd.RunE}
	cmd.Flags().Bool("enabled", true, "")
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"error-vault", "--enabled=false"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update vault")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsUpdate_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "nofmt-vault"}}, nil)
	updated := &model.Vault{ID: uuid.New(), Name: "nofmt-vault", Enabled: false}
	tc.MockVaultService.On("UpdateVault", mock.Anything, "nofmt-vault", mock.Anything, tc.TestUserID).
		Return(updated, nil)

	cmd := &cobra.Command{Use: "update", Args: updateCmd.Args, RunE: updateCmd.RunE}
	cmd.Flags().Bool("enabled", true, "")
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	// No formatter in context.
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{"nofmt-vault", "--enabled=false"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockVaultService.AssertExpectations(t)
}

func TestVaultsUpdate_WithPurgeAndRetention(t *testing.T) {
	tc := testutils.NewTestContext(t)
	updated := &model.Vault{
		ID:              uuid.New(),
		Name:            "full-update-vault",
		Enabled:         true,
		PurgeProtection: true,
		RetentionDays:   45,
	}
	tc.MockVaultService.On("ListVaults", mock.Anything, true).
		Return([]model.Vault{{ID: uuid.New(), Name: "full-update-vault"}}, nil)
	tc.MockVaultService.On("UpdateVault", mock.Anything, "full-update-vault",
		mock.MatchedBy(func(r model.UpdateVaultRequest) bool {
			return r.PurgeProtection != nil && *r.PurgeProtection &&
				r.RetentionDays != nil && *r.RetentionDays == 45
		}), tc.TestUserID).Return(updated, nil)

	cmd := &cobra.Command{Use: "update", Args: updateCmd.Args, RunE: updateCmd.RunE}
	cmd.Flags().Bool("enabled", true, "")
	cmd.Flags().Bool("purge-protection", false, "")
	cmd.Flags().Int("retention-days", 0, "")
	cmd.SetContext(ctxWithFormatter(tc.Ctx))
	cmd.SetArgs([]string{"full-update-vault", "--purge-protection=true", "--retention-days=45"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "full-update-vault")
	tc.MockVaultService.AssertExpectations(t)
}
