package cmd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/model"
)

// TestVersionListCommand_NeverPrintsValues is the CLI counterpart to
// api.TestListSecretVersionsHandler_NeverEmitsValues.
//
// This test previously asserted the opposite -- it was named
// ReturnsDecryptedVersions and required "plaintext-value-1" to appear in the
// output. That is the § B30 leak, encoded as a requirement: listing versions
// is a metadata operation, and the command now authorizes with
// ActionSecretsReadMetadata, so it must not print values. Reading one value
// goes through "secrets version get", which requires ActionSecretsGet.
func TestVersionListCommand_NeverPrintsValues(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	// The metadata type has no Value field at all, so the command cannot
	// print one even by mistake.
	versions := []model.SecretVersionMetadata{
		{SecretID: secretID, Version: 1, Name: "my-secret", CreatedAt: time.Now()},
		{SecretID: secretID, Version: 2, Name: "my-secret", CreatedAt: time.Now()},
	}
	tc.MockSecretService.On("GetSecretVersionsMetadata", mock.Anything, secretID, mock.Anything).
		Return(versions, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	versionSecretID = secretID.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "list", RunE: versionListCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", secretID.String(), "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))
	cmd.SetOut(&out)

	// Call RunE directly to avoid cobra.OnInitialize global hooks.
	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)

	assert.Contains(t, out.String(), "my-secret", "metadata is still listed")
	assert.Contains(t, out.String(), "VERSION", "the header is still printed")
	assert.NotContains(t, out.String(), "VALUE", "the value column must be gone")
	// The value-bearing service method must never be reached from this path.
	tc.MockSecretService.AssertNotCalled(t, "GetSecretVersions", mock.Anything, mock.Anything, mock.Anything)
	tc.MockSecretService.AssertExpectations(t)
}

func TestVersionGetCommand_ReturnsDecryptedVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	version := &model.SecretVersion{
		SecretID: secretID, Version: 2,
		Name: "my-secret", Value: "decrypted-value", CreatedAt: time.Now(),
	}
	tc.MockSecretService.On("GetSecretVersion", mock.Anything, secretID, 2, mock.Anything).
		Return(version, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	versionSecretID = secretID.String()
	versionNumber = 2

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "get", RunE: versionGetCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", secretID.String(), "")
	cmd.Flags().IntVar(&versionNumber, "version", 2, "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))
	cmd.SetOut(&out)

	// Call RunE directly to avoid cobra.OnInitialize global hooks.
	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "decrypted-value")
	tc.MockSecretService.AssertExpectations(t)
}

func TestVersionLatestCommand_ReturnsDecryptedLatest(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	version := &model.SecretVersion{
		SecretID: secretID, Version: 3,
		Name: "my-secret", Value: "latest-decrypted-value", CreatedAt: time.Now(),
	}
	tc.MockSecretService.On("GetLatestSecretVersion", mock.Anything, secretID, mock.Anything).
		Return(version, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	versionSecretID = secretID.String()

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "latest", RunE: versionLatestCmd.RunE}
	cmd.Flags().StringVar(&versionSecretID, "secret-id", secretID.String(), "")
	cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))
	cmd.SetOut(&out)

	// Call RunE directly to avoid cobra.OnInitialize global hooks.
	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "latest-decrypted-value")
	tc.MockSecretService.AssertExpectations(t)
}

// TestVersionCommands_Forbidden pins the authorization check on all three
// version subcommands.
//
// Before 2026-08-20 none of them called vaultcli.RequireDataAction at all --
// the CLI bypasses PolicyMiddleware entirely, so there was no enforcement
// point whatsoever on this path -- and each used model.NewOwnerScope, which
// survives revocation: a user who created a secret could still read its
// history after losing access to the vault holding it.
func TestVersionCommands_Forbidden(t *testing.T) {
	for _, tc2 := range []struct {
		name       string
		runE       func(*cobra.Command, []string) error
		neverCalls string
	}{
		{"list", versionListCmd.RunE, "GetSecretVersionsMetadata"},
		{"get", versionGetCmd.RunE, "GetSecretVersion"},
		{"latest", versionLatestCmd.RunE, "GetLatestSecretVersion"},
	} {
		t.Run(tc2.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			secretID := uuid.New()
			tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService).Maybe()

			denyRoles := &testutils.MockRoleAssignmentService{}
			denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(false, nil).Maybe()
			tc.MockContainer.RoleAssignmentService = denyRoles

			versionSecretID = secretID.String()
			versionNumber = 1

			cmd := &cobra.Command{Use: tc2.name, RunE: tc2.runE}
			cmd.Flags().StringVar(&versionSecretID, "secret-id", secretID.String(), "")
			cmd.SetContext(context.WithValue(tc.Ctx, common.UserIDKey, tc.TestUserID))

			err := cmd.RunE(cmd, []string{})
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "forbidden")
			// The denial must precede the read, not follow it.
			tc.MockSecretService.AssertNotCalled(t, tc2.neverCalls,
				mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
