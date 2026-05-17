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

func TestVersionListCommand_ReturnsDecryptedVersions(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	versions := []model.SecretVersion{
		{SecretID: secretID, Version: 1, Name: "my-secret", Value: "plaintext-value-1", CreatedAt: time.Now()},
		{SecretID: secretID, Version: 2, Name: "my-secret", Value: "plaintext-value-2", CreatedAt: time.Now()},
	}
	tc.MockSecretService.On("GetSecretVersions", mock.Anything, secretID, tc.TestUserID).
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
	assert.Contains(t, out.String(), "plaintext-value-1")
	tc.MockSecretService.AssertExpectations(t)
}

func TestVersionGetCommand_ReturnsDecryptedVersion(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	version := &model.SecretVersion{
		SecretID: secretID, Version: 2,
		Name: "my-secret", Value: "decrypted-value", CreatedAt: time.Now(),
	}
	tc.MockSecretService.On("GetSecretVersion", mock.Anything, secretID, 2, tc.TestUserID).
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
	tc.MockSecretService.On("GetLatestSecretVersion", mock.Anything, secretID, tc.TestUserID).
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
