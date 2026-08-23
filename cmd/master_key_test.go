package cmd

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/model"
)

// encodedKey returns a base64 32-byte key built from seed. Distinct seeds give
// distinct keys, and the byte spread passes common.ValidateMasterKey.
func encodedKey(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)*7
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestRequireMasterKeyAdmin_NoClaims(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	_, err := requireMasterKeyAdmin(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestRequireMasterKeyAdmin_NonAdminRole(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{
		UserID: uuid.New(), Username: "bob", Roles: []string{model.RoleSecretsManager},
	}))

	_, err := requireMasterKeyAdmin(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin")
}

func TestRequireMasterKeyAdmin_Admin(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{
		UserID: uuid.New(), Username: "admin", Roles: []string{model.RoleAdmin},
	}))

	claims, err := requireMasterKeyAdmin(cmd)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Username)
}

// TestRequireMasterKeyAdmin_MultiRoleWithAdmin proves a caller holding
// multiple roles, admin among them but not first, still passes.
func TestRequireMasterKeyAdmin_MultiRoleWithAdmin(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{
		UserID: uuid.New(), Username: "admin", Roles: []string{model.RoleSecretsManager, model.RoleAdmin},
	}))

	claims, err := requireMasterKeyAdmin(cmd)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Username)
}

func TestResolveRotationKeys_OldKeyFromConfig(t *testing.T) {
	original := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", original) })
	viper.Set("master_key", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", encodedKey(100))

	oldKey, newKey, oldSource, err := resolveRotationKeys("", "TEST_NEW_MASTER_KEY")
	require.NoError(t, err)
	assert.Len(t, oldKey, 32)
	assert.Len(t, newKey, 32)
	assert.Contains(t, oldSource, "config file")
}

func TestResolveRotationKeys_OldKeyFromEnv(t *testing.T) {
	t.Setenv("TEST_OLD_MASTER_KEY", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", encodedKey(100))

	_, _, oldSource, err := resolveRotationKeys("TEST_OLD_MASTER_KEY", "TEST_NEW_MASTER_KEY")
	require.NoError(t, err)
	assert.Contains(t, oldSource, "TEST_OLD_MASTER_KEY")
}

func TestResolveRotationKeys_MissingNewKeyEnvValue(t *testing.T) {
	original := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", original) })
	viper.Set("master_key", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", "")

	_, _, _, err := resolveRotationKeys("", "TEST_NEW_MASTER_KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TEST_NEW_MASTER_KEY")
	assert.Contains(t, err.Error(), "openssl rand -base64 32")
}

func TestResolveRotationKeys_RejectsWeakNewKey(t *testing.T) {
	original := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", original) })
	viper.Set("master_key", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	_, _, _, err := resolveRotationKeys("", "TEST_NEW_MASTER_KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "known-compromised")
}

func TestResolveRotationKeys_RejectsIdenticalKeys(t *testing.T) {
	original := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", original) })
	viper.Set("master_key", encodedKey(1))
	t.Setenv("TEST_NEW_MASTER_KEY", encodedKey(1))

	_, _, _, err := resolveRotationKeys("", "TEST_NEW_MASTER_KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identical")
}

func TestMasterKeyRotateCmd_IsRegistered(t *testing.T) {
	var found *cobra.Command
	for _, sub := range rootCmd.Commands() {
		if sub.Name() == "master-key" {
			found = sub
		}
	}
	require.NotNil(t, found, "master-key command group must be registered on rootCmd")

	var rotate *cobra.Command
	for _, sub := range found.Commands() {
		if sub.Name() == "rotate" {
			rotate = sub
		}
	}
	require.NotNil(t, rotate, "rotate subcommand must be registered")
	assert.NotNil(t, rotate.Flags().Lookup("new-key-env"))
	assert.NotNil(t, rotate.Flags().Lookup("old-key-env"))
	assert.NotNil(t, rotate.Flags().Lookup("dry-run"))
	assert.NotNil(t, rotate.Flags().Lookup("batch-size"))
	assert.NotNil(t, rotate.Flags().Lookup("yes"))
}
