package cliclient

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vaultTestCmd builds a command with a --vault flag, setting it only when
// flagValue is non-empty so Flags().Changed reflects real usage. It also
// clears any viper "vault" key so a developer's .rocketvault.yaml cannot
// change the result.
func vaultTestCmd(t *testing.T, flagValue string) *cobra.Command {
	t.Helper()
	viper.Set("vault", "")
	t.Cleanup(func() { viper.Set("vault", "") })

	c := &cobra.Command{}
	c.Flags().String("vault", "", "")
	if flagValue != "" {
		require.NoError(t, c.Flags().Set("vault", flagValue))
	}
	return c
}

func TestResolveRemoteVault_FlagWins(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "from-env")
	target := &Target{Vault: "from-context"}
	assert.Equal(t, "from-flag", ResolveRemoteVault(vaultTestCmd(t, "from-flag"), target))
}

func TestResolveRemoteVault_EnvBeatsContext(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "from-env")
	target := &Target{Vault: "from-context"}
	assert.Equal(t, "from-env", ResolveRemoteVault(vaultTestCmd(t, ""), target))
}

func TestResolveRemoteVault_ContextWhenNoFlagOrEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "")
	target := &Target{Vault: "from-context"}
	assert.Equal(t, "from-context", ResolveRemoteVault(vaultTestCmd(t, ""), target))
}

func TestResolveRemoteVault_DefaultsWhenNothingSet(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "")
	assert.Equal(t, "default", ResolveRemoteVault(vaultTestCmd(t, ""), &Target{}))
}

func TestResolveRemoteVault_NilTarget(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "")
	assert.Equal(t, "default", ResolveRemoteVault(vaultTestCmd(t, ""), nil))
}

// A flag left at a non-empty default is not an explicit choice, so an
// exported ROCKETVAULT_VAULT must still win. This mirrors
// common.ResolveVaultName's Flags().Changed test.
func TestResolveRemoteVault_UnchangedFlagDefaultLosesToEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "from-env")
	viper.Set("vault", "")
	t.Cleanup(func() { viper.Set("vault", "") })

	c := &cobra.Command{}
	c.Flags().String("vault", "flag-default", "")

	assert.Equal(t, "from-env", ResolveRemoteVault(c, &Target{}))
}

func TestResolveRemoteVault_ConfigBeatsOnlyTheDefault(t *testing.T) {
	t.Setenv("ROCKETVAULT_VAULT", "")
	viper.Set("vault", "from-config")
	t.Cleanup(func() { viper.Set("vault", "") })

	c := &cobra.Command{}
	c.Flags().String("vault", "", "")

	assert.Equal(t, "from-config", ResolveRemoteVault(c, &Target{}))
	assert.Equal(t, "from-context", ResolveRemoteVault(c, &Target{Vault: "from-context"}))
}
