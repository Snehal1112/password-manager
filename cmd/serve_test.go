package cmd

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newServeListenTestCmd builds a minimal command carrying the same "listen"
// flag serveCmd registers in init(), so servePreRun's Changed() check has
// something real to inspect without depending on the package-global
// serveCmd singleton's mutable state across tests.
func newServeListenTestCmd(defaultListen string) *cobra.Command {
	c := &cobra.Command{Use: "serve"}
	c.Flags().StringVar(&bootstrapConfig.Listen, "listen", defaultListen, "")
	c.SetContext(context.Background())
	return c
}

func TestServePreRun_AppliesConfigListenAddr_WhenFlagNotSet(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("server.listen_addr", ":9999")

	bootstrapConfig.Listen = "127.0.0.1:8774" // the flag's own env-var-or-hardcoded default
	cmd := newServeListenTestCmd(bootstrapConfig.Listen)

	require.NoError(t, servePreRun(cmd, nil))
	assert.Equal(t, ":9999", bootstrapConfig.Listen)
}

func TestServePreRun_ExplicitFlagWinsOverConfig(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("server.listen_addr", ":9999")

	cmd := newServeListenTestCmd("127.0.0.1:8774")
	require.NoError(t, cmd.Flags().Set("listen", ":7777")) // marks the flag Changed
	bootstrapConfig.Listen = ":7777"

	require.NoError(t, servePreRun(cmd, nil))
	assert.Equal(t, ":7777", bootstrapConfig.Listen, "an explicitly passed --listen must not be overwritten by the config file")
}

func TestServePreRun_NoConfigValue_LeavesFlagDefaultUnchanged(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	// server.listen_addr deliberately left unset.

	bootstrapConfig.Listen = "127.0.0.1:8774"
	cmd := newServeListenTestCmd(bootstrapConfig.Listen)

	require.NoError(t, servePreRun(cmd, nil))
	assert.Equal(t, "127.0.0.1:8774", bootstrapConfig.Listen, "an empty config value must not overwrite the flag's own default")
}
