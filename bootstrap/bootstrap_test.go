package bootstrap

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestBuildServerConfigFromViper(t *testing.T) {
	viper.Set("server.tls.enabled", true)
	viper.Set("server.tls.cert_file", "/tmp/test.crt")
	viper.Set("server.tls.key_file", "/tmp/test.key")
	defer viper.Reset()

	cfg := buildServerConfigFromViper()
	assert.True(t, cfg.EnableTLS)
	assert.Equal(t, "/tmp/test.crt", cfg.CertFile)
	assert.Equal(t, "/tmp/test.key", cfg.KeyFile)
}
