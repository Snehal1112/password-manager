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

// TestBuildServerConfigFromViper_HTTP2Default verifies that HTTP/2 is enabled
// even when server.http2.enabled is absent from the YAML config.
func TestBuildServerConfigFromViper_HTTP2Default(t *testing.T) {
	// Use a clean viper state without the http2 key set.
	viper.Reset()
	defer viper.Reset()

	cfg := buildServerConfigFromViper()
	assert.True(t, cfg.EnableHTTP2, "HTTP/2 must be enabled by default when key is absent")
}
