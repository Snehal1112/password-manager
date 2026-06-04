// Package bootstrap provides tests for the application bootstrap layer.
package bootstrap

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/softdelete"
)

// newTestLogger returns a minimal *logging.Logger for use in tests.
func newTestLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

// ----- buildServerConfigFromViper -----

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

// ----- DatabaseInitializer constructor -----

func TestNewDatabaseInitializer(t *testing.T) {
	t.Parallel()
	logger := newTestLogger()
	di := NewDatabaseInitializer(logger)
	assert.NotNil(t, di)
}

// ----- ServerStarter constructor -----

func TestNewServerStarter(t *testing.T) {
	t.Parallel()
	logger := newTestLogger()
	ss := NewServerStarter(logger)
	assert.NotNil(t, ss)
}

// ----- ConfigurationValidator constructor -----

func TestNewConfigurationValidator(t *testing.T) {
	t.Parallel()
	logger := newTestLogger()
	cv := NewConfigurationValidator(logger)
	assert.NotNil(t, cv)
}

// ----- ConfigurationValidator.Validate -----

// validServerCfg returns a config.Config with a non-nil Logger,
// the minimum required by ConfigurationValidator.Validate.
func validServerCfg() *config.Config {
	return &config.Config{Logger: newTestLogger()}
}

// validBootstrapCfg returns a Config that satisfies all validator checks.
func validBootstrapCfg() *Config {
	return &Config{
		DatabaseName: "test.db",
		Listen:       ":8080",
		BasePath:     "/api",
		Logger:       logrus.New(),
	}
}

func TestValidate_Success(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	err := cv.Validate(validBootstrapCfg(), validServerCfg())
	require.NoError(t, err)
}

func TestValidate_MissingDatabaseName(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	cfg := validBootstrapCfg()
	cfg.DatabaseName = ""
	err := cv.Validate(cfg, validServerCfg())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database name is required")
}

func TestValidate_MissingListenAddress(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	cfg := validBootstrapCfg()
	cfg.Listen = ""
	err := cv.Validate(cfg, validServerCfg())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen address is required")
}

func TestValidate_EmptyBasePathDefaultsToSlash(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	cfg := validBootstrapCfg()
	cfg.BasePath = ""
	err := cv.Validate(cfg, validServerCfg())
	// Validation should succeed and BasePath must be set to "/"
	require.NoError(t, err)
	assert.Equal(t, "/", cfg.BasePath)
}

func TestValidate_NilLogger(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	cfg := validBootstrapCfg()
	cfg.Logger = nil
	err := cv.Validate(cfg, validServerCfg())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestValidate_NilServerLogger(t *testing.T) {
	t.Parallel()
	cv := NewConfigurationValidator(newTestLogger())
	serverCfg := &config.Config{Logger: nil}
	err := cv.Validate(validBootstrapCfg(), serverCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server logger is required")
}

// ----- newBootstrap / Config / GetServiceContainer -----

func TestNewBootstrap_ReturnsNonNil(t *testing.T) {
	t.Parallel()
	bs := newBootstrap(validServerCfg())
	require.NotNil(t, bs)
}

func TestBootstrap_ConfigReturnsServerCfg(t *testing.T) {
	t.Parallel()
	serverCfg := validServerCfg()
	bs := newBootstrap(serverCfg)
	assert.Equal(t, serverCfg, bs.Config())
}

func TestBootstrap_GetServiceContainerInitiallyNil(t *testing.T) {
	t.Parallel()
	bs := newBootstrap(validServerCfg())
	assert.Nil(t, bs.GetServiceContainer())
}

func TestNewBootstrap_InitializesSubComponents(t *testing.T) {
	t.Parallel()
	serverCfg := validServerCfg()
	bs := newBootstrap(serverCfg)
	// Verify the three sub-initializers were wired up.
	assert.NotNil(t, bs.dbInitializer)
	assert.NotNil(t, bs.serverStarter)
	assert.NotNil(t, bs.configValidator)
}

// ----- Shutdown with nil fields -----

func TestShutdown_AllNilFields_NoError(t *testing.T) {
	t.Parallel()
	bs := &bootstrap{}
	err := bs.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestShutdown_NilSchedulers_NoError(t *testing.T) {
	t.Parallel()
	// Only cfg set — all scheduler fields are nil.
	bs := &bootstrap{cfg: validServerCfg()}
	err := bs.Shutdown(context.Background())
	assert.NoError(t, err)
}

// ----- Shutdown with a live PurgeScheduler -----

func TestShutdown_WithPurgeScheduler_StopsCleanly(t *testing.T) {
	t.Parallel()

	// Open an in-memory SQLite DB — PurgeScheduler just needs a *sql.DB;
	// it will fail silently on the purge query but that is acceptable here.
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	logger := newTestLogger()
	sdCfg := config.SoftDeleteConfig{RetentionDays: 30}
	ps := softdelete.NewPurgeScheduler(db, sdCfg, logger)
	ps.Start(context.Background())

	bs := &bootstrap{purgeScheduler: ps}
	err = bs.Shutdown(context.Background())
	assert.NoError(t, err)
}
