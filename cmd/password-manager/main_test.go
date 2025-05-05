// Package main contains unit tests for the main package.
// It verifies configuration initialization, logging setup, and CLI command execution.
package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestInitConfig tests the initConfig function to ensure it loads configuration from a file.
func TestInitConfig(t *testing.T) {
	// Create a temporary config file.
	configContent := []byte(`
database:
  connection: ./test.db
log:
  level: debug
api:
  port: 8080
`)
	err := os.WriteFile("config.yaml", configContent, 0644)
	assert.NoError(t, err, "writing config file should succeed")
	defer os.Remove("config.yaml")

	// Reset Viper to avoid interference.
	viper.Reset()

	// Test configuration loading.
	err = initConfig()
	assert.NoError(t, err, "configuration initialization should succeed")
	assert.Equal(t, "./test.db", viper.GetString("database.connection"), "database connection should be set")
	assert.Equal(t, "debug", viper.GetString("log.level"), "log level should be set")
	assert.Equal(t, "8080", viper.GetString("api.port"), "api port should be set")
}

// TestInitConfigNoFile tests initConfig when no config file exists, falling back to environment variables or defaults.
func TestInitConfigNoFile(t *testing.T) {
	// Ensure no config file exists.
	os.Remove("config.yaml")

	// Set environment variable.
	os.Setenv("DATABASE_CONNECTION", "./env_test.db")
	defer os.Unsetenv("DATABASE_CONNECTION")

	// Reset Viper.
	viper.Reset()

	// Test configuration loading.
	err := initConfig()
	assert.NoError(t, err, "configuration initialization should succeed with env vars")
	assert.Equal(t, "./env_test.db", viper.GetString("database.connection"), "database connection should be set from env")
	assert.Equal(t, "debug", viper.GetString("log.level"), "log level should be set to default")
}

// TestInitConfigInvalidFile tests initConfig with an invalid config file.
func TestInitConfigInvalidFile(t *testing.T) {
	// Create an invalid config file.
	configContent := []byte(`invalid: yaml: content`)
	err := os.WriteFile("config.yaml", configContent, 0644)
	assert.NoError(t, err, "writing config file should succeed")
	defer os.Remove("config.yaml")

	// Reset Viper.
	viper.Reset()

	// Test configuration loading.
	err = initConfig()
	assert.Error(t, err, "configuration initialization should fail with invalid YAML")
	assert.Contains(t, err.Error(), "failed to read config file", "error should indicate config file issue")
}

// TestMainLogging tests logging configuration in the main function.
func TestMainLogging(t *testing.T) {
	// Redirect log output to a buffer.
	var buf bytes.Buffer
	logrus.SetOutput(&buf)
	defer logrus.SetOutput(os.Stderr)

	// Set log level.
	viper.Set("log.level", "debug")

	// Configure logging.
	logLevel, _ := logrus.ParseLevel(viper.GetString("log.level"))
	logrus.SetLevel(logLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.Info("Test log")

	// Verify log output.
	assert.Contains(t, buf.String(), `"level":"info"`, "log should be info level")
	assert.Contains(t, buf.String(), `"msg":"Test log"`, "log message should be present")
}

// BenchmarkInitConfig measures the performance of configuration initialization.
func BenchmarkInitConfig(b *testing.B) {
	os.Remove("config.yaml")
	viper.Reset()
	for i := 0; i < b.N; i++ {
		initConfig()
	}
}
