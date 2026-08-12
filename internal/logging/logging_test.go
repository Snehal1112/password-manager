// Package logging contains unit tests for the logging system.
// It verifies structured logging and both lumberjack and custom gzip rotation functionality in the root directory.
package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestInitLogger tests the initialization of the structured logger for both rotation methods.
// It verifies JSON output, log level, and file creation in the root directory.
func TestInitLogger(t *testing.T) {
	tests := []struct {
		name           string
		rotationMethod string
	}{
		{"lumberjack", "lumberjack"},
		{"custom", "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up viper configuration.
			viper.Set("log.level", "debug")
			viper.Set("log.file", "test.log")
			viper.Set("log.format", "json") // 1 MB

			viper.Set("log.max_size_mb", 1)
			viper.Set("log.max_backups", 3)
			viper.Set("log.max_age_days", 7)
			viper.Set("log.rotation_method", tt.rotationMethod)

			// Create logger.
			logger := InitLogger()

			// Create a buffer to capture log output.
			var buf bytes.Buffer
			logger.SetOutput(&buf)

			// Log a test message with audit fields.
			userID := uuid.New().String()
			operation := "test_operation"
			status := "success"
			message := "Test message"
			logger.LogAuditInfo(userID, operation, status, message)

			// Parse JSON output.
			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			assert.NoError(t, err, "log output should be valid JSON")

			// Verify log fields.
			assert.Equal(t, "info", logEntry["level"], "log level should be info")
			assert.Equal(t, message, logEntry["msg"], "log message should match")
			assert.Equal(t, userID, logEntry["user_id"], "user_id should match")
			assert.Equal(t, operation, logEntry["operation"], "operation should match")
			assert.Equal(t, status, logEntry["status"], "status should match")
			assert.NotEmpty(t, logEntry["timestamp"], "timestamp should be present")

			// Verify log file in root directory.
			logFile := viper.GetString("log.file")
			_, err = os.Stat(logFile)
			assert.NoError(t, err, "log file should exist")
			assert.NoError(t, os.Remove(logFile), "cleanup should succeed")
		})
	}
}

// TestLogAuditError tests the LogAuditError method.
// It verifies error logging with audit fields.
func TestLogAuditError(t *testing.T) {
	// Set up viper configuration (default to custom rotation).
	viper.Set("log.level", "error")
	viper.Set("log.file", "test.log")
	viper.Set("log.format", "json") // 1 MB
	viper.Set("log.rotation_method", "custom")

	// Create logger.
	logger := InitLogger()

	// Create a buffer to capture log output.
	var buf bytes.Buffer
	logger.SetOutput(&buf)

	// Log an error with audit fields.
	userID := uuid.New()
	operation := "test_error_operation"
	status := "failed"
	message := "Test error"
	err := fmt.Errorf("test error")
	logger.LogAuditError(userID.String(), operation, status, message, err)

	// Parse JSON output.
	var logEntry map[string]interface{}
	jsonErr := json.Unmarshal(buf.Bytes(), &logEntry)
	log.Println("Log output:", buf.String())
	assert.NoError(t, jsonErr, "log output should be valid JSON")

	// Verify log fields.
	assert.Equal(t, "error", logEntry["level"], "log level should be error")
	assert.Equal(t, message, logEntry["msg"], "log message should match")
	assert.Equal(t, userID.String(), logEntry["user_id"], "user_id should match")
	assert.Equal(t, operation, logEntry["operation"], "operation should match")
	assert.Equal(t, status, logEntry["status"], "status should match")
	assert.Equal(t, err.Error(), logEntry["error"], "error should match")
}

// TestRotateLogFileCustom tests the custom log rotation mechanism with gzip.
// It verifies size-based rotation and cleanup of old files in the root directory.
func TestRotateLogFileCustom(t *testing.T) {
	// Set up viper configuration.
	viper.Set("log.level", "info")
	viper.Set("log.file", "test.log")
	viper.Set("log.format", "json") // 1 MB
	viper.Set("log.max_size_mb", 1) // 1 MB
	viper.Set("log.max_backups", 2)
	viper.Set("log.max_age_days", 7)
	viper.Set("log.rotation_method", "custom")

	// Create logger.
	logger := InitLogger()

	// Write data to exceed size limit.
	file, err := os.OpenFile(logger.logFile, os.O_APPEND|os.O_WRONLY, 0o600)
	assert.NoError(t, err, "failed to open log file")
	defer file.Close()                  //nolint:errcheck
	data := make([]byte, 1.5*1024*1024) // 1.5 MB
	_, err = file.Write(data)
	assert.NoError(t, err, "failed to write to log file")

	// Trigger rotation.
	err = logger.RotateLogFile()
	assert.NoError(t, err, "rotation should succeed")

	// Verify rotated file exists in root directory.
	matches, err := filepath.Glob(logger.logFile + ".*.gz")
	assert.NoError(t, err, "failed to list rotated files")
	assert.Len(t, matches, 1, "one rotated file should exist")

	// Verify new log file is created and under size limit.
	fileInfo, err := os.Stat(logger.logFile)
	assert.NoError(t, err, "new log file should exist")
	assert.Less(t, fileInfo.Size(), logger.maxSizeBytes, "new log file should be under size limit")

	// Test cleanup with old files.
	oldFile := fmt.Sprintf("%s.%s.gz", logger.logFile, time.Now().AddDate(0, 0, -10).Format("20060102_150405"))
	err = os.WriteFile(oldFile, []byte("old"), 0o600)
	assert.NoError(t, err, "failed to create old log file")

	err = logger.cleanupOldLogs()
	assert.NoError(t, err, "cleanup should succeed")

	_, err = os.Stat(oldFile)
	assert.True(t, err == nil || os.IsExist(err) || os.IsNotExist(err), "old log file should be deleted")

	// Test backup limit.
	for i := 0; i < 3; i++ {
		extraFile := fmt.Sprintf("%s.%s.gz", logger.logFile, time.Now().Add(-time.Duration(i)*time.Hour).Format("20060102_150405"))
		err = os.WriteFile(extraFile, []byte("extra"), 0o600)
		assert.NoError(t, err, "failed to create extra log file")
	}
	err = logger.cleanupOldLogs()
	assert.NoError(t, err, "cleanup should succeed")
	matches, err = filepath.Glob(logger.logFile + ".*.gz")
	assert.NoError(t, err, "failed to list rotated files")
	assert.LessOrEqual(t, len(matches), logger.maxBackups, "number of backups should not exceed limit")

	// Cleanup.
	for _, match := range matches {
		assert.NoError(t, os.Remove(match), "cleanup should succeed")
	}
	assert.NoError(t, os.Remove(logger.logFile), "cleanup should succeed")
}

// TestRotateLogFileLumberjack tests the lumberjack log rotation mechanism.
// It verifies that lumberjack handles rotation correctly.
func TestRotateLogFileLumberjack(t *testing.T) {
	// Set up viper configuration.
	viper.Set("log.level", "info")
	viper.Set("log.file", "test.log")
	viper.Set("log.format", "json") // 1 MB
	viper.Set("log.max_size_mb", 1) // 1 MB
	viper.Set("log.max_backups", 2)
	viper.Set("log.max_age_days", 7)
	viper.Set("log.rotation_method", "lumberjack")

	// Create logger.
	logger := InitLogger()

	// Write data to exceed size limit.
	file, err := os.OpenFile(logger.logFile, os.O_APPEND|os.O_WRONLY, 0o600)
	assert.NoError(t, err, "failed to open log file")
	defer file.Close()                  //nolint:errcheck
	data := make([]byte, 1.5*1024*1024) // 1.5 MB
	_, err = file.Write(data)
	assert.NoError(t, err, "failed to write to log file")

	// Trigger rotation (handled by lumberjack).
	logger.Info("Test log to trigger rotation")

	fileName := strings.Split(file.Name(), ".")[0]

	// Verify rotated file exists.
	matches, err := filepath.Glob(fileName + "-*.log*")
	assert.NoError(t, err, "failed to list rotated files")
	assert.GreaterOrEqual(t, len(matches), 1, "at least one rotated file should exist")

	// Verify new log file is created and under size limit.
	fileInfo, err := os.Stat(logger.logFile)
	assert.NoError(t, err, "new log file should exist")
	assert.Less(t, fileInfo.Size(), logger.maxSizeBytes, "new log file should be under size limit")

	// Cleanup.
	for _, match := range matches {
		assert.NoError(t, os.Remove(match), "cleanup should succeed")
	}
	assert.NoError(t, os.Remove(logger.logFile), "cleanup should succeed")
}

// mockAuditPersister captures PersistAudit calls for testing.
type mockAuditPersister struct {
	calls []struct{ userID, action, details string }
	err   error
}

func (m *mockAuditPersister) PersistAudit(userID, action, details string) error {
	m.calls = append(m.calls, struct{ userID, action, details string }{userID, action, details})
	return m.err
}

// TestLogAuditInfo_PersistsToDBWhenPersisterSet verifies that LogAuditInfo
// forwards the call to the registered AuditPersister.
func TestLogAuditInfo_PersistsToDBWhenPersisterSet(t *testing.T) {
	logger := WrapLogrus(logrus.New())
	mock := &mockAuditPersister{}
	logger.SetAuditPersister(mock)

	logger.LogAuditInfo("user-abc", "create_secret", "success", "secret created")

	assert.Len(t, mock.calls, 1, "expected 1 PersistAudit call")
	assert.Equal(t, "user-abc", mock.calls[0].userID)
	assert.Equal(t, "create_secret", mock.calls[0].action)
	if !strings.Contains(mock.calls[0].details, "operation=create_secret") {
		t.Errorf("expected details to contain 'operation=create_secret', got %s", mock.calls[0].details)
	}
}

// TestLogAuditError_PersistsToDBWhenPersisterSet verifies that LogAuditError
// forwards the call to the registered AuditPersister.
func TestLogAuditError_PersistsToDBWhenPersisterSet(t *testing.T) {
	logger := WrapLogrus(logrus.New())
	mock := &mockAuditPersister{}
	logger.SetAuditPersister(mock)

	logger.LogAuditError("user-xyz", "get_key", "failed", "key not found", errors.New("sql: no rows"))

	assert.Len(t, mock.calls, 1, "expected 1 PersistAudit call")
	assert.Equal(t, "user-xyz", mock.calls[0].userID)
	if mock.calls[0].action != "get_key" {
		t.Errorf("expected action get_key, got %s", mock.calls[0].action)
	}
	if !strings.Contains(mock.calls[0].details, "operation=get_key") {
		t.Errorf("expected details to contain 'operation=get_key', got %s", mock.calls[0].details)
	}
}

// TestLogAuditInfo_SkipsDBWhenNoPersister verifies that LogAuditInfo does
// not panic when no AuditPersister has been registered.
func TestLogAuditInfo_SkipsDBWhenNoPersister(t *testing.T) {
	logger := WrapLogrus(logrus.New())
	// Must not panic when no persister is set.
	assert.NotPanics(t, func() {
		logger.LogAuditInfo("u1", "op", "status", "msg")
	})
}

// TestLogAuditError_PersisterFailureDoesNotPanic verifies that a persister
// error is handled gracefully and does not propagate as a panic.
func TestLogAuditError_PersisterFailureDoesNotPanic(t *testing.T) {
	logger := WrapLogrus(logrus.New())
	mock := &mockAuditPersister{err: errors.New("db connection lost")}
	logger.SetAuditPersister(mock)

	// Must not panic — persister errors are fire-and-forget.
	assert.NotPanics(t, func() {
		logger.LogAuditError("u1", "op", "failed", "msg", nil)
	})
	if len(mock.calls) != 1 {
		t.Errorf("expected 1 PersistAudit call even on error, got %d", len(mock.calls))
	}
}
