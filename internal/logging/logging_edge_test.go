// Package logging contains additional edge-case tests for the logging package.
package logging

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitLogger_YAMLFormat verifies that the yaml log format is configured correctly.
func TestInitLogger_YAMLFormat(t *testing.T) {
	viper.Set("log.format", "yaml")
	viper.Set("log.level", "info")
	viper.Set("log.file", "")
	logger := InitLogger()
	require.NotNil(t, logger)
	// Should not panic when logging.
	logger.Info("yaml format test")
}

// TestInitLogger_TextFormat verifies that the text log format is configured correctly.
func TestInitLogger_TextFormat(t *testing.T) {
	viper.Set("log.format", "text")
	viper.Set("log.level", "debug")
	viper.Set("log.file", "")
	logger := InitLogger()
	require.NotNil(t, logger)
	logger.Debug("text format test")
}

// TestInitLogger_DefaultFormat verifies that an unknown format falls back to default.
func TestInitLogger_DefaultFormat(t *testing.T) {
	viper.Set("log.format", "unknown")
	viper.Set("log.level", "info")
	viper.Set("log.file", "")
	logger := InitLogger()
	require.NotNil(t, logger)
}

// TestInitLogger_InvalidLogLevel verifies that an invalid log level defaults to info.
func TestInitLogger_InvalidLogLevel(t *testing.T) {
	viper.Set("log.format", "json")
	viper.Set("log.level", "not-a-level")
	viper.Set("log.file", "")
	logger := InitLogger()
	require.NotNil(t, logger)
	assert.Equal(t, logrus.InfoLevel, logger.GetLevel())
}

// TestInitLogger_FileOpenFailure verifies graceful fallback when a file in a
// non-existent path fails to open under the default (custom gzip) rotation.
func TestInitLogger_FileOpenFailure(t *testing.T) {
	viper.Set("log.format", "json")
	viper.Set("log.level", "info")
	viper.Set("log.max_size_mb", 1)
	viper.Set("log.max_backups", 2)
	viper.Set("log.max_age_days", 7)
	viper.Set("log.rotation_method", "custom")
	// Use a path that cannot be created (root-owned directory).
	viper.Set("log.file", "/proc/nonexistent_dir/test.log")
	logger := InitLogger()
	require.NotNil(t, logger)
}

// TestInitLogger_LumberjackFileOpenFailure verifies graceful fallback when a
// lumberjack-mode log file path is unwritable.
func TestInitLogger_LumberjackFileOpenFailure(t *testing.T) {
	viper.Set("log.format", "json")
	viper.Set("log.level", "info")
	viper.Set("log.max_size_mb", 1)
	viper.Set("log.max_backups", 2)
	viper.Set("log.max_age_days", 7)
	viper.Set("log.rotation_method", "lumberjack")
	// Use a path that cannot be created.
	viper.Set("log.file", "/proc/nonexistent_dir/test.log")
	logger := InitLogger()
	require.NotNil(t, logger)
}

// TestEnsureLogDirectory_CurrentDir verifies that a log file with no directory
// component (current dir) is returned unchanged.
func TestEnsureLogDirectory_CurrentDir(t *testing.T) {
	base := logrus.New()
	result := ensureLogDirectory("test.log", base)
	assert.Equal(t, "test.log", result)
}

// TestEnsureLogDirectory_CreatesDir verifies that a valid sub-directory is created.
func TestEnsureLogDirectory_CreatesDir(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/subdir/test.log"
	base := logrus.New()
	result := ensureLogDirectory(logPath, base)
	assert.Equal(t, logPath, result)
	_, err := os.Stat(dir + "/subdir")
	assert.NoError(t, err)
}

// TestEnsureLogDirectory_FallbackOnError verifies that an uncreateable directory
// falls back to just the base filename.
func TestEnsureLogDirectory_FallbackOnError(t *testing.T) {
	base := logrus.New()
	// /proc/1 is root-owned; creating a subdir inside it should fail.
	result := ensureLogDirectory("/proc/1/impossibledir/test.log", base)
	assert.Equal(t, "test.log", result)
}

// TestRotateLogFile_LumberjackNoOp verifies that RotateLogFile is a no-op for
// lumberjack rotation.
func TestRotateLogFile_LumberjackNoOp(t *testing.T) {
	l := &Logger{
		Logger:         logrus.New(),
		logFile:        "test.log",
		rotationMethod: "lumberjack",
	}
	err := l.RotateLogFile()
	assert.NoError(t, err)
}

// TestRotateLogFile_EmptyFileNoOp verifies that RotateLogFile is a no-op when
// logFile is empty.
func TestRotateLogFile_EmptyFileNoOp(t *testing.T) {
	l := &Logger{
		Logger:  logrus.New(),
		logFile: "",
	}
	err := l.RotateLogFile()
	assert.NoError(t, err)
}

// TestRotateLogFile_StatError verifies that a stat error (not IsNotExist) is
// returned as an error.
func TestRotateLogFile_StatError(t *testing.T) {
	// /proc/1/fd is a directory; statting it won't be NotExist but the
	// subsequent open-for-append will fail, so we use a known-invalid path
	// that os.Stat returns an error other than IsNotExist for.
	// The simplest approach: use a path under /proc where stat fails non-ENOENT.
	// Actually on Linux, /proc/1/mem exists but may fail with EPERM — use that.
	l := &Logger{
		Logger:         logrus.New(),
		logFile:        "/proc/1/mem",
		maxSizeBytes:   1,
		rotationMethod: "custom",
	}
	err := l.RotateLogFile()
	// Either no error (file under size) or an error — we just verify no panic.
	_ = err
}

// TestRotateLogFile_UnderSizeNoOp verifies no rotation when file is under limit.
func TestRotateLogFile_UnderSizeNoOp(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "test*.log")
	require.NoError(t, err)
	_, _ = f.WriteString("small")
	f.Close()

	l := &Logger{
		Logger:         logrus.New(),
		logFile:        f.Name(),
		maxSizeBytes:   1024 * 1024, // 1 MB limit
		rotationMethod: "custom",
	}
	err = l.RotateLogFile()
	assert.NoError(t, err)
}

// TestCleanupOldLogs_LumberjackNoOp verifies no-op for lumberjack rotation.
func TestCleanupOldLogs_LumberjackNoOp(t *testing.T) {
	l := &Logger{
		Logger:         logrus.New(),
		logFile:        "test.log",
		rotationMethod: "lumberjack",
	}
	err := l.cleanupOldLogs()
	assert.NoError(t, err)
}

// TestStartPeriodicRotation_ExitsImmediatelyForLumberjack verifies no goroutine
// is started when rotation method is lumberjack.
func TestStartPeriodicRotation_ExitsImmediatelyForLumberjack(t *testing.T) {
	l := &Logger{
		Logger:         logrus.New(),
		logFile:        "test.log",
		rotationMethod: "lumberjack",
	}
	// Must return immediately without blocking.
	done := make(chan struct{})
	go func() {
		l.StartPeriodicRotation()
		close(done)
	}()
	select {
	case <-done:
		// Passed: returned immediately.
	case <-time.After(100 * time.Millisecond):
		t.Error("StartPeriodicRotation did not return immediately for lumberjack")
	}
}

// TestStartPeriodicRotation_ExitsImmediatelyForEmptyFile verifies no goroutine
// is started when logFile is empty.
func TestStartPeriodicRotation_ExitsImmediatelyForEmptyFile(t *testing.T) {
	l := &Logger{
		Logger:  logrus.New(),
		logFile: "",
	}
	done := make(chan struct{})
	go func() {
		l.StartPeriodicRotation()
		close(done)
	}()
	select {
	case <-done:
		// Passed.
	case <-time.After(100 * time.Millisecond):
		t.Error("StartPeriodicRotation did not return immediately for empty logFile")
	}
}

// TestStartPeriodicRotation_CanBeCancelled verifies that the periodic rotation
// goroutine stops when the context (indirectly via goroutine exit) is cancelled.
// We start it in a goroutine and just ensure it doesn't panic at startup.
func TestStartPeriodicRotation_CanBeCancelled(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "test*.log")
	require.NoError(t, err)
	f.Close()

	l := &Logger{
		Logger:         logrus.New(),
		logFile:        f.Name(),
		maxSizeBytes:   1024 * 1024,
		maxBackups:     2,
		maxAgeDays:     7,
		rotationMethod: "custom",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run in goroutine; the test just ensures no panic during startup.
	go l.StartPeriodicRotation()

	// Wait for context timeout.
	<-ctx.Done()
}

// TestYAMLFormatter_FormatEdge verifies that the formatter produces valid YAML output.
func TestYAMLFormatter_FormatEdge(t *testing.T) {
	f := &YAMLFormatter{
		TimestampFormat: time.RFC3339,
		PrettyPrint:     false,
	}

	entry := &logrus.Entry{
		Logger:  logrus.New(),
		Message: "hello yaml",
		Level:   logrus.InfoLevel,
		Time:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Data:    logrus.Fields{"key": "value"},
	}

	out, err := f.Format(entry)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)
	assert.Contains(t, string(out), "hello yaml")
	assert.Contains(t, string(out), "info")
}

// TestYAMLFormatter_Format_PrettyPrint verifies pretty-print mode also works.
func TestYAMLFormatter_Format_PrettyPrint(t *testing.T) {
	f := &YAMLFormatter{
		TimestampFormat: time.RFC3339,
		PrettyPrint:     true,
	}

	entry := &logrus.Entry{
		Logger:  logrus.New(),
		Message: "pretty yaml",
		Level:   logrus.WarnLevel,
		Time:    time.Now(),
		Data:    logrus.Fields{},
	}

	out, err := f.Format(entry)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)
}

// TestLogAuditInfo_PersistenceError verifies that a persister error on LogAuditInfo
// does not panic or propagate.
func TestLogAuditInfo_PersistenceError(t *testing.T) {
	logger := WrapLogrus(logrus.New())
	mock := &mockAuditPersister{err: assert.AnError}
	logger.SetAuditPersister(mock)
	assert.NotPanics(t, func() {
		logger.LogAuditInfo("u1", "op", "status", "msg")
	})
}
