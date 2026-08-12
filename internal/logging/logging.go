// Package logging provides structural logging for the password manager.
// It configures logrus for JSON logging with configurable rotation (lumberjack or custom gzip),
// supporting audit trails and compliance.
package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Logger wraps logrus for application-specific logging with audit fields.
type Logger struct {
	*logrus.Logger
	logFile        string
	maxSizeBytes   int64
	maxBackups     int
	maxAgeDays     int
	rotationMethod string
	mu             sync.RWMutex
	auditPersister AuditPersister // Optional; nil means DB writes are skipped.
}

// AuditPersister is implemented by anything that can durably store an audit record.
// Keeping the interface here avoids a circular import with the repositories package.
type AuditPersister interface {
	PersistAudit(userID, action, details string) error
}

// SetAuditPersister wires a durable storage backend for audit records.
// Called once during container initialisation; safe to leave nil (log-only mode).
func (l *Logger) SetAuditPersister(p AuditPersister) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.auditPersister = p
}

// ensureLogDirectory ensures the log file's directory exists.
// If the directory cannot be created, it falls back to using the root folder.
// Returns the potentially modified log file path.
func ensureLogDirectory(logFile string, logger *logrus.Logger) string {
	// Extract directory from log file path.
	logDir := filepath.Dir(logFile)

	// If logDir is current directory, no need to create.
	if logDir == "." {
		return logFile
	}

	// Try to create the directory.
	if err := os.MkdirAll(logDir, 0o0755); err != nil {
		logger.Warnf("Failed to create log directory %s: %v. Using root folder instead.", logDir, err)
		// Fallback to root folder with just the filename.
		return filepath.Base(logFile)
	}

	logger.Infof("Log directory ensured: %s", logDir)
	return logFile
}

// InitLogger initializes a structured logger with JSON output and configurable rotation.
// It uses either lumberjack or custom gzip rotation based on viper settings.
func InitLogger() *Logger {
	logger := logrus.New()

	switch viper.GetString("log.format") {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			PrettyPrint:     viper.GetBool("log.pretty_print"),
		})
	case "yaml":
		logger.SetFormatter(&YAMLFormatter{
			TimestampFormat: time.RFC3339,
			PrettyPrint:     viper.GetBool("log.pretty_print"),
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
		})
	default:
		logger.WithField("format", viper.GetString("log.format")).Infoln("Default log format is used by logrus")
	}

	// Set log level from config.yaml.
	level, err := logrus.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		logger.Warn("Invalid log level, defaulting to info")
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Configure log file output.
	logFile := viper.GetString("log.file")
	maxSizeMB := viper.GetInt("log.max_size_mb")
	maxBackups := viper.GetInt("log.max_backups")
	maxAgeDays := viper.GetInt("log.max_age_days")
	rotationMethod := viper.GetString("log.rotation_method")

	l := &Logger{
		Logger:         logger,
		logFile:        logFile,
		maxSizeBytes:   int64(maxSizeMB) * 1024 * 1024,
		maxBackups:     maxBackups,
		maxAgeDays:     maxAgeDays,
		rotationMethod: rotationMethod,
	}

	if logFile != "" {
		// Ensure log directory exists or fallback to root folder.
		logFile = ensureLogDirectory(logFile, logger)
		l.logFile = logFile // Update with potentially modified path.

		if rotationMethod == "lumberjack" {
			// Use lumberjack for rotation.
			lumberjackLogger := &lumberjack.Logger{
				Filename:   logFile,
				MaxSize:    maxSizeMB,
				MaxBackups: maxBackups,
				MaxAge:     maxAgeDays,
				Compress:   true,
				LocalTime:  true,
			}
			logger.SetOutput(lumberjackLogger)

			_, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				logger.Warn("Failed to open log file, falling back to stdout: ", err)
				logger.SetOutput(os.Stdout)
			} else {
				// Set file permissions manually for lumberjack logs.
				if err := os.Chmod(logFile, 0o600); err != nil && !os.IsNotExist(err) {
					logger.Warn("Failed to set log file permissions: ", err)
				}
			}
		} else {
			// Use custom gzip rotation (default).
			file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				logger.Warn("Failed to open log file, falling back to stdout: ", err)
				logger.SetOutput(os.Stdout)
			} else {
				mw := io.MultiWriter(os.Stdout, file)
				logger.SetOutput(mw)
			}
		}
	} else {
		logger.SetOutput(os.Stdout)
	}

	return l
}

// WrapLogrus wraps an existing logrus.Logger in a Logger.
func WrapLogrus(l *logrus.Logger) *Logger {
	return &Logger{Logger: l}
}

// LogAuditInfo logs an info-level audit event with standard fields.
func (l *Logger) LogAuditInfo(userID, operation, status, message string) {
	l.WithAuditFields(userID, operation, status).Info(message)
	l.mu.RLock()
	p := l.auditPersister
	l.mu.RUnlock()
	if p != nil {
		details := fmt.Sprintf("operation=%s status=%s message=%s", operation, status, message)
		if err := p.PersistAudit(userID, operation, details); err != nil {
			l.WithError(err).Warn("audit persistence failed")
		}
	}
}

// LogAuditError logs an error-level audit event with standard fields and an error.
func (l *Logger) LogAuditError(userID string, operation, status, message string, err error) {
	l.WithAuditFields(userID, operation, status).WithError(err).Error(message)
	l.mu.RLock()
	p := l.auditPersister
	l.mu.RUnlock()
	if p != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		details := fmt.Sprintf("operation=%s status=%s message=%s error=%s", operation, status, message, errStr)
		if persistErr := p.PersistAudit(userID, operation, details); persistErr != nil {
			l.WithError(persistErr).Warn("audit persistence failed")
		}
	}
}

// WithAuditFields adds standard audit fields to a log entry.
func (l *Logger) WithAuditFields(userID string, operation, status string) *logrus.Entry {
	return l.WithFields(logrus.Fields{
		"user_id":   userID,
		"operation": operation,
		"status":    status,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// RotateLogFile checks if the log file needs rotation and performs cleanup (custom rotation only).
// It rotates based on size and removes old files based on retention and backup limits.
func (l *Logger) RotateLogFile() error {
	if l.logFile == "" || l.rotationMethod == "lumberjack" {
		return nil // No rotation needed for stdout or lumberjack.
	}

	// Check file size.
	fileInfo, err := os.Stat(l.logFile)
	if os.IsNotExist(err) {
		return nil // File doesn’t exist yet.
	}
	if err != nil {
		return fmt.Errorf("failed to stat log file: %w", err)
	}
	if fileInfo.Size() < l.maxSizeBytes {
		return nil // File is under size limit.
	}

	// Close current file.
	currentFile, err := os.OpenFile(l.logFile, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open current log file: %w", err)
	}
	currentFile.Close() //nolint:errcheck,gosec

	// Generate new rotated file name with timestamp.
	timestamp := time.Now().Format("20060102_150405")
	rotatedFile := fmt.Sprintf("%s.%s.gz", l.logFile, timestamp)

	// Compress current log file.
	if err := compressLogFile(l.logFile, rotatedFile); err != nil {
		return fmt.Errorf("failed to compress log file: %w", err)
	}

	// Create new log file.
	newFile, err := os.OpenFile(l.logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %w", err)
	}
	l.SetOutput(newFile)

	// Clean up old log files.
	if err := l.cleanupOldLogs(); err != nil {
		return fmt.Errorf("failed to clean up old logs: %w", err)
	}

	return nil
}

// compressLogFile compresses the source file to a gzip destination file in the root directory.
func compressLogFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer in.Close() //nolint:errcheck

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer out.Close() //nolint:errcheck

	gzWriter := gzip.NewWriter(out)
	defer gzWriter.Close() //nolint:errcheck

	_, err = io.Copy(gzWriter, in)
	if err != nil {
		return fmt.Errorf("failed to compress file: %w", err)
	}

	// Remove original file after compression.
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("failed to remove source file: %w", err)
	}

	// Set permissions on compressed file.
	if err := os.Chmod(dst, 0o600); err != nil {
		return fmt.Errorf("failed to set permissions on compressed file: %w", err)
	}

	return nil
}

// cleanupOldLogs removes log files exceeding retention period or backup limit in the root directory (custom rotation only).
func (l *Logger) cleanupOldLogs() error {
	if l.logFile == "" || l.rotationMethod == "lumberjack" {
		return nil
	}

	// Get all log files in root directory.
	pattern := fmt.Sprintf("%s.*.gz", l.logFile)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to list log files: %w", err)
	}

	// Sort files by modification time (newest first).
	type logFile struct {
		name  string
		mtime time.Time
	}
	var logFiles []logFile
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		logFiles = append(logFiles, logFile{name: match, mtime: info.ModTime()})
	}
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].mtime.After(logFiles[j].mtime)
	})

	// Remove files exceeding maxBackups or maxAgeDays.
	cutoff := time.Now().AddDate(0, 0, -l.maxAgeDays)
	for i, lf := range logFiles {
		if i >= l.maxBackups || lf.mtime.Before(cutoff) {
			if err := os.Remove(lf.name); err != nil {
				l.Warn("Failed to remove old log file: ", err)
			}
		}
	}

	return nil
}

// StartPeriodicRotation starts a goroutine that periodically checks and rotates the log file.
// It checks every 10 minutes and rotates if the file exceeds the configured size limit.
// This function should be called with go StartPeriodicRotation(logger).
func (l *Logger) StartPeriodicRotation() {
	if l.logFile == "" || l.rotationMethod == "lumberjack" {
		return // No periodic rotation needed for stdout or lumberjack
	}

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := l.RotateLogFile(); err != nil {
			l.Errorf("Failed to rotate log file: %v", err)
		}
	}
}
