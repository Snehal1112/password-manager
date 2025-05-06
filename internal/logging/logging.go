// Package logging provides structural logging for the password manager.
// It configures logrus for JSON logging with custom file rotation in the root directory, supporting audit trails and compliance.
package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Logger wraps logrus for application-specific logging with audit fields.
type Logger struct {
	*logrus.Logger
	logFile      string
	maxSizeBytes int64
	maxBackups   int
	maxAgeDays   int
}

// InitLogger initializes a structured logger with JSON output and custom file rotation.
// It configures log level, output file, and rotation settings from viper.
func InitLogger() *Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

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

	l := &Logger{
		Logger:       logger,
		logFile:      logFile,
		maxSizeBytes: int64(maxSizeMB) * 1024 * 1024,
		maxBackups:   maxBackups,
		maxAgeDays:   maxAgeDays,
	}

	if logFile != "" {
		// Open log file in root directory, creating it if it doesn’t exist.
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			logger.Fatal("Failed to open log file: ", err)
		}
		logger.SetOutput(file)
	} else {
		logger.SetOutput(os.Stdout)
	}

	return l
}

// LogAuditInfo logs an info-level audit event with standard fields.
func (l *Logger) LogAuditInfo(userID int, operation, status, message string, fields *logrus.Fields) {
	l.WithAuditFields(userID, operation, status).Info(message)
}

// LogAuditError logs an error-level audit event with standard fields and an error.
func (l *Logger) LogAuditError(userID int, operation, status, message string, err error) {
	l.WithAuditFields(userID, operation, status).WithError(err).Error(message)
}

func (l *Logger) WithAuditFields(userID int, operation, status string) *logrus.Entry {
	// Start with the audit fields
	auditFields := logrus.Fields{
		"user_id":   userID,
		"operation": operation,
		"status":    status,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	// log.Println("fields:", fields)
	// // If additional fields are provided, include them
	// if fields != nil {
	// 	for k, v := range *fields {
	// 		auditFields[k] = v
	// 	}
	// }

	return l.WithFields(auditFields)
}

// RotateLogFile checks if the log file needs rotation and performs cleanup.
// It rotates based on size and removes old files based on retention and backup limits.
func (l *Logger) RotateLogFile() error {
	if l.logFile == "" {
		return nil // No rotation for stdout.
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
	currentFile, err := os.OpenFile(l.logFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open current log file: %w", err)
	}
	currentFile.Close()

	// Generate new rotated file name with timestamp.
	timestamp := time.Now().Format("20060102_150405")
	rotatedFile := fmt.Sprintf("%s.%s.gz", l.logFile, timestamp)

	// Compress current log file.
	if err := compressLogFile(l.logFile, rotatedFile); err != nil {
		return fmt.Errorf("failed to compress log file: %w", err)
	}

	// Create new log file.
	newFile, err := os.OpenFile(l.logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer out.Close()

	gzWriter := gzip.NewWriter(out)
	defer gzWriter.Close()

	_, err = io.Copy(gzWriter, in)
	if err != nil {
		return fmt.Errorf("failed to compress file: %w", err)
	}

	// Remove original file after compression.
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("failed to remove source file: %w", err)
	}

	// Set permissions on compressed file.
	if err := os.Chmod(dst, 0600); err != nil {
		return fmt.Errorf("failed to set permissions on compressed file: %w", err)
	}

	return nil
}

// cleanupOldLogs removes log files exceeding retention period or backup limit in the root directory.
func (l *Logger) cleanupOldLogs() error {
	if l.logFile == "" {
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
