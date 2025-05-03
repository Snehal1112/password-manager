package monitoring

import (
	"os"

	"github.com/sirupsen/logrus"
)

// SetupLogging configures the logging system using logrus.
// It sets up a log file and the specified log level for application-wide logging.
//
// Parameters:
//
//	logFile: The path to the log file (e.g., "app.log").
//	logLevel: The logging level (debug, info, warn, error, fatal).
//
// Returns:
//
//	None.
//
// The function is used to initialize logging for the application.
func SetupLogging(logFile, logLevel string) {
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to open log file")
		os.Exit(1)
	}

	logrus.SetOutput(file)
	logrus.SetFormatter(&logrus.JSONFormatter{})

	switch logLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	default:
		logrus.WithFields(logrus.Fields{"level": logLevel}).Warn("Invalid log level, defaulting to debug")
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.WithFields(logrus.Fields{"file": logFile, "level": logLevel}).Info("Logging initialized")
}
