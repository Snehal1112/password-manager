package monitoring

import (
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// SetupLogging configures structured JSON logging.
// It sets up logging to a file with rotation and to stdout.
//
// Parameters:
//
//	logFile: The path to the log file (e.g., "app.log").
//
// Returns:
//
//	None, as it configures the global logger.
//
// The function is used to initialize logging for the application.
func SetupLogging(logFile string) {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		logrus.Warn("Invalid log level, defaulting to info ", err.Error())
		level = logrus.InfoLevel
	}

	logrus.SetLevel(level)

	logrus.SetOutput(&lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    100, // MB
		MaxBackups: 3,
		MaxAge:     30, // days
	})
	logrus.Info("Logging configured")
}
