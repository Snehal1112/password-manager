package logger

import (
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func InitLogger() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		logrus.Warn("Invalid log level, defaulting to info")
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	// Configure log rotation
	logrus.SetOutput(&lumberjack.Logger{
		Filename:   "password-manager.log",
		MaxSize:    10, // MB
		MaxBackups: 3,
		MaxAge:     28, // days
		Compress:   true,
	})
}
