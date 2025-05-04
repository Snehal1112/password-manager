package config

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func LoadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	// Set default values
	viper.SetDefault("database.path", "./password_manager.db")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("api.port", "8080")
	viper.SetDefault("master_key", "") // Must be set by user

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logrus.Warn("Config file not found, using defaults and environment variables")
		} else {
			return err
		}
	}

	return nil
}
