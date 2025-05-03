package main

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/monitoring"
	"github.com/snehal1112/password-manager/internal/secret"
	"github.com/snehal1112/password-manager/internal/store"
	"github.com/spf13/viper"
)

// initConfig initializes the application configuration.
// It loads settings from a YAML file or environment variables.
//
// Parameters:
//
//	None.
//
// Returns:
//
//	An error if the configuration file cannot be read or is invalid.
//
// The function is used to set up the application environment.
func initConfig() error {
	viper.SetConfigName("config")
	viper.AddConfigPath("./configs")
	viper.SetConfigType("yaml")
	viper.AutomaticEnv() // Bind environment variables
	if err := viper.ReadInConfig(); err != nil {
		logrus.WithError(err).Error("Reading config file")
		return fmt.Errorf("reading config file: %w", err)
	}
	logrus.Info("Configuration loaded")
	return nil
}

// initDatabase initializes the database connection.
// It opens a connection based on the configured driver and DSN.
//
// Parameters:
//
//	None.
//
// Returns:
//
//	A pointer to the SQL database connection and an error if the connection fails.
//
// The function is used to set up the database for storing entities.
func initDatabase() (*sql.DB, error) {
	driver := viper.GetString("database.driver")
	dsn := viper.GetString("database.dsn")
	if driver == "" || dsn == "" {
		logrus.Error("Database driver or DSN not configured")
		return nil, fmt.Errorf("database driver or DSN not configured")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		logrus.WithError(err).Error("Opening database connection")
		return nil, fmt.Errorf("opening database connection: %w", err)
	}
	if err := db.Ping(); err != nil {
		logrus.WithError(err).Error("Pinging database")
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	logrus.WithFields(logrus.Fields{"driver": driver}).Info("Database connection initialized")
	return db, nil
}

func main() {

	// Initialize configuration
	if err := initConfig(); err != nil {
		logrus.WithError(err).Fatal("Failed to initialize configuration")
		os.Exit(1)
	}

	// Initialize logging
	monitoring.SetupLogging("app.log")

	// Validate security configuration
	masterKey := viper.GetString("master_key")
	jwtSecret := viper.GetString("auth.jwt_secret")
	if masterKey == "" {
		logrus.Fatal("master_key not set in configuration")
		os.Exit(1)
	}
	if len(masterKey) != 32 {
		logrus.WithFields(logrus.Fields{
			"key_length": len(masterKey),
		}).Fatal("master_key must be 32 bytes")
		os.Exit(1)
	}
	if jwtSecret == "" {
		logrus.Fatal("auth.jwt_secret not set in configuration")
		os.Exit(1)
	}

	// Initialize database
	db, err := initDatabase()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize database")
		os.Exit(1)
	}
	defer db.Close()

	// Initialize stores
	secretStore := store.NewSQLStore[*secret.Secret](db, "secrets")
	userStore := store.NewSQLStore[*auth.User](db, "users")

	// Initialize database schemas
	if err := secretStore.InitSchema(); err != nil {
		logrus.WithError(err).Fatal("Failed to initialize secrets schema")
		os.Exit(1)
	}
	if err := userStore.InitSchema(); err != nil {
		logrus.WithError(err).Fatal("Failed to initialize users schema")
		os.Exit(1)
	}

	// Example: Create and save a user
	user, err := auth.NewUser("john_doe", "securepassword123", "user_123")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create user")
		os.Exit(1)
	}
	if err := userStore.Save(user); err != nil {
		logrus.WithError(err).Fatal("Failed to save user")
		os.Exit(1)
	}

	// Example: Authenticate user (placeholder TOTP code)
	if err := user.Authenticate("securepassword123", "123456"); err != nil {
		logrus.WithError(err).Fatal("Failed to authenticate user")
		os.Exit(1)
	}

	// Example: Generate JWT
	jwtToken, err := user.GenerateJWT(os.Getenv("JWT_SECRET"), 24*time.Hour)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate JWT")
		os.Exit(1)
	}
	logrus.WithFields(logrus.Fields{"user_id": user.ID, "jwt": jwtToken}).Info("JWT generated")

	// Example: Create and save a secret
	s, err := secret.NewSecret("api_key_123", "mysecret123", os.Getenv("MASTER_KEY"))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create secret")
		os.Exit(1)
	}
	if err := secretStore.Save(s); err != nil {
		logrus.WithError(err).Fatal("Failed to save secret")
		os.Exit(1)
	}

	// Example: Update the secret
	s.Version = 2
	s.Value, err = s.EncryptAES("newsecret456", os.Getenv("MASTER_KEY"))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to encrypt updated secret")
		os.Exit(1)
	}
	if err := secretStore.Update(s); err != nil {
		logrus.WithError(err).Fatal("Failed to update secret")
		os.Exit(1)
	}

	// Example: Retrieve the secret
	retrieved, err := secretStore.Get("api_key_123")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to retrieve secret")
		os.Exit(1)
	}
	value, err := retrieved.DecryptAES(os.Getenv("MASTER_KEY"))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to decrypt secret")
		os.Exit(1)
	}
	logrus.WithFields(logrus.Fields{
		"secret_id": retrieved.ID,
		"value":     value,
	}).Info("Secret retrieved and decrypted")

	// Example: Delete the secret
	if err := secretStore.Delete("api_key_123"); err != nil {
		logrus.WithError(err).Fatal("Failed to delete secret")
		os.Exit(1)
	}

	// Placeholder for further initialization (e.g., API server)
	logrus.Info("Password manager application started")
}
