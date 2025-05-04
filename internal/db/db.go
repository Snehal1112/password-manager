// Package db manages database operations for the password manager.
// It provides functions to initialize and interact with the SQLite or PostgreSQL
// database, storing users, secrets, keys, certificates, and audit logs securely.
package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for database/sql.
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// DB is the global database connection for the application.
var DB *sql.DB

// InitializeDB initializes the SQLite or PostgreSQL database.
// It sets up the database connection using the configured connection string,
// creates necessary tables (users, secrets, keys, ca_keys, crl, audit_logs),
// and ensures the schema is ready for use.
//
// Parameters:
//
//	none
//
// Returns:
//
//	An error if the connection or schema creation fails.
//
// The function is called during application startup to prepare the database.
func InitializeDB() error {
	// Retrieve the database connection string from configuration.
	connStr := viper.GetString("database.connection")
	if connStr == "" {
		logrus.Error("Database connection string is empty")
		return fmt.Errorf("database connection string not configured")
	}

	// Open a connection to the database using the SQLite driver.
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		logrus.Error("Failed to open database: ", err)
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Test the database connection to ensure it’s working.
	if err := db.Ping(); err != nil {
		logrus.Error("Failed to ping database: ", err)
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create tables if they don’t exist to store application data.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS ca_keys (
			user_id INTEGER PRIMARY KEY,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS crl (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			serial_number TEXT NOT NULL,
			revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			action TEXT NOT NULL,
			details TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
	`)
	if err != nil {
		logrus.Error("Failed to create tables: ", err)
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Assign the connection to the global DB variable for application-wide use.
	DB = db
	logrus.Info("Database initialized successfully")
	return nil
}

// CloseDB closes the database connection.
// It ensures the database connection is properly closed during application shutdown.
//
// Parameters:
//
//	none
//
// Returns:
//
//	An error if the connection cannot be closed.
//
// The function is called to clean up resources when the application terminates.
func CloseDB() error {
	if DB == nil {
		return nil
	}

	// Close the database connection to release resources.
	if err := DB.Close(); err != nil {
		logrus.Error("Failed to close database: ", err)
		return fmt.Errorf("failed to close database: %w", err)
	}

	logrus.Info("Database connection closed")
	return nil
}
