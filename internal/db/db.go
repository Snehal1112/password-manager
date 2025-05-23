// Package db manages database operations for the password manager.
// It initializes and interacts with a SQLite or PostgreSQL database to store users,
// secrets, keys, certificates, and audit logs securely, using Go Generics for type-safe
// data access.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"password-manager/internal/logging"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3" // SQLite driver for database/sql.
	"github.com/spf13/viper"
)

// DB is the global database connection for the application.
var DB *sql.DB

// Repository defines a generic interface for database operations.
// It supports type-safe CRUD operations for entities like users, secrets, and keys.
type Repository[T any] interface {
	Create(ctx context.Context, entity T) error
	Read(ctx context.Context, id uuid.UUID) (T, error)
	Update(ctx context.Context, entity T) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// DBRepository implements the Repository interface for SQLite or PostgreSQL databases.
// It provides methods to create, read, update, and delete records in the database.
// The repository is initialized with a logger for logging database operations.
// It uses Go Generics to allow for type-safe operations on different entity types.
// The repository is designed to work with various database backends, including SQLite and PostgreSQL.
// The database connection is managed through the global DB variable.
type DBRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewRepository creates a new instance of DBRepository.
func NewRepository(log *logging.Logger) *DBRepository {
	return &DBRepository{log: log}
}

// GetDB returns the current database connection.
// It is used to access the database for executing queries and transactions.
// Parameters:
//
//	none
//
// Returns:
//
//	A pointer to the sql.DB instance representing the database connection.
//
// This function is useful for accessing the database directly when needed.
// It is typically used in conjunction with the Repository interface for CRUD operations.
// Example usage:
// db := repository.GetDB()
// result, err := db.Exec("INSERT INTO users (id, username) VALUES (?, ?)", userID, username)
//
//	if err != nil {
//	    log.Error("Failed to insert user: ", err)
//	}
func (d *DBRepository) GetDB() *sql.DB {
	return d.db
}

// InitializeDB sets up the SQLite or PostgreSQL database.
// It opens a connection using the configured connection string and creates
// tables for users, secrets, keys, CA keys, CRLs, and audit logs.
//
// Parameters:
//
//	none
//
// Returns:
//
//	An error if the connection or table creation fails.
//
// The function is called during application startup to prepare the database.
func (d *DBRepository) InitializeDB() error {
	// Retrieve the database connection string from configuration.
	connStr := viper.GetString("database.connection")
	if connStr == "" {
		d.log.Error("Database connection string is empty")
		return fmt.Errorf("database connection string not configured")
	}

	// Open a connection to the database using the SQLite driver.
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		d.log.Error("Failed to open database: ", err)
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Verify the database connection.
	if err := db.Ping(); err != nil {
		d.log.Error("Failed to ping database: ", err)
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create tables if they don’t exist.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag),
			FOREIGN KEY (key_id) REFERENCES keys(id)
		);
		CREATE TABLE IF NOT EXISTS certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS certificate_tags (
			certificate_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag),
			FOREIGN KEY (certificate_id) REFERENCES certificates(id)
		);
		CREATE TABLE IF NOT EXISTS crl (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			action TEXT NOT NULL,
			details TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS secret_tags (
			secret_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (secret_id, tag),
			FOREIGN KEY (secret_id) REFERENCES secrets(id)
		);
	`)
	if err != nil {
		d.log.Error("Failed to create tables: ", err)
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Assign the connection to the global DB variable.
	DB = db
	d.db = db
	d.log.Info("Database initialized successfully")
	return nil
}

// CloseDB closes the database connection.
// It ensures the connection is properly closed during application shutdown.
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
func (d *DBRepository) CloseDB() error {
	if d.db == nil {
		return nil
	}

	// Close the database connection.
	if err := d.db.Close(); err != nil {
		d.log.Println("Failed to close database: ", err)
		return fmt.Errorf("failed to close database: %w", err)
	}

	d.log.Println("Database connection closed")
	return nil
}
