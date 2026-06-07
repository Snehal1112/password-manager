// Package db manages database operations for the password manager.
// It initializes and interacts with a SQLite or PostgreSQL database to store users,
// secrets, keys, certificates, and audit logs securely, using Go Generics for type-safe
// data access.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"            // PostgreSQL driver for database/sql.
	_ "github.com/mattn/go-sqlite3" // SQLite driver for database/sql.
	"github.com/spf13/viper"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// DB is the global database connection for the application.
var DB *sql.DB

// ConnectionPoolConfig holds database connection pool configuration.
type ConnectionPoolConfig struct {
	MaxOpenConns    int           // Maximum number of open connections
	MaxIdleConns    int           // Maximum number of idle connections
	ConnMaxLifetime time.Duration // Maximum lifetime of a connection
	ConnMaxIdleTime time.Duration // Maximum idle time of a connection
}

// DatabaseConfig holds complete database configuration.
type DatabaseConfig struct {
	ConnectionString string
	DriverName       string
	PoolConfig       ConnectionPoolConfig
	Environment      string // dev, staging, prod
}

// PerformanceMetrics tracks database performance indicators.
type PerformanceMetrics struct {
	QueryCount       int64         `json:"query_count"`
	SlowQueryCount   int64         `json:"slow_query_count"`
	TotalQueryTime   time.Duration `json:"total_query_time"`
	AverageQueryTime time.Duration `json:"avg_query_time"`
	ConnectionStats  sql.DBStats   `json:"connection_stats"`
	mu               sync.RWMutex
}

// Global performance metrics
var metrics *PerformanceMetrics

// Initialize metrics
func init() {
	metrics = &PerformanceMetrics{}
}

// Repository defines a generic interface for database operations.
// It supports type-safe CRUD operations for entities like users, secrets, and keys.
type Repository[T any] interface {
	Create(ctx context.Context, entity *T) error
	Read(ctx context.Context, id uuid.UUID) (*T, error)
	Update(ctx context.Context, entity *T) error
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

// OpenDatabase opens a database connection with the provided configuration.
// Exported for use by migration commands.
func (d *DBRepository) OpenDatabase(config *DatabaseConfig) (*sql.DB, error) {
	// Open a connection to the database
	db, err := sql.Open(config.DriverName, config.ConnectionString)
	if err != nil {
		d.log.Error("Failed to open database: ", err)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for optimal performance
	if err := d.configureConnectionPool(db, config.PoolConfig); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure connection pool: %w", err)
	}

	return db, nil
}

// InitializeDB sets up the SQLite or PostgreSQL database with optimized connection pooling.
// It opens a connection using the configured connection string, configures connection pool,
// and creates tables for users, secrets, keys, CA keys, CRLs, and audit logs.
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
	// Get database configuration
	dbConfig, err := d.loadDatabaseConfig()
	if err != nil {
		return fmt.Errorf("failed to load database config: %w", err)
	}

	// Open a connection to the database.
	db, err := sql.Open(dbConfig.DriverName, dbConfig.ConnectionString)
	if err != nil {
		d.log.Error("Failed to open database: ", err)
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for optimal performance
	if err := d.configureConnectionPool(db, dbConfig.PoolConfig); err != nil {
		db.Close()
		return fmt.Errorf("failed to configure connection pool: %w", err)
	}

	// Verify the database connection with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		d.log.Error("Failed to ping database: ", err)
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create optimized tables with proper indexes if they don't exist.
	if err := d.createOptimizedSchema(db); err != nil {
		db.Close()
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Migrate schema for existing databases (idempotent — duplicate-column errors are ignored).
	if err := d.migrateSchema(db); err != nil {
		db.Close()
		return fmt.Errorf("failed to migrate schema: %w", err)
	}

	// Seed the bootstrap token from config so the first admin can be created.
	if err := d.seedBootstrapToken(db); err != nil {
		db.Close()
		return fmt.Errorf("failed to seed bootstrap token: %w", err)
	}

	if err := d.seedAuditConfig(db); err != nil {
		db.Close()
		return fmt.Errorf("failed to seed audit config: %w", err)
	}

	// Seed the default vault before finalizing indexes so the row exists.
	if err := d.seedDefaultVault(db); err != nil {
		db.Close()
		return fmt.Errorf("failed to seed default vault: %w", err)
	}

	// Resolve any name collisions and create the per-vault unique indexes.
	if err := d.finalizeVaultIndexes(db); err != nil {
		db.Close()
		return fmt.Errorf("failed to finalize vault indexes: %w", err)
	}

	// Assign the connection to the global DB variable.
	DB = db
	d.db = db
	d.log.Info("Database initialized successfully with connection pooling")
	return nil
}

// LoadDatabaseConfig loads and validates database configuration.
// Exported for use by migration commands.
func (d *DBRepository) LoadDatabaseConfig() (*DatabaseConfig, error) {
	return d.loadDatabaseConfig()
}

// loadDatabaseConfig loads and validates database configuration (internal).
func (d *DBRepository) loadDatabaseConfig() (*DatabaseConfig, error) {
	// Retrieve the database connection string from configuration.
	connStr := viper.GetString("database.connection")
	if connStr == "" {
		d.log.Error("Database connection string is empty")
		return nil, fmt.Errorf("database connection string not configured")
	}

	// Determine driver based on connection string or explicit config
	driverName := "sqlite3" // default
	if viper.GetString("database.driver") != "" {
		driverName = viper.GetString("database.driver")
	} else if len(connStr) > 10 && connStr[:10] == "postgres://" {
		driverName = "postgres"
	}

	// Get environment-specific pool configuration
	env := viper.GetString("environment")
	if env == "" {
		env = "dev"
	}

	poolConfig := d.getEnvironmentPoolConfig(env)

	return &DatabaseConfig{
		ConnectionString: connStr,
		DriverName:       driverName,
		PoolConfig:       poolConfig,
		Environment:      env,
	}, nil
}

// getEnvironmentPoolConfig returns optimized pool config for each environment.
func (d *DBRepository) getEnvironmentPoolConfig(env string) ConnectionPoolConfig {
	switch env {
	case "prod", "production":
		return ConnectionPoolConfig{
			MaxOpenConns:    50,               // High concurrency for production
			MaxIdleConns:    10,               // Keep connections ready
			ConnMaxLifetime: 30 * time.Minute, // Rotate connections regularly
			ConnMaxIdleTime: 5 * time.Minute,  // Close idle connections
		}
	default: // dev, test
		return ConnectionPoolConfig{
			MaxOpenConns:    10,               // Limited concurrency for dev
			MaxIdleConns:    2,                // Minimal idle connections
			ConnMaxLifetime: 10 * time.Minute, // Shorter lifetime for dev
			ConnMaxIdleTime: 2 * time.Minute,  // Quick cleanup
		}
	}
}

// configureConnectionPool sets up optimized connection pool settings.
func (d *DBRepository) configureConnectionPool(db *sql.DB, config ConnectionPoolConfig) error {
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	d.log.Info(fmt.Sprintf(
		"Connection pool configured: MaxOpen=%d, MaxIdle=%d, MaxLifetime=%v, MaxIdleTime=%v",
		config.MaxOpenConns, config.MaxIdleConns, config.ConnMaxLifetime, config.ConnMaxIdleTime,
	))

	return nil
}

// createOptimizedSchema creates tables with proper indexes for performance.
func (d *DBRepository) createOptimizedSchema(db *sql.DB) error {
	// Create tables with optimized schema.
	// The three vault_id column defaults below are hardcoded SQL literals and must
	// stay equal to model.DefaultVaultID ("00000000-0000-0000-0000-00000000efa1").
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
		CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
		CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

		CREATE TABLE IF NOT EXISTS vaults (
			id                 TEXT PRIMARY KEY,
			name               TEXT UNIQUE NOT NULL,
			enabled            BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection   BOOLEAN NOT NULL DEFAULT FALSE,
			retention_days     INTEGER NOT NULL DEFAULT 90,
			created_by         TEXT NOT NULL,
			created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at         TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL,
			tags               TEXT NOT NULL DEFAULT '{}',
			updated_at         TIMESTAMP NULL,
			updated_by         TEXT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name);

		CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			content_type TEXT NOT NULL DEFAULT '',
			enabled      BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at   TIMESTAMP NULL,
			not_before   TIMESTAMP NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);
		CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
		CREATE INDEX IF NOT EXISTS idx_secrets_user_name ON secrets(user_id, name);
		CREATE INDEX IF NOT EXISTS idx_secrets_created_at ON secrets(created_at);

		CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			value TEXT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			deleted_at TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at TIMESTAMP NULL,
			not_before TIMESTAMP NULL,
			bits INTEGER NOT NULL DEFAULT 0,
			curve TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_keys_user_id ON keys(user_id);
		CREATE INDEX IF NOT EXISTS idx_keys_type ON keys(type);
		CREATE INDEX IF NOT EXISTS idx_keys_revoked ON keys(revoked);
		CREATE INDEX IF NOT EXISTS idx_keys_user_type ON keys(user_id, type);

		CREATE TABLE IF NOT EXISTS key_tags (
			key_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (key_id, tag),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_key_tags_tag ON key_tags(tag);

		CREATE TABLE IF NOT EXISTS key_versions (
			key_id     TEXT NOT NULL,
			version    INTEGER NOT NULL,
			value      TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_key_versions_key_id ON key_versions(key_id);

		CREATE TABLE IF NOT EXISTS certificates (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			key_id TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL,
			vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
			certificate TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			scheduled_purge_at TIMESTAMP NULL,
			expires_at DATETIME,
			auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
			renewal_days INTEGER NOT NULL DEFAULT 30,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			not_before TIMESTAMP NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON certificates(user_id);
		CREATE INDEX IF NOT EXISTS idx_certificates_name ON certificates(name);
		CREATE INDEX IF NOT EXISTS idx_certificates_created_at ON certificates(created_at);

		CREATE TABLE IF NOT EXISTS certificate_tags (
			certificate_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (certificate_id, tag),
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_certificate_tags_tag ON certificate_tags(tag);

		CREATE TABLE IF NOT EXISTS certificate_policies (
			id                TEXT PRIMARY KEY,
			certificate_id    TEXT NOT NULL UNIQUE,
			user_id           TEXT NOT NULL,
			validity_months   INTEGER NOT NULL DEFAULT 12,
			key_type          TEXT NOT NULL DEFAULT 'RSA',
			key_size          INTEGER NOT NULL DEFAULT 2048,
			curve             TEXT NOT NULL DEFAULT '',
			subject           TEXT NOT NULL DEFAULT '',
			sans              TEXT NOT NULL DEFAULT '',
			auto_renew        BOOLEAN NOT NULL DEFAULT FALSE,
			days_before_expiry INTEGER NOT NULL DEFAULT 30,
			issuer_name       TEXT NOT NULL DEFAULT '',
			created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_cert_policies_cert_id ON certificate_policies(certificate_id);
		CREATE INDEX IF NOT EXISTS idx_cert_policies_user_id ON certificate_policies(user_id);

		CREATE TABLE IF NOT EXISTS crl (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_crl_user_id ON crl(user_id);
		CREATE INDEX IF NOT EXISTS idx_crl_serial_number ON crl(serial_number);

		CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			action TEXT NOT NULL,
			details TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			resource_type TEXT,
			resource_id TEXT,
			ip_address TEXT,
			outcome TEXT,
			source TEXT,
			prev_hash TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action ON audit_logs(user_id, action);

		CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			token TEXT PRIMARY KEY,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			used BOOLEAN DEFAULT FALSE
		);
		CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_used ON bootstrap_tokens(used);

		CREATE TABLE IF NOT EXISTS secret_tags (
			secret_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (secret_id, tag),
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_secret_tags_tag ON secret_tags(tag);

		CREATE TABLE IF NOT EXISTS secret_versions (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_secret_versions_secret_id ON secret_versions(secret_id);
		CREATE INDEX IF NOT EXISTS idx_secret_versions_version ON secret_versions(secret_id, version);
		CREATE INDEX IF NOT EXISTS idx_secret_versions_created_at ON secret_versions(created_at);

		CREATE TABLE IF NOT EXISTS rotation_policies (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_rotation_policies_user_id ON rotation_policies(user_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_policies_enabled ON rotation_policies(enabled);
		CREATE INDEX IF NOT EXISTS idx_rotation_policies_auto_rotate ON rotation_policies(auto_rotate);

		CREATE TABLE IF NOT EXISTS secret_rotation_history (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT,
			rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			previous_version INTEGER,
			new_version INTEGER,
			triggered_by TEXT NOT NULL, -- 'manual', 'scheduled', 'auto'
			notes TEXT,
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
			FOREIGN KEY (policy_id) REFERENCES rotation_policies(id) ON DELETE SET NULL
		);
		CREATE INDEX IF NOT EXISTS idx_rotation_history_secret_id ON secret_rotation_history(secret_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_history_policy_id ON secret_rotation_history(policy_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_history_rotated_at ON secret_rotation_history(rotated_at);
		CREATE INDEX IF NOT EXISTS idx_rotation_history_triggered_by ON secret_rotation_history(triggered_by);

		CREATE TABLE IF NOT EXISTS rotation_reminders (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			reminder_type TEXT NOT NULL, -- 'upcoming', 'overdue'
			sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			next_reminder_at TIMESTAMP,
			acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
			FOREIGN KEY (policy_id) REFERENCES rotation_policies(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_secret_id ON rotation_reminders(secret_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_policy_id ON rotation_reminders(policy_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_type ON rotation_reminders(reminder_type);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_acknowledged ON rotation_reminders(acknowledged);
		CREATE INDEX IF NOT EXISTS idx_rotation_reminders_next_at ON rotation_reminders(next_reminder_at);

		CREATE TABLE IF NOT EXISTS secret_policies (
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_rotated_at TIMESTAMP,
			next_rotation_at TIMESTAMP,
			PRIMARY KEY (secret_id, policy_id),
			FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
			FOREIGN KEY (policy_id) REFERENCES rotation_policies(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_secret_policies_next_rotation ON secret_policies(next_rotation_at);
		CREATE INDEX IF NOT EXISTS idx_secret_policies_last_rotated ON secret_policies(last_rotated_at);

		CREATE TABLE IF NOT EXISTS user_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			refresh_token_hash TEXT NOT NULL,
			device_info TEXT,
			ip_address TEXT,
			user_agent TEXT,
			expires_at TIMESTAMP NOT NULL,
			last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			revoked BOOLEAN DEFAULT FALSE,
			revoked_at TIMESTAMP,
			revoked_reason TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_token ON user_sessions(refresh_token_hash);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_revoked ON user_sessions(revoked);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_last_used ON user_sessions(last_used_at);

		CREATE TABLE IF NOT EXISTS access_policies (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			operation      TEXT NOT NULL,
			effect         TEXT NOT NULL,
			vault_id       TEXT NULL,
			assignment_id  TEXT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_access_policies_principal ON access_policies(principal_id);
		CREATE INDEX IF NOT EXISTS idx_access_policies_lookup    ON access_policies(principal_id, resource_type, operation);

		CREATE TABLE IF NOT EXISTS role_assignments (
			id             TEXT PRIMARY KEY,
			principal_id   TEXT NOT NULL,
			principal_type TEXT NOT NULL,
			role           TEXT NOT NULL,
			vault_id       TEXT NOT NULL,
			created_by     TEXT NOT NULL,
			created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (principal_id, role, vault_id),
			FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id);

		CREATE TABLE IF NOT EXISTS oauth2_clients (
			id            TEXT PRIMARY KEY,
			name          TEXT NOT NULL UNIQUE,
			client_secret TEXT NOT NULL,
			description   TEXT DEFAULT '',
			enabled       BOOLEAN DEFAULT TRUE,
			created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at    TIMESTAMP NULL
		);
		CREATE INDEX IF NOT EXISTS idx_oauth2_clients_name ON oauth2_clients(name);

		CREATE TABLE IF NOT EXISTS audit_config (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		-- Indexes on the enriched audit_logs columns (outcome, resource_type,
		-- resource_id, source) are created in migrateSchema, after the ALTER TABLE
		-- statements that add those columns to pre-existing databases. Creating them
		-- here would fail on upgraded DBs where the columns do not yet exist.
	`)
	if err != nil {
		d.log.Error("Failed to create tables: ", err)
		return fmt.Errorf("failed to create tables: %w", err)
	}

	d.log.Info("Database schema created successfully with optimized indexes")
	return nil
}

// migrateSchema adds columns to existing databases that were created before
// those columns existed. Each ALTER TABLE is idempotent: duplicate-column errors
// are silently ignored so the function is safe to call on every startup.
func (d *DBRepository) migrateSchema(db *sql.DB) error {
	migrations := []string{
		// BUG-001: soft-delete columns missing from secrets (fresh-install schema fix)
		"ALTER TABLE secrets ADD COLUMN deleted_at TIMESTAMP NULL",
		"ALTER TABLE secrets ADD COLUMN purge_protection BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE secrets ADD COLUMN scheduled_purge_at TIMESTAMP NULL",
		// Feature: secret content types
		"ALTER TABLE secrets ADD COLUMN content_type TEXT NOT NULL DEFAULT ''",
		// Milestone 1: soft-delete columns for keys and certificates
		"ALTER TABLE keys ADD COLUMN deleted_at TIMESTAMP NULL",
		"ALTER TABLE keys ADD COLUMN purge_protection BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE keys ADD COLUMN scheduled_purge_at TIMESTAMP NULL",
		"ALTER TABLE certificates ADD COLUMN deleted_at TIMESTAMP NULL",
		"ALTER TABLE certificates ADD COLUMN purge_protection BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificates ADD COLUMN scheduled_purge_at TIMESTAMP NULL",
		// Bug fix: key_id column missing from certificates
		"ALTER TABLE certificates ADD COLUMN key_id TEXT NOT NULL DEFAULT ''",
		// Feature: certificate auto-renewal
		"ALTER TABLE certificates ADD COLUMN expires_at DATETIME",
		"ALTER TABLE certificates ADD COLUMN auto_renew BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificates ADD COLUMN renewal_days INTEGER NOT NULL DEFAULT 30",
		// Feature: lifecycle attributes for secrets
		"ALTER TABLE secrets ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
		"ALTER TABLE secrets ADD COLUMN expires_at TIMESTAMP NULL",
		"ALTER TABLE secrets ADD COLUMN not_before TIMESTAMP NULL",
		// Feature: lifecycle attributes for keys
		"ALTER TABLE keys ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
		"ALTER TABLE keys ADD COLUMN expires_at TIMESTAMP NULL",
		"ALTER TABLE keys ADD COLUMN not_before TIMESTAMP NULL",
		"ALTER TABLE keys ADD COLUMN bits INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE keys ADD COLUMN curve TEXT NOT NULL DEFAULT ''",
		// Feature: Azure Key Vault parity — updated_at timestamp on keys.
		"ALTER TABLE keys ADD COLUMN updated_at TIMESTAMP NULL",
		// Feature: lifecycle attributes for certificates
		"ALTER TABLE certificates ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE",
		"ALTER TABLE certificates ADD COLUMN not_before TIMESTAMP NULL",
		// Milestone 3: service-account / OAuth2 table (CREATE TABLE IF NOT EXISTS is idempotent)
		`CREATE TABLE IF NOT EXISTS oauth2_clients (
			id            TEXT PRIMARY KEY,
			name          TEXT NOT NULL UNIQUE,
			client_secret TEXT NOT NULL,
			description   TEXT DEFAULT '',
			enabled       BOOLEAN DEFAULT TRUE,
			created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at    TIMESTAMP NULL
		)`,
		"CREATE INDEX IF NOT EXISTS idx_oauth2_clients_name ON oauth2_clients(name)",
		// Feature: key versioning table for true rotation
		`CREATE TABLE IF NOT EXISTS key_versions (
			key_id     TEXT NOT NULL,
			version    INTEGER NOT NULL,
			value      TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version),
			FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_key_versions_key_id ON key_versions(key_id)",
		// Feature: certificate policy table for creation and renewal settings
		`CREATE TABLE IF NOT EXISTS certificate_policies (
			id                TEXT PRIMARY KEY,
			certificate_id    TEXT NOT NULL UNIQUE,
			user_id           TEXT NOT NULL,
			validity_months   INTEGER NOT NULL DEFAULT 12,
			key_type          TEXT NOT NULL DEFAULT 'RSA',
			key_size          INTEGER NOT NULL DEFAULT 2048,
			curve             TEXT NOT NULL DEFAULT '',
			subject           TEXT NOT NULL DEFAULT '',
			sans              TEXT NOT NULL DEFAULT '',
			auto_renew        BOOLEAN NOT NULL DEFAULT FALSE,
			days_before_expiry INTEGER NOT NULL DEFAULT 30,
			issuer_name       TEXT NOT NULL DEFAULT '',
			created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		"CREATE INDEX IF NOT EXISTS idx_cert_policies_cert_id ON certificate_policies(certificate_id)",
		"CREATE INDEX IF NOT EXISTS idx_cert_policies_user_id ON certificate_policies(user_id)",
		// Feature: enriched audit fields for SOC 2 / GDPR compliance
		"ALTER TABLE audit_logs ADD COLUMN resource_type TEXT",
		"ALTER TABLE audit_logs ADD COLUMN resource_id TEXT",
		"ALTER TABLE audit_logs ADD COLUMN ip_address TEXT",
		"ALTER TABLE audit_logs ADD COLUMN outcome TEXT",
		"ALTER TABLE audit_logs ADD COLUMN source TEXT",
		"ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT",
		// Indexes on the enriched audit_logs columns. These must run AFTER the
		// ALTER TABLE statements above so the columns exist on upgraded databases.
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_outcome ON audit_logs(outcome)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_source ON audit_logs(source)",
		// Feature: audit configuration table (idempotent — IF NOT EXISTS prevents errors)
		"CREATE TABLE IF NOT EXISTS audit_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
		// Multi-vault: vaults table and vault_id scoping columns.
		// The vault_id column defaults are hardcoded SQL literals and must stay
		// equal to model.DefaultVaultID ("00000000-0000-0000-0000-00000000efa1").
		`CREATE TABLE IF NOT EXISTS vaults (
			id                 TEXT PRIMARY KEY,
			name               TEXT UNIQUE NOT NULL,
			enabled            BOOLEAN NOT NULL DEFAULT TRUE,
			purge_protection   BOOLEAN NOT NULL DEFAULT FALSE,
			retention_days     INTEGER NOT NULL DEFAULT 90,
			created_by         TEXT NOT NULL,
			created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at         TIMESTAMP NULL,
			scheduled_purge_at TIMESTAMP NULL
		)`,
		"CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name)",
		// Vault tags + modification tracking (Azure parity). Tags stored as a JSON
		// object; (de)serialization is confined to vault_repository.go.
		"ALTER TABLE vaults ADD COLUMN tags TEXT NOT NULL DEFAULT '{}'",
		"ALTER TABLE vaults ADD COLUMN updated_at TIMESTAMP NULL",
		"ALTER TABLE vaults ADD COLUMN updated_by TEXT NULL",
		"ALTER TABLE secrets ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
		"ALTER TABLE keys ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
		"ALTER TABLE certificates ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1'",
		"ALTER TABLE access_policies ADD COLUMN vault_id TEXT NULL",
		"ALTER TABLE access_policies ADD COLUMN assignment_id TEXT NULL",
	}
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			if !isDuplicateColumnError(err) {
				return fmt.Errorf("migration failed (%q): %w", stmt, err)
			}
		}
	}

	// Feature: vault-scoped role assignments table (idempotent).
	// Runs after the loop so the vaults table (created above) already exists.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS role_assignments (
		id             TEXT PRIMARY KEY,
		principal_id   TEXT NOT NULL,
		principal_type TEXT NOT NULL,
		role           TEXT NOT NULL,
		vault_id       TEXT NOT NULL,
		created_by     TEXT NOT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (principal_id, role, vault_id),
		FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create role_assignments: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id)`); err != nil {
		return fmt.Errorf("index role_assignments vault: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_access_policies_assignment ON access_policies(assignment_id)`); err != nil {
		return fmt.Errorf("index access_policies assignment: %w", err)
	}

	d.log.Info("Schema migration completed")
	return nil
}

// finalizeVaultIndexes resolves name collisions then creates the per-vault unique
// indexes. It is idempotent and safe to run on every startup.
func (d *DBRepository) finalizeVaultIndexes(db *sql.DB) error {
	ctx := context.Background()
	for _, table := range []string{"secrets", "keys", "certificates"} {
		if _, err := ResolveNameCollisions(ctx, db, table); err != nil {
			return err
		}
	}
	stmts := []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_vault_name ON secrets(vault_id, name)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_vault_name ON keys(vault_id, name)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_vault_name ON certificates(vault_id, name)",
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("create vault unique index: %w", err)
		}
	}
	return nil
}

// isDuplicateColumnError returns true when err represents a "column already exists"
// error from SQLite or PostgreSQL, allowing migrateSchema to be idempotent.
// The logic now lives on Dialect; this shim keeps existing call sites unchanged.
func isDuplicateColumnError(err error) bool {
	// The check is dialect-agnostic (string match plus pq code), so either
	// dialect value produces the same result here.
	return SQLite.IsDuplicateColumnErr(err)
}

// seedBootstrapToken inserts the configured bootstrap token into the
// bootstrap_tokens table if it is not already present. The SELECT-then-INSERT
// approach keeps the SQL portable across SQLite and PostgreSQL drivers.
func (d *DBRepository) seedBootstrapToken(db *sql.DB) error {
	token := viper.GetString("bootstrap_token")
	if token == "" {
		return nil
	}

	var count int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM bootstrap_tokens WHERE token = ?", token,
	).Scan(&count); err != nil {
		return fmt.Errorf("failed to check bootstrap token: %w", err)
	}

	if count > 0 {
		return nil // already seeded (or already used)
	}

	if _, err := db.Exec(
		"INSERT INTO bootstrap_tokens (token, used) VALUES (?, FALSE)", token,
	); err != nil {
		return fmt.Errorf("failed to seed bootstrap token: %w", err)
	}
	return nil
}

// seedAuditConfig inserts default audit configuration values if they are not
// already present. Safe to call on every startup.
func (d *DBRepository) seedAuditConfig(db *sql.DB) error {
	defaults := map[string]string{
		"retention_days": "365",
	}
	for k, v := range defaults {
		var count int
		if err := db.QueryRow(
			"SELECT COUNT(*) FROM audit_config WHERE key = ?", k,
		).Scan(&count); err != nil {
			return fmt.Errorf("failed to check audit_config key %q: %w", k, err)
		}
		if count == 0 {
			if _, err := db.Exec(
				"INSERT INTO audit_config (key, value) VALUES (?, ?)", k, v,
			); err != nil {
				return fmt.Errorf("failed to seed audit_config key %q: %w", k, err)
			}
		}
	}
	return nil
}

// seedDefaultVault inserts the default vault if it is absent. It is idempotent.
// The default vault holds all pre-multi-vault data and backs the legacy flat routes.
func (d *DBRepository) seedDefaultVault(db *sql.DB) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM vaults WHERE name = ?", model.DefaultVaultName).Scan(&count); err != nil {
		return fmt.Errorf("failed to check default vault: %w", err)
	}
	if count > 0 {
		return nil
	}
	// Choose an owner: an existing admin, else any user, else the zero UUID.
	creator := "00000000-0000-0000-0000-000000000000"
	_ = db.QueryRow("SELECT COALESCE((SELECT id FROM users WHERE role = 'admin' LIMIT 1), (SELECT id FROM users LIMIT 1), ?)", creator).Scan(&creator)
	if _, err := db.Exec(
		"INSERT INTO vaults (id, name, enabled, retention_days, created_by) VALUES (?, ?, ?, ?, ?)",
		model.DefaultVaultID, model.DefaultVaultName, true, 90, creator,
	); err != nil {
		return fmt.Errorf("failed to seed default vault: %w", err)
	}
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

// RecordQueryExecution records query performance metrics.
func RecordQueryExecution(duration time.Duration) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	metrics.QueryCount++
	metrics.TotalQueryTime += duration

	if metrics.QueryCount > 0 {
		metrics.AverageQueryTime = metrics.TotalQueryTime / time.Duration(metrics.QueryCount)
	}

	// Track slow queries (>100ms)
	if duration > 100*time.Millisecond {
		metrics.SlowQueryCount++
	}
}

// PerformanceMetricsSnapshot is a copy of PerformanceMetrics without the mutex for safe return.
type PerformanceMetricsSnapshot struct {
	QueryCount       int64         `json:"query_count"`
	SlowQueryCount   int64         `json:"slow_query_count"`
	TotalQueryTime   time.Duration `json:"total_query_time"`
	AverageQueryTime time.Duration `json:"avg_query_time"`
	ConnectionStats  sql.DBStats   `json:"connection_stats"`
}

// GetPerformanceMetrics returns current database performance metrics without copying the mutex.
func GetPerformanceMetrics() PerformanceMetricsSnapshot {
	metrics.mu.RLock()
	defer metrics.mu.RUnlock()

	result := PerformanceMetricsSnapshot{
		QueryCount:       metrics.QueryCount,
		SlowQueryCount:   metrics.SlowQueryCount,
		TotalQueryTime:   metrics.TotalQueryTime,
		AverageQueryTime: metrics.AverageQueryTime,
	}

	// Add current connection stats if DB is available
	if DB != nil {
		result.ConnectionStats = DB.Stats()
	}

	return result
}

// ResetPerformanceMetrics resets performance tracking metrics.
func ResetPerformanceMetrics() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	metrics.QueryCount = 0
	metrics.SlowQueryCount = 0
	metrics.TotalQueryTime = 0
	metrics.AverageQueryTime = 0
}

// GetConnectionPoolStats returns detailed connection pool statistics.
func GetConnectionPoolStats() map[string]interface{} {
	if DB == nil {
		return map[string]interface{}{"error": "database not initialized"}
	}

	stats := DB.Stats()
	return map[string]interface{}{
		"open_connections":    stats.OpenConnections,
		"in_use":              stats.InUse,
		"idle":                stats.Idle,
		"wait_count":          stats.WaitCount,
		"wait_duration_ms":    stats.WaitDuration.Milliseconds(),
		"max_idle_closed":     stats.MaxIdleClosed,
		"max_lifetime_closed": stats.MaxLifetimeClosed,
		"utilization_percent": float64(stats.InUse) / float64(stats.OpenConnections) * 100,
	}
}

// HealthCheck performs comprehensive database health validation.
func HealthCheck(ctx context.Context) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	if err := DB.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}
	duration := time.Since(start)

	// Record the health check as a query
	RecordQueryExecution(duration)

	// Check connection pool health
	stats := DB.Stats()
	if stats.OpenConnections == 0 {
		return fmt.Errorf("no open database connections")
	}

	// Warn about potential issues
	if stats.WaitCount > 100 && stats.WaitDuration > time.Millisecond*100 {
		return fmt.Errorf("database connection pool under stress: wait_count=%d, wait_duration=%v",
			stats.WaitCount, stats.WaitDuration)
	}

	return nil
}
