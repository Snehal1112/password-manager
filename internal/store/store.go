package store

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/secret"
)

// Store defines generic CRUD operations for entities.
type Store[T any] interface {
	InitSchema() error
	Save(entity T) error
	Get(id string) (T, error)
	Update(entity T) error
	Delete(id string) error
}

// sqlStore implements Store for SQL databases.
type sqlStore[T any] struct {
	db        *sql.DB
	mu        sync.Mutex
	tableName string
}

// NewSQLStore creates a new generic SQL store.
// It initializes a thread-safe store for the specified database table.
//
// Parameters:
//
//	db: The SQL database connection (e.g., SQLite or PostgreSQL instance).
//	tableName: The name of the database table (e.g., "secrets").
//
// Returns:
//
//	A pointer to the sqlStore implementing the Store interface.
//
// The function is used to set up storage for entities like secrets or users.
func NewSQLStore[T any](db *sql.DB, tableName string) Store[T] {
	if db == nil || tableName == "" {
		logrus.WithFields(logrus.Fields{"table_name": tableName}).Error("Invalid database or table name")
		panic("database and table name must not be nil or empty")
	}
	store := &sqlStore[T]{
		db:        db,
		tableName: tableName,
	}
	logrus.WithFields(logrus.Fields{"table_name": tableName}).Info("SQL store initialized")
	return store
}

// InitSchema initializes the database schema for the store.
// It creates the specified table (secrets or users) if it does not exist.
//
// Parameters:
//
//	None.
//
// Returns:
//
//	An error if the table creation fails.
//
// The function is used to set up the database tables for storing entities.
func (s *sqlStore[T]) InitSchema() error {
	var query string
	switch s.tableName {
	case "secrets":
		query = fmt.Sprintf(`
            CREATE TABLE IF NOT EXISTS %s (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                version INTEGER NOT NULL,
                created_at TIMESTAMP NOT NULL,
                rotate_at TIMESTAMP NOT NULL
            )`, s.tableName)
	case "users":
		query = fmt.Sprintf(`
            CREATE TABLE IF NOT EXISTS %s (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL
            )`, s.tableName)
	default:
		logrus.WithFields(logrus.Fields{"table_name": s.tableName}).Error("Unsupported table name")
		return fmt.Errorf("unsupported table name: %s", s.tableName)
	}
	_, err := s.db.Exec(query)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"table_name": s.tableName,
		}).Error("Failed to initialize schema")
		return fmt.Errorf("initializing schema for %s: %w", s.tableName, err)
	}
	logrus.WithFields(logrus.Fields{
		"table_name": s.tableName,
	}).Info("Schema initialized")
	return nil
}

// Save stores an entity in the database.
// It ensures thread-safe database operations using a mutex.
//
// Parameters:
//
//	entity: The entity to save (e.g., a Secret or User struct with relevant fields).
//
// Returns:
//
//	An error if the database operation fails.
//
// The function is used to persist entities securely in the database.
func (s *sqlStore[T]) Save(entity T) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch v := any(entity).(type) {
	case *secret.Secret:
		query := fmt.Sprintf("INSERT INTO %s (id, value, version, created_at, rotate_at) VALUES (?, ?, ?, ?, ?)", s.tableName)
		_, err := s.db.Exec(query, v.ID, v.Value, v.Version, v.CreatedAt, v.RotateAt)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  v.ID,
			}).Error("Failed to save secret")
			return fmt.Errorf("saving secret to %s: %w", s.tableName, err)
		}
	case *auth.User:
		query := fmt.Sprintf("INSERT INTO %s (id, username, password_hash, totp_secret) VALUES (?, ?, ?, ?)", s.tableName)
		_, err := s.db.Exec(query, v.ID, v.Username, v.PasswordHash, v.TOTPSecret)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  v.ID,
			}).Error("Failed to save user")
			return fmt.Errorf("saving user to %s: %w", s.tableName, err)
		}
	default:
		logrus.WithFields(logrus.Fields{
			"table_name":  s.tableName,
			"entity_type": fmt.Sprintf("%T", entity),
		}).Error("Unsupported entity type")
		return fmt.Errorf("unsupported entity type: %T", entity)
	}

	logrus.WithFields(logrus.Fields{
		"table_name": s.tableName,
	}).Info("Entity saved")
	return nil
}

// Get retrieves an entity from the database by ID.
// It ensures thread-safe database operations using a mutex.
//
// Parameters:
//
//	id: The unique identifier of the entity (e.g., "api_key_123").
//
// Returns:
//
//	The retrieved entity and an error if the database operation fails or the entity is not found.
//
// The function is used to fetch entities like secrets or users from the database.
func (s *sqlStore[T]) Get(id string) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var entity T
	switch any(entity).(type) {
	case *secret.Secret:
		query := fmt.Sprintf("SELECT id, value, version, created_at, rotate_at FROM %s WHERE id = ?", s.tableName)
		var dbID, dbValue string
		var dbVersion int
		var dbCreatedAt, dbRotateAt time.Time
		err := s.db.QueryRow(query, id).Scan(&dbID, &dbValue, &dbVersion, &dbCreatedAt, &dbRotateAt)
		if err == sql.ErrNoRows {
			logrus.WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  id,
			}).Warn("Secret not found")
			return entity, fmt.Errorf("secret with id %s not found in %s", id, s.tableName)
		}
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  id,
			}).Error("Failed to retrieve secret")
			return entity, fmt.Errorf("retrieving secret from %s: %w", s.tableName, err)
		}
		entity = any(&secret.Secret{
			ID:        dbID,
			Value:     dbValue,
			Version:   dbVersion,
			CreatedAt: dbCreatedAt,
			RotateAt:  dbRotateAt,
		}).(T)
	case *auth.User:
		query := fmt.Sprintf("SELECT id, username, password_hash, totp_secret FROM %s WHERE id = ?", s.tableName)
		var dbID, dbUsername, dbPasswordHash, dbTOTPSecret string
		err := s.db.QueryRow(query, id).Scan(&dbID, &dbUsername, &dbPasswordHash, &dbTOTPSecret)
		if err == sql.ErrNoRows {
			logrus.WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  id,
			}).Warn("User not found")
			return entity, fmt.Errorf("user with id %s not found in %s", id, s.tableName)
		}
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  id,
			}).Error("Failed to retrieve user")
			return entity, fmt.Errorf("retrieving user from %s: %w", s.tableName, err)
		}
		entity = any(&auth.User{
			ID:           dbID,
			Username:     dbUsername,
			PasswordHash: dbPasswordHash,
			TOTPSecret:   dbTOTPSecret,
		}).(T)
	default:
		logrus.WithFields(logrus.Fields{
			"table_name":  s.tableName,
			"entity_type": fmt.Sprintf("%T", entity),
		}).Error("Unsupported entity type")
		return entity, fmt.Errorf("unsupported entity type: %T", entity)
	}

	logrus.WithFields(logrus.Fields{
		"table_name": s.tableName,
		"entity_id":  id,
	}).Info("Entity retrieved")
	return entity, nil
}

// Update updates an existing entity in the database.
// It ensures thread-safe database operations using a mutex.
//
// Parameters:
//
//	entity: The entity to update (e.g., a Secret or User struct with updated fields).
//
// Returns:
//
//	An error if the database operation fails or the entity is not found.
//
// The function is used to update entities like secrets or users in the database.
func (s *sqlStore[T]) Update(entity T) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch v := any(entity).(type) {
	case *secret.Secret:
		query := fmt.Sprintf("UPDATE %s SET value = ?, version = ?, created_at = ?, rotate_at = ? WHERE id = ?", s.tableName)
		result, err := s.db.Exec(query, v.Value, v.Version, v.CreatedAt, v.RotateAt, v.ID)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  v.ID,
			}).Error("Failed to update secret")
			return fmt.Errorf("updating secret in %s: %w", s.tableName, err)
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			logrus.WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  v.ID,
			}).Warn("Secret not found for update")
			return fmt.Errorf("secret with id %s not found in %s", v.ID, s.tableName)
		}
	case *auth.User:
		query := fmt.Sprintf("UPDATE %s SET username = ?, password_hash = ?, totp_secret = ? WHERE id = ?", s.tableName)
		result, err := s.db.Exec(query, v.Username, v.PasswordHash, v.TOTPSecret, v.ID)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  v.ID,
			}).Error("Failed to update user")
			return fmt.Errorf("updating user in %s: %w", s.tableName, err)
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			logrus.WithFields(logrus.Fields{
				"table_name": s.tableName,
				"entity_id":  v.ID,
			}).Warn("User not found for update")
			return fmt.Errorf("user with id %s not found in %s", v.ID, s.tableName)
		}
	default:
		logrus.WithFields(logrus.Fields{
			"table_name":  s.tableName,
			"entity_type": fmt.Sprintf("%T", entity),
		}).Error("Unsupported entity type")
		return fmt.Errorf("unsupported entity type: %T", entity)
	}

	logrus.WithFields(logrus.Fields{
		"table_name": s.tableName,
	}).Info("Entity updated")
	return nil
}

// Delete removes an entity from the database by ID.
// It ensures thread-safe database operations using a mutex.
//
// Parameters:
//
//	id: The unique identifier of the entity (e.g., "api_key_123").
//
// Returns:
//
//	An error if the database operation fails or the entity is not found.
//
// The function is used to remove entities like secrets or users from the database.
func (s *sqlStore[T]) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", s.tableName)
	result, err := s.db.Exec(query, id)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"table_name": s.tableName,
			"entity_id":  id,
		}).Error("Failed to delete entity")
		return fmt.Errorf("deleting entity from %s: %w", s.tableName, err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		logrus.WithFields(logrus.Fields{
			"table_name": s.tableName,
			"entity_id":  id,
		}).Warn("Entity not found for deletion")
		return fmt.Errorf("entity with id %s not found in %s", id, s.tableName)
	}
	logrus.WithFields(logrus.Fields{
		"table_name": s.tableName,
		"entity_id":  id,
	}).Info("Entity deleted")
	return nil
}
