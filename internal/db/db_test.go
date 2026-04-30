// Package db_test contains unit tests for the db package.
// It verifies database initialization, table creation, and connection management.
package db

import (
	"fmt"
	"os"
	"testing"

	"github.com/lib/pq"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/logging"
)

// TestInitializeDB tests the InitializeDB function to ensure it opens a SQLite connection and creates tables.
func TestInitializeDB(t *testing.T) {
	// Set up test configuration.
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db") // Clean up test database.
	log := logging.InitLogger()

	// Test happy path.
	db := NewRepository(log)
	err := db.InitializeDB()
	assert.NoError(t, err, "database initialization should succeed")
	assert.NotNil(t, DB, "DB connection should be initialized")

	// Verify table creation.
	rows, err := DB.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
	assert.NoError(t, err, "query for users table should succeed")
	assert.True(t, rows.Next(), "users table should exist")
	rows.Close()
}

// TestInitializeDBInvalidConfig tests InitializeDB with an invalid connection string.
func TestInitializeDBInvalidConfig(t *testing.T) {
	viper.Set("database.connection", "")
	log := logging.InitLogger()
	db := NewRepository(log)
	err := db.InitializeDB()
	assert.Error(t, err, "database initialization should fail with empty connection string")
	assert.Contains(t, err.Error(), "database connection string not configured")
}

// TestCloseDB tests the CloseDB function to ensure it closes the connection gracefully.
func TestCloseDB(t *testing.T) {
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db")

	// Initialize database.
	log := logging.InitLogger()
	db := NewRepository(log)
	err := db.InitializeDB()
	assert.NoError(t, err, "database initialization should succeed")

	// Test closing.
	err = db.CloseDB()
	assert.NoError(t, err, "closing database should succeed")
}

// BenchmarkInitializeDB measures the performance of database initialization.
func BenchmarkInitializeDB(b *testing.B) {
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db")
	log := logging.InitLogger()

	for i := 0; i < b.N; i++ {
		db := NewRepository(log)
		db.InitializeDB()
		db.CloseDB()
	}
}

// TestIsDuplicateColumnError_SQLite tests duplicate column detection for SQLite.
func TestIsDuplicateColumnError_SQLite(t *testing.T) {
	err := fmt.Errorf("table secrets already has column deleted_at: duplicate column name: deleted_at")
	assert.True(t, isDuplicateColumnError(err), "SQLite duplicate column error should be detected")
}

// TestIsDuplicateColumnError_PostgreSQL_DuplicateColumn tests PostgreSQL error code 42701.
func TestIsDuplicateColumnError_PostgreSQL_DuplicateColumn(t *testing.T) {
	err := &pq.Error{Code: "42701", Message: "column deleted_at of relation secrets already exists"}
	assert.True(t, isDuplicateColumnError(err), "PostgreSQL duplicate column error (42701) should be detected")
}

// TestIsDuplicateColumnError_PostgreSQL_TableAlreadyExists tests that table-exists errors are NOT silenced.
func TestIsDuplicateColumnError_PostgreSQL_TableAlreadyExists(t *testing.T) {
	err := &pq.Error{Code: "42P07", Message: "relation secrets already exists"}
	assert.False(t, isDuplicateColumnError(err), "table already exists error (42P07) must not be silenced as duplicate column")
}

// TestIsDuplicateColumnError_Nil tests that nil errors are handled correctly.
func TestIsDuplicateColumnError_Nil(t *testing.T) {
	assert.False(t, isDuplicateColumnError(nil), "nil error should return false")
}

// TestIsDuplicateColumnError_GenericError tests that unrelated errors are not matched.
func TestIsDuplicateColumnError_GenericError(t *testing.T) {
	assert.False(t, isDuplicateColumnError(fmt.Errorf("connection refused")), "generic error should not match duplicate column")
}
