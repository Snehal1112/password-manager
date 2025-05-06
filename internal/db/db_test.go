// Package db_test contains unit tests for the db package.
// It verifies database initialization, table creation, and connection management.
package db

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestInitializeDB tests the InitializeDB function to ensure it opens a SQLite connection and creates tables.
func TestInitializeDB(t *testing.T) {
	// Set up test configuration.
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db") // Clean up test database.

	// Test happy path.
	err := InitializeDB()
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
	err := InitializeDB()
	assert.Error(t, err, "database initialization should fail with empty connection string")
	assert.Contains(t, err.Error(), "database connection string not configured")
}

// TestCloseDB tests the CloseDB function to ensure it closes the connection gracefully.
func TestCloseDB(t *testing.T) {
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db")

	// Initialize database.
	err := InitializeDB()
	assert.NoError(t, err, "database initialization should succeed")

	// Test closing.
	err = CloseDB()
	assert.NoError(t, err, "closing database should succeed")
}

// BenchmarkInitializeDB measures the performance of database initialization.
func BenchmarkInitializeDB(b *testing.B) {
	viper.Set("database.connection", "./test.db")
	defer os.Remove("./test.db")

	for i := 0; i < b.N; i++ {
		InitializeDB()
		CloseDB()
	}
}
