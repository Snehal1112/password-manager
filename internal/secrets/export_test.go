package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"password-manager/common"
	"password-manager/internal/db"
	"password-manager/internal/logging"
)

func setupExportTestEnvironment(t *testing.T) (SecretRepository, context.Context, func()) {
	t.Helper()

	// Setup test environment
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "export_test.db")
	logPath := filepath.Join(tempDir, "export_test.log")

	// Configure test environment
	viper.Reset()
	viper.Set("database.connection", dbPath)
	viper.Set("log.file", logPath)
	viper.Set("log.level", "debug")
	viper.Set("jwt_secret", "test-jwt-secret-for-export-tests")
	viper.Set("master_key", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	// Initialize logger and database
	logger := logging.InitLogger()
	require.NotNil(t, logger, "Logger should be initialized")

	database := db.NewRepository(logger)
	err := database.InitializeDB()
	require.NoError(t, err, "Database should initialize")

	sqlDB := database.GetDB()
	require.NotNil(t, sqlDB, "Database connection should be available")

	// Initialize secrets repository
	secretsRepo := NewSecretRepository(sqlDB, logger)
	require.NotNil(t, secretsRepo, "Secrets repository should be created")

	ctx := context.Background()
	ctx = context.WithValue(ctx, common.DBKey, sqlDB)
	ctx = context.WithValue(ctx, common.LogKey, logger)

	cleanup := func() {
		sqlDB.Close()
		os.Remove(dbPath)
		os.Remove(logPath)
	}

	return secretsRepo, ctx, cleanup
}

func createTestSecrets(t *testing.T, repo SecretRepository, ctx context.Context, userID uuid.UUID) []Secret {
	t.Helper()

	secrets := []Secret{
		{
			ID:        uuid.New(),
			UserID:    userID,
			Name:      "database-password",
			Value:     "super-secret-db-password",
			Version:   1,
			Tags:      []string{"database", "production"},
			CreatedAt: time.Now().Add(-time.Hour),
		},
		{
			ID:        uuid.New(),
			UserID:    userID,
			Name:      "api-key",
			Value:     "sk-1234567890abcdef",
			Version:   1,
			Tags:      []string{"api", "external"},
			CreatedAt: time.Now().Add(-30 * time.Minute),
		},
		{
			ID:        uuid.New(),
			UserID:    userID,
			Name:      "encryption-key",
			Value:     "aes-256-key-very-secure",
			Version:   1,
			Tags:      []string{"encryption", "security"},
			CreatedAt: time.Now().Add(-10 * time.Minute),
		},
	}

	for _, secret := range secrets {
		err := repo.Create(ctx, &secret)
		require.NoError(t, err, "Should create test secret: %s", secret.Name)
	}

	return secrets
}

func TestExportSecretsJSON(t *testing.T) {
	repo, ctx, cleanup := setupExportTestEnvironment(t)
	defer cleanup()

	userID := uuid.New()
	testSecrets := createTestSecrets(t, repo, ctx, userID)

	t.Run("Export_All_Secrets_JSON_Encrypted", func(t *testing.T) {
		options := ExportOptions{
			Format:      ExportFormatJSON,
			IncludeTags: true,
			Encrypt:     true,
			UserID:      userID,
			ExportedAt:  time.Now(),
			ExportedBy:  "test-user",
		}

		data, err := repo.ExportSecrets(ctx, options)
		require.NoError(t, err, "Should export secrets successfully")
		assert.NotEmpty(t, data, "Export data should not be empty")

		// Since it's encrypted, we should be able to decrypt it
		decryptedData, err := common.DecryptSecret(string(data))
		require.NoError(t, err, "Should decrypt exported data")

		// Parse the decrypted JSON
		var container ExportContainer
		err = json.Unmarshal([]byte(decryptedData), &container)
		require.NoError(t, err, "Should parse decrypted JSON")

		assert.Equal(t, ExportFormatJSON, container.Metadata.Format)
		assert.True(t, container.Metadata.Encrypt)
		assert.Equal(t, userID, container.Metadata.UserID)
		assert.Len(t, container.Secrets, len(testSecrets))

		// Verify secret content
		secretMap := make(map[string]ExportedSecret)
		for _, secret := range container.Secrets {
			secretMap[secret.Name] = secret
		}

		assert.Contains(t, secretMap, "database-password")
		assert.Equal(t, "super-secret-db-password", secretMap["database-password"].Value)
		assert.Contains(t, secretMap["database-password"].Tags, "database")
		assert.Contains(t, secretMap["database-password"].Tags, "production")
	})

	t.Run("Export_All_Secrets_JSON_Unencrypted", func(t *testing.T) {
		options := ExportOptions{
			Format:      ExportFormatJSON,
			IncludeTags: true,
			Encrypt:     false,
			UserID:      userID,
			ExportedAt:  time.Now(),
			ExportedBy:  "test-user",
		}

		data, err := repo.ExportSecrets(ctx, options)
		require.NoError(t, err, "Should export secrets successfully")
		assert.NotEmpty(t, data, "Export data should not be empty")

		// Parse the JSON directly
		var container ExportContainer
		err = json.Unmarshal(data, &container)
		require.NoError(t, err, "Should parse JSON")

		assert.Equal(t, ExportFormatJSON, container.Metadata.Format)
		assert.False(t, container.Metadata.Encrypt)
		assert.Len(t, container.Secrets, len(testSecrets))
	})

	t.Run("Export_Filtered_Secrets_By_Tags", func(t *testing.T) {
		options := ExportOptions{
			Format:      ExportFormatJSON,
			IncludeTags: true,
			FilterTags:  []string{"database"},
			Encrypt:     false,
			UserID:      userID,
			ExportedAt:  time.Now(),
			ExportedBy:  "test-user",
		}

		data, err := repo.ExportSecrets(ctx, options)
		require.NoError(t, err, "Should export filtered secrets successfully")

		var container ExportContainer
		err = json.Unmarshal(data, &container)
		require.NoError(t, err, "Should parse JSON")

		// Should only contain secrets with 'database' tag
		assert.Len(t, container.Secrets, 1)
		assert.Equal(t, "database-password", container.Secrets[0].Name)
	})
}

func TestExportSecretsCSV(t *testing.T) {
	repo, ctx, cleanup := setupExportTestEnvironment(t)
	defer cleanup()

	userID := uuid.New()
	testSecrets := createTestSecrets(t, repo, ctx, userID)

	t.Run("Export_All_Secrets_CSV_Encrypted", func(t *testing.T) {
		options := ExportOptions{
			Format:      ExportFormatCSV,
			IncludeTags: true,
			Encrypt:     true,
			UserID:      userID,
			ExportedAt:  time.Now(),
			ExportedBy:  "test-user",
		}

		data, err := repo.ExportSecrets(ctx, options)
		require.NoError(t, err, "Should export secrets successfully")
		assert.NotEmpty(t, data, "Export data should not be empty")

		// Decrypt the data
		decryptedData, err := common.DecryptSecret(string(data))
		require.NoError(t, err, "Should decrypt exported data")

		// Verify CSV format
		lines := strings.Split(decryptedData, "\n")
		assert.GreaterOrEqual(t, len(lines), len(testSecrets)+1, "Should have header plus secret lines")

		// Check header
		header := lines[0]
		assert.Contains(t, header, "id,name,value,version,tags,created_at")

		// Check that secrets are present
		csvContent := strings.Join(lines, "\n")
		assert.Contains(t, csvContent, "database-password")
		assert.Contains(t, csvContent, "api-key")
		assert.Contains(t, csvContent, "encryption-key")
	})

	t.Run("Export_All_Secrets_CSV_Unencrypted", func(t *testing.T) {
		options := ExportOptions{
			Format:      ExportFormatCSV,
			IncludeTags: true,
			Encrypt:     false,
			UserID:      userID,
			ExportedAt:  time.Now(),
			ExportedBy:  "test-user",
		}

		data, err := repo.ExportSecrets(ctx, options)
		require.NoError(t, err, "Should export secrets successfully")

		csvContent := string(data)
		lines := strings.Split(csvContent, "\n")
		assert.GreaterOrEqual(t, len(lines), len(testSecrets)+1)

		// Verify CSV structure
		assert.Contains(t, lines[0], "id,name,value,version,tags,created_at")
		assert.Contains(t, csvContent, "database;production") // Tags should be semicolon-separated
	})
}

func TestImportSecrets(t *testing.T) {
	repo, ctx, cleanup := setupExportTestEnvironment(t)
	defer cleanup()

	userID := uuid.New()

	t.Run("Import_JSON_Encrypted", func(t *testing.T) {
		// First create and export some secrets
		testSecrets := createTestSecrets(t, repo, ctx, userID)

		exportOptions := ExportOptions{
			Format:      ExportFormatJSON,
			IncludeTags: true,
			Encrypt:     true,
			UserID:      userID,
			ExportedAt:  time.Now(),
			ExportedBy:  "test-user",
		}

		exportedData, err := repo.ExportSecrets(ctx, exportOptions)
		require.NoError(t, err, "Should export secrets successfully")

		// Clear the database to test import
		for _, secret := range testSecrets {
			err := repo.Delete(ctx, secret.ID)
			require.NoError(t, err, "Should delete test secret")
		}

		// Import the data
		importOptions := ImportOptions{
			Format:            ExportFormatJSON,
			OverwriteExisting: false,
			Encrypted:         true,
			UserID:            userID,
			ImportedBy:        "test-user",
		}

		importedCount, err := repo.ImportSecrets(ctx, exportedData, importOptions)
		require.NoError(t, err, "Should import secrets successfully")
		assert.Equal(t, len(testSecrets), importedCount, "Should import all test secrets")

		// Verify secrets were imported correctly
		secrets, err := repo.ListByUser(ctx, userID, nil)
		require.NoError(t, err, "Should list imported secrets")
		assert.Len(t, secrets, len(testSecrets))

		// Check specific secret content
		secretMap := make(map[string]Secret)
		for _, secret := range secrets {
			secretMap[secret.Name] = secret
		}

		assert.Contains(t, secretMap, "database-password")
		assert.Equal(t, "super-secret-db-password", secretMap["database-password"].Value)
	})

	t.Run("Import_CSV_Unencrypted", func(t *testing.T) {
		// Create CSV data manually
		csvData := `id,name,value,version,tags,created_at
550e8400-e29b-41d4-a716-446655440000,test-secret,test-value,1,test;manual,2023-01-01T12:00:00Z
550e8400-e29b-41d4-a716-446655440001,another-secret,another-value,1,production;api,2023-01-01T13:00:00Z`

		importOptions := ImportOptions{
			Format:            ExportFormatCSV,
			OverwriteExisting: true,
			Encrypted:         false,
			UserID:            userID,
			ImportedBy:        "test-user",
		}

		importedCount, err := repo.ImportSecrets(ctx, []byte(csvData), importOptions)
		require.NoError(t, err, "Should import CSV secrets successfully")
		assert.Equal(t, 2, importedCount, "Should import 2 secrets from CSV")

		// Verify imported secrets
		secrets, err := repo.ListByUser(ctx, userID, nil)
		require.NoError(t, err, "Should list imported secrets")

		secretMap := make(map[string]Secret)
		for _, secret := range secrets {
			secretMap[secret.Name] = secret
		}

		assert.Contains(t, secretMap, "test-secret")
		assert.Equal(t, "test-value", secretMap["test-secret"].Value)
		assert.Contains(t, secretMap["test-secret"].Tags, "test")
		assert.Contains(t, secretMap["test-secret"].Tags, "manual")
	})

	t.Run("Import_Overwrite_Existing", func(t *testing.T) {
		// Create a secret
		originalSecret := Secret{
			ID:        uuid.New(),
			UserID:    userID,
			Name:      "overwrite-test",
			Value:     "original-value",
			Version:   1,
			Tags:      []string{"original"},
			CreatedAt: time.Now(),
		}

		err := repo.Create(ctx, &originalSecret)
		require.NoError(t, err, "Should create original secret")

		// Create import data with same ID but different value
		jsonData := fmt.Sprintf(`{
			"metadata": {
				"format": "json",
				"user_id": "%s"
			},
			"secrets": [
				{
					"id": "%s",
					"name": "overwrite-test",
					"value": "updated-value",
					"version": 2,
					"tags": ["updated"],
					"created_at": "2023-01-01T12:00:00Z"
				}
			]
		}`, userID.String(), originalSecret.ID.String())

		importOptions := ImportOptions{
			Format:            ExportFormatJSON,
			OverwriteExisting: true,
			Encrypted:         false,
			UserID:            userID,
			ImportedBy:        "test-user",
		}

		importedCount, err := repo.ImportSecrets(ctx, []byte(jsonData), importOptions)
		require.NoError(t, err, "Should import with overwrite")
		assert.Equal(t, 1, importedCount, "Should import 1 secret")

		// Verify secret was updated
		updatedSecret, err := repo.Read(ctx, originalSecret.ID)
		require.NoError(t, err, "Should read updated secret")
		assert.Equal(t, "updated-value", updatedSecret.Value)
		assert.Contains(t, updatedSecret.Tags, "updated")
	})
}

func TestExportImportErrorCases(t *testing.T) {
	repo, ctx, cleanup := setupExportTestEnvironment(t)
	defer cleanup()

	userID := uuid.New()

	t.Run("Export_Unsupported_Format", func(t *testing.T) {
		options := ExportOptions{
			Format: "unsupported",
			UserID: userID,
		}

		_, err := repo.ExportSecrets(ctx, options)
		assert.Error(t, err, "Should fail with unsupported format")
		assert.Contains(t, err.Error(), "unsupported export format")
	})

	t.Run("Import_Unsupported_Format", func(t *testing.T) {
		options := ImportOptions{
			Format: "unsupported",
			UserID: userID,
		}

		_, err := repo.ImportSecrets(ctx, []byte("test"), options)
		assert.Error(t, err, "Should fail with unsupported format")
		assert.Contains(t, err.Error(), "unsupported import format")
	})

	t.Run("Import_Invalid_JSON", func(t *testing.T) {
		options := ImportOptions{
			Format:    ExportFormatJSON,
			Encrypted: false,
			UserID:    userID,
		}

		_, err := repo.ImportSecrets(ctx, []byte("invalid json"), options)
		assert.Error(t, err, "Should fail with invalid JSON")
		assert.Contains(t, err.Error(), "failed to parse import data")
	})

	t.Run("Import_Invalid_CSV", func(t *testing.T) {
		// CSV with wrong number of fields
		csvData := "id,name\ninvalid-row"

		options := ImportOptions{
			Format:    ExportFormatCSV,
			Encrypted: false,
			UserID:    userID,
		}

		_, err := repo.ImportSecrets(ctx, []byte(csvData), options)
		assert.Error(t, err, "Should fail with invalid CSV")
		assert.Contains(t, err.Error(), "invalid CSV record")
	})

	t.Run("Import_Encrypted_With_Wrong_Key", func(t *testing.T) {
		// Change master key to make decryption fail
		viper.Set("master_key", "d3JvbmdrZXlmb3J0ZXN0aW5ncHVycG9zZXNvbmx5")

		options := ImportOptions{
			Format:    ExportFormatJSON,
			Encrypted: true,
			UserID:    userID,
		}

		_, err := repo.ImportSecrets(ctx, []byte("encrypted-data"), options)
		assert.Error(t, err, "Should fail with wrong decryption key")
		assert.Contains(t, err.Error(), "failed to decrypt import data")
	})
}