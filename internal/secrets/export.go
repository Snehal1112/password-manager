// Package secrets provides export/import functionality for secrets management.
// It supports encrypted JSON and CSV formats with master key compatibility.
package secrets

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/common"
)

// ExportFormat represents the format for exporting secrets.
type ExportFormat string

const (
	// ExportFormatJSON exports secrets in JSON format.
	ExportFormatJSON ExportFormat = "json"
	// ExportFormatCSV exports secrets in CSV format.
	ExportFormatCSV ExportFormat = "csv"
)

// ExportOptions contains options for exporting secrets.
type ExportOptions struct {
	Format       ExportFormat `json:"format"`
	IncludeTags  bool         `json:"include_tags"`
	FilterTags   []string     `json:"filter_tags,omitempty"`
	Encrypt      bool         `json:"encrypt"`
	UserID       uuid.UUID    `json:"user_id"`
	ExportedAt   time.Time    `json:"exported_at"`
	ExportedBy   string       `json:"exported_by"`
}

// ImportOptions contains options for importing secrets.
type ImportOptions struct {
	Format          ExportFormat `json:"format"`
	OverwriteExisting bool        `json:"overwrite_existing"`
	Encrypted       bool         `json:"encrypted"`
	UserID          uuid.UUID    `json:"user_id"`
	ImportedBy      string       `json:"imported_by"`
}

// ExportedSecret represents a secret in export format.
type ExportedSecret struct {
	ID        string    `json:"id" csv:"id"`
	Name      string    `json:"name" csv:"name"`
	Value     string    `json:"value" csv:"value"`
	Version   int       `json:"version" csv:"version"`
	Tags      []string  `json:"tags" csv:"tags"`
	CreatedAt time.Time `json:"created_at" csv:"created_at"`
}

// ExportContainer represents the complete export structure.
type ExportContainer struct {
	Metadata ExportOptions    `json:"metadata"`
	Secrets  []ExportedSecret `json:"secrets"`
}

// ExportSecrets exports secrets to the specified format.
// It retrieves secrets for the user and formats them according to the export options.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - options: Export options including format, filters, and encryption.
//
// Returns:
//   - The exported data as bytes and an error if the operation fails.
func (r *secretRepository) ExportSecrets(ctx context.Context, options ExportOptions) ([]byte, error) {
	logrus.WithFields(logrus.Fields{
		"user_id": options.UserID.String(),
		"format":  string(options.Format),
		"encrypt": options.Encrypt,
	}).Info("Starting secrets export")

	// Retrieve secrets for the user
	secrets, err := r.ListByUser(ctx, options.UserID, options.FilterTags)
	if err != nil {
		r.log.LogAuditError(options.UserID.String(), "export_secrets", "failed", "Failed to retrieve secrets", err)
		return nil, fmt.Errorf("failed to retrieve secrets: %w", err)
	}

	// Convert to export format
	exportedSecrets := make([]ExportedSecret, 0, len(secrets))
	for _, secret := range secrets {
		exported := ExportedSecret{
			ID:        secret.ID.String(),
			Name:      secret.Name,
			Value:     secret.Value,
			Version:   secret.Version,
			CreatedAt: secret.CreatedAt,
		}

		if options.IncludeTags {
			exported.Tags = secret.Tags
		}

		exportedSecrets = append(exportedSecrets, exported)
	}

	// Create export container
	container := ExportContainer{
		Metadata: options,
		Secrets:  exportedSecrets,
	}

	var data []byte
	switch options.Format {
	case ExportFormatJSON:
		data, err = r.exportToJSON(container)
	case ExportFormatCSV:
		data, err = r.exportToCSV(container)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", options.Format)
	}

	if err != nil {
		r.log.LogAuditError(options.UserID.String(), "export_secrets", "failed", "Failed to format export data", err)
		return nil, fmt.Errorf("failed to format export data: %w", err)
	}

	// Encrypt if requested
	if options.Encrypt {
		encryptedData, err := common.EncryptSecret(string(data))
		if err != nil {
			r.log.LogAuditError(options.UserID.String(), "export_secrets", "failed", "Failed to encrypt export data", err)
			return nil, fmt.Errorf("failed to encrypt export data: %w", err)
		}
		data = []byte(encryptedData)
	}

	r.log.LogAuditInfo(options.UserID.String(), "export_secrets", "success", 
		fmt.Sprintf("Successfully exported %d secrets", len(exportedSecrets)))
	logrus.WithFields(logrus.Fields{
		"user_id":     options.UserID.String(),
		"format":      string(options.Format),
		"secret_count": len(exportedSecrets),
		"encrypted":   options.Encrypt,
	}).Info("Secrets exported successfully")

	return data, nil
}

// ImportSecrets imports secrets from the specified format.
// It parses the import data and creates secrets according to the import options.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - data: The import data as bytes.
//   - options: Import options including format, overwrite behavior, and encryption.
//
// Returns:
//   - The number of imported secrets and an error if the operation fails.
func (r *secretRepository) ImportSecrets(ctx context.Context, data []byte, options ImportOptions) (int, error) {
	logrus.WithFields(logrus.Fields{
		"user_id":   options.UserID.String(),
		"format":    string(options.Format),
		"encrypted": options.Encrypted,
	}).Info("Starting secrets import")

	var importData []byte = data

	// Decrypt if necessary
	if options.Encrypted {
		decryptedData, err := common.DecryptSecret(string(data))
		if err != nil {
			r.log.LogAuditError(options.UserID.String(), "import_secrets", "failed", "Failed to decrypt import data", err)
			return 0, fmt.Errorf("failed to decrypt import data: %w", err)
		}
		importData = []byte(decryptedData)
	}

	// Parse import data
	var container ExportContainer
	var err error

	switch options.Format {
	case ExportFormatJSON:
		err = r.importFromJSON(importData, &container)
	case ExportFormatCSV:
		err = r.importFromCSV(importData, &container)
	default:
		return 0, fmt.Errorf("unsupported import format: %s", options.Format)
	}

	if err != nil {
		r.log.LogAuditError(options.UserID.String(), "import_secrets", "failed", "Failed to parse import data", err)
		return 0, fmt.Errorf("failed to parse import data: %w", err)
	}

	// Import secrets
	importedCount := 0
	for _, exportedSecret := range container.Secrets {
		secret := Secret{
			ID:        uuid.MustParse(exportedSecret.ID),
			UserID:    options.UserID,
			Name:      exportedSecret.Name,
			Value:     exportedSecret.Value,
			Version:   exportedSecret.Version,
			Tags:      exportedSecret.Tags,
			CreatedAt: exportedSecret.CreatedAt,
		}

		// Check if secret already exists
		existingSecret, err := r.Read(ctx, secret.ID)
		if err == nil && existingSecret != nil {
			if !options.OverwriteExisting {
				logrus.WithFields(logrus.Fields{
					"secret_id": secret.ID.String(),
					"name":      secret.Name,
				}).Warn("Skipping existing secret (overwrite disabled)")
				continue
			}
			// Update existing secret
			err = r.Update(ctx, &secret)
		} else {
			// Create new secret
			err = r.Create(ctx, &secret)
		}

		if err != nil {
			r.log.LogAuditError(options.UserID.String(), "import_secrets", "failed", 
				fmt.Sprintf("Failed to import secret %s", secret.Name), err)
			logrus.WithFields(logrus.Fields{
				"secret_id": secret.ID.String(),
				"name":      secret.Name,
				"error":     err.Error(),
			}).Error("Failed to import secret")
			continue
		}

		importedCount++
	}

	r.log.LogAuditInfo(options.UserID.String(), "import_secrets", "success", 
		fmt.Sprintf("Successfully imported %d secrets", importedCount))
	logrus.WithFields(logrus.Fields{
		"user_id":        options.UserID.String(),
		"format":         string(options.Format),
		"imported_count": importedCount,
		"total_count":    len(container.Secrets),
	}).Info("Secrets imported successfully")

	return importedCount, nil
}

// exportToJSON converts the export container to JSON format.
func (r *secretRepository) exportToJSON(container ExportContainer) ([]byte, error) {
	return json.MarshalIndent(container, "", "  ")
}

// exportToCSV converts the export container to CSV format.
func (r *secretRepository) exportToCSV(container ExportContainer) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"id", "name", "value", "version", "tags", "created_at"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write secrets
	for _, secret := range container.Secrets {
		tags := strings.Join(secret.Tags, ";")
		record := []string{
			secret.ID,
			secret.Name,
			secret.Value,
			strconv.Itoa(secret.Version),
			tags,
			secret.CreatedAt.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	return []byte(buf.String()), nil
}

// importFromJSON parses JSON import data into the export container.
func (r *secretRepository) importFromJSON(data []byte, container *ExportContainer) error {
	return json.Unmarshal(data, container)
}

// importFromCSV parses CSV import data into the export container.
func (r *secretRepository) importFromCSV(data []byte, container *ExportContainer) error {
	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV data: %w", err)
	}

	if len(records) < 1 {
		return fmt.Errorf("CSV data is empty")
	}

	// Skip header row
	records = records[1:]

	container.Secrets = make([]ExportedSecret, 0, len(records))
	for i, record := range records {
		if len(record) != 6 {
			return fmt.Errorf("invalid CSV record at line %d: expected 6 fields, got %d", i+2, len(record))
		}

		version, err := strconv.Atoi(record[3])
		if err != nil {
			return fmt.Errorf("invalid version at line %d: %w", i+2, err)
		}

		createdAt, err := time.Parse(time.RFC3339, record[5])
		if err != nil {
			return fmt.Errorf("invalid created_at at line %d: %w", i+2, err)
		}

		var tags []string
		if record[4] != "" {
			tags = strings.Split(record[4], ";")
		}

		secret := ExportedSecret{
			ID:        record[0],
			Name:      record[1],
			Value:     record[2],
			Version:   version,
			Tags:      tags,
			CreatedAt: createdAt,
		}

		container.Secrets = append(container.Secrets, secret)
	}

	return nil
}