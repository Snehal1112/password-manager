/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"rocketvault/common"
	"rocketvault/internal/logging"
)

// BackupMetadata contains metadata about a backup
type BackupMetadata struct {
	Version     string    `json:"version"`
	Timestamp   time.Time `json:"timestamp"`
	Database    string    `json:"database"`
	TableCount  int       `json:"table_count"`
	RecordCount int       `json:"record_count"`
	Encrypted   bool      `json:"encrypted"`
	Checksum    string    `json:"checksum,omitempty"`
}

// TableData represents data from a single table
type TableData struct {
	Name     string                   `json:"name"`
	Columns  []string                 `json:"columns"`
	Rows     []map[string]interface{} `json:"rows"`
	RowCount int                      `json:"row_count"`
}

// BackupData represents the complete backup structure
type BackupData struct {
	Metadata BackupMetadata `json:"metadata"`
	Tables   []TableData    `json:"tables"`
}

// Manager handles backup and restore operations
type Manager struct {
	db     *sql.DB
	logger *logging.Logger
}

// NewManager creates a new backup manager
func NewManager(db *sql.DB, logger *logging.Logger) *Manager {
	return &Manager{
		db:     db,
		logger: logger,
	}
}

// CreateBackup creates a backup of the database
func (m *Manager) CreateBackup(outputPath string, encrypt bool) error {
	m.logger.Info("Starting database backup")

	// Get all table names
	tables, err := m.getTableNames()
	if err != nil {
		return fmt.Errorf("failed to get table names: %w", err)
	}

	backupData := BackupData{
		Metadata: BackupMetadata{
			Version:    "1.0",
			Timestamp:  time.Now(),
			TableCount: len(tables),
			Encrypted:  encrypt,
		},
		Tables: make([]TableData, 0, len(tables)),
	}

	totalRecords := 0

	// Export data from each table
	for _, tableName := range tables {
		tableData, err := m.exportTableData(tableName)
		if err != nil {
			return fmt.Errorf("failed to export table %s: %w", tableName, err)
		}

		backupData.Tables = append(backupData.Tables, *tableData)
		totalRecords += tableData.RowCount
		m.logger.WithField("table", tableName).WithField("records", tableData.RowCount).Info("Exported table")
	}

	backupData.Metadata.RecordCount = totalRecords

	// Create backup file
	if err := m.writeBackupFile(backupData, outputPath, encrypt); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	m.logger.WithFields(map[string]interface{}{
		"file":      outputPath,
		"tables":    len(tables),
		"records":   totalRecords,
		"encrypted": encrypt,
	}).Info("Backup completed successfully")

	return nil
}

// RestoreBackup restores the database from a backup file
func (m *Manager) RestoreBackup(backupPath string, encrypted bool) error {
	m.logger.Info("Starting database restore")

	// Read and parse backup file
	backupData, err := m.readBackupFile(backupPath, encrypted)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Validate backup data
	if err := m.validateBackupData(backupData); err != nil {
		return fmt.Errorf("invalid backup data: %w", err)
	}

	// Begin transaction for restore
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Clear existing data and restore
	totalRecords := 0
	for _, tableData := range backupData.Tables {
		if err := m.restoreTableData(tx, &tableData); err != nil {
			return fmt.Errorf("failed to restore table %s: %w", tableData.Name, err)
		}
		totalRecords += tableData.RowCount
		m.logger.WithField("table", tableData.Name).WithField("records", tableData.RowCount).Info("Restored table")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	m.logger.WithFields(map[string]interface{}{
		"file":    backupPath,
		"tables":  len(backupData.Tables),
		"records": totalRecords,
	}).Info("Restore completed successfully")

	return nil
}

// ListBackups lists available backup files in a directory
func (m *Manager) ListBackups(backupDir string) ([]BackupMetadata, error) {
	files, err := filepath.Glob(filepath.Join(backupDir, "*.backup"))
	if err != nil {
		return nil, fmt.Errorf("failed to list backup files: %w", err)
	}

	var backups []BackupMetadata
	for _, file := range files {
		metadata, err := m.getBackupMetadata(file)
		if err != nil {
			m.logger.WithField("file", file).WithError(err).Warn("Failed to read backup metadata")
			continue
		}
		backups = append(backups, *metadata)
	}

	return backups, nil
}

// getTableNames retrieves all table names from the database
func (m *Manager) getTableNames() ([]string, error) {
	rows, err := m.db.Query(`
		SELECT name FROM sqlite_master
		WHERE type='table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, err
		}
		tables = append(tables, tableName)
	}

	return tables, rows.Err()
}

// exportTableData exports all data from a specific table
func (m *Manager) exportTableData(tableName string) (*TableData, error) {
	// Get column information
	columns, err := m.getTableColumns(tableName)
	if err != nil {
		return nil, err
	}

	// Query all data from the table
	query := fmt.Sprintf("SELECT * FROM %s", tableName)
	rows, err := m.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Convert rows to map format
	var tableRows []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		tableRows = append(tableRows, row)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &TableData{
		Name:     tableName,
		Columns:  columns,
		Rows:     tableRows,
		RowCount: len(tableRows),
	}, nil
}

// getTableColumns gets column names for a table
func (m *Manager) getTableColumns(tableName string) ([]string, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	rows, err := m.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue interface{}

		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}

	return columns, rows.Err()
}

// writeBackupFile writes the backup data to a file
func (m *Manager) writeBackupFile(data BackupData, outputPath string, encrypt bool) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	var finalData []byte
	if encrypt {
		encrypted, err := common.EncryptSecret(string(jsonData))
		if err != nil {
			return fmt.Errorf("failed to encrypt backup: %w", err)
		}
		finalData = []byte(encrypted)
	} else {
		finalData = jsonData
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, finalData, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

// readBackupFile reads and parses a backup file
func (m *Manager) readBackupFile(backupPath string, encrypted bool) (*BackupData, error) {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file: %w", err)
	}

	var jsonData string
	if encrypted {
		jsonData, err = common.DecryptSecret(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt backup: %w", err)
		}
	} else {
		jsonData = string(data)
	}

	var backupData BackupData
	if err := json.Unmarshal([]byte(jsonData), &backupData); err != nil {
		return nil, fmt.Errorf("failed to parse backup data: %w", err)
	}

	return &backupData, nil
}

// validateBackupData validates the backup data structure
func (m *Manager) validateBackupData(data *BackupData) error {
	if data.Metadata.Version == "" {
		return fmt.Errorf("missing backup version")
	}
	if data.Metadata.TableCount != len(data.Tables) {
		return fmt.Errorf("table count mismatch: expected %d, got %d", data.Metadata.TableCount, len(data.Tables))
	}
	return nil
}

// restoreTableData restores data for a specific table
func (m *Manager) restoreTableData(tx *sql.Tx, tableData *TableData) error {
	// Clear existing data
	if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s", tableData.Name)); err != nil {
		return err
	}

	if len(tableData.Rows) == 0 {
		return nil
	}

	// Prepare INSERT statement
	placeholders := make([]string, len(tableData.Columns))
	args := make([]interface{}, len(tableData.Columns))

	for i := range placeholders {
		placeholders[i] = "?"
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		tableData.Name,
		fmt.Sprintf("%s", fmt.Sprintf("%s", fmt.Sprintf("%s", tableData.Columns))),
		fmt.Sprintf("%s", placeholders))

	// Fix the column formatting
	columnsStr := ""
	for i, col := range tableData.Columns {
		if i > 0 {
			columnsStr += ", "
		}
		columnsStr += col
	}

	placeholdersStr := ""
	for i := range tableData.Columns {
		if i > 0 {
			placeholdersStr += ", "
		}
		placeholdersStr += "?"
	}

	query = fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		tableData.Name, columnsStr, placeholdersStr)

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Insert all rows
	for _, row := range tableData.Rows {
		for i, col := range tableData.Columns {
			args[i] = row[col]
		}

		if _, err := stmt.Exec(args...); err != nil {
			return err
		}
	}

	return nil
}

// getBackupMetadata reads metadata from a backup file without full parsing
func (m *Manager) getBackupMetadata(backupPath string) (*BackupMetadata, error) {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, err
	}

	content := string(data)

	// If the file appears to be encrypted (doesn't start with '{'), we can't read metadata
	if len(content) == 0 || content[0] != '{' {
		return nil, fmt.Errorf("backup file appears to be encrypted or corrupted")
	}

	// Parse the full backup data structure
	var backupData BackupData
	if err := json.Unmarshal([]byte(content), &backupData); err != nil {
		return nil, fmt.Errorf("failed to parse backup file: %w", err)
	}

	return &backupData.Metadata, nil
}
