// Package domain contains the core domain types and constants for secret management.
// It defines the fundamental entities, value objects, and business rules that are central
// to the secret management domain, following Domain-Driven Design principles.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// Secret represents a secret in the password manager.
// It includes the secret's ID, user ID, name, encrypted value, version, tags, and creation time.
type Secret struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

// SecretVersion represents a version of a secret for version history.
type SecretVersion struct {
	ID        uuid.UUID `json:"id"`
	SecretID  uuid.UUID `json:"secret_id"`
	UserID    uuid.UUID `json:"user_id"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

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
	Format      ExportFormat `json:"format"`
	IncludeTags bool         `json:"include_tags"`
	FilterTags  []string     `json:"filter_tags,omitempty"`
	Encrypt     bool         `json:"encrypt"`
	UserID      uuid.UUID    `json:"user_id"`
	ExportedAt  time.Time    `json:"exported_at"`
	ExportedBy  string       `json:"exported_by"`
}

// ImportOptions contains options for importing secrets.
type ImportOptions struct {
	Format            ExportFormat `json:"format"`
	OverwriteExisting bool         `json:"overwrite_existing"`
	Encrypted         bool         `json:"encrypted"`
	UserID            uuid.UUID    `json:"user_id"`
	ImportedBy        string       `json:"imported_by"`
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
