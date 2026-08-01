package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// Secret represents a secret in the password manager.
type Secret struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	VaultID          uuid.UUID  `json:"vault_id"`
	Name             string     `json:"name"`
	Value            string     `json:"value"`
	Version          int        `json:"version"`
	Tags             []string   `json:"tags"`
	CreatedAt        time.Time  `json:"created_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	Enabled          bool       `json:"enabled"`
	ContentType      string     `json:"content_type,omitempty"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
}

func (s *Secret) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

func (s *Secret) IsActive() bool {
	if s.NotBefore == nil {
		return true
	}
	return time.Now().After(*s.NotBefore)
}

// IsAccessible reports whether the secret may be served. A soft-deleted
// secret never is: the SQL read path filters deleted_at IS NULL, and the
// cache hit path relies on this check alone, so omitting DeletedAt here would
// let a vault-delete cascade leave a still-servable cached copy behind.
func (s *Secret) IsAccessible() bool {
	return s.DeletedAt == nil && s.Enabled && s.IsActive() && !s.IsExpired()
}

func (s *Secret) DaysUntilExpiration() int {
	if s.ExpiresAt == nil {
		return -1
	}
	if s.IsExpired() {
		return 0
	}
	return int(time.Until(*s.ExpiresAt).Hours() / 24)
}

// SecretVersion represents a version of a secret.
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
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
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

// ExportContainer is the complete export structure.
type ExportContainer struct {
	Metadata ExportOptions    `json:"metadata"`
	Secrets  []ExportedSecret `json:"secrets"`
}

// --- HTTP request/response types ---

type CreateSecretRequest struct {
	Name        string     `json:"name"`
	Value       string     `json:"value"`
	Tags        []string   `json:"tags,omitempty"`
	ContentType string     `json:"content_type,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

func CreateSecretRequestFromJson(data io.Reader) (*CreateSecretRequest, error) {
	var r CreateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateSecretRequest struct {
	Name        string     `json:"name,omitempty"`
	Value       string     `json:"value,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	ContentType *string    `json:"content_type,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

func UpdateSecretRequestFromJson(data io.Reader) (*UpdateSecretRequest, error) {
	var r UpdateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type GenerateSecretRequest struct {
	Length       int    `json:"length,omitempty"`
	UseSymbols   bool   `json:"use_symbols,omitempty"`
	UseNumbers   bool   `json:"use_numbers,omitempty"`
	UseUppercase bool   `json:"use_uppercase,omitempty"`
	UseLowercase bool   `json:"use_lowercase,omitempty"`
	Name         string `json:"name"`
}

func GenerateSecretRequestFromJson(data io.Reader) (*GenerateSecretRequest, error) {
	var r GenerateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type ExportSecretsRequest struct {
	Format      string   `json:"format"`
	Encrypt     bool     `json:"encrypt"`
	Tags        []string `json:"tags"`
	IncludeTags bool     `json:"include_tags"`
}

func ExportSecretsRequestFromJson(data io.Reader) (*ExportSecretsRequest, error) {
	var r ExportSecretsRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type SecretResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Value       string     `json:"value,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	Version     int        `json:"version"`
	ContentType string     `json:"content_type,omitempty"`
	CreatedAt   string     `json:"created_at"`
	UpdatedAt   string     `json:"updated_at,omitempty"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

func (r *SecretResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListSecretsResponse struct {
	Secrets []SecretResponse `json:"secrets"`
	Total   int              `json:"total"`
}

func (r *ListSecretsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ExportResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Count      int    `json:"count"`
	Format     string `json:"format"`
	Encrypted  bool   `json:"encrypted"`
	ExportedAt string `json:"exported_at"`
}

func (r *ExportResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ImportResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	ImportedCount int    `json:"imported_count"`
	TotalCount    int    `json:"total_count"`
	Format        string `json:"format"`
	ImportedAt    string `json:"imported_at"`
}

func (r *ImportResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
