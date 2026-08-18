package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// Certificate represents an X.509 certificate in the password manager.
type Certificate struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	VaultID          uuid.UUID  `json:"vault_id"`
	KeyID            uuid.UUID  `json:"key_id" db:"key_id"`
	Name             string     `json:"name"`
	Certificate      string     `json:"certificate"`
	PrivateKey       string     `json:"private_key"`
	CreatedAt        time.Time  `json:"created_at"`
	Tags             []string   `json:"tags"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	AutoRenew        bool       `json:"auto_renew"`
	RenewalDays      int        `json:"renewal_days"`
	Enabled          bool       `json:"enabled"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
}

// IsAccessible returns true when the certificate is enabled and within its validity window.
func (c *Certificate) IsAccessible() bool {
	if !c.Enabled {
		return false
	}
	now := time.Now()
	if c.NotBefore != nil && now.Before(*c.NotBefore) {
		return false
	}
	if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
		return false
	}
	return true
}

// RevokedCertificate represents a revoked certificate in the CRL.
type RevokedCertificate struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	SerialNumber string
	Name         string
	RevokedAt    time.Time
}

// --- HTTP request/response types ---

type CreateCertificateRequest struct {
	Name         string     `json:"name"`
	KeyID        string     `json:"key_id"`
	ValidityDays int        `json:"validity_days"`
	Tags         []string   `json:"tags,omitempty"`
	AutoRenew    bool       `json:"auto_renew"`
	RenewalDays  int        `json:"renewal_days"`
	CAKeyID      string     `json:"ca_key_id,omitempty"`
	CACertID     string     `json:"ca_cert_id,omitempty"`
	Enabled      *bool      `json:"enabled,omitempty"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil leaves the stored default alone.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

func CreateCertificateRequestFromJson(data io.Reader) (*CreateCertificateRequest, error) {
	var r CreateCertificateRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateCertificateRequest struct {
	Name        *string    `json:"name,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	AutoRenew   *bool      `json:"auto_renew,omitempty"`
	RenewalDays *int       `json:"renewal_days,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
	// PurgeProtection is optional; nil means no change.
	PurgeProtection *bool `json:"purge_protection,omitempty"`
}

func UpdateCertificateRequestFromJson(data io.Reader) (*UpdateCertificateRequest, error) {
	var r UpdateCertificateRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type CertificateResponse struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	UserID      uuid.UUID  `json:"user_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Tags        []string   `json:"tags"`
	AutoRenew   bool       `json:"auto_renew"`
	RenewalDays int        `json:"renewal_days"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Enabled     bool       `json:"enabled"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

func (r *CertificateResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type CertificateListResponse struct {
	Certificates []CertificateResponse `json:"certificates"`
}

func (r *CertificateListResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
