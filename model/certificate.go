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
	Name         string   `json:"name"`
	KeyID        string   `json:"key_id"`
	ValidityDays int      `json:"validity_days"`
	Tags         []string `json:"tags,omitempty"`
	AutoRenew    bool     `json:"auto_renew"`
	RenewalDays  int      `json:"renewal_days"`
	CAKeyID      string   `json:"ca_key_id,omitempty"`
	CACertID     string   `json:"ca_cert_id,omitempty"`
}

func CreateCertificateRequestFromJson(data io.Reader) (*CreateCertificateRequest, error) {
	var r CreateCertificateRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateCertificateRequest struct {
	Name        *string  `json:"name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	AutoRenew   *bool    `json:"auto_renew,omitempty"`
	RenewalDays *int     `json:"renewal_days,omitempty"`
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
