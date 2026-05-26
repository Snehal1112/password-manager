package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// CertificatePolicy holds the creation and renewal policy for a certificate.
type CertificatePolicy struct {
	ID               uuid.UUID `json:"id" db:"id"`
	CertificateID    uuid.UUID `json:"certificate_id" db:"certificate_id"`
	UserID           uuid.UUID `json:"user_id" db:"user_id"`
	ValidityMonths   int       `json:"validity_months" db:"validity_months"`
	KeyType          string    `json:"key_type" db:"key_type"`
	KeySize          int       `json:"key_size,omitempty" db:"key_size"`
	Curve            string    `json:"curve,omitempty" db:"curve"`
	Subject          string    `json:"subject" db:"subject"`
	SANs             string    `json:"sans,omitempty" db:"sans"`
	AutoRenew        bool      `json:"auto_renew" db:"auto_renew"`
	DaysBeforeExpiry int       `json:"days_before_expiry" db:"days_before_expiry"`
	IssuerName       string    `json:"issuer_name,omitempty" db:"issuer_name"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// UpsertCertificatePolicyRequest is the request body for creating or updating a policy.
type UpsertCertificatePolicyRequest struct {
	ValidityMonths   int    `json:"validity_months"`
	KeyType          string `json:"key_type"`
	KeySize          int    `json:"key_size,omitempty"`
	Curve            string `json:"curve,omitempty"`
	Subject          string `json:"subject"`
	SANs             string `json:"sans,omitempty"`
	AutoRenew        bool   `json:"auto_renew"`
	DaysBeforeExpiry int    `json:"days_before_expiry"`
	IssuerName       string `json:"issuer_name,omitempty"`
}

// UpsertCertificatePolicyRequestFromJson decodes a request body into an upsert request.
func UpsertCertificatePolicyRequestFromJson(r io.Reader) (*UpsertCertificatePolicyRequest, error) {
	var req UpsertCertificatePolicyRequest
	return &req, json.NewDecoder(r).Decode(&req)
}
