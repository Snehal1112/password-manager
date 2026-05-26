package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// Key represents a cryptographic key in the password manager.
type Key struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	Value            string     `json:"value"`
	Revoked          bool       `json:"revoked"`
	CreatedAt        time.Time  `json:"created_at"`
	Tags             []string   `json:"tags"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
}

const (
	KeyTypeRSA    = "RSA"
	KeyTypeECDSA  = "ECDSA"
	KeyTypeES256K = "ES256K" // secp256k1 ECDSA
	KeyTypeOct    = "oct"    // Symmetric key (HMAC / AES)
)

// --- HTTP request/response types ---

type CreateKeyRequest struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Bits  int      `json:"bits"`
	Curve string   `json:"curve"`
	Tags  []string `json:"tags"`
}

func CreateKeyRequestFromJson(data io.Reader) (*CreateKeyRequest, error) {
	var r CreateKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateKeyRequest struct {
	Name    *string  `json:"name,omitempty"`
	Revoked *bool    `json:"revoked,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

func UpdateKeyRequestFromJson(data io.Reader) (*UpdateKeyRequest, error) {
	var r UpdateKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type KeyResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	UserID    uuid.UUID `json:"user_id"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	Tags      []string  `json:"tags"`
}

func (r *KeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type KeyListResponse struct {
	Keys []KeyResponse `json:"keys"`
}

func (r *KeyListResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type WrapKeyRequest struct {
	PlaintextKey string `json:"plaintext_key"`
	Algorithm    string `json:"algorithm"`
}

func WrapKeyRequestFromJson(data io.Reader) (*WrapKeyRequest, error) {
	var r WrapKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type WrapKeyResponse struct {
	WrappedKey string `json:"wrapped_key"`
	Algorithm  string `json:"algorithm"`
}

func (r *WrapKeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type UnwrapKeyRequest struct {
	WrappedKey string `json:"wrapped_key"`
	Algorithm  string `json:"algorithm"`
}

func UnwrapKeyRequestFromJson(data io.Reader) (*UnwrapKeyRequest, error) {
	var r UnwrapKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"`
	Algorithm    string `json:"algorithm"`
}

func (r *UnwrapKeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
