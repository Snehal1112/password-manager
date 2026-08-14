package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// KeyRotationPolicy holds the per-key rotation policy, matching the shape of
// Azure Key Vault's GET/PUT /keys/{name}/rotationpolicy resource: how long
// after creation a key auto-rotates, how long before a version's expiry a
// notification fires, and how long each new version stays valid.
type KeyRotationPolicy struct {
	ID                     uuid.UUID `json:"id" db:"id"`
	KeyID                  uuid.UUID `json:"key_id" db:"key_id"`
	UserID                 uuid.UUID `json:"user_id" db:"user_id"`
	RotateAfterDays        int       `json:"rotate_after_days" db:"rotate_after_days"`
	NotifyBeforeExpiryDays int       `json:"notify_before_expiry_days" db:"notify_before_expiry_days"`
	ExpiryDays             int       `json:"expiry_days" db:"expiry_days"`
	Enabled                bool      `json:"enabled" db:"enabled"`
	CreatedAt              time.Time `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time `json:"updated_at" db:"updated_at"`
}

// UpsertKeyRotationPolicyRequest is the request body for creating or updating
// a key's rotation policy.
type UpsertKeyRotationPolicyRequest struct {
	RotateAfterDays        int  `json:"rotate_after_days"`
	NotifyBeforeExpiryDays int  `json:"notify_before_expiry_days"`
	ExpiryDays             int  `json:"expiry_days"`
	Enabled                bool `json:"enabled"`
}

// UpsertKeyRotationPolicyRequestFromJson decodes a request body into an upsert request.
func UpsertKeyRotationPolicyRequestFromJson(r io.Reader) (*UpsertKeyRotationPolicyRequest, error) {
	var req UpsertKeyRotationPolicyRequest
	return &req, json.NewDecoder(r).Decode(&req)
}
