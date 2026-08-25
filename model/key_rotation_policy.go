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
	ID                     uuid.UUID  `json:"id" db:"id"`
	KeyID                  uuid.UUID  `json:"key_id" db:"key_id"`
	UserID                 uuid.UUID  `json:"user_id" db:"user_id"`
	VaultID                uuid.UUID  `json:"vault_id" db:"vault_id"`
	RotateAfterDays        int        `json:"rotate_after_days" db:"rotate_after_days"`
	NotifyBeforeExpiryDays int        `json:"notify_before_expiry_days" db:"notify_before_expiry_days"`
	ExpiryDays             int        `json:"expiry_days" db:"expiry_days"`
	Enabled                bool       `json:"enabled" db:"enabled"`
	LastRotatedAt          *time.Time `json:"last_rotated_at,omitempty" db:"last_rotated_at"`
	NextRotationAt         time.Time  `json:"next_rotation_at" db:"next_rotation_at"`
	CreatedAt              time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at" db:"updated_at"`
}

// KeyRotationPolicyWithKeyName pairs a KeyRotationPolicy with its parent
// key's name, for report output (e.g. "keys rotation-policy list") where
// the raw key ID alone is not informative enough on its own.
type KeyRotationPolicyWithKeyName struct {
	KeyRotationPolicy
	KeyName string `json:"key_name"`
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
