package domain

import (
"time"

"github.com/google/uuid"
)

// OAuth2Client represents a machine-to-machine authentication client.
// It implements the RFC 6749 §4.4 client credentials grant type.
// The ClientSecret field holds a bcrypt hash when stored in the database;
// it contains the plain-text secret only on creation or rotation responses.
type OAuth2Client struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	ClientSecret string     `json:"client_secret,omitempty"`
	Description  string     `json:"description"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}
