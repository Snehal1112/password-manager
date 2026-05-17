package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Session represents a user session with refresh token capability.
type Session struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	RefreshTokenHash string     `json:"refresh_token_hash"`
	DeviceInfo       string     `json:"device_info"`
	IPAddress        string     `json:"ip_address"`
	UserAgent        string     `json:"user_agent"`
	ExpiresAt        time.Time  `json:"expires_at"`
	LastUsedAt       time.Time  `json:"last_used_at"`
	CreatedAt        time.Time  `json:"created_at"`
	Revoked          bool       `json:"revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedReason    string     `json:"revoked_reason,omitempty"`
}

// SessionInfo contains structured device metadata.
type SessionInfo struct {
	DeviceName string `json:"device_name,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
	OS         string `json:"os,omitempty"`
	Browser    string `json:"browser,omitempty"`
	AppVersion string `json:"app_version,omitempty"`
}

// SessionConfig contains configuration for session management.
type SessionConfig struct {
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	MaxSessions        int
	EnableRotation     bool
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		AccessTokenExpiry:  30 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		MaxSessions:        5,
		EnableRotation:     true,
	}
}

type SessionResponse struct {
	ID         string    `json:"id"`
	DeviceInfo string    `json:"device_info"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	CreatedAt  time.Time `json:"created_at"`
	Revoked    bool      `json:"revoked"`
}

func (r *SessionResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListSessionsResponse struct {
	Sessions []SessionResponse `json:"sessions"`
	Total    int               `json:"total"`
}

func (r *ListSessionsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
