package domain

import (
	"time"

	"github.com/google/uuid"
)

// Session represents a user session with refresh token capability.
// It tracks device information, session metadata, and security attributes
// for comprehensive session management and audit trails.
type Session struct {
	ID               uuid.UUID  // Unique session identifier
	UserID           uuid.UUID  // Reference to the user
	RefreshTokenHash string     // Hashed refresh token for security
	DeviceInfo       string     // JSON string with device details
	IPAddress        string     // Client IP address
	UserAgent        string     // Client user agent
	ExpiresAt        time.Time  // Session expiration time
	LastUsedAt       time.Time  // Last activity timestamp
	CreatedAt        time.Time  // Session creation time
	Revoked          bool       // Whether session is revoked
	RevokedAt        *time.Time // Revocation timestamp (nullable)
	RevokedReason    string     // Reason for revocation
}

// SessionInfo contains device and client information for session tracking.
// This provides structured device metadata for security and user experience.
type SessionInfo struct {
	DeviceName string `json:"device_name,omitempty"`
	DeviceType string `json:"device_type,omitempty"` // mobile, desktop, tablet
	OS         string `json:"os,omitempty"`
	Browser    string `json:"browser,omitempty"`
	AppVersion string `json:"app_version,omitempty"`
}

// RefreshTokenRequest represents the request to refresh an access token.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenResponse represents the response from a token refresh operation.
type RefreshTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// SessionListResponse represents the response for listing user sessions.
type SessionListResponse struct {
	Sessions []SessionInfoResponse `json:"sessions"`
	Total    int                   `json:"total"`
}

// SessionInfoResponse represents session information for API responses.
type SessionInfoResponse struct {
	ID         string    `json:"id"`
	DeviceInfo string    `json:"device_info"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	CreatedAt  time.Time `json:"created_at"`
	Revoked    bool      `json:"revoked"`
}

// RevokeSessionRequest represents a request to revoke a session.
type RevokeSessionRequest struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason,omitempty"`
}

// SessionConfig contains configuration for session management.
type SessionConfig struct {
	AccessTokenExpiry  time.Duration // Access token lifetime
	RefreshTokenExpiry time.Duration // Refresh token lifetime
	MaxSessions        int           // Maximum concurrent sessions per user
	EnableRotation     bool          // Enable refresh token rotation
}

// DefaultSessionConfig returns default session configuration.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		AccessTokenExpiry:  30 * time.Minute,  // 30 minutes
		RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		MaxSessions:        5,                  // 5 concurrent sessions
		EnableRotation:     true,               // Enable rotation by default
	}
}