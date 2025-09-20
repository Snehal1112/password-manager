// Package domain contains the core domain types and constants for the password manager.
// It defines the fundamental entities, value objects, and business rules that are central
// to the password management domain, following Domain-Driven Design principles.
package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// User represents a user in the Password Manager.
// It includes the user's ID, username, password hash, TOTP secret, role, and creation time.
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"user_name"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// Claims extends JWT claims with user-specific fields.
// It includes the user's ID, username, and role for use in authenticated requests.
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	jwt.RegisteredClaims
}

// Role constants define user roles for RBAC.
const (
	RoleAdmin              = "admin"
	RoleUser               = "user"
	RoleSecretsManager     = "secrets_manager"
	RoleCryptoManager      = "crypto_manager"
	RoleCertificateManager = "certificate_manager"
)