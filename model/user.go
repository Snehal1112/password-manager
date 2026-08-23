package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// User represents a user in the password manager.
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"user_name"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	Roles        []string  `json:"roles"`
	// AuthProvider is "local" for username/password/TOTP users, or an OIDC
	// provider identifier (e.g. "oidc") for externally-authenticated users.
	AuthProvider string `json:"auth_provider"`
	// ExternalIDPSubject is the external provider's stable subject (`sub`
	// claim) for externally-authenticated users, empty for local users.
	ExternalIDPSubject string    `json:"external_idp_subject,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

// Claims extends JWT claims with user-specific fields.
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Roles    []string  `json:"roles"`
	jwt.RegisteredClaims
}

// Role constants for RBAC.
const (
	RoleAdmin              = "admin"
	RoleUser               = "user"
	RoleSecretsManager     = "secrets_manager"
	RoleCryptoManager      = "crypto_manager"
	RoleCertificateManager = "certificate_manager"
	RoleServiceAccount     = "service_account"
)

// AuthProviderLocal identifies a username/password/TOTP user. This is the
// default and the only provider value that existed before OIDC support.
const AuthProviderLocal = "local"

// AuthProviderOIDC identifies a user authenticated via the configured OIDC
// provider.
const AuthProviderOIDC = "oidc"

// --- HTTP request/response types ---

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func CreateUserRequestFromJson(data io.Reader) (*CreateUserRequest, error) {
	var r CreateUserRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateUserRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
}

func UpdateUserRequestFromJson(data io.Reader) (*UpdateUserRequest, error) {
	var r UpdateUserRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UserResponse struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	CreatedAt  string `json:"created_at"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

func (r *UserResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
}

func (r *ListUsersResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

func LoginRequestFromJson(data io.Reader) (*LoginRequest, error) {
	var r LoginRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
}

func (r *LoginResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func RefreshTokenRequestFromJson(data io.Reader) (*RefreshTokenRequest, error) {
	var r RefreshTokenRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type RefreshTokenResponse struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (r *RefreshTokenResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
