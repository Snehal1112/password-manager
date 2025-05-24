// Package auth manages user authentication and authorization for the password manager.
// It provides functions for JWT-based authentication, TOTP MFA, and RBAC checks,
// using Go Generics for type-safe user and claims structures.
package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"password-manager/common"
	"password-manager/internal/db"
	"password-manager/internal/logging"
)

// User represents a user in the Password Manager.
// It includes the user’s ID, username, password hash, TOTP secret, role, and creation time.
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"user_name"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// Claims extends JWT claims with user-specific fields.
// It includes the user’s ID, username, and role for use in authenticated requests.
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	jwt.RegisteredClaims
}

// Role constants define user roles for RBAC.
const (
	RoleSecretsManager     = "secrets_manager"
	RoleCryptoManager      = "crypto_manager"
	RoleCertificateManager = "certificate_manager"
)

// UserRepository is a generic repository interface for user operations.
// It provides type-safe CRUD operations for the User type.
type UserRepository interface {
	db.Repository[User]
	Login(ctx context.Context, username, password, totpCode string) (string, error)
}

// userRepository implements UserRepository for database operations on users.
type userRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewUserRepository creates a new UserRepository with the given database connection.
// It initializes the repository for user-related database operations.
//
// Parameters:
//
//	db: The database connection.
//
// Returns:
//
//	A UserRepository for user operations.
func NewUserRepository(db *sql.DB, log *logging.Logger) UserRepository {
	return &userRepository{db: db, log: log}
}

// Create creates a new user in the database.
// It hashes the password, generates a TOTP secret and UUID for the ID,
// and stores the user with the specified role.
// The TOTP secret is returned for user setup.
//
// Parameters:
// - ctx: The context for the database operation.
// - user: The user to create, with Username, PasswordHash (raw password), and Role.
//
// Returns: The TOTP secret and an error if the operation fails.
func (r *userRepository) Create(ctx context.Context, user *User) error {
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"role":     user.Role,
	}).Info("Creating user")

	hashedPassword, err := common.HashString(user.PasswordHash)
	if err != nil {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to hash password", err)
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Check if the username already exists.
	var existingUserID string
	err = r.db.QueryRowContext(ctx, "SELECT id FROM users WHERE username = ?", user.Username).Scan(&existingUserID)
	if err == nil {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Username already exists", nil)
		return fmt.Errorf("username already exists")
	}

	totpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "PasswordManager",
		AccountName: user.Username,
		SecretSize:  20,
	})

	if err != nil {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to generate TOTP secret", err)
		return fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// If the user already exists, return an error.
	userID := uuid.New()
	_, err = r.db.ExecContext(
		ctx,
		"INSERT INTO users (id, username, password_hash, totp_secret, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		userID.String(), user.Username, string(hashedPassword), totpKey.Secret(), user.Role, time.Now(),
	)

	// Check for errors during insertion.
	if err != nil {
		r.log.LogAuditError(userID.String(), "create_user", "failed", "Failed to create user", err)
		return fmt.Errorf("failed to create user: %w", err)
	}

	user.TOTPSecret = totpKey.URL()

	r.log.LogAuditInfo(userID.String(), "create_user", "success", fmt.Sprintf("User created: %s", user.Username))
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"role":     user.Role,
		"user_id":  userID.String(),
	}).Info("User created successfully")

	return nil
}

// Read retrieves a user by ID from the database.
// It fetches the user’s ID, username, and role.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The user’s ID.
//
// Returns:
//
//	The user and an error if the retrieval fails.
func (r *userRepository) Read(ctx context.Context, id uuid.UUID) (*User, error) {
	var user User
	err := r.db.QueryRowContext(ctx, "SELECT id, username, role FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Role)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	return &user, nil
}

// Update updates a user in the database.
// It is not implemented as user updates are handled by specific functions.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	user: The user to update.
//
// Returns:
//
//	An error indicating the operation is not supported.
func (r *userRepository) Update(ctx context.Context, user *User) error {
	return fmt.Errorf("user updates not supported")
}

// Delete deletes a user by ID from the database.
// It is not implemented as user deletion is restricted.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The user’s ID.
//
// Returns:
//
//	An error indicating the operation is not supported.
func (r *userRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return fmt.Errorf("user deletion not supported")
}

// Login authenticates a user with username, password, and TOTP code.
// It verifies credentials and issues a JWT token for authenticated requests.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	username: The user’s username.
//	password: The user’s plaintext password.
//	totpCode: The TOTP code from the user’s MFA app.
//
// Returns:
//
//	A JWT token string and an error if authentication fails.
//
// The function is used by the /login endpoint to authenticate users and issue tokens.
func (r *userRepository) Login(ctx context.Context, username, password, totpCode string) (string, error) {
	// Retrieve user data from the database.
	var user User
	var hashedPassword, totpSecret string
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, role, totp_secret FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &hashedPassword, &user.Role, &totpSecret)
	if err == sql.ErrNoRows {
		logrus.Warn("User not found: ", username)
		return "", fmt.Errorf("invalid credentials")
	}
	if err != nil {
		logrus.Error("Failed to query user: ", err)
		return "", fmt.Errorf("failed to query user: %w", err)
	}

	if err := common.CheckPassword(password, hashedPassword); err != nil {
		logrus.Warn("Invalid password for user: ", username)
		return "", fmt.Errorf("invalid credentials")
	}

	// Verify the TOTP code with custom options for tolerance.
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      2,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}

	valid, err := totp.ValidateCustom(totpCode, totpSecret, time.Now(), opts)
	if err != nil {
		logrus.Error("TOTP validation error: ", err)
		return "", fmt.Errorf("TOTP validation error: %w", err)
	}
	if !valid {
		logrus.WithFields(logrus.Fields{
			"username":  username,
			"totp_code": totpCode,
		}).Warn("Invalid TOTP code")
		return "", fmt.Errorf("invalid TOTP code")
	}

	// Retrieve the JWT secret from configuration.
	jwtSecret := viper.GetString("jwt_secret")
	if jwtSecret == "" {
		logrus.Error("JWT secret not configured")
		return "", fmt.Errorf("JWT secret not configured")
	}

	// Generate a JWT token with user claims.
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Audience:  jwt.ClaimStrings{"PASSWORD_MANAGER"},
			Subject:   user.ID.String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		logrus.Error("Failed to generate JWT: ", err)
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"username": username,
		"user_id":  user.ID,
	}).Info("User logged in successfully")
	return tokenString, nil
}

// GenerateTOTPCode generates a TOTP code for testing purposes.
// It is a helper function to create valid TOTP codes for a given secret and time.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, t, totp.ValidateOpts{
		Period:    30,
		Skew:      2,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// ParseJWT parses a JWT token string into Claims.
// It validates the token’s signature using the jwt_secret from configuration.
//
// Parameters:
//
//	tokenString: The JWT token string.
//
// Returns:
//
//	The parsed Claims and an error if parsing or validation fails.
func ParseJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}

	// Parse the JWT token and validate its claims.
	// Use jwt.ParseWithClaims to parse the token and validate the claims.
	// The claims struct should match the structure of the JWT claims.
	// The function will return an error if the token is invalid or expired.
	// The claims struct should include the user ID and role.
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		logrus.WithFields(logrus.Fields{
			"token": tokenString,
		}).Info("Validating JWT token")

		// Validate the token signing method.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logrus.Warn("Unexpected signing method: ", token.Header["alg"])
			return nil, jwt.ErrSignatureInvalid
		}

		// Retrieve the JWT secret from the configuration.
		var jwtSecret = viper.GetString("jwt_secret")
		if jwtSecret == "" {
			logrus.Error("JWT secret is not set")
			return nil, jwt.ErrInvalidKey
		}

		// Validate the token expiration.
		if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
			logrus.Error("Token has expired")
			return nil, jwt.ErrTokenExpired
		}

		return []byte(viper.GetString("jwt_secret")), nil
	})

	if err != nil {
		logrus.Error("Invalid JWT token: ", err)
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	if !token.Valid {
		logrus.Error("Invalid JWT: token is invalid")
		return nil, fmt.Errorf("invalid JWT: token is invalid")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		logrus.Error("Invalid JWT claims")
		return nil, fmt.Errorf("invalid JWT claims")
	}

	return claims, nil
}
