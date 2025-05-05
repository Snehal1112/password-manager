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
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"github.com/snehal1112/password-manager/internal/db"
)

// User represents a user in the password manager.
// It stores the user’s ID, username, and role for authentication and authorization.
type User struct {
	ID       int
	Username string
	Role     string
}

// Claims extends JWT claims with user-specific fields.
// It includes the user’s ID, username, and role for use in authenticated requests.
type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Role constants define user roles for RBAC.
const (
	RoleSecretsManager     = "SecretsManager"
	RoleCryptoManager      = "CryptoManager"
	RoleCertificateManager = "CertificateManager"
)

// UserRepository is a generic repository interface for user operations.
// It provides type-safe CRUD operations for the User type.
type UserRepository interface {
	db.Repository[User]
}

// userRepository implements UserRepository for database operations on users.
type userRepository struct {
	db *sql.DB
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
func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepository{db: db}
}

// Create inserts a new user into the database.
// It stores the user’s username, password hash, TOTP secret, and role.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	user: The user to create.
//
// Returns:
//
//	An error if the insertion fails.
func (r *userRepository) Create(ctx context.Context, user User) error {
	// This is a placeholder; actual user creation is handled by Register.
	return fmt.Errorf("use Register function for user creation")
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
func (r *userRepository) Read(ctx context.Context, id int) (User, error) {
	var user User
	err := r.db.QueryRowContext(ctx, "SELECT id, username, role FROM users WHERE id = ?", id).
		Scan(&user.ID, &user.Username, &user.Role)
	if err == sql.ErrNoRows {
		return user, fmt.Errorf("user not found")
	}
	if err != nil {
		return user, fmt.Errorf("failed to query user: %w", err)
	}
	return user, nil
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
func (r *userRepository) Update(ctx context.Context, user User) error {
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
func (r *userRepository) Delete(ctx context.Context, id int) error {
	return fmt.Errorf("user deletion not supported")
}

// Register creates a new user with a hashed password and TOTP secret.
// It stores the user in the database and returns a TOTP URL for MFA setup.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	username: The user’s chosen username.
//	password: The user’s plaintext password.
//	role: The user’s role (e.g., SecretsManager, CryptoManager, CertificateManager).
//
// Returns:
//
//	A TOTP URL for MFA setup and an error if registration fails.
//
// The function is used to onboard new users, enabling them to log in with MFA.
func Register(ctx context.Context, username, password, role string) (string, error) {
	// Hash the password using bcrypt.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logrus.Error("Failed to hash password: ", err)
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate a TOTP secret for MFA.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "PasswordManager",
		AccountName: username,
	})
	if err != nil {
		logrus.Error("Failed to generate TOTP key: ", err)
		return "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Insert the user into the database.
	result, err := db.DB.ExecContext(
		ctx,
		"INSERT INTO users (username, password_hash, role, totp_secret) VALUES (?, ?, ?, ?)",
		username, string(hashedPassword), role, key.Secret(),
	)
	if err != nil {
		logrus.Error("Failed to register user: ", err)
		return "", fmt.Errorf("failed to register user: %w", err)
	}

	// Retrieve the new user’s ID.
	userID, _ := result.LastInsertId()

	logrus.WithFields(logrus.Fields{
		"username": username,
		"user_id":  userID,
	}).Info("User registered successfully")
	return key.URL(), nil
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
func Login(ctx context.Context, username, password, totpCode string) (string, error) {
	// Retrieve user data from the database.
	var user User
	var hashedPassword, totpSecret string
	err := db.DB.QueryRowContext(
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

	// Verify the password using bcrypt.
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
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
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		logrus.Error("Failed to generate JWT: ", err)
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"username": "snehal1112",
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
	var claims Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(viper.GetString("jwt_secret")), nil
	})
	if err != nil {
		logrus.Warn("Invalid JWT token: ", err)
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}
	if !token.Valid {
		logrus.Warn("Invalid JWT claims")
		return nil, fmt.Errorf("invalid JWT claims")
	}

	return &claims, nil
}
