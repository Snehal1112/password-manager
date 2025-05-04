// Package auth manages user authentication and authorization for the password manager.
// It provides functions to register users, authenticate login attempts with JWT and TOTP MFA,
// and define roles for RBAC, ensuring secure access to secrets, keys, and certificates.
package auth

import (
	"database/sql"
	"errors"
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

// Register creates a new user with a hashed password and TOTP secret.
// It stores the user in the database and returns a TOTP URL for MFA setup.
//
// Parameters:
//
//	username: The user’s chosen username.
//	password: The user’s plaintext password.
//	role: The user’s role (e.g., SecretsManager, CryptoManager, CertificateManager).
//
// Returns:
//
//	A TOTP URL for MFA setup and an error if registration fails.
//
// The function is used to onboard new users, enabling them to log in with MFA.
func Register(username, password, role string) (string, error) {
	// Hash the password using bcrypt for secure storage.
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

	// Insert the user into the database with hashed password and TOTP secret.
	result, err := db.DB.Exec(
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
	return key.URL(), nil // Return TOTP URL for user to scan with an MFA app
}

// Login authenticates a user with username, password, and TOTP code.
// It verifies credentials and issues a JWT token for authenticated requests.
//
// Parameters:
//
//	username: The user’s username.
//	password: The user’s plaintext password.
//	totpCode: The TOTP code from the user’s MFA app.
//
// Returns:
//
//	A JWT token string and an error if authentication fails.
//
// The function is used by the /login endpoint to authenticate users and issue tokens.
func Login(username, password, totpCode string) (string, error) {
	// Retrieve user data from the database.
	var user User
	var hashedPassword, totpSecret string
	err := db.DB.QueryRow(
		"SELECT id, username, password_hash, role, totp_secret FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &hashedPassword, &user.Role, &totpSecret)
	if err == sql.ErrNoRows {
		logrus.Warn("User not found: ", username)
		return "", errors.New("invalid credentials")
	} else if err != nil {
		logrus.Error("Failed to query user: ", err)
		return "", fmt.Errorf("failed to query user: %w", err)
	}

	// Verify the password using bcrypt.
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		logrus.Warn("Invalid password for user: ", username)
		return "", errors.New("invalid credentials")
	}

	// Verify the TOTP code with custom options for increased tolerance.
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      2, // Allow 2 steps (60 seconds) before/after
		Digits:    6,
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
		return "", errors.New("invalid TOTP code")
	}

	// Retrieve the JWT secret from configuration.
	jwtSecret := viper.GetString("auth.jwt_secret")
	if jwtSecret == "" {
		logrus.Error("JWT secret not configured")
		return "", errors.New("JWT secret not configured")
	}

	// Generate a JWT token with user claims.
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
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
		"username": username,
		"user_id":  user.ID,
	}).Info("User logged in successfully")
	return tokenString, nil
}
