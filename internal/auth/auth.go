package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// User represents an authenticated user.
type User struct {
	ID           string // Exported
	Username     string // Exported
	PasswordHash string // Exported
	TOTPSecret   string // Exported
}

// Claims defines JWT claims for the user.
type Claims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

// NewUser creates a new user with hashed password and TOTP secret.
// It generates a bcrypt hash for the password and a TOTP secret for MFA.
//
// Parameters:
//
//	username: The user's unique username (e.g., "john_doe").
//	password: The plaintext password to hash.
//	userID: A unique identifier for the user (e.g., UUID "123e4567-e89b-12d3-a456-426614174000").
//
// Returns:
//
//	A pointer to the User struct and an error if hashing or TOTP generation fails.
//
// The function is used to register new users securely.
func NewUser(username, password, userID string) (*User, error) {
	if username == "" || password == "" || userID == "" {
		logrus.WithFields(logrus.Fields{"user_id": userID, "username": username}).Error("Username, password, or userID is empty")
		return nil, errors.New("username, password, and userID cannot be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"user_id": userID}).Error("Hashing password")
		return nil, fmt.Errorf("hashing password: %w", err)
	}
	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "PasswordManager",
		AccountName: username,
	})
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"user_id": userID}).Error("Generating TOTP secret")
		return nil, fmt.Errorf("generating TOTP secret: %w", err)
	}
	user := &User{
		ID:           userID,
		Username:     username,
		PasswordHash: string(hash),
		TOTPSecret:   totpSecret.Secret(),
	}
	logrus.WithFields(logrus.Fields{"user_id": userID, "username": username}).Info("User created")
	return user, nil
}

// Authenticate verifies user credentials.
// It checks the password hash and TOTP code for validity.
//
// Parameters:
//
//	password: The plaintext password to verify.
//	totpCode: The TOTP code provided by the user (e.g., "123456").
//
// Returns:
//
//	An error if authentication fails (wrong password or TOTP code).
//
// The function is used to authenticate users during login.
func (u *User) Authenticate(password, totpCode string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		logrus.WithFields(logrus.Fields{"user_id": u.ID, "username": u.Username}).Warn("Invalid password")
		return fmt.Errorf("invalid password: %w", err)
	}
	valid := totp.Validate(totpCode, u.TOTPSecret)
	if !valid {
		logrus.WithFields(logrus.Fields{"user_id": u.ID, "username": u.Username}).Warn("Invalid TOTP code")
		return errors.New("invalid TOTP code")
	}
	logrus.WithFields(logrus.Fields{"user_id": u.ID, "username": u.Username}).Info("User authenticated")
	return nil
}

// GenerateJWT issues a JWT token for the user.
// It creates a token with the user ID and a configurable expiration time.
//
// Parameters:
//
//	secretKey: The JWT signing key (e.g., a 32-byte secret).
//	ttl: The token's time-to-live duration (e.g., 24 * time.Hour).
//
// Returns:
//
//	The signed JWT token string and an error if token generation fails.
//
// The function is used to issue tokens for authenticated sessions.
func (u *User) GenerateJWT(secretKey string, ttl time.Duration) (string, error) {
	claims := &Claims{
		UserID: u.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ttl).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"user_id": u.ID}).Error("Generating JWT")
		return "", fmt.Errorf("generating JWT: %w", err)
	}
	logrus.WithFields(logrus.Fields{"user_id": u.ID}).Info("JWT generated")
	return signedToken, nil
}
