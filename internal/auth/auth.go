package auth

import (
	"errors"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user entity.
// It includes authentication credentials and metadata.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	CreatedAt    time.Time `json:"created_at"`
}

// NewUser creates a new user with the provided credentials.
// It hashes the password and generates a TOTP secret.
//
// Parameters:
//
//	username: The user's username.
//	password: The user's plaintext password.
//	id: The unique identifier for the user.
//
// Returns:
//
//	A pointer to the created User and an error if creation fails.
//
// The function is used to initialize a new user entity.
func NewUser(username, password, id string) (*User, error) {
	if username == "" || password == "" || id == "" {
		err := errors.New("username, password, and id must not be empty")
		logrus.WithFields(logrus.Fields{
			"username": username,
			"id":       id,
		}).Error(err)
		return nil, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logrus.WithError(err).Error("hashing password")
		return nil, err
	}

	totpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "PasswordManager",
		AccountName: username,
	})
	if err != nil {
		logrus.WithError(err).Error("generating TOTP secret")
		return nil, err
	}

	user := &User{
		ID:           id,
		Username:     username,
		PasswordHash: string(passwordHash),
		TOTPSecret:   totpSecret.Secret(),
		CreatedAt:    time.Now(),
	}

	logrus.WithFields(logrus.Fields{
		"user_id":  id,
		"username": username,
	}).Info("User created")
	logrus.WithFields(logrus.Fields{
		"user_id":     id,
		"totp_secret": totpSecret.Secret(),
	}).Debug("TOTP secret generated")

	return user, nil
}

// Authenticate verifies the user's credentials.
// It checks the password and TOTP code.
//
// Parameters:
//
//	password: The plaintext password to verify.
//	totpCode: The TOTP code to verify.
//
// Returns:
//
//	An error if authentication fails.
//
// The function is used to validate user credentials.
func (u *User) Authenticate(password, totpCode string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		logrus.WithFields(logrus.Fields{
			"user_id":  u.ID,
			"username": u.Username,
		}).Warn("Invalid password")
		logrus.WithError(err).Error("invalid password")
		return err
	}

	log.Println("totpCode", totpCode)
	log.Println("u.TOTPSecret", u.TOTPSecret)
	valid := totp.Validate(totpCode, u.TOTPSecret)
	if !valid {
		err := errors.New("invalid TOTP code")
		logrus.WithFields(logrus.Fields{
			"user_id":  u.ID,
			"username": u.Username,
		}).Error(err)
		return err
	}

	logrus.WithFields(logrus.Fields{
		"user_id":  u.ID,
		"username": u.Username,
	}).Info("User authenticated")
	return nil
}

// GenerateJWT creates a JWT for the user.
// It includes the user ID and expiration time.
//
// Parameters:
//
//	secret: The secret key for signing the JWT.
//	ttl: The duration until the token expires.
//
// Returns:
//
//	The JWT string and an error if generation fails.
//
// The function is used to issue authentication tokens.
func (u *User) GenerateJWT(secret string, ttl time.Duration) (string, error) {
	if secret == "" {
		logrus.Error("JWT secret is empty")
		return "", errors.New("JWT secret is empty")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": u.ID,
		"exp":     time.Now().Add(ttl).Unix(),
		"iat":     time.Now().Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"user_id": u.ID,
		}).Error("Generating JWT")
		logrus.WithError(err).Error("generating JWT")
		return "", err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": u.ID,
	}).Debug("JWT generated")
	return tokenString, nil
}
