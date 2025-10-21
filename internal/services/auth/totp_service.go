package auth

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPService handles Time-based One-Time Password operations.
// It provides TOTP generation, validation, and key management
// for multi-factor authentication.
type TOTPService interface {
	GenerateSecret(issuer, accountName string) (*otp.Key, error)
	ValidateCode(code, secret string, currentTime time.Time) (bool, error)
	GenerateCode(secret string, currentTime time.Time) (string, error)
}

// totpService implements TOTPService for TOTP operations.
type totpService struct {
	// TOTP configuration options
	period    uint
	skew      uint
	digits    otp.Digits
	algorithm otp.Algorithm
}

// NewTOTPService creates a new TOTPService with default TOTP parameters.
// It configures the service with standard TOTP settings:
// - 30 second period
// - 2 step skew tolerance
// - 6 digits
// - SHA1 algorithm
//
// Returns:
//
//	A TOTPService implementation for TOTP operations.
func NewTOTPService() TOTPService {
	return &totpService{
		period:    30,
		skew:      2,
		digits:    otp.DigitsSix,
		algorithm: otp.AlgorithmSHA1,
	}
}

// GenerateSecret creates a new TOTP secret key for a user account.
// It generates a secure random secret and returns the key with metadata
// including the QR code URL for user setup.
//
// Parameters:
//
//	issuer: The service name (e.g., "PasswordManager").
//	accountName: The user's account identifier (e.g., username).
//
// Returns:
//
//	The generated TOTP key and an error if generation fails.
func (s *totpService) GenerateSecret(issuer, accountName string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		SecretSize:  20,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	return key, nil
}

// ValidateCode verifies a TOTP code against a secret at a specific time.
// It uses the configured tolerance settings to allow for clock skew
// and provides secure validation of user-provided codes.
//
// Parameters:
//
//	code: The TOTP code to validate.
//	secret: The base32-encoded TOTP secret.
//	currentTime: The time to use for validation.
//
// Returns:
//
//	True if the code is valid, false otherwise, and an error if validation fails.
func (s *totpService) ValidateCode(code, secret string, currentTime time.Time) (bool, error) {
	opts := totp.ValidateOpts{
		Period:    s.period,
		Skew:      s.skew,
		Digits:    s.digits,
		Algorithm: s.algorithm,
	}

	valid, err := totp.ValidateCustom(code, secret, currentTime, opts)
	if err != nil {
		return false, fmt.Errorf("TOTP validation error: %w", err)
	}

	return valid, nil
}

// GenerateCode creates a TOTP code for a secret at a specific time.
// This is primarily used for testing purposes to generate valid codes
// for verification workflows.
//
// Parameters:
//
//	secret: The base32-encoded TOTP secret.
//	currentTime: The time to use for code generation.
//
// Returns:
//
//	The generated TOTP code and an error if generation fails.
func (s *totpService) GenerateCode(secret string, currentTime time.Time) (string, error) {
	code, err := totp.GenerateCodeCustom(secret, currentTime, totp.ValidateOpts{
		Period:    s.period,
		Skew:      s.skew,
		Digits:    s.digits,
		Algorithm: s.algorithm,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return code, nil
}
