// Package auth provides authentication services for the password manager.
// This package contains services for password hashing, JWT token management,
// TOTP operations, and user authentication workflows.
package auth

import (
	"fmt"

	"password-manager/common"
)

// PasswordService handles password hashing and validation operations.
// It provides a clean interface for password security operations,
// separating password concerns from repository logic.
type PasswordService interface {
	HashPassword(password string) (string, error)
	ValidatePassword(password, hash string) error
}

// passwordService implements PasswordService using bcrypt for secure password hashing.
type passwordService struct{}

// NewPasswordService creates a new PasswordService instance.
// It provides password hashing and validation functionality
// using bcrypt for secure password storage.
//
// Returns:
//
//	A PasswordService implementation for password operations.
func NewPasswordService() PasswordService {
	return &passwordService{}
}

// HashPassword securely hashes a plaintext password using bcrypt.
// It uses the common.HashString function to ensure consistent
// hashing across the application.
//
// Parameters:
//
//	password: The plaintext password to hash.
//
// Returns:
//
//	The hashed password string and an error if hashing fails.
func (s *passwordService) HashPassword(password string) (string, error) {
	hashedPassword, err := common.HashString(password)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return hashedPassword, nil
}

// ValidatePassword verifies a plaintext password against a bcrypt hash.
// It uses the common.CheckPassword function for consistent validation.
//
// Parameters:
//
//	password: The plaintext password to validate.
//	hash: The bcrypt hash to validate against.
//
// Returns:
//
//	An error if validation fails, nil if password is correct.
func (s *passwordService) ValidatePassword(password, hash string) error {
	if err := common.CheckPassword(password, hash); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}
	return nil
}
