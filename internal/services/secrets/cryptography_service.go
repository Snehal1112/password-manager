// Package secrets provides secret management services for the password manager.
// This package contains services for encryption, versioning, tagging,
// and orchestrating secret operations with proper separation of concerns.
package secrets

import (
	"fmt"

	"rocketvault/common"
)

// CryptographyService handles encryption and decryption operations for secrets.
// It provides a clean interface for cryptographic operations,
// separating encryption concerns from repository and business logic.
type CryptographyService interface {
	EncryptSecret(plaintext string) (string, error)
	DecryptSecret(ciphertext string) (string, error)
}

// cryptographyService implements CryptographyService using AES encryption.
type cryptographyService struct{}

// NewCryptographyService creates a new CryptographyService instance.
// It provides encryption and decryption functionality using AES-GCM
// for secure secret storage.
//
// Returns:
//
//	A CryptographyService implementation for cryptographic operations.
func NewCryptographyService() CryptographyService {
	return &cryptographyService{}
}

// EncryptSecret encrypts a plaintext secret using AES-GCM encryption.
// It uses the common.EncryptSecret function to ensure consistent
// encryption across the application.
//
// Parameters:
//
//	plaintext: The plaintext secret to encrypt.
//
// Returns:
//
//	The encrypted secret string and an error if encryption fails.
func (s *cryptographyService) EncryptSecret(plaintext string) (string, error) {
	ciphertext, err := common.EncryptSecret(plaintext)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt secret: %w", err)
	}
	return ciphertext, nil
}

// DecryptSecret decrypts an encrypted secret using AES-GCM decryption.
// It uses the common.DecryptSecret function for consistent decryption.
//
// Parameters:
//
//	ciphertext: The encrypted secret to decrypt.
//
// Returns:
//
//	The decrypted plaintext string and an error if decryption fails.
func (s *cryptographyService) DecryptSecret(ciphertext string) (string, error) {
	plaintext, err := common.DecryptSecret(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt secret: %w", err)
	}
	return plaintext, nil
}
