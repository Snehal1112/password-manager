package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// CheckPassword compares a plaintext password with a hashed password.
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// HashString hashes a string using bcrypt.
func HashString(input string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// EncryptSecret encrypts a secret value using AES-256-GCM.
// It uses the master key from configuration for encryption.
//
// Parameters:
//
//	value: The plaintext secret value.
//
// Returns:
//
//	The encrypted value (base64-encoded) and an error if encryption fails.
func EncryptSecret(value string) (string, error) {
	masterKey := viper.GetString("master_key")
	if masterKey == "" {
		return "", fmt.Errorf("master key not configured")
	}

	key, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode master key: %w", err)
	}
	if len(key) < 32 {
		return "", fmt.Errorf("master key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSecret decrypts a secret value encrypted with AES-256-GCM.
// It uses the master key from configuration for decryption.
//
// Parameters:
//
//	encryptedValue: The encrypted value (base64-encoded).
//
// Returns:
//
//	The decrypted plaintext value and an error if decryption fails.
func DecryptSecret(encryptedValue string) (string, error) {
	masterKey := viper.GetString("master_key")
	if masterKey == "" {
		return "", fmt.Errorf("master key not configured")
	}

	key, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode master key: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("master key must be 32 bytes")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted value: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}
