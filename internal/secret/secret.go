package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

// Secret represents a secret entity.
// It includes metadata and an encrypted value.
type Secret struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	RotateAt  time.Time `json:"rotate_at"`
}

// NewSecret creates a new secret with the provided ID and value.
// It encrypts the value using AES with the given key.
//
// Parameters:
//
//	id: The unique identifier for the secret.
//	value: The plaintext value to encrypt.
//	key: The encryption key (must be 32 bytes for AES-256).
//
// Returns:
//
//	A pointer to the created Secret and an error if encryption fails.
//
// The function is used to initialize a new secret entity.
func NewSecret(id, value, key string) (*Secret, error) {
	if id == "" || value == "" || key == "" {
		return nil, fmt.Errorf("id, value, and key must not be empty")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	encryptedValue, err := EncryptAES(value, key)
	if err != nil {
		return nil, fmt.Errorf("encrypting secret: %w", err)
	}

	return &Secret{
		ID:        id,
		Value:     encryptedValue,
		Version:   1,
		CreatedAt: time.Now(),
		RotateAt:  time.Now().Add(30 * 24 * time.Hour), // Rotate every 30 days
	}, nil
}

// EncryptAES encrypts the plaintext using AES-256 in GCM mode.
// It uses a random nonce for each encryption.
//
// Parameters:
//
//	plaintext: The data to encrypt.
//	key: The encryption key (must be 32 bytes).
//
// Returns:
//
//	The base64-encoded ciphertext (including nonce) and an error if encryption fails.
//
// The function is used to secure secret values.
func EncryptAES(plaintext, key string) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts the ciphertext using AES-256 in GCM mode.
// It expects a base64-encoded ciphertext (including nonce).
//
// Parameters:
//
//	key: The decryption key (must be 32 bytes).
//
// Returns:
//
//	The decrypted plaintext and an error if decryption fails.
//
// The function is used to retrieve the original secret value.
func (s *Secret) DecryptAES(key string) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(s.Value)
	if err != nil {
		return "", fmt.Errorf("decoding ciphertext: %w", err)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting: %w", err)
	}

	return string(plaintext), nil
}
