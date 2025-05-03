package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

// Secret represents an encrypted secret stored in the database.
// The Value field contains the encrypted secret (nonce + ciphertext).
type Secret struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"` // Encrypted value (nonce + ciphertext)
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	RotateAt  time.Time `json:"rotate_at"`
}

// NewSecret creates a new Secret with an encrypted value.
// It encrypts the provided plaintext value using AES-GCM.
//
// Parameters:
//
//	id: The unique identifier for the secret (e.g., "api_key_123").
//	value: The plaintext secret to encrypt.
//	key: The AES encryption key (32 bytes for AES-256).
//
// Returns:
//
//	A pointer to the created Secret and an error if encryption fails.
//
// The function is used to initialize a secret with secure encryption.
func NewSecret(id, value, key string) (*Secret, error) {
	if id == "" || value == "" || key == "" {
		logrus.WithFields(logrus.Fields{
			"id":  id,
			"key": key != "",
		}).Error("ID, value, and key must not be empty")
		return nil, fmt.Errorf("id, value, and key must not be empty")
	}

	s := &Secret{
		ID:        id,
		Version:   1,
		CreatedAt: time.Now(),
		RotateAt:  time.Now().Add(30 * 24 * time.Hour), // Default rotation: 30 days
	}

	encryptedValue, err := s.EncryptAES(value, key)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"id": id,
		}).Error("Failed to encrypt secret")
		return nil, fmt.Errorf("encrypting secret: %w", err)
	}
	s.Value = encryptedValue

	logrus.WithFields(logrus.Fields{
		"id":      id,
		"version": s.Version,
	}).Info("Secret created")
	return s, nil
}

// EncryptAES encrypts a plaintext value using AES-GCM.
// It generates a random nonce and returns the concatenated nonce and ciphertext.
//
// Parameters:
//
//	plaintext: The plaintext to encry.pt.
//	key: The AES encryption key (32 bytes for AES-256).
//
// Returns:
//
//	The encrypted value (nonce + ciphertext) as a string and an error if encryption fails.
//
// The function is used to securely encrypt secrets before storage.
func (s *Secret) EncryptAES(plaintext, key string) (string, error) {
	if len(key) != 32 {
		logrus.WithFields(logrus.Fields{
			"key_length": len(key),
		}).Error("Encryption key must be 32 bytes")
		return "", fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		logrus.WithError(err).Error("Failed to create AES cipher")
		return "", fmt.Errorf("creating AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		logrus.WithError(err).Error("Failed to create GCM")
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logrus.WithError(err).Error("Failed to generate nonce")
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	encryptedValue := append(nonce, ciphertext...)

	logrus.Info("Value encrypted successfully")
	return string(encryptedValue), nil
}

// DecryptAES decrypts the Secret's Value field using AES-GCM.
// It extracts the nonce and ciphertext from Value and returns the plaintext.
//
// Parameters:
//
//	key: The AES encryption key (32 bytes for AES-256).
//
// Returns:
//
//	The decrypted plaintext and an error if decryption fails.
//
// The function is used to retrieve the original secret value.
func (s *Secret) DecryptAES(key string) (string, error) {
	if len(key) != 32 {
		logrus.WithFields(logrus.Fields{
			"key_length": len(key),
		}).Error("Decryption key must be 32 bytes")
		return "", fmt.Errorf("decryption key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		logrus.WithError(err).Error("Failed to create AES cipher")
		return "", fmt.Errorf("creating AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		logrus.WithError(err).Error("Failed to create GCM")
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	data := []byte(s.Value)
	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		logrus.WithFields(logrus.Fields{
			"data_length": len(data),
			"nonce_size":  nonceSize,
		}).Error("Invalid encrypted data")
		return "", fmt.Errorf("invalid encrypted data: too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"id": s.ID,
		}).Error("Failed to decrypt value")
		return "", fmt.Errorf("decrypting value: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"id": s.ID,
	}).Info("Value decrypted successfully")
	return string(plaintext), nil
}
