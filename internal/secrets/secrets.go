package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/db"
	"github.com/spf13/viper"
)

// Secret represents a secret stored in the database
type Secret struct {
	ID        int
	UserID    int
	Name      string
	Value     string
	Version   int
	CreatedAt string
}

// CreateSecret encrypts and stores a new secret in the database
func (s *Secret) CreateSecret(userID int, name, value string) error {
	encryptedValue, err := Encrypt(value, viper.GetString("master_key"))
	if err != nil {
		logrus.Error("Failed to encrypt secret: ", err)
		return err
	}

	// Get the latest version for this secret
	var latestVersion int
	err = db.DB.QueryRow(
		"SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_id = ? AND name = ?",
		userID, name,
	).Scan(&latestVersion)
	if err != nil {
		logrus.Error("Failed to query latest version: ", err)
		return err
	}

	newVersion := latestVersion + 1

	_, err = db.DB.Exec(
		"INSERT INTO secrets (user_id, name, value, version, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
		userID, name, encryptedValue, newVersion,
	)
	if err != nil {
		logrus.Error("Failed to store secret: ", err)
		return err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
		"version": newVersion,
	}).Info("Secret created")
	return nil
}

// UpdateSecret updates an existing secret by creating a new version
func UpdateSecret(userID int, name, value string) error {
	// Check if the secret exists
	var latestVersion int
	err := db.DB.QueryRow(
		"SELECT COALESCE(MAX(version), 0) FROM secrets WHERE user_id = ? AND name = ?",
		userID, name,
	).Scan(&latestVersion)
	if err != nil {
		logrus.Error("Failed to query latest version: ", err)
		return err
	}
	if latestVersion == 0 {
		logrus.WithFields(logrus.Fields{
			"user_id": userID,
			"name":    name,
		}).Warn("Secret not found for update")
		return errors.New("secret not found")
	}

	encryptedValue, err := Encrypt(value, viper.GetString("master_key"))
	if err != nil {
		logrus.Error("Failed to encrypt secret: ", err)
		return err
	}

	newVersion := latestVersion + 1

	_, err = db.DB.Exec(
		"INSERT INTO secrets (user_id, name, value, version, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
		userID, name, encryptedValue, newVersion,
	)
	if err != nil {
		logrus.Error("Failed to update secret: ", err)
		return err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
		"version": newVersion,
	}).Info("Secret updated")
	return nil
}

// DeleteSecret removes a specific secret by name and version for a user
func DeleteSecret(userID int, name string, version int) error {
	result, err := db.DB.Exec(
		"DELETE FROM secrets WHERE user_id = ? AND name = ? AND version = ?",
		userID, name, version,
	)
	if err != nil {
		logrus.Error("Failed to delete secret: ", err)
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logrus.Error("Failed to check rows affected: ", err)
		return err
	}
	if rowsAffected == 0 {
		logrus.WithFields(logrus.Fields{
			"user_id": userID,
			"name":    name,
			"version": version,
		}).Warn("Secret not found")
		return errors.New("secret not found")
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
		"version": version,
	}).Info("Secret deleted")
	return nil
}

func ExportSecrets(userID int) (string, error) {
	rows, err := db.DB.Query(
		"SELECT name, value, version, created_at FROM secrets WHERE user_id = ? ORDER BY name, version",
		userID,
	)
	if err != nil {
		logrus.Error("Failed to query secrets for export: ", err)
		return "", err
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var s Secret
		var encryptedValue string
		if err := rows.Scan(&s.Name, &encryptedValue, &s.Version, &s.CreatedAt); err != nil {
			logrus.Error("Failed to scan secret: ", err)
			return "", err
		}
		s.Value, err = Decrypt(encryptedValue, viper.GetString("master_key"))
		if err != nil {
			logrus.Error("Failed to decrypt secret for export: ", err)
			return "", err
		}
		s.UserID = userID
		secrets = append(secrets, s)
	}

	// Convert secrets to JSON and encrypt
	data, err := json.Marshal(secrets)
	if err != nil {
		logrus.Error("Failed to marshal secrets: ", err)
		return "", err
	}

	encryptedData, err := Encrypt(string(data), viper.GetString("master_key"))
	if err != nil {
		logrus.Error("Failed to encrypt exported secrets: ", err)
		return "", err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"count":   len(secrets),
	}).Info("Secrets exported")
	return encryptedData, nil
}
func Encrypt(plaintext, key string) (string, error) {
	keyHash := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return "", err
	}

	plaintextBytes := []byte(plaintext)
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintextBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(ciphertext, key string) (string, error) {
	keyHash := sha256.Sum256([]byte(key))
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return "", err
	}

	if len(ciphertextBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

	return string(ciphertextBytes), nil
}
