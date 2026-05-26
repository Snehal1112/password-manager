package backup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ItemBackupService provides per-item backup and restore for secrets, keys,
// and certificates. Each backup is a base64url-encoded JSON envelope that is
// opaque to the caller.
type ItemBackupService struct {
	secretRepo repositories.SecretRepositoryInterface
	keyRepo    repositories.KeyRepositoryInterface
	certRepo   repositories.CertificateRepositoryInterface
}

// NewItemBackupService creates an ItemBackupService wired to the given repos.
// Any repo may be nil if that resource type is not required by the caller.
func NewItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
) *ItemBackupService {
	return &ItemBackupService{
		secretRepo: secretRepo,
		keyRepo:    keyRepo,
		certRepo:   certRepo,
	}
}

// backupEnvelope is the internal structure stored inside the opaque blob.
type backupEnvelope struct {
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Data         json.RawMessage `json:"data"`
}

// BackupSecret creates a base64url-encoded backup blob for the given secret.
// It returns an error when the secret does not belong to userID.
func (s *ItemBackupService) BackupSecret(ctx context.Context, id, userID uuid.UUID) (string, error) {
	secret, err := s.secretRepo.Read(ctx, id)
	if err != nil {
		return "", fmt.Errorf("backup secret: %w", err)
	}
	if secret.UserID != userID {
		return "", fmt.Errorf("forbidden")
	}
	return encodeBlob("secret", id.String(), secret)
}

// RestoreSecret decodes a backup blob and re-inserts the secret under newID so
// that the caller can avoid primary-key collisions with the original row.
func (s *ItemBackupService) RestoreSecret(ctx context.Context, blob string, userID uuid.UUID, newID uuid.UUID) error {
	var secret model.Secret
	if err := decodeBlob(blob, "secret", &secret); err != nil {
		return err
	}
	secret.ID = newID
	secret.UserID = userID
	return s.secretRepo.Create(ctx, &secret)
}

// BackupKey creates a base64url-encoded backup blob for the given key.
// It returns an error when the key does not belong to userID.
func (s *ItemBackupService) BackupKey(ctx context.Context, id, userID uuid.UUID) (string, error) {
	key, err := s.keyRepo.Read(ctx, id)
	if err != nil {
		return "", fmt.Errorf("backup key: %w", err)
	}
	if key.UserID != userID {
		return "", fmt.Errorf("forbidden")
	}
	return encodeBlob("key", id.String(), key)
}

// RestoreKey decodes a backup blob and re-inserts the key under newID.
func (s *ItemBackupService) RestoreKey(ctx context.Context, blob string, userID uuid.UUID, newID uuid.UUID) error {
	var key model.Key
	if err := decodeBlob(blob, "key", &key); err != nil {
		return err
	}
	key.ID = newID
	key.UserID = userID
	return s.keyRepo.Create(ctx, &key)
}

// BackupCertificate creates a base64url-encoded backup blob for the given certificate.
// It returns an error when the certificate does not belong to userID.
func (s *ItemBackupService) BackupCertificate(ctx context.Context, id, userID uuid.UUID) (string, error) {
	cert, err := s.certRepo.Read(ctx, id)
	if err != nil {
		return "", fmt.Errorf("backup certificate: %w", err)
	}
	if cert.UserID != userID {
		return "", fmt.Errorf("forbidden")
	}
	return encodeBlob("certificate", id.String(), cert)
}

// RestoreCertificate decodes a backup blob and re-inserts the certificate under newID.
func (s *ItemBackupService) RestoreCertificate(ctx context.Context, blob string, userID uuid.UUID, newID uuid.UUID) error {
	var cert model.Certificate
	if err := decodeBlob(blob, "certificate", &cert); err != nil {
		return err
	}
	cert.ID = newID
	cert.UserID = userID
	return s.certRepo.Create(ctx, &cert)
}

// encodeBlob marshals data into a JSON envelope and base64url-encodes it.
func encodeBlob(resourceType, resourceID string, data interface{}) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal data: %w", err)
	}
	envelope, err := json.Marshal(backupEnvelope{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Data:         raw,
	})
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return base64.URLEncoding.EncodeToString(envelope), nil
}

// decodeBlob base64url-decodes a blob and unmarshals the envelope into out.
// It returns an error when the resource type does not match expectedType.
func decodeBlob(blob, expectedType string, out interface{}) error {
	raw, err := base64.URLEncoding.DecodeString(blob)
	if err != nil {
		return fmt.Errorf("invalid blob encoding: %w", err)
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("invalid blob format: %w", err)
	}
	if envelope.ResourceType != expectedType {
		return fmt.Errorf("blob type mismatch: expected %s, got %s", expectedType, envelope.ResourceType)
	}
	return json.Unmarshal(envelope.Data, out)
}
