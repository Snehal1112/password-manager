package backup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ErrInvalidBlob is returned when the backup blob cannot be decoded.
var ErrInvalidBlob = errors.New("invalid backup blob")

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
	ResourceType string                   `json:"resource_type"`
	ResourceID   string                   `json:"resource_id"`
	Data         json.RawMessage          `json:"data"`
	Versions     []model.KeyVersionRecord `json:"versions,omitempty"` // keys only
}

// BackupSecret creates a base64url-encoded backup blob for the given secret.
//
// vaultID is the vault the caller's request was authorized against. See
// BackupKey for why the scoped read replaces the previous unscoped read plus
// ownership comparison.
func (s *ItemBackupService) BackupSecret(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	secret, err := s.secretRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup secret: %w", err)
	}
	return encodeBlob("secret", id.String(), secret, nil)
}

// RestoreSecret decodes blob and re-inserts it as newID, owned by userID,
// into vaultID — the vault authorized by the caller's request, never the
// vault embedded in the blob. Trusting the blob's vault_id would let a
// caller with restore permission in one vault silently write into any vault
// a blob happens to reference.
func (s *ItemBackupService) RestoreSecret(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var secret model.Secret
	if _, err := decodeBlob(blob, "secret", &secret); err != nil {
		return err
	}
	secret.ID = newID
	secret.UserID = userID
	secret.VaultID = vaultID
	if err := s.secretRepo.Create(ctx, &secret); err != nil {
		return err
	}
	// Create does not write purge_protection, so a protected item would be
	// restored unprotected. Re-apply the blob's flag as a second write.
	if secret.PurgeProtection {
		if err := s.secretRepo.SetPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore secret: set purge protection: %w", err)
		}
	}
	return nil
}

// BackupKey creates a base64url-encoded backup blob for the given key.
//
// vaultID is the vault the caller's request was authorized against, never a
// vault taken from user input — the same rule RestoreKey follows. The scoped
// read is the entire authorization gate: an unscoped read plus an ownership
// comparison (the previous design) refused a Crypto User who legitimately held
// ActionKeysBackup without owning the key, while still letting any caller name
// a key in a vault they were never authorized for.
func (s *ItemBackupService) BackupKey(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	key, err := s.keyRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup key: %w", err)
	}

	// Version records are filtered by the key's owner, not the caller:
	// ListVersionRecords joins on k.user_id, so passing a non-owning caller's
	// ID returns zero rows and silently drops the key's rotation history from
	// the blob.
	versions, err := s.keyRepo.ListVersionRecords(ctx, id, key.UserID)
	if err != nil {
		return "", fmt.Errorf("backup key: list versions: %w", err)
	}
	return encodeBlob("key", id.String(), key, versions)
}

// RestoreKey decodes blob and re-inserts it as newID, owned by userID, into
// vaultID — the vault authorized by the caller's request. See RestoreSecret.
func (s *ItemBackupService) RestoreKey(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var key model.Key
	versions, err := decodeBlob(blob, "key", &key)
	if err != nil {
		return err
	}
	key.ID = newID
	key.UserID = userID
	key.VaultID = vaultID
	if err := s.keyRepo.Create(ctx, &key); err != nil {
		return err
	}
	// See RestoreSecret: Create does not write purge_protection.
	if key.PurgeProtection {
		if err := s.keyRepo.SetPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore key: set purge protection: %w", err)
		}
	}
	for _, v := range versions {
		if err := s.keyRepo.CreateVersion(ctx, newID, v.Version, v.Value); err != nil {
			return fmt.Errorf("restore key: create version %d: %w", v.Version, err)
		}
	}
	return nil
}

// BackupCertificate creates a base64url-encoded backup blob for the given
// certificate.
//
// vaultID is the vault the caller's request was authorized against. See
// BackupKey for why the scoped read replaces the previous unscoped read plus
// ownership comparison.
func (s *ItemBackupService) BackupCertificate(ctx context.Context, id, userID, vaultID uuid.UUID) (string, error) {
	cert, err := s.certRepo.Read(ctx, id, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return "", fmt.Errorf("backup certificate: %w", err)
	}
	return encodeBlob("certificate", id.String(), cert, nil)
}

// RestoreCertificate decodes blob and re-inserts it as newID, owned by
// userID, into vaultID — the vault authorized by the caller's request. See
// RestoreSecret.
func (s *ItemBackupService) RestoreCertificate(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var cert model.Certificate
	if _, err := decodeBlob(blob, "certificate", &cert); err != nil {
		return err
	}
	cert.ID = newID
	cert.UserID = userID
	cert.VaultID = vaultID
	if err := s.certRepo.Create(ctx, &cert); err != nil {
		return err
	}
	// See RestoreSecret: Create does not write purge_protection.
	if cert.PurgeProtection {
		if err := s.certRepo.SetPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore certificate: set purge protection: %w", err)
		}
	}
	return nil
}

// encodeBlob marshals data into a JSON envelope and base64url-encodes it.
// versions is nil for secrets/certificates (no version-material concept);
// keys pass their archived version records.
func encodeBlob(resourceType, resourceID string, data interface{}, versions []model.KeyVersionRecord) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal data: %w", err)
	}
	envelope, err := json.Marshal(backupEnvelope{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Data:         raw,
		Versions:     versions,
	})
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return base64.URLEncoding.EncodeToString(envelope), nil
}

// decodeBlob base64url-decodes a blob and unmarshals the envelope into out.
// Returns the envelope's Versions (nil for secrets/certificates, and nil for
// a blob encoded before this field existed — the field is purely additive).
func decodeBlob(blob, expectedType string, out interface{}) ([]model.KeyVersionRecord, error) {
	raw, err := base64.URLEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid encoding: %w", ErrInvalidBlob, err)
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%w: invalid format: %w", ErrInvalidBlob, err)
	}
	if envelope.ResourceType != expectedType {
		return nil, fmt.Errorf("%w: type mismatch: expected %s, got %s", ErrInvalidBlob, expectedType, envelope.ResourceType)
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return nil, err
	}
	return envelope.Versions, nil
}
