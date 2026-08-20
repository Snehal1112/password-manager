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
	secretRepo  repositories.SecretRepositoryInterface
	keyRepo     repositories.KeyRepositoryInterface
	certRepo    repositories.CertificateRepositoryInterface
	versionRepo repositories.SecretVersionRepositoryInterface
}

// NewItemBackupService creates an ItemBackupService wired to the given repos.
// Any repo may be nil if that resource type is not required by the caller.
func NewItemBackupService(
	secretRepo repositories.SecretRepositoryInterface,
	keyRepo repositories.KeyRepositoryInterface,
	certRepo repositories.CertificateRepositoryInterface,
	versionRepo repositories.SecretVersionRepositoryInterface,
) *ItemBackupService {
	return &ItemBackupService{
		secretRepo:  secretRepo,
		keyRepo:     keyRepo,
		certRepo:    certRepo,
		versionRepo: versionRepo,
	}
}

// blobVersions carries whatever version history a resource type has. Both
// fields are optional: a key blob populates Key, a secret blob populates
// Secret, and a certificate blob populates neither (certificates have no
// version table).
type blobVersions struct {
	Key    []model.KeyVersionRecord
	Secret []model.SecretVersion
}

// backupEnvelope is the internal structure stored inside the opaque blob.
//
// Both version fields are omitempty and additive: a blob written before a
// given field existed simply decodes it as nil. That is what lets pre-2026-08
// key blobs and pre-2026-08-20 secret blobs still restore. Never rename or
// retype an existing field here — it is a wire format.
type backupEnvelope struct {
	ResourceType   string                   `json:"resource_type"`
	ResourceID     string                   `json:"resource_id"`
	Data           json.RawMessage          `json:"data"`
	Versions       []model.KeyVersionRecord `json:"versions,omitempty"`        // keys only
	SecretVersions []model.SecretVersion    `json:"secret_versions,omitempty"` // secrets only
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

	// Version rows are fetched by secret ID; the scoped read above is their
	// authorization. Without these the blob would restore a single version
	// and silently discard the rest — the same loss B26 closed for keys.
	versions, err := s.versionRepo.GetVersions(ctx, id)
	if err != nil {
		return "", fmt.Errorf("backup secret: list versions: %w", err)
	}
	return encodeBlob("secret", id.String(), secret, blobVersions{Secret: versions})
}

// RestoreSecret decodes blob and re-inserts it as newID, owned by userID,
// into vaultID — the vault authorized by the caller's request, never the
// vault embedded in the blob. Trusting the blob's vault_id would let a
// caller with restore permission in one vault silently write into any vault
// a blob happens to reference.
//
// Archived versions in the blob are replayed under newID. Each gets a fresh
// primary key: secret_versions.id is a PRIMARY KEY, and the source secret
// usually still exists, so reusing the blob's IDs would collide.
func (s *ItemBackupService) RestoreSecret(ctx context.Context, blob string, userID, vaultID, newID uuid.UUID) error {
	var secret model.Secret
	versions, err := decodeBlob(blob, "secret", &secret)
	if err != nil {
		return err
	}
	secret.ID = newID
	secret.UserID = userID
	secret.VaultID = vaultID
	if err := s.secretRepo.Create(ctx, &secret); err != nil {
		return err
	}
	// Replay versions before applying purge protection: if this fails, the
	// partial restore is left unprotected and can still be purged by an
	// operator. Setting purge protection first would leave a partial restore
	// that PurgeSecret refuses to clean up, orphaning it under an ID the
	// caller never received.
	for _, v := range versions.Secret {
		v.ID = uuid.New()
		v.SecretID = newID
		v.UserID = userID
		if err := s.versionRepo.CreateVersion(ctx, &v); err != nil {
			return fmt.Errorf("restore secret: create version %d: %w", v.Version, err)
		}
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

	// Version records are fetched by key ID. The scoped Read above is the
	// authorization for them.
	versions, err := s.keyRepo.ListVersionRecords(ctx, id)
	if err != nil {
		return "", fmt.Errorf("backup key: list versions: %w", err)
	}
	return encodeBlob("key", id.String(), key, blobVersions{Key: versions})
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
	// Replay versions before applying purge protection, for the reason spelled
	// out in RestoreSecret: a failure here must leave the partial restore
	// purgeable. Setting purge protection first would strand it, since
	// PurgeKey refuses a protected key.
	for _, v := range versions.Key {
		if err := s.keyRepo.CreateVersion(ctx, newID, v.Version, v.Value); err != nil {
			return fmt.Errorf("restore key: create version %d: %w", v.Version, err)
		}
	}
	// See RestoreSecret: Create does not write purge_protection.
	if key.PurgeProtection {
		if err := s.keyRepo.SetPurgeProtection(ctx, newID, true); err != nil {
			return fmt.Errorf("restore key: set purge protection: %w", err)
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
	return encodeBlob("certificate", id.String(), cert, blobVersions{})
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
// versions carries whatever history the resource type has; a zero blobVersions
// means none, and both envelope fields are then omitted.
func encodeBlob(resourceType, resourceID string, data interface{}, versions blobVersions) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal data: %w", err)
	}
	envelope, err := json.Marshal(backupEnvelope{
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		Data:           raw,
		Versions:       versions.Key,
		SecretVersions: versions.Secret,
	})
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return base64.URLEncoding.EncodeToString(envelope), nil
}

// decodeBlob base64url-decodes a blob and unmarshals the envelope into out.
// The returned blobVersions is zero for a resource type with no history, and
// zero for a blob encoded before the corresponding field existed — both
// fields are purely additive.
func decodeBlob(blob, expectedType string, out interface{}) (blobVersions, error) {
	var none blobVersions

	raw, err := base64.URLEncoding.DecodeString(blob)
	if err != nil {
		return none, fmt.Errorf("%w: invalid encoding: %w", ErrInvalidBlob, err)
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return none, fmt.Errorf("%w: invalid format: %w", ErrInvalidBlob, err)
	}
	if envelope.ResourceType != expectedType {
		return none, fmt.Errorf("%w: type mismatch: expected %s, got %s", ErrInvalidBlob, expectedType, envelope.ResourceType)
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return none, err
	}
	return blobVersions{Key: envelope.Versions, Secret: envelope.SecretVersions}, nil
}
