// Package keys provides key management services for the password manager.
// It handles cryptographic key generation, lifecycle, and access control
// while maintaining proper separation of concerns.
package keys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ErrKeyNotFound is returned when a key does not exist or is not accessible
// within the requested scope (vault or user ownership).
var ErrKeyNotFound = errors.New("key not found")

// ErrKeyLifecycleDenied is returned when a key exists but is disabled or
// outside its valid time window (not_before / expires_at).
var ErrKeyLifecycleDenied = errors.New("key is disabled or outside its valid time window")

// ErrKeyForbidden is returned when the caller does not own the key or the key
// does not belong to the requested vault.
var ErrKeyForbidden = errors.New("forbidden: key access denied")

// ErrKeyRevoked is returned when the caller attempts to use a revoked key.
var ErrKeyRevoked = errors.New("key is revoked")

// ErrUnsupportedAlgorithm is returned when an unsupported algorithm is requested.
var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

// CreateKeyRequest represents a request to create a new cryptographic key.
type CreateKeyRequest struct {
	Name      string
	Type      string // "RSA" or "ECDSA"
	Bits      int    // For RSA: 2048, 3072, or 4096
	Curve     string // For ECDSA: P-256, P-384, P-521
	Tags      []string
	UserID    uuid.UUID
	VaultID   uuid.UUID // Target vault; defaults to the default vault when nil.
	Enabled   *bool     // Defaults to true if nil.
	ExpiresAt *time.Time
	NotBefore *time.Time
}

// resolveVaultID returns the requested vault id, falling back to the default
// vault when the caller did not specify one.
func resolveVaultID(vaultID uuid.UUID) uuid.UUID {
	if vaultID == uuid.Nil {
		return uuid.MustParse(model.DefaultVaultID)
	}
	return vaultID
}

// CreateKeyResult represents the result of creating a new key.
type CreateKeyResult struct {
	KeyID     uuid.UUID
	Name      string
	Type      string
	Tags      []string
	CreatedAt time.Time
}

// UpdateKeyRequest represents a request to update an existing key.
type UpdateKeyRequest struct {
	KeyID     uuid.UUID
	Name      *string    // Optional - nil means no change
	Tags      []string   // Optional - empty means no change
	Revoked   *bool      // Optional - nil means no change
	UserID    uuid.UUID  // For access control
	Enabled   *bool      // Optional - nil means no change
	ExpiresAt *time.Time // Optional - nil means no change
	NotBefore *time.Time // Optional - nil means no change
}

// KeyService handles cryptographic key management operations.
// It orchestrates key generation, validation, and access control
// while delegating storage to repositories.
type KeyService interface {
	CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	GetKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error)
	ListKeys(ctx context.Context, userID uuid.UUID) ([]model.Key, error)
	ListKeysWithFilters(ctx context.Context, userID *uuid.UUID, keyType string, tags []string, isAdmin bool) ([]model.Key, error)
	UpdateKey(ctx context.Context, req UpdateKeyRequest) error
	DeleteKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error)
	// GetKeyInVault retrieves a key scoped to the given vault.
	GetKeyInVault(ctx context.Context, keyID, vaultID uuid.UUID) (*model.Key, error)
	// ListKeysInVault lists keys scoped to the given vault, optionally filtered by type and tags.
	ListKeysInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error)
	// DeleteKeyInVault soft-deletes a key scoped to the given vault.
	// userID is used to enforce ownership; pass uuid.Nil to skip the check (admin/cascade ops).
	DeleteKeyInVault(ctx context.Context, keyID, vaultID, userID uuid.UUID) (*model.Key, error)
	RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*CreateKeyResult, error)
	ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error
}

// keyService implements KeyService by coordinating key operations
// and access control while delegating to repository layer.
type keyService struct {
	keyRepo     repositories.KeyRepositoryInterface
	keyProvider crypto.KeyProvider
	keyCache    keycache.Cache
	logger      *logging.Logger
}

// KeyServiceConfig holds the dependencies for key service.
type KeyServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	KeyProvider   crypto.KeyProvider
	// KeyCache is optional. When nil, a NopCache is used and mutations still
	// call Invalidate (which is a no-op on NopCache).
	KeyCache keycache.Cache
	Logger   *logging.Logger
}

// NewKeyService creates a new KeyService with the provided dependencies.
// It orchestrates key management operations while maintaining SRP compliance.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	A KeyService implementation for key management operations.
func NewKeyService(config KeyServiceConfig) KeyService {
	if config.KeyCache == nil {
		config.KeyCache = keycache.NewNopCache()
	}
	return &keyService{
		keyRepo:     config.KeyRepository,
		keyProvider: config.KeyProvider,
		keyCache:    config.KeyCache,
		logger:      config.Logger,
	}
}

// CreateRSAKey creates a new RSA cryptographic key.
// It validates parameters, generates the key, encrypts it, and handles storage.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The key creation request with RSA-specific parameters.
//
// Returns:
//
//	The created key information or an error if creation fails.
func (s *keyService) CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"type":    req.Type,
		"bits":    req.Bits,
		"user_id": req.UserID.String(),
	}).Info("Creating RSA key")

	// Validate RSA-specific parameters
	if req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096 {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "invalid RSA key size: must be 2048, 3072, or 4096", nil)
		return nil, fmt.Errorf("invalid RSA key size: must be 2048, 3072, or 4096")
	}

	// Generate key via the configured provider (software or PKCS#11 HSM).
	handle, err := s.keyProvider.GenerateRSAKey(ctx, req.Bits)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to generate RSA key", err)
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// For software keys, the handle is PEM — encrypt before storage.
	// For PKCS#11 keys, the handle is a UUID label — prefix and store as-is.
	var storedValue string
	if isPKCS11Handle(handle) {
		storedValue = "pkcs11:" + handle
	} else {
		storedValue, err = common.EncryptSecret(handle)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to encrypt key", err)
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
	}

	// Default to enabled when caller did not specify.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Create key entity.
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      model.KeyTypeRSA,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		Bits:      req.Bits,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	// Store in repository.
	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store RSA key: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_rsa_key", "success", fmt.Sprintf("RSA key created: %s, ID: %s", req.Name, key.ID))
	logrus.WithFields(logrus.Fields{
		"key_id": key.ID.String(),
		"name":   key.Name,
		"type":   key.Type,
	}).Info("RSA key created successfully")

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}

// CreateECDSAKey creates a new ECDSA cryptographic key.
// It validates parameters, generates the key, encrypts it, and handles storage.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The key creation request with ECDSA-specific parameters.
//
// Returns:
//
//	The created key information or an error if creation fails.
func (s *keyService) CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"type":    req.Type,
		"curve":   req.Curve,
		"user_id": req.UserID.String(),
	}).Info("Creating ECDSA key")

	// Validate ECDSA-specific parameters.
	if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" && req.Curve != "P-256K" {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "invalid ECDSA curve: must be P-256, P-384, P-521, or P-256K", nil)
		return nil, fmt.Errorf("invalid ECDSA curve: must be P-256, P-384, P-521, or P-256K")
	}

	// Generate key via the configured provider (software or PKCS#11 HSM).
	handle, err := s.keyProvider.GenerateECDSAKey(ctx, req.Curve)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to generate ECDSA key", err)
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	var storedValue string
	if isPKCS11Handle(handle) {
		storedValue = "pkcs11:" + handle
	} else {
		storedValue, err = common.EncryptSecret(handle)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to encrypt key", err)
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
	}

	// P-256K keys use a distinct type so the crypto layer routes them correctly.
	keyType := model.KeyTypeECDSA
	if req.Curve == "P-256K" {
		keyType = model.KeyTypeES256K
	}

	// Default to enabled when caller did not specify.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Create key entity.
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      keyType,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		Curve:     req.Curve,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	// Store in repository.
	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store ECDSA key: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_ecdsa_key", "success", fmt.Sprintf("ECDSA key created: %s, ID: %s", req.Name, key.ID))
	logrus.WithFields(logrus.Fields{
		"key_id": key.ID.String(),
		"name":   key.Name,
		"type":   key.Type,
	}).Info("ECDSA key created successfully")

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}

// GetKey retrieves a key by ID with access control validation.
//
// Parameters:
//
//	ctx: The context for the operation.
//	keyID: The key's unique identifier.
//	userID: The requesting user's ID for access control.
//
// Returns:
//
//	The key information or an error if not found or access denied.
func (s *keyService) GetKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	// Log key access attempt with detailed context
	s.logger.LogAuditInfo(userID.String(), "get_key", "attempt",
		fmt.Sprintf("Accessing key: %s", keyID))

	key, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_key", "failed",
			fmt.Sprintf("Key not found: %s", keyID), err)
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	// Access control: users can only access their own keys. Treat cross-user
	// access as not-found to avoid leaking the existence of other users' keys.
	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "get_key", "forbidden",
			fmt.Sprintf("Unauthorized access attempt to key: %s (owner: %s)",
				keyID, key.UserID), nil)
		return nil, fmt.Errorf("%w: cannot access other users' keys", ErrKeyNotFound)
	}

	// Enforce lifecycle policy: key must be enabled and within its validity window.
	if !key.IsAccessible() {
		s.logger.LogAuditError(userID.String(), "get_key", "denied",
			fmt.Sprintf("Key is disabled or outside its valid time window: %s", keyID), nil)
		return nil, fmt.Errorf("%w", ErrKeyLifecycleDenied)
	}

	// Log successful key access with key metadata (excluding sensitive data)
	logrus.WithFields(logrus.Fields{
		"key_id":   key.ID,
		"key_name": key.Name,
		"key_type": key.Type,
		"user_id":  userID,
		"revoked":  key.Revoked,
	}).Info("Key accessed successfully")

	s.logger.LogAuditInfo(userID.String(), "get_key", "success",
		fmt.Sprintf("Key accessed: %s (name: %s, type: %s, revoked: %t)",
			key.ID, key.Name, key.Type, key.Revoked))

	return key, nil
}

// ListKeys retrieves all keys for a specific user.
//
// Parameters:
//
//	ctx: The context for the operation.
//	userID: The user's unique identifier.
//
// Returns:
//
//	A slice of user's keys or an error if retrieval fails.
func (s *keyService) ListKeys(ctx context.Context, userID uuid.UUID) ([]model.Key, error) {
	return s.keyRepo.ListByUser(ctx, &userID, "", nil)
}

// GetKeyInVault retrieves a key by ID scoped to a vault. It mirrors GetKey but
// enforces vault scope at the SQL level via ReadInVault and applies the same
// lifecycle policy.
func (s *keyService) GetKeyInVault(ctx context.Context, keyID, vaultID uuid.UUID) (*model.Key, error) {
	key, err := s.keyRepo.ReadInVault(ctx, keyID, vaultID)
	if err != nil {
		s.logger.LogAuditError("", "get_key", "failed",
			fmt.Sprintf("Key not found in vault: %s", keyID), err)
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	if !key.IsAccessible() {
		s.logger.LogAuditError("", "get_key", "denied",
			fmt.Sprintf("Key is disabled or outside its valid time window: %s", keyID), nil)
		return nil, fmt.Errorf("%w", ErrKeyLifecycleDenied)
	}

	return key, nil
}

// ListKeysInVault retrieves keys for a vault, optionally filtered by type and
// tags. It mirrors ListKeysWithFilters but scopes by vault instead of user.
func (s *keyService) ListKeysInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	return s.keyRepo.ListInVault(ctx, vaultID, keyType, tags)
}

// DeleteKeyInVault soft-deletes a key scoped to a vault. It mirrors DeleteKey
// but verifies vault scope via ReadInVault instead of ownership.
func (s *keyService) DeleteKeyInVault(ctx context.Context, keyID, vaultID, userID uuid.UUID) (*model.Key, error) {
	key, err := s.keyRepo.ReadInVault(ctx, keyID, vaultID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	// Enforce ownership unless caller explicitly opts out (uuid.Nil = admin/cascade).
	if userID != uuid.Nil && key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "delete_key", "forbidden", "key does not belong to user", nil)
		return nil, fmt.Errorf("%w", ErrKeyForbidden)
	}

	if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
		s.logger.LogAuditError("", "delete_key", "failed", "Failed to soft-delete key", err)
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	if s.keyCache != nil {
		s.keyCache.Invalidate(keyID)
	}

	deleted, err := s.keyRepo.ReadDeleted(ctx, keyID)
	if err != nil {
		s.logger.LogAuditInfo("", "delete_key", "success", "Key deleted (metadata unavailable)")
		return key, nil
	}

	s.logger.LogAuditInfo("", "delete_key", "success", "Key deleted successfully")
	return deleted, nil
}

// ListKeysWithFilters retrieves keys with optional filtering by type and tags.
// Supports admin mode where userID can be nil to list all keys in the system.
//
// Parameters:
//
//	ctx: The context for the operation.
//	userID: Optional user ID - nil for admin queries to list all keys.
//	keyType: Optional key type filter (RSA, ECDSA) - empty string means no filter.
//	tags: Optional tag filter - empty slice means no filter.
//	isAdmin: Whether the requester has admin privileges.
//
// Returns:
//
//	A slice of keys matching the filters or an error if retrieval fails.
func (s *keyService) ListKeysWithFilters(ctx context.Context, userID *uuid.UUID, keyType string, tags []string, isAdmin bool) ([]model.Key, error) {
	// Log the filter request
	logFields := logrus.Fields{
		"is_admin": isAdmin,
		"key_type": keyType,
		"tags":     tags,
	}
	if userID != nil {
		logFields["user_id"] = userID.String()
	} else {
		logFields["user_id"] = "all (admin)"
	}
	logrus.WithFields(logFields).Info("Listing keys with filters")

	// Non-admin users can only list their own keys
	if !isAdmin && userID == nil {
		s.logger.LogAuditError("unknown", "list_keys_with_filters", "failed", "Non-admin users cannot list all keys", nil)
		return nil, fmt.Errorf("forbidden: non-admin users cannot list all keys")
	}

	// Delegate to repository with filters
	keys, err := s.keyRepo.ListByUser(ctx, userID, keyType, tags)
	if err != nil {
		userIDStr := "all"
		if userID != nil {
			userIDStr = userID.String()
		}
		s.logger.LogAuditError(userIDStr, "list_keys_with_filters", "failed", "Failed to list keys", err)
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"key_count": len(keys),
		"is_admin":  isAdmin,
	}).Info("Keys listed successfully")

	return keys, nil
}

// UpdateKey updates an existing key with access control validation.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The key update request with optional fields.
//
// Returns:
//
//	An error if the update fails or access is denied.
func (s *keyService) UpdateKey(ctx context.Context, req UpdateKeyRequest) error {
	logrus.WithField("key_id", req.KeyID.String()).Info("Updating key")

	// Read directly so operators can update disabled/expired keys (e.g. re-enable them).
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "update_key", "forbidden", "key does not belong to user", nil)
		return fmt.Errorf("%w", ErrKeyForbidden)
	}

	// Prepare updated key
	updatedKey := *key

	// Update name if provided
	if req.Name != nil {
		updatedKey.Name = *req.Name
	}

	// Update tags if provided; non-nil empty slice clears all tags.
	if req.Tags != nil {
		updatedKey.Tags = req.Tags
	}

	// Update revocation status if provided.
	if req.Revoked != nil {
		updatedKey.Revoked = *req.Revoked
	}

	// Update lifecycle fields if provided.
	if req.Enabled != nil {
		updatedKey.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		updatedKey.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		updatedKey.NotBefore = req.NotBefore
	}

	// Update key via repository
	if err := s.keyRepo.Update(ctx, &updatedKey); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_key", "failed", "Failed to update key", err)
		return fmt.Errorf("failed to update key: %w", err)
	}

	// Evict stale cached material (covers revoke, disable, and expiry changes).
	if s.keyCache != nil {
		s.keyCache.Invalidate(updatedKey.ID)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "update_key", "success", fmt.Sprintf("Key updated: %s", updatedKey.Name))
	return nil
}

// DeleteKey removes a key from the system with access control validation.
// It returns the deleted key record so callers can inspect deletion metadata
// (deleted_at, scheduled_purge_at) matching Azure Key Vault behaviour.
//
// Parameters:
//
//	ctx: The context for the operation.
//	keyID: The key's unique identifier.
//	userID: The requesting user's ID for access control.
//
// Returns:
//
//	The deleted key record (with deleted_at populated) or an error if deletion fails.
func (s *keyService) DeleteKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	// Verify key exists and that the caller owns it.
	key, err := s.GetKey(ctx, keyID, userID)
	if err != nil {
		return nil, fmt.Errorf("delete key: %w", err)
	}

	if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
		s.logger.LogAuditError(userID.String(), "delete_key", "failed", "Failed to soft-delete key", err)
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	// Evict stale cached material now that the key is deleted.
	if s.keyCache != nil {
		s.keyCache.Invalidate(keyID)
	}

	// Re-read the row so deleted_at is populated from the database.
	deleted, err := s.keyRepo.ReadDeleted(ctx, keyID)
	if err != nil {
		// Non-fatal: return the pre-delete snapshot without metadata.
		s.logger.LogAuditInfo(userID.String(), "delete_key", "success", "Key deleted (metadata unavailable)")
		return key, nil
	}

	s.logger.LogAuditInfo(userID.String(), "delete_key", "success", "Key deleted successfully")
	return deleted, nil
}

// RotateKey rotates an existing key in-place by generating new key material,
// archiving the current and new material into key_versions, and updating the
// key's value field to the freshly generated material.
//
// Unlike the old implementation, rotation does NOT create a new key with a
// "-rotated" suffix. The key identity (ID, name, tags) is preserved.
//
// Parameters:
//
//	ctx: The context for the operation.
//	keyID: The key to rotate.
//	userID: The requesting user's ID for ownership verification.
//
// Returns:
//
//	A CreateKeyResult describing the (unchanged) key identity, or an error.
func (s *keyService) RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*CreateKeyResult, error) {
	// Use Read directly so rotation works even on disabled/expired keys.
	existing, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("rotate key: %w", err)
	}
	if existing.UserID != userID {
		s.logger.LogAuditError(userID.String(), "rotate_key", "forbidden", "key does not belong to user", nil)
		return nil, fmt.Errorf("forbidden: key does not belong to user")
	}

	bits := existing.Bits
	if bits == 0 {
		bits = 2048 // Fallback for keys without stored bit size.
	}
	curve := existing.Curve
	if curve == "" {
		curve = "P-256" // Fallback for keys without stored curve.
	}

	// Generate new key material via the configured provider.
	var newHandle string
	switch existing.Type {
	case model.KeyTypeRSA:
		newHandle, err = s.keyProvider.GenerateRSAKey(ctx, bits)
	case model.KeyTypeECDSA:
		newHandle, err = s.keyProvider.GenerateECDSAKey(ctx, curve)
	case model.KeyTypeES256K:
		newHandle, err = s.keyProvider.GenerateECDSAKey(ctx, "P-256K")
	default:
		s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "unsupported key type for rotation", nil)
		return nil, fmt.Errorf("unsupported key type for rotation: %s", existing.Type)
	}
	if err != nil {
		s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "key generation failed", err)
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	var encryptedNew string
	if isPKCS11Handle(newHandle) {
		encryptedNew = "pkcs11:" + newHandle
	} else {
		encryptedNew, err = common.EncryptSecret(newHandle)
		if err != nil {
			s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "key encryption failed", err)
			return nil, fmt.Errorf("key encryption failed: %w", err)
		}
	}

	// Determine next version number from existing history.
	versions, err := s.keyRepo.ListVersions(ctx, keyID, userID)
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	nextVersion := len(versions) + 1

	// If this is the first rotation, archive the original material as version 1 first.
	if len(versions) == 0 {
		if err := s.keyRepo.CreateVersion(ctx, keyID, 1, existing.Value); err != nil {
			return nil, fmt.Errorf("archive original key version: %w", err)
		}
		nextVersion = 2
	}

	// Archive the new material as the next version.
	if err := s.keyRepo.CreateVersion(ctx, keyID, nextVersion, encryptedNew); err != nil {
		return nil, fmt.Errorf("create new key version: %w", err)
	}

	// Update the key's active value in place.
	existing.Value = encryptedNew
	if err := s.keyRepo.Update(ctx, existing); err != nil {
		return nil, fmt.Errorf("update key value: %w", err)
	}

	// Evict stale cached material now that the key has new material.
	if s.keyCache != nil {
		s.keyCache.Invalidate(keyID)
	}

	s.logger.LogAuditInfo(userID.String(), "rotate_key", "success",
		fmt.Sprintf("Key %s rotated to version %d.", keyID, nextVersion))

	return &CreateKeyResult{
		KeyID:     keyID,
		Name:      existing.Name,
		Type:      existing.Type,
		Tags:      existing.Tags,
		CreatedAt: existing.CreatedAt,
	}, nil
}

// ValidateKeyAccess validates that a user has access to a specific key.
// It handles role-based access control for key operations.
//
// Parameters:
//
//	ctx: The context for the operation.
//	keyID: The key's unique identifier.
//	userID: The requesting user's ID.
//	role: The user's role for permission checking.
//
// Returns:
//
//	An error if access is denied.
func (s *keyService) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	// Admin users have access to all keys
	if role == model.RoleAdmin {
		return nil
	}

	// Non-admin users can only access their own keys
	key, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "validate_key_access", "failed", fmt.Sprintf("key not found: %s", err), err)
		return fmt.Errorf("key not found: %w", err)
	}

	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "validate_key_access", "failed", "forbidden: cannot access other users' keys", nil)
		return fmt.Errorf("forbidden: cannot access other users' keys")
	}

	return nil
}

// isPKCS11Handle returns true when handle is a UUID label returned by the
// PKCS#11 provider rather than a PEM string from the software provider.
func isPKCS11Handle(handle string) bool {
	return len(handle) == 36 &&
		handle[8] == '-' && handle[13] == '-' &&
		handle[18] == '-' && handle[23] == '-'
}
