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
	Scope     model.Scope // Authorization scope for the read and the write.
	VaultID   uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	UserID    uuid.UUID   // Deprecated: shim field; removed in Phase 6.
	Name      *string     // Optional - nil means no change
	Tags      []string    // Optional - nil means no change; empty slice clears
	Revoked   *bool       // Optional - nil means no change
	Enabled   *bool       // Optional - nil means no change
	ExpiresAt *time.Time  // Optional - nil means no change
	NotBefore *time.Time  // Optional - nil means no change
}

// KeyService handles cryptographic key management operations.
// It orchestrates key generation, validation, and access control
// while delegating storage to repositories.
type KeyService interface {
	CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	// GetKeyScoped retrieves a key authorized by scope and enforces its lifecycle.
	GetKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// ListKeysScoped lists keys authorized by scope and narrowed by filter.
	ListKeysScoped(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error)
	// UpdateKeyScoped updates a key authorized by req.Scope.
	UpdateKeyScoped(ctx context.Context, req UpdateKeyRequest) error
	// DeleteKeyScoped soft-deletes a key authorized by scope.
	DeleteKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	GetKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error)
	ListKeys(ctx context.Context, userID uuid.UUID) ([]model.Key, error)
	ListKeysWithFilters(ctx context.Context, userID *uuid.UUID, keyType string, tags []string, isAdmin bool) ([]model.Key, error)
	UpdateKey(ctx context.Context, req UpdateKeyRequest) error
	// UpdateKeyInVault updates a key scoped to a vault. Any vault member may
	// update any key in the vault (no ownership check).
	UpdateKeyInVault(ctx context.Context, req UpdateKeyRequest) error
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

// GetKeyScoped retrieves a key authorized by scope. The scoped read is the
// access check; a key outside the scope is reported as not found so the
// endpoint is not an existence oracle.
func (s *keyService) GetKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	actor := scope.ActorID().String()
	s.logger.LogAuditInfo(actor, "get_key", "attempt", fmt.Sprintf("Accessing key: %s", keyID))

	key, err := s.keyRepo.ReadScoped(ctx, keyID, scope)
	if err != nil {
		s.logger.LogAuditError(actor, "get_key", "failed", fmt.Sprintf("Key not found: %s", keyID), err)
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	if !key.IsAccessible() {
		s.logger.LogAuditError(actor, "get_key", "denied",
			fmt.Sprintf("Key is disabled or outside its valid time window: %s", keyID), nil)
		return nil, fmt.Errorf("%w", ErrKeyLifecycleDenied)
	}

	logrus.WithFields(logrus.Fields{
		"key_id":   key.ID,
		"key_name": key.Name,
		"key_type": key.Type,
		"scope":    scope.String(),
		"revoked":  key.Revoked,
	}).Info("Key accessed successfully")

	s.logger.LogAuditInfo(actor, "get_key", "success",
		fmt.Sprintf("Key accessed: %s (name: %s, type: %s, revoked: %t)", key.ID, key.Name, key.Type, key.Revoked))

	return key, nil
}

// ListKeysScoped lists keys authorized by scope and narrowed by filter.
func (s *keyService) ListKeysScoped(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	keys, err := s.keyRepo.ListScoped(ctx, scope, filter)
	if err != nil {
		s.logger.LogAuditError(scope.ActorID().String(), "list_keys", "failed", "Failed to list keys", err)
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	logrus.WithFields(logrus.Fields{"scope": scope.String(), "key_count": len(keys)}).Info("Keys listed successfully")
	return keys, nil
}

// UpdateKeyScoped updates a key authorized by req.Scope. It reads with the
// scope directly rather than through GetKeyScoped so operators can still
// re-enable a disabled or expired key.
func (s *keyService) UpdateKeyScoped(ctx context.Context, req UpdateKeyRequest) error {
	actor := req.Scope.ActorID().String()
	logrus.WithFields(logrus.Fields{
		"key_id": req.KeyID.String(),
		"scope":  req.Scope.String(),
	}).Info("Updating key")

	key, err := s.keyRepo.ReadScoped(ctx, req.KeyID, req.Scope)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	updatedKey, err := applyKeyUpdate(key, req)
	if err != nil {
		return err
	}

	if err := s.keyRepo.UpdateScoped(ctx, updatedKey, req.Scope); err != nil {
		s.logger.LogAuditError(actor, "update_key", "failed", "Failed to update key", err)
		return fmt.Errorf("failed to update key: %w", err)
	}

	// Evict stale cached material (covers revoke, disable, and expiry changes).
	if s.keyCache != nil {
		s.keyCache.Invalidate(updatedKey.ID)
	}

	s.logger.LogAuditInfo(actor, "update_key", "success", fmt.Sprintf("Key updated: %s", updatedKey.Name))
	return nil
}

// DeleteKeyScoped soft-deletes a key authorized by scope and returns the
// deleted record so callers can read Azure-style deletion metadata.
func (s *keyService) DeleteKeyScoped(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	actor := scope.ActorID().String()

	key, err := s.keyRepo.ReadScoped(ctx, keyID, scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	// B6 conjunction, P1 only: an owner scope may carry an advisory vault id,
	// and the pre-refactor DeleteKeyInVault required BOTH predicates. A Scope
	// cannot express AND, so the vault half stays in Go until P2 retires
	// ScopeOwner from the data plane.
	if _, ownerScoped := scope.OwnerID(); ownerScoped && scope.VaultID() != uuid.Nil && key.VaultID != scope.VaultID() {
		s.logger.LogAuditError(actor, "delete_key", "forbidden", "key does not belong to the requested vault", nil)
		return nil, fmt.Errorf("%w: key does not belong to the requested vault", ErrKeyNotFound)
	}

	if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
		s.logger.LogAuditError(actor, "delete_key", "failed", "Failed to soft-delete key", err)
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	if s.keyCache != nil {
		s.keyCache.Invalidate(keyID)
	}

	deleted, err := s.keyRepo.ReadDeleted(ctx, keyID)
	if err != nil {
		s.logger.LogAuditInfo(actor, "delete_key", "success", "Key deleted (metadata unavailable)")
		return key, nil
	}

	s.logger.LogAuditInfo(actor, "delete_key", "success", "Key deleted successfully")
	return deleted, nil
}

// Deprecated: shim over GetKeyScoped; removed in Phase 6.
func (s *keyService) GetKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	return s.GetKeyScoped(ctx, keyID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over GetKeyScoped; removed in Phase 6.
func (s *keyService) GetKeyInVault(ctx context.Context, keyID, vaultID uuid.UUID) (*model.Key, error) {
	return s.GetKeyScoped(ctx, keyID, model.NewVaultScope(vaultID, uuid.Nil))
}

// Deprecated: shim over ListKeysScoped; removed in Phase 6.
func (s *keyService) ListKeys(ctx context.Context, userID uuid.UUID) ([]model.Key, error) {
	return s.ListKeysScoped(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.KeyFilter{})
}

// Deprecated: shim over ListKeysScoped; removed in Phase 6.
func (s *keyService) ListKeysInVault(ctx context.Context, vaultID uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	return s.ListKeysScoped(ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.KeyFilter{Type: keyType, Tags: tags})
}

// Deprecated: shim over DeleteKeyScoped; removed in Phase 6.
func (s *keyService) DeleteKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	return s.DeleteKeyScoped(ctx, keyID, model.NewOwnerScope(uuid.Nil, userID))
}

// Deprecated: shim over DeleteKeyScoped; removed in Phase 6. The uuid.Nil
// userID sentinel ("skip the ownership check") maps to a plain vault scope.
func (s *keyService) DeleteKeyInVault(ctx context.Context, keyID, vaultID, userID uuid.UUID) (*model.Key, error) {
	if userID == uuid.Nil {
		return s.DeleteKeyScoped(ctx, keyID, model.NewVaultScope(vaultID, uuid.Nil))
	}
	return s.DeleteKeyScoped(ctx, keyID, model.NewOwnerScope(vaultID, userID))
}

// Deprecated: shim over ListKeysScoped; removed in Phase 6. The isAdmin guard
// is a runtime re-derivation of what the caller already knew; callers migrate
// to model.NewAdminScope in Phase 4.
func (s *keyService) ListKeysWithFilters(ctx context.Context, userID *uuid.UUID, keyType string, tags []string, isAdmin bool) ([]model.Key, error) {
	if !isAdmin && userID == nil {
		s.logger.LogAuditError("unknown", "list_keys_with_filters", "failed", "Non-admin users cannot list all keys", nil)
		return nil, fmt.Errorf("forbidden: non-admin users cannot list all keys")
	}
	scope := model.NewAdminScope(uuid.Nil)
	if userID != nil {
		scope = model.NewOwnerScope(uuid.Nil, *userID)
	}
	return s.ListKeysScoped(ctx, scope, repositories.KeyFilter{Type: keyType, Tags: tags})
}

// Deprecated: shim over UpdateKeyScoped; removed in Phase 6.
func (s *keyService) UpdateKey(ctx context.Context, req UpdateKeyRequest) error {
	req.Scope = model.NewOwnerScope(uuid.Nil, req.UserID)
	return s.UpdateKeyScoped(ctx, req)
}

// Deprecated: shim over UpdateKeyScoped; removed in Phase 6.
func (s *keyService) UpdateKeyInVault(ctx context.Context, req UpdateKeyRequest) error {
	req.Scope = model.NewVaultScope(req.VaultID, req.UserID)
	return s.UpdateKeyScoped(ctx, req)
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
