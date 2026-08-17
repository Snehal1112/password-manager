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
	// CreateOctKey creates a symmetric AES key. HSM-only — see
	// crypto.ErrOctKeysRequireHSM.
	CreateOctKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	// GetKey retrieves a key authorized by scope and enforces its lifecycle.
	GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// ListKeys lists keys authorized by scope and narrowed by filter.
	ListKeys(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error)
	// UpdateKey updates a key authorized by req.Scope.
	UpdateKey(ctx context.Context, req UpdateKeyRequest) error
	// DeleteKey soft-deletes a key authorized by scope.
	DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error)
	// RotateKey rotates a key authorized by scope.
	RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*CreateKeyResult, error)
	// ListDeletedKeys lists soft-deleted keys authorized by scope.
	ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error)
	// RecoverKey restores a soft-deleted key authorized by scope.
	RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	// PurgeKey permanently deletes a soft-deleted key authorized by scope.
	PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error
	// GetKeyRotationPolicy retrieves the rotation policy for keyID, authorized
	// by scope against the parent key.
	GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error)
	// UpsertKeyRotationPolicy creates or replaces the rotation policy for
	// keyID, authorized by scope against the parent key.
	UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error)
	// DeleteKeyRotationPolicy removes the rotation policy for keyID,
	// authorized by scope against the parent key.
	DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	// ListKeyVersions returns keyID's version history, authorized by scope
	// against the parent key. Resolving the owner from the authorized key
	// (not the caller's own id) keeps vault-member access consistent with
	// GetKey, since KeyRepository.ListVersions filters on owner with no
	// vault predicate.
	ListKeyVersions(ctx context.Context, keyID uuid.UUID, scope model.Scope) ([]model.KeyVersion, error)
}

// keyService implements KeyService by coordinating key operations
// and access control while delegating to repository layer.
type keyService struct {
	keyRepo     repositories.KeyRepositoryInterface
	keyProvider crypto.KeyProvider
	keyCache    keycache.Cache
	policyRepo  repositories.KeyRotationPolicyRepositoryInterface
	logger      *logging.Logger
}

// KeyServiceConfig holds the dependencies for key service.
type KeyServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	KeyProvider   crypto.KeyProvider
	// KeyCache is optional. When nil, a NopCache is used and mutations still
	// call Invalidate (which is a no-op on NopCache).
	KeyCache         keycache.Cache
	PolicyRepository repositories.KeyRotationPolicyRepositoryInterface
	Logger           *logging.Logger
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
		policyRepo:  config.PolicyRepository,
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

// CreateOctKey creates a new symmetric AES key. Requires an HSM-backed key
// provider — see crypto.ErrOctKeysRequireHSM.
func (s *keyService) CreateOctKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"bits":    req.Bits,
		"user_id": req.UserID.String(),
	}).Info("Creating AES (oct) key")

	if req.Bits != 128 && req.Bits != 192 && req.Bits != 256 {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "invalid AES key size: must be 128, 192, or 256", nil)
		return nil, fmt.Errorf("invalid AES key size: must be 128, 192, or 256")
	}

	handle, err := s.keyProvider.GenerateAESKey(ctx, req.Bits)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "failed to generate AES key", err)
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// AES keys are HSM-only: GenerateAESKey never returns a software (PEM)
	// handle, so the value is always the PKCS#11 label — no plaintext key
	// material ever reaches this process.
	storedValue := "pkcs11:" + handle

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		VaultID:   resolveVaultID(req.VaultID),
		Name:      req.Name,
		Type:      model.KeyTypeOct,
		Value:     storedValue,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   enabled,
		Bits:      req.Bits,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	if err := s.keyRepo.Create(ctx, key); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_oct_key", "failed", "failed to store key", err)
		return nil, fmt.Errorf("failed to store AES key: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_oct_key", "success", fmt.Sprintf("AES key created: %s, ID: %s", req.Name, key.ID))

	return &CreateKeyResult{
		KeyID:     key.ID,
		Name:      key.Name,
		Type:      key.Type,
		Tags:      key.Tags,
		CreatedAt: key.CreatedAt,
	}, nil
}

// GetKey retrieves a key authorized by scope. The scoped read is the
// access check; a key outside the scope is reported as not found so the
// endpoint is not an existence oracle.
func (s *keyService) GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	actor := scope.ActorID().String()
	s.logger.LogAuditInfo(actor, "get_key", "attempt", fmt.Sprintf("Accessing key: %s", keyID))

	key, err := s.keyRepo.Read(ctx, keyID, scope)
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

// ListKeyVersions returns keyID's version history, authorized by scope
// against the parent key. Resolving the owner from the authorized key (not
// the caller's own id) keeps vault-member access consistent with GetKey,
// since KeyRepository.ListVersions filters on owner with no vault predicate.
func (s *keyService) ListKeyVersions(ctx context.Context, keyID uuid.UUID, scope model.Scope) ([]model.KeyVersion, error) {
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}
	return s.keyRepo.ListVersions(ctx, keyID, key.UserID)
}

// GetKeyRotationPolicy retrieves the rotation policy for keyID, authorized by
// scope against the parent key.
func (s *keyService) GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByKeyID(ctx, keyID, scope)
}

// UpsertKeyRotationPolicy creates or replaces the rotation policy for keyID,
// authorized by scope against the parent key.
func (s *keyService) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	key, err := s.GetKey(ctx, keyID, scope)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	// Preserve an existing policy's rotation history: an Upsert that only
	// changes e.g. notify_before_expiry_days must not reset the due-date
	// clock an earlier automatic rotation already advanced.
	var lastRotatedAt *time.Time
	baseline := key.CreatedAt
	if existing, err := s.policyRepo.GetByKeyID(ctx, keyID, scope); err == nil && existing != nil {
		lastRotatedAt = existing.LastRotatedAt
		if lastRotatedAt != nil {
			baseline = *lastRotatedAt
		}
	}

	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 scope.ActorID(),
		VaultID:                key.VaultID, // derived from the parent key, never from the caller
		RotateAfterDays:        req.RotateAfterDays,
		NotifyBeforeExpiryDays: req.NotifyBeforeExpiryDays,
		ExpiryDays:             req.ExpiryDays,
		Enabled:                req.Enabled,
		LastRotatedAt:          lastRotatedAt,
		NextRotationAt:         baseline.AddDate(0, 0, req.RotateAfterDays),
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, err
	}
	// Read-after-write so the caller gets the canonical stored row.
	return s.policyRepo.GetByKeyID(ctx, keyID, scope)
}

// DeleteKeyRotationPolicy removes the rotation policy for keyID, authorized
// by scope against the parent key.
func (s *keyService) DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return err
	}
	return s.policyRepo.DeleteByKeyID(ctx, keyID, scope)
}

// ListKeys lists keys authorized by scope and narrowed by filter.
func (s *keyService) ListKeys(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	keys, err := s.keyRepo.List(ctx, scope, filter)
	if err != nil {
		s.logger.LogAuditError(scope.ActorID().String(), "list_keys", "failed", "Failed to list keys", err)
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	logrus.WithFields(logrus.Fields{"scope": scope.String(), "key_count": len(keys)}).Info("Keys listed successfully")
	return keys, nil
}

// UpdateKey updates a key authorized by req.Scope. It reads with the
// scope directly rather than through GetKey so operators can still
// re-enable a disabled or expired key.
func (s *keyService) UpdateKey(ctx context.Context, req UpdateKeyRequest) error {
	actor := req.Scope.ActorID().String()
	logrus.WithFields(logrus.Fields{
		"key_id": req.KeyID.String(),
		"scope":  req.Scope.String(),
	}).Info("Updating key")

	key, err := s.keyRepo.Read(ctx, req.KeyID, req.Scope)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	updatedKey, err := applyKeyUpdate(key, req)
	if err != nil {
		return err
	}

	if err := s.keyRepo.Update(ctx, updatedKey, req.Scope); err != nil {
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

// DeleteKey soft-deletes a key authorized by scope and returns the
// deleted record so callers can read Azure-style deletion metadata.
func (s *keyService) DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	actor := scope.ActorID().String()

	key, err := s.keyRepo.Read(ctx, keyID, scope)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, err.Error())
	}

	// B6 conjunction, P1 only: an owner scope may carry an advisory vault id,
	// and the pre-refactor two-argument delete (key ID plus vault ID) required
	// BOTH predicates. A Scope cannot express AND, so the vault half stays in
	// Go until P2 retires ScopeOwner from the data plane.
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

// keyDeletedInScope reports whether keyID names a soft-deleted key the scope
// authorizes.
func (s *keyService) keyDeletedInScope(ctx context.Context, keyID uuid.UUID, scope model.Scope) (bool, error) {
	deleted, err := s.keyRepo.List(ctx, scope, repositories.KeyFilter{OnlyDeleted: true})
	if err != nil {
		return false, fmt.Errorf("failed to list deleted keys: %w", err)
	}
	for _, key := range deleted {
		if key.ID == keyID {
			return true, nil
		}
	}
	return false, nil
}

// ListDeletedKeys lists soft-deleted keys authorized by scope.
func (s *keyService) ListDeletedKeys(ctx context.Context, scope model.Scope) ([]model.Key, error) {
	keys, err := s.keyRepo.List(ctx, scope, repositories.KeyFilter{OnlyDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted keys: %w", err)
	}
	return keys, nil
}

// RecoverKey restores a soft-deleted key authorized by scope.
func (s *keyService) RecoverKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	inScope, err := s.keyDeletedInScope(ctx, keyID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "recover_key", "failed",
			"Key not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrKeyNotFound)
	}
	if err := s.keyRepo.RecoverKey(ctx, keyID); err != nil {
		return fmt.Errorf("failed to recover key: %w", err)
	}
	return nil
}

// PurgeKey permanently deletes a soft-deleted key authorized by scope.
func (s *keyService) PurgeKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	inScope, err := s.keyDeletedInScope(ctx, keyID, scope)
	if err != nil {
		return err
	}
	if !inScope {
		s.logger.LogAuditError(scope.ActorID().String(), "purge_key", "failed",
			"Key not found in deleted state within scope", nil)
		return fmt.Errorf("%w", ErrKeyNotFound)
	}
	if err := s.keyRepo.PurgeKey(ctx, keyID); err != nil {
		return fmt.Errorf("failed to purge key: %w", err)
	}
	return nil
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
//	scope: The authorization scope for the read and the write.
//
// Returns:
//
//	A CreateKeyResult describing the (unchanged) key identity, or an error.
func (s *keyService) RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*CreateKeyResult, error) {
	userID := scope.ActorID()

	// Read with the scope directly rather than through GetKey, matching
	// UpdateKey: rotation must still work on a disabled or expired key. The
	// scoped read is the access check -- there is no separate in-Go ownership
	// comparison.
	existing, err := s.keyRepo.Read(ctx, keyID, scope)
	if err != nil {
		return nil, fmt.Errorf("rotate key: %w", err)
	}

	// B6 conjunction, P1 only: identical to DeleteKey. An owner scope may
	// carry an advisory vault id, and a Scope cannot express AND, so the vault
	// half of "owner AND vault" stays in Go until P2 retires ScopeOwner from
	// the data plane. Without it, rotate on a vault-scoped route would ignore
	// the vault entirely.
	if _, ownerScoped := scope.OwnerID(); ownerScoped && scope.VaultID() != uuid.Nil && existing.VaultID != scope.VaultID() {
		s.logger.LogAuditError(userID.String(), "rotate_key", "forbidden", "key does not belong to the requested vault", nil)
		return nil, fmt.Errorf("%w: key does not belong to the requested vault", ErrKeyNotFound)
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

	// Determine next version number from existing history. ListVersions joins
	// on the key's owner, so pass the owner of the row the scope just
	// authorized rather than the acting principal — they differ under an
	// admin scope.
	versions, err := s.keyRepo.ListVersions(ctx, keyID, existing.UserID)
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

	// Update the key's active value in place, repeating the scope predicate
	// that authorized the read.
	existing.Value = encryptedNew
	if err := s.keyRepo.Update(ctx, existing, scope); err != nil {
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
	key, err := s.keyRepo.Read(ctx, keyID, model.NewAdminScope(userID))
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
