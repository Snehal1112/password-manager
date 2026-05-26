// Package keys provides key management services for the password manager.
// It handles cryptographic key generation, lifecycle, and access control
// while maintaining proper separation of concerns.
package keys

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// CreateKeyRequest represents a request to create a new cryptographic key.
type CreateKeyRequest struct {
	Name   string
	Type   string // "RSA" or "ECDSA"
	Bits   int    // For RSA: 2048 or 4096
	Curve  string // For ECDSA: P-256, P-384, P-521
	Tags   []string
	UserID uuid.UUID
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
	KeyID   uuid.UUID
	Name    *string   // Optional - nil means no change
	Tags    []string  // Optional - empty means no change
	Revoked *bool     // Optional - nil means no change
	UserID  uuid.UUID // For access control
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
	DeleteKey(ctx context.Context, keyID, userID uuid.UUID) error
	RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*CreateKeyResult, error)
	ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error
}

// keyService implements KeyService by coordinating key operations
// and access control while delegating to repository layer.
type keyService struct {
	keyRepo repositories.KeyRepositoryInterface
	logger  *logging.Logger
}

// KeyServiceConfig holds the dependencies for key service.
type KeyServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	Logger        *logging.Logger
}

// NewKeyService creates a new KeyService with the provided dependencies.
// It orchestrates key management operations while maintaining SRP compliance.
//
// Parameters:
//   config: Configuration containing all required dependencies.
//
// Returns:
//   A KeyService implementation for key management operations.
func NewKeyService(config KeyServiceConfig) KeyService {
	return &keyService{
		keyRepo: config.KeyRepository,
		logger:  config.Logger,
	}
}

// CreateRSAKey creates a new RSA cryptographic key.
// It validates parameters, generates the key, encrypts it, and handles storage.
//
// Parameters:
//   ctx: The context for the operation.
//   req: The key creation request with RSA-specific parameters.
//
// Returns:
//   The created key information or an error if creation fails.
func (s *keyService) CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":    req.Name,
		"type":    req.Type,
		"bits":    req.Bits,
		"user_id": req.UserID.String(),
	}).Info("Creating RSA key")

	// Validate RSA-specific parameters
	if req.Bits != 2048 && req.Bits != 4096 {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "invalid RSA key size: must be 2048 or 4096", nil)
		return nil, fmt.Errorf("invalid RSA key size: must be 2048 or 4096")
	}

	// Generate RSA key using crypto helper
	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(req.Bits)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to generate RSA key", err)
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encrypt the private key
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", "failed to encrypt key", err)
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	// Create key entity.
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		Name:      req.Name,
		Type:      model.KeyTypeRSA,
		Value:     encryptedKey,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   true,
		Bits:      req.Bits,
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
//   ctx: The context for the operation.
//   req: The key creation request with ECDSA-specific parameters.
//
// Returns:
//   The created key information or an error if creation fails.
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

	// Generate ECDSA key using crypto helper
	privateKeyPEM, err := crypto.GenerateECDSAKeyPEM(req.Curve)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to generate ECDSA key", err)
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Encrypt the private key
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "failed to encrypt key", err)
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	// P-256K keys use a distinct type so the crypto layer routes them correctly.
	keyType := model.KeyTypeECDSA
	if req.Curve == "P-256K" {
		keyType = model.KeyTypeES256K
	}

	// Create key entity.
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    req.UserID,
		Name:      req.Name,
		Type:      keyType,
		Value:     encryptedKey,
		Revoked:   false,
		CreatedAt: time.Now(),
		Tags:      req.Tags,
		Enabled:   true,
		Curve:     req.Curve,
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
//   ctx: The context for the operation.
//   keyID: The key's unique identifier.
//   userID: The requesting user's ID for access control.
//
// Returns:
//   The key information or an error if not found or access denied.
func (s *keyService) GetKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	// Log key access attempt with detailed context
	s.logger.LogAuditInfo(userID.String(), "get_key", "attempt",
		fmt.Sprintf("Accessing key: %s", keyID))

	key, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_key", "failed",
			fmt.Sprintf("Key not found: %s", keyID), err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	// Access control: users can only access their own keys.
	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "get_key", "forbidden",
			fmt.Sprintf("Unauthorized access attempt to key: %s (owner: %s)",
				keyID, key.UserID), nil)
		return nil, fmt.Errorf("forbidden: cannot access other users' keys")
	}

	// Enforce lifecycle policy: key must be enabled and within its validity window.
	if !key.IsAccessible() {
		s.logger.LogAuditError(userID.String(), "get_key", "denied",
			fmt.Sprintf("Key is disabled or outside its valid time window: %s", keyID), nil)
		return nil, fmt.Errorf("key is disabled or outside its valid time window")
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
//   ctx: The context for the operation.
//   userID: The user's unique identifier.
//
// Returns:
//   A slice of user's keys or an error if retrieval fails.
func (s *keyService) ListKeys(ctx context.Context, userID uuid.UUID) ([]model.Key, error) {
	return s.keyRepo.ListByUser(ctx, &userID, "", nil)
}

// ListKeysWithFilters retrieves keys with optional filtering by type and tags.
// Supports admin mode where userID can be nil to list all keys in the system.
//
// Parameters:
//   ctx: The context for the operation.
//   userID: Optional user ID - nil for admin queries to list all keys.
//   keyType: Optional key type filter (RSA, ECDSA) - empty string means no filter.
//   tags: Optional tag filter - empty slice means no filter.
//   isAdmin: Whether the requester has admin privileges.
//
// Returns:
//   A slice of keys matching the filters or an error if retrieval fails.
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
//   ctx: The context for the operation.
//   req: The key update request with optional fields.
//
// Returns:
//   An error if the update fails or access is denied.
func (s *keyService) UpdateKey(ctx context.Context, req UpdateKeyRequest) error {
	logrus.WithField("key_id", req.KeyID.String()).Info("Updating key")

	// Verify key exists and access
	key, err := s.GetKey(ctx, req.KeyID, req.UserID)
	if err != nil {
		return fmt.Errorf("update key: %w", err)
	}

	// Prepare updated key
	updatedKey := *key

	// Update name if provided
	if req.Name != nil {
		updatedKey.Name = *req.Name
	}

	// Update tags if provided
	if len(req.Tags) > 0 {
		updatedKey.Tags = req.Tags
	}

	// Update revocation status if provided.
	if req.Revoked != nil {
		updatedKey.Revoked = *req.Revoked
	}

	// Update key via repository
	if err := s.keyRepo.Update(ctx, &updatedKey); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_key", "failed", "Failed to update key", err)
		return fmt.Errorf("failed to update key: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "update_key", "success", fmt.Sprintf("Key updated: %s", updatedKey.Name))
	return nil
}

// DeleteKey removes a key from the system with access control validation.
//
// Parameters:
//   ctx: The context for the operation.
//   keyID: The key's unique identifier.
//   userID: The requesting user's ID for access control.
//
// Returns:
//   An error if deletion fails or access is denied.
func (s *keyService) DeleteKey(ctx context.Context, keyID, userID uuid.UUID) error {
	// Verify key exists and access
	if _, err := s.GetKey(ctx, keyID, userID); err != nil {
		return fmt.Errorf("delete key: %w", err)
	}

	if err := s.keyRepo.SoftDelete(ctx, keyID); err != nil {
		s.logger.LogAuditError(userID.String(), "delete_key", "failed", "Failed to soft-delete key", err)
		return fmt.Errorf("failed to delete key: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "delete_key", "success", "Key deleted successfully")
	return nil
}

// RotateKey creates a new key to replace an existing one.
// It marks the old key as revoked and generates a new key with the same properties.
//
// Parameters:
//   ctx: The context for the operation.
//   keyID: The key to rotate.
//   userID: The requesting user's ID for access control.
//
// Returns:
//   The new key information or an error if rotation fails.
func (s *keyService) RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*CreateKeyResult, error) {
	// Get existing key
	existingKey, err := s.GetKey(ctx, keyID, userID)
	if err != nil {
		return nil, fmt.Errorf("rotate key: %w", err)
	}

	// Mark old key as revoked
	if err := s.keyRepo.UpdateRevocationStatus(ctx, keyID, true); err != nil {
		s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "failed to revoke old key", err)
		return nil, fmt.Errorf("failed to revoke old key: %w", err)
	}

	// Create rotation request based on existing key
	req := CreateKeyRequest{
		Name:   existingKey.Name + "-rotated",
		Type:   existingKey.Type,
		Tags:   existingKey.Tags,
		UserID: userID,
	}

	// Set type-specific parameters and create new key
	switch existingKey.Type {
	case model.KeyTypeRSA:
		req.Bits = 2048 // Default RSA size for rotation.
		return s.CreateRSAKey(ctx, req)
	case model.KeyTypeECDSA:
		req.Curve = "P-256" // Default ECDSA curve for rotation.
		return s.CreateECDSAKey(ctx, req)
	case model.KeyTypeES256K:
		req.Curve = "P-256K" // Keep the same curve family on rotation.
		return s.CreateECDSAKey(ctx, req)
	default:
		s.logger.LogAuditError(userID.String(), "rotate_key", "failed", "unsupported key type for rotation", nil)
		return nil, fmt.Errorf("unsupported key type for rotation: %s", existingKey.Type)
	}
}

// ValidateKeyAccess validates that a user has access to a specific key.
// It handles role-based access control for key operations.
//
// Parameters:
//   ctx: The context for the operation.
//   keyID: The key's unique identifier.
//   userID: The requesting user's ID.
//   role: The user's role for permission checking.
//
// Returns:
//   An error if access is denied.
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
