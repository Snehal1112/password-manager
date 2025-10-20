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

	"password-manager/internal/domain"
	"password-manager/internal/keys"
	"password-manager/internal/logging"
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
	KeyID  uuid.UUID
	Name   *string   // Optional - nil means no change
	Tags   []string  // Optional - empty means no change
	UserID uuid.UUID // For access control
}

// KeyService handles cryptographic key management operations.
// It orchestrates key generation, validation, and access control
// while delegating storage to repositories.
type KeyService interface {
	CreateRSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	CreateECDSAKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResult, error)
	GetKey(ctx context.Context, keyID, userID uuid.UUID) (*keys.Key, error)
	ListKeys(ctx context.Context, userID uuid.UUID) ([]keys.Key, error)
	UpdateKey(ctx context.Context, req UpdateKeyRequest) error
	DeleteKey(ctx context.Context, keyID, userID uuid.UUID) error
	RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*CreateKeyResult, error)
	ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error
}

// keyService implements KeyService by coordinating key operations
// and access control while delegating to repository layer.
type keyService struct {
	keyRepo keys.KeyRepository
	logger  *logging.Logger
}

// KeyServiceConfig holds the dependencies for key service.
type KeyServiceConfig struct {
	KeyRepository keys.KeyRepository
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
// It validates parameters, generates the key, and handles storage.
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

	// Delegate key generation to repository
	key, err := s.keyRepo.GenerateRSA(ctx, req.UserID, req.Name, req.Bits, req.Tags)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_rsa_key", "failed", fmt.Sprintf("failed to generate RSA key: %s", err), err)
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
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
// It validates parameters, generates the key, and handles storage.
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

	// Validate ECDSA-specific parameters
	if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", "invalid ECDSA curve: must be P-256, P-384, or P-521", nil)
		return nil, fmt.Errorf("invalid ECDSA curve: must be P-256, P-384, or P-521")
	}

	// Delegate key generation to repository
	key, err := s.keyRepo.GenerateECDSA(ctx, req.UserID, req.Name, req.Curve, req.Tags)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ecdsa_key", "failed", fmt.Sprintf("failed to generate ECDSA key: %s", err), err)
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
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
func (s *keyService) GetKey(ctx context.Context, keyID, userID uuid.UUID) (*keys.Key, error) {
	key, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_key", "failed", fmt.Sprintf("failed to read key: %s", err), err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	// Access control: users can only access their own keys
	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "get_key", "failed", "forbidden: cannot access other users' keys", nil)
		return nil, fmt.Errorf("forbidden: cannot access other users' keys")
	}

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
func (s *keyService) ListKeys(ctx context.Context, userID uuid.UUID) ([]keys.Key, error) {
	return s.keyRepo.ListByUser(ctx, &userID, "", nil)
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
		return err
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
		return err
	}

	if err := s.keyRepo.Delete(ctx, keyID); err != nil {
		s.logger.LogAuditError(userID.String(), "delete_key", "failed", "Failed to delete key", err)
		return fmt.Errorf("failed to delete key: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "delete_key", "success", "Key deleted successfully")
	return nil
}

// RotateKey creates a new key to replace an existing one.
// It generates a new key with the same properties as the original.
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
		return nil, err
	}

	// Create rotation request based on existing key
	req := CreateKeyRequest{
		Name:   existingKey.Name + "_rotated",
		Type:   existingKey.Type,
		Tags:   existingKey.Tags,
		UserID: userID,
	}

	// Set type-specific parameters
	switch existingKey.Type {
	case "RSA":
		req.Bits = 2048 // Default RSA size for rotation
		return s.CreateRSAKey(ctx, req)
	case "ECDSA":
		req.Curve = "P-256" // Default ECDSA curve for rotation
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
	if role == domain.RoleAdmin {
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
