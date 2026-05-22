package keys

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// SignRequest represents a request to sign data.
type SignRequest struct {
	KeyID     uuid.UUID
	Data      []byte
	Algorithm crypto.SignatureAlgorithm
	UserID    uuid.UUID
}

// SignResult represents the result of a sign operation.
type SignResult struct {
	Signature []byte
	Algorithm crypto.SignatureAlgorithm
	Digest    []byte
	KeyID     uuid.UUID
}

// VerifyRequest represents a request to verify a signature.
type VerifyRequest struct {
	KeyID     uuid.UUID
	Data      []byte
	Signature []byte
	Algorithm crypto.SignatureAlgorithm
	UserID    uuid.UUID
}

// VerifyResult represents the result of a verify operation.
type VerifyResult struct {
	Valid     bool
	Algorithm crypto.SignatureAlgorithm
	KeyID     uuid.UUID
}

// EncryptRequest represents a request to encrypt data.
type EncryptRequest struct {
	KeyID     uuid.UUID
	Data      []byte
	Algorithm crypto.EncryptionAlgorithm
	UserID    uuid.UUID
}

// EncryptResult represents the result of an encrypt operation.
type EncryptResult struct {
	Ciphertext []byte
	Algorithm  crypto.EncryptionAlgorithm
	Nonce      []byte
	KeyID      uuid.UUID
}

// DecryptRequest represents a request to decrypt data.
type DecryptRequest struct {
	KeyID      uuid.UUID
	Ciphertext []byte
	Nonce      []byte
	Algorithm  crypto.EncryptionAlgorithm
	UserID     uuid.UUID
}

// DecryptResult represents the result of a decrypt operation.
type DecryptResult struct {
	Plaintext []byte
	Algorithm crypto.EncryptionAlgorithm
	KeyID     uuid.UUID
}

// WrapKeyRequest is a request to wrap key material with an RSA vault key.
type WrapKeyRequest struct {
	KeyID        uuid.UUID
	UserID       uuid.UUID
	PlaintextKey []byte
	Algorithm    string // must be "RSA-OAEP"
}

// WrapKeyResult holds the wrapped key bytes.
type WrapKeyResult struct {
	WrappedKey []byte
	Algorithm  string
}

// UnwrapKeyRequest is a request to unwrap key material with an RSA vault key.
type UnwrapKeyRequest struct {
	KeyID      uuid.UUID
	UserID     uuid.UUID
	WrappedKey []byte
	Algorithm  string // must be "RSA-OAEP"
}

// UnwrapKeyResult holds the recovered plaintext key bytes.
type UnwrapKeyResult struct {
	PlaintextKey []byte
	Algorithm    string
}

// CryptoService provides cryptographic operations using stored keys.
type CryptoService interface {
	Sign(ctx context.Context, req SignRequest) (*SignResult, error)
	Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error)
	Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResult, error)
	Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResult, error)
	WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error)
	UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (*UnwrapKeyResult, error)
}

// cryptoService implements CryptoService.
type cryptoService struct {
	keyRepo    repositories.KeyRepositoryInterface
	cryptoOps  *crypto.CryptoOperations
	logger     *logging.Logger
}

// CryptoServiceConfig holds dependencies for crypto service.
type CryptoServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	Logger        *logging.Logger
}

// NewCryptoService creates a new crypto service.
func NewCryptoService(config CryptoServiceConfig) CryptoService {
	return &cryptoService{
		keyRepo:   config.KeyRepository,
		cryptoOps: crypto.NewCryptoOperations(),
		logger:    config.Logger,
	}
}

// Sign signs data using the specified key.
func (s *cryptoService) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	// Retrieve and validate key access
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Access control
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "sign", "forbidden",
			fmt.Sprintf("Unauthorized sign attempt with key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Check if key is revoked
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed",
			fmt.Sprintf("Attempted to sign with revoked key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot sign with revoked key")
	}

	// Decrypt the private key
	decryptedKey, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Perform sign operation
	signResult, err := s.cryptoOps.Sign(decryptedKey, key.Type, req.Data, req.Algorithm)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Signing operation failed", err)
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "sign", "success",
		fmt.Sprintf("Data signed with key: %s (algorithm: %s)", req.KeyID, req.Algorithm))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"user_id":   req.UserID,
	}).Info("Data signed successfully")

	return &SignResult{
		Signature: signResult.Signature,
		Algorithm: signResult.Algorithm,
		Digest:    signResult.Digest,
		KeyID:     req.KeyID,
	}, nil
}

// Verify verifies a signature using the specified key.
func (s *cryptoService) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	// Retrieve and validate key access
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Access control
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "verify", "forbidden",
			fmt.Sprintf("Unauthorized verify attempt with key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Decrypt the private key (to extract public key)
	decryptedKey, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Perform verify operation
	verifyResult, err := s.cryptoOps.Verify(decryptedKey, key.Type, req.Data, req.Signature, req.Algorithm)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Verification operation failed", err)
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	status := "valid"
	if !verifyResult.Valid {
		status = "invalid"
	}

	s.logger.LogAuditInfo(req.UserID.String(), "verify", status,
		fmt.Sprintf("Signature verification with key: %s (result: %s)", req.KeyID, status))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"valid":     verifyResult.Valid,
		"user_id":   req.UserID,
	}).Info("Signature verified")

	return &VerifyResult{
		Valid:     verifyResult.Valid,
		Algorithm: verifyResult.Algorithm,
		KeyID:     req.KeyID,
	}, nil
}

// Encrypt encrypts data using the specified key.
func (s *cryptoService) Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResult, error) {
	// Retrieve and validate key access
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Access control
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "forbidden",
			fmt.Sprintf("Unauthorized encrypt attempt with key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Check if key is revoked
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed",
			fmt.Sprintf("Attempted to encrypt with revoked key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot encrypt with revoked key")
	}

	// Decrypt the private key
	decryptedKey, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Perform encrypt operation
	encryptResult, err := s.cryptoOps.Encrypt(decryptedKey, req.Data, req.Algorithm)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Encryption operation failed", err)
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "encrypt", "success",
		fmt.Sprintf("Data encrypted with key: %s (algorithm: %s)", req.KeyID, req.Algorithm))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"user_id":   req.UserID,
	}).Info("Data encrypted successfully")

	return &EncryptResult{
		Ciphertext: encryptResult.Ciphertext,
		Algorithm:  encryptResult.Algorithm,
		Nonce:      encryptResult.Nonce,
		KeyID:      req.KeyID,
	}, nil
}

// Decrypt decrypts data using the specified key.
func (s *cryptoService) Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResult, error) {
	// Retrieve and validate key access
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Access control
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "forbidden",
			fmt.Sprintf("Unauthorized decrypt attempt with key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Decrypt the private key
	decryptedKey, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Perform decrypt operation
	decryptResult, err := s.cryptoOps.Decrypt(decryptedKey, req.Ciphertext, req.Nonce, req.Algorithm)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Decryption operation failed", err)
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "decrypt", "success",
		fmt.Sprintf("Data decrypted with key: %s (algorithm: %s)", req.KeyID, req.Algorithm))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"user_id":   req.UserID,
	}).Info("Data decrypted successfully")

	return &DecryptResult{
		Plaintext: decryptResult.Plaintext,
		Algorithm: decryptResult.Algorithm,
		KeyID:     req.KeyID,
	}, nil
}

// WrapKey encrypts plaintext key material using RSA-OAEP with the specified vault key.
func (s *cryptoService) WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error) {
	if req.Algorithm != "RSA-OAEP" && req.Algorithm != "RSA-OAEP-256" {
		return nil, fmt.Errorf("unsupported algorithm %q: only RSA-OAEP and RSA-OAEP-256 are supported", req.Algorithm)
	}
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "forbidden",
			fmt.Sprintf("unauthorized wrap attempt with key %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed",
			fmt.Sprintf("attempted wrap with revoked key %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot wrap with revoked key")
	}
	decryptedKey, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "failed to decrypt vault key", err)
		return nil, fmt.Errorf("failed to decrypt vault key: %w", err)
	}
	var encAlgo crypto.EncryptionAlgorithm
	if req.Algorithm == "RSA-OAEP-256" {
		encAlgo = crypto.AlgorithmRSAOAEP256
	} else {
		encAlgo = crypto.AlgorithmRSAOAEP
	}
	result, err := s.cryptoOps.Encrypt(decryptedKey, req.PlaintextKey, encAlgo)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "RSA-OAEP wrap failed", err)
		return nil, fmt.Errorf("wrap failed: %w", err)
	}
	s.logger.LogAuditInfo(req.UserID.String(), "wrap_key", "success",
		fmt.Sprintf("key material wrapped with vault key %s", req.KeyID))
	return &WrapKeyResult{WrappedKey: result.Ciphertext, Algorithm: string(result.Algorithm)}, nil
}

// UnwrapKey decrypts wrapped key material using RSA-OAEP with the specified vault key.
func (s *cryptoService) UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (*UnwrapKeyResult, error) {
	if req.Algorithm != "RSA-OAEP" && req.Algorithm != "RSA-OAEP-256" {
		return nil, fmt.Errorf("unsupported algorithm %q: only RSA-OAEP and RSA-OAEP-256 are supported", req.Algorithm)
	}
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "forbidden",
			fmt.Sprintf("unauthorized unwrap attempt with key %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed",
			fmt.Sprintf("attempted unwrap with revoked key %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot unwrap with revoked key")
	}
	decryptedKey, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "failed to decrypt vault key", err)
		return nil, fmt.Errorf("failed to decrypt vault key: %w", err)
	}
	var decAlgo crypto.EncryptionAlgorithm
	if req.Algorithm == "RSA-OAEP-256" {
		decAlgo = crypto.AlgorithmRSAOAEP256
	} else {
		decAlgo = crypto.AlgorithmRSAOAEP
	}
	result, err := s.cryptoOps.Decrypt(decryptedKey, req.WrappedKey, nil, decAlgo)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "RSA-OAEP unwrap failed", err)
		return nil, fmt.Errorf("unwrap failed: %w", err)
	}
	s.logger.LogAuditInfo(req.UserID.String(), "unwrap_key", "success",
		fmt.Sprintf("key material unwrapped with vault key %s", req.KeyID))
	return &UnwrapKeyResult{PlaintextKey: result.Plaintext, Algorithm: string(result.Algorithm)}, nil
}
