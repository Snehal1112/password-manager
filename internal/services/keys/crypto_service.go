package keys

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	"rocketvault/model"
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
	Algorithm    string // must be one of: RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, A256KW, A128CBC, A192CBC, A256CBC
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
	Algorithm  string // must be one of: RSA-OAEP, RSA-OAEP-256, A128KW, A192KW, A256KW, A128CBC, A192CBC, A256CBC
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
	keyRepo       repositories.KeyRepositoryInterface
	cryptoOps     *crypto.CryptoOperations
	keyProvider   crypto.KeyProvider
	logger        *logging.Logger
	keyCache      keycache.Cache
	cryptoMetrics metrics.CryptoMetrics
	cfg           CryptoServiceConfig
}

// CryptoServiceConfig holds dependencies for crypto service.
type CryptoServiceConfig struct {
	KeyRepository repositories.KeyRepositoryInterface
	KeyProvider   crypto.KeyProvider
	Logger        *logging.Logger
	// KeyCache is optional; nil defaults to NopCache (no caching).
	KeyCache keycache.Cache
	// CryptoMetrics is optional; nil defaults to NopCryptoMetrics (no metrics).
	CryptoMetrics metrics.CryptoMetrics
	// CacheConfig controls TTL and eviction; nil defaults to DefaultKeyCacheConfig.
	CacheConfig *keycache.KeyCacheConfig
}

// NewCryptoService creates a new crypto service.
func NewCryptoService(config CryptoServiceConfig) CryptoService {
	if config.KeyCache == nil {
		config.KeyCache = keycache.NewNopCache()
	}
	if config.CryptoMetrics == nil {
		config.CryptoMetrics = metrics.NewNopCryptoMetrics()
	}
	if config.CacheConfig == nil {
		config.CacheConfig = keycache.DefaultKeyCacheConfig()
	}
	return &cryptoService{
		keyRepo:       config.KeyRepository,
		cryptoOps:     crypto.NewCryptoOperations(),
		keyProvider:   config.KeyProvider,
		logger:        config.Logger,
		keyCache:      config.KeyCache,
		cryptoMetrics: config.CryptoMetrics,
		cfg:           config,
	}
}

const pkcs11Prefix = "pkcs11:"

// resolveKeyHandle decodes the stored key value into a plain handle string.
// For software keys, it AES-GCM decrypts the stored PEM. For PKCS#11 keys,
// it strips the "pkcs11:" prefix and returns the bare UUID label.
// The boolean return is true when the handle refers to a PKCS#11 key.
func resolveKeyHandle(storedValue string) (handle string, isPKCS11 bool, err error) {
	if strings.HasPrefix(storedValue, pkcs11Prefix) {
		return strings.TrimPrefix(storedValue, pkcs11Prefix), true, nil
	}
	decrypted, decErr := common.DecryptSecret(storedValue)
	if decErr != nil {
		return "", false, fmt.Errorf("failed to decrypt key: %w", decErr)
	}
	return decrypted, false, nil
}

// resolveKeyMaterial returns decrypted PEM key material from cache (hit) or via
// AES-GCM decrypt (miss). For PKCS#11 keys the material is the raw token handle
// and caching is skipped entirely. On a cache hit, handle contains the decrypted
// PEM string stored earlier.
func (s *cryptoService) resolveKeyMaterial(key *model.Key) (
	handle   string,
	isPKCS11 bool,
	cacheHit bool,
	err      error,
) {
	// PKCS#11 keys store the token handle directly; never cache them.
	if strings.HasPrefix(key.Value, pkcs11Prefix) {
		handle = strings.TrimPrefix(key.Value, pkcs11Prefix)
		isPKCS11 = true
		return
	}

	// Check cache using keyID and version 0 (model.Key has no version field).
	if entry, ok := s.keyCache.Get(key.ID, 0); ok {
		if pem, ok := entry.PrivateKey.(string); ok {
			handle = pem
			cacheHit = true
			return
		}
	}

	// Cache miss: AES-GCM decrypt the stored PEM.
	decrypted, decErr := common.DecryptSecret(key.Value)
	if decErr != nil {
		err = fmt.Errorf("failed to decrypt key: %w", decErr)
		return
	}

	// Store decrypted PEM in cache for subsequent calls.
	s.keyCache.Set(key.ID, 0, &keycache.Entry{
		PrivateKey: decrypted, // PEM string stored as crypto.PrivateKey (any).
		KeyType:    key.Type,
		Version:    0,
		ExpiresAt:  time.Now().Add(s.cfg.CacheConfig.TTL),
	})

	handle = decrypted
	return
}

// Sign signs data using the specified key.
func (s *cryptoService) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	start := time.Now()

	// Retrieve and validate key access.
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Access control.
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "sign", "forbidden",
			fmt.Sprintf("Unauthorized sign attempt with key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Check if key is revoked.
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed",
			fmt.Sprintf("Attempted to sign with revoked key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot sign with revoked key")
	}

	// Check if key is accessible (enabled and within validity window).
	if !key.IsAccessible() {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed",
			fmt.Sprintf("Attempted sign with inaccessible key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot sign with disabled or expired key")
	}

	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Failed to resolve key handle", err)
		return nil, err
	}
	defer s.cryptoMetrics.RecordOp("sign", key.Type, cacheHit, time.Since(start))

	var signature, digest []byte
	if isPKCS11 {
		if s.keyProvider == nil {
			return nil, fmt.Errorf("no HSM key provider configured")
		}
		signature, err = s.keyProvider.Sign(ctx, handle, key.Type, req.Data, req.Algorithm)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "PKCS#11 signing failed", err)
			return nil, fmt.Errorf("signing failed: %w", err)
		}
	} else {
		signResult, signErr := s.cryptoOps.Sign(handle, key.Type, req.Data, req.Algorithm)
		if signErr != nil {
			s.logger.LogAuditError(req.UserID.String(), "sign", "failed", "Signing operation failed", signErr)
			return nil, fmt.Errorf("signing failed: %w", signErr)
		}
		signature = signResult.Signature
		digest = signResult.Digest
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
		Signature: signature,
		Algorithm: req.Algorithm,
		Digest:    digest,
		KeyID:     req.KeyID,
	}, nil
}

// Verify verifies a signature using the specified key.
func (s *cryptoService) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	start := time.Now()

	// Retrieve and validate key access.
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Access control.
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "verify", "forbidden",
			fmt.Sprintf("Unauthorized verify attempt with key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Check if key is revoked.
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed",
			fmt.Sprintf("Attempted to verify with revoked key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot verify with revoked key")
	}

	// Check if key is accessible (enabled and within validity window).
	if !key.IsAccessible() {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed",
			fmt.Sprintf("Attempted verify with inaccessible key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot verify with disabled or expired key")
	}

	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Failed to resolve key handle", err)
		return nil, err
	}
	defer s.cryptoMetrics.RecordOp("verify", key.Type, cacheHit, time.Since(start))

	var valid bool
	if isPKCS11 {
		valid, err = s.keyProvider.Verify(ctx, handle, key.Type, req.Data, req.Signature, req.Algorithm)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "PKCS#11 verification failed", err)
			return nil, fmt.Errorf("verification failed: %w", err)
		}
	} else {
		verifyResult, verifyErr := s.cryptoOps.Verify(handle, key.Type, req.Data, req.Signature, req.Algorithm)
		if verifyErr != nil {
			s.logger.LogAuditError(req.UserID.String(), "verify", "failed", "Verification operation failed", verifyErr)
			return nil, fmt.Errorf("verification failed: %w", verifyErr)
		}
		valid = verifyResult.Valid
	}

	status := "valid"
	if !valid {
		status = "invalid"
	}

	s.logger.LogAuditInfo(req.UserID.String(), "verify", status,
		fmt.Sprintf("Signature verification with key: %s (result: %s)", req.KeyID, status))

	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"key_type":  key.Type,
		"algorithm": req.Algorithm,
		"valid":     valid,
		"user_id":   req.UserID,
	}).Info("Signature verified")

	return &VerifyResult{
		Valid:     valid,
		Algorithm: req.Algorithm,
		KeyID:     req.KeyID,
	}, nil
}

// Encrypt encrypts data using the specified key.
func (s *cryptoService) Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResult, error) {
	start := time.Now()

	// Retrieve and validate key access.
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Access control.
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "forbidden",
			fmt.Sprintf("Unauthorized encrypt attempt with key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Check if key is revoked.
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed",
			fmt.Sprintf("Attempted to encrypt with revoked key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot encrypt with revoked key")
	}

	// Check if key is accessible (enabled and within validity window).
	if !key.IsAccessible() {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed",
			fmt.Sprintf("Attempted encrypt with inaccessible key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot encrypt with disabled or expired key")
	}

	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Failed to resolve key handle", err)
		return nil, err
	}
	defer s.cryptoMetrics.RecordOp("encrypt", key.Type, cacheHit, time.Since(start))

	var ct, nonce []byte
	if isPKCS11 {
		ct, nonce, err = s.keyProvider.Encrypt(ctx, handle, req.Data, req.Algorithm)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "PKCS#11 encryption failed", err)
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
	} else {
		encResult, encErr := s.cryptoOps.Encrypt(handle, req.Data, req.Algorithm)
		if encErr != nil {
			s.logger.LogAuditError(req.UserID.String(), "encrypt", "failed", "Encryption operation failed", encErr)
			return nil, fmt.Errorf("encryption failed: %w", encErr)
		}
		ct = encResult.Ciphertext
		nonce = encResult.Nonce
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
		Ciphertext: ct,
		Algorithm:  req.Algorithm,
		Nonce:      nonce,
		KeyID:      req.KeyID,
	}, nil
}

// Decrypt decrypts data using the specified key.
func (s *cryptoService) Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResult, error) {
	start := time.Now()

	// Retrieve and validate key access.
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Key not found", err)
		return nil, fmt.Errorf("key not found: %w", err)
	}

	// Access control.
	if key.UserID != req.UserID {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "forbidden",
			fmt.Sprintf("Unauthorized decrypt attempt with key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("forbidden: cannot use other users' keys")
	}

	// Check if key is revoked.
	if key.Revoked {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed",
			fmt.Sprintf("Attempted to decrypt with revoked key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot decrypt with revoked key")
	}

	// Check if key is accessible (enabled and within validity window).
	if !key.IsAccessible() {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed",
			fmt.Sprintf("Attempted decrypt with inaccessible key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot decrypt with disabled or expired key")
	}

	handle, isPKCS11, cacheHit, err := s.resolveKeyMaterial(key)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Failed to resolve key handle", err)
		return nil, err
	}
	defer s.cryptoMetrics.RecordOp("decrypt", key.Type, cacheHit, time.Since(start))

	var plaintext []byte
	if isPKCS11 {
		plaintext, err = s.keyProvider.Decrypt(ctx, handle, req.Ciphertext, req.Nonce, req.Algorithm)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "PKCS#11 decryption failed", err)
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
	} else {
		decResult, decErr := s.cryptoOps.Decrypt(handle, req.Ciphertext, req.Nonce, req.Algorithm)
		if decErr != nil {
			s.logger.LogAuditError(req.UserID.String(), "decrypt", "failed", "Decryption operation failed", decErr)
			return nil, fmt.Errorf("decryption failed: %w", decErr)
		}
		plaintext = decResult.Plaintext
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
		Plaintext: plaintext,
		Algorithm: req.Algorithm,
		KeyID:     req.KeyID,
	}, nil
}

// WrapKey encrypts plaintext key material using RSA-OAEP, RSA-OAEP-256, AES-KW, or AES-CBC with the specified vault key.
func (s *cryptoService) WrapKey(ctx context.Context, req WrapKeyRequest) (*WrapKeyResult, error) {
	start := time.Now()

	validWrapAlgorithms := map[string]bool{
		"RSA-OAEP": true, "RSA-OAEP-256": true,
		"A128KW": true, "A192KW": true, "A256KW": true,
		"A128CBC": true, "A192CBC": true, "A256CBC": true,
	}
	if !validWrapAlgorithms[req.Algorithm] {
		return nil, fmt.Errorf("unsupported wrap algorithm %q", req.Algorithm)
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

	// Check if key is accessible (enabled and within validity window).
	if !key.IsAccessible() {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed",
			fmt.Sprintf("Attempted wrap_key with inaccessible key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot wrap_key with disabled or expired key")
	}

	wrapHandle, wrapIsPKCS11, cacheHit, err := s.resolveKeyMaterial(key)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "failed to resolve vault key handle", err)
		return nil, err
	}
	defer s.cryptoMetrics.RecordOp("wrap_key", key.Type, cacheHit, time.Since(start))
	var encAlgo crypto.EncryptionAlgorithm
	switch req.Algorithm {
	case "RSA-OAEP-256":
		encAlgo = crypto.AlgorithmRSAOAEP256
	case "RSA-OAEP":
		encAlgo = crypto.AlgorithmRSAOAEP
	case "A128KW":
		encAlgo = crypto.AlgorithmA128KW
	case "A192KW":
		encAlgo = crypto.AlgorithmA192KW
	case "A256KW":
		encAlgo = crypto.AlgorithmA256KW
	case "A128CBC":
		encAlgo = crypto.AlgorithmA128CBC
	case "A192CBC":
		encAlgo = crypto.AlgorithmA192CBC
	case "A256CBC":
		encAlgo = crypto.AlgorithmA256CBC
	}
	// AES wrap/unwrap requires a software key; HSM keys only support RSA-OAEP variants.
	if wrapIsPKCS11 && req.Algorithm != "RSA-OAEP" && req.Algorithm != "RSA-OAEP-256" {
		return nil, fmt.Errorf("algorithm %q is not supported for HSM-backed keys; use RSA-OAEP or RSA-OAEP-256", req.Algorithm)
	}
	var wrappedKey []byte
	if wrapIsPKCS11 {
		wrappedKey, _, err = s.keyProvider.Encrypt(ctx, wrapHandle, req.PlaintextKey, encAlgo)
	} else {
		var result *crypto.EncryptResult
		result, err = s.cryptoOps.Encrypt(wrapHandle, req.PlaintextKey, encAlgo)
		if err == nil {
			wrappedKey = result.Ciphertext
		}
	}
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "wrap_key", "failed", "wrap operation failed", err)
		return nil, fmt.Errorf("wrap failed: %w", err)
	}
	s.logger.LogAuditInfo(req.UserID.String(), "wrap_key", "success",
		fmt.Sprintf("key material wrapped with vault key %s", req.KeyID))
	return &WrapKeyResult{WrappedKey: wrappedKey, Algorithm: req.Algorithm}, nil
}

// UnwrapKey decrypts wrapped key material using RSA-OAEP, RSA-OAEP-256, AES-KW, or AES-CBC with the specified vault key.
func (s *cryptoService) UnwrapKey(ctx context.Context, req UnwrapKeyRequest) (*UnwrapKeyResult, error) {
	start := time.Now()

	validUnwrapAlgorithms := map[string]bool{
		"RSA-OAEP": true, "RSA-OAEP-256": true,
		"A128KW": true, "A192KW": true, "A256KW": true,
		"A128CBC": true, "A192CBC": true, "A256CBC": true,
	}
	if !validUnwrapAlgorithms[req.Algorithm] {
		return nil, fmt.Errorf("unsupported unwrap algorithm %q", req.Algorithm)
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

	// Check if key is accessible (enabled and within validity window).
	if !key.IsAccessible() {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed",
			fmt.Sprintf("Attempted unwrap_key with inaccessible key: %s", req.KeyID), nil)
		return nil, fmt.Errorf("cannot unwrap_key with disabled or expired key")
	}

	unwrapHandle, unwrapIsPKCS11, cacheHit, err := s.resolveKeyMaterial(key)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "failed to resolve vault key handle", err)
		return nil, err
	}
	defer s.cryptoMetrics.RecordOp("unwrap_key", key.Type, cacheHit, time.Since(start))
	var decAlgo crypto.EncryptionAlgorithm
	switch req.Algorithm {
	case "RSA-OAEP-256":
		decAlgo = crypto.AlgorithmRSAOAEP256
	case "RSA-OAEP":
		decAlgo = crypto.AlgorithmRSAOAEP
	case "A128KW":
		decAlgo = crypto.AlgorithmA128KW
	case "A192KW":
		decAlgo = crypto.AlgorithmA192KW
	case "A256KW":
		decAlgo = crypto.AlgorithmA256KW
	case "A128CBC":
		decAlgo = crypto.AlgorithmA128CBC
	case "A192CBC":
		decAlgo = crypto.AlgorithmA192CBC
	case "A256CBC":
		decAlgo = crypto.AlgorithmA256CBC
	}
	// AES wrap/unwrap requires a software key; HSM keys only support RSA-OAEP variants.
	if unwrapIsPKCS11 && req.Algorithm != "RSA-OAEP" && req.Algorithm != "RSA-OAEP-256" {
		return nil, fmt.Errorf("algorithm %q is not supported for HSM-backed keys; use RSA-OAEP or RSA-OAEP-256", req.Algorithm)
	}
	var plaintext []byte
	if unwrapIsPKCS11 {
		plaintext, err = s.keyProvider.Decrypt(ctx, unwrapHandle, req.WrappedKey, nil, decAlgo)
	} else {
		var result *crypto.DecryptResult
		result, err = s.cryptoOps.Decrypt(unwrapHandle, req.WrappedKey, nil, decAlgo)
		if err == nil {
			plaintext = result.Plaintext
		}
	}
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "unwrap_key", "failed", "unwrap operation failed", err)
		return nil, fmt.Errorf("unwrap failed: %w", err)
	}
	s.logger.LogAuditInfo(req.UserID.String(), "unwrap_key", "success",
		fmt.Sprintf("key material unwrapped with vault key %s", req.KeyID))
	return &UnwrapKeyResult{PlaintextKey: plaintext, Algorithm: req.Algorithm}, nil
}
