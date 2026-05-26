package crypto

import (
	"context"
)

// KeyProvider abstracts key generation and raw crypto operations.
// Implementations may use in-process Go crypto (SoftwareKeyProvider)
// or an external PKCS#11 token (PKCS11KeyProvider).
type KeyProvider interface {
	// GenerateRSAKey generates an RSA key and returns an opaque handle string.
	// For SoftwareKeyProvider the handle is PEM. For PKCS11KeyProvider it is
	// the CKA_LABEL of the key object on the token.
	GenerateRSAKey(ctx context.Context, bits int) (handle string, err error)

	// GenerateECDSAKey generates an ECDSA key. curveName is "P-256", "P-384",
	// "P-521", or "P-256K".
	GenerateECDSAKey(ctx context.Context, curveName string) (handle string, err error)

	// Sign signs data with the key identified by handle using the given algorithm.
	Sign(ctx context.Context, handle string, keyType string, data []byte, algorithm SignatureAlgorithm) ([]byte, error)

	// Verify verifies a signature. Returns true if valid.
	Verify(ctx context.Context, handle string, keyType string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error)

	// Encrypt encrypts data with the key identified by handle.
	// nonce is non-nil for AES-GCM; nil for RSA modes.
	Encrypt(ctx context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) (ciphertext []byte, nonce []byte, err error)

	// Decrypt decrypts ciphertext with the key identified by handle.
	Decrypt(ctx context.Context, handle string, data []byte, nonce []byte, algorithm EncryptionAlgorithm) ([]byte, error)

	// Close releases any resources held by the provider (e.g., PKCS#11 session).
	Close() error
}
