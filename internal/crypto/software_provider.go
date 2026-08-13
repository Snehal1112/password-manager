package crypto

import (
	"context"
	"errors"
)

// ErrOctKeysRequireHSM is returned by SoftwareKeyProvider.GenerateAESKey.
// Symmetric (oct/AES) key creation is Managed-HSM-only in Azure Key Vault —
// Standard and Premium vaults never allow it — and RocketVault's software
// provider models that same restriction: only PKCS11KeyProvider implements
// this method for real.
var ErrOctKeysRequireHSM = errors.New("symmetric (oct/AES) key creation requires an HSM-backed key provider (hsm.enabled: true)")

// SoftwareKeyProvider implements KeyProvider using in-process Go crypto.
// It wraps the existing GenerateRSAKeyPEM / GenerateECDSAKeyPEM helpers and
// delegates sign/verify/encrypt/decrypt to CryptoOperations.
type SoftwareKeyProvider struct {
	ops *CryptoOperations
}

// NewSoftwareKeyProvider creates a SoftwareKeyProvider backed by the standard
// Go crypto library. No configuration is required.
func NewSoftwareKeyProvider() *SoftwareKeyProvider {
	return &SoftwareKeyProvider{ops: NewCryptoOperations()}
}

// GenerateRSAKey generates an RSA private key and returns the PEM as the handle.
func (p *SoftwareKeyProvider) GenerateRSAKey(_ context.Context, bits int) (string, error) {
	return GenerateRSAKeyPEM(bits)
}

// GenerateECDSAKey generates an ECDSA private key and returns the PEM as the handle.
func (p *SoftwareKeyProvider) GenerateECDSAKey(_ context.Context, curveName string) (string, error) {
	return GenerateECDSAKeyPEM(curveName)
}

// GenerateAESKey always fails: see ErrOctKeysRequireHSM.
func (p *SoftwareKeyProvider) GenerateAESKey(_ context.Context, _ int) (string, error) {
	return "", ErrOctKeysRequireHSM
}

// Sign signs data using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Sign(_ context.Context, handle string, keyType string, data []byte, algorithm SignatureAlgorithm) ([]byte, error) {
	result, err := p.ops.Sign(handle, keyType, data, algorithm)
	if err != nil {
		return nil, err
	}
	return result.Signature, nil
}

// Verify verifies a signature using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Verify(_ context.Context, handle string, keyType string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error) {
	result, err := p.ops.Verify(handle, keyType, data, sig, algorithm)
	if err != nil {
		return false, err
	}
	return result.Valid, nil
}

// Encrypt encrypts data using the key PEM stored in handle.
// Returns (ciphertext, nonce, error). nonce is nil for RSA modes.
func (p *SoftwareKeyProvider) Encrypt(_ context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) ([]byte, []byte, error) {
	result, err := p.ops.Encrypt(handle, data, algorithm)
	if err != nil {
		return nil, nil, err
	}
	return result.Ciphertext, result.Nonce, nil
}

// Decrypt decrypts ciphertext using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Decrypt(_ context.Context, handle string, data []byte, nonce []byte, algorithm EncryptionAlgorithm) ([]byte, error) {
	result, err := p.ops.Decrypt(handle, data, nonce, algorithm)
	if err != nil {
		return nil, err
	}
	return result.Plaintext, nil
}

// Close is a no-op for the software provider.
func (p *SoftwareKeyProvider) Close() error { return nil }
