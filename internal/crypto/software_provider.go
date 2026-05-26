package crypto

import (
	"context"
	"fmt"
)

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

// GenerateRSAKey generates an RSA private key; returns the PEM as the handle.
func (p *SoftwareKeyProvider) GenerateRSAKey(_ context.Context, bits int) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// GenerateECDSAKey generates an ECDSA private key; returns the PEM as the handle.
func (p *SoftwareKeyProvider) GenerateECDSAKey(_ context.Context, curveName string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// Sign signs data using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Sign(_ context.Context, handle string, keyType string, data []byte, algorithm SignatureAlgorithm) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// Verify verifies a signature using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Verify(_ context.Context, handle string, keyType string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error) {
	return false, fmt.Errorf("not implemented")
}

// Encrypt encrypts data using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Encrypt(_ context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

// Decrypt decrypts ciphertext using the key PEM stored in handle.
func (p *SoftwareKeyProvider) Decrypt(_ context.Context, handle string, data []byte, nonce []byte, algorithm EncryptionAlgorithm) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// Close is a no-op for the software provider.
func (p *SoftwareKeyProvider) Close() error { return nil }
