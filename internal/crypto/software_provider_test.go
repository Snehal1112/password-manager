package crypto_test

import (
	"context"
	gocrypto "crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
)

func TestSoftwareKeyProvider_GenerateRSAKey_Returns_PEM(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)
	assert.Contains(t, handle, "RSA PRIVATE KEY")
}

func TestSoftwareKeyProvider_GenerateECDSAKey_P256(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateECDSAKey(context.Background(), "P-256")
	require.NoError(t, err)
	assert.Contains(t, handle, "EC PRIVATE KEY")
}

func TestSoftwareKeyProvider_GenerateECDSAKey_P256K(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateECDSAKey(context.Background(), "P-256K")
	require.NoError(t, err)
	assert.Contains(t, handle, "EC PRIVATE KEY")
}

func TestSoftwareKeyProvider_Sign_RSA(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	sig, err := p.Sign(context.Background(), handle, "RSA", []byte("hello"), crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestSoftwareKeyProvider_Verify_RSA(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("hello world")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmRS256)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "RSA", data, sig, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestSoftwareKeyProvider_Encrypt_Decrypt_RSA_OAEP(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	plaintext := []byte("secret payload")
	ct, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.NotEmpty(t, ct)

	pt, err := p.Decrypt(context.Background(), handle, ct, nonce, crypto.AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestSoftwareKeyProvider_Close_NoError(t *testing.T) {
	p := crypto.NewSoftwareKeyProvider()
	assert.NoError(t, p.Close())
}

// Compile-time interface check.
var _ crypto.KeyProvider = (*crypto.SoftwareKeyProvider)(nil)

// Ensure Sign uses the gocrypto package (import kept alive).
var _ gocrypto.Hash = gocrypto.SHA256
