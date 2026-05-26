package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractRSAPublicComponents(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}))

	n, e, x, y, err := ExtractPublicComponents(privPEM, "RSA")
	require.NoError(t, err)
	assert.NotEmpty(t, n)
	assert.NotEmpty(t, e)
	assert.Empty(t, x)
	assert.Empty(t, y)
}

func TestExtractECPublicComponents(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privBytes, err := x509.MarshalECPrivateKey(privKey)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}))

	n, e, x, y, err := ExtractPublicComponents(privPEM, "ECDSA")
	require.NoError(t, err)
	assert.Empty(t, n)
	assert.Empty(t, e)
	assert.NotEmpty(t, x)
	assert.NotEmpty(t, y)
}

func TestExtractPublicComponents_PKCS11ReturnsEmpty(t *testing.T) {
	n, e, x, y, err := ExtractPublicComponents("pkcs11:some-label", "RSA")
	require.NoError(t, err)
	assert.Empty(t, n)
	assert.Empty(t, e)
	assert.Empty(t, x)
	assert.Empty(t, y)
}
