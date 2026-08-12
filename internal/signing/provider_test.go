package signing_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/signing"
)

// --- ExternalPKIProvider tests ---

func TestExternalPKIProvider_RSA_FromFile(t *testing.T) {
	keyPEM := generateRSAPEM(t)

	f, err := os.CreateTemp(t.TempDir(), "rsa-*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(keyPEM)
	require.NoError(t, err)
	f.Close() //nolint:errcheck,gosec

	p, err := signing.NewExternalPKIProvider(f.Name())
	require.NoError(t, err)

	assert.Equal(t, "RS256", p.Algorithm())
	assert.NotEmpty(t, p.KeyID())
	assert.NotNil(t, p.PrivateKey())
	assert.Len(t, p.PublicKeys(), 1)
	assert.Equal(t, "RS256", p.PublicKeys()[0].Algorithm)

	_, ok := p.PublicKeys()[0].PublicKey.(*rsa.PublicKey)
	assert.True(t, ok, "public key should be *rsa.PublicKey")
}

func TestExternalPKIProvider_ECDSA_FromFile(t *testing.T) {
	keyPEM := generateECDSAPEM(t)

	f, err := os.CreateTemp(t.TempDir(), "ecdsa-*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(keyPEM)
	require.NoError(t, err)
	f.Close() //nolint:errcheck,gosec

	p, err := signing.NewExternalPKIProvider(f.Name())
	require.NoError(t, err)

	assert.Equal(t, "ES256", p.Algorithm())
	assert.NotEmpty(t, p.KeyID())

	_, ok := p.PublicKeys()[0].PublicKey.(*ecdsa.PublicKey)
	assert.True(t, ok, "public key should be *ecdsa.PublicKey")
}

func TestExternalPKIProvider_RSA_FromEnvVar(t *testing.T) {
	keyPEM := generateRSAPEM(t)
	encoded := base64.StdEncoding.EncodeToString([]byte(keyPEM))
	t.Setenv("ROCKETVAULT_JWT_SIGNING_KEY", encoded)

	p, err := signing.NewExternalPKIProvider("")
	require.NoError(t, err)
	assert.Equal(t, "RS256", p.Algorithm())
}

func TestExternalPKIProvider_MissingKey_Error(t *testing.T) {
	// Ensure env var is unset.
	t.Setenv("ROCKETVAULT_JWT_SIGNING_KEY", "")

	_, err := signing.NewExternalPKIProvider("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no signing key")
}

func TestExternalPKIProvider_InvalidFile_Error(t *testing.T) {
	t.Setenv("ROCKETVAULT_JWT_SIGNING_KEY", "")

	_, err := signing.NewExternalPKIProvider("/nonexistent/path/key.pem")
	require.Error(t, err)
}

// --- OSStoreProvider tests ---

func TestOSStoreProvider_AutoGenerates_WhenNoCertFound(t *testing.T) {
	// System cert store never exposes private keys, so auto-gen is always triggered.
	p, err := signing.NewOSStoreProvider("rocketvault-test")
	require.NoError(t, err)

	assert.Equal(t, "RS256", p.Algorithm())
	assert.NotEmpty(t, p.KeyID())
	assert.NotNil(t, p.PrivateKey())
	assert.Len(t, p.PublicKeys(), 1)

	_, ok := p.PublicKeys()[0].PublicKey.(*rsa.PublicKey)
	assert.True(t, ok, "auto-generated key must be RSA")
}

// --- JWKS serialization tests ---

func TestRSAPublicKeyToJWK(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := signing.RSAPublicKeyToJWK(&key.PublicKey, "test-kid", "RS256")

	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, "sig", jwk["use"])
	assert.Equal(t, "RS256", jwk["alg"])
	assert.Equal(t, "test-kid", jwk["kid"])
	assert.NotEmpty(t, jwk["n"])
	assert.NotEmpty(t, jwk["e"])
}

func TestECDSAPublicKeyToJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk, err := signing.ECDSAPublicKeyToJWK(&key.PublicKey, "test-kid", "ES256")
	require.NoError(t, err)

	assert.Equal(t, "EC", jwk["kty"])
	assert.Equal(t, "sig", jwk["use"])
	assert.Equal(t, "ES256", jwk["alg"])
	assert.Equal(t, "P-256", jwk["crv"])
	assert.NotEmpty(t, jwk["x"])
	assert.NotEmpty(t, jwk["y"])
}

// --- helpers ---

func generateRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func generateECDSAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}
