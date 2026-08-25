package signing_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/signing"
)

func marshalJWK(t *testing.T, key any) []byte {
	t.Helper()
	jwk := jose.JSONWebKey{Key: key}
	data, err := jwk.MarshalJSON()
	require.NoError(t, err)
	return data
}

func TestParseJWK_ValidRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	parsed, keyType, err := signing.ParseJWK(marshalJWK(t, priv))
	require.NoError(t, err)
	assert.Equal(t, "RSA", keyType)
	parsedRSA, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey, got %T", parsed)
	assert.Equal(t, priv.N, parsedRSA.N)
	assert.Equal(t, priv.D, parsedRSA.D)
}

func TestParseJWK_ValidECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	parsed, keyType, err := signing.ParseJWK(marshalJWK(t, priv))
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", keyType)
	parsedEC, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected *ecdsa.PrivateKey, got %T", parsed)
	assert.Equal(t, priv.D, parsedEC.D)
}

func TestParseJWK_PublicOnlyRSA_Rejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, _, err = signing.ParseJWK(marshalJWK(t, &priv.PublicKey))
	require.ErrorIs(t, err, signing.ErrJWKNoPrivateKey)
}

func TestParseJWK_InvalidJSON_Rejected(t *testing.T) {
	_, _, err := signing.ParseJWK([]byte("not json"))
	require.Error(t, err)
}

func TestParseJWK_UnsupportedKeyType_Rejected(t *testing.T) {
	// A symmetric ("oct") JWK is well-formed JSON but not an RSA/ECDSA key.
	symmetric := []byte(`{"kty":"oct","k":"c2VjcmV0LWtleS1tYXRlcmlhbA"}`)
	_, _, err := signing.ParseJWK(symmetric)
	require.Error(t, err)
	assert.NotErrorIs(t, err, signing.ErrJWKNoPrivateKey, "an oct key has a 'private' component and must fail as unsupported, not as public-only")
}
