package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectPrivateKeyType_RSA(t *testing.T) {
	pemData, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	got, err := DetectPrivateKeyType(pemData)
	require.NoError(t, err)
	require.Equal(t, "RSA", got)
}

func TestDetectPrivateKeyType_ECDSA(t *testing.T) {
	for _, curve := range []string{"P-256", "P-384", "P-521"} {
		pemData, err := GenerateECDSAKeyPEM(curve)
		require.NoError(t, err)

		got, err := DetectPrivateKeyType(pemData)
		require.NoError(t, err, "curve %s", curve)
		require.Equal(t, "ECDSA", got, "curve %s", curve)
	}
}

// secp256k1 keys share the "EC PRIVATE KEY" block type but hold a raw
// 32-byte scalar, so they must be distinguished by content, not by header.
func TestDetectPrivateKeyType_ES256K(t *testing.T) {
	pemData, err := GenerateECDSAKeyPEM("P-256K")
	require.NoError(t, err)

	got, err := DetectPrivateKeyType(pemData)
	require.NoError(t, err)
	require.Equal(t, "ES256K", got)
}

// Whatever DetectPrivateKeyType returns must be accepted by ParsePrivateKey,
// or the detection is useless to its only caller.
func TestDetectPrivateKeyType_RoundTripsThroughParsePrivateKey(t *testing.T) {
	for _, pemFn := range []func() (string, error){
		func() (string, error) { return GenerateRSAKeyPEM(2048) },
		func() (string, error) { return GenerateECDSAKeyPEM("P-256") },
		func() (string, error) { return GenerateECDSAKeyPEM("P-256K") },
	} {
		pemData, err := pemFn()
		require.NoError(t, err)

		keyType, err := DetectPrivateKeyType(pemData)
		require.NoError(t, err)

		key, err := ParsePrivateKey(pemData, keyType)
		require.NoError(t, err, "detected type %q must parse", keyType)
		require.NotNil(t, key)
	}
}

func TestDetectPrivateKeyType_NotPEM(t *testing.T) {
	_, err := DetectPrivateKeyType("not a pem block")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode private key PEM")
}

func TestDetectPrivateKeyType_UnknownBlockType(t *testing.T) {
	_, err := DetectPrivateKeyType("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported private key PEM block type")
}
