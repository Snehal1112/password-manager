// Edge tests for the crypto package to push coverage above 80%.
package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── GenerateRSAKeyPEM ────────────────────────────────────────────────────────

func TestGenerateRSAKeyPEM_ValidBits(t *testing.T) {
	pem, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	assert.Contains(t, pem, "RSA PRIVATE KEY")
}

func TestGenerateRSAKeyPEM_SmallBitsError(t *testing.T) {
	// rsa.GenerateKey rejects key sizes that are too small.
	_, err := GenerateRSAKeyPEM(1)
	require.Error(t, err)
}

// ─── GenerateECDSAKeyPEM ─────────────────────────────────────────────────────

func TestGenerateECDSAKeyPEM_P384(t *testing.T) {
	pem, err := GenerateECDSAKeyPEM("P-384")
	require.NoError(t, err)
	assert.Contains(t, pem, "EC PRIVATE KEY")
}

func TestGenerateECDSAKeyPEM_P521(t *testing.T) {
	pem, err := GenerateECDSAKeyPEM("P-521")
	require.NoError(t, err)
	assert.Contains(t, pem, "EC PRIVATE KEY")
}

func TestGenerateECDSAKeyPEM_UnsupportedCurve(t *testing.T) {
	_, err := GenerateECDSAKeyPEM("P-192")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported curve")
}

// ─── ParsePrivateKey ─────────────────────────────────────────────────────────

func TestParsePrivateKey_RSASuccess(t *testing.T) {
	pemStr, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	key, err := ParsePrivateKey(pemStr, "RSA")
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestParsePrivateKey_ECDSASuccess(t *testing.T) {
	pemStr, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)

	key, err := ParsePrivateKey(pemStr, "ECDSA")
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestParsePrivateKey_ES256K(t *testing.T) {
	pemStr, err := GenerateECDSAKeyPEM("P-256K")
	require.NoError(t, err)

	key, err := ParsePrivateKey(pemStr, "ES256K")
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestParsePrivateKey_UnsupportedType(t *testing.T) {
	pemStr, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	_, err = ParsePrivateKey(pemStr, "UNKNOWN")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestParsePrivateKey_InvalidPEM(t *testing.T) {
	_, err := ParsePrivateKey("not valid pem data", "RSA")
	require.Error(t, err)
}

func TestParsePrivateKey_WrongKeyTypeForBlock(t *testing.T) {
	// EC PEM passed as RSA type should fail at parse stage.
	ecPEM, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)

	_, err = ParsePrivateKey(ecPEM, "RSA")
	require.Error(t, err)
}

// ─── x509 helper functions ───────────────────────────────────────────────────

func TestGenerateSerialNumber(t *testing.T) {
	sn, err := GenerateSerialNumber()
	require.NoError(t, err)
	require.NotNil(t, sn)
	assert.Greater(t, sn.Sign(), 0)
}

func TestCreateX509Template(t *testing.T) {
	tmpl, err := CreateX509Template(CertificateTemplate{
		CommonName:   "test.example.com",
		ValidityDays: 365,
		IsCA:         false,
	})
	require.NoError(t, err)
	require.NotNil(t, tmpl)
	assert.Equal(t, "test.example.com", tmpl.Subject.CommonName)
}

func TestCreateSelfSignedCertificatePEM_RSA(t *testing.T) {
	privPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	certPEM, err := CreateSelfSignedCertificatePEM(privPEM, "RSA", CertificateTemplate{
		CommonName:   "rsa.example.com",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.Contains(t, certPEM, "CERTIFICATE")
}

func TestCreateSelfSignedCertificatePEM_ECDSA(t *testing.T) {
	privPEM, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)

	certPEM, err := CreateSelfSignedCertificatePEM(privPEM, "ECDSA", CertificateTemplate{
		CommonName:   "ec.example.com",
		ValidityDays: 30,
	})
	require.NoError(t, err)
	assert.Contains(t, certPEM, "CERTIFICATE")
}

func TestCreateSelfSignedCertificatePEM_UnsupportedKeyType(t *testing.T) {
	// UNKNOWN key type causes ParsePrivateKey to fail.
	privPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	_, err = CreateSelfSignedCertificatePEM(privPEM, "UNKNOWN", CertificateTemplate{
		CommonName:   "x.example.com",
		ValidityDays: 1,
	})
	require.Error(t, err)
}

func TestCreateSelfSignedCertificatePEM_InvalidPEM(t *testing.T) {
	_, err := CreateSelfSignedCertificatePEM("not valid pem", "RSA", CertificateTemplate{
		CommonName:   "x.example.com",
		ValidityDays: 1,
	})
	require.Error(t, err)
}

func TestCreateCASignedCertificatePEM_RSACA_RSALeaf(t *testing.T) {
	caPrivPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caCertPEM, err := CreateSelfSignedCertificatePEM(caPrivPEM, "RSA", CertificateTemplate{
		CommonName:   "ca.example.com",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	leafPrivPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	certPEM, err := CreateCASignedCertificatePEM(leafPrivPEM, "RSA", caCertPEM, caPrivPEM, "RSA", CertificateTemplate{
		CommonName:   "leaf.example.com",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	assert.Contains(t, certPEM, "CERTIFICATE")
}

func TestCreateCASignedCertificatePEM_ECCA_ECLeaf(t *testing.T) {
	caPrivPEM, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)

	caCertPEM, err := CreateSelfSignedCertificatePEM(caPrivPEM, "ECDSA", CertificateTemplate{
		CommonName:   "ec-ca.example.com",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	leafPrivPEM, err := GenerateECDSAKeyPEM("P-384")
	require.NoError(t, err)

	certPEM, err := CreateCASignedCertificatePEM(leafPrivPEM, "ECDSA", caCertPEM, caPrivPEM, "ECDSA", CertificateTemplate{
		CommonName:   "ec-leaf.example.com",
		ValidityDays: 90,
	})
	require.NoError(t, err)
	assert.Contains(t, certPEM, "CERTIFICATE")
}

func TestCreateCASignedCertificatePEM_RSALeaf_ECCA(t *testing.T) {
	caPrivPEM, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)

	caCertPEM, err := CreateSelfSignedCertificatePEM(caPrivPEM, "ECDSA", CertificateTemplate{
		CommonName:   "ec-ca.example.com",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	leafPrivPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	certPEM, err := CreateCASignedCertificatePEM(leafPrivPEM, "RSA", caCertPEM, caPrivPEM, "ECDSA", CertificateTemplate{
		CommonName:   "rsa-leaf.example.com",
		ValidityDays: 90,
	})
	require.NoError(t, err)
	assert.Contains(t, certPEM, "CERTIFICATE")
}

func TestCreateCASignedCertificatePEM_ECLeaf_RSACA(t *testing.T) {
	caPrivPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caCertPEM, err := CreateSelfSignedCertificatePEM(caPrivPEM, "RSA", CertificateTemplate{
		CommonName:   "rsa-ca.example.com",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	leafPrivPEM, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)

	certPEM, err := CreateCASignedCertificatePEM(leafPrivPEM, "ECDSA", caCertPEM, caPrivPEM, "RSA", CertificateTemplate{
		CommonName:   "ec-leaf.example.com",
		ValidityDays: 90,
	})
	require.NoError(t, err)
	assert.Contains(t, certPEM, "CERTIFICATE")
}

func TestCreateCASignedCertificatePEM_InvalidCACert(t *testing.T) {
	leafPrivPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	_, err = CreateCASignedCertificatePEM(leafPrivPEM, "RSA", "not-pem", leafPrivPEM, "RSA", CertificateTemplate{
		CommonName:   "x.example.com",
		ValidityDays: 1,
	})
	require.Error(t, err)
}

// ─── CryptoOperations – RSA1_5 encrypt/decrypt round-trip ────────────────────

func TestEncryptDecryptRSA1_5(t *testing.T) {
	ops := NewCryptoOperations()

	privPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	plaintext := []byte("rsa-1-5 plaintext")
	enc, err := ops.encryptRSA1_5(privPEM, plaintext)
	require.NoError(t, err)
	require.NotNil(t, enc)

	dec, err := ops.decryptRSA1_5(privPEM, enc.Ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec.Plaintext)
}

func TestEncryptRSA1_5_BadKey(t *testing.T) {
	ops := NewCryptoOperations()
	_, err := ops.encryptRSA1_5("bad pem", []byte("data"))
	require.Error(t, err)
}

func TestDecryptRSA1_5_BadKey(t *testing.T) {
	ops := NewCryptoOperations()
	_, err := ops.decryptRSA1_5("bad pem", []byte("data"))
	require.Error(t, err)
}

func TestDecryptRSA1_5_BadCiphertext(t *testing.T) {
	ops := NewCryptoOperations()
	privPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	_, err = ops.decryptRSA1_5(privPEM, []byte("not ciphertext"))
	require.Error(t, err)
}

// ─── aesKeySize ───────────────────────────────────────────────────────────────

func TestAesKeySize(t *testing.T) {
	cases := []struct {
		alg  EncryptionAlgorithm
		size int
	}{
		{AlgorithmA128KW, 16},
		{AlgorithmA128CBC, 16},
		{AlgorithmA192KW, 24},
		{AlgorithmA192CBC, 24},
		{AlgorithmA256KW, 32},
		{AlgorithmA256CBC, 32},
		{AlgorithmRSAOAEP, 0}, // unknown → 0
	}
	for _, tc := range cases {
		assert.Equal(t, tc.size, aesKeySize(tc.alg), "algorithm: %s", tc.alg)
	}
}

// ─── wrapAES / unwrapAES error paths ─────────────────────────────────────────

func TestWrapAES_BadBase64(t *testing.T) {
	ops := NewCryptoOperations()
	_, err := ops.wrapAES("!!!not-base64!!!", []byte("data"), AlgorithmA256KW)
	require.Error(t, err)
}

func TestUnwrapAES_BadBase64(t *testing.T) {
	ops := NewCryptoOperations()
	_, err := ops.unwrapAES("!!!not-base64!!!", []byte("data"), AlgorithmA256KW)
	require.Error(t, err)
}

func TestWrapAES_KeySizeMismatch(t *testing.T) {
	ops := NewCryptoOperations()
	// 8-byte key encoded as base64, but A256KW needs 32 bytes.
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 8))
	_, err := ops.wrapAES(shortKey, []byte("data"), AlgorithmA256KW)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key size mismatch")
}

func TestUnwrapAES_KeySizeMismatch(t *testing.T) {
	ops := NewCryptoOperations()
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 8))
	_, err := ops.unwrapAES(shortKey, []byte("data"), AlgorithmA256KW)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key size mismatch")
}

// ─── decryptAESCBC – error paths ─────────────────────────────────────────────

func TestDecryptAESCBC_BadBase64(t *testing.T) {
	ops := NewCryptoOperations()
	_, err := ops.decryptAESCBC("!!!not-base64!!!", []byte("ct"), nil, AlgorithmA128CBC)
	require.Error(t, err)
}

func TestDecryptAESCBC_InvalidCiphertextLength(t *testing.T) {
	ops := NewCryptoOperations()
	key := make([]byte, 16)
	keyB64 := base64.StdEncoding.EncodeToString(key)
	// 5 bytes is not a multiple of the AES block size (16).
	_, err := ops.decryptAESCBC(keyB64, []byte("12345"), make([]byte, 16), AlgorithmA128CBC)
	require.Error(t, err)
}

func TestDecryptAESCBC_InvalidIVLength(t *testing.T) {
	ops := NewCryptoOperations()
	key := make([]byte, 16)
	keyB64 := base64.StdEncoding.EncodeToString(key)
	// IV of wrong length.
	_, err := ops.decryptAESCBC(keyB64, make([]byte, 16), []byte("short-iv"), AlgorithmA128CBC)
	require.Error(t, err)
}

func TestDecryptAESCBC_KeySizeMismatch(t *testing.T) {
	ops := NewCryptoOperations()
	// 8-byte key for A128CBC which expects 16 bytes.
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 8))
	_, err := ops.decryptAESCBC(shortKey, make([]byte, 16), make([]byte, 16), AlgorithmA128CBC)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key size mismatch")
}
