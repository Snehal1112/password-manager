package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRSASignAndVerify(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	// Generate RSA key
	privateKeyPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	testData := []byte("Hello, World! This is a test message.")

	tests := []struct {
		name      string
		algorithm SignatureAlgorithm
	}{
		{"RS256", AlgorithmRS256},
		{"RS384", AlgorithmRS384},
		{"RS512", AlgorithmRS512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Sign the data
			signResult, err := ops.Sign(privateKeyPEM, "RSA", testData, tt.algorithm)
			require.NoError(t, err)
			assert.NotNil(t, signResult)
			assert.NotEmpty(t, signResult.Signature)
			assert.Equal(t, tt.algorithm, signResult.Algorithm)
			assert.NotEmpty(t, signResult.Digest)

			// Verify the signature
			verifyResult, err := ops.Verify(privateKeyPEM, "RSA", testData, signResult.Signature, tt.algorithm)
			require.NoError(t, err)
			assert.True(t, verifyResult.Valid, "Signature should be valid")
			assert.Equal(t, tt.algorithm, verifyResult.Algorithm)

			// Test with tampered data
			tamperedData := []byte("Tampered message")
			verifyResult, err = ops.Verify(privateKeyPEM, "RSA", tamperedData, signResult.Signature, tt.algorithm)
			require.NoError(t, err)
			assert.False(t, verifyResult.Valid, "Signature should be invalid for tampered data")
		})
	}
}

func TestECDSASignAndVerify(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	curves := []struct {
		name      string
		curve     string
		algorithm SignatureAlgorithm
	}{
		{"P-256/ES256", "P-256", AlgorithmES256},
		{"P-384/ES384", "P-384", AlgorithmES384},
		{"P-521/ES512", "P-521", AlgorithmES512},
	}

	testData := []byte("Hello, ECDSA! This is a test message.")

	for _, tt := range curves {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Generate ECDSA key
			privateKeyPEM, err := GenerateECDSAKeyPEM(tt.curve)
			require.NoError(t, err)

			// Sign the data
			signResult, err := ops.Sign(privateKeyPEM, "ECDSA", testData, tt.algorithm)
			require.NoError(t, err)
			assert.NotNil(t, signResult)
			assert.NotEmpty(t, signResult.Signature)
			assert.Equal(t, tt.algorithm, signResult.Algorithm)

			// Verify the signature
			verifyResult, err := ops.Verify(privateKeyPEM, "ECDSA", testData, signResult.Signature, tt.algorithm)
			require.NoError(t, err)
			assert.True(t, verifyResult.Valid, "Signature should be valid")

			// Test with tampered data
			tamperedData := []byte("Tampered ECDSA message")
			verifyResult, err = ops.Verify(privateKeyPEM, "ECDSA", tamperedData, signResult.Signature, tt.algorithm)
			require.NoError(t, err)
			assert.False(t, verifyResult.Valid, "Signature should be invalid for tampered data")
		})
	}
}

func TestRSAEncryptDecrypt(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	// Generate RSA key
	privateKeyPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	testData := []byte("Sensitive data to encrypt")

	// Encrypt
	encryptResult, err := ops.Encrypt(privateKeyPEM, testData, AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.NotNil(t, encryptResult)
	assert.NotEmpty(t, encryptResult.Ciphertext)
	assert.Equal(t, AlgorithmRSAOAEP, encryptResult.Algorithm)
	assert.NotEqual(t, testData, encryptResult.Ciphertext, "Ciphertext should differ from plaintext")

	// Decrypt
	decryptResult, err := ops.Decrypt(privateKeyPEM, encryptResult.Ciphertext, nil, AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.NotNil(t, decryptResult)
	assert.Equal(t, testData, decryptResult.Plaintext)
	assert.Equal(t, AlgorithmRSAOAEP, decryptResult.Algorithm)
}

func TestAESEncryptDecrypt(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	// Use a fixed 32-byte key for testing
	keyBase64 := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")) // 32 bytes

	testData := []byte("Sensitive secret data to encrypt with AES")

	// Encrypt
	encryptResult, err := ops.Encrypt(keyBase64, testData, AlgorithmAES256)
	require.NoError(t, err)
	assert.NotNil(t, encryptResult)
	assert.NotEmpty(t, encryptResult.Ciphertext)
	assert.NotEmpty(t, encryptResult.Nonce)
	assert.Equal(t, AlgorithmAES256, encryptResult.Algorithm)
	assert.NotEqual(t, testData, encryptResult.Ciphertext, "Ciphertext should differ from plaintext")

	// Decrypt
	decryptResult, err := ops.Decrypt(keyBase64, encryptResult.Ciphertext, encryptResult.Nonce, AlgorithmAES256)
	require.NoError(t, err)
	assert.NotNil(t, decryptResult)
	assert.Equal(t, testData, decryptResult.Plaintext)
	assert.Equal(t, AlgorithmAES256, decryptResult.Algorithm)
}

func TestInvalidKey(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	invalidPEM := "invalid-pem-data"
	testData := []byte("test data")

	// Test Sign with invalid key
	_, err := ops.Sign(invalidPEM, "RSA", testData, AlgorithmRS256)
	assert.Error(t, err)

	// Test Verify with invalid key
	_, err = ops.Verify(invalidPEM, "RSA", testData, []byte("signature"), AlgorithmRS256)
	assert.Error(t, err)

	// Test Encrypt with invalid key
	_, err = ops.Encrypt(invalidPEM, testData, AlgorithmRSAOAEP)
	assert.Error(t, err)

	// Test Decrypt with invalid key
	_, err = ops.Decrypt(invalidPEM, testData, nil, AlgorithmRSAOAEP)
	assert.Error(t, err)
}

func TestUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	// Generate RSA key
	privateKeyPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	testData := []byte("test data")

	// Test with unsupported signature algorithm
	_, err = ops.Sign(privateKeyPEM, "RSA", testData, "INVALID")
	assert.Error(t, err)

	// Test with unsupported encryption algorithm
	_, err = ops.Encrypt(privateKeyPEM, testData, "INVALID")
	assert.Error(t, err)
}

func TestRSADataSizeLimits(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	// Generate RSA key
	privateKeyPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	// RSA-OAEP can encrypt up to (key_size - 2*hash_size - 2) bytes
	// For 2048-bit key with SHA-1: 2048/8 - 2*20 - 2 = 214 bytes max
	largeData := make([]byte, 190)

	// Should work with data at the limit
	encryptResult, err := ops.Encrypt(privateKeyPEM, largeData, AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.NotNil(t, encryptResult)

	// Decrypt should work
	decryptResult, err := ops.Decrypt(privateKeyPEM, encryptResult.Ciphertext, nil, AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, largeData, decryptResult.Plaintext)

	// Should fail with data exceeding the limit
	tooLargeData := make([]byte, 300)
	_, err = ops.Encrypt(privateKeyPEM, tooLargeData, AlgorithmRSAOAEP)
	assert.Error(t, err)
}

func TestAESKeySize(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	testData := []byte("test data")

	// Test with invalid key size (not 32 bytes)
	invalidKey := base64.StdEncoding.EncodeToString([]byte("short-key"))

	_, err := ops.Encrypt(invalidKey, testData, AlgorithmAES256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "32-byte key")
}

func BenchmarkRSASign(b *testing.B) {
	ops := NewCryptoOperations()
	privateKeyPEM, _ := GenerateRSAKeyPEM(2048)
	testData := []byte("Benchmark data for signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ops.Sign(privateKeyPEM, "RSA", testData, AlgorithmRS256)
	}
}

func BenchmarkECDSASign(b *testing.B) {
	ops := NewCryptoOperations()
	privateKeyPEM, _ := GenerateECDSAKeyPEM("P-256")
	testData := []byte("Benchmark data for signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ops.Sign(privateKeyPEM, "ECDSA", testData, AlgorithmES256)
	}
}

func TestSignVerify_ES256K(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()

	// Generate a secp256k1 key.
	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	// Serialise the key to PEM so Sign/Verify can consume it.
	privPEM, err := MarshalSecp256k1PrivateKeyPEM(privKey)
	require.NoError(t, err)

	data := []byte("test message for secp256k1 signing")

	// Sign the data with ES256K.
	sig, err := ops.Sign(privPEM, "ES256K", data, AlgorithmES256K)
	require.NoError(t, err)
	require.NotEmpty(t, sig.Signature)
	assert.Equal(t, AlgorithmES256K, sig.Algorithm)

	// Verify the signature.
	result, err := ops.Verify(privPEM, "ES256K", data, sig.Signature, AlgorithmES256K)
	require.NoError(t, err)
	assert.True(t, result.Valid, "signature should be valid")

	// Verify that tampered data fails.
	tampered := []byte("tampered message")
	result2, err := ops.Verify(privPEM, "ES256K", tampered, sig.Signature, AlgorithmES256K)
	require.NoError(t, err)
	assert.False(t, result2.Valid, "tampered data should not verify")
}

func TestSignVerify_HMAC(t *testing.T) {
	t.Parallel()
	c := NewCryptoOperations()
	// 32-byte key encoded as base64.
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))
	data := []byte("hmac payload")

	for _, alg := range []SignatureAlgorithm{AlgorithmHS256, AlgorithmHS384, AlgorithmHS512} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()
			sig, err := c.Sign(key, "oct", data, alg)
			require.NoError(t, err)
			result, err := c.Verify(key, "oct", data, sig.Signature, alg)
			require.NoError(t, err)
			require.True(t, result.Valid)

			// Tamper detection: corrupted data must not verify.
			tampered := []byte("tampered payload")
			bad, err := c.Verify(key, "oct", tampered, sig.Signature, alg)
			require.NoError(t, err)
			require.False(t, bad.Valid)
		})
	}
}

func BenchmarkAESEncrypt(b *testing.B) {
	ops := NewCryptoOperations()
	keyBase64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	testData := []byte("Benchmark data for encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ops.Encrypt(keyBase64, testData, AlgorithmAES256)
	}
}

func TestRSAOAEP_SHA1_RoundTrip(t *testing.T) {
	ops := NewCryptoOperations()
	pemKey, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	plaintext := []byte("secret payload for SHA-1 OAEP")

	enc, err := ops.Encrypt(pemKey, plaintext, AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmRSAOAEP, enc.Algorithm)

	dec, err := ops.Decrypt(pemKey, enc.Ciphertext, nil, AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec.Plaintext)
}

func TestRSAOAEP256_SHA256_RoundTrip(t *testing.T) {
	ops := NewCryptoOperations()
	pemKey, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	plaintext := []byte("secret payload for SHA-256 OAEP")

	enc, err := ops.Encrypt(pemKey, plaintext, AlgorithmRSAOAEP256)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmRSAOAEP256, enc.Algorithm)

	dec, err := ops.Decrypt(pemKey, enc.Ciphertext, nil, AlgorithmRSAOAEP256)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec.Plaintext)
}

func TestSign_RSA_PSS_Algorithms(t *testing.T) {
	t.Parallel()
	ops := NewCryptoOperations()
	privateKeyPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	data := []byte("data to sign with PSS")

	for _, alg := range []SignatureAlgorithm{AlgorithmPS256, AlgorithmPS384, AlgorithmPS512} {
		t.Run(string(alg), func(t *testing.T) {
			sig, err := ops.Sign(privateKeyPEM, "RSA", data, alg)
			require.NoError(t, err)
			assert.NotEmpty(t, sig.Signature)
			assert.Equal(t, alg, sig.Algorithm)

			v, err := ops.Verify(privateKeyPEM, "RSA", data, sig.Signature, alg)
			require.NoError(t, err)
			assert.True(t, v.Valid)

			// Mutated data must not verify.
			tampered := make([]byte, len(data)+1)
			copy(tampered, data)
			tampered[len(data)] = 0
			v2, err := ops.Verify(privateKeyPEM, "RSA", tampered, sig.Signature, alg)
			require.NoError(t, err)
			assert.False(t, v2.Valid)
		})
	}
}

func TestRSAOAEP_And_RSAOAEP256_Are_Not_Interchangeable(t *testing.T) {
	ops := NewCryptoOperations()
	pemKey, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	plaintext := []byte("cross-algorithm test")

	enc, err := ops.Encrypt(pemKey, plaintext, AlgorithmRSAOAEP)
	require.NoError(t, err)

	// SHA-256 path cannot decrypt what SHA-1 path encrypted
	_, err = ops.Decrypt(pemKey, enc.Ciphertext, nil, AlgorithmRSAOAEP256)
	assert.Error(t, err)
}
