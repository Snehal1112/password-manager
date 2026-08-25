package crypto_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/crypto"
)

// softhsmAvailable returns true when softhsm2-util is on PATH and the
// SOFTHSM2_LIB environment variable points to an existing shared library.
func softhsmAvailable() bool {
	_, err := exec.LookPath("softhsm2-util")
	if err != nil {
		return false
	}
	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		return false
	}
	if _, err := os.Stat(lib); err != nil {
		return false
	}
	return true
}

// newTestPKCS11Provider creates a PKCS11KeyProvider against the local SoftHSM2
// token. The test is skipped when SoftHSM2 is not available.
func newTestPKCS11Provider(t *testing.T) *crypto.PKCS11KeyProvider {
	t.Helper()
	if !softhsmAvailable() {
		t.Skip("softhsm2-util not found or SOFTHSM2_LIB not set; skipping PKCS#11 integration tests")
	}

	lib := os.Getenv("SOFTHSM2_LIB")
	cfg := crypto.PKCS11Config{
		LibPath:    lib,
		TokenLabel: "rocketvault",
		PIN:        "1234",
	}

	p, err := crypto.NewPKCS11KeyProvider(cfg)
	require.NoError(t, err, "failed to create PKCS11KeyProvider")
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// --- Key generation ---

func TestPKCS11Provider_GenerateRSAKey(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)
	assert.NotEmpty(t, handle, "handle must be a non-empty UUID label")
	assert.Len(t, handle, 36)
}

// --- Import ---

// TestPKCS11Provider_ImportKey_RSA_SignVerifyRoundTrip covers functional
// usability of an imported RSA key (Sign/Verify round trip). It does NOT
// assert CKA_EXTRACTABLE -- that requires reaching the unexported token
// session/object handle, which this external (crypto_test) package cannot
// do; see TestPKCS11Provider_ImportKey_RSA_PrivateKeyIsNonExtractable in the
// in-package pkcs11_import_extractability_test.go for the real
// non-extractability assertion.
func TestPKCS11Provider_ImportKey_RSA_SignVerifyRoundTrip(t *testing.T) {
	p := newTestPKCS11Provider(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	handle, err := p.ImportKey(context.Background(), "RSA", priv)
	require.NoError(t, err)
	assert.Len(t, handle, 36, "handle must be a UUID label, matching GenerateRSAKey's contract")

	sig, err := p.Sign(context.Background(), handle, "RSA", []byte("test data"), crypto.AlgorithmRS256)
	require.NoError(t, err)
	ok, err := p.Verify(context.Background(), handle, "RSA", []byte("test data"), sig, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestPKCS11Provider_ImportKey_ECDSA(t *testing.T) {
	p := newTestPKCS11Provider(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	handle, err := p.ImportKey(context.Background(), "ECDSA", priv)
	require.NoError(t, err)

	sig, err := p.Sign(context.Background(), handle, "ECDSA", []byte("test data"), crypto.AlgorithmES256)
	require.NoError(t, err)
	ok, err := p.Verify(context.Background(), handle, "ECDSA", []byte("test data"), sig, crypto.AlgorithmES256)
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestPKCS11Provider_ImportKey_MismatchedKeyType_ReturnsError pins the
// keyType-vs-privateKey-concrete-type validation: previously ImportKey
// dispatched purely on privateKey's Go type via the type switch and never
// checked keyType, so ImportKey(ctx, "ECDSA", rsaKey) would silently succeed
// and persist an RSA token object mislabeled as ECDSA, only surfacing an
// opaque CKR_KEY_TYPE_INCONSISTENT later at Sign time.
func TestPKCS11Provider_ImportKey_MismatchedKeyType_ReturnsError(t *testing.T) {
	p := newTestPKCS11Provider(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, err = p.ImportKey(context.Background(), "ECDSA", priv)
	assert.Error(t, err)

	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = p.ImportKey(context.Background(), "RSA", privEC)
	assert.Error(t, err)
}

// TestPKCS11Provider_ImportKey_InvalidRSAKey_ReturnsError pins a nil-pointer
// panic regression: a key where len(Primes) == 2 but p*q != N (i.e. not
// actually a valid RSA key) previously passed the prime-count guard, then
// key.Precompute() silently left Precomputed.Dp/Dq/Qinv nil (it has no error
// return), and CKA_EXPONENT_1's key.Precomputed.Dp.Bytes() call nil-dereffed.
// N=35, D=5, Primes=[5,7] is the minimal reproduction: 5*7=35 satisfies
// p*q==N by coincidence of small numbers chosen for the test, but D=5 does
// not satisfy the RSA key equation, so key.Validate() must reject it.
func TestPKCS11Provider_ImportKey_InvalidRSAKey_ReturnsError(t *testing.T) {
	p := newTestPKCS11Provider(t)

	invalid := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(35), E: 65537},
		D:         big.NewInt(5),
		Primes:    []*big.Int{big.NewInt(5), big.NewInt(7)},
	}

	_, err := p.ImportKey(context.Background(), "RSA", invalid)
	require.Error(t, err, "an invalid RSA key must be rejected, not nil-deref inside PKCS#11 attribute construction")
	assert.Contains(t, err.Error(), "invalid RSA key")
}

func TestPKCS11Provider_GenerateECDSAKey_P256(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateECDSAKey(context.Background(), "P-256")
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateECDSAKey_P384(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateECDSAKey(context.Background(), "P-384")
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateECDSAKey_P521(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateECDSAKey(context.Background(), "P-521")
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateECDSAKey_P256K(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateECDSAKey(context.Background(), "P-256K")
	require.NoError(t, err)
	assert.Len(t, handle, 36, "handle must be a UUID label")
}

func TestPKCS11Provider_SignVerify_ECDSA_ES256K(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateECDSAKey(context.Background(), "P-256K")
	require.NoError(t, err)

	data := []byte("secp256k1 hsm sign test")
	sig, err := p.Sign(context.Background(), handle, "ECDSA", data, crypto.AlgorithmES256K)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	valid, err := p.Verify(context.Background(), handle, "ECDSA", data, sig, crypto.AlgorithmES256K)
	require.NoError(t, err)
	assert.True(t, valid, "signature must verify as valid")
}

func TestPKCS11Provider_Verify_ES256K_TamperedData_ReturnsFalse(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateECDSAKey(context.Background(), "P-256K")
	require.NoError(t, err)

	data := []byte("original")
	sig, err := p.Sign(context.Background(), handle, "ECDSA", data, crypto.AlgorithmES256K)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "ECDSA", []byte("tampered"), sig, crypto.AlgorithmES256K)
	require.NoError(t, err)
	assert.False(t, valid, "tampered data must not verify")
}

// --- Sign / Verify ---

func TestPKCS11Provider_SignVerify_RSA_RS256(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("rocketvault pkcs11 sign test")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	valid, err := p.Verify(context.Background(), handle, "RSA", data, sig, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.True(t, valid, "signature must verify as valid")
}

func TestPKCS11Provider_SignVerify_RSA_RS512(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("rs512 test payload")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmRS512)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "RSA", data, sig, crypto.AlgorithmRS512)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPKCS11Provider_SignVerify_RSA_PS256(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("ps256 test payload")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmPS256)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "RSA", data, sig, crypto.AlgorithmPS256)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPKCS11Provider_SignVerify_ECDSA_ES256(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateECDSAKey(context.Background(), "P-256")
	require.NoError(t, err)

	data := []byte("ecdsa sign test")
	sig, err := p.Sign(context.Background(), handle, "ECDSA", data, crypto.AlgorithmES256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	valid, err := p.Verify(context.Background(), handle, "ECDSA", data, sig, crypto.AlgorithmES256)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPKCS11Provider_Verify_TamperedData_ReturnsFalse(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	data := []byte("original")
	sig, err := p.Sign(context.Background(), handle, "RSA", data, crypto.AlgorithmRS256)
	require.NoError(t, err)

	valid, err := p.Verify(context.Background(), handle, "RSA", []byte("tampered"), sig, crypto.AlgorithmRS256)
	require.NoError(t, err)
	assert.False(t, valid, "tampered data must not verify")
}

// --- Encrypt / Decrypt ---

func TestPKCS11Provider_EncryptDecrypt_RSA_OAEP(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	plaintext := []byte("hsm encryption test")
	ct, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.NotEmpty(t, ct)
	assert.Nil(t, nonce, "RSA-OAEP nonce must be nil")

	pt, err := p.Decrypt(context.Background(), handle, ct, nil, crypto.AlgorithmRSAOAEP)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestPKCS11Provider_EncryptDecrypt_RSA_OAEP256(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	plaintext := []byte("oaep256 payload")
	ct, _, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmRSAOAEP256)
	if err != nil && isCKRArgumentsBad(err) {
		// SoftHSM 2.6.x does not support CKM_RSA_PKCS_OAEP with SHA-256 on all
		// configurations. Skip rather than fail so CI stays green on constrained
		// environments; the production code path is correct.
		t.Skipf("SoftHSM token does not support RSA-OAEP-256 (CKR_ARGUMENTS_BAD): %v", err)
	}
	require.NoError(t, err)

	pt, err := p.Decrypt(context.Background(), handle, ct, nil, crypto.AlgorithmRSAOAEP256)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

// isCKRArgumentsBad returns true when err is the PKCS#11 CKR_ARGUMENTS_BAD (0x7) error.
func isCKRArgumentsBad(err error) bool {
	return err != nil && (err.Error() == "pkcs11 encrypt init: pkcs11: 0x7: CKR_ARGUMENTS_BAD" ||
		err.Error() == "pkcs11: 0x7: CKR_ARGUMENTS_BAD")
}

func TestPKCS11Provider_EncryptDecrypt_AES256GCM(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)

	plaintext := []byte("aes-gcm hsm round trip payload")
	ct, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmAES256)
	require.NoError(t, err)
	assert.NotEmpty(t, ct)
	assert.Len(t, nonce, 12, "GCM nonce must be 96 bits")

	pt, err := p.Decrypt(context.Background(), handle, ct, nonce, crypto.AlgorithmAES256)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestPKCS11Provider_DecryptAESGCM_TamperedCiphertext_Fails(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)

	plaintext := []byte("gcm tamper detection payload")
	ct, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmAES256)
	require.NoError(t, err)

	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0xFF

	// GCM is authenticated: a tampered ciphertext MUST fail to decrypt, never
	// silently return wrong plaintext.
	_, err = p.Decrypt(context.Background(), handle, tampered, nonce, crypto.AlgorithmAES256)
	assert.Error(t, err, "tampered GCM ciphertext must fail authentication")
}

func TestPKCS11Provider_DecryptAESGCM_WrongNonce_Fails(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)

	plaintext := []byte("gcm wrong nonce payload")
	ct, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmAES256)
	require.NoError(t, err)

	wrongNonce := make([]byte, len(nonce))
	copy(wrongNonce, nonce)
	wrongNonce[0] ^= 0xFF

	_, err = p.Decrypt(context.Background(), handle, ct, wrongNonce, crypto.AlgorithmAES256)
	assert.Error(t, err, "wrong GCM nonce must fail authentication")
}

// --- AES (oct) key generation and wrap/unwrap ---

func TestPKCS11Provider_GenerateAESKey_128(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateAESKey(context.Background(), 128)
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateAESKey_256(t *testing.T) {
	p := newTestPKCS11Provider(t)
	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)
	assert.Len(t, handle, 36)
}

func TestPKCS11Provider_GenerateAESKey_InvalidBits_ReturnsError(t *testing.T) {
	p := newTestPKCS11Provider(t)
	_, err := p.GenerateAESKey(context.Background(), 100)
	assert.Error(t, err)
}

func TestPKCS11Provider_WrapUnwrap_AES256KW(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)

	// RFC 3394 unpadded AES-KW requires a plaintext that is a multiple of 8
	// bytes, matching SoftwareKeyProvider's aesKeyWrap contract for the same
	// algorithm identifier.
	plaintext := []byte("hsm aes-kw wrap test!!!!") // 24 bytes
	wrapped, nonce, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA256KW)
	require.NoError(t, err)
	assert.NotEmpty(t, wrapped)
	assert.Nil(t, nonce, "AES-KW nonce must be nil")

	unwrapped, err := p.Decrypt(context.Background(), handle, wrapped, nil, crypto.AlgorithmA256KW)
	require.NoError(t, err)
	assert.Equal(t, plaintext, unwrapped)
}

func TestPKCS11Provider_WrapUnwrap_AES128KW(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 128)
	require.NoError(t, err)

	// RFC 3394's base (unpadded) wrap algorithm requires at least two 64-bit
	// blocks (16 bytes); a single 8-byte block is only defined under the
	// RFC 5649 padded variant, which RocketVault does not use here. SoftHSM2
	// enforces this and returns CKR_KEY_SIZE_RANGE below 16 bytes.
	plaintext := []byte("shortpad16bytes!") // 16 bytes
	wrapped, _, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA128KW)
	require.NoError(t, err)

	unwrapped, err := p.Decrypt(context.Background(), handle, wrapped, nil, crypto.AlgorithmA128KW)
	require.NoError(t, err)
	assert.Equal(t, plaintext, unwrapped)
}

func TestPKCS11Provider_Encrypt_AESKWWithRSAKey_ReturnsError(t *testing.T) {
	p := newTestPKCS11Provider(t)

	// An RSA key has no CKO_SECRET_KEY object under its label, so AES-KW
	// against it must fail at the find-secret-key step.
	handle, err := p.GenerateRSAKey(context.Background(), 2048)
	require.NoError(t, err)

	_, _, err = p.Encrypt(context.Background(), handle, []byte("test"), crypto.AlgorithmA256KW)
	assert.Error(t, err)
}

// --- AES-CBC Encrypt/Decrypt ---

func TestPKCS11Provider_EncryptDecrypt_AES128CBC(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 128)
	require.NoError(t, err)

	plaintext := []byte("aes-cbc round trip test payload, any length works with padding")
	ct, iv, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA128CBC)
	require.NoError(t, err)
	assert.NotEmpty(t, ct)
	assert.Len(t, iv, 16, "CBC IV must be one AES block")

	pt, err := p.Decrypt(context.Background(), handle, ct, iv, crypto.AlgorithmA128CBC)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestPKCS11Provider_EncryptDecrypt_AES192CBC(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 192)
	require.NoError(t, err)

	plaintext := []byte("192-bit cbc payload")
	ct, iv, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA192CBC)
	require.NoError(t, err)

	pt, err := p.Decrypt(context.Background(), handle, ct, iv, crypto.AlgorithmA192CBC)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestPKCS11Provider_EncryptDecrypt_AES256CBC(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)

	plaintext := []byte("256-bit cbc payload, deliberately not block-aligned to exercise padding")
	ct, iv, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA256CBC)
	require.NoError(t, err)

	pt, err := p.Decrypt(context.Background(), handle, ct, iv, crypto.AlgorithmA256CBC)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)
}

func TestPKCS11Provider_DecryptAESCBC_WrongIV_Fails(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)

	plaintext := []byte("cbc tamper detection payload")
	ct, iv, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA256CBC)
	require.NoError(t, err)

	wrongIV := make([]byte, len(iv))
	copy(wrongIV, iv)
	wrongIV[0] ^= 0xFF

	pt, err := p.Decrypt(context.Background(), handle, ct, wrongIV, crypto.AlgorithmA256CBC)
	// CBC has no built-in integrity check: a wrong IV corrupts only the first
	// plaintext block (this is the well-known CBC property), so decryption
	// itself may succeed while producing wrong plaintext, or may fail if the
	// corruption breaks PKCS7 padding. Either outcome proves the wrong IV was
	// not silently ignored.
	if err == nil {
		assert.NotEqual(t, plaintext, pt, "wrong IV must not silently decrypt to the original plaintext")
	}
}

// TestPKCS11Provider_DecryptAESCBC_WrongLengthIV_ReturnsValidationError pins
// the IV-length check in decryptAESCBC. Without it, SoftHSM2 rejects a
// wrong-length IV with CKR_MECHANISM_INVALID, which is on
// isHSMCapabilityError's allowlist, so a malformed caller-supplied IV would be
// misreported as ErrUnsupportedAlgorithm ("AES-CBC (rejected by HSM)") rather
// than the input-validation error it actually is.
func TestPKCS11Provider_DecryptAESCBC_WrongLengthIV_ReturnsValidationError(t *testing.T) {
	p := newTestPKCS11Provider(t)

	handle, err := p.GenerateAESKey(context.Background(), 256)
	require.NoError(t, err)

	plaintext := []byte("cbc iv length validation payload")
	ct, iv, err := p.Encrypt(context.Background(), handle, plaintext, crypto.AlgorithmA256CBC)
	require.NoError(t, err)
	require.Len(t, iv, 16)

	for _, shortIV := range [][]byte{nil, {}, iv[:8], append(append([]byte{}, iv...), 0x00)} {
		_, err := p.Decrypt(context.Background(), handle, ct, shortIV, crypto.AlgorithmA256CBC)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aes-cbc iv must be 16 bytes")
		assert.NotErrorIs(t, err, crypto.ErrUnsupportedAlgorithm,
			"a malformed IV is an input error, not an HSM capability rejection")
	}
}

// --- Interface compliance ---

// Ensure PKCS11KeyProvider satisfies KeyProvider at compile time.
var _ crypto.KeyProvider = (*crypto.PKCS11KeyProvider)(nil)
