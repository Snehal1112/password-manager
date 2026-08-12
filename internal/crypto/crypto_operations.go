package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// SignatureAlgorithm represents the signing algorithm to use.
type SignatureAlgorithm string

const (
	// RSA signature algorithms
	AlgorithmRS256 SignatureAlgorithm = "RS256" // RSA with SHA-256
	AlgorithmRS384 SignatureAlgorithm = "RS384" // RSA with SHA-384
	AlgorithmRS512 SignatureAlgorithm = "RS512" // RSA with SHA-512

	// ECDSA signature algorithms
	AlgorithmES256  SignatureAlgorithm = "ES256"  // ECDSA with SHA-256
	AlgorithmES384  SignatureAlgorithm = "ES384"  // ECDSA with SHA-384
	AlgorithmES512  SignatureAlgorithm = "ES512"  // ECDSA with SHA-512
	AlgorithmES256K SignatureAlgorithm = "ES256K" // ECDSA with SHA-256 on secp256k1

	AlgorithmPS256 SignatureAlgorithm = "PS256" // RSA-PSS with SHA-256
	AlgorithmPS384 SignatureAlgorithm = "PS384" // RSA-PSS with SHA-384
	AlgorithmPS512 SignatureAlgorithm = "PS512" // RSA-PSS with SHA-512

	// HMAC signature algorithms (oct key type).
	AlgorithmHS256 SignatureAlgorithm = "HS256" // HMAC with SHA-256
	AlgorithmHS384 SignatureAlgorithm = "HS384" // HMAC with SHA-384
	AlgorithmHS512 SignatureAlgorithm = "HS512" // HMAC with SHA-512
)

// KeyTypeOct is the symmetric key type (raw bytes, base64-encoded).
const KeyTypeOct = "oct"

// EncryptionAlgorithm represents the encryption algorithm to use.
type EncryptionAlgorithm string

const (
	// AlgorithmRSAOAEP uses RSA-OAEP with SHA-1 — matches Azure SDK default "RSA-OAEP".
	AlgorithmRSAOAEP EncryptionAlgorithm = "RSA-OAEP"
	// AlgorithmRSAOAEP256 uses RSA-OAEP with SHA-256 — matches Azure "RSA-OAEP-256".
	AlgorithmRSAOAEP256 EncryptionAlgorithm = "RSA-OAEP-256"
	AlgorithmAES256     EncryptionAlgorithm = "AES256-GCM" // AES-256-GCM

	// AlgorithmRSA1_5 uses PKCS1v15 RSA encryption.
	AlgorithmRSA1_5 EncryptionAlgorithm = "RSA1_5"

	// AES key-wrap algorithms (RFC 3394).
	AlgorithmA128KW EncryptionAlgorithm = "A128KW"
	AlgorithmA192KW EncryptionAlgorithm = "A192KW"
	AlgorithmA256KW EncryptionAlgorithm = "A256KW"

	// AES-CBC algorithms with PKCS7 padding.
	AlgorithmA128CBC EncryptionAlgorithm = "A128CBC"
	AlgorithmA192CBC EncryptionAlgorithm = "A192CBC"
	AlgorithmA256CBC EncryptionAlgorithm = "A256CBC"
)

// SignResult contains the signature and metadata.
type SignResult struct {
	Signature []byte
	Algorithm SignatureAlgorithm
	Digest    []byte // The hashed data that was signed
}

// VerifyResult contains verification result and metadata.
type VerifyResult struct {
	Valid     bool
	Algorithm SignatureAlgorithm
	Digest    []byte
}

// EncryptResult contains encrypted data and metadata.
type EncryptResult struct {
	Ciphertext []byte
	Algorithm  EncryptionAlgorithm
	Nonce      []byte // For AES-GCM
}

// DecryptResult contains decrypted data.
type DecryptResult struct {
	Plaintext []byte
	Algorithm EncryptionAlgorithm
}

// CryptoOperations provides cryptographic sign/verify/encrypt/decrypt operations.
type CryptoOperations struct{}

// NewCryptoOperations creates a new crypto operations instance.
func NewCryptoOperations() *CryptoOperations {
	return &CryptoOperations{}
}

// Sign signs data using the provided private key.
// Supports RSA, ECDSA, and oct (HMAC) keys with various hash algorithms.
func (c *CryptoOperations) Sign(privateKeyPEM string, keyType string, data []byte, algorithm SignatureAlgorithm) (*SignResult, error) {
	// Handle HMAC (oct) keys directly — no PEM parsing needed.
	if keyType == KeyTypeOct {
		keyBytes, err := base64.StdEncoding.DecodeString(privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode oct key: %w", err)
		}
		var h hash.Hash
		switch algorithm {
		case AlgorithmHS384:
			h = hmac.New(sha512.New384, keyBytes)
		case AlgorithmHS512:
			h = hmac.New(sha512.New, keyBytes)
		default:
			h = hmac.New(sha256.New, keyBytes)
		}
		h.Write(data)
		return &SignResult{Signature: h.Sum(nil), Algorithm: algorithm}, nil
	}

	// Parse private key
	privateKey, err := ParsePrivateKey(privateKeyPEM, keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Hash the data
	hasher, err := getHasher(algorithm)
	if err != nil {
		return nil, err
	}
	hasher.Write(data)
	digest := hasher.Sum(nil)

	var signature []byte

	switch keyType {
	case "RSA":
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA private key")
		}
		hashType, err := getHashType(algorithm)
		if err != nil {
			return nil, err
		}
		switch algorithm {
		case AlgorithmPS256, AlgorithmPS384, AlgorithmPS512:
			signature, err = rsa.SignPSS(rand.Reader, rsaKey, hashType, digest, nil)
		default:
			signature, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, hashType, digest)
		}
		if err != nil {
			return nil, fmt.Errorf("RSA signing failed: %w", err)
		}

	case "ECDSA":
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid ECDSA private key")
		}

		signature, err = ecdsa.SignASN1(rand.Reader, ecdsaKey, digest)
		if err != nil {
			return nil, fmt.Errorf("ECDSA signing failed: %w", err)
		}

	case "ES256K":
		sk256k, ok := privateKey.(*secp256k1.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secp256k1 private key")
		}
		// Sign returns a deterministic DER-encoded signature.
		sig := secp256k1ecdsa.Sign(sk256k, digest)
		signature = sig.Serialize()

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	return &SignResult{
		Signature: signature,
		Algorithm: algorithm,
		Digest:    digest,
	}, nil
}

// Verify verifies a signature using the provided public key.
func (c *CryptoOperations) Verify(publicKeyPEM string, keyType string, data []byte, signature []byte, algorithm SignatureAlgorithm) (*VerifyResult, error) {
	// Handle HMAC (oct) keys directly — no PEM parsing needed.
	if keyType == KeyTypeOct {
		keyBytes, err := base64.StdEncoding.DecodeString(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode oct key: %w", err)
		}
		var h hash.Hash
		switch algorithm {
		case AlgorithmHS384:
			h = hmac.New(sha512.New384, keyBytes)
		case AlgorithmHS512:
			h = hmac.New(sha512.New, keyBytes)
		default:
			h = hmac.New(sha256.New, keyBytes)
		}
		h.Write(data)
		expected := h.Sum(nil)
		return &VerifyResult{Valid: hmac.Equal(expected, signature), Algorithm: algorithm}, nil
	}

	// Parse private key to extract public key
	privateKey, err := ParsePrivateKey(publicKeyPEM, keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	// Hash the data
	hasher, err := getHasher(algorithm)
	if err != nil {
		return nil, err
	}
	hasher.Write(data)
	digest := hasher.Sum(nil)

	var valid bool

	switch keyType {
	case "RSA":
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA private key")
		}
		hashType, err := getHashType(algorithm)
		if err != nil {
			return nil, err
		}
		var verifyErr error
		switch algorithm {
		case AlgorithmPS256, AlgorithmPS384, AlgorithmPS512:
			verifyErr = rsa.VerifyPSS(&rsaKey.PublicKey, hashType, digest, signature, nil)
		default:
			verifyErr = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, hashType, digest, signature)
		}
		valid = (verifyErr == nil)

	case "ECDSA":
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid ECDSA private key")
		}

		valid = ecdsa.VerifyASN1(&ecdsaKey.PublicKey, digest, signature)

	case "ES256K":
		sk256k, ok := privateKey.(*secp256k1.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid secp256k1 private key")
		}
		parsedSig, err := secp256k1ecdsa.ParseDERSignature(signature)
		if err != nil {
			valid = false
		} else {
			valid = parsedSig.Verify(digest, sk256k.PubKey())
		}

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	return &VerifyResult{
		Valid:     valid,
		Algorithm: algorithm,
		Digest:    digest,
	}, nil
}

// Encrypt encrypts data using the specified algorithm.
func (c *CryptoOperations) Encrypt(keyData string, data []byte, algorithm EncryptionAlgorithm) (*EncryptResult, error) {
	switch algorithm {
	case AlgorithmRSAOAEP:
		return c.encryptRSAOAEP(keyData, data, false) // SHA-1
	case AlgorithmRSAOAEP256:
		return c.encryptRSAOAEP(keyData, data, true) // SHA-256
	case AlgorithmAES256:
		return c.encryptAES(keyData, data)
	case AlgorithmRSA1_5:
		return c.encryptRSA1_5(keyData, data)
	case AlgorithmA128KW, AlgorithmA192KW, AlgorithmA256KW:
		return c.wrapAES(keyData, data, algorithm)
	case AlgorithmA128CBC, AlgorithmA192CBC, AlgorithmA256CBC:
		return c.encryptAESCBC(keyData, data, algorithm)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}

// Decrypt decrypts data using the specified algorithm.
func (c *CryptoOperations) Decrypt(keyData string, ciphertext []byte, nonce []byte, algorithm EncryptionAlgorithm) (*DecryptResult, error) {
	switch algorithm {
	case AlgorithmRSAOAEP:
		return c.decryptRSAOAEP(keyData, ciphertext, false) // SHA-1
	case AlgorithmRSAOAEP256:
		return c.decryptRSAOAEP(keyData, ciphertext, true) // SHA-256
	case AlgorithmAES256:
		return c.decryptAES(keyData, ciphertext, nonce)
	case AlgorithmRSA1_5:
		return c.decryptRSA1_5(keyData, ciphertext)
	case AlgorithmA128KW, AlgorithmA192KW, AlgorithmA256KW:
		return c.unwrapAES(keyData, ciphertext, algorithm)
	case AlgorithmA128CBC, AlgorithmA192CBC, AlgorithmA256CBC:
		return c.decryptAESCBC(keyData, ciphertext, nonce, algorithm)
	default:
		return nil, fmt.Errorf("unsupported decryption algorithm: %s", algorithm)
	}
}

// encryptRSAOAEP encrypts data using RSA-OAEP.
// useSHA256=false uses SHA-1 (matches Azure "RSA-OAEP").
// useSHA256=true  uses SHA-256 (matches Azure "RSA-OAEP-256").
func (c *CryptoOperations) encryptRSAOAEP(privateKeyPEM string, data []byte, useSHA256 bool) (*EncryptResult, error) {
	privateKey, err := ParsePrivateKey(privateKeyPEM, "RSA")
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA private key")
	}

	var h hash.Hash
	algo := AlgorithmRSAOAEP
	if useSHA256 {
		h = sha256.New()
		algo = AlgorithmRSAOAEP256
	} else {
		h = sha1.New()
	}

	ciphertext, err := rsa.EncryptOAEP(h, rand.Reader, &rsaKey.PublicKey, data, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}
	return &EncryptResult{Ciphertext: ciphertext, Algorithm: algo}, nil
}

// decryptRSAOAEP decrypts data using RSA-OAEP.
func (c *CryptoOperations) decryptRSAOAEP(privateKeyPEM string, ciphertext []byte, useSHA256 bool) (*DecryptResult, error) {
	privateKey, err := ParsePrivateKey(privateKeyPEM, "RSA")
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA private key")
	}

	var h hash.Hash
	algo := AlgorithmRSAOAEP
	if useSHA256 {
		h = sha256.New()
		algo = AlgorithmRSAOAEP256
	} else {
		h = sha1.New()
	}

	plaintext, err := rsa.DecryptOAEP(h, rand.Reader, rsaKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decryption failed: %w", err)
	}
	return &DecryptResult{Plaintext: plaintext, Algorithm: algo}, nil
}

// encryptAES encrypts data using AES-256-GCM.
func (c *CryptoOperations) encryptAES(keyBase64 string, data []byte) (*EncryptResult, error) {
	// Decode the base64-encoded key
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires a 32-byte key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	return &EncryptResult{
		Ciphertext: ciphertext,
		Algorithm:  AlgorithmAES256,
		Nonce:      nonce,
	}, nil
}

// decryptAES decrypts data using AES-256-GCM.
func (c *CryptoOperations) decryptAES(keyBase64 string, ciphertext []byte, nonce []byte) (*DecryptResult, error) {
	// Decode the base64-encoded key
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires a 32-byte key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}

	return &DecryptResult{
		Plaintext: plaintext,
		Algorithm: AlgorithmAES256,
	}, nil
}

// encryptRSA1_5 encrypts data using RSA PKCS1v15.
func (c *CryptoOperations) encryptRSA1_5(privateKeyPEM string, data []byte) (*EncryptResult, error) {
	key, err := ParsePrivateKey(privateKeyPEM, "RSA")
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA private key")
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, data)
	if err != nil {
		return nil, fmt.Errorf("RSA1_5 encrypt failed: %w", err)
	}
	return &EncryptResult{Ciphertext: ciphertext, Algorithm: AlgorithmRSA1_5}, nil
}

// decryptRSA1_5 decrypts data using RSA PKCS1v15.
func (c *CryptoOperations) decryptRSA1_5(privateKeyPEM string, ciphertext []byte) (*DecryptResult, error) {
	key, err := ParsePrivateKey(privateKeyPEM, "RSA")
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid RSA private key")
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, rsaKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("RSA1_5 decrypt failed: %w", err)
	}
	return &DecryptResult{Plaintext: plaintext, Algorithm: AlgorithmRSA1_5}, nil
}

// aesKeyWrap implements RFC 3394 AES key wrap.
func aesKeyWrap(key, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("AES-KW plaintext must be a multiple of 8 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// a is the running integrity check value initialised to the RFC IV.
	a := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	n := len(plaintext) / 8
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a[:])
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			// XOR the high 64 bits with the step counter.
			t := uint64(n*j + i + 1)
			for k := 7; k >= 0; k-- {
				buf[k] ^= byte(t)
				t >>= 8
			}
			copy(a[:], buf[:8])
			copy(r[i], buf[8:])
		}
	}
	out := make([]byte, 8+len(plaintext))
	copy(out[:8], a[:])
	for i, ri := range r {
		copy(out[8+i*8:], ri)
	}
	return out, nil
}

// aesKeyUnwrap implements RFC 3394 AES key unwrap.
func aesKeyUnwrap(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, fmt.Errorf("AES-KW ciphertext has invalid length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext)/8 - 1
	var a [8]byte
	copy(a[:], ciphertext[:8])
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[8+i*8:])
	}
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			// XOR the high 64 bits with the step counter before decryption.
			t := uint64(n*j + i + 1)
			copy(buf[:8], a[:])
			for k := 7; k >= 0; k-- {
				buf[k] ^= byte(t)
				t >>= 8
			}
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)
			copy(a[:], buf[:8])
			copy(r[i], buf[8:])
		}
	}
	// Verify the RFC IV to detect corruption or wrong key.
	iv := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	if a != iv {
		return nil, fmt.Errorf("AES-KW integrity check failed")
	}
	out := make([]byte, n*8)
	for i, ri := range r {
		copy(out[i*8:], ri)
	}
	return out, nil
}

// wrapAES wraps key material using AES key wrap (RFC 3394).
func (c *CryptoOperations) wrapAES(keyBase64 string, data []byte, algorithm EncryptionAlgorithm) (*EncryptResult, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES-KW key: %w", err)
	}
	if expected := aesKeySize(algorithm); expected != 0 && len(key) != expected {
		return nil, fmt.Errorf("key size mismatch: algorithm %s requires %d bytes, got %d", algorithm, expected, len(key))
	}
	wrapped, err := aesKeyWrap(key, data)
	if err != nil {
		return nil, fmt.Errorf("AES-KW wrap failed: %w", err)
	}
	return &EncryptResult{Ciphertext: wrapped, Algorithm: algorithm}, nil
}

// unwrapAES unwraps key material using AES key wrap (RFC 3394).
func (c *CryptoOperations) unwrapAES(keyBase64 string, ciphertext []byte, algorithm EncryptionAlgorithm) (*DecryptResult, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES-KW key: %w", err)
	}
	if expected := aesKeySize(algorithm); expected != 0 && len(key) != expected {
		return nil, fmt.Errorf("key size mismatch: algorithm %s requires %d bytes, got %d", algorithm, expected, len(key))
	}
	plaintext, err := aesKeyUnwrap(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("AES-KW unwrap failed: %w", err)
	}
	return &DecryptResult{Plaintext: plaintext, Algorithm: algorithm}, nil
}

// encryptAESCBC encrypts data using AES-CBC with PKCS7 padding.
func (c *CryptoOperations) encryptAESCBC(keyBase64 string, data []byte, algorithm EncryptionAlgorithm) (*EncryptResult, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES-CBC key: %w", err)
	}
	if expected := aesKeySize(algorithm); expected != 0 && len(key) != expected {
		return nil, fmt.Errorf("key size mismatch: algorithm %s requires %d bytes, got %d", algorithm, expected, len(key))
	}
	// Apply PKCS7 padding so the plaintext is a multiple of the block size.
	bs := aes.BlockSize
	pad := bs - len(data)%bs
	padded := make([]byte, len(data)+pad)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	iv := make([]byte, bs)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return &EncryptResult{Ciphertext: ciphertext, Algorithm: algorithm, Nonce: iv}, nil
}

// decryptAESCBC decrypts data using AES-CBC and strips PKCS7 padding.
func (c *CryptoOperations) decryptAESCBC(keyBase64 string, ciphertext []byte, iv []byte, algorithm EncryptionAlgorithm) (*DecryptResult, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES-CBC key: %w", err)
	}
	if expected := aesKeySize(algorithm); expected != 0 && len(key) != expected {
		return nil, fmt.Errorf("key size mismatch: algorithm %s requires %d bytes, got %d", algorithm, expected, len(key))
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length is not a multiple of the block size")
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	// Remove PKCS7 padding.
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext after decryption")
	}
	pad := int(plaintext[len(plaintext)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, fmt.Errorf("invalid PKCS7 padding")
	}
	for i := len(plaintext) - pad; i < len(plaintext); i++ {
		if plaintext[i] != byte(pad) {
			return nil, fmt.Errorf("invalid PKCS7 padding")
		}
	}
	return &DecryptResult{Plaintext: plaintext[:len(plaintext)-pad], Algorithm: algorithm}, nil
}

// aesKeySize returns the expected key byte length for an AES algorithm name.
// Returns 0 for unknown algorithms.
func aesKeySize(alg EncryptionAlgorithm) int {
	switch alg {
	case AlgorithmA128KW, AlgorithmA128CBC:
		return 16
	case AlgorithmA192KW, AlgorithmA192CBC:
		return 24
	case AlgorithmA256KW, AlgorithmA256CBC:
		return 32
	default:
		return 0
	}
}

// getHasher returns the appropriate hash function for the algorithm.
func getHasher(algorithm SignatureAlgorithm) (hash.Hash, error) {
	switch algorithm {
	case AlgorithmRS256, AlgorithmES256, AlgorithmPS256, AlgorithmES256K:
		return sha256.New(), nil
	case AlgorithmRS384, AlgorithmES384, AlgorithmPS384:
		return sha512.New384(), nil
	case AlgorithmRS512, AlgorithmES512, AlgorithmPS512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// getHashType returns the crypto.Hash type for RSA signature verification.
func getHashType(algorithm SignatureAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case AlgorithmRS256, AlgorithmPS256:
		return crypto.SHA256, nil
	case AlgorithmRS384, AlgorithmPS384:
		return crypto.SHA384, nil
	case AlgorithmRS512, AlgorithmPS512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported RSA algorithm: %s", algorithm)
	}
}
