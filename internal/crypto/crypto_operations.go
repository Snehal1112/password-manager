package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
)

// SignatureAlgorithm represents the signing algorithm to use.
type SignatureAlgorithm string

const (
	// RSA signature algorithms
	AlgorithmRS256 SignatureAlgorithm = "RS256" // RSA with SHA-256
	AlgorithmRS384 SignatureAlgorithm = "RS384" // RSA with SHA-384
	AlgorithmRS512 SignatureAlgorithm = "RS512" // RSA with SHA-512

	// ECDSA signature algorithms
	AlgorithmES256 SignatureAlgorithm = "ES256" // ECDSA with SHA-256
	AlgorithmES384 SignatureAlgorithm = "ES384" // ECDSA with SHA-384
	AlgorithmES512 SignatureAlgorithm = "ES512" // ECDSA with SHA-512

	// RSA-PSS — Azure "PS256", "PS384", "PS512".
	AlgorithmPS256 SignatureAlgorithm = "PS256"
	AlgorithmPS384 SignatureAlgorithm = "PS384"
	AlgorithmPS512 SignatureAlgorithm = "PS512"
)

// EncryptionAlgorithm represents the encryption algorithm to use.
type EncryptionAlgorithm string

const (
	// AlgorithmRSAOAEP uses RSA-OAEP with SHA-1 — matches Azure SDK default "RSA-OAEP".
	AlgorithmRSAOAEP    EncryptionAlgorithm = "RSA-OAEP"
	// AlgorithmRSAOAEP256 uses RSA-OAEP with SHA-256 — matches Azure "RSA-OAEP-256".
	AlgorithmRSAOAEP256 EncryptionAlgorithm = "RSA-OAEP-256"
	AlgorithmAES256     EncryptionAlgorithm = "AES256-GCM" // AES-256-GCM
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
// Supports RSA and ECDSA keys with various hash algorithms.
func (c *CryptoOperations) Sign(privateKeyPEM string, keyType string, data []byte, algorithm SignatureAlgorithm) (*SignResult, error) {
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

// getHasher returns the appropriate hash function for the algorithm.
func getHasher(algorithm SignatureAlgorithm) (hash.Hash, error) {
	switch algorithm {
	case AlgorithmRS256, AlgorithmES256, AlgorithmPS256:
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
