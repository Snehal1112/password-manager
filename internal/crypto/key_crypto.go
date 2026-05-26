// Package crypto provides cryptographic utilities for the password manager.
// It includes key generation, X.509 certificate operations, and encryption helpers.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/sirupsen/logrus"
)

// GenerateRSAKeyPEM generates an RSA private key and returns it as PEM-encoded string.
//
// Parameters:
//   - bits: The RSA key size in bits (e.g., 2048, 4096).
//
// Returns:
//
//	The PEM-encoded RSA private key as a string or an error if generation fails.
func GenerateRSAKeyPEM(bits int) (string, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate RSA key")
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return string(privateKeyPEM), nil
}

// GenerateECDSAKeyPEM generates an ECDSA private key and returns it as PEM-encoded string.
//
// Parameters:
//   - curveName: The elliptic curve name ("P-256", "P-384", "P-521").
//
// Returns:
//
//	The PEM-encoded ECDSA private key as a string or an error if generation fails.
func GenerateECDSAKeyPEM(curveName string) (string, error) {
	// Handle secp256k1 separately — it is not in the standard library.
	if curveName == "P-256K" {
		privKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return "", fmt.Errorf("failed to generate secp256k1 key: %w", err)
		}
		return MarshalSecp256k1PrivateKeyPEM(privKey)
	}

	var curve elliptic.Curve
	switch curveName {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return "", fmt.Errorf("unsupported curve: %s", curveName)
	}

	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate ECDSA key")
		return "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Encode private key to PEM
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal ECDSA key")
		return "", fmt.Errorf("failed to marshal ECDSA key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

// ParsePrivateKey parses a PEM-encoded private key based on its type.
// It supports RSA and ECDSA keys.
//
// Parameters:
//   - pemData: The PEM-encoded private key data.
//   - keyType: The type of key ("RSA" or "ECDSA").
//
// Returns:
//
//	The parsed private key (as any) or an error if parsing fails.
func ParsePrivateKey(pemData, keyType string) (any, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	switch keyType {
	case "RSA":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		return privateKey, nil
	case "ECDSA":
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		return privateKey, nil
	case "ES256K":
		// block.Bytes holds the raw 32-byte scalar written by MarshalSecp256k1PrivateKeyPEM.
		return secp256k1.PrivKeyFromBytes(block.Bytes), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// ExtractPublicComponents parses a PEM-encoded private key and returns the
// base64url-encoded public key components. Returns empty strings for PKCS#11
// keys (which carry a label, not PEM).
func ExtractPublicComponents(pemOrHandle string, keyType string) (n, e, x, y string, err error) {
	if strings.HasPrefix(pemOrHandle, "pkcs11:") {
		return "", "", "", "", nil
	}
	block, _ := pem.Decode([]byte(pemOrHandle))
	if block == nil {
		return "", "", "", "", fmt.Errorf("failed to decode PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if parseErr != nil {
			return "", "", "", "", fmt.Errorf("parse RSA private key: %w", parseErr)
		}
		n = base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes())
		eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
		e = base64.RawURLEncoding.EncodeToString(eBytes)
		return n, e, "", "", nil
	case "EC PRIVATE KEY":
		priv, parseErr := x509.ParseECPrivateKey(block.Bytes)
		if parseErr != nil {
			return "", "", "", "", fmt.Errorf("parse EC private key: %w", parseErr)
		}
		byteLen := (priv.PublicKey.Curve.Params().BitSize + 7) / 8
		xb := make([]byte, byteLen)
		yb := make([]byte, byteLen)
		priv.PublicKey.X.FillBytes(xb)
		priv.PublicKey.Y.FillBytes(yb)
		x = base64.RawURLEncoding.EncodeToString(xb)
		y = base64.RawURLEncoding.EncodeToString(yb)
		return "", "", x, y, nil
	default:
		return "", "", "", "", fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// MarshalSecp256k1PrivateKeyPEM serialises a secp256k1 private key to PEM.
// The PEM body contains the raw 32-byte key scalar (not DER/ASN.1),
// which is what ParsePrivateKey("ES256K") expects.
func MarshalSecp256k1PrivateKeyPEM(privKey *secp256k1.PrivateKey) (string, error) {
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKey.Serialize(),
	})
	if pemBlock == nil {
		return "", fmt.Errorf("failed to encode secp256k1 key to PEM")
	}
	return string(pemBlock), nil
}
