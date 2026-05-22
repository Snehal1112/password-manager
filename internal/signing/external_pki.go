package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

// ExternalPKIProvider reads a PEM private key from an env var or a file path.
// It supports RSA (→ RS256) and ECDSA (→ ES256); algorithm is auto-detected.
// There is no runtime rotation — operators replace the key and restart.
type ExternalPKIProvider struct {
	privateKey crypto.Signer
	publicInfo []PublicKeyInfo
	algorithm  string
	kid        string
}

// NewExternalPKIProvider loads the signing key. Priority:
//  1. ROCKETVAULT_JWT_SIGNING_KEY env var (base64-encoded PEM)
//  2. File at signingKeyFile config path
//  3. Error if neither is set
func NewExternalPKIProvider(signingKeyFile string) (*ExternalPKIProvider, error) {
	pemData, err := loadPEM(signingKeyFile)
	if err != nil {
		return nil, fmt.Errorf("external_pki: %w", err)
	}

	key, alg, err := parsePEMKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("external_pki: %w", err)
	}

	kid := thumbprint(key.Public())

	return &ExternalPKIProvider{
		privateKey: key,
		algorithm:  alg,
		kid:        kid,
		publicInfo: []PublicKeyInfo{{KeyID: kid, Algorithm: alg, PublicKey: key.Public()}},
	}, nil
}

func (p *ExternalPKIProvider) PrivateKey() crypto.Signer    { return p.privateKey }
func (p *ExternalPKIProvider) PublicKeys() []PublicKeyInfo   { return p.publicInfo }
func (p *ExternalPKIProvider) Algorithm() string             { return p.algorithm }
func (p *ExternalPKIProvider) KeyID() string                 { return p.kid }

// loadPEM returns PEM bytes from env var or file.
func loadPEM(keyFile string) ([]byte, error) {
	if envVal := os.Getenv("ROCKETVAULT_JWT_SIGNING_KEY"); envVal != "" {
		data, err := base64.StdEncoding.DecodeString(envVal)
		if err != nil {
			return nil, fmt.Errorf("ROCKETVAULT_JWT_SIGNING_KEY is not valid base64: %w", err)
		}
		return data, nil
	}
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("reading signing key file %q: %w", keyFile, err)
		}
		return data, nil
	}
	return nil, fmt.Errorf("no signing key: set ROCKETVAULT_JWT_SIGNING_KEY env var or jwt.signing_key_file config")
}

// parsePEMKey parses an RSA or ECDSA private key PEM and returns the signer + algorithm.
func parsePEMKey(data []byte) (crypto.Signer, string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block found in signing key data")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse RSA PKCS1 key: %w", err)
		}
		return k, "RS256", nil

	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse EC key: %w", err)
		}
		alg, err := ecAlgorithm(k)
		if err != nil {
			return nil, "", err
		}
		return k, alg, nil

	case "PRIVATE KEY":
		// PKCS8 wraps both RSA and EC.
		raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse PKCS8 key: %w", err)
		}
		switch k := raw.(type) {
		case *rsa.PrivateKey:
			return k, "RS256", nil
		case *ecdsa.PrivateKey:
			alg, err := ecAlgorithm(k)
			if err != nil {
				return nil, "", err
			}
			return k, alg, nil
		default:
			return nil, "", fmt.Errorf("unsupported PKCS8 key type: %T", raw)
		}

	default:
		return nil, "", fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

func ecAlgorithm(k *ecdsa.PrivateKey) (string, error) {
	switch k.Curve.Params().Name {
	case "P-256":
		return "ES256", nil
	case "P-384":
		return "ES384", nil
	case "P-521":
		return "ES512", nil
	default:
		return "", fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
	}
}

// thumbprint returns the first 16 hex chars of the SHA-256 hash of the DER-encoded public key.
func thumbprint(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Fallback: unlikely but non-fatal.
		return "unknown"
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum[:8])
}
