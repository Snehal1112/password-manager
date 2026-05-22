package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

// OSStoreProvider looks up a certificate by CN in the OS trust store.
// If none is found it auto-generates a self-signed RSA-2048 key and certificate,
// persisting it to /etc/ssl/certs/ (root) or ~/.local/share/rocketvault/ (fallback).
type OSStoreProvider struct {
	privateKey crypto.Signer
	publicInfo []PublicKeyInfo
	kid        string
}

const osStoreAlgorithm = "RS256"

// NewOSStoreProvider constructs the provider. cn is the certificate CN to search for.
func NewOSStoreProvider(cn string) (*OSStoreProvider, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		// Non-fatal on some platforms; we fall through to auto-gen.
		logrus.WithError(err).Warn("OSStoreProvider: could not load system cert pool, will auto-generate key")
		pool = x509.NewCertPool()
	}

	if key, kid, found := findCertInPool(pool, cn); found {
		return &OSStoreProvider{
			privateKey: key,
			kid:        kid,
			publicInfo: []PublicKeyInfo{{KeyID: kid, Algorithm: osStoreAlgorithm, PublicKey: key.Public()}},
		}, nil
	}

	logrus.WithField("cn", cn).Warn("OSStoreProvider: no matching certificate found, auto-generating RSA-2048 key")

	key, cert, err := generateSelfSignedRSA(cn)
	if err != nil {
		return nil, fmt.Errorf("OSStoreProvider: auto-generate key: %w", err)
	}

	if err := persistKey(key, cert, cn); err != nil {
		logrus.WithError(err).Warn("OSStoreProvider: could not persist auto-generated key (non-fatal)")
	}

	kid := thumbprint(key.Public())
	return &OSStoreProvider{
		privateKey: key,
		kid:        kid,
		publicInfo: []PublicKeyInfo{{KeyID: kid, Algorithm: osStoreAlgorithm, PublicKey: key.Public()}},
	}, nil
}

func (p *OSStoreProvider) PrivateKey() crypto.Signer    { return p.privateKey }
func (p *OSStoreProvider) PublicKeys() []PublicKeyInfo   { return p.publicInfo }
func (p *OSStoreProvider) Algorithm() string             { return osStoreAlgorithm }
func (p *OSStoreProvider) KeyID() string                 { return p.kid }

// findCertInPool searches the pool for a leaf certificate whose CN matches.
// Because x509.CertPool does not expose its contents, we rely on a known
// system cert path on Linux; on other platforms we skip and auto-gen.
func findCertInPool(_ *x509.CertPool, _ string) (crypto.Signer, string, bool) {
	// System cert pools do not expose private keys — this path intentionally
	// returns false so the auto-gen path is always taken in practice.
	// A future implementation can query the OS keychain or PKCS#11 via cgo.
	return nil, "", false
}

// generateSelfSignedRSA creates a new RSA-2048 key and a self-signed certificate.
func generateSelfSignedRSA(cn string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa.GenerateKey: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.ParseCertificate: %w", err)
	}

	return key, cert, nil
}

// persistKey writes the key + cert PEM to the system path if writable, otherwise to user home.
func persistKey(key *rsa.PrivateKey, cert *x509.Certificate, cn string) error {
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	combined := append(certPEM, keyPEM...)

	systemPath := filepath.Join("/etc/ssl/certs", cn+"-jwt.pem")
	if err := os.WriteFile(systemPath, combined, 0600); err == nil {
		logrus.WithField("path", systemPath).Info("OSStoreProvider: persisted auto-generated key")
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home dir: %w", err)
	}
	dir := filepath.Join(home, ".local", "share", "rocketvault")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	userPath := filepath.Join(dir, "jwt-signing.pem")
	if err := os.WriteFile(userPath, combined, 0600); err != nil {
		return fmt.Errorf("write to %s: %w", userPath, err)
	}
	logrus.WithField("path", userPath).Info("OSStoreProvider: persisted auto-generated key to user home")
	return nil
}
