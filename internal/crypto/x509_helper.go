// Package crypto provides cryptographic utilities for the password manager.
package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/sirupsen/logrus"
)

// CertificateTemplate holds parameters for certificate generation.
type CertificateTemplate struct {
	CommonName   string
	ValidityDays int
	IsCA         bool
}

// GenerateSerialNumber generates a random serial number for a certificate.
//
// Returns:
//   A big integer serial number or an error if generation fails.
func GenerateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate serial number")
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}

// CreateX509Template creates an X.509 certificate template.
//
// Parameters:
//   - params: The certificate template parameters.
//
// Returns:
//   An x509.Certificate template or an error if creation fails.
func CreateX509Template(params CertificateTemplate) (*x509.Certificate, error) {
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: params.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, params.ValidityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  params.IsCA,
	}

	return template, nil
}

// CreateSelfSignedCertificatePEM creates a self-signed certificate and returns it as PEM.
//
// Parameters:
//   - privateKeyPEM: The PEM-encoded private key.
//   - keyType: The key type ("RSA" or "ECDSA").
//   - params: The certificate template parameters.
//
// Returns:
//   The PEM-encoded certificate as a string or an error if creation fails.
func CreateSelfSignedCertificatePEM(privateKeyPEM, keyType string, params CertificateTemplate) (string, error) {
	// Parse private key
	privateKey, err := ParsePrivateKey(privateKeyPEM, keyType)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Create certificate template
	template, err := CreateX509Template(params)
	if err != nil {
		return "", err
	}

	// Create certificate
	var certBytes []byte
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		certBytes, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	case *ecdsa.PrivateKey:
		certBytes, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	default:
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	if err != nil {
		logrus.WithError(err).Error("Failed to create certificate")
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return string(certPEM), nil
}

// CreateCASignedCertificatePEM creates a CA-signed certificate and returns it as PEM.
//
// Parameters:
//   - privateKeyPEM: The PEM-encoded private key for the new certificate.
//   - keyType: The key type ("RSA" or "ECDSA").
//   - caCertPEM: The PEM-encoded CA certificate.
//   - caKeyPEM: The PEM-encoded CA private key.
//   - caKeyType: The CA key type ("RSA" or "ECDSA").
//   - params: The certificate template parameters.
//
// Returns:
//   The PEM-encoded certificate as a string or an error if creation fails.
func CreateCASignedCertificatePEM(privateKeyPEM, keyType, caCertPEM, caKeyPEM, caKeyType string, params CertificateTemplate) (string, error) {
	// Parse certificate private key
	privateKey, err := ParsePrivateKey(privateKeyPEM, keyType)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse CA certificate
	caBlock, _ := pem.Decode([]byte(caCertPEM))
	if caBlock == nil {
		return "", fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caPrivateKey, err := ParsePrivateKey(caKeyPEM, caKeyType)
	if err != nil {
		return "", fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Create certificate template
	template, err := CreateX509Template(params)
	if err != nil {
		return "", err
	}

	// Create certificate signed by CA
	var certBytes []byte
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		switch caPriv := caPrivateKey.(type) {
		case *rsa.PrivateKey:
			certBytes, err = x509.CreateCertificate(rand.Reader, template, caCertificate, &priv.PublicKey, caPriv)
		case *ecdsa.PrivateKey:
			certBytes, err = x509.CreateCertificate(rand.Reader, template, caCertificate, &priv.PublicKey, caPriv)
		}
	case *ecdsa.PrivateKey:
		switch caPriv := caPrivateKey.(type) {
		case *rsa.PrivateKey:
			certBytes, err = x509.CreateCertificate(rand.Reader, template, caCertificate, &priv.PublicKey, caPriv)
		case *ecdsa.PrivateKey:
			certBytes, err = x509.CreateCertificate(rand.Reader, template, caCertificate, &priv.PublicKey, caPriv)
		}
	default:
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	if err != nil {
		logrus.WithError(err).Error("Failed to create CA-signed certificate")
		return "", fmt.Errorf("failed to create CA-signed certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return string(certPEM), nil
}
