// Package keys manages cryptographic keys and certificates for the password manager.
// It provides functionality to generate, store, retrieve, and revoke SSH keys and X.509
// certificates, as well as create Certificate Revocation Lists (CRLs). The package interacts
// with the database to persist keys and certificates securely, enabling users to manage
// their cryptographic assets for authentication and secure communication.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/db"
)

// Key represents a cryptographic key or certificate stored in the database.
// It holds details for SSH keys or X.509 certificates, including ownership, type,
// and revocation status.
//
// Fields:
//
//	ID: Unique database identifier for the key.
//	UserID: ID of the user owning the key.
//	Name: User-defined name (e.g., "my-ssh-key", "mycert").
//	Value: PEM-encoded key or certificate data.
//	Type: Either "ssh" for SSH keys or "certificate" for X.509 certificates.
//	CreatedAt: Timestamp of key creation.
//	Revoked: True if the key or certificate is revoked.
type Key struct {
	ID        int
	UserID    int
	Name      string
	Value     string
	Type      string
	CreatedAt string
	Revoked   bool
}

// GenerateCAKey generates and stores a CA certificate and private key for a user.
// It creates a self-signed X.509 CA certificate and a 2048-bit RSA key pair, storing
// them in the ca_keys table. The CA signs user certificates and CRLs.
//
// Parameters:
//
//	userID: ID of the user for whom the CA key is generated.
//
// Returns:
//
//	An error if key generation, certificate creation, or database storage fails.
//
// The function is used to establish a user-specific Certificate Authority, enabling
// certificate-based authentication within the password manager.
func GenerateCAKey(userID int) error {
	// Generate a 2048-bit RSA private key for the CA.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logrus.Error("Failed to generate CA private key: ", err)
		return err
	}

	// Create a random 128-bit serial number for the CA certificate.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		logrus.Error("Failed to generate CA serial number: ", err)
		return err
	}

	// Define the CA certificate template with a 10-year validity.
	caCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Password Manager CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Create a self-signed CA certificate.
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &privateKey.PublicKey, privateKey)
	if err != nil {
		logrus.Error("Failed to create CA certificate: ", err)
		return err
	}

	// Encode the certificate to PEM format.
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	})

	// Encode the private key to PEM format.
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Store the CA certificate and key in the ca_keys table.
	_, err = db.DB.Exec(
		"INSERT OR REPLACE INTO ca_keys (user_id, certificate, private_key, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
		userID, string(caCertPEM), string(privateKeyPEM),
	)
	if err != nil {
		logrus.Error("Failed to store CA key: ", err)
		return err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("CA key generated")
	return nil
}

// GenerateSSHKey generates and stores an RSA SSH key for a user.
// It creates a 2048-bit RSA private key, stores it in the keys table as a PEM-encoded
// string, and returns the key details. The key enables SSH authentication to servers.
//
// Parameters:
//
//	userID: ID of the user for whom the SSH key is generated.
//	name: User-defined name for the SSH key (e.g., "my-ssh-key").
//
// Returns:
//
//	A pointer to the generated Key and an error if key generation or storage fails.
//
// The function supports secure storage of SSH keys within the password manager.
func GenerateSSHKey(userID int, name string) (*Key, error) {
	// Generate a 2048-bit RSA private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logrus.Error("Failed to generate RSA key: ", err)
		return nil, err
	}

	// Encode the private key to PEM format.
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Store the SSH key in the keys table.
	_, err = db.DB.Exec(
		"INSERT INTO keys (user_id, name, value, type, created_at, revoked) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, FALSE)",
		userID, name, string(privateKeyPEM), "ssh",
	)
	if err != nil {
		logrus.Error("Failed to store key: ", err)
		return nil, err
	}

	// Retrieve the stored key details.
	var key Key
	err = db.DB.QueryRow(
		"SELECT id, user_id, name, value, type, created_at, revoked FROM keys WHERE user_id = ? AND name = ?",
		userID, name,
	).Scan(&key.ID, &key.UserID, &key.Name, &key.Value, &key.Type, &key.CreatedAt, &key.Revoked)
	if err != nil {
		logrus.Error("Failed to retrieve key: ", err)
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
		"type":    "ssh",
	}).Info("SSH key generated")
	return &key, nil
}

// GenerateCertificate generates and stores an X.509 certificate for a user.
// It creates a 2048-bit RSA key pair and a certificate signed by the user’s CA, storing
// the certificate in the keys table. If no CA exists, it generates one first. The
// certificate supports client or server authentication (e.g., TLS).
//
// Parameters:
//
//	userID: ID of the user for whom the certificate is generated.
//	name: User-defined name for the certificate, used as the CommonName (e.g., "mycert").
//
// Returns:
//
//	A pointer to the generated Key and an error if CA retrieval, certificate creation,
//	or storage fails.
//
// The function enables certificate-based authentication within the password manager.
func GenerateCertificate(userID int, name string) (*Key, error) {
	// Check if a CA key exists; generate one if absent.
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM ca_keys WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		logrus.Error("Failed to check CA key: ", err)
		return nil, err
	}
	if count == 0 {
		if err := GenerateCAKey(userID); err != nil {
			logrus.Error("Failed to generate CA key: ", err)
			return nil, err
		}
	}

	// Generate a 2048-bit RSA private key for the certificate.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logrus.Error("Failed to generate RSA key: ", err)
		return nil, err
	}

	// Create a random 128-bit serial number for the certificate.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		logrus.Error("Failed to generate serial number: ", err)
		return nil, err
	}

	// Define the certificate template with a 1-year validity.
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Load the CA certificate and private key.
	var caCertPEM, caPrivateKeyPEM string
	err = db.DB.QueryRow(
		"SELECT certificate, private_key FROM ca_keys WHERE user_id = ?",
		userID,
	).Scan(&caCertPEM, &caPrivateKeyPEM)
	if err != nil {
		logrus.Error("Failed to retrieve CA key: ", err)
		return nil, err
	}

	// Decode the CA certificate PEM.
	caCertBlock, _ := pem.Decode([]byte(caCertPEM))
	if caCertBlock == nil {
		logrus.Error("Failed to decode CA certificate PEM")
		return nil, fmt.Errorf("invalid CA certificate format")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		logrus.Error("Failed to parse CA certificate: ", err)
		return nil, err
	}

	// Decode the CA private key PEM.
	caPrivateKeyBlock, _ := pem.Decode([]byte(caPrivateKeyPEM))
	if caPrivateKeyBlock == nil {
		logrus.Error("Failed to decode CA private key PEM")
		return nil, fmt.Errorf("invalid CA private key format")
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBlock.Bytes)
	if err != nil {
		logrus.Error("Failed to parse CA private key: ", err)
		return nil, err
	}

	// Create the certificate, signed by the CA.
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		logrus.Error("Failed to create certificate: ", err)
		return nil, err
	}

	// Encode the certificate to PEM format.
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Store the certificate in the keys table.
	_, err = db.DB.Exec(
		"INSERT INTO keys (user_id, name, value, type, created_at, revoked) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, FALSE)",
		userID, name, string(certPEM), "certificate",
	)
	if err != nil {
		logrus.Error("Failed to store certificate: ", err)
		return nil, err
	}

	// Retrieve the stored certificate details.
	var key Key
	err = db.DB.QueryRow(
		"SELECT id, user_id, name, value, type, created_at, revoked FROM keys WHERE user_id = ? AND name = ?",
		userID, name,
	).Scan(&key.ID, &key.UserID, &key.Name, &key.Value, &key.Type, &key.CreatedAt, &key.Revoked)
	if err != nil {
		logrus.Error("Failed to retrieve certificate: ", err)
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
		"type":    "certificate",
	}).Info("Certificate generated")
	return &key, nil
}

// RevokeKey revokes a user’s certificate and adds it to the CRL.
// It marks the certificate as revoked in the keys table and records its serial number
// in the crl table for inclusion in the Certificate Revocation List.
//
// Parameters:
//
//	userID: ID of the user whose certificate is revoked.
//	name: Name of the certificate to revoke (e.g., "mycert").
//
// Returns:
//
//	An error if the certificate is not found, parsing fails, or database updates fail.
//
// The function ensures that compromised or obsolete certificates are invalidated.
func RevokeKey(userID int, name string) error {
	// Mark the certificate as revoked in the keys table.
	result, err := db.DB.Exec(
		"UPDATE keys SET revoked = TRUE WHERE user_id = ? AND name = ? AND type = 'certificate'",
		userID, name,
	)
	if err != nil {
		logrus.Error("Failed to revoke key: ", err)
		return err
	}

	// Verify that the certificate was found and updated.
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logrus.Error("Failed to check rows affected: ", err)
		return err
	}
	if rowsAffected == 0 {
		logrus.WithFields(logrus.Fields{
			"user_id": userID,
			"name":    name,
		}).Warn("Certificate not found")
		return fmt.Errorf("certificate not found")
	}

	// Retrieve the certificate to extract its serial number.
	var certPEM string
	err = db.DB.QueryRow(
		"SELECT value FROM keys WHERE user_id = ? AND name = ? AND type = 'certificate'",
		userID, name,
	).Scan(&certPEM)
	if err != nil {
		logrus.Error("Failed to retrieve certificate: ", err)
		return err
	}

	// Decode the certificate PEM.
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		logrus.Error("Failed to decode PEM block")
		return fmt.Errorf("invalid certificate format")
	}

	// Parse the certificate to obtain its serial number.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logrus.Error("Failed to parse certificate: ", err)
		return err
	}

	// Add the serial number to the crl table.
	_, err = db.DB.Exec(
		"INSERT INTO crl (serial_number, revoked_at, user_id, name) VALUES (?, CURRENT_TIMESTAMP, ?, ?)",
		cert.SerialNumber.String(), userID, name,
	)
	if err != nil {
		logrus.Error("Failed to update CRL: ", err)
		return err
	}

	logrus.WithFields(logrus.Fields{
		"user_id":       userID,
		"name":          name,
		"serial_number": cert.SerialNumber.String(),
	}).Info("Certificate revoked and added to CRL")
	return nil
}

// GetKey retrieves a key or certificate from the database.
// It fetches details of an SSH key or X.509 certificate by user ID and name.
//
// Parameters:
//
//	userID: ID of the user whose key is retrieved.
//	name: Name of the key or certificate (e.g., "my-ssh-key", "mycert").
//
// Returns:
//
//	A pointer to the retrieved Key and an error if the key is not found or the query fails.
//
// The function supports key and certificate management via the CLI or API.
func GetKey(userID int, name string) (*Key, error) {
	// Query the keys table for the specified key or certificate.
	var key Key
	err := db.DB.QueryRow(
		"SELECT id, user_id, name, value, type, created_at, revoked FROM keys WHERE user_id = ? AND name = ?",
		userID, name,
	).Scan(&key.ID, &key.UserID, &key.Name, &key.Value, &key.Type, &key.CreatedAt, &key.Revoked)
	if err != nil {
		logrus.Error("Failed to retrieve key: ", err)
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
		"type":    key.Type,
	}).Info("Key retrieved")
	return &key, nil
}

// GenerateCRL generates a Certificate Revocation List (CRL) for a user.
// It queries the crl table for revoked certificates, creates a CRL signed by the user’s
// CA, and returns it in DER-encoded format. The CRL informs relying parties of revoked
// certificates.
//
// Parameters:
//
//	userID: ID of the user whose CRL is generated.
//
// Returns:
//
//	A byte slice containing the DER-encoded CRL and an error if CA retrieval, database
//	query, or CRL creation fails.
//
// The function is accessible via the API (GET /api/keys/crl) or CLI (keys crl).
func GenerateCRL(userID int) ([]byte, error) {
	// Load the CA certificate and private key from the ca_keys table.
	var caCertPEM, caPrivateKeyPEM string
	err := db.DB.QueryRow(
		"SELECT certificate, private_key FROM ca_keys WHERE user_id = ?",
		userID,
	).Scan(&caCertPEM, &caPrivateKeyPEM)
	if err != nil {
		logrus.Error("Failed to retrieve CA key: ", err)
		return nil, err
	}

	// Decode the CA certificate PEM.
	caCertBlock, _ := pem.Decode([]byte(caCertPEM))
	if caCertBlock == nil {
		logrus.Error("Failed to decode CA certificate PEM")
		return nil, fmt.Errorf("invalid CA certificate format")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		logrus.Error("Failed to parse CA certificate: ", err)
		return nil, err
	}

	// Decode the CA private key PEM.
	caPrivateKeyBlock, _ := pem.Decode([]byte(caPrivateKeyPEM))
	if caPrivateKeyBlock == nil {
		logrus.Error("Failed to decode CA private key PEM")
		return nil, fmt.Errorf("invalid CA private key format")
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBlock.Bytes)
	if err != nil {
		logrus.Error("Failed to parse CA private key: ", err)
		return nil, err
	}

	// Query the crl table for revoked certificates.
	rows, err := db.DB.Query(
		"SELECT serial_number, revoked_at FROM crl WHERE user_id = ?",
		userID,
	)
	if err != nil {
		logrus.Error("Failed to query CRL: ", err)
		return nil, err
	}
	defer rows.Close()

	// Collect revoked certificates from the query results.
	var revokedCerts []pkix.RevokedCertificate
	for rows.Next() {
		var serialNumberStr string
		var revokedAt time.Time
		if err := rows.Scan(&serialNumberStr, &revokedAt); err != nil {
			logrus.Error("Failed to scan CRL entry: ", err)
			return nil, err
		}
		// Parse the serial number, stored as a string.
		serialNumber, ok := new(big.Int).SetString(serialNumberStr, 0)
		if !ok {
			logrus.Error("Failed to parse serial number: ", serialNumberStr)
			return nil, fmt.Errorf("invalid serial number: %s", serialNumberStr)
		}
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: revokedAt,
		})
	}

	// Log if no revoked certificates are found; an empty CRL is valid.
	if len(revokedCerts) == 0 {
		logrus.WithFields(logrus.Fields{
			"user_id": userID,
		}).Info("No revoked certificates found, generating empty CRL")
	}

	// Define the CRL template with a 30-day validity period.
	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(30 * 24 * time.Hour),
	}

	// Create and sign the CRL using the CA certificate and private key.
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caPrivateKey)
	if err != nil {
		logrus.Error("Failed to create CRL: ", err)
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"count":   len(revokedCerts),
	}).Info("CRL generated")
	return crlBytes, nil
}
