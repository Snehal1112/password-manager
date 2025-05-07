// Package certificates manages X.509 certificate storage and operations for the password manager.
// It supports certificate creation, retrieval, updating, deletion, and revocation,
// using Go Generics for type-safe certificate handling.
package certificates

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/snehal1112/password-manager/internal/keys"
	"github.com/snehal1112/password-manager/internal/logging"
	"github.com/snehal1112/password-manager/internal/secrets"
)

// Certificate represents an X.509 certificate in the password manager.
// It includes the certificate’s user ID, PEM-encoded certificate, encrypted private key, and creation time.
type Certificate struct {
	UserID      int
	Certificate string // PEM-encoded certificate
	PrivateKey  string // Encrypted PEM-encoded private key
	CreatedAt   time.Time
}

// RevokedCertificate represents a revoked certificate in the CRL.
// It includes the certificate’s ID, user ID, serial number, name, and revocation time.
type RevokedCertificate struct {
	ID           int
	UserID       int
	SerialNumber string
	Name         string
	RevokedAt    time.Time
}

// CertificateRepository is a generic repository interface for certificate operations.
// It provides type-safe CRUD operations for certificates and CRL management.
type CertificateRepository interface {
	CreateSelfSigned(ctx context.Context, userID int, name string, keyID int, validityDays int) error
	CreateCASigned(ctx context.Context, userID int, name string, keyID int, caCertID int, validityDays int) error
	Read(ctx context.Context, userID int) (Certificate, error)
	Update(ctx context.Context, cert Certificate) error
	Delete(ctx context.Context, userID int) error
	Revoke(ctx context.Context, userID int, serialNumber, name string) error
	ListRevoked(ctx context.Context, userID int) ([]RevokedCertificate, error)
}

// certificateRepository implements CertificateRepository for database operations on certificates.
type certificateRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewCertificateRepository creates a new instance of certificateRepository.
// It initializes the repository with a database connection and a logger.
//
// Parameters:
//
//	db: The database connection.
//
// Returns:
//
//	A new instance of CertificateRepository.
//
// It returns an error if the database connection is nil.
func NewCertificateRepository(db *sql.DB, log *logging.Logger) CertificateRepository {
	return &certificateRepository{db: db, log: log}
}

// CreateSelfSigned creates a self-signed X.509 certificate and stores it in the database.
// It generates a certificate signed with the specified private key.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//	name: The certificate’s common name.
//	keyID: The ID of the private key to use.
//	validityDays: The certificate’s validity period in days.
//
// Returns:
//
//	An error if certificate creation or storage fails.
func (r *certificateRepository) CreateSelfSigned(ctx context.Context, userID int, name string, keyID int, validityDays int) error {
	// Retrieve the private key.
	keyRepo := keys.NewKeyRepository(r.db, r.log)
	key, err := keyRepo.Read(ctx, keyID)
	if err != nil {
		r.log.LogAuditError(0, "CreateSelfSigned", "failed", "Failed to read private key", err)
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse the private key (assuming RSA for simplicity; extend for ECDSA if needed).
	block, _ := pem.Decode([]byte(key.Value))
	if block == nil {
		r.log.LogAuditError(0, "CreateSelfSigned", "failed", "Failed to decode private key PEM", nil)
		return fmt.Errorf("failed to decode private key PEM")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		r.log.LogAuditError(0, "CreateSelfSigned", "failed", "Failed to parse RSA private key", err)
		return fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	// Create certificate template.
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // Self-signed certificate acts as its own CA.
	}

	// Create self-signed certificate.
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		r.log.LogAuditError(0, "CreateSelfSigned", "failed", "Failed to create certificate", err)
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Store the certificate and private key in the database.
	cert := Certificate{
		UserID:      userID,
		Certificate: string(certPEM),
		PrivateKey:  key.Value, // Already encrypted from keys table.
		CreatedAt:   time.Now(),
	}
	if err := r.storeCertificate(ctx, cert); err != nil {
		r.log.LogAuditError(0, "CreateSelfSigned", "failed", "Failed to store certificate", err)
		return err
	}

	r.log.LogAuditInfo(cert.UserID, "CreateSelfSigned", "success", "Self-signed certificate created successfully")
	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
	}).Info("Self-signed certificate created successfully")
	return nil
}

// CreateCASigned creates a CA-signed X.509 certificate and stores it in the database.
// It signs the certificate with the specified CA certificate’s private key.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//	name: The certificate’s common name.
//	keyID: The ID of the private key to use.
//	caCertID: The user ID of the CA certificate.
//	validityDays: The certificate’s validity period in days.
//
// Returns:
//
//	An error if certificate creation or storage fails.
func (r *certificateRepository) CreateCASigned(ctx context.Context, userID int, name string, keyID int, caCertID int, validityDays int) error {
	// Retrieve the private key.
	keyRepo := keys.NewKeyRepository(r.db, r.log)
	key, err := keyRepo.Read(ctx, keyID)
	if err != nil {
		logrus.Error("Failed to read private key: ", err)
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse the private key (assuming RSA for simplicity).
	block, _ := pem.Decode([]byte(key.Value))
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logrus.Error("Failed to parse RSA private key: ", err)
		return fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	// Retrieve the CA certificate and private key.
	caCert, err := r.Read(ctx, caCertID)
	if err != nil {
		logrus.Error("Failed to read CA certificate: ", err)
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caBlock, _ := pem.Decode([]byte(caCert.Certificate))
	if caBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		logrus.Error("Failed to parse CA certificate: ", err)
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caPrivateKeyBlock, _ := pem.Decode([]byte(caCert.PrivateKey))
	if caPrivateKeyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBlock.Bytes)
	if err != nil {
		logrus.Error("Failed to parse CA private key: ", err)
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Create certificate template.
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create CA-signed certificate.
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCertificate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		logrus.Error("Failed to create CA-signed certificate: ", err)
		return fmt.Errorf("failed to create CA-signed certificate: %w", err)
	}

	// Encode certificate to PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Store the certificate and private key in the database.
	cert := Certificate{
		UserID:      userID,
		Certificate: string(certPEM),
		PrivateKey:  key.Value, // Already encrypted from keys table.
		CreatedAt:   time.Now(),
	}
	if err := r.storeCertificate(ctx, cert); err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
	}).Info("CA-signed certificate created successfully")
	return nil
}

// Read retrieves a certificate by user ID from the database.
// It returns the certificate and its encrypted private key.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//
// Returns:
//
//	The certificate and an error if the retrieval fails.
func (r *certificateRepository) Read(ctx context.Context, userID int) (Certificate, error) {
	var cert Certificate
	var encryptedPrivateKey string
	err := r.db.QueryRowContext(
		ctx,
		"SELECT user_id, certificate, private_key, created_at FROM ca_keys WHERE user_id = ?",
		userID,
	).Scan(&cert.UserID, &cert.Certificate, &encryptedPrivateKey, &cert.CreatedAt)
	if err == sql.ErrNoRows {
		return cert, fmt.Errorf("certificate not found")
	}
	if err != nil {
		logrus.Error("Failed to query certificate: ", err)
		return cert, fmt.Errorf("failed to query certificate: %w", err)
	}

	// Decrypt the private key.
	cert.PrivateKey, err = secrets.DecryptSecret(encryptedPrivateKey)
	if err != nil {
		logrus.Error("Failed to decrypt private key: ", err)
		return cert, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	return cert, nil
}

// Update updates a certificate in the database.
// It encrypts the updated certificate and private key.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	cert: The certificate to update.
//
// Returns:
//
//	An error if the update fails.
func (r *certificateRepository) Update(ctx context.Context, cert Certificate) error {
	// Encrypt the private key.
	encryptedPrivateKey, err := secrets.EncryptSecret(cert.PrivateKey)
	if err != nil {
		logrus.Error("Failed to encrypt private key: ", err)
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Update the certificate in the database.
	_, err = r.db.ExecContext(
		ctx,
		"UPDATE ca_keys SET certificate = ?, private_key = ?, created_at = ? WHERE user_id = ?",
		cert.Certificate, encryptedPrivateKey, cert.CreatedAt, cert.UserID,
	)
	if err != nil {
		logrus.Error("Failed to update certificate: ", err)
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"user_id": cert.UserID,
	}).Info("Certificate updated successfully")
	return nil
}

// Delete deletes a certificate by user ID from the database.
// It removes the certificate and its associated private key.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//
// Returns:
//
//	An error if the deletion fails.
func (r *certificateRepository) Delete(ctx context.Context, userID int) error {
	// Delete the certificate.
	_, err := r.db.ExecContext(ctx, "DELETE FROM ca_keys WHERE user_id = ?", userID)
	if err != nil {
		logrus.Error("Failed to delete certificate: ", err)
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Certificate deleted successfully")
	return nil
}

// Revoke adds a certificate to the CRL by user ID and serial number.
// It marks the certificate as revoked in the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//	serialNumber: The certificate’s serial number.
//	name: The certificate’s common name.
//
// Returns:
//
//	An error if revocation fails.
func (r *certificateRepository) Revoke(ctx context.Context, userID int, serialNumber, name string) error {
	// Insert the revoked certificate into the CRL.
	_, err := r.db.ExecContext(
		ctx,
		"INSERT INTO crl (user_id, serial_number, name, revoked_at) VALUES (?, ?, ?, ?)",
		userID, serialNumber, name, time.Now(),
	)
	if err != nil {
		logrus.Error("Failed to revoke certificate: ", err)
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"user_id":       userID,
		"serial_number": serialNumber,
		"name":          name,
	}).Info("Certificate revoked successfully")
	return nil
}

// ListRevoked retrieves all revoked certificates for a user from the CRL.
// It returns the list of revoked certificates.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user’s ID.
//
// Returns:
//
//	A list of revoked certificates and an error if the retrieval fails.
func (r *certificateRepository) ListRevoked(ctx context.Context, userID int) ([]RevokedCertificate, error) {
	var revokedCerts []RevokedCertificate
	rows, err := r.db.QueryContext(
		ctx,
		"SELECT id, user_id, serial_number, name, revoked_at FROM crl WHERE user_id = ?",
		userID,
	)
	if err != nil {
		logrus.Error("Failed to query revoked certificates: ", err)
		return nil, fmt.Errorf("failed to query revoked certificates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cert RevokedCertificate
		if err := rows.Scan(&cert.ID, &cert.UserID, &cert.SerialNumber, &cert.Name, &cert.RevokedAt); err != nil {
			logrus.Error("Failed to scan revoked certificate: ", err)
			return nil, fmt.Errorf("failed to scan revoked certificate: %w", err)
		}
		revokedCerts = append(revokedCerts, cert)
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"count":   len(revokedCerts),
	}).Info("Revoked certificates listed successfully")
	return revokedCerts, nil
}

// storeCertificate stores a certificate and its private key in the database.
// It encrypts the private key before storage.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	cert: The certificate to store.
//
// Returns:
//
//	An error if storage fails.
func (r *certificateRepository) storeCertificate(ctx context.Context, cert Certificate) error {
	// Encrypt the private key.
	encryptedPrivateKey, err := secrets.EncryptSecret(cert.PrivateKey)
	if err != nil {
		logrus.Error("Failed to encrypt private key: ", err)
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Insert or update the certificate in the database.
	_, err = r.db.ExecContext(
		ctx,
		"INSERT OR REPLACE INTO ca_keys (user_id, certificate, private_key, created_at) VALUES (?, ?, ?, ?)",
		cert.UserID, cert.Certificate, encryptedPrivateKey, cert.CreatedAt,
	)
	if err != nil {
		logrus.Error("Failed to store certificate: ", err)
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	return nil
}

// generateSerialNumber generates a random serial number for a certificate.
// It creates a unique big integer for certificate identification.
//
// Parameters:
//
//	none
//
// Returns:
//
//	A big integer and an error if generation fails.
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.Error("Failed to generate serial number: ", err)
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}
