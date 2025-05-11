// Package certificates manages X.509 certificate storage and operations for the password manager.
// It supports certificate creation, retrieval, updating, deletion, and revocation,
// using Go Generics for type-safe certificate handling.
package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/keys"
	"github.com/snehal1112/password-manager/internal/logging"
	"github.com/snehal1112/password-manager/internal/secrets"
)

// Certificate represents an X.509 certificate in the password manager.
// It includes the certificate’s ID, user ID, name, PEM-encoded certificate,
// encrypted private key, creation time, and tags.
type Certificate struct {
	ID          int
	UserID      int
	Name        string
	Certificate string
	PrivateKey  string
	CreatedAt   time.Time
	Tags        []string
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
// It provides type-safe CRUD operations, certificate creation, revocation, and listing.
type CertificateRepository interface {
	CreateSelfSigned(ctx context.Context, userID int, name string, keyID int, validityDays int, tags []string) error
	CreateCASigned(ctx context.Context, userID int, name string, keyID int, caCertID int, validityDays int, tags []string) error
	Read(ctx context.Context, id int) (Certificate, error)
	Update(ctx context.Context, cert Certificate) error
	Delete(ctx context.Context, id int) error
	Revoke(ctx context.Context, id int, serialNumber, name string) error
	ListByUser(ctx context.Context, userID int, certType string, tags []string) ([]Certificate, error)
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
// - db: The database connection.
// - log: The logger for audit and error logging.
// Returns: A new instance of CertificateRepository.
func NewCertificateRepository(db *sql.DB, log *logging.Logger) CertificateRepository {
	return &certificateRepository{db: db, log: log}
}

// CreateSelfSigned creates a self-signed X.509 certificate and stores it in the database.
// It generates a certificate signed with the specified private key and associates tags.
//
// Parameters:
// - ctx: The context for the database operation.
// - userID: The user’s ID.
// - name: The certificate’s common name.
// - keyID: The ID of the private key to use.
// - validityDays: The certificate’s validity period in days.
// - tags: The tags to associate with the certificate.
// Returns: An error if certificate creation or storage fails.
func (r *certificateRepository) CreateSelfSigned(ctx context.Context, userID int, name string, keyID int, validityDays int, tags []string) error {
	keyRepo := keys.NewKeyRepository(r.db, r.log)
	key, err := keyRepo.Read(ctx, keyID)
	if err != nil {
		r.log.LogAuditError(userID, "create_self_signed", "failed", "Failed to read private key", err)
		return fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := parsePrivateKey(key.Value, key.Type)
	if err != nil {
		r.log.LogAuditError(userID, "create_self_signed", "failed", "Failed to parse private key", err)
		return err
	}

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
		IsCA:                  true,
	}

	var certBytes []byte
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	case *ecdsa.PrivateKey:
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	default:
		err = fmt.Errorf("unsupported key type: %s", key.Type)
	}
	if err != nil {
		r.log.LogAuditError(userID, "create_self_signed", "failed", "Failed to create certificate", err)
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	cert := Certificate{
		UserID:      userID,
		Name:        name,
		Certificate: string(certPEM),
		PrivateKey:  key.Value,
		CreatedAt:   time.Now(),
		Tags:        tags,
	}
	if err := r.storeCertificate(ctx, cert); err != nil {
		r.log.LogAuditError(userID, "create_self_signed", "failed", "Failed to store certificate", err)
		return err
	}

	r.log.LogAuditInfo(userID, "create_self_signed", "success", "Self-signed certificate created successfully")
	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
	}).Info("Self-signed certificate created successfully")
	return nil
}

// CreateCASigned creates a CA-signed X.509 certificate and stores it in the database.
// It signs the certificate with the specified CA certificate’s private key and associates tags.
//
// Parameters:
// - ctx: The context for the database operation.
// - userID: The user’s ID.
// - name: The certificate’s common name.
// - keyID: The ID of the private key to use.
// - caCertID: The ID of the CA certificate.
// - validityDays: The certificate’s validity period in days.
// - tags: The tags to associate with the certificate.
// Returns: An error if certificate creation or storage fails.
func (r *certificateRepository) CreateCASigned(ctx context.Context, userID int, name string, keyID int, caCertID int, validityDays int, tags []string) error {
	keyRepo := keys.NewKeyRepository(r.db, r.log)
	key, err := keyRepo.Read(ctx, keyID)
	if err != nil {
		r.log.LogAuditError(userID, "create_ca_signed", "failed", "Failed to read private key", err)
		return fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := parsePrivateKey(key.Value, key.Type)
	if err != nil {
		r.log.LogAuditError(userID, "create_ca_signed", "failed", "Failed to parse private key", err)
		return err
	}

	caCert, err := r.Read(ctx, caCertID)
	if err != nil {
		r.log.LogAuditError(userID, "create_ca_signed", "failed", "Failed to read CA certificate", err)
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caBlock, _ := pem.Decode([]byte(caCert.Certificate))
	if caBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		r.log.LogAuditError(userID, "create_ca_signed", "failed", "Failed to parse CA certificate", err)
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caPrivateKey, err := parsePrivateKey(caCert.PrivateKey, "RSA") // Assume CA key is RSA; extend if needed
	if err != nil {
		r.log.LogAuditError(userID, "create_ca_signed", "failed", "Failed to parse CA private key", err)
		return err
	}

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

	var certBytes []byte
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		switch caPriv := caPrivateKey.(type) {
		case *rsa.PrivateKey:
			certBytes, err = x509.CreateCertificate(rand.Reader, &template, caCertificate, &priv.PublicKey, caPriv)
		case *ecdsa.PrivateKey:
			certBytes, err = x509.CreateCertificate(rand.Reader, &template, caCertificate, &priv.PublicKey, caPriv)
		}
	case *ecdsa.PrivateKey:
		switch caPriv := caPrivateKey.(type) {
		case *rsa.PrivateKey:
			certBytes, err = x509.CreateCertificate(rand.Reader, &template, caCertificate, &priv.PublicKey, caPriv)
		case *ecdsa.PrivateKey:
			certBytes, err = x509.CreateCertificate(rand.Reader, &template, caCertificate, &priv.PublicKey, caPriv)
		}
	default:
		err = fmt.Errorf("unsupported key type: %s", key.Type)
	}
	if err != nil {
		r.log.LogAuditError(userID, "create_ca_signed", "failed", "Failed to create CA-signed certificate", err)
		return fmt.Errorf("failed to create CA-signed certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	cert := Certificate{
		UserID:      userID,
		Name:        name,
		Certificate: string(certPEM),
		PrivateKey:  key.Value,
		CreatedAt:   time.Now(),
		Tags:        tags,
	}
	if err := r.storeCertificate(ctx, cert); err != nil {
		r.log.LogAuditError(userID, "create_ca_signed", "failed", "Failed to store certificate", err)
		return err
	}

	r.log.LogAuditInfo(userID, "create_ca_signed", "success", "CA-signed certificate created successfully")
	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"name":    name,
	}).Info("CA-signed certificate created successfully")
	return nil
}

// Read retrieves a certificate by ID from the database.
// It returns the certificate, decrypted private key, and associated tags.
//
// Parameters:
// - ctx: The context for the database operation.
// - id: The certificate’s ID.
// Returns: The certificate and an error if the retrieval fails.
func (r *certificateRepository) Read(ctx context.Context, id int) (Certificate, error) {
	var cert Certificate
	var encryptedPrivateKey string
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, certificate, private_key, created_at FROM certificates WHERE id = ?",
		id,
	).Scan(&cert.ID, &cert.UserID, &cert.Name, &cert.Certificate, &encryptedPrivateKey, &cert.CreatedAt)
	if err == sql.ErrNoRows {
		return cert, fmt.Errorf("certificate not found")
	}
	if err != nil {
		logrus.Error("Failed to query certificate: ", err)
		return cert, fmt.Errorf("failed to query certificate: %w", err)
	}

	cert.PrivateKey, err = secrets.DecryptSecret(encryptedPrivateKey)
	if err != nil {
		logrus.Error("Failed to decrypt private key: ", err)
		return cert, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	tagRepo := db.NewTagRepository[Certificate](r.db, "certificate_tags", "certificate_id")
	cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
	if err != nil {
		logrus.Error("Failed to read tags: ", err)
		return cert, fmt.Errorf("failed to read tags: %w", err)
	}

	return cert, nil
}

// Update updates a certificate in the database.
// It encrypts the updated certificate and private key, and updates associated tags.
//
// Parameters:
// - ctx: The context for the database operation.
// - cert: The certificate to update.
// Returns: An error if the update fails.
func (r *certificateRepository) Update(ctx context.Context, cert Certificate) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		logrus.Error("Failed to begin transaction: ", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	encryptedPrivateKey, err := secrets.EncryptSecret(cert.PrivateKey)
	if err != nil {
		logrus.Error("Failed to encrypt private key: ", err)
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	_, err = tx.ExecContext(
		ctx,
		"UPDATE certificates SET name = ?, certificate = ?, private_key = ?, created_at = ? WHERE id = ?",
		cert.Name, cert.Certificate, encryptedPrivateKey, cert.CreatedAt, cert.ID,
	)
	if err != nil {
		logrus.Error("Failed to update certificate: ", err)
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	if len(cert.Tags) > 0 {
		tagRepo := db.NewTagRepository[Certificate](r.db, "certificate_tags", "certificate_id")
		_, err = tx.ExecContext(ctx, "DELETE FROM certificate_tags WHERE certificate_id = ?", cert.ID)
		if err != nil {
			logrus.Error("Failed to delete existing tags: ", err)
			return fmt.Errorf("failed to delete existing tags: %w", err)
		}
		if err := tagRepo.AddTags(ctx, cert.ID, cert.Tags); err != nil {
			logrus.Error("Failed to add tags: ", err)
			return fmt.Errorf("failed to add tags: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		logrus.Error("Failed to commit transaction: ", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"certificate_id": cert.ID,
		"user_id":        cert.UserID,
		"name":           cert.Name,
	}).Info("Certificate updated successfully")
	return nil
}

// Delete deletes a certificate by ID from the database.
// It removes the certificate, its private key, and associated tags.
//
// Parameters:
// - ctx: The context for the database operation.
// - id: The certificate’s ID.
// Returns: An error if the deletion fails.
func (r *certificateRepository) Delete(ctx context.Context, id int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		logrus.Error("Failed to begin transaction: ", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "DELETE FROM certificate_tags WHERE certificate_id = ?", id)
	if err != nil {
		logrus.Error("Failed to delete tags: ", err)
		return fmt.Errorf("failed to delete tags: %w", err)
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM certificates WHERE id = ?", id)
	if err != nil {
		logrus.Error("Failed to delete certificate: ", err)
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logrus.Error("Failed to commit transaction: ", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"certificate_id": id,
	}).Info("Certificate deleted successfully")
	return nil
}

// Revoke adds a certificate to the CRL by ID, serial number, and name.
// It marks the certificate as revoked in the database.
//
// Parameters:
// - ctx: The context for the database operation.
// - id: The certificate’s ID.
// - serialNumber: The certificate’s serial number.
// - name: The certificate’s common name.
// Returns: An error if revocation fails.
func (r *certificateRepository) Revoke(ctx context.Context, id int, serialNumber, name string) error {
	cert, err := r.Read(ctx, id)
	if err != nil {
		logrus.Error("Failed to read certificate: ", err)
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	_, err = r.db.ExecContext(
		ctx,
		"INSERT INTO crl (user_id, serial_number, name, revoked_at) VALUES (?, ?, ?, ?)",
		cert.UserID, serialNumber, name, time.Now(),
	)
	if err != nil {
		logrus.Error("Failed to revoke certificate: ", err)
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"certificate_id": id,
		"user_id":        cert.UserID,
		"serial_number":  serialNumber,
		"name":           name,
	}).Info("Certificate revoked successfully")
	return nil
}

// ListByUser lists certificates for a user, optionally filtered by type and tags.
// It retrieves certificates matching the user ID and filters, including decrypted private keys and tags.
//
// Parameters:
// - ctx: The context for the database operation.
// - userID: The ID of the user whose certificates to list.
// - certType: The certificate type to filter by (e.g., "X509"; empty for all).
// - tags: The tags to filter by (empty for no tag filter).
// Returns: A slice of certificates and an error if the operation fails.
func (r *certificateRepository) ListByUser(ctx context.Context, userID int, certType string, tags []string) ([]Certificate, error) {
	query := "SELECT id, user_id, name, certificate, private_key, created_at FROM certificates WHERE user_id = ?"
	args := []interface{}{userID}
	if certType != "" {
		query += " AND type = ?"
		args = append(args, certType)
	}
	if len(tags) > 0 {
		query += " AND id IN (SELECT certificate_id FROM certificate_tags WHERE tag IN (?" + strings.Repeat(",?", len(tags)-1) + "))"
		for _, tag := range tags {
			args = append(args, tag)
		}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		logrus.Error("Failed to list certificates: ", err)
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	defer rows.Close()

	var certificates []Certificate
	for rows.Next() {
		var cert Certificate
		var encryptedPrivateKey string
		if err := rows.Scan(&cert.ID, &cert.UserID, &cert.Name, &cert.Certificate, &encryptedPrivateKey, &cert.CreatedAt); err != nil {
			logrus.Error("Failed to scan certificate: ", err)
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}
		cert.PrivateKey, err = secrets.DecryptSecret(encryptedPrivateKey)
		if err != nil {
			logrus.Error("Failed to decrypt private key: ", err)
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}

		// Fetch tags for the certificate
		tagRepo := db.NewTagRepository[Certificate](r.db, "certificate_tags", "certificate_id")
		cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
		if err != nil {
			logrus.Error("Failed to read tags: ", err)
			return nil, fmt.Errorf("failed to read tags: %w", err)
		}
		certificates = append(certificates, cert)
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"count":   len(certificates),
	}).Info("Certificates listed successfully")
	return certificates, nil
}

// ListRevoked retrieves all revoked certificates for a user from the CRL.
// It returns the list of revoked certificates.
//
// Parameters:
// - ctx: The context for the database operation.
// - userID: The user’s ID.
// Returns: A list of revoked certificates and an error if the retrieval fails.
func (r *certificateRepository) ListRevoked(ctx context.Context, userID int) ([]RevokedCertificate, error) {
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

	var revokedCerts []RevokedCertificate
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
// It encrypts the private key and stores associated tags within a transaction.
//
// Parameters:
// - ctx: The context for the database operation.
// - cert: The certificate to store.
// Returns: An error if storage fails.
func (r *certificateRepository) storeCertificate(ctx context.Context, cert Certificate) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		logrus.Error("Failed to begin transaction: ", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	encryptedPrivateKey, err := secrets.EncryptSecret(cert.PrivateKey)
	if err != nil {
		logrus.Error("Failed to encrypt private key: ", err)
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	result, err := tx.ExecContext(
		ctx,
		"INSERT INTO certificates (user_id, name, certificate, private_key, created_at) VALUES (?, ?, ?, ?, ?)",
		cert.UserID, cert.Name, cert.Certificate, encryptedPrivateKey, cert.CreatedAt,
	)
	if err != nil {
		logrus.Error("Failed to store certificate: ", err)
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logrus.Error("Failed to commit transaction: ", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		logrus.Error("Failed to get certificate ID: ", err)
		return fmt.Errorf("failed to get certificate ID: %w", err)
	}

	cert.ID = int(id)
	if len(cert.Tags) > 0 {
		tagRepo := db.NewTagRepository[Certificate](r.db, "certificate_tags", "certificate_id")
		if err := tagRepo.AddTags(ctx, cert.ID, cert.Tags); err != nil {
			logrus.Error("Failed to add tags: ", err)
			return fmt.Errorf("failed to add tags: %w", err)
		}
	}

	return nil
}

// generateSerialNumber generates a random serial number for a certificate.
// It creates a unique big integer for certificate identification.
//
// Returns:
// A big integer and an error if generation fails.
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logrus.Error("Failed to generate serial number: ", err)
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}

// parsePrivateKey parses a PEM-encoded private key based on its type.
// It supports RSA and ECDSA keys.
//
// Parameters:
// - pemData: The PEM-encoded private key data.
// - keyType: The type of key ("RSA" or "ECDSA").
// Returns: The parsed private key and an error if parsing fails.
func parsePrivateKey(pemData, keyType string) (interface{}, error) {
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
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}
