// Package certificates provides certificate management services for the password manager.
// It handles X.509 certificate lifecycle, validation, and access control
// while maintaining proper separation of concerns.
package certificates

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// CreateCertificateRequest represents a request to create a new X.509 certificate.
type CreateCertificateRequest struct {
	Name         string
	KeyID        uuid.UUID
	ValidityDays int
	Tags         []string
	UserID       uuid.UUID
	CACertID     *uuid.UUID // Optional for CA-signed certificates.
	AutoRenew    bool
	RenewalDays  int // 0 defaults to 30.
}

// CreateCertificateResult represents the result of creating a new certificate.
type CreateCertificateResult struct {
	CertID    uuid.UUID
	Name      string
	Tags      []string
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// UpdateCertificateRequest represents a request to update an existing certificate.
type UpdateCertificateRequest struct {
	CertID      uuid.UUID
	Name        *string  // Optional - nil means no change
	Tags        []string // Optional - empty means no change
	UserID      uuid.UUID
	AutoRenew   *bool // Optional - nil means no change
	RenewalDays *int  // Optional - nil means no change
}

// CertificateService handles X.509 certificate management operations.
// It orchestrates certificate generation, validation, and access control
// while delegating storage to repositories.
type CertificateService interface {
	CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error)
	GetCertificate(ctx context.Context, certID, userID uuid.UUID) (*domain.Certificate, error)
	ListCertificates(ctx context.Context, userID uuid.UUID) ([]domain.Certificate, error)
	UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error
	DeleteCertificate(ctx context.Context, certID, userID uuid.UUID) error
	RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*CreateCertificateResult, error)
	ValidateCertificateAccess(ctx context.Context, certID, userID uuid.UUID, role string) error
	ValidateKeyOwnership(ctx context.Context, keyID, userID uuid.UUID, role string) error
}

// certificateService implements CertificateService by coordinating certificate operations
// and access control while delegating to repository layers.
type certificateService struct {
	certRepo repositories.CertificateRepositoryInterface
	keyRepo  repositories.KeyRepositoryInterface
	logger   *logging.Logger
}

// CertificateServiceConfig holds the dependencies for certificate service.
type CertificateServiceConfig struct {
	CertificateRepository repositories.CertificateRepositoryInterface
	KeyRepository         repositories.KeyRepositoryInterface
	Logger                *logging.Logger
}

// NewCertificateService creates a new CertificateService with the provided dependencies.
// It orchestrates certificate management operations while maintaining SRP compliance.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	A CertificateService implementation for certificate management operations.
func NewCertificateService(config CertificateServiceConfig) CertificateService {
	return &certificateService{
		certRepo: config.CertificateRepository,
		keyRepo:  config.KeyRepository,
		logger:   config.Logger,
	}
}

// CreateSelfSignedCertificate creates a new self-signed X.509 certificate.
// It validates parameters, verifies key ownership, generates the certificate, and handles storage.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The certificate creation request.
//
// Returns:
//
//	The created certificate information or an error if creation fails.
func (s *certificateService) CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":          req.Name,
		"key_id":        req.KeyID.String(),
		"validity_days": req.ValidityDays,
		"user_id":       req.UserID.String(),
	}).Info("Creating self-signed certificate")

	// Validate parameters
	if req.ValidityDays <= 0 {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}

	// Verify key ownership and access
	if err := s.ValidateKeyOwnership(ctx, req.KeyID, req.UserID, ""); err != nil {
		return nil, err
	}

	// Get the private key
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to read key", err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	// Decrypt the private key
	privateKeyPEM, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Generate self-signed certificate
	certPEM, err := crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, key.Type, crypto.CertificateTemplate{
		CommonName:   req.Name,
		ValidityDays: req.ValidityDays,
		IsCA:         true,
	})
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to generate certificate", err)
		return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}

	// Parse the expiry date from the generated certificate.
	expiresAt, err := extractExpiresAt(certPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to parse certificate expiry", err)
		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
	}

	// Encrypt the private key for storage
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to encrypt private key", err)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	renewalDays := req.RenewalDays
	if renewalDays <= 0 {
		renewalDays = 30
	}

	// Create certificate entity
	cert := &domain.Certificate{
		ID:          uuid.New(),
		UserID:      req.UserID,
		Name:        req.Name,
		Certificate: certPEM,
		PrivateKey:  encryptedKey,
		CreatedAt:   time.Now(),
		Tags:        req.Tags,
		ExpiresAt:   expiresAt,
		AutoRenew:   req.AutoRenew,
		RenewalDays: renewalDays,
	}

	// Store in repository
	if err := s.certRepo.Create(ctx, cert); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_self_signed_cert", "failed", "failed to store certificate", err)
		return nil, fmt.Errorf("failed to store self-signed certificate: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_self_signed_cert", "success", fmt.Sprintf("self-signed certificate created: %s, ID: %s", req.Name, cert.ID))
	logrus.WithFields(logrus.Fields{
		"cert_id": cert.ID.String(),
		"name":    cert.Name,
		"key_id":  req.KeyID.String(),
	}).Info("Self-signed certificate created successfully")

	return &CreateCertificateResult{
		CertID:    cert.ID,
		Name:      cert.Name,
		Tags:      cert.Tags,
		CreatedAt: cert.CreatedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// CreateCASignedCertificate creates a new CA-signed X.509 certificate.
// It validates parameters, verifies key ownership, generates the certificate with CA signing, and handles storage.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The certificate creation request with CA certificate ID.
//
// Returns:
//
//	The created certificate information or an error if creation fails.
func (s *certificateService) CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error) {
	logrus.WithFields(logrus.Fields{
		"name":          req.Name,
		"key_id":        req.KeyID.String(),
		"ca_cert_id":    req.CACertID.String(),
		"validity_days": req.ValidityDays,
		"user_id":       req.UserID.String(),
	}).Info("Creating CA-signed certificate")

	// Validate parameters
	if req.CACertID == nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "CA certificate ID required for CA-signed certificates", nil)
		return nil, fmt.Errorf("CA certificate ID required for CA-signed certificates")
	}

	if req.ValidityDays <= 0 {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "validity days must be positive", nil)
		return nil, fmt.Errorf("validity days must be positive")
	}

	// Verify key ownership and access
	if err := s.ValidateKeyOwnership(ctx, req.KeyID, req.UserID, ""); err != nil {
		return nil, err
	}

	// Verify CA certificate access
	if err := s.ValidateCertificateAccess(ctx, *req.CACertID, req.UserID, ""); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "cannot access CA certificate", err)
		return nil, fmt.Errorf("cannot access CA certificate: %w", err)
	}

	// Get the private key for the new certificate
	key, err := s.keyRepo.Read(ctx, req.KeyID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to read key", err)
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	// Decrypt the private key
	privateKeyPEM, err := common.DecryptSecret(key.Value)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to decrypt key", err)
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Get the CA certificate
	caCert, err := s.certRepo.Read(ctx, *req.CACertID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to read CA certificate", err)
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Decrypt CA private key
	caKeyPEM, err := common.DecryptSecret(caCert.PrivateKey)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to decrypt CA key", err)
		return nil, fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	// Generate CA-signed certificate - assume CA uses RSA for simplicity
	certPEM, err := crypto.CreateCASignedCertificatePEM(privateKeyPEM, key.Type, caCert.Certificate, caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName:   req.Name,
		ValidityDays: req.ValidityDays,
		IsCA:         false,
	})
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to generate certificate", err)
		return nil, fmt.Errorf("failed to generate CA-signed certificate: %w", err)
	}

	// Parse the expiry date from the generated certificate.
	expiresAt, err := extractExpiresAt(certPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to parse certificate expiry", err)
		return nil, fmt.Errorf("failed to determine certificate expiry: %w", err)
	}

	// Encrypt the private key for storage
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to encrypt private key", err)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	renewalDays := req.RenewalDays
	if renewalDays <= 0 {
		renewalDays = 30
	}

	// Create certificate entity
	cert := &domain.Certificate{
		ID:          uuid.New(),
		UserID:      req.UserID,
		Name:        req.Name,
		Certificate: certPEM,
		PrivateKey:  encryptedKey,
		CreatedAt:   time.Now(),
		Tags:        req.Tags,
		ExpiresAt:   expiresAt,
		AutoRenew:   req.AutoRenew,
		RenewalDays: renewalDays,
	}

	// Store in repository
	if err := s.certRepo.Create(ctx, cert); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "create_ca_signed_cert", "failed", "failed to store certificate", err)
		return nil, fmt.Errorf("failed to store CA-signed certificate: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "create_ca_signed_cert", "success", fmt.Sprintf("CA-signed certificate created: %s, ID: %s", req.Name, cert.ID))
	logrus.WithFields(logrus.Fields{
		"cert_id":    cert.ID.String(),
		"name":       cert.Name,
		"key_id":     req.KeyID.String(),
		"ca_cert_id": req.CACertID.String(),
	}).Info("CA-signed certificate created successfully")

	return &CreateCertificateResult{
		CertID:    cert.ID,
		Name:      cert.Name,
		Tags:      cert.Tags,
		CreatedAt: cert.CreatedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// GetCertificate retrieves a certificate by ID with access control validation.
//
// Parameters:
//
//	ctx: The context for the operation.
//	certID: The certificate's unique identifier.
//	userID: The requesting user's ID for access control.
//
// Returns:
//
//	The certificate information or an error if not found or access denied.
func (s *certificateService) GetCertificate(ctx context.Context, certID, userID uuid.UUID) (*domain.Certificate, error) {
	cert, err := s.certRepo.Read(ctx, certID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "get_certificate", "failed", fmt.Sprintf("failed to read certificate: %s", err), err)
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Access control: users can only access their own certificates
	if cert.UserID != userID {
		s.logger.LogAuditError(userID.String(), "get_certificate", "failed", "forbidden: cannot access other users' certificates", nil)
		return nil, fmt.Errorf("forbidden: cannot access other users' certificates")
	}

	return cert, nil
}

// ListCertificates retrieves all certificates for a specific user.
//
// Parameters:
//
//	ctx: The context for the operation.
//	userID: The user's unique identifier.
//
// Returns:
//
//	A slice of user's certificates or an error if retrieval fails.
func (s *certificateService) ListCertificates(ctx context.Context, userID uuid.UUID) ([]domain.Certificate, error) {
	return s.certRepo.ListByUser(ctx, userID, "", nil)
}

// UpdateCertificate updates an existing certificate with access control validation.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The certificate update request with optional fields.
//
// Returns:
//
//	An error if the update fails or access is denied.
func (s *certificateService) UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error {
	logrus.WithField("cert_id", req.CertID.String()).Info("Updating certificate")

	// Verify certificate exists and access
	cert, err := s.GetCertificate(ctx, req.CertID, req.UserID)
	if err != nil {
		return err
	}

	// Prepare updated certificate
	updatedCert := *cert

	// Update name if provided
	if req.Name != nil {
		updatedCert.Name = *req.Name
	}

	// Update tags if provided
	if len(req.Tags) > 0 {
		updatedCert.Tags = req.Tags
	}

	// Update auto-renew setting if provided
	if req.AutoRenew != nil {
		updatedCert.AutoRenew = *req.AutoRenew
	}

	// Update renewal days if provided
	if req.RenewalDays != nil {
		updatedCert.RenewalDays = *req.RenewalDays
	}

	// Update certificate via repository
	if err := s.certRepo.Update(ctx, &updatedCert); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_certificate", "failed", "Failed to update certificate", err)
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "update_certificate", "success", fmt.Sprintf("Certificate updated: %s", updatedCert.Name))
	return nil
}

// DeleteCertificate removes a certificate from the system with access control validation.
//
// Parameters:
//
//	ctx: The context for the operation.
//	certID: The certificate's unique identifier.
//	userID: The requesting user's ID for access control.
//
// Returns:
//
//	An error if deletion fails or access is denied.
func (s *certificateService) DeleteCertificate(ctx context.Context, certID, userID uuid.UUID) error {
	// Verify certificate exists and access
	if _, err := s.GetCertificate(ctx, certID, userID); err != nil {
		return err
	}

	if err := s.certRepo.SoftDelete(ctx, certID); err != nil {
		s.logger.LogAuditError(userID.String(), "delete_certificate", "failed", "Failed to soft delete certificate", err)
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "delete_certificate", "success", "Certificate soft deleted successfully")
	return nil
}

// RenewCertificate creates a new certificate to replace an expiring one.
// It generates a new certificate with the same properties as the original.
//
// Parameters:
//
//	ctx: The context for the operation.
//	certID: The certificate to renew.
//	userID: The requesting user's ID for access control.
//	validityDays: The validity period for the new certificate.
//
// Returns:
//
//	The new certificate information or an error if renewal fails.
func (s *certificateService) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*CreateCertificateResult, error) {
	// Verify certificate exists and access; original carries AutoRenew/RenewalDays.
	original, err := s.GetCertificate(ctx, certID, userID)
	if err != nil {
		return nil, err
	}

	// Renewal requires a KeyID that is not stored on the Certificate struct.
	// The caller must supply it; until the struct is extended this path cannot complete.
	_ = original // AutoRenew and RenewalDays would be forwarded to the new cert here.
	return nil, fmt.Errorf("certificate renewal requires KeyID information not available in Certificate struct")
}

// ValidateCertificateAccess validates that a user has access to a specific certificate.
// It handles role-based access control for certificate operations.
//
// Parameters:
//
//	ctx: The context for the operation.
//	certID: The certificate's unique identifier.
//	userID: The requesting user's ID.
//	role: The user's role for permission checking.
//
// Returns:
//
//	An error if access is denied.
func (s *certificateService) ValidateCertificateAccess(ctx context.Context, certID, userID uuid.UUID, role string) error {
	// Admin users have access to all certificates
	if role == domain.RoleAdmin {
		return nil
	}

	// Non-admin users can only access their own certificates
	cert, err := s.certRepo.Read(ctx, certID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "validate_certificate_access", "failed", fmt.Sprintf("certificate not found: %s", err), err)
		return fmt.Errorf("certificate not found: %w", err)
	}

	if cert.UserID != userID {
		s.logger.LogAuditError(userID.String(), "validate_certificate_access", "failed", "forbidden: cannot access other users' certificates", nil)
		return fmt.Errorf("forbidden: cannot access other users' certificates")
	}

	return nil
}

// ValidateKeyOwnership validates that a user has access to use a specific key.
// It handles role-based access control for key usage in certificate operations.
//
// Parameters:
//
//	ctx: The context for the operation.
//	keyID: The key's unique identifier.
//	userID: The requesting user's ID.
//	role: The user's role for permission checking.
//
// Returns:
//
//	An error if access is denied.
func (s *certificateService) ValidateKeyOwnership(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	// Admin users can use any key
	if role == domain.RoleAdmin {
		return nil
	}

	// Verify key ownership
	key, err := s.keyRepo.Read(ctx, keyID)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "validate_key_ownership", "failed", fmt.Sprintf("key not found: %s", err), err)
		return fmt.Errorf("key not found: %w", err)
	}

	if key.UserID != userID {
		s.logger.LogAuditError(userID.String(), "validate_key_ownership", "failed", "forbidden: cannot use other users' keys", nil)
		return fmt.Errorf("forbidden: cannot use other users' keys")
	}

	return nil
}

// extractExpiresAt parses the NotAfter field from a PEM-encoded X.509 certificate.
func extractExpiresAt(certPEM string) (*time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}
	t := cert.NotAfter
	return &t, nil
}
