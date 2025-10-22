// Package repositories provides data access layer implementations.
// This package contains repository implementations that focus solely on
// database operations without business logic, following the SRP principle.
package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/db"
	"password-manager/internal/domain"
	"password-manager/internal/logging"
)

// CertificateRepositoryInterface defines the interface for certificate repository operations.
// It provides type-safe CRUD operations for the Certificate type.
type CertificateRepositoryInterface interface {
	Create(ctx context.Context, cert *domain.Certificate) error
	Read(ctx context.Context, id uuid.UUID) (*domain.Certificate, error)
	Update(ctx context.Context, cert *domain.Certificate) error
	Delete(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error
	ListByUser(ctx context.Context, userID uuid.UUID, certType string, tags []string) ([]domain.Certificate, error)
	ListRevoked(ctx context.Context, userID uuid.UUID) ([]domain.RevokedCertificate, error)
}

// CertificateRepository implements CertificateRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like X.509 generation or encryption.
// All crypto operations (encryption, certificate generation) are handled by the service layer.
type CertificateRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// executeWithMetrics wraps database operations with performance monitoring.
func (r *CertificateRepository) executeWithMetrics(operation string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	// Record performance metrics
	db.RecordQueryExecution(duration)

	// Log slow queries
	if duration > 100*time.Millisecond {
		logrus.WithFields(logrus.Fields{
			"operation": operation,
			"duration":  duration.Milliseconds(),
			"table":     "certificates",
		}).Warn("Slow database query detected")
	}

	return err
}

// NewCertificateRepository creates a new CertificateRepository instance.
// It provides pure database operations for certificate entities.
//
// Parameters:
//   - db: The database connection.
//   - log: The logger for database operation logging.
//
// Returns:
//
//	A CertificateRepositoryInterface implementation for certificate database operations.
func NewCertificateRepository(db *sql.DB, log *logging.Logger) CertificateRepositoryInterface {
	return &CertificateRepository{db: db, log: log}
}

// Create inserts a new certificate into the database.
// It expects the certificate PEM and private key to be already generated and encrypted.
// NO X.509 generation or encryption happens here - pure data access only.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - cert: The certificate entity to store (with pre-generated cert PEM and encrypted private key).
//
// Returns:
//
//	An error if the insertion fails.
func (r *CertificateRepository) Create(ctx context.Context, cert *domain.Certificate) error {
	return r.executeWithMetrics("create_certificate", func() error {
		logrus.WithFields(logrus.Fields{
			"cert_id": cert.ID.String(),
			"user_id": cert.UserID.String(),
			"name":    cert.Name,
		}).Debug("Inserting certificate into database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback()

		// Insert certificate with pre-encrypted private key
		_, err = tx.ExecContext(
			ctx,
			"INSERT INTO certificates (id, user_id, name, certificate, private_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			cert.ID.String(), cert.UserID.String(), cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
		)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", "Failed to insert certificate", err)
			return fmt.Errorf("failed to insert certificate: %w", err)
		}

		// Insert tags if provided (using existing transaction to avoid locks)
		if len(cert.Tags) > 0 {
			for _, tag := range cert.Tags {
				_, err := tx.ExecContext(ctx,
					"INSERT INTO certificate_tags (certificate_id, tag) VALUES (?, ?)",
					cert.ID.String(), tag,
				)
				if err != nil {
					r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", fmt.Sprintf("Failed to insert tag %s", tag), err)
					return fmt.Errorf("failed to insert tag %s: %w", tag, err)
				}
			}
		}

		if err := tx.Commit(); err != nil {
			r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(cert.UserID.String(), "create_certificate", "success", fmt.Sprintf("Certificate created: %s", cert.Name))
		logrus.WithFields(logrus.Fields{
			"cert_id": cert.ID.String(),
			"user_id": cert.UserID.String(),
			"name":    cert.Name,
		}).Debug("Certificate inserted successfully")

		return nil
	})
}

// Read retrieves a certificate by ID from the database.
// It returns the certificate with encrypted private key - NO decryption happens here.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	The certificate entity (with encrypted private key) or an error if not found.
func (r *CertificateRepository) Read(ctx context.Context, id uuid.UUID) (*domain.Certificate, error) {
	var cert domain.Certificate
	var idStr, userIDStr string

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, certificate, private_key, created_at FROM certificates WHERE id = ?",
		id.String(),
	).Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate not found")
	}
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_certificate", "failed", "Failed to query certificate", err)
		return nil, fmt.Errorf("failed to query certificate: %w", err)
	}

	cert.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate ID: %w", err)
	}

	cert.UserID, err = uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	// Retrieve tags using TagRepository
	tagRepo := db.NewTagRepository[domain.Certificate](r.db, "certificate_tags", "certificate_id")
	cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_certificate", "failed", "Failed to read tags", err)
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}

	return &cert, nil
}

// Update updates a certificate in the database.
// It expects the private key to be already encrypted if changed.
// NO encryption or X.509 generation happens here - pure data access only.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - cert: The certificate entity with updated fields (pre-encrypted private key).
//
// Returns:
//
//	An error if the update fails.
func (r *CertificateRepository) Update(ctx context.Context, cert *domain.Certificate) error {
	return r.executeWithMetrics("update_certificate", func() error {
		logrus.WithFields(logrus.Fields{
			"cert_id": cert.ID.String(),
			"user_id": cert.UserID.String(),
			"name":    cert.Name,
		}).Debug("Updating certificate in database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "update_certificate", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback()

		result, err := tx.ExecContext(
			ctx,
			"UPDATE certificates SET name = ?, certificate = ?, private_key = ?, created_at = ? WHERE id = ?",
			cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt, cert.ID.String(),
		)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "update_certificate", "failed", "Failed to update certificate", err)
			return fmt.Errorf("failed to update certificate: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "update_certificate", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(cert.UserID.String(), "update_certificate", "failed", "Certificate not found for update", nil)
			return fmt.Errorf("certificate not found")
		}

		// Update tags if provided
		if len(cert.Tags) > 0 {
			_, err = tx.ExecContext(ctx, "DELETE FROM certificate_tags WHERE certificate_id = ?", cert.ID.String())
			if err != nil {
				r.log.LogAuditError(cert.UserID.String(), "update_certificate", "failed", "Failed to delete existing tags", err)
				return fmt.Errorf("failed to delete existing tags: %w", err)
			}

			tagRepo := db.NewTagRepository[domain.Certificate](r.db, "certificate_tags", "certificate_id")
			if err := tagRepo.AddTags(ctx, cert.ID, cert.Tags); err != nil {
				r.log.LogAuditError(cert.UserID.String(), "update_certificate", "failed", "Failed to add tags", err)
				return fmt.Errorf("failed to add tags: %w", err)
			}
		}

		if err := tx.Commit(); err != nil {
			r.log.LogAuditError(cert.UserID.String(), "update_certificate", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(cert.UserID.String(), "update_certificate", "success", fmt.Sprintf("Certificate updated: %s", cert.Name))
		logrus.WithFields(logrus.Fields{
			"cert_id": cert.ID.String(),
			"user_id": cert.UserID.String(),
			"name":    cert.Name,
		}).Debug("Certificate updated successfully")

		return nil
	})
}

// Delete removes a certificate from the database.
// It removes the certificate, its private key, and associated tags within a transaction.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	An error if the deletion fails.
func (r *CertificateRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("delete_certificate", func() error {
		logrus.WithField("cert_id", id.String()).Debug("Deleting certificate from database")

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_certificate", "failed", "Failed to begin transaction", err)
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback()

		// Delete tags first
		_, err = tx.ExecContext(ctx, "DELETE FROM certificate_tags WHERE certificate_id = ?", id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_certificate", "failed", "Failed to delete tags", err)
			return fmt.Errorf("failed to delete tags: %w", err)
		}

		// Delete certificate
		result, err := tx.ExecContext(ctx, "DELETE FROM certificates WHERE id = ?", id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_certificate", "failed", "Failed to delete certificate", err)
			return fmt.Errorf("failed to delete certificate: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_certificate", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "delete_certificate", "failed", "Certificate not found for deletion", nil)
			return fmt.Errorf("certificate not found")
		}

		if err := tx.Commit(); err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "delete_certificate", "failed", "Failed to commit transaction", err)
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "delete_certificate", "success", "Certificate deleted successfully")
		logrus.WithField("cert_id", id.String()).Debug("Certificate deleted successfully")

		return nil
	})
}

// Revoke adds a certificate to the CRL (Certificate Revocation List).
// It marks the certificate as revoked in the database.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's ID.
//   - serialNumber: The certificate's serial number.
//   - name: The certificate's common name.
//
// Returns:
//
//	An error if revocation fails.
func (r *CertificateRepository) Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error {
	return r.executeWithMetrics("revoke_certificate", func() error {
		// Read certificate to get user ID
		cert, err := r.Read(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to read certificate: %w", err)
		}

		_, err = r.db.ExecContext(
			ctx,
			"INSERT INTO crl (user_id, serial_number, name, revoked_at) VALUES (?, ?, ?, ?)",
			cert.UserID.String(), serialNumber, name, time.Now(),
		)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "revoke_certificate", "failed", "Failed to insert into CRL", err)
			return fmt.Errorf("failed to revoke certificate: %w", err)
		}

		r.log.LogAuditInfo(cert.UserID.String(), "revoke_certificate", "success", fmt.Sprintf("Certificate revoked: %s", name))
		logrus.WithFields(logrus.Fields{
			"cert_id":       id.String(),
			"serial_number": serialNumber,
			"name":          name,
		}).Debug("Certificate revoked successfully")

		return nil
	})
}

// ListByUser retrieves certificates for a user, optionally filtered by type and tags.
// It returns certificates with encrypted private keys - NO decryption happens here.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - userID: The ID of the user whose certificates to list.
//   - certType: The certificate type to filter by (empty for all types).
//   - tags: The tags to filter by (empty for no tag filter).
//
// Returns:
//
//	A slice of certificates (with encrypted private keys) or an error if retrieval fails.
func (r *CertificateRepository) ListByUser(ctx context.Context, userID uuid.UUID, certType string, tags []string) ([]domain.Certificate, error) {
	var certList []domain.Certificate

	err := r.executeWithMetrics("list_certificates_by_user", func() error {
		query := "SELECT id, user_id, name, certificate, private_key, created_at FROM certificates WHERE user_id = ?"
		args := []interface{}{userID.String()}

		if certType != "" {
			query += " AND type = ?"
			args = append(args, certType)
		}

		if len(tags) > 0 {
			placeholders := strings.Repeat(",?", len(tags))[1:]
			query += fmt.Sprintf(" AND id IN (SELECT certificate_id FROM certificate_tags WHERE tag IN (%s))", placeholders)
			for _, tag := range tags {
				args = append(args, tag)
			}
		}

		query += " ORDER BY created_at DESC"

		rows, err := r.db.QueryContext(ctx, query, args...)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_certificates", "failed", "Failed to query certificates", err)
			return fmt.Errorf("failed to query certificates: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice for better memory performance
		certList = make([]domain.Certificate, 0, 50)

		for rows.Next() {
			var cert domain.Certificate
			var idStr, userIDStr string

			if err := rows.Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt); err != nil {
				r.log.LogAuditError(userID.String(), "list_certificates", "failed", "Failed to scan certificate", err)
				return fmt.Errorf("failed to scan certificate: %w", err)
			}

			cert.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_certificates", "failed", "Failed to parse certificate ID", err)
				return fmt.Errorf("failed to parse certificate ID: %w", err)
			}

			cert.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_certificates", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			// Retrieve tags for each certificate
			tagRepo := db.NewTagRepository[domain.Certificate](r.db, "certificate_tags", "certificate_id")
			cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_certificates", "failed", "Failed to read tags for certificate", err)
				return fmt.Errorf("failed to read tags for certificate: %w", err)
			}

			certList = append(certList, cert)
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID.String(),
		"count":   len(certList),
	}).Debug("Certificates listed successfully")

	return certList, nil
}

// ListRevoked retrieves all revoked certificates for a user from the CRL.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - userID: The user's ID.
//
// Returns:
//
//	A list of revoked certificates or an error if retrieval fails.
func (r *CertificateRepository) ListRevoked(ctx context.Context, userID uuid.UUID) ([]domain.RevokedCertificate, error) {
	var revokedList []domain.RevokedCertificate

	err := r.executeWithMetrics("list_revoked_certificates", func() error {
		rows, err := r.db.QueryContext(
			ctx,
			"SELECT id, user_id, serial_number, name, revoked_at FROM crl WHERE user_id = ? ORDER BY revoked_at DESC",
			userID.String(),
		)
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_revoked_certificates", "failed", "Failed to query revoked certificates", err)
			return fmt.Errorf("failed to query revoked certificates: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice
		revokedList = make([]domain.RevokedCertificate, 0, 20)

		for rows.Next() {
			var cert domain.RevokedCertificate
			var idStr, userIDStr string

			if err := rows.Scan(&idStr, &userIDStr, &cert.SerialNumber, &cert.Name, &cert.RevokedAt); err != nil {
				r.log.LogAuditError(userID.String(), "list_revoked_certificates", "failed", "Failed to scan revoked certificate", err)
				return fmt.Errorf("failed to scan revoked certificate: %w", err)
			}

			cert.ID, err = uuid.Parse(idStr)
			if err != nil {
				return fmt.Errorf("failed to parse revoked certificate ID: %w", err)
			}

			cert.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			revokedList = append(revokedList, cert)
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("row iteration error: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"user_id": userID.String(),
		"count":   len(revokedList),
	}).Debug("Revoked certificates listed successfully")

	return revokedList, nil
}
