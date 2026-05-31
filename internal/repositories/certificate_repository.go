// Package repositories provides data access layer implementations.
// This package contains repository implementations that focus solely on
// database operations without business logic, following the SRP principle.
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// CertificateRepositoryInterface defines the interface for certificate repository operations.
// It provides type-safe CRUD operations for the Certificate type.
type CertificateRepositoryInterface interface {
	Create(ctx context.Context, cert *model.Certificate) error
	Read(ctx context.Context, id uuid.UUID) (*model.Certificate, error)
	Update(ctx context.Context, cert *model.Certificate) error
	Delete(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error
	ListByUser(ctx context.Context, userID uuid.UUID, certType string, tags []string) ([]model.Certificate, error)
	ListRevoked(ctx context.Context, userID uuid.UUID) ([]model.RevokedCertificate, error)
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverCertificate(ctx context.Context, id uuid.UUID) error
	PurgeCertificate(ctx context.Context, id uuid.UUID) error
	SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
	ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Certificate, error)
	ListAll(ctx context.Context) ([]model.Certificate, error)
	// ListInVault lists certificates scoped to a vault, optionally filtered by type and tags.
	ListInVault(ctx context.Context, vaultID uuid.UUID, certType string, tags []string) ([]model.Certificate, error)
	// ReadInVault fetches a certificate only when id and vaultID both match.
	ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Certificate, error)
	// SoftDeleteVaultContents soft-deletes every active certificate in a vault.
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContents recovers only the certificates the cascade soft-deleted at deletedAt.
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
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
func (r *CertificateRepository) Create(ctx context.Context, cert *model.Certificate) error {
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

		// Insert certificate with pre-encrypted private key and renewal metadata.
		_, err = tx.ExecContext(
			ctx,
			"INSERT INTO certificates (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			cert.ID.String(), cert.UserID.String(), cert.VaultID.String(), cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
			cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays, cert.KeyID.String(), cert.Enabled, cert.NotBefore,
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
func (r *CertificateRepository) Read(ctx context.Context, id uuid.UUID) (*model.Certificate, error) {
	var cert model.Certificate
	var idStr, userIDStr string
	var keyIDStr sql.NullString

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before FROM certificates WHERE id = ? AND deleted_at IS NULL",
		id.String(),
	).Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
		&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &cert.Enabled, &cert.NotBefore)

	if errors.Is(err, sql.ErrNoRows) {
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

	if keyIDStr.Valid {
		cert.KeyID, err = uuid.Parse(keyIDStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key ID: %w", err)
		}
	}

	// Retrieve tags using TagRepository
	tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
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
func (r *CertificateRepository) Update(ctx context.Context, cert *model.Certificate) error {
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
			"UPDATE certificates SET name = ?, certificate = ?, private_key = ?, created_at = ?, expires_at = ?, auto_renew = ?, renewal_days = ?, enabled = ?, not_before = ? WHERE id = ?",
			cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
			cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays, cert.Enabled, cert.NotBefore, cert.ID.String(),
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

			tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
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
func (r *CertificateRepository) ListByUser(ctx context.Context, userID uuid.UUID, certType string, tags []string) ([]model.Certificate, error) {
	var certList []model.Certificate

	err := r.executeWithMetrics("list_certificates_by_user", func() error {
		query := "SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before FROM certificates WHERE user_id = ? AND deleted_at IS NULL"
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
		certList = make([]model.Certificate, 0, 50)

		for rows.Next() {
			var cert model.Certificate
			var idStr, userIDStr string
			var keyIDStr sql.NullString

			if err := rows.Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
				&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &cert.Enabled, &cert.NotBefore); err != nil {
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

			if keyIDStr.Valid {
				cert.KeyID, err = uuid.Parse(keyIDStr.String)
				if err != nil {
					r.log.LogAuditError(userID.String(), "list_certificates", "failed", "Failed to parse key ID", err)
					return fmt.Errorf("failed to parse key ID: %w", err)
				}
			}

			// Retrieve tags for each certificate
			tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
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
func (r *CertificateRepository) ListRevoked(ctx context.Context, userID uuid.UUID) ([]model.RevokedCertificate, error) {
	var revokedList []model.RevokedCertificate

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
		revokedList = make([]model.RevokedCertificate, 0, 20)

		for rows.Next() {
			var cert model.RevokedCertificate
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

// SoftDelete marks a certificate as deleted without removing it from the database.
// The certificate is excluded from normal reads but remains available for recovery.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *CertificateRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("soft_delete_certificate", func() error {
		logrus.WithField("cert_id", id.String()).Debug("Soft deleting certificate from database")

		now := time.Now()
		result, err := r.db.ExecContext(ctx,
			"UPDATE certificates SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
			now, id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "soft_delete_certificate", "failed", "Failed to soft delete certificate", err)
			return fmt.Errorf("failed to soft delete certificate: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "soft_delete_certificate", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "soft_delete_certificate", "failed", "Certificate not found or already deleted", nil)
			return fmt.Errorf("certificate not found or already deleted")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "soft_delete_certificate", "success", "Certificate soft deleted successfully")
		logrus.WithField("cert_id", id.String()).Debug("Certificate soft deleted successfully")

		return nil
	})
}

// RecoverCertificate restores a soft-deleted certificate by clearing its deleted_at timestamp.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	An error if the certificate is not found in a deleted state or the update fails.
func (r *CertificateRepository) RecoverCertificate(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("recover_certificate", func() error {
		logrus.WithField("cert_id", id.String()).Debug("Recovering soft-deleted certificate")

		result, err := r.db.ExecContext(ctx,
			"UPDATE certificates SET deleted_at = NULL, scheduled_purge_at = NULL WHERE id = ? AND deleted_at IS NOT NULL",
			id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "recover_certificate", "failed", "Failed to recover certificate", err)
			return fmt.Errorf("failed to recover certificate: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "recover_certificate", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "recover_certificate", "failed", "Certificate not found in deleted state", nil)
			return fmt.Errorf("certificate not found in deleted state")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "recover_certificate", "success", "Certificate recovered successfully")
		logrus.WithField("cert_id", id.String()).Debug("Certificate recovered successfully")

		return nil
	})
}

// PurgeCertificate permanently removes a soft-deleted certificate from the database.
// It fails if the certificate has purge protection enabled.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//
// Returns:
//
//	An error if the purge operation fails or purge protection is enabled.
func (r *CertificateRepository) PurgeCertificate(ctx context.Context, id uuid.UUID) error {
	return r.executeWithMetrics("purge_certificate", func() error {
		logrus.WithField("cert_id", id.String()).Debug("Purging certificate from database")

		// Check certificate status before purging.
		var deletedAt *time.Time
		var purgeProtection bool
		err := r.db.QueryRowContext(ctx,
			"SELECT deleted_at, purge_protection FROM certificates WHERE id = ?", id.String()).
			Scan(&deletedAt, &purgeProtection)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Certificate not found", nil)
				return fmt.Errorf("certificate not found")
			}
			r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Failed to check certificate status", err)
			return fmt.Errorf("failed to check certificate status: %w", err)
		}

		if deletedAt == nil {
			r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Certificate is not soft-deleted", nil)
			return fmt.Errorf("certificate is not soft-deleted")
		}
		if purgeProtection {
			r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Certificate has purge protection enabled", nil)
			return fmt.Errorf("certificate has purge protection enabled")
		}

		result, err := r.db.ExecContext(ctx, "DELETE FROM certificates WHERE id = ?", id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Failed to purge certificate", err)
			return fmt.Errorf("failed to purge certificate: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "purge_certificate", "failed", "Certificate not found for purge", nil)
			return fmt.Errorf("certificate not found for purge")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "purge_certificate", "success", "Certificate purged successfully")
		logrus.WithField("cert_id", id.String()).Debug("Certificate purged successfully")

		return nil
	})
}

// SetPurgeProtection enables or disables purge protection on a certificate.
// A certificate with purge protection cannot be permanently deleted via PurgeCertificate.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//   - enabled: True to enable purge protection, false to disable it.
//
// Returns:
//
//	An error if the update fails.
func (r *CertificateRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return r.executeWithMetrics("set_purge_protection_certificate", func() error {
		result, err := r.db.ExecContext(ctx,
			"UPDATE certificates SET purge_protection = ? WHERE id = ?",
			enabled, id.String())
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "set_purge_protection_certificate", "failed", "Failed to set purge protection", err)
			return fmt.Errorf("failed to set purge protection: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			r.log.LogAuditError(uuid.Nil.String(), "set_purge_protection_certificate", "failed", "Failed to get rows affected", err)
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			r.log.LogAuditError(uuid.Nil.String(), "set_purge_protection_certificate", "failed", "Certificate not found", nil)
			return fmt.Errorf("certificate not found")
		}

		r.log.LogAuditInfo(uuid.Nil.String(), "set_purge_protection_certificate", "success", fmt.Sprintf("Certificate purge protection set to %v", enabled))
		return nil
	})
}

// ListSoftDeleted retrieves all soft-deleted certificates for a given user.
// Only certificates with deleted_at set are returned.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - userID: The user's unique identifier.
//
// Returns:
//
//	A slice of soft-deleted certificate pointers, or an error if retrieval fails.
func (r *CertificateRepository) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Certificate, error) {
	var certList []*model.Certificate

	err := r.executeWithMetrics("list_soft_deleted_certificates", func() error {
		logrus.WithField("user_id", userID.String()).Debug("Listing soft-deleted certificates for user")

		rows, err := r.db.QueryContext(ctx,
			"SELECT id, user_id, name, certificate, private_key, created_at, deleted_at, purge_protection, key_id, enabled, not_before FROM certificates WHERE user_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC",
			userID.String())
		if err != nil {
			r.log.LogAuditError(userID.String(), "list_soft_deleted_certificates", "failed", "Failed to query soft-deleted certificates", err)
			return fmt.Errorf("failed to query soft-deleted certificates: %w", err)
		}
		defer rows.Close()

		certList = make([]*model.Certificate, 0)

		for rows.Next() {
			var cert model.Certificate
			var idStr, userIDStr string
			var deletedAt *time.Time
			var purgeProtection bool
			var keyIDStr sql.NullString

			if err := rows.Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt, &deletedAt, &purgeProtection, &keyIDStr, &cert.Enabled, &cert.NotBefore); err != nil {
				r.log.LogAuditError(userID.String(), "list_soft_deleted_certificates", "failed", "Failed to scan certificate", err)
				return fmt.Errorf("failed to scan certificate: %w", err)
			}

			cert.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_soft_deleted_certificates", "failed", "Failed to parse certificate ID", err)
				return fmt.Errorf("failed to parse certificate ID: %w", err)
			}

			cert.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(userID.String(), "list_soft_deleted_certificates", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			if keyIDStr.Valid {
				cert.KeyID, err = uuid.Parse(keyIDStr.String)
				if err != nil {
					r.log.LogAuditError(userID.String(), "list_soft_deleted_certificates", "failed", "Failed to parse key ID", err)
					return fmt.Errorf("failed to parse key ID: %w", err)
				}
			}

			cert.DeletedAt = deletedAt
			cert.PurgeProtection = purgeProtection

			certList = append(certList, &cert)
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
		"user_id":    userID.String(),
		"cert_count": len(certList),
	}).Debug("Soft-deleted certificates listed successfully")

	return certList, nil
}

// ListAll returns all non-deleted certificates across all users.
// It is used by the renewal scheduler to find certificates that need renewal.
//
// Parameters:
//   - ctx: The context for the database operation.
//
// Returns:
//
//	A slice of all active certificates, or an error if retrieval fails.
func (r *CertificateRepository) ListAll(ctx context.Context) ([]model.Certificate, error) {
	var certs []model.Certificate

	err := r.executeWithMetrics("list_all_certificates", func() error {
		rows, err := r.db.QueryContext(ctx,
			"SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before FROM certificates WHERE deleted_at IS NULL")
		if err != nil {
			return fmt.Errorf("failed to list all certificates: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var cert model.Certificate
			var idStr, userIDStr string
			var keyIDStr sql.NullString
			if err := rows.Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
				&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &cert.Enabled, &cert.NotBefore); err != nil {
				return fmt.Errorf("failed to scan certificate row: %w", err)
			}
			cert.ID = uuid.MustParse(idStr)
			cert.UserID = uuid.MustParse(userIDStr)
			if keyIDStr.Valid {
				cert.KeyID = uuid.MustParse(keyIDStr.String)
			}
			certs = append(certs, cert)
		}

		return rows.Err()
	})

	return certs, err
}

// ListInVault retrieves certificates for a vault, optionally filtered by type and tags.
// It mirrors ListByUser but scopes by vault_id instead of user_id.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose certificates to list.
//   - certType: The certificate type to filter by (empty for all types).
//   - tags: The tags to filter by (empty for no tag filter).
//
// Returns:
//
//	A slice of certificates (with encrypted private keys) or an error if retrieval fails.
func (r *CertificateRepository) ListInVault(ctx context.Context, vaultID uuid.UUID, certType string, tags []string) ([]model.Certificate, error) {
	var certList []model.Certificate

	err := r.executeWithMetrics("list_certificates_by_vault", func() error {
		query := "SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before FROM certificates WHERE vault_id = ? AND deleted_at IS NULL"
		args := []interface{}{vaultID.String()}

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
			r.log.LogAuditError(vaultID.String(), "list_certificates", "failed", "Failed to query certificates", err)
			return fmt.Errorf("failed to query certificates: %w", err)
		}
		defer rows.Close()

		// Pre-allocate slice for better memory performance.
		certList = make([]model.Certificate, 0, 50)

		for rows.Next() {
			var cert model.Certificate
			var idStr, userIDStr string
			var keyIDStr sql.NullString

			if err := rows.Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
				&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &cert.Enabled, &cert.NotBefore); err != nil {
				r.log.LogAuditError(vaultID.String(), "list_certificates", "failed", "Failed to scan certificate", err)
				return fmt.Errorf("failed to scan certificate: %w", err)
			}

			cert.ID, err = uuid.Parse(idStr)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_certificates", "failed", "Failed to parse certificate ID", err)
				return fmt.Errorf("failed to parse certificate ID: %w", err)
			}

			cert.UserID, err = uuid.Parse(userIDStr)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_certificates", "failed", "Failed to parse user ID", err)
				return fmt.Errorf("failed to parse user ID: %w", err)
			}

			if keyIDStr.Valid {
				cert.KeyID, err = uuid.Parse(keyIDStr.String)
				if err != nil {
					r.log.LogAuditError(vaultID.String(), "list_certificates", "failed", "Failed to parse key ID", err)
					return fmt.Errorf("failed to parse key ID: %w", err)
				}
			}

			// Retrieve tags for each certificate.
			tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
			cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
			if err != nil {
				r.log.LogAuditError(vaultID.String(), "list_certificates", "failed", "Failed to read tags for certificate", err)
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
		"vault_id": vaultID.String(),
		"count":    len(certList),
	}).Debug("Certificates listed successfully")

	return certList, nil
}

// ReadInVault retrieves a certificate by ID only when it belongs to the given vault.
// It mirrors Read but adds a vault_id scope.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - id: The certificate's unique identifier.
//   - vaultID: The vault the certificate must belong to.
//
// Returns:
//
//	The certificate entity (with encrypted private key) or an error if not found / access denied.
func (r *CertificateRepository) ReadInVault(ctx context.Context, id, vaultID uuid.UUID) (*model.Certificate, error) {
	var cert model.Certificate
	var idStr, userIDStr string
	var keyIDStr sql.NullString

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, enabled, not_before FROM certificates WHERE id = ? AND vault_id = ? AND deleted_at IS NULL",
		id.String(), vaultID.String(),
	).Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
		&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &cert.Enabled, &cert.NotBefore)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("certificate not found or access denied")
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

	if keyIDStr.Valid {
		cert.KeyID, err = uuid.Parse(keyIDStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key ID: %w", err)
		}
	}

	// Retrieve tags using TagRepository.
	tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
	cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
	if err != nil {
		r.log.LogAuditError(uuid.Nil.String(), "read_certificate", "failed", "Failed to read tags", err)
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}

	return &cert, nil
}

// SoftDeleteVaultContents marks every active certificate in a vault as soft-deleted.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose certificates should be soft-deleted.
//   - deletedAt: The exact deletion timestamp to stamp on each cascaded row.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *CertificateRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("soft_delete_vault_certificates", func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Soft deleting all certificates in vault")

		_, err := r.db.ExecContext(ctx,
			"UPDATE certificates SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
			deletedAt, vaultID.String())
		if err != nil {
			r.log.LogAuditError(vaultID.String(), "soft_delete_vault_certificates", "failed", "Failed to soft delete vault certificates", err)
			return fmt.Errorf("failed to soft delete vault certificates: %w", err)
		}

		r.log.LogAuditInfo(vaultID.String(), "soft_delete_vault_certificates", "success", "Vault certificates soft deleted successfully")
		return nil
	})
}

// RecoverVaultContents restores every soft-deleted certificate in a vault.
//
// Parameters:
//   - ctx: The context for the database operation.
//   - vaultID: The vault whose certificates should be recovered.
//   - deletedAt: The cascade deletion timestamp; only rows stamped with it are restored.
//
// Returns:
//
//	An error if the recovery fails.
func (r *CertificateRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("recover_vault_certificates", func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Recovering cascade soft-deleted certificates in vault")

		_, err := r.db.ExecContext(ctx,
			"UPDATE certificates SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at = ?",
			vaultID.String(), deletedAt)
		if err != nil {
			r.log.LogAuditError(vaultID.String(), "recover_vault_certificates", "failed", "Failed to recover vault certificates", err)
			return fmt.Errorf("failed to recover vault certificates: %w", err)
		}

		r.log.LogAuditInfo(vaultID.String(), "recover_vault_certificates", "success", "Vault certificates recovered successfully")
		return nil
	})
}
