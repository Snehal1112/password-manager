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
	// Read fetches a certificate authorized by scope. The scoped read is the
	// access check: a row outside the scope is indistinguishable from a row
	// that does not exist.
	Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error)
	// Update updates a certificate authorized by scope. The predicate comes
	// from the scope argument, never from the entity.
	Update(ctx context.Context, cert *model.Certificate, scope model.Scope) error
	// List lists certificates authorized by scope and narrowed by filter.
	List(ctx context.Context, scope model.Scope, filter CertificateFilter) ([]model.Certificate, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error
	ListRevoked(ctx context.Context, userID uuid.UUID) ([]model.RevokedCertificate, error)
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverCertificate(ctx context.Context, id uuid.UUID) error
	PurgeCertificate(ctx context.Context, id uuid.UUID) error
	SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
	ListAll(ctx context.Context) ([]model.Certificate, error)
	// SoftDeleteVaultContents soft-deletes every active certificate in a vault.
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContents recovers only the certificates the cascade soft-deleted at deletedAt.
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
}

// CertificateFilter narrows a scoped certificate listing. There is no Type
// field: the certificates table has no type column.
type CertificateFilter struct {
	Tags           []string
	IncludeDeleted bool
	OnlyDeleted    bool
}

// certificateColumns is the canonical SELECT list shared by every scoped query.
const certificateColumns = "id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before, deleted_at, purge_protection"

// scanCertificateRow scans one certificates row in the canonical column order.
func scanCertificateRow(scan func(dest ...any) error) (model.Certificate, error) {
	var cert model.Certificate
	var idStr, userIDStr, vaultIDStr string
	var keyIDStr, caCertIDStr sql.NullString

	if err := scan(&idStr, &userIDStr, &vaultIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey,
		&cert.CreatedAt, &cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &caCertIDStr,
		&cert.Enabled, &cert.NotBefore, &cert.DeletedAt, &cert.PurgeProtection); err != nil {
		return cert, err
	}

	var err error
	if cert.ID, err = uuid.Parse(idStr); err != nil {
		return cert, fmt.Errorf("failed to parse certificate ID: %w", err)
	}
	if cert.UserID, err = uuid.Parse(userIDStr); err != nil {
		return cert, fmt.Errorf("failed to parse user ID: %w", err)
	}
	if cert.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return cert, fmt.Errorf("failed to parse vault ID: %w", err)
	}
	if keyIDStr.Valid && keyIDStr.String != "" {
		if cert.KeyID, err = uuid.Parse(keyIDStr.String); err != nil {
			return cert, fmt.Errorf("failed to parse key ID: %w", err)
		}
	}
	// A NULL or empty ca_cert_id means self-signed, which stays nil rather
	// than becoming a zero UUID that later reads as a real CA.
	if caCertIDStr.Valid && caCertIDStr.String != "" {
		caCertID, parseErr := uuid.Parse(caCertIDStr.String)
		if parseErr != nil {
			return cert, fmt.Errorf("failed to parse CA certificate ID: %w", parseErr)
		}
		cert.CACertID = &caCertID
	}
	return cert, nil
}

// Read retrieves a certificate by ID, authorized by scope.
func (r *CertificateRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	query := "SELECT " + certificateColumns + " FROM certificates WHERE id = ? AND " + predicate + " AND deleted_at IS NULL"
	queryArgs := append([]any{id.String()}, args...)

	cert, err := scanCertificateRow(r.db.QueryRowContext(ctx, query, queryArgs...).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		if scope.Kind() == model.ScopeAdmin {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, fmt.Errorf("certificate not found or access denied")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate: %w", err)
	}

	tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
	cert.Tags, err = tagRepo.GetTags(ctx, cert.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}
	return &cert, nil
}

// Update updates a certificate, authorized by scope. The predicate is
// built from the scope argument, never from the entity.
//
// This method does not emit audit rows: audit attribution belongs to the
// caller (service layer), which knows the acting principal from the request.
// UpdateCertificate already logs its own audit row after calling this,
// for every error path and on success — logging here too would duplicate
// every scoped update into two audit_logs rows.
func (r *CertificateRepository) Update(ctx context.Context, cert *model.Certificate, scope model.Scope) error {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return err
	}

	return r.executeWithMetrics("update_certificate_scoped", func() error {
		tx, txErr := r.db.BeginTx(ctx, nil)
		if txErr != nil {
			return fmt.Errorf("failed to begin transaction: %w", txErr)
		}
		defer tx.Rollback() //nolint:errcheck

		// ca_cert_id is deliberately absent: the CA link is set at creation and
		// immutable afterwards. Renewal writes through this method, so touching
		// the column here would erase the issuer on the first renewal (B37).
		query := "UPDATE certificates SET name = ?, certificate = ?, private_key = ?, created_at = ?, expires_at = ?, auto_renew = ?, renewal_days = ?, enabled = ?, not_before = ? WHERE id = ? AND " + predicate
		execArgs := append([]any{
			cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt, cert.ExpiresAt,
			cert.AutoRenew, cert.RenewalDays, cert.Enabled, cert.NotBefore, cert.ID.String(),
		}, args...)

		result, execErr := tx.ExecContext(ctx, query, execArgs...)
		if execErr != nil {
			return fmt.Errorf("failed to update certificate: %w", execErr)
		}

		rowsAffected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("failed to get rows affected: %w", rowsErr)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("certificate not found")
		}

		// Replace the tag set inside the outer transaction. The inserts run on
		// tx directly, the way Create's tag insertion already does, rather than
		// through a TagRepository built on r.db: that would open a second
		// transaction on a separate connection while this one still holds the
		// write lock (a SQLITE_BUSY risk), and its inserts would survive a
		// rollback of the certificate row they belong to.
		if len(cert.Tags) > 0 {
			if _, delErr := tx.ExecContext(ctx, "DELETE FROM certificate_tags WHERE certificate_id = ?", cert.ID.String()); delErr != nil {
				return fmt.Errorf("failed to delete existing tags: %w", delErr)
			}
			for _, tag := range cert.Tags {
				if _, tagErr := tx.ExecContext(ctx,
					"INSERT INTO certificate_tags (certificate_id, tag) VALUES (?, ?)",
					cert.ID.String(), tag,
				); tagErr != nil {
					return fmt.Errorf("failed to add tags: %w", tagErr)
				}
			}
		}

		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("failed to commit transaction: %w", commitErr)
		}

		logrus.WithFields(logrus.Fields{
			"certificate_id": cert.ID.String(),
			"scope":          scope.String(),
		}).Debug("Certificate updated successfully")
		return nil
	})
}

// List lists certificates authorized by scope and narrowed by filter.
func (r *CertificateRepository) List(ctx context.Context, scope model.Scope, filter CertificateFilter) ([]model.Certificate, error) {
	predicate, args, err := scopePredicate(scope)
	if err != nil {
		return nil, err
	}

	conditions := []string{predicate}
	switch {
	case filter.OnlyDeleted:
		conditions = append(conditions, "deleted_at IS NOT NULL")
	case filter.IncludeDeleted:
		// No deleted_at constraint.
	default:
		conditions = append(conditions, "deleted_at IS NULL")
	}

	if len(filter.Tags) > 0 {
		placeholders := strings.Repeat(",?", len(filter.Tags))[1:]
		conditions = append(conditions, fmt.Sprintf("id IN (SELECT certificate_id FROM certificate_tags WHERE tag IN (%s))", placeholders))
		for _, tag := range filter.Tags {
			args = append(args, tag)
		}
	}

	query := "SELECT " + certificateColumns + " FROM certificates WHERE " +
		strings.Join(conditions, " AND ") + " ORDER BY created_at DESC"

	var certList []model.Certificate
	err = r.executeWithMetrics("list_certificates_scoped", func() error {
		rows, queryErr := r.db.QueryContext(ctx, query, args...)
		if queryErr != nil {
			return fmt.Errorf("failed to query certificates: %w", queryErr)
		}
		defer rows.Close() //nolint:errcheck

		tagRepo := db.NewTagRepository[model.Certificate](r.db, "certificate_tags", "certificate_id")
		certList = make([]model.Certificate, 0, 50)
		for rows.Next() {
			cert, scanErr := scanCertificateRow(rows.Scan)
			if scanErr != nil {
				return fmt.Errorf("failed to scan certificate: %w", scanErr)
			}
			cert.Tags, scanErr = tagRepo.GetTags(ctx, cert.ID)
			if scanErr != nil {
				return fmt.Errorf("failed to read tags for certificate: %w", scanErr)
			}
			certList = append(certList, cert)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return fmt.Errorf("row iteration error: %w", rowsErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	logrus.WithField("count", len(certList)).Debug("Certificates listed successfully")
	return certList, nil
}

// CertificateRepository implements CertificateRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like X.509 generation or encryption.
// All crypto operations (encryption, certificate generation) are handled by the service layer.
type CertificateRepository struct {
	db  db.DB
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
func NewCertificateRepository(db db.DB, log *logging.Logger) CertificateRepositoryInterface {
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
		defer tx.Rollback() //nolint:errcheck

		if err := r.insertCertAndTags(ctx, tx, cert); err != nil {
			return err
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

// CreateTx is Create's Tx-scoped variant. Unlike Create, it does not open
// its own transaction: ex is expected to already be a transaction the
// caller (ItemBackupService, for an atomic restore, F3) owns and will
// commit or roll back.
func (r *CertificateRepository) CreateTx(ctx context.Context, ex db.DBTX, cert *model.Certificate) error {
	return r.executeWithMetrics("create_certificate", func() error {
		if err := r.insertCertAndTags(ctx, ex, cert); err != nil {
			return err
		}
		r.log.LogAuditInfo(cert.UserID.String(), "create_certificate", "success", fmt.Sprintf("Certificate created: %s", cert.Name))
		return nil
	})
}

// insertCertAndTags issues the certificate row insert and its tag inserts
// against ex. Shared by Create (ex is a transaction it began and owns) and
// CreateTx (ex is a transaction an outer caller began and owns).
func (r *CertificateRepository) insertCertAndTags(ctx context.Context, ex db.DBTX, cert *model.Certificate) error {
	// ca_cert_id is NULL for a self-signed certificate.
	var caCertID any
	if cert.CACertID != nil {
		caCertID = cert.CACertID.String()
	}

	// Insert certificate with pre-encrypted private key and renewal metadata.
	_, err := ex.ExecContext(
		ctx,
		"INSERT INTO certificates (id, user_id, vault_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		cert.ID.String(), cert.UserID.String(), cert.VaultID.String(), cert.Name, cert.Certificate, cert.PrivateKey, cert.CreatedAt,
		cert.ExpiresAt, cert.AutoRenew, cert.RenewalDays, cert.KeyID.String(), caCertID, cert.Enabled, cert.NotBefore,
	)
	if err != nil {
		r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", "Failed to insert certificate", err)
		return fmt.Errorf("failed to insert certificate: %w", err)
	}

	// Insert tags if provided (using the same transaction to avoid locks).
	for _, tag := range cert.Tags {
		_, err := ex.ExecContext(ctx,
			"INSERT INTO certificate_tags (certificate_id, tag) VALUES (?, ?)",
			cert.ID.String(), tag,
		)
		if err != nil {
			r.log.LogAuditError(cert.UserID.String(), "create_certificate", "failed", fmt.Sprintf("Failed to insert tag %s", tag), err)
			return fmt.Errorf("failed to insert tag %s: %w", tag, err)
		}
	}
	return nil
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
		defer tx.Rollback() //nolint:errcheck

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
		cert, err := r.Read(ctx, id, model.NewAdminScope(uuid.Nil))
		if err != nil {
			return fmt.Errorf("failed to read certificate: %w", err)
		}

		_, err = r.db.ExecContext(
			ctx,
			"INSERT INTO crl (id, user_id, serial_number, name, revoked_at) VALUES (?, ?, ?, ?, ?)",
			uuid.New().String(), cert.UserID.String(), serialNumber, name, time.Now(),
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
		defer rows.Close() //nolint:errcheck

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
			return ErrCertPurgeProtected
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
	return r.setPurgeProtection(ctx, r.db, id, enabled)
}

// SetPurgeProtectionTx is SetPurgeProtection's Tx-scoped variant. See
// CreateTx.
func (r *CertificateRepository) SetPurgeProtectionTx(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error {
	return r.setPurgeProtection(ctx, ex, id, enabled)
}

func (r *CertificateRepository) setPurgeProtection(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error {
	return r.executeWithMetrics("set_purge_protection_certificate", func() error {
		result, err := ex.ExecContext(ctx,
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
			"SELECT id, user_id, name, certificate, private_key, created_at, expires_at, auto_renew, renewal_days, key_id, ca_cert_id, enabled, not_before FROM certificates WHERE deleted_at IS NULL")
		if err != nil {
			return fmt.Errorf("failed to list all certificates: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			var cert model.Certificate
			var idStr, userIDStr string
			var keyIDStr, caCertIDStr sql.NullString
			if err := rows.Scan(&idStr, &userIDStr, &cert.Name, &cert.Certificate, &cert.PrivateKey, &cert.CreatedAt,
				&cert.ExpiresAt, &cert.AutoRenew, &cert.RenewalDays, &keyIDStr, &caCertIDStr, &cert.Enabled, &cert.NotBefore); err != nil {
				return fmt.Errorf("failed to scan certificate row: %w", err)
			}
			cert.ID = uuid.MustParse(idStr)
			cert.UserID = uuid.MustParse(userIDStr)
			if keyIDStr.Valid {
				cert.KeyID = uuid.MustParse(keyIDStr.String)
			}
			// The renewal scheduler branches on this, so it must survive the
			// listing read too.
			if caCertIDStr.Valid && caCertIDStr.String != "" {
				caCertID, parseErr := uuid.Parse(caCertIDStr.String)
				if parseErr != nil {
					return fmt.Errorf("failed to parse CA certificate ID: %w", parseErr)
				}
				cert.CACertID = &caCertID
			}
			certs = append(certs, cert)
		}

		return rows.Err()
	})

	return certs, err
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
		return r.softDeleteVaultContents(ctx, r.db, vaultID, deletedAt)
	})
}

// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
func (r *CertificateRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("soft_delete_vault_certificates", func() error {
		return r.softDeleteVaultContents(ctx, ex, vaultID, deletedAt)
	})
}

func (r *CertificateRepository) softDeleteVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Soft deleting all certificates in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE certificates SET deleted_at = ? WHERE vault_id = ? AND deleted_at IS NULL",
		deletedAt, vaultID.String())
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "soft_delete_vault_certificates", "failed", "Failed to soft delete vault certificates", err)
		return fmt.Errorf("failed to soft delete vault certificates: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "soft_delete_vault_certificates", "success", "Vault certificates soft deleted successfully")
	return nil
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
		return r.recoverVaultContents(ctx, r.db, vaultID, deletedAt)
	})
}

// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
func (r *CertificateRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.executeWithMetrics("recover_vault_certificates", func() error {
		return r.recoverVaultContents(ctx, ex, vaultID, deletedAt)
	})
}

func (r *CertificateRepository) recoverVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	logrus.WithField("vault_id", vaultID.String()).Debug("Recovering cascade soft-deleted certificates in vault")

	_, err := ex.ExecContext(ctx,
		"UPDATE certificates SET deleted_at = NULL, scheduled_purge_at = NULL WHERE vault_id = ? AND deleted_at = ?",
		vaultID.String(), deletedAt)
	if err != nil {
		r.log.LogAuditError(vaultID.String(), "recover_vault_certificates", "failed", "Failed to recover vault certificates", err)
		return fmt.Errorf("failed to recover vault certificates: %w", err)
	}

	r.log.LogAuditInfo(vaultID.String(), "recover_vault_certificates", "success", "Vault certificates recovered successfully")
	return nil
}

// PurgeVaultContents permanently deletes every certificate in a vault,
// regardless of soft-delete state. certificates.vault_id carries no foreign
// key to vaults(id) (unlike role_assignments.vault_id, which cascades), so
// without this call a vault purge would strand every certificate it ever
// contained as an orphaned row, unreachable through any route and never
// swept by the soft-delete purge scheduler (which only purges
// individually-deleted items, not vault orphans). Mirrors the unconditional
// DELETE the vault service already issues for access_policies on purge, for
// the same reason.
func (r *CertificateRepository) PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	return r.executeWithMetrics("purge_vault_certificates", func() error {
		logrus.WithField("vault_id", vaultID.String()).Debug("Purging all certificates in vault")

		_, err := r.db.ExecContext(ctx, "DELETE FROM certificates WHERE vault_id = ?", vaultID.String())
		if err != nil {
			r.log.LogAuditError(vaultID.String(), "purge_vault_certificates", "failed", "Failed to purge vault certificates", err)
			return fmt.Errorf("failed to purge vault certificates: %w", err)
		}

		r.log.LogAuditInfo(vaultID.String(), "purge_vault_certificates", "success", "Vault certificates purged successfully")
		return nil
	})
}

// HasProtectedContent reports whether any certificate in the vault, active
// or soft-deleted, has purge_protection enabled. Consumed by the vault
// service's cascade purge-protection check (see vaults.CascadeRepository) so
// purging a vault can't bypass an individual certificate's own protection.
func (r *CertificateRepository) HasProtectedContent(ctx context.Context, vaultID uuid.UUID) (bool, error) {
	var exists bool
	err := r.executeWithMetrics("has_protected_content_certificates", func() error {
		return r.db.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM certificates WHERE vault_id = ? AND purge_protection = TRUE)",
			vaultID.String()).Scan(&exists)
	})
	if err != nil {
		return false, fmt.Errorf("failed to check certificate purge protection: %w", err)
	}
	return exists, nil
}
