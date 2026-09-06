package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// SecretRepositoryInterface defines the interface for secret repository operations.
type SecretRepositoryInterface interface {
	Create(ctx context.Context, secret *model.Secret) error
	// Read fetches a secret authorized by scope. The scoped read is the
	// access check: a row outside the scope is indistinguishable from a row
	// that does not exist.
	Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error)
	// FindByName looks up the active (non-deleted) secret named name within
	// scope. It returns ErrNotFound, wrapped, when no such secret exists in
	// scope. ImportSecrets uses this to decide whether a record is a create
	// or an overwrite.
	FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error)
	// Update updates a secret authorized by scope. The predicate comes
	// from the scope argument, never from the entity.
	Update(ctx context.Context, secret *model.Secret, scope model.Scope) error
	// List lists secrets authorized by scope and narrowed by filter.
	List(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error)
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RecoverSecret(ctx context.Context, id uuid.UUID) error
	// SoftDeleteVaultContents soft-deletes every active secret in a vault.
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContents recovers only the secrets the cascade soft-deleted at deletedAt.
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error)
	ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error)
	GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error)
	GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error)
	GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error)
	PurgeSecret(ctx context.Context, id uuid.UUID) error
	// SetPurgeProtection enables or disables purge protection on a secret.
	SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error
}

// SecretFilter narrows a scoped secret listing. Tags is accepted for
// compatibility; tag filtering lives in TagService.
type SecretFilter struct {
	Tags           []string
	IncludeDeleted bool
	OnlyDeleted    bool
	// Limit caps the number of rows returned; 0 means unlimited.
	Limit int
	// Offset skips this many matching rows before Limit is applied. Ignored
	// when Limit is 0.
	Offset int
}

// scanSecretRow scans one secrets row in the canonical column order used by
// every scope-aware query.
func scanSecretRow(scan func(dest ...any) error) (model.Secret, error) {
	var secret model.Secret
	var idStr, userIDStr, vaultIDStr string
	var deletedAt *time.Time
	var purgeProtection bool

	if err := scan(&idStr, &userIDStr, &vaultIDStr, &secret.Name, &secret.Value, &secret.Version,
		&secret.CreatedAt, &deletedAt, &purgeProtection, &secret.ContentType, &secret.Enabled,
		&secret.ExpiresAt, &secret.NotBefore); err != nil {
		return secret, err
	}

	var err error
	if secret.ID, err = uuid.Parse(idStr); err != nil {
		return secret, fmt.Errorf("failed to parse secret ID: %w", err)
	}
	if secret.UserID, err = uuid.Parse(userIDStr); err != nil {
		return secret, fmt.Errorf("failed to parse user ID: %w", err)
	}
	if secret.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return secret, fmt.Errorf("failed to parse vault ID: %w", err)
	}

	secret.DeletedAt = deletedAt
	secret.PurgeProtection = purgeProtection
	return secret, nil
}

// secretColumns is the canonical SELECT list shared by every scoped query.
const secretColumns = "id, user_id, vault_id, name, value, version, created_at, deleted_at, purge_protection, content_type, enabled, expires_at, not_before"

// SecretRepository implements SecretRepositoryInterface with pure CRUD operations.
// It focuses solely on database interactions without business logic like encryption or versioning with performance monitoring.
type SecretRepository struct {
	db  db.DB
	log *logging.Logger
}

// crud returns the itemLifecycleConfig for secrets. A method rather than a
// constructor-set field, since tests (and possibly other code) construct
// SecretRepository via a struct literal rather than NewSecretRepository — a
// stored field would silently zero-value there, and a nil wrap panics on
// first call.
func (r *SecretRepository) crud() itemLifecycleConfig {
	return itemLifecycleConfig{
		table:              "secrets",
		item:               "secret",
		itemCap:            "Secret",
		idField:            "secret_id",
		tagTable:           "secret_tags",
		tagFK:              "secret_id",
		auditActor:         "",
		purgeErr:           ErrSecretPurgeProtected,
		notFoundIsSentinel: true,
		log:                r.log,
		wrap:               passthroughWrap,
	}
}

// executeWithMetrics wraps database operations with performance monitoring.
// See KeyRepository.executeWithMetrics for why this stays a method.
func (r *SecretRepository) executeWithMetrics(operation string, fn func() error) error {
	return withMetrics("secrets", operation, fn)
}

// NewSecretRepository creates a new SecretRepository instance.
// It provides pure database operations for secret entities.
//
// Parameters:
//
//	db: The database connection.
//	log: The logger for database operation logging.
//
// Returns:
//
//	A SecretRepositoryInterface implementation for secret database operations.
func NewSecretRepository(db db.DB, log *logging.Logger) SecretRepositoryInterface {
	return &SecretRepository{db: db, log: log}
}

// Create inserts a new secret into the database.
// It expects the secret value to be already encrypted.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secret: The secret entity to store (with encrypted value).
//
// Returns:
//
//	An error if the insertion fails.
func (r *SecretRepository) Create(ctx context.Context, secret *model.Secret) error {
	return r.create(ctx, r.db, secret)
}

// CreateTx is Create's Tx-scoped variant: it executes against ex (typically
// a *db.Tx an outer caller began and owns) instead of r.db, so it can be
// composed with other Tx-scoped writes into one atomic unit of work. Used by
// ItemBackupService.RestoreSecret for an atomic restore (F3) — a version
// insert failing partway no longer leaves a stray secret row behind.
func (r *SecretRepository) CreateTx(ctx context.Context, ex db.DBTX, secret *model.Secret) error {
	return r.create(ctx, ex, secret)
}

func (r *SecretRepository) create(ctx context.Context, ex db.DBTX, secret *model.Secret) error {
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   secret.UserID.String(),
		"name":      secret.Name,
	}).Debug("Inserting secret into database")

	// Insert the secret into the database.
	_, err := ex.ExecContext(
		ctx,
		"INSERT INTO secrets (id, user_id, vault_id, name, value, version, created_at, content_type, enabled, expires_at, not_before) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		secret.ID.String(), secret.UserID.String(), secret.VaultID.String(), secret.Name, secret.Value, secret.Version, secret.CreatedAt, secret.ContentType, secret.Enabled, secret.ExpiresAt, secret.NotBefore,
	)
	if err != nil {
		if db.SQLite.IsConstraintErr(err) {
			r.log.LogAuditError(secret.UserID.String(), "create_secret", "failed", fmt.Sprintf("Secret name already taken: %s", secret.Name), err)
			return fmt.Errorf("secret %q: %w: %w", secret.Name, ErrNameTaken, err)
		}
		r.log.LogAuditError(secret.UserID.String(), "create_secret", "failed", "Failed to insert secret", err)
		return fmt.Errorf("failed to insert secret: %w", err)
	}

	// Insert tags if provided.
	for _, tag := range secret.Tags {
		_, err = ex.ExecContext(
			ctx,
			"INSERT INTO secret_tags (secret_id, tag) VALUES (?, ?)",
			secret.ID.String(), tag,
		)
		if err != nil {
			r.log.LogAuditError(secret.UserID.String(), "create_secret", "failed", "Failed to insert tag", err)
			return fmt.Errorf("failed to insert tag: %w", err)
		}
	}

	r.log.LogAuditInfo(secret.UserID.String(), "create_secret", "success", fmt.Sprintf("Secret inserted: %s", secret.Name))
	logrus.WithFields(logrus.Fields{
		"secret_id": secret.ID.String(),
		"user_id":   secret.UserID.String(),
		"name":      secret.Name,
	}).Debug("Secret inserted successfully")

	return nil
}

// Read retrieves a secret by ID, authorized by scope. The scoped read is
// the access check: a row outside the scope is indistinguishable from a row
// that does not exist.
func (r *SecretRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	query := "SELECT " + secretColumns + " FROM secrets WHERE id = ? AND deleted_at IS NULL"
	secret, err := ScopedGet(ctx, r.db, query, []any{id.String()}, scope, func(row *sql.Row) (model.Secret, error) {
		return scanSecretRow(row.Scan)
	})
	switch {
	case errors.Is(err, ErrInvalidScope):
		return nil, err
	case errors.Is(err, sql.ErrNoRows):
		if scope.Kind() == model.ScopeAdmin {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("secret not found or access denied")
	case err != nil:
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}
	return &secret, nil
}

// FindByName looks up the active secret named name, authorized by scope. It
// mirrors Read's scoping rules exactly, keyed on name instead of id.
func (r *SecretRepository) FindByName(ctx context.Context, name string, scope model.Scope) (*model.Secret, error) {
	query := "SELECT " + secretColumns + " FROM secrets WHERE name = ? AND deleted_at IS NULL"
	secret, err := ScopedGet(ctx, r.db, query, []any{name}, scope, func(row *sql.Row) (model.Secret, error) {
		return scanSecretRow(row.Scan)
	})
	switch {
	case errors.Is(err, ErrInvalidScope):
		return nil, err
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("secret %q: %w", name, ErrNotFound)
	case err != nil:
		return nil, fmt.Errorf("failed to query secret by name: %w", err)
	}
	return &secret, nil
}

// Update updates a secret, authorized by scope. The predicate is built
// from the scope argument, never from the entity, so a caller cannot widen its
// own authorization by mutating secret.VaultID or secret.UserID.
//
// This method does not emit audit rows: audit attribution belongs to the
// caller (service layer), which knows the acting principal from the request,
// not just the scope it was handed. UpdateSecret already logs its own
// audit row after calling this, for every error path and on success — logging
// here too would duplicate every scoped update into two audit_logs rows.
func (r *SecretRepository) Update(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	return r.executeWithMetrics("update_secret_scoped", func() error {
		logrus.WithFields(logrus.Fields{
			"secret_id": secret.ID.String(),
			"scope":     scope.String(),
			"version":   secret.Version,
		}).Debug("Updating secret in database")

		query := "UPDATE secrets SET name = ?, value = ?, version = ?, content_type = ?, enabled = ?, expires_at = ?, not_before = ? WHERE id = ?"
		execArgs := []any{
			secret.Name, secret.Value, secret.Version, secret.ContentType,
			secret.Enabled, secret.ExpiresAt, secret.NotBefore, secret.ID.String(),
		}

		result, err := ScopedExec(ctx, r.db, query, execArgs, scope)
		if err != nil {
			if errors.Is(err, ErrInvalidScope) {
				return err
			}
			return fmt.Errorf("failed to update secret: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("secret not found")
		}

		logrus.WithFields(logrus.Fields{
			"secret_id": secret.ID.String(),
			"scope":     scope.String(),
			"version":   secret.Version,
		}).Debug("Secret updated successfully")
		return nil
	})
}

// List lists secrets authorized by scope and narrowed by filter. The
// soft-delete predicate is applied in SQL rather than by discarding rows in Go.
func (r *SecretRepository) List(ctx context.Context, scope model.Scope, filter SecretFilter) ([]model.Secret, error) {
	where := "1 = 1" // Base predicate ScopedList's appended "AND <scope>" attaches to when no filter condition below fires.
	switch {
	case filter.OnlyDeleted:
		where = "deleted_at IS NOT NULL"
	case filter.IncludeDeleted:
		// No deleted_at constraint.
	default:
		where = "deleted_at IS NULL"
	}

	query := "SELECT " + secretColumns + " FROM secrets WHERE " + where

	tail := " ORDER BY name ASC"
	var tailArgs []any
	if filter.Limit > 0 {
		tail += " LIMIT ? OFFSET ?"
		tailArgs = []any{filter.Limit, filter.Offset}
	}

	var secretList []model.Secret
	err := r.executeWithMetrics("list_secrets_scoped", func() error {
		var listErr error
		secretList, listErr = ScopedList(ctx, r.db, query, nil, scope, tail, tailArgs, func(rows *sql.Rows) (model.Secret, error) {
			return scanSecretRow(rows.Scan)
		})
		return listErr
	})
	if err != nil {
		if errors.Is(err, ErrInvalidScope) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to query secrets: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"scope":        scope.String(),
		"secret_count": len(secretList),
	}).Debug("Secrets listed successfully")

	return secretList, nil
}

// Delete removes a secret from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	An error if the deletion fails.
func (r *SecretRepository) Delete(ctx context.Context, id uuid.UUID) error {
	logrus.WithField("secret_id", id.String()).Debug("Deleting secret from database")

	result, err := r.db.ExecContext(ctx, "DELETE FROM secrets WHERE id = ?", id.String())
	if err != nil {
		r.log.LogAuditError("", "delete_secret", "failed", "Failed to delete secret", err)
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.log.LogAuditError("", "delete_secret", "failed", "Failed to get rows affected", err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError("", "delete_secret", "failed", "Secret not found for deletion", nil)
		return fmt.Errorf("secret not found")
	}

	r.log.LogAuditInfo("", "delete_secret", "success", "Secret deleted successfully")
	logrus.WithField("secret_id", id.String()).Debug("Secret deleted successfully")

	return nil
}

// SoftDelete marks a secret as deleted without removing it from the database.
// This implements soft delete functionality for compliance and recovery purposes.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *SecretRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return softDeleteItem(ctx, r.db, r.crud(), id)
}

// RecoverSecret restores a soft-deleted secret by clearing its deleted_at timestamp.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	An error if the secret is not found in a deleted state or the update fails.
func (r *SecretRepository) RecoverSecret(ctx context.Context, id uuid.UUID) error {
	return recoverItem(ctx, r.db, r.crud(), id)
}

// PurgeSecret permanently removes a soft-deleted secret from the database.
// This should only be called for secrets that have been soft-deleted and have purge protection disabled.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//
// Returns:
//
//	An error if the purge operation fails.
func (r *SecretRepository) PurgeSecret(ctx context.Context, id uuid.UUID) error {
	return purgeItem(ctx, r.db, r.crud(), id)
}

// SetPurgeProtection enables or disables purge protection on a secret.
// A secret with purge protection cannot be permanently deleted via PurgeSecret.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	id: The secret's unique identifier.
//	enabled: True to enable purge protection, false to disable it.
//
// Returns:
//
//	An error if the update fails.
func (r *SecretRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return r.setPurgeProtection(ctx, r.db, id, enabled)
}

// SetPurgeProtectionTx is SetPurgeProtection's Tx-scoped variant. See
// CreateTx.
func (r *SecretRepository) SetPurgeProtectionTx(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error {
	return r.setPurgeProtection(ctx, ex, id, enabled)
}

func (r *SecretRepository) setPurgeProtection(ctx context.Context, ex db.DBTX, id uuid.UUID, enabled bool) error {
	return setPurgeProtectionItem(ctx, ex, r.crud(), id, enabled)
}

// ExportSecrets is deprecated and should be moved to a dedicated export service.
func (r *SecretRepository) ExportSecrets(ctx context.Context, options model.ExportOptions) ([]byte, error) {
	return nil, fmt.Errorf("export functionality has been moved to export service")
}

// ImportSecrets is deprecated and should be moved to a dedicated import service.
func (r *SecretRepository) ImportSecrets(ctx context.Context, data []byte, options model.ImportOptions) (int, error) {
	return 0, fmt.Errorf("import functionality has been moved to import service")
}

// GetVersions is deprecated and should use the VersioningService.
func (r *SecretRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}

// GetVersion is deprecated and should use the VersioningService.
func (r *SecretRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}

// GetLatestVersion is deprecated and should use the VersioningService.
func (r *SecretRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	return nil, fmt.Errorf("versioning functionality has been moved to versioning service")
}

// SoftDeleteVaultContents marks every active secret in a vault as soft-deleted.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	vaultID: The vault whose secrets should be soft-deleted.
//	deletedAt: The exact deletion timestamp to stamp on each cascaded row.
//
// Returns:
//
//	An error if the soft deletion fails.
func (r *SecretRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.softDeleteVaultContents(ctx, r.db, vaultID, deletedAt)
}

// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
func (r *SecretRepository) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.softDeleteVaultContents(ctx, ex, vaultID, deletedAt)
}

func (r *SecretRepository) softDeleteVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return softDeleteVaultContents(ctx, ex, r.crud(), vaultID, deletedAt)
}

// RecoverVaultContents restores every soft-deleted secret in a vault.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	vaultID: The vault whose secrets should be recovered.
//	deletedAt: The cascade deletion timestamp; only rows stamped with it are restored.
//
// Returns:
//
//	An error if the recovery fails.
func (r *SecretRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.recoverVaultContents(ctx, r.db, vaultID, deletedAt)
}

// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
func (r *SecretRepository) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return r.recoverVaultContents(ctx, ex, vaultID, deletedAt)
}

func (r *SecretRepository) recoverVaultContents(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	return recoverVaultContents(ctx, ex, r.crud(), vaultID, deletedAt)
}

// PurgeVaultContents permanently deletes every secret in a vault, regardless
// of soft-delete state. secrets.vault_id carries no foreign key to vaults(id)
// (unlike role_assignments.vault_id, which cascades), so without this call a
// vault purge would strand every secret it ever contained as an orphaned row,
// unreachable through any route and never swept by the soft-delete purge
// scheduler (which only purges individually-deleted items, not vault
// orphans). Mirrors the unconditional DELETE the vault service already
// issues for access_policies on purge, for the same reason.
func (r *SecretRepository) PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	return purgeVaultContents(ctx, r.db, r.crud(), vaultID)
}

// HasProtectedContent reports whether any secret in the vault, active or
// soft-deleted, has purge_protection enabled. Consumed by the vault service's
// cascade purge-protection check (see vaults.CascadeRepository) so purging a
// vault can't bypass an individual secret's own protection.
func (r *SecretRepository) HasProtectedContent(ctx context.Context, vaultID uuid.UUID) (bool, error) {
	return hasProtectedContent(ctx, r.db, r.crud(), vaultID)
}
