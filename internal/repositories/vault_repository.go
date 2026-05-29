package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// VaultRepositoryInterface defines pure CRUD data access for vaults.
type VaultRepositoryInterface interface {
	Create(ctx context.Context, v *model.Vault) error
	ReadByName(ctx context.Context, name string) (*model.Vault, error)
	ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error)
	List(ctx context.Context) ([]model.Vault, error)
	ListDeleted(ctx context.Context) ([]model.Vault, error)
	Update(ctx context.Context, v *model.Vault) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	Recover(ctx context.Context, id uuid.UUID) error
	Purge(ctx context.Context, id uuid.UUID) error
}

// VaultRepository implements VaultRepositoryInterface with pure CRUD operations.
type VaultRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewVaultRepository creates a new VaultRepository.
func NewVaultRepository(db *sql.DB, log *logging.Logger) VaultRepositoryInterface {
	return &VaultRepository{db: db, log: log}
}

const vaultCols = "id, name, enabled, purge_protection, retention_days, created_by, created_at, deleted_at, scheduled_purge_at"

// scanRow is satisfied by both *sql.Row and *sql.Rows.
type scanRow interface{ Scan(dest ...any) error }

func scanVault(row scanRow) (*model.Vault, error) {
	var v model.Vault
	var idStr, createdByStr string
	var deletedAt, scheduledPurgeAt sql.NullTime
	if err := row.Scan(&idStr, &v.Name, &v.Enabled, &v.PurgeProtection, &v.RetentionDays,
		&createdByStr, &v.CreatedAt, &deletedAt, &scheduledPurgeAt); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid vault id: %w", err)
	}
	v.ID = id
	createdBy, err := uuid.Parse(createdByStr)
	if err != nil {
		return nil, fmt.Errorf("invalid created_by id: %w", err)
	}
	v.CreatedBy = createdBy
	if deletedAt.Valid {
		v.DeletedAt = &deletedAt.Time
	}
	if scheduledPurgeAt.Valid {
		v.ScheduledPurgeAt = &scheduledPurgeAt.Time
	}
	return &v, nil
}

func (r *VaultRepository) Create(ctx context.Context, v *model.Vault) error {
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO vaults (id, name, enabled, purge_protection, retention_days, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		v.ID.String(), v.Name, v.Enabled, v.PurgeProtection, v.RetentionDays, v.CreatedBy.String(), v.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert vault: %w", err)
	}
	return nil
}

func (r *VaultRepository) ReadByName(ctx context.Context, name string) (*model.Vault, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT "+vaultCols+" FROM vaults WHERE name = ? AND deleted_at IS NULL", name)
	v, err := scanVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault %q not found", name)
	}
	return v, err
}

func (r *VaultRepository) ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT "+vaultCols+" FROM vaults WHERE id = ?", id.String())
	v, err := scanVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("vault %s not found", id)
	}
	return v, err
}

func (r *VaultRepository) listWhere(ctx context.Context, where string) ([]model.Vault, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+vaultCols+" FROM vaults "+where+" ORDER BY name ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}
	defer rows.Close()
	var out []model.Vault
	for rows.Next() {
		v, err := scanVault(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

func (r *VaultRepository) List(ctx context.Context) ([]model.Vault, error) {
	return r.listWhere(ctx, "WHERE deleted_at IS NULL")
}

func (r *VaultRepository) ListDeleted(ctx context.Context) ([]model.Vault, error) {
	return r.listWhere(ctx, "WHERE deleted_at IS NOT NULL")
}

func (r *VaultRepository) Update(ctx context.Context, v *model.Vault) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE vaults SET enabled = ?, purge_protection = ?, retention_days = ? WHERE id = ?",
		v.Enabled, v.PurgeProtection, v.RetentionDays, v.ID.String())
	if err != nil {
		return fmt.Errorf("failed to update vault: %w", err)
	}
	return nil
}

func (r *VaultRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE vaults SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL", time.Now(), id.String())
	if err != nil {
		return fmt.Errorf("failed to soft-delete vault: %w", err)
	}
	return nil
}

func (r *VaultRepository) Recover(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE vaults SET deleted_at = NULL, scheduled_purge_at = NULL WHERE id = ? AND deleted_at IS NOT NULL", id.String())
	if err != nil {
		return fmt.Errorf("failed to recover vault: %w", err)
	}
	return nil
}

func (r *VaultRepository) Purge(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM vaults WHERE id = ?", id.String())
	if err != nil {
		return fmt.Errorf("failed to purge vault: %w", err)
	}
	return nil
}
