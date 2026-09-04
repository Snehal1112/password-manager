package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/model"
)

// VaultProvisioningGrantRepositoryInterface is pure data access for the
// bounded vault-creation right. Quota enforcement is a business rule and
// lives in the service layer, not here.
type VaultProvisioningGrantRepositoryInterface interface {
	Upsert(ctx context.Context, g *model.VaultProvisioningGrant) error
	GetByPrincipal(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error)
	Delete(ctx context.Context, principalID uuid.UUID) error
	List(ctx context.Context) ([]*model.VaultProvisioningGrant, error)
	// LockAndReadQuotaTx takes a row lock on the principal's grant and returns
	// its quota, scoped to the given executor so it can join a caller's
	// transaction. Declared directly on this interface -- unlike the
	// VaultRepository CreateTx/CountByCreatedBy pair, which live only on the
	// concrete type -- because this repository is new in this series and has
	// no existing test doubles that a widened interface would break.
	LockAndReadQuotaTx(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error)
}

type vaultProvisioningGrantRepository struct {
	db db.DB
}

func NewVaultProvisioningGrantRepository(database db.DB) VaultProvisioningGrantRepositoryInterface {
	return &vaultProvisioningGrantRepository{db: database}
}

const grantCols = "id, principal_id, quota, created_at, created_by"

// Upsert writes the grant, replacing any existing grant for the same
// principal. principal_id is UNIQUE, so a second grant for one principal is a
// quota change rather than an additional right.
func (r *vaultProvisioningGrantRepository) Upsert(ctx context.Context, g *model.VaultProvisioningGrant) error {
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO vault_provisioning_grants (id, principal_id, quota, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (principal_id) DO UPDATE SET quota = excluded.quota`,
		g.ID.String(), g.PrincipalID.String(), g.Quota, g.CreatedAt, g.CreatedBy.String())
	if err != nil {
		return fmt.Errorf("upsert provisioning grant: %w", err)
	}
	return nil
}

func (r *vaultProvisioningGrantRepository) GetByPrincipal(ctx context.Context, principalID uuid.UUID) (*model.VaultProvisioningGrant, error) {
	row := r.db.QueryRowContext(ctx,
		"SELECT "+grantCols+" FROM vault_provisioning_grants WHERE principal_id = ?",
		principalID.String())
	g, err := scanGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("provisioning grant for principal %s: %w", principalID, ErrNotFound)
	}
	return g, err
}

func (r *vaultProvisioningGrantRepository) Delete(ctx context.Context, principalID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM vault_provisioning_grants WHERE principal_id = ?", principalID.String())
	return err
}

func (r *vaultProvisioningGrantRepository) List(ctx context.Context) ([]*model.VaultProvisioningGrant, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT "+grantCols+" FROM vault_provisioning_grants ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []*model.VaultProvisioningGrant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// LockAndReadQuotaTx takes a row lock on the principal's grant and returns
// its quota. The no-op UPDATE is the lock: PostgreSQL takes a row lock on an
// updated row, SQLite escalates the transaction to RESERVED. Without it, two
// concurrent creates under READ COMMITTED both read the same count and both
// insert, exceeding the quota by one. This statement is load-bearing -- it is
// not a redundant write.
func (r *vaultProvisioningGrantRepository) LockAndReadQuotaTx(ctx context.Context, ex db.DBTX, principalID uuid.UUID) (int, error) {
	if _, err := ex.ExecContext(ctx,
		"UPDATE vault_provisioning_grants SET quota = quota WHERE principal_id = ?",
		principalID.String()); err != nil {
		return 0, fmt.Errorf("lock provisioning grant: %w", err)
	}
	var quota int
	err := ex.QueryRowContext(ctx,
		"SELECT quota FROM vault_provisioning_grants WHERE principal_id = ?",
		principalID.String()).Scan(&quota)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("provisioning grant for principal %s: %w", principalID, ErrNotFound)
	}
	if err != nil {
		return 0, fmt.Errorf("read provisioning quota: %w", err)
	}
	return quota, nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanGrant(s scanner) (*model.VaultProvisioningGrant, error) {
	var (
		g           model.VaultProvisioningGrant
		idStr       string
		principal   string
		createdByID string
	)
	if err := s.Scan(&idStr, &principal, &g.Quota, &g.CreatedAt, &createdByID); err != nil {
		return nil, err
	}
	var err error
	if g.ID, err = uuid.Parse(idStr); err != nil {
		return nil, fmt.Errorf("parse grant id: %w", err)
	}
	if g.PrincipalID, err = uuid.Parse(principal); err != nil {
		return nil, fmt.Errorf("parse grant principal_id: %w", err)
	}
	if g.CreatedBy, err = uuid.Parse(createdByID); err != nil {
		return nil, fmt.Errorf("parse grant created_by: %w", err)
	}
	return &g, nil
}
