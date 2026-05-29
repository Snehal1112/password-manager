package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// AccessPolicyRepositoryInterface defines the data access contract for access policies.
type AccessPolicyRepositoryInterface interface {
	Create(ctx context.Context, policy *model.AccessPolicy) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error)
	List(ctx context.Context) ([]*model.AccessPolicy, error)
	ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error)
	// FindEffects returns all policies matching the exact (principal, resource, operation)
	// triple that are either scoped to vaultID or global (vault_id IS NULL).
	FindEffects(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) ([]*model.AccessPolicy, error)
	Update(ctx context.Context, policy *model.AccessPolicy) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type accessPolicyRepository struct {
	db *sql.DB
}

// NewAccessPolicyRepository creates a new AccessPolicyRepository.
func NewAccessPolicyRepository(db *sql.DB) AccessPolicyRepositoryInterface {
	return &accessPolicyRepository{db: db}
}

func (r *accessPolicyRepository) Create(ctx context.Context, p *model.AccessPolicy) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	var vaultArg any
	if p.VaultID != nil {
		vaultArg = p.VaultID.String()
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID.String(), p.PrincipalID.String(), string(p.PrincipalType),
		string(p.ResourceType), string(p.Operation), string(p.Effect), vaultArg, p.CreatedAt,
	)
	return err
}

func (r *accessPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, created_at
		 FROM access_policies WHERE id = ?`, id.String())
	return scanAccessPolicy(row)
}

func (r *accessPolicyRepository) List(ctx context.Context) ([]*model.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, created_at
		 FROM access_policies ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAccessPolicies(rows)
}

func (r *accessPolicyRepository) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, created_at
		 FROM access_policies WHERE principal_id = ? ORDER BY created_at DESC`, principalID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAccessPolicies(rows)
}

func (r *accessPolicyRepository) FindEffects(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) ([]*model.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, created_at
		 FROM access_policies
		 WHERE principal_id = ? AND resource_type = ? AND operation = ?
		   AND (vault_id = ? OR vault_id IS NULL)`,
		principalID.String(), string(resourceType), string(operation), vaultID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAccessPolicies(rows)
}

func (r *accessPolicyRepository) Update(ctx context.Context, p *model.AccessPolicy) error {
	var vaultArg any
	if p.VaultID != nil {
		vaultArg = p.VaultID.String()
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE access_policies SET principal_type = ?, resource_type = ?, operation = ?, effect = ?, vault_id = ?
		 WHERE id = ?`,
		string(p.PrincipalType), string(p.ResourceType), string(p.Operation), string(p.Effect), vaultArg, p.ID.String(),
	)
	return err
}

func (r *accessPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM access_policies WHERE id = ?`, id.String())
	return err
}

// scanAccessPolicy scans a single row into an AccessPolicy.
func scanAccessPolicy(row *sql.Row) (*model.AccessPolicy, error) {
	var p model.AccessPolicy
	var idStr, principalStr string
	var vaultStr sql.NullString
	err := row.Scan(&idStr, &principalStr,
		&p.PrincipalType, &p.ResourceType, &p.Operation, &p.Effect, &vaultStr, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("access policy not found")
	}
	if err != nil {
		return nil, err
	}
	p.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid policy id: %w", err)
	}
	p.PrincipalID, err = uuid.Parse(principalStr)
	if err != nil {
		return nil, fmt.Errorf("invalid principal id: %w", err)
	}
	if vaultStr.Valid && vaultStr.String != "" {
		vid, err := uuid.Parse(vaultStr.String)
		if err != nil {
			return nil, fmt.Errorf("invalid vault id: %w", err)
		}
		p.VaultID = &vid
	}
	return &p, nil
}

// scanAccessPolicies scans multiple rows into an AccessPolicy slice.
func scanAccessPolicies(rows *sql.Rows) ([]*model.AccessPolicy, error) {
	var results []*model.AccessPolicy
	for rows.Next() {
		var p model.AccessPolicy
		var idStr, principalStr string
		var vaultStr sql.NullString
		if err := rows.Scan(&idStr, &principalStr,
			&p.PrincipalType, &p.ResourceType, &p.Operation, &p.Effect, &vaultStr, &p.CreatedAt); err != nil {
			return nil, err
		}
		var err error
		p.ID, err = uuid.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("invalid policy id: %w", err)
		}
		p.PrincipalID, err = uuid.Parse(principalStr)
		if err != nil {
			return nil, fmt.Errorf("invalid principal id: %w", err)
		}
		if vaultStr.Valid && vaultStr.String != "" {
			vid, err := uuid.Parse(vaultStr.String)
			if err != nil {
				return nil, fmt.Errorf("invalid vault id: %w", err)
			}
			p.VaultID = &vid
		}
		results = append(results, &p)
	}
	return results, rows.Err()
}
