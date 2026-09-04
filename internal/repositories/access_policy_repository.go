package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
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
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.AccessPolicy, error)
	Update(ctx context.Context, policy *model.AccessPolicy) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByAssignmentID(ctx context.Context, assignmentID uuid.UUID) error
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
}

type accessPolicyRepository struct {
	db db.DB
}

// NewAccessPolicyRepository creates a new AccessPolicyRepository.
func NewAccessPolicyRepository(db db.DB) AccessPolicyRepositoryInterface {
	return &accessPolicyRepository{db: db}
}

func (r *accessPolicyRepository) Create(ctx context.Context, p *model.AccessPolicy) error {
	return r.create(ctx, r.db, p)
}

// CreateTx inserts an access policy on the given executor, so the insert can
// join a caller's transaction -- used by the provisioned create path, which
// writes the vault and the creator's grants atomically.
func (r *accessPolicyRepository) CreateTx(ctx context.Context, ex db.DBTX, p *model.AccessPolicy) error {
	return r.create(ctx, ex, p)
}

func (r *accessPolicyRepository) create(ctx context.Context, ex db.DBTX, p *model.AccessPolicy) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	var vaultArg any
	if p.VaultID != nil {
		vaultArg = p.VaultID.String()
	}
	var assignArg any
	if p.AssignmentID != nil {
		assignArg = p.AssignmentID.String()
	}
	_, err := ex.ExecContext(ctx,
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID.String(), p.PrincipalID.String(), string(p.PrincipalType),
		string(p.ResourceType), string(p.Operation), string(p.Effect), vaultArg, assignArg, p.CreatedAt,
	)
	return err
}

func (r *accessPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.AccessPolicy, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at
		 FROM access_policies WHERE id = ?`, id.String())
	return scanAccessPolicy(row)
}

func (r *accessPolicyRepository) List(ctx context.Context) ([]*model.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at
		 FROM access_policies ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanAccessPolicies(rows)
}

func (r *accessPolicyRepository) ListByPrincipal(ctx context.Context, principalID uuid.UUID) ([]*model.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at
		 FROM access_policies WHERE principal_id = ? ORDER BY created_at DESC`, principalID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanAccessPolicies(rows)
}

func (r *accessPolicyRepository) FindEffects(ctx context.Context, principalID uuid.UUID, resourceType model.PolicyResourceType, operation model.PolicyOperation, vaultID uuid.UUID) ([]*model.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at
		 FROM access_policies
		 WHERE principal_id = ? AND resource_type = ? AND operation = ?
		   AND (vault_id = ? OR vault_id IS NULL)`,
		principalID.String(), string(resourceType), string(operation), vaultID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanAccessPolicies(rows)
}

func (r *accessPolicyRepository) ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.AccessPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, resource_type, operation, effect, vault_id, assignment_id, created_at
		 FROM access_policies WHERE vault_id = ? ORDER BY created_at DESC`, vaultID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
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

func (r *accessPolicyRepository) DeleteByAssignmentID(ctx context.Context, assignmentID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM access_policies WHERE assignment_id = ?`, assignmentID.String())
	return err
}

func (r *accessPolicyRepository) DeleteByVault(ctx context.Context, vaultID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM access_policies WHERE vault_id = ?`, vaultID.String())
	return err
}

// scanAccessPolicy scans a single row into an AccessPolicy.
func scanAccessPolicy(row *sql.Row) (*model.AccessPolicy, error) {
	var p model.AccessPolicy
	var idStr, principalStr string
	var vaultStr sql.NullString
	var assignStr sql.NullString
	err := row.Scan(&idStr, &principalStr,
		&p.PrincipalType, &p.ResourceType, &p.Operation, &p.Effect, &vaultStr, &assignStr, &p.CreatedAt)
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
	if assignStr.Valid && assignStr.String != "" {
		aid, err := uuid.Parse(assignStr.String)
		if err != nil {
			return nil, fmt.Errorf("invalid assignment id: %w", err)
		}
		p.AssignmentID = &aid
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
		var assignStr sql.NullString
		if err := rows.Scan(&idStr, &principalStr,
			&p.PrincipalType, &p.ResourceType, &p.Operation, &p.Effect, &vaultStr, &assignStr, &p.CreatedAt); err != nil {
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
		if assignStr.Valid && assignStr.String != "" {
			aid, err := uuid.Parse(assignStr.String)
			if err != nil {
				return nil, fmt.Errorf("invalid assignment id: %w", err)
			}
			p.AssignmentID = &aid
		}
		results = append(results, &p)
	}
	return results, rows.Err()
}
