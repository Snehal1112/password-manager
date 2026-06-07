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

// RoleAssignmentRepositoryInterface is the data-access contract for role assignments.
type RoleAssignmentRepositoryInterface interface {
	Create(ctx context.Context, ra *model.RoleAssignment) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.RoleAssignment, error)
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
	FindByTuple(ctx context.Context, principalID uuid.UUID, role string, vaultID uuid.UUID) (*model.RoleAssignment, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type roleAssignmentRepository struct {
	db db.DB
}

// NewRoleAssignmentRepository creates a RoleAssignmentRepository.
func NewRoleAssignmentRepository(db db.DB) RoleAssignmentRepositoryInterface {
	return &roleAssignmentRepository{db: db}
}

func (r *roleAssignmentRepository) Create(ctx context.Context, ra *model.RoleAssignment) error {
	if ra.CreatedAt.IsZero() {
		ra.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO role_assignments (id, principal_id, principal_type, role, vault_id, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ra.ID.String(), ra.PrincipalID.String(), string(ra.PrincipalType),
		ra.Role, ra.VaultID.String(), ra.CreatedBy.String(), ra.CreatedAt)
	return err
}

func (r *roleAssignmentRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.RoleAssignment, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, principal_id, principal_type, role, vault_id, created_by, created_at
		 FROM role_assignments WHERE id = ?`, id.String())
	return scanRoleAssignment(row)
}

func (r *roleAssignmentRepository) ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, role, vault_id, created_by, created_at
		 FROM role_assignments WHERE vault_id = ? ORDER BY created_at DESC`, vaultID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.RoleAssignment
	for rows.Next() {
		ra, err := scanRoleAssignmentRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ra)
	}
	return out, rows.Err()
}

func (r *roleAssignmentRepository) FindByTuple(ctx context.Context, principalID uuid.UUID, role string, vaultID uuid.UUID) (*model.RoleAssignment, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, principal_id, principal_type, role, vault_id, created_by, created_at
		 FROM role_assignments WHERE principal_id = ? AND role = ? AND vault_id = ?`,
		principalID.String(), role, vaultID.String())
	ra, err := scanRoleAssignment(row)
	if err != nil {
		if err.Error() == "role assignment not found" {
			return nil, nil
		}
		return nil, err
	}
	return ra, nil
}

func (r *roleAssignmentRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM role_assignments WHERE id = ?`, id.String())
	return err
}

func scanRoleAssignment(row *sql.Row) (*model.RoleAssignment, error) {
	var ra model.RoleAssignment
	var idStr, pidStr, vidStr, cbStr string
	err := row.Scan(&idStr, &pidStr, &ra.PrincipalType, &ra.Role, &vidStr, &cbStr, &ra.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role assignment not found")
	}
	if err != nil {
		return nil, err
	}
	return parseRoleAssignmentIDs(&ra, idStr, pidStr, vidStr, cbStr)
}

func scanRoleAssignmentRows(rows *sql.Rows) (*model.RoleAssignment, error) {
	var ra model.RoleAssignment
	var idStr, pidStr, vidStr, cbStr string
	if err := rows.Scan(&idStr, &pidStr, &ra.PrincipalType, &ra.Role, &vidStr, &cbStr, &ra.CreatedAt); err != nil {
		return nil, err
	}
	return parseRoleAssignmentIDs(&ra, idStr, pidStr, vidStr, cbStr)
}

func parseRoleAssignmentIDs(ra *model.RoleAssignment, idStr, pidStr, vidStr, cbStr string) (*model.RoleAssignment, error) {
	var err error
	if ra.ID, err = uuid.Parse(idStr); err != nil {
		return nil, fmt.Errorf("invalid assignment id: %w", err)
	}
	if ra.PrincipalID, err = uuid.Parse(pidStr); err != nil {
		return nil, fmt.Errorf("invalid principal id: %w", err)
	}
	if ra.VaultID, err = uuid.Parse(vidStr); err != nil {
		return nil, fmt.Errorf("invalid vault id: %w", err)
	}
	if ra.CreatedBy, err = uuid.Parse(cbStr); err != nil {
		return nil, fmt.Errorf("invalid created_by: %w", err)
	}
	return ra, nil
}
