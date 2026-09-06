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

// RoleAssignmentRepositoryInterface is the data-access contract for role assignments.
type RoleAssignmentRepositoryInterface interface {
	Create(ctx context.Context, ra *model.RoleAssignment) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.RoleAssignment, error)
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
	// ListByPrincipalInVault returns every role assignment the principal holds in
	// the given vault. It is the authorization lookup: the middleware turns the
	// returned roles into data actions. An empty result means no access.
	ListByPrincipalInVault(ctx context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
	FindByTuple(ctx context.Context, principalID uuid.UUID, role string, vaultID uuid.UUID) (*model.RoleAssignment, error)
	Delete(ctx context.Context, id uuid.UUID) error
	// DeleteByVault removes every role assignment scoped to vaultID. Called
	// when a vault is purged: role_assignments declares ON DELETE CASCADE on
	// vault_id, but SQLite runs with the foreign_keys pragma off, so that
	// cascade never fires and the rows would be stranded -- unreachable but
	// never removed.
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
}

type roleAssignmentRepository struct {
	db db.DB
}

// NewRoleAssignmentRepository creates a RoleAssignmentRepository.
func NewRoleAssignmentRepository(db db.DB) RoleAssignmentRepositoryInterface {
	return &roleAssignmentRepository{db: db}
}

func (r *roleAssignmentRepository) Create(ctx context.Context, ra *model.RoleAssignment) error {
	return r.create(ctx, r.db, ra)
}

// CreateTx inserts a role assignment on the given executor, so the insert can
// join a caller's transaction -- used by the provisioned create path, which
// writes the vault and the creator's grants atomically.
func (r *roleAssignmentRepository) CreateTx(ctx context.Context, ex db.DBTX, ra *model.RoleAssignment) error {
	return r.create(ctx, ex, ra)
}

func (r *roleAssignmentRepository) create(ctx context.Context, ex db.DBTX, ra *model.RoleAssignment) error {
	if ra.CreatedAt.IsZero() {
		ra.CreatedAt = time.Now().UTC()
	}
	_, err := ex.ExecContext(ctx,
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
	defer rows.Close() //nolint:errcheck
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

func (r *roleAssignmentRepository) ListByPrincipalInVault(ctx context.Context, principalID, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, principal_id, principal_type, role, vault_id, created_by, created_at
		 FROM role_assignments WHERE principal_id = ? AND vault_id = ?`,
		principalID.String(), vaultID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
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
		// (nil, nil) means "no such assignment", which callers treat as a
		// normal absence rather than a failure. Identified by sentinel, not by
		// message text: the previous string comparison meant rewording
		// scanRoleAssignment's message silently turned every miss into an
		// error on an authorization-adjacent path.
		if errors.Is(err, ErrNotFound) {
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

// DeleteByVault removes every role assignment scoped to vaultID. Called when
// a vault is purged: role_assignments declares ON DELETE CASCADE on vault_id,
// but SQLite runs with the foreign_keys pragma off, so that cascade never
// fires and the rows would be stranded -- unreachable but never removed.
func (r *roleAssignmentRepository) DeleteByVault(ctx context.Context, vaultID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM role_assignments WHERE vault_id = ?", vaultID.String())
	if err != nil {
		return fmt.Errorf("delete role assignments for vault %s: %w", vaultID, err)
	}
	return nil
}

func scanRoleAssignment(row *sql.Row) (*model.RoleAssignment, error) {
	var ra model.RoleAssignment
	var idStr, pidStr, vidStr, cbStr string
	err := row.Scan(&idStr, &pidStr, &ra.PrincipalType, &ra.Role, &vidStr, &cbStr, &ra.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("role assignment not found: %w", ErrNotFound)
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
