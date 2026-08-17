package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// KeyRotationPolicyRepositoryInterface defines CRUD operations for per-key
// rotation policies.
type KeyRotationPolicyRepositoryInterface interface {
	// Upsert inserts or replaces the policy for a key. policy.VaultID must be
	// the parent key's own vault — callers derive it from the key, never
	// supply it independently.
	Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error
	// GetByKeyID retrieves the policy for a key, scoped to a vault.
	GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error)
	// DeleteByKeyID removes the policy for a key, scoped to a vault.
	DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error
	// GetDuePolicies returns enabled policies (with a configured rotation
	// action) whose next_rotation_at has passed, authorized by scope. The
	// scheduler sweep always passes model.NewAdminScope.
	GetDuePolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error)
	// MarkRotated stamps last_rotated_at = at and recomputes
	// next_rotation_at = at + rotateAfterDays, after a successful automatic
	// rotation. rotateAfterDays is supplied by the caller (already available
	// from the GetDuePolicies row) so this stays a plain parameterized
	// UPDATE with no per-row SQL date arithmetic.
	MarkRotated(ctx context.Context, keyID uuid.UUID, scope model.Scope, at time.Time, rotateAfterDays int) error
}

// KeyRotationPolicyRepository is the default database-backed implementation.
type KeyRotationPolicyRepository struct {
	db  db.DB
	log *logging.Logger
}

// NewKeyRotationPolicyRepository creates a new KeyRotationPolicyRepository.
func NewKeyRotationPolicyRepository(db db.DB, log *logging.Logger) KeyRotationPolicyRepositoryInterface {
	return &KeyRotationPolicyRepository{db: db, log: log}
}

// Upsert inserts a new policy or updates the existing one for the same key_id.
func (r *KeyRotationPolicyRepository) Upsert(ctx context.Context, p *model.KeyRotationPolicy) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO key_rotation_policies
			(id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
			 expiry_days, enabled, last_rotated_at, next_rotation_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key_id) DO UPDATE SET
			rotate_after_days         = excluded.rotate_after_days,
			notify_before_expiry_days = excluded.notify_before_expiry_days,
			expiry_days               = excluded.expiry_days,
			enabled                   = excluded.enabled,
			last_rotated_at           = excluded.last_rotated_at,
			next_rotation_at          = excluded.next_rotation_at,
			updated_at                = excluded.updated_at`,
		p.ID.String(), p.KeyID.String(), p.UserID.String(), p.VaultID.String(),
		p.RotateAfterDays, p.NotifyBeforeExpiryDays, p.ExpiryDays, p.Enabled,
		p.LastRotatedAt, p.NextRotationAt, p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetByKeyID retrieves the policy for a key, scoped to a vault.
func (r *KeyRotationPolicyRepository) GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	query := `
		SELECT id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, last_rotated_at, next_rotation_at, created_at, updated_at
		FROM key_rotation_policies WHERE key_id = ?
	`
	return ScopedGet(ctx, r.db, query, []any{keyID.String()}, scope, scanKeyRotationPolicyRow)
}

// GetDuePolicies returns enabled policies with a configured rotation action
// (rotate_after_days > 0) whose next_rotation_at has passed, authorized by
// scope. The scheduler sweep always passes an admin scope (see spec section 10).
//
// The parent key must also still exist, not be soft-deleted, and not be an
// OCT (symmetric) key -- both are permanent-failure classes for RotateKey
// (a deleted key's read is filtered out; OCT keys have no rotation branch in
// RotateKey's type switch), so excluding them here keeps the sweep from
// retrying the same doomed rotation on every tick forever (see I2 in the
// final review). This is expressed as a subquery, not a JOIN, so the scope
// predicate appended by ScopedList (an unqualified "vault_id = ?" / "user_id
// = ?") stays unambiguous -- a JOIN against keys, which also has vault_id
// and user_id columns, would make that predicate ambiguous in SQL.
func (r *KeyRotationPolicyRepository) GetDuePolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	query := `
		SELECT id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, last_rotated_at, next_rotation_at, created_at, updated_at
		FROM key_rotation_policies
		WHERE enabled = TRUE AND rotate_after_days > 0 AND next_rotation_at <= ?
		  AND key_id IN (SELECT id FROM keys WHERE deleted_at IS NULL AND type != ?)
	`
	due, err := ScopedList(ctx, r.db, query, []any{time.Now().UTC(), model.KeyTypeOct}, scope, scanKeyRotationPolicyRows)
	if err != nil {
		r.log.WithError(err).Error("Failed to get due key rotation policies")
		return nil, fmt.Errorf("failed to get due key rotation policies: %w", err)
	}
	return due, nil
}

// MarkRotated stamps last_rotated_at = at and recomputes
// next_rotation_at = at + rotateAfterDays, after a successful automatic
// rotation. Returns sql.ErrNoRows if keyID has no policy within scope.
func (r *KeyRotationPolicyRepository) MarkRotated(ctx context.Context, keyID uuid.UUID, scope model.Scope, at time.Time, rotateAfterDays int) error {
	next := at.AddDate(0, 0, rotateAfterDays)
	result, err := ScopedExec(ctx, r.db,
		"UPDATE key_rotation_policies SET last_rotated_at = ?, next_rotation_at = ? WHERE key_id = ?",
		[]any{at, next, keyID.String()}, scope)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteByKeyID removes the policy for a key, scoped to a vault. Returns
// sql.ErrNoRows when no matching policy exists.
func (r *KeyRotationPolicyRepository) DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	result, err := ScopedExec(ctx, r.db, "DELETE FROM key_rotation_policies WHERE key_id = ?", []any{keyID.String()}, scope)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// scanKeyRotationPolicyRow scans one key_rotation_policies row.
func scanKeyRotationPolicyRow(row *sql.Row) (*model.KeyRotationPolicy, error) {
	var p model.KeyRotationPolicy
	var idStr, keyIDStr, userIDStr, vaultIDStr string
	var lastRotatedAt, nextRotationAt sql.NullTime
	if err := row.Scan(&idStr, &keyIDStr, &userIDStr, &vaultIDStr,
		&p.RotateAfterDays, &p.NotifyBeforeExpiryDays, &p.ExpiryDays, &p.Enabled,
		&lastRotatedAt, &nextRotationAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	var err error
	if p.ID, err = uuid.Parse(idStr); err != nil {
		return nil, err
	}
	if p.KeyID, err = uuid.Parse(keyIDStr); err != nil {
		return nil, err
	}
	if p.UserID, err = uuid.Parse(userIDStr); err != nil {
		return nil, err
	}
	if p.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return nil, err
	}
	if lastRotatedAt.Valid {
		p.LastRotatedAt = &lastRotatedAt.Time
	}
	// A NULL next_rotation_at (M3 in the final review: a mixed-binary
	// rolling upgrade could leave this NULL despite the fresh-install
	// schema's historical NOT NULL) leaves NextRotationAt at its Go zero
	// value rather than erroring the scan. That zero value naturally fails
	// GetDuePolicies' "next_rotation_at <= ?" comparison, so such a row is
	// simply never swept -- the safe default.
	if nextRotationAt.Valid {
		p.NextRotationAt = nextRotationAt.Time
	}
	return &p, nil
}

// scanKeyRotationPolicyRows scans one key_rotation_policies row from a
// *sql.Rows cursor (ScopedList's shape), mirroring scanKeyRotationPolicyRow.
func scanKeyRotationPolicyRows(rows *sql.Rows) (model.KeyRotationPolicy, error) {
	var p model.KeyRotationPolicy
	var idStr, keyIDStr, userIDStr, vaultIDStr string
	var lastRotatedAt, nextRotationAt sql.NullTime
	if err := rows.Scan(&idStr, &keyIDStr, &userIDStr, &vaultIDStr,
		&p.RotateAfterDays, &p.NotifyBeforeExpiryDays, &p.ExpiryDays, &p.Enabled,
		&lastRotatedAt, &nextRotationAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	var err error
	if p.ID, err = uuid.Parse(idStr); err != nil {
		return p, err
	}
	if p.KeyID, err = uuid.Parse(keyIDStr); err != nil {
		return p, err
	}
	if p.UserID, err = uuid.Parse(userIDStr); err != nil {
		return p, err
	}
	if p.VaultID, err = uuid.Parse(vaultIDStr); err != nil {
		return p, err
	}
	if lastRotatedAt.Valid {
		p.LastRotatedAt = &lastRotatedAt.Time
	}
	// See scanKeyRotationPolicyRow's identical comment: a NULL
	// next_rotation_at is left at its Go zero value (M3), which safely
	// excludes the row from GetDuePolicies' due comparison.
	if nextRotationAt.Valid {
		p.NextRotationAt = nextRotationAt.Time
	}
	return p, nil
}
