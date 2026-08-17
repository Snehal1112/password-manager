package repositories

import (
	"context"
	"database/sql"

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
			 expiry_days, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key_id) DO UPDATE SET
			rotate_after_days         = excluded.rotate_after_days,
			notify_before_expiry_days = excluded.notify_before_expiry_days,
			expiry_days               = excluded.expiry_days,
			enabled                   = excluded.enabled,
			updated_at                = excluded.updated_at`,
		p.ID.String(), p.KeyID.String(), p.UserID.String(), p.VaultID.String(),
		p.RotateAfterDays, p.NotifyBeforeExpiryDays, p.ExpiryDays, p.Enabled,
		p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetByKeyID retrieves the policy for a key, scoped to a vault.
func (r *KeyRotationPolicyRepository) GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	query := `
		SELECT id, key_id, user_id, vault_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, created_at, updated_at
		FROM key_rotation_policies WHERE key_id = ?
	`
	return ScopedGet(ctx, r.db, query, []any{keyID.String()}, scope, scanKeyRotationPolicyRow)
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
	if err := row.Scan(&idStr, &keyIDStr, &userIDStr, &vaultIDStr,
		&p.RotateAfterDays, &p.NotifyBeforeExpiryDays, &p.ExpiryDays, &p.Enabled,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
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
	return &p, nil
}
