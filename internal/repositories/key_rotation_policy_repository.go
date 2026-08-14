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
	// Upsert inserts or replaces the policy for a key.
	Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error
	// GetByKeyID retrieves the policy for a given key and owner.
	GetByKeyID(ctx context.Context, keyID, userID uuid.UUID) (*model.KeyRotationPolicy, error)
	// DeleteByKeyID removes the policy for a given key and owner.
	DeleteByKeyID(ctx context.Context, keyID, userID uuid.UUID) error
	// GetByKeyIDAny retrieves the policy for a key regardless of owner.
	// Callers must independently verify the caller's access to the key
	// (e.g. vault membership) before calling this.
	GetByKeyIDAny(ctx context.Context, keyID uuid.UUID) (*model.KeyRotationPolicy, error)
	// DeleteByKeyIDAny removes the policy for a key regardless of owner.
	// Callers must independently verify the caller's access to the key
	// before calling this.
	DeleteByKeyIDAny(ctx context.Context, keyID uuid.UUID) error
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
			(id, key_id, user_id, rotate_after_days, notify_before_expiry_days,
			 expiry_days, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key_id) DO UPDATE SET
			rotate_after_days         = excluded.rotate_after_days,
			notify_before_expiry_days = excluded.notify_before_expiry_days,
			expiry_days               = excluded.expiry_days,
			enabled                   = excluded.enabled,
			updated_at                = excluded.updated_at`,
		p.ID.String(), p.KeyID.String(), p.UserID.String(),
		p.RotateAfterDays, p.NotifyBeforeExpiryDays, p.ExpiryDays, p.Enabled,
		p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetByKeyID retrieves the policy scoped to a key and its owner.
func (r *KeyRotationPolicyRepository) GetByKeyID(ctx context.Context, keyID, userID uuid.UUID) (*model.KeyRotationPolicy, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, key_id, user_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, created_at, updated_at
		FROM key_rotation_policies
		WHERE key_id = ? AND user_id = ?`,
		keyID.String(), userID.String(),
	)
	return scanKeyRotationPolicyRow(row)
}

// DeleteByKeyID removes the policy owned by userID for the given key.
// Returns sql.ErrNoRows when no matching policy exists.
func (r *KeyRotationPolicyRepository) DeleteByKeyID(ctx context.Context, keyID, userID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM key_rotation_policies WHERE key_id = ? AND user_id = ?",
		keyID.String(), userID.String(),
	)
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

// GetByKeyIDAny retrieves the policy for a key, ignoring owner. Callers are
// responsible for verifying access to the key (e.g. vault membership) before
// calling this.
func (r *KeyRotationPolicyRepository) GetByKeyIDAny(ctx context.Context, keyID uuid.UUID) (*model.KeyRotationPolicy, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, key_id, user_id, rotate_after_days, notify_before_expiry_days,
		       expiry_days, enabled, created_at, updated_at
		FROM key_rotation_policies
		WHERE key_id = ?`,
		keyID.String(),
	)
	return scanKeyRotationPolicyRow(row)
}

// DeleteByKeyIDAny removes the policy for a key, ignoring owner. Callers are
// responsible for verifying access to the key before calling this. Returns
// sql.ErrNoRows when no matching policy exists.
func (r *KeyRotationPolicyRepository) DeleteByKeyIDAny(ctx context.Context, keyID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM key_rotation_policies WHERE key_id = ?",
		keyID.String(),
	)
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
	var idStr, keyIDStr, userIDStr string
	if err := row.Scan(&idStr, &keyIDStr, &userIDStr,
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
	return &p, nil
}
