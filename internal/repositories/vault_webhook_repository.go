package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// VaultWebhookRepositoryInterface defines pure CRUD for per-vault webhook
// configuration. One row per vault, enforced by UNIQUE(vault_id).
//
// Unlike the data-plane repositories (secrets, keys, certificates, key
// rotation policies) these methods take no model.Scope: webhook config is
// vault-management-tier, authorized by CanManageVault at the API and CLI
// edges, exactly as VaultRepositoryInterface is.
type VaultWebhookRepositoryInterface interface {
	// Upsert inserts the vault's config, or replaces url, signing secret,
	// enabled and updated_at if a row already exists. The caller supplies
	// the ciphertext; this layer never encrypts or decrypts.
	Upsert(ctx context.Context, cfg *model.VaultWebhookConfig) error
	// GetByVaultID returns the vault's config, or an error wrapping
	// ErrNotFound if the vault has none. The returned config includes
	// SigningSecretEncrypted; callers building an API response must use
	// model.VaultWebhookConfig.ToResponse rather than forwarding this value.
	GetByVaultID(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error)
	// DeleteByVaultID removes the vault's config. Deleting a vault that has
	// no config is not an error -- the vault-purge cleanup hook calls this
	// unconditionally.
	DeleteByVaultID(ctx context.Context, vaultID uuid.UUID) error
}

// VaultWebhookRepository is the default database-backed implementation.
type VaultWebhookRepository struct {
	db  db.DB
	log *logging.Logger
}

// NewVaultWebhookRepository creates a new VaultWebhookRepository.
func NewVaultWebhookRepository(database db.DB, log *logging.Logger) VaultWebhookRepositoryInterface {
	return &VaultWebhookRepository{db: database, log: log}
}

// Upsert inserts a new config or replaces the existing one for the same vault.
func (r *VaultWebhookRepository) Upsert(ctx context.Context, cfg *model.VaultWebhookConfig) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO vault_webhook_configs
			(id, vault_id, url, signing_secret_encrypted, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(vault_id) DO UPDATE SET
			url                      = excluded.url,
			signing_secret_encrypted = excluded.signing_secret_encrypted,
			enabled                  = excluded.enabled,
			updated_at               = excluded.updated_at`,
		cfg.ID.String(), cfg.VaultID.String(), cfg.URL,
		cfg.SigningSecretEncrypted, cfg.Enabled, cfg.CreatedAt, cfg.UpdatedAt,
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to upsert vault webhook config")
		return fmt.Errorf("upsert vault webhook config: %w", err)
	}
	return nil
}

// GetByVaultID retrieves the vault's webhook config.
func (r *VaultWebhookRepository) GetByVaultID(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error) {
	var (
		cfg    model.VaultWebhookConfig
		idStr  string
		vidStr string
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT id, vault_id, url, signing_secret_encrypted, enabled, created_at, updated_at
		FROM vault_webhook_configs WHERE vault_id = ?`, vaultID.String(),
	).Scan(&idStr, &vidStr, &cfg.URL, &cfg.SigningSecretEncrypted,
		&cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("webhook config for vault %s: %w", vaultID, ErrNotFound)
		}
		return nil, fmt.Errorf("read vault webhook config: %w", err)
	}

	if cfg.ID, err = uuid.Parse(idStr); err != nil {
		return nil, fmt.Errorf("parse webhook config id %q: %w", idStr, err)
	}
	if cfg.VaultID, err = uuid.Parse(vidStr); err != nil {
		return nil, fmt.Errorf("parse webhook config vault_id %q: %w", vidStr, err)
	}
	return &cfg, nil
}

// DeleteByVaultID removes the vault's webhook config, if any.
func (r *VaultWebhookRepository) DeleteByVaultID(ctx context.Context, vaultID uuid.UUID) error {
	if _, err := r.db.ExecContext(ctx,
		"DELETE FROM vault_webhook_configs WHERE vault_id = ?", vaultID.String(),
	); err != nil {
		r.log.WithError(err).Error("Failed to delete vault webhook config")
		return fmt.Errorf("delete vault webhook config: %w", err)
	}
	return nil
}
