// Package vaults provides the vault lifecycle service.
package vaults

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// defaultRetentionDays is the soft-delete retention applied to new vaults.
const defaultRetentionDays = 90

// ErrVaultNotFound is returned when a vault cannot be found by name.
var ErrVaultNotFound = errors.New("vault not found")

// ErrDefaultVaultProtected is returned when an operation refuses to act on
// the default vault (e.g. delete, purge).
var ErrDefaultVaultProtected = errors.New("default vault is protected from this operation")

// ErrVaultPurgeProtected is returned when PurgeVault refuses to act because
// the vault has purge protection enabled.
var ErrVaultPurgeProtected = errors.New("vault is protected from purge")

// ErrVaultContentsPurgeProtected is returned when PurgeVault refuses to act
// because a secret, key, or certificate inside the vault has its own
// purge_protection flag enabled. Without this check, purging the vault would
// bypass that item's protection entirely -- the same guarantee the item's own
// manual purge path already enforces (see internal/repositories's
// Err{Secret,Key,Cert}PurgeProtected).
var ErrVaultContentsPurgeProtected = errors.New("vault contains items protected from purge")

// CascadeRepository soft-deletes, recovers, or purges all resources belonging to a vault.
type CascadeRepository interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// PurgeVaultContents permanently deletes every secret/key/certificate row
	// belonging to a vault, active or already soft-deleted. Secrets, keys,
	// and certificates carry no foreign key on vault_id, so without this
	// call PurgeVault would strand their rows permanently, unreachable but
	// never removed.
	PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error
	// HasProtectedContent reports whether any secret, key, or certificate in
	// the vault (active or soft-deleted) has purge_protection enabled.
	// PurgeVault refuses to proceed when this is true.
	HasProtectedContent(ctx context.Context, vaultID uuid.UUID) (bool, error)
}

// PolicyCleaner removes access policies scoped to a vault (used on purge).
type PolicyCleaner interface {
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
}

// WebhookCleaner removes a vault's webhook config (used on purge). Satisfied
// by repositories.VaultWebhookRepositoryInterface.
//
// This is required, not belt-and-braces: vault_webhook_configs declares a
// FOREIGN KEY ... ON DELETE CASCADE, but SQLite's foreign_keys PRAGMA is off
// in this project, so that clause never fires there. Without this hook a
// purged vault strands a row holding an encrypted signing secret -- the same
// reason PurgeVaultContents and DeleteByVault below exist.
type WebhookCleaner interface {
	DeleteByVaultID(ctx context.Context, vaultID uuid.UUID) error
}

// SecretCacheFlusher empties the secret cache. The delete/recover cascade
// stamps deleted_at on every secret in a vault with one UPDATE, so the ids it
// touched are never enumerated and per-id eviction is not possible; a flush is
// the only correct primitive. Satisfied by *cache.SecretCache.
type SecretCacheFlusher interface {
	Flush(ctx context.Context) error
}

// VaultCacheInterface caches vault records by name. Satisfied by
// *vaultcache.Cache. Declared here (not imported from internal/vaultcache)
// to keep this package import-cycle-free, matching the existing
// SecretCacheFlusher pattern in this same file.
type VaultCacheInterface interface {
	Get(name string) (*model.Vault, bool)
	Set(name string, v *model.Vault)
	Invalidate(name string)
}

// TxBeginner begins a transaction usable by the Tx-scoped repository/cascade
// methods. Satisfied by *db.Conn. Injected via SetTxBeginner so unit tests
// that construct a vaultService without a real database (every existing test
// in this package) keep exercising the pre-existing non-transactional path.
type TxBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*db.Tx, error)
}

// txCapableVaultRepo is implemented by VaultRepositoryInterface's concrete
// type when it also supports the Tx-scoped delete/recover cascade. The
// Tx-scoped methods live only on the concrete VaultRepository struct (Task
// 6's Step 0), not on the exported VaultRepositoryInterface, so adding them
// doesn't ripple to every test double implementing that interface. A type
// assertion recovers the capability from s.repo's dynamic type -- always
// present for the real *repositories.VaultRepository, never exercised by
// test fakes (which never call SetTxBeginner, so this branch never runs
// for them).
type txCapableVaultRepo interface {
	ReadByIDTx(ctx context.Context, ex db.DBTX, id uuid.UUID) (*model.Vault, error)
	SoftDeleteTx(ctx context.Context, ex db.DBTX, id uuid.UUID) error
	RecoverTx(ctx context.Context, ex db.DBTX, id uuid.UUID) error
}

// VaultService orchestrates the vault lifecycle.
type VaultService interface {
	CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error)
	GetVault(ctx context.Context, name string) (*model.Vault, error)
	ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error)
	UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RecoverVault(ctx context.Context, name string) error
	PurgeVault(ctx context.Context, name string) error
	SetPolicyCleaner(p PolicyCleaner)
	SetWebhookCleaner(c WebhookCleaner)
	SetTxBeginner(tb TxBeginner)
	SetSecretCacheFlusher(f SecretCacheFlusher)
	SetVaultCache(c VaultCacheInterface)
}

type vaultService struct {
	repo        repositories.VaultRepositoryInterface
	cascade     CascadeRepository
	policies    PolicyCleaner
	webhooks    WebhookCleaner
	txBeginner  TxBeginner
	secretCache SecretCacheFlusher
	vaultCache  VaultCacheInterface
	log         *logging.Logger
}

// NewVaultService constructs a VaultService backed by the given repository and cascade handler.
func NewVaultService(repo repositories.VaultRepositoryInterface, cascade CascadeRepository, log *logging.Logger) VaultService {
	return &vaultService{repo: repo, cascade: cascade, log: log}
}

// SetPolicyCleaner attaches an optional cleaner that removes vault-scoped access policies on purge.
func (s *vaultService) SetPolicyCleaner(p PolicyCleaner) { s.policies = p }

// SetWebhookCleaner attaches an optional cleaner that removes a vault's
// webhook config on purge.
func (s *vaultService) SetWebhookCleaner(c WebhookCleaner) { s.webhooks = c }

// SetTxBeginner attaches an optional transaction beginner. When set,
// DeleteVault/RecoverVault run their cascade atomically inside one
// transaction; when unset, they run the pre-existing non-transactional
// sequence.
func (s *vaultService) SetTxBeginner(tb TxBeginner) { s.txBeginner = tb }

// SetSecretCacheFlusher attaches an optional secret-cache flusher. When set,
// DeleteVault and RecoverVault flush the cache after the cascade commits, so a
// secret soft-deleted (or restored) by the cascade is not still served from a
// cache entry primed before the change. Unset means caching is disabled.
func (s *vaultService) SetSecretCacheFlusher(f SecretCacheFlusher) { s.secretCache = f }

// SetVaultCache attaches an optional vault-by-name cache. When set,
// getByName consults it before the repository and populates it on a miss;
// Update/Delete/Recover/Purge invalidate the entry after a successful write.
// Unset means vault caching is disabled.
func (s *vaultService) SetVaultCache(c VaultCacheInterface) { s.vaultCache = c }

// flushSecretCache empties the secret cache after a cascade. It runs only on
// the success path (post-commit), so a rolled-back cascade never evicts, and a
// flush failure is logged rather than failing the completed operation.
func (s *vaultService) flushSecretCache(ctx context.Context, vaultID uuid.UUID, operation string) {
	if s.secretCache == nil {
		return
	}
	if err := s.secretCache.Flush(ctx); err != nil && s.log != nil {
		s.log.WithError(err).WithField("vault_id", vaultID).
			Warnf("Failed to flush secret cache after %s", operation)
	}
}

// withTx runs fn inside a transaction begun via txBeginner, committing on
// success and rolling back on error. Mirrors db.WithTx's commit/rollback
// semantics but operates on the dialect-aware db.Tx the repository layer
// uses, rather than a raw *sql.Tx.
func (s *vaultService) withTx(ctx context.Context, fn func(tx *db.Tx) error) error {
	tx, err := s.txBeginner.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %w (original: %v)", rbErr, err)
		}
		return err
	}
	return tx.Commit()
}

// CreateVault validates the request, applies defaults and overrides, and persists a new vault.
func (s *vaultService) CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error) {
	if err := model.ValidateVaultName(req.Name); err != nil {
		return nil, err
	}
	if err := model.ValidateVaultTags(req.Tags); err != nil {
		return nil, err
	}

	v := &model.Vault{
		ID:            uuid.New(),
		Name:          req.Name,
		Enabled:       true,
		RetentionDays: defaultRetentionDays,
		Tags:          req.Tags,
		CreatedBy:     createdBy,
		CreatedAt:     time.Now(),
	}
	if req.Enabled != nil {
		v.Enabled = *req.Enabled
	}
	if req.PurgeProtection != nil {
		v.PurgeProtection = *req.PurgeProtection
	}
	if req.RetentionDays != nil {
		v.RetentionDays = *req.RetentionDays
	}

	if err := s.repo.Create(ctx, v); err != nil {
		return nil, fmt.Errorf("create vault: %w", err)
	}
	if s.log != nil {
		s.log.LogAuditInfo(createdBy.String(), "create_vault", "success", fmt.Sprintf("Vault created: %s", v.Name))
	}
	return v, nil
}

// getByName reads a vault by name, normalizing a genuine not-found into
// ErrVaultNotFound while propagating any other repository error (e.g. a DB
// outage) unchanged, so callers can tell "vault doesn't exist" (404) apart
// from "the lookup itself failed" (500).
func (s *vaultService) getByName(ctx context.Context, name string) (*model.Vault, error) {
	if s.vaultCache != nil {
		if v, ok := s.vaultCache.Get(name); ok {
			return v, nil
		}
	}
	v, err := s.repo.ReadByName(ctx, name)
	if err != nil {
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("vault %q: %w", name, ErrVaultNotFound)
		}
		return nil, fmt.Errorf("get vault %q: %w", name, err)
	}
	if s.vaultCache != nil {
		s.vaultCache.Set(name, v)
	}
	return v, nil
}

// GetVault returns an active vault by name.
func (s *vaultService) GetVault(ctx context.Context, name string) (*model.Vault, error) {
	return s.getByName(ctx, name)
}

// ListVaults returns active vaults, optionally including soft-deleted ones.
func (s *vaultService) ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error) {
	vaults, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	if includeDeleted {
		deleted, err := s.repo.ListDeleted(ctx)
		if err != nil {
			return nil, err
		}
		vaults = append(vaults, deleted...)
	}
	return vaults, nil
}

// UpdateVault applies the non-nil request overrides to an active vault and persists it.
func (s *vaultService) UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest, updatedBy uuid.UUID) (*model.Vault, error) {
	v, err := s.getByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		v.Enabled = *req.Enabled
	}
	if req.PurgeProtection != nil {
		v.PurgeProtection = *req.PurgeProtection
	}
	if req.RetentionDays != nil {
		v.RetentionDays = *req.RetentionDays
	}
	if req.Tags != nil {
		if err := model.ValidateVaultTags(*req.Tags); err != nil {
			return nil, err
		}
		v.Tags = *req.Tags
	}
	if updatedBy != uuid.Nil {
		v.UpdatedBy = &updatedBy
	}
	if err := s.repo.Update(ctx, v); err != nil {
		return nil, fmt.Errorf("update vault: %w", err)
	}
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}
	if s.log != nil {
		s.log.LogAuditInfo(updatedBy.String(), "update_vault", "success", fmt.Sprintf("Vault updated: %s", v.Name))
	}
	return v, nil
}

// DeleteVault soft-deletes a vault and cascades the soft-delete to its contents.
func (s *vaultService) DeleteVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be deleted: %w", ErrDefaultVaultProtected)
	}
	v, err := s.getByName(ctx, name)
	if err != nil {
		return err
	}

	if s.txBeginner == nil {
		// No transaction support configured (e.g. unit tests against fakes);
		// fall back to the pre-existing non-transactional sequence.
		if err := s.repo.SoftDelete(ctx, v.ID); err != nil {
			return err
		}
		deleted, err := s.repo.ReadByID(ctx, v.ID)
		if err != nil {
			return fmt.Errorf("read vault after soft-delete: %w", err)
		}
		if deleted.DeletedAt == nil {
			return fmt.Errorf("vault %q missing deleted_at after soft-delete", name)
		}
		if err := s.cascade.SoftDeleteVaultContents(ctx, v.ID, *deleted.DeletedAt); err != nil {
			return fmt.Errorf("cascade soft-delete vault contents: %w", err)
		}
	} else {
		txRepo, ok := s.repo.(txCapableVaultRepo)
		if !ok {
			return fmt.Errorf("vault repository %T does not support transactional operations", s.repo)
		}
		// Soft-delete the vault row and cascade its contents atomically: if the
		// cascade fails partway, the whole transaction rolls back and the vault
		// row itself is never left soft-deleted without its contents following.
		if err := s.withTx(ctx, func(tx *db.Tx) error {
			if err := txRepo.SoftDeleteTx(ctx, tx, v.ID); err != nil {
				return err
			}
			deleted, err := txRepo.ReadByIDTx(ctx, tx, v.ID)
			if err != nil {
				return fmt.Errorf("read vault after soft-delete: %w", err)
			}
			if deleted.DeletedAt == nil {
				return fmt.Errorf("vault %q missing deleted_at after soft-delete", name)
			}
			if err := s.cascade.SoftDeleteVaultContentsTx(ctx, tx, v.ID, *deleted.DeletedAt); err != nil {
				return fmt.Errorf("cascade soft-delete vault contents: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	// The cascade soft-deleted this vault's secrets with a bulk UPDATE that
	// never went through CachedSecretService, so evict what it invalidated.
	s.flushSecretCache(ctx, v.ID, "vault delete")
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}

	if s.log != nil {
		s.log.LogAuditInfo("", "delete_vault", "success", fmt.Sprintf("Vault deleted: %s", name))
	}
	return nil
}

// RecoverVault restores a soft-deleted vault and cascades the recovery to its contents.
func (s *vaultService) RecoverVault(ctx context.Context, name string) error {
	v, err := s.findDeleted(ctx, name)
	if err != nil {
		return err
	}
	if v.DeletedAt == nil {
		return fmt.Errorf("vault %q missing deleted_at", name)
	}
	// Capture the vault's deletion timestamp before recovery clears it. The cascade
	// restores only the contents stamped with this exact timestamp, leaving rows the
	// user deleted individually (different deleted_at) untouched.
	deletedAt := *v.DeletedAt

	if s.txBeginner == nil {
		if err := s.repo.Recover(ctx, v.ID); err != nil {
			return fmt.Errorf("recover vault: %w", err)
		}
		if err := s.cascade.RecoverVaultContents(ctx, v.ID, deletedAt); err != nil {
			return fmt.Errorf("cascade recover vault contents: %w", err)
		}
	} else {
		txRepo, ok := s.repo.(txCapableVaultRepo)
		if !ok {
			return fmt.Errorf("vault repository %T does not support transactional operations", s.repo)
		}
		if err := s.withTx(ctx, func(tx *db.Tx) error {
			if err := txRepo.RecoverTx(ctx, tx, v.ID); err != nil {
				return fmt.Errorf("recover vault: %w", err)
			}
			if err := s.cascade.RecoverVaultContentsTx(ctx, tx, v.ID, deletedAt); err != nil {
				return fmt.Errorf("cascade recover vault contents: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	// The cascade cleared deleted_at on this vault's secrets outside the cache
	// layer; flush so no entry admitted during the deleted window survives.
	s.flushSecretCache(ctx, v.ID, "vault recover")
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}

	if s.log != nil {
		s.log.LogAuditInfo("", "recover_vault", "success", fmt.Sprintf("Vault recovered: %s", name))
	}
	return nil
}

// PurgeVault permanently removes a vault, refusing the default and purge-protected vaults.
func (s *vaultService) PurgeVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be purged: %w", ErrDefaultVaultProtected)
	}

	// Normally a vault is purged after a soft-delete, so check there first.
	v, err := s.findDeleted(ctx, name)
	if err != nil {
		if !errors.Is(err, ErrVaultNotFound) {
			// findDeleted failed for a reason other than "no match" (e.g. the
			// underlying ListDeleted call hit a DB error) -- don't mask it by
			// falling through to a second lookup.
			return err
		}
		// Fall back to an active vault when no soft-deleted match exists.
		v, err = s.getByName(ctx, name)
		if err != nil {
			return err
		}
	}
	if v.PurgeProtection {
		return fmt.Errorf("vault %q is protected from purge: %w", name, ErrVaultPurgeProtected)
	}
	// Fail closed: if the check itself errors, refuse the purge rather than
	// risk bypassing an item's own protection because its status couldn't be
	// read (same posture as the vault-level PurgeProtection read).
	protected, err := s.cascade.HasProtectedContent(ctx, v.ID)
	if err != nil {
		return fmt.Errorf("check vault %q contents for purge protection: %w", name, err)
	}
	if protected {
		return fmt.Errorf("vault %q contains items protected from purge: %w", name, ErrVaultContentsPurgeProtected)
	}
	if err := s.repo.Purge(ctx, v.ID); err != nil {
		return err
	}
	if s.vaultCache != nil {
		s.vaultCache.Invalidate(name)
	}
	// Secrets, keys, and certificates have no FK on vault_id either -- purge
	// their rows explicitly for the same reason access_policies' are purged
	// below, or they'd be stranded permanently, unreachable but never removed.
	if err := s.cascade.PurgeVaultContents(ctx, v.ID); err != nil {
		return fmt.Errorf("purge vault contents: %w", err)
	}
	// access_policies has no FK to vaults, so vault-scoped policy rows must be
	// removed explicitly to avoid orphaning them after the vault is purged.
	if s.policies != nil {
		if err := s.policies.DeleteByVault(ctx, v.ID); err != nil {
			return fmt.Errorf("delete vault policies: %w", err)
		}
	}
	// vault_webhook_configs' ON DELETE CASCADE is inert on SQLite (the
	// foreign_keys PRAGMA is off here), so the row must be removed explicitly
	// or it strands an encrypted signing secret for a vault that no longer
	// exists.
	if s.webhooks != nil {
		if err := s.webhooks.DeleteByVaultID(ctx, v.ID); err != nil {
			return fmt.Errorf("purge vault webhook config: %w", err)
		}
	}
	if s.log != nil {
		s.log.LogAuditInfo("", "purge_vault", "success", fmt.Sprintf("Vault purged: %s", name))
	}
	return nil
}

// findDeleted returns the soft-deleted vault with the given name, or an error if none exists.
func (s *vaultService) findDeleted(ctx context.Context, name string) (*model.Vault, error) {
	deleted, err := s.repo.ListDeleted(ctx)
	if err != nil {
		return nil, err
	}
	for i := range deleted {
		if deleted[i].Name == name {
			return &deleted[i], nil
		}
	}
	return nil, fmt.Errorf("vault %q: %w", name, ErrVaultNotFound)
}
