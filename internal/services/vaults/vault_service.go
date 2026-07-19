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

// CascadeRepository soft-deletes or recovers all resources belonging to a vault.
type CascadeRepository interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	// SoftDeleteVaultContentsTx is SoftDeleteVaultContents scoped to an explicit executor.
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	// RecoverVaultContentsTx is RecoverVaultContents scoped to an explicit executor.
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
}

// PolicyCleaner removes access policies scoped to a vault (used on purge).
type PolicyCleaner interface {
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
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
	SetTxBeginner(tb TxBeginner)
}

type vaultService struct {
	repo       repositories.VaultRepositoryInterface
	cascade    CascadeRepository
	policies   PolicyCleaner
	txBeginner TxBeginner
	log        *logging.Logger
}

// NewVaultService constructs a VaultService backed by the given repository and cascade handler.
func NewVaultService(repo repositories.VaultRepositoryInterface, cascade CascadeRepository, log *logging.Logger) VaultService {
	return &vaultService{repo: repo, cascade: cascade, log: log}
}

// SetPolicyCleaner attaches an optional cleaner that removes vault-scoped access policies on purge.
func (s *vaultService) SetPolicyCleaner(p PolicyCleaner) { s.policies = p }

// SetTxBeginner attaches an optional transaction beginner. When set,
// DeleteVault/RecoverVault run their cascade atomically inside one
// transaction; when unset, they run the pre-existing non-transactional
// sequence.
func (s *vaultService) SetTxBeginner(tb TxBeginner) { s.txBeginner = tb }

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
	v, err := s.repo.ReadByName(ctx, name)
	if err != nil {
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("vault %q: %w", name, ErrVaultNotFound)
		}
		return nil, fmt.Errorf("get vault %q: %w", name, err)
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

	if s.log != nil {
		s.log.LogAuditInfo("", "recover_vault", "success", fmt.Sprintf("Vault recovered: %s", name))
	}
	return nil
}

// PurgeVault permanently removes a vault, refusing the default and purge-protected vaults.
func (s *vaultService) PurgeVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be purged")
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
		return fmt.Errorf("vault %q is protected from purge", name)
	}
	if err := s.repo.Purge(ctx, v.ID); err != nil {
		return err
	}
	// access_policies has no FK to vaults, so vault-scoped policy rows must be
	// removed explicitly to avoid orphaning them after the vault is purged.
	if s.policies != nil {
		if err := s.policies.DeleteByVault(ctx, v.ID); err != nil {
			return fmt.Errorf("delete vault policies: %w", err)
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
