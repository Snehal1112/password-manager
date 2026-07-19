// Package vaults provides the vault lifecycle service.
package vaults

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// defaultRetentionDays is the soft-delete retention applied to new vaults.
const defaultRetentionDays = 90

// ErrVaultNotFound is returned when a vault cannot be found by name.
var ErrVaultNotFound = errors.New("vault not found")

// CascadeRepository soft-deletes or recovers all resources belonging to a vault.
type CascadeRepository interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
}

// PolicyCleaner removes access policies scoped to a vault (used on purge).
type PolicyCleaner interface {
	DeleteByVault(ctx context.Context, vaultID uuid.UUID) error
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
}

type vaultService struct {
	repo     repositories.VaultRepositoryInterface
	cascade  CascadeRepository
	policies PolicyCleaner
	log      *logging.Logger
}

// NewVaultService constructs a VaultService backed by the given repository and cascade handler.
func NewVaultService(repo repositories.VaultRepositoryInterface, cascade CascadeRepository, log *logging.Logger) VaultService {
	return &vaultService{repo: repo, cascade: cascade, log: log}
}

// SetPolicyCleaner attaches an optional cleaner that removes vault-scoped access policies on purge.
func (s *vaultService) SetPolicyCleaner(p PolicyCleaner) { s.policies = p }

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
		return fmt.Errorf("the default vault cannot be deleted")
	}
	v, err := s.getByName(ctx, name)
	if err != nil {
		return err
	}
	// Soft-delete the vault row first; VaultRepository.SoftDelete stamps its own
	// timestamp. We then read that persisted deleted_at back and stamp the contents
	// with the SAME value, so recovery (which reads the vault row's DeletedAt) matches
	// exactly. This avoids resurrecting items soft-deleted before the vault was deleted.
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
	if err := s.repo.Recover(ctx, v.ID); err != nil {
		return fmt.Errorf("recover vault: %w", err)
	}
	if err := s.cascade.RecoverVaultContents(ctx, v.ID, deletedAt); err != nil {
		return fmt.Errorf("cascade recover vault contents: %w", err)
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
