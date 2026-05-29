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
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID) error
}

// VaultService orchestrates the vault lifecycle.
type VaultService interface {
	CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error)
	GetVault(ctx context.Context, name string) (*model.Vault, error)
	ListVaults(ctx context.Context, includeDeleted bool) ([]model.Vault, error)
	UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest) (*model.Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RecoverVault(ctx context.Context, name string) error
	PurgeVault(ctx context.Context, name string) error
}

type vaultService struct {
	repo    repositories.VaultRepositoryInterface
	cascade CascadeRepository
	log     *logging.Logger
}

// NewVaultService constructs a VaultService backed by the given repository and cascade handler.
func NewVaultService(repo repositories.VaultRepositoryInterface, cascade CascadeRepository, log *logging.Logger) VaultService {
	return &vaultService{repo: repo, cascade: cascade, log: log}
}

// CreateVault validates the request, applies defaults and overrides, and persists a new vault.
func (s *vaultService) CreateVault(ctx context.Context, req model.CreateVaultRequest, createdBy uuid.UUID) (*model.Vault, error) {
	if err := model.ValidateVaultName(req.Name); err != nil {
		return nil, err
	}

	v := &model.Vault{
		ID:            uuid.New(),
		Name:          req.Name,
		Enabled:       true,
		RetentionDays: defaultRetentionDays,
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

// GetVault returns an active vault by name.
func (s *vaultService) GetVault(ctx context.Context, name string) (*model.Vault, error) {
	return s.repo.ReadByName(ctx, name)
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
func (s *vaultService) UpdateVault(ctx context.Context, name string, req model.UpdateVaultRequest) (*model.Vault, error) {
	v, err := s.repo.ReadByName(ctx, name)
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
	if err := s.repo.Update(ctx, v); err != nil {
		return nil, fmt.Errorf("update vault: %w", err)
	}
	if s.log != nil {
		s.log.LogAuditInfo("", "update_vault", "success", fmt.Sprintf("Vault updated: %s", v.Name))
	}
	return v, nil
}

// DeleteVault soft-deletes a vault and cascades the soft-delete to its contents.
func (s *vaultService) DeleteVault(ctx context.Context, name string) error {
	if name == model.DefaultVaultName {
		return fmt.Errorf("the default vault cannot be deleted")
	}
	v, err := s.repo.ReadByName(ctx, name)
	if err != nil {
		return err
	}
	if err := s.cascade.SoftDeleteVaultContents(ctx, v.ID); err != nil {
		return fmt.Errorf("cascade soft-delete vault contents: %w", err)
	}
	if err := s.repo.SoftDelete(ctx, v.ID); err != nil {
		return err
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
	if err := s.repo.Recover(ctx, v.ID); err != nil {
		return fmt.Errorf("recover vault: %w", err)
	}
	if err := s.cascade.RecoverVaultContents(ctx, v.ID); err != nil {
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
		// Fall back to an active vault when no soft-deleted match exists.
		v, err = s.repo.ReadByName(ctx, name)
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
