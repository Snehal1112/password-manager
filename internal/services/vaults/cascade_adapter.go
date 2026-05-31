package vaults

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// vaultContentRepo is the subset of a resource repository the cascade needs.
type vaultContentRepo interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
}

// cascadeAdapter fans cascade operations out to the secret, key, and cert repos.
type cascadeAdapter struct {
	repos []vaultContentRepo
}

// NewCascadeAdapter builds a CascadeRepository over the given content repos.
func NewCascadeAdapter(repos ...vaultContentRepo) CascadeRepository {
	return &cascadeAdapter{repos: repos}
}

func (a *cascadeAdapter) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	for _, r := range a.repos {
		if err := r.SoftDeleteVaultContents(ctx, vaultID, deletedAt); err != nil {
			return err
		}
	}
	return nil
}

func (a *cascadeAdapter) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	for _, r := range a.repos {
		if err := r.RecoverVaultContents(ctx, vaultID, deletedAt); err != nil {
			return err
		}
	}
	return nil
}
