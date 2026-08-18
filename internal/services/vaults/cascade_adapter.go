package vaults

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
)

// vaultContentRepo is the subset of a resource repository the cascade needs.
// Deliberately unchanged by the Tx work below: this interface's production
// values arrive as SecretRepositoryInterface/KeyRepositoryInterface/
// CertificateRepositoryInterface, which are implemented by many test doubles
// across the codebase -- adding methods here would ripple to all of them.
type vaultContentRepo interface {
	SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error
}

// txCapableContentRepo is implemented by a vaultContentRepo's concrete type
// when it also supports running inside a caller-supplied transaction. The
// Tx-scoped methods live only on the concrete Secret/Key/CertificateRepository
// structs (Task 5), not on their exported *RepositoryInterface types. A type
// assertion recovers the capability from the stored interface value's dynamic
// type -- present for the real repositories, never for a plain test double
// that only implements the two non-Tx methods above.
type txCapableContentRepo interface {
	SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
	RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error
}

// purgeCapableContentRepo is implemented by a vaultContentRepo's concrete
// type when it also supports permanently purging every row it holds for a
// vault. Kept as its own interface for the same reason txCapableContentRepo
// is: PurgeVaultContents lives only on the concrete Secret/Key/
// CertificateRepository structs, not on their exported *RepositoryInterface
// types, so adding it directly to vaultContentRepo would ripple to every
// test double implementing those wider interfaces across the codebase.
type purgeCapableContentRepo interface {
	PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error
}

// protectionCheckableContentRepo is implemented by a vaultContentRepo's
// concrete type when it can report whether any row it holds for a vault has
// purge protection enabled. Kept as its own interface for the same reason
// purgeCapableContentRepo is: HasProtectedContent lives only on the concrete
// Secret/Key/CertificateRepository structs, not on their exported
// *RepositoryInterface types.
type protectionCheckableContentRepo interface {
	HasProtectedContent(ctx context.Context, vaultID uuid.UUID) (bool, error)
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

func (a *cascadeAdapter) SoftDeleteVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	for _, r := range a.repos {
		txRepo, ok := r.(txCapableContentRepo)
		if !ok {
			return fmt.Errorf("repository %T does not support transactional vault cascade", r)
		}
		if err := txRepo.SoftDeleteVaultContentsTx(ctx, ex, vaultID, deletedAt); err != nil {
			return err
		}
	}
	return nil
}

func (a *cascadeAdapter) RecoverVaultContentsTx(ctx context.Context, ex db.DBTX, vaultID uuid.UUID, deletedAt time.Time) error {
	for _, r := range a.repos {
		txRepo, ok := r.(txCapableContentRepo)
		if !ok {
			return fmt.Errorf("repository %T does not support transactional vault cascade", r)
		}
		if err := txRepo.RecoverVaultContentsTx(ctx, ex, vaultID, deletedAt); err != nil {
			return err
		}
	}
	return nil
}

func (a *cascadeAdapter) PurgeVaultContents(ctx context.Context, vaultID uuid.UUID) error {
	for _, r := range a.repos {
		purgeRepo, ok := r.(purgeCapableContentRepo)
		if !ok {
			return fmt.Errorf("repository %T does not support vault content purge", r)
		}
		if err := purgeRepo.PurgeVaultContents(ctx, vaultID); err != nil {
			return err
		}
	}
	return nil
}

func (a *cascadeAdapter) HasProtectedContent(ctx context.Context, vaultID uuid.UUID) (bool, error) {
	for _, r := range a.repos {
		checker, ok := r.(protectionCheckableContentRepo)
		if !ok {
			return false, fmt.Errorf("repository %T does not support purge-protection checks", r)
		}
		protected, err := checker.HasProtectedContent(ctx, vaultID)
		if err != nil {
			return false, err
		}
		if protected {
			return true, nil
		}
	}
	return false, nil
}
