package repositories

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestZeroScopeRejectedByEveryRepositoryMethod is the fail-closed gate for the
// refactor's highest-severity risk: a partially-migrated call site or a
// zero-valued mock return producing model.Scope{} must never read or write a
// row. Every scope-aware repository method belongs in this test.
func TestZeroScopeRejectedByEveryRepositoryMethod(t *testing.T) {
	ctx := context.Background()
	var zero model.Scope

	t.Run("SecretRepository", func(t *testing.T) {
		repo := newScopeTestSecretRepo(t)
		secret := seedScopeSecret(t, repo, uuid.New(), uuid.New(), "zero-scope")

		t.Run("ReadScoped", func(t *testing.T) {
			got, err := repo.ReadScoped(ctx, secret.ID, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Nil(t, got, "no row may be returned for an invalid scope")
		})
		t.Run("UpdateScoped", func(t *testing.T) {
			mutated := *secret
			mutated.Name = "zero-scope-write"
			err := repo.UpdateScoped(ctx, &mutated, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)

			after, readErr := repo.ReadScoped(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
			require.NoError(t, readErr)
			assert.Equal(t, "zero-scope", after.Name, "the row must be untouched")
		})
		t.Run("ListScoped", func(t *testing.T) {
			rows, err := repo.ListScoped(ctx, zero, SecretFilter{})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Empty(t, rows)
		})
	})

	t.Run("KeyRepository", func(t *testing.T) {
		repo := newScopeTestKeyRepo(t)
		key := seedScopeKey(t, repo, uuid.New(), uuid.New(), "zero-scope-key", model.KeyTypeRSA)

		t.Run("ReadScoped", func(t *testing.T) {
			got, err := repo.ReadScoped(ctx, key.ID, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Nil(t, got)
		})
		t.Run("UpdateScoped", func(t *testing.T) {
			mutated := *key
			mutated.Name = "zero-scope-write"
			err := repo.UpdateScoped(ctx, &mutated, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)

			after, readErr := repo.ReadScoped(ctx, key.ID, model.NewAdminScope(uuid.Nil))
			require.NoError(t, readErr)
			assert.Equal(t, "zero-scope-key", after.Name)
		})
		t.Run("ListScoped", func(t *testing.T) {
			rows, err := repo.ListScoped(ctx, zero, KeyFilter{})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Empty(t, rows)
		})
	})

	t.Run("CertificateRepository", func(t *testing.T) {
		repo := newScopeTestCertRepo(t)
		cert := seedScopeCert(t, repo, uuid.New(), uuid.New(), "zero-scope-cert")

		t.Run("ReadScoped", func(t *testing.T) {
			got, err := repo.ReadScoped(ctx, cert.ID, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Nil(t, got)
		})
		t.Run("UpdateScoped", func(t *testing.T) {
			mutated := *cert
			mutated.Name = "zero-scope-write"
			err := repo.UpdateScoped(ctx, &mutated, zero)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)

			after, readErr := repo.ReadScoped(ctx, cert.ID, model.NewAdminScope(uuid.Nil))
			require.NoError(t, readErr)
			assert.Equal(t, "zero-scope-cert", after.Name)
		})
		t.Run("ListScoped", func(t *testing.T) {
			rows, err := repo.ListScoped(ctx, zero, CertificateFilter{})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidScope)
			assert.Empty(t, rows)
		})
	})
}
