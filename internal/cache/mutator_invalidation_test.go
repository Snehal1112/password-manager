package cache

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// TestEveryMutatorInvalidates primes the cache under BOTH a vault scope and an
// owner scope, invokes each mutating method under one of them, and asserts both
// entries are gone. The cache stores decrypted values, so a missed invalidation
// serves stale plaintext.
//
// RULE: a new mutating method on CachedSecretService joins this table in the
// same commit that adds it.
func TestEveryMutatorInvalidates(t *testing.T) {
	secretID := uuid.New()
	vaultID := uuid.New()
	ownerID := uuid.New()
	vaultScope := model.NewVaultScope(vaultID, ownerID)
	ownerScope := model.NewOwnerScope(uuid.Nil, ownerID)

	mutators := []struct {
		name   string
		invoke func(ctx context.Context, svc *CachedSecretService) error
	}{
		{"UpdateSecret", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, Scope: vaultScope})
		}},
		{"DeleteSecret", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.DeleteSecret(ctx, secretID, vaultScope)
		}},
		{"RecoverSecret", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.RecoverSecret(ctx, secretID, vaultScope)
		}},
		{"PurgeSecret", func(ctx context.Context, svc *CachedSecretService) error {
			return svc.PurgeSecret(ctx, secretID, vaultScope)
		}},
		{"ImportSecrets", func(ctx context.Context, svc *CachedSecretService) error {
			_, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{Format: "json", Data: []byte("[]")})
			return err
		}},
	}

	for _, m := range mutators {
		t.Run(m.name, func(t *testing.T) {
			ctx := context.Background()
			cache := newScopeCache(t, time.Minute)
			inner := &countingSecretService{secret: &model.Secret{
				ID: secretID, UserID: ownerID, VaultID: vaultID, Value: "plaintext", Enabled: true,
			}}
			svc := NewCachedSecretService(inner, cache, newQuietLogger(t))

			secret := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Value: "plaintext", Enabled: true}
			require.NoError(t, cache.Set(ctx, secret, vaultScope))
			require.NoError(t, cache.Set(ctx, secret, ownerScope))

			require.NoError(t, m.invoke(ctx, svc))

			_, found := cache.Get(ctx, secretID, vaultScope)
			assert.False(t, found, "%s left a stale vault-scoped entry", m.name)
			_, found = cache.Get(ctx, secretID, ownerScope)
			assert.False(t, found, "%s left a stale owner-scoped entry", m.name)
		})
	}
}
