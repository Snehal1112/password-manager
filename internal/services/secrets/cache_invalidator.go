package secrets

import (
	"context"

	"github.com/google/uuid"
)

// SecretCacheInvalidator evicts every cached view of one secret.
//
// It exists because not every write to the secrets table goes through
// CachedSecretService: the rotation and versioning services update rows
// directly, so they need their own invalidation hook or a rotated (possibly
// compromised) credential keeps being served from cache for the full TTL.
//
// The interface is declared here rather than imported from internal/cache
// because that package imports this one; *cache.SecretCache satisfies it.
type SecretCacheInvalidator interface {
	DeleteByID(ctx context.Context, secretID uuid.UUID) error
}

// noopSecretCacheInvalidator is the "always non-nil, real-or-no-op" default
// used when a constructor is handed a nil SecretCacheInvalidator (tests,
// mainly). It matches the pattern this effort established for the caches
// themselves: callers can always invoke DeleteByID without a nil check.
type noopSecretCacheInvalidator struct{}

func (noopSecretCacheInvalidator) DeleteByID(context.Context, uuid.UUID) error { return nil }
