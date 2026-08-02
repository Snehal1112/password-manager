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
// It is always optional — a nil invalidator means caching is disabled.
type SecretCacheInvalidator interface {
	DeleteByID(ctx context.Context, secretID uuid.UUID) error
}
