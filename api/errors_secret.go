package api

import (
	"errors"

	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
)

// writeSecretError maps a secret-service error onto an HTTP response. It
// replaces the identical three-way errors.Is chain that was repeated across
// getSecret, updateSecret, deleteSecret and the three version handlers — and
// with it the inconsistency where listSecretVersionsHandler returned 500 for a
// wrong-vault lookup while its two siblings returned 404.
func writeSecretError(c *Context, err error) {
	switch {
	case errors.Is(err, secrets.ErrSecretLifecycleDenied):
		c.SetPermissionError("secret is disabled or outside its valid time window")
	case errors.Is(err, secrets.ErrSecretNotFound):
		c.SetNotFound("secret")
	case errors.Is(err, repositories.ErrSecretPurgeProtected):
		c.SetPermissionError("secret has purge protection enabled (directly or via its vault)")
	default:
		c.SetInternalError(err)
	}
}
