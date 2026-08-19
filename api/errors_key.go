package api

import (
	"errors"

	"rocketvault/internal/crypto"
	"rocketvault/internal/repositories"
	keyservices "rocketvault/internal/services/keys"
)

// writeKeyError maps a key-service error onto an HTTP response.
//
// It mirrors writeSecretError so every key handler agrees on the mapping. In
// particular a lifecycle denial is a 403, not a 500: the handlers that update
// or rotate a key read it back afterwards, and that read-back legitimately
// hits ErrKeyLifecycleDenied when the caller just disabled the key or the key
// has expired. That is a state condition, not a server fault, and 403 is the
// status every other lifecycle denial in this codebase already returns
// (writeSecretError, getKey, and the crypto handlers).
func writeKeyError(c *Context, err error) {
	switch {
	case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
		c.SetPermissionError("key is disabled or outside its valid time window")
	case errors.Is(err, keyservices.ErrKeyForbidden) || errors.Is(err, keyservices.ErrKeyRevoked):
		c.SetPermissionError("key_access")
	case errors.Is(err, keyservices.ErrKeyNotFound):
		c.SetNotFound("key")
	case errors.Is(err, repositories.ErrKeyPurgeProtected):
		c.SetPermissionError("key has purge protection enabled (directly or via its vault)")
	case errors.Is(err, crypto.ErrUnsupportedCurve):
		c.SetInvalidParam("curve: " + err.Error())
	default:
		c.SetInternalError(err)
	}
}
