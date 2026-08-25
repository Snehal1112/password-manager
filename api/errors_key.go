package api

import (
	"errors"

	"rocketvault/internal/crypto"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
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
	case errors.Is(err, keyservices.ErrInvalidJWK):
		c.SetInvalidParam(err.Error())
	case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
		c.SetPermissionError("key is disabled or outside its valid time window")
	case errors.Is(err, keyservices.ErrKeyForbidden) || errors.Is(err, keyservices.ErrKeyRevoked):
		c.SetPermissionError("key_access")
	case errors.Is(err, keyservices.ErrKeyNotFound):
		c.SetNotFound("key")
	case errors.Is(err, model.ErrKeyPurgeProtected):
		c.SetPermissionError("key has purge protection enabled (directly or via its vault)")
	case errors.Is(err, model.ErrGlobalPurgeProtectionEnabled):
		c.SetPermissionError(err.Error())
	case errors.Is(err, crypto.ErrOctKeysRequireHSM):
		c.SetInvalidParam("type: OCT key creation requires an HSM-backed key provider (hsm.enabled: true)")
	case errors.Is(err, crypto.ErrUnsupportedCurve):
		// The message deliberately omits err.Error(): a real HSM's curve
		// rejection can wrap raw PKCS#11 text (e.g. "rejected by HSM"), the
		// same backend-detail leak fixed for the algorithm case below.
		c.SetInvalidParam("curve")
	case errors.Is(err, keyservices.ErrUnsupportedAlgorithm) || errors.Is(err, crypto.ErrUnsupportedAlgorithm):
		// crypto.ErrUnsupportedAlgorithm is the provider-side twin of
		// keyservices.ErrUnsupportedAlgorithm: an HSM that rejects a mechanism
		// (AES-CBC, AES-GCM, ...) surfaces here via isHSMCapabilityError.
		// Without this case it would fall through to a 500 carrying the raw
		// PKCS#11 error, the same leak B24/B25 closed for the curve case above.
		// The message deliberately omits err.Error(): the wrapped PKCS#11 text
		// (e.g. "rejected by HSM") is a backend implementation detail that must
		// not reach the client — see TestEncryptKey/DecryptKey_HSMRejectsAlgorithm_Returns400.
		c.SetInvalidParam("algorithm")
	case errors.Is(err, model.ErrKeyVersionNotFound):
		c.SetNotFound("key version")
	default:
		c.SetInternalError(err)
	}
}
