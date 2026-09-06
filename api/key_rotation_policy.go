package api

import (
	"database/sql"
	"errors"
	"net/http"

	"rocketvault/internal/container"
	keyServices "rocketvault/internal/services/keys"
	vvalidation "rocketvault/internal/validation"
	"rocketvault/model"
)

// getKeyRotationPolicy returns the rotation policy for a key.
func getKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	policy, err := keySvc.GetKeyRotationPolicy(r.Context(), keyID, scope)
	if err != nil {
		if errors.Is(err, keyServices.ErrKeyNotFound) || errors.Is(err, keyServices.ErrKeyLifecycleDenied) {
			c.SetNotFound("key")
		} else {
			c.SetNotFound("rotation policy")
		}
		return
	}

	writeJSON(w, policy)
}

// upsertKeyRotationPolicy creates or replaces the rotation policy for a key.
func upsertKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	req, err := model.UpsertKeyRotationPolicyRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	if err := vvalidation.ValidateKeyRotationPolicy(vvalidation.KeyRotationPolicyRequest{
		RotateAfterDays: req.RotateAfterDays,
		Enabled:         req.Enabled,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	policy, err := keySvc.UpsertKeyRotationPolicy(r.Context(), keyID, scope, *req)
	if err != nil {
		if errors.Is(err, keyServices.ErrKeyNotFound) || errors.Is(err, keyServices.ErrKeyLifecycleDenied) {
			c.SetNotFound("key")
		} else {
			c.SetInternalError(err)
		}
		return
	}

	writeJSONStatus(w, http.StatusOK, policy)
}

// deleteKeyRotationPolicy removes the rotation policy for a key.
func deleteKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	if err := keySvc.DeleteKeyRotationPolicy(r.Context(), keyID, scope); err != nil {
		switch {
		case errors.Is(err, keyServices.ErrKeyNotFound), errors.Is(err, keyServices.ErrKeyLifecycleDenied):
			c.SetNotFound("key")
		case errors.Is(err, sql.ErrNoRows):
			c.SetNotFound("rotation policy not found")
		default:
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}
