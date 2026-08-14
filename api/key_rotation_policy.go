package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// getKeyRotationPolicy returns the rotation policy for a key.
func getKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy) //nolint:errcheck,gosec
}

// upsertKeyRotationPolicy creates or replaces the rotation policy for a key.
func upsertKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	req, err := model.UpsertKeyRotationPolicyRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(policy) //nolint:errcheck,gosec
}

// deleteKeyRotationPolicy removes the rotation policy for a key.
func deleteKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
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
