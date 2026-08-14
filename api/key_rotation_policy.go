package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// getKeyRotationPolicy returns the rotation policy for a key.
func getKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	repo := c.keyRotationPolicyRepo()
	if repo == nil {
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
	if _, err := keySvc.GetKey(r.Context(), keyID, scope); err != nil {
		c.SetNotFound("key")
		return
	}

	policy, err := repo.GetByKeyIDAny(r.Context(), keyID)
	if err != nil {
		c.SetNotFound("rotation policy")
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

	repo := c.keyRotationPolicyRepo()
	if repo == nil {
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
	if _, err := keySvc.GetKey(r.Context(), keyID, scope); err != nil {
		c.SetNotFound("key")
		return
	}

	now := time.Now()
	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 scope.ActorID(),
		RotateAfterDays:        req.RotateAfterDays,
		NotifyBeforeExpiryDays: req.NotifyBeforeExpiryDays,
		ExpiryDays:             req.ExpiryDays,
		Enabled:                req.Enabled,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	if err := repo.Upsert(r.Context(), policy); err != nil {
		c.SetInternalError(err)
		return
	}

	// Read-after-write so the response reflects the canonical stored ID. The
	// scope has already authorized the parent key, so the owner-agnostic
	// lookup is safe here too.
	stored, err := repo.GetByKeyIDAny(r.Context(), keyID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stored) //nolint:errcheck,gosec
}

// deleteKeyRotationPolicy removes the rotation policy for a key.
func deleteKeyRotationPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	repo := c.keyRotationPolicyRepo()
	if repo == nil {
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
	if _, err := keySvc.GetKey(r.Context(), keyID, scope); err != nil {
		c.SetNotFound("key")
		return
	}

	if err := repo.DeleteByKeyIDAny(r.Context(), keyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.SetNotFound("rotation policy not found")
		} else {
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}
