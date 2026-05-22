package api

import (
	"encoding/json"
	"net/http"

	"rocketvault/common"
	"rocketvault/internal/signing"
)

// InitJWKS registers the JWKS endpoints on the router.
func (a *API) InitJWKS() {
	// GET /jwks.json — public, no auth, registered directly on rootRouter.
	a.rootRouter.Handle("/jwks.json", ApiHandler(a.App, getJWKS)).Methods(http.MethodGet)

	// POST /api/v1/jwks/rotate — admin only, behind the auth middleware.
	a.BaseRoutes.ApiRoot.Handle("/jwks/rotate", ApiHandler(a.App, rotateJWKS)).Methods(http.MethodPost)
}

// getJWKS serves GET /jwks.json — RFC 7517 JWK Set with all active public keys.
func getJWKS(c *Context, w http.ResponseWriter, r *http.Request) {
	provider := c.App.ServiceContainer.GetSigningProvider()
	if provider == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "signing provider not available"}) //nolint:errcheck
		return
	}

	jwks, err := buildJWKSet(provider.PublicKeys())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to build JWK set"}) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwks) //nolint:errcheck
}

// rotateJWKS serves POST /api/v1/jwks/rotate — only available with the self_pki provider.
func rotateJWKS(c *Context, w http.ResponseWriter, r *http.Request) {
	provider := c.App.ServiceContainer.GetSigningProvider()
	if provider == nil {
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.provider_unavailable", nil,
			"signing provider not available", http.StatusServiceUnavailable)
		return
	}

	rotatable, ok := provider.(signing.RotatableProvider)
	if !ok {
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.rotate_not_supported", nil,
			"key rotation is only supported for the self_pki key source", http.StatusBadRequest)
		return
	}

	newKID, overlapUntil, err := rotatable.Rotate()
	if err != nil {
		c.Err = common.NewAppError("api.jwks.rotate", "api.jwks.rotate_failed", nil,
			err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"status":        "ok",
		"new_kid":       newKID,
		"overlap_until": overlapUntil,
	})
}

// buildJWKSet converts a slice of PublicKeyInfo into a RFC 7517 JWK Set map.
func buildJWKSet(keys []signing.PublicKeyInfo) (map[string]any, error) {
	jwkList := make([]map[string]any, 0, len(keys))
	for _, info := range keys {
		jwk, err := signing.PublicKeyInfoToJWK(info)
		if err != nil {
			return nil, err
		}
		jwkList = append(jwkList, jwk)
	}
	return map[string]any{"keys": jwkList}, nil
}
