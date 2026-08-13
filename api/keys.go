/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/internal/crypto"
	"rocketvault/internal/repositories"
	keyservices "rocketvault/internal/services/keys"
	vvalidation "rocketvault/internal/validation"
	"rocketvault/model"
)

// CreateKeyRequest represents the request structure for creating a cryptographic key.
type CreateKeyRequest struct {
	Name      string     `json:"name"`              // Key name.
	Type      string     `json:"type"`              // Key type (RSA, ECDSA).
	Bits      int        `json:"bits"`              // RSA key size in bits (2048, 3072, or 4096).
	Curve     string     `json:"curve"`             // ECDSA curve (P-256, P-384, P-521).
	Tags      []string   `json:"tags"`              // Tags for the key.
	Enabled   *bool      `json:"enabled,omitempty"` // Defaults to true if nil.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
}

// UpdateKeyRequest represents the request structure for updating a cryptographic key.
type UpdateKeyRequest struct {
	Name      *string    `json:"name,omitempty"`    // New name for the key.
	Revoked   *bool      `json:"revoked,omitempty"` // Set key revocation status.
	Tags      []string   `json:"tags,omitempty"`    // Replace existing tags.
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
}

// KeyResponse represents the response structure for a cryptographic key.
type KeyResponse struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	UserID    uuid.UUID  `json:"user_id"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	Tags      []string   `json:"tags"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	Bits      int        `json:"bits,omitempty"`
	Curve     string     `json:"curve,omitempty"`
	// JWK public components (omitted for HSM-backed keys).
	N string `json:"n,omitempty"` // RSA modulus (base64url).
	E string `json:"e,omitempty"` // RSA public exponent (base64url).
	X string `json:"x,omitempty"` // EC x coordinate (base64url).
	Y string `json:"y,omitempty"` // EC y coordinate (base64url).
}

// KeyListResponse represents the response structure for listing keys.
type KeyListResponse struct {
	Keys []KeyResponse `json:"keys"`
}

// WrapKeyRequest is the HTTP request body for POST /keys/{key_id}/wrap.
type WrapKeyRequest struct {
	PlaintextKey string `json:"plaintext_key"` // base64-encoded key material.
	Algorithm    string `json:"algorithm"`     // defaults to "RSA-OAEP".
}

// WrapKeyResponse is the HTTP response for a successful wrap.
type WrapKeyResponse struct {
	WrappedKey string `json:"wrapped_key"` // base64-encoded wrapped bytes.
	Algorithm  string `json:"algorithm"`
}

// UnwrapKeyRequest is the HTTP request body for POST /keys/{key_id}/unwrap.
type UnwrapKeyRequest struct {
	WrappedKey string `json:"wrapped_key"` // base64-encoded wrapped bytes.
	Algorithm  string `json:"algorithm"`   // defaults to "RSA-OAEP".
}

// UnwrapKeyResponse is the HTTP response for a successful unwrap.
type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"` // base64-encoded recovered key.
	Algorithm    string `json:"algorithm"`
}

// SignKeyRequest is the HTTP request body for POST /keys/{key_id}/sign.
type SignKeyRequest struct {
	Value     string `json:"value"`     // base64-encoded data to sign
	Algorithm string `json:"algorithm"` // RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
}

// SignKeyResponse is the HTTP response for a successful sign.
type SignKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"` // base64-encoded signature
}

// VerifyKeyRequest is the HTTP request body for POST /keys/{key_id}/verify.
type VerifyKeyRequest struct {
	Value     string `json:"value"`     // base64-encoded original data
	Signature string `json:"signature"` // base64-encoded signature
	Algorithm string `json:"algorithm"`
}

// VerifyKeyResponse is the HTTP response for a verify operation.
type VerifyKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Valid     bool   `json:"valid"`
}

// EncryptKeyRequest is the HTTP request body for POST /keys/{key_id}/encrypt.
type EncryptKeyRequest struct {
	Value     string `json:"value"`     // base64-encoded plaintext
	Algorithm string `json:"algorithm"` // RSA-OAEP, RSA-OAEP-256, AES256-GCM
}

// EncryptKeyResponse is the HTTP response for a successful encrypt.
type EncryptKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`           // base64-encoded ciphertext
	Nonce     string `json:"nonce,omitempty"` // base64-encoded, for AES-GCM
}

// DecryptKeyRequest is the HTTP request body for POST /keys/{key_id}/decrypt.
type DecryptKeyRequest struct {
	Value     string `json:"value"`           // base64-encoded ciphertext
	Nonce     string `json:"nonce,omitempty"` // base64-encoded, for AES-GCM
	Algorithm string `json:"algorithm"`
}

// DecryptKeyResponse is the HTTP response for a successful decrypt.
type DecryptKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"` // base64-encoded plaintext
}

// buildKeyResponse converts a model.Key to a KeyResponse.
// When the key's value carries a "pkcs11:" prefix the type is suffixed with
// "-HSM" (e.g. "RSA" → "RSA-HSM", "ECDSA" → "EC-HSM") to match Azure Key
// Vault's convention for hardware-backed keys.
func buildKeyResponse(key *model.Key) KeyResponse {
	kty := key.Type
	if strings.HasPrefix(key.Value, "pkcs11:") {
		switch kty {
		case "ECDSA", "ES256K":
			kty = "EC-HSM"
		default:
			kty = kty + "-HSM"
		}
	}
	n, e, x, y, _ := crypto.ExtractPublicComponents(key.Value, key.Type)
	return KeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Type:      kty,
		UserID:    key.UserID,
		Revoked:   key.Revoked,
		CreatedAt: key.CreatedAt,
		UpdatedAt: key.UpdatedAt,
		Tags:      key.Tags,
		Enabled:   key.Enabled,
		ExpiresAt: key.ExpiresAt,
		NotBefore: key.NotBefore,
		Bits:      key.Bits,
		Curve:     key.Curve,
		N:         n,
		E:         e,
		X:         x,
		Y:         y,
	}
}

// InitKeys initializes the routes for cryptographic keys management API.
// It sets up the following endpoints:
// - POST /keys: Create a new cryptographic key.
// - GET /keys: List all keys for authenticated user (with filtering).
// - GET /keys/{key_id}: Get a specific key by ID.
// - PUT /keys/{key_id}: Update a key.
// - DELETE /keys/{key_id}: Delete a key.
// - POST /keys/{key_id}/rotate: Rotate a key (generate new key pair, revoke old).
func (api *API) InitKeys() {
	api.registerKeyRoutes(api.BaseRoutes.Keys)
	if api.BaseRoutes.VaultScoped != nil {
		api.registerKeyRoutes(api.BaseRoutes.VaultScoped.PathPrefix("/keys").Subrouter())
	}
}

// registerKeyRoutes registers the key handlers on the provided subrouter. It is
// called for both the legacy flat routes and the vault-scoped routes.
func (api *API) registerKeyRoutes(k *mux.Router) {
	// Basic CRUD operations.
	k.Handle("", ApiSessionRequired(api.App, createKey)).Methods("POST")
	k.Handle("", ApiSessionRequired(api.App, listKeys)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getKey)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateKey)).Methods("PUT")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteKey)).Methods("DELETE")

	// Additional operations.
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/rotate", ApiSessionRequired(api.App, rotateKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/versions", ApiSessionRequired(api.App, listKeyVersions)).Methods("GET")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/wrap", ApiSessionRequired(api.App, wrapKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/unwrap", ApiSessionRequired(api.App, unwrapKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/sign", ApiSessionRequired(api.App, signKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/verify", ApiSessionRequired(api.App, verifyKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/encrypt", ApiSessionRequired(api.App, encryptKey)).Methods("POST")
	k.Handle("/{key_id:[A-Fa-f0-9-]+}/decrypt", ApiSessionRequired(api.App, decryptKey)).Methods("POST")

	api.Logger.Infoln("Keys API routes initialized")
}

// createKey creates a new cryptographic key.
func createKey(c *Context, w http.ResponseWriter, r *http.Request) {
	// Authorization happens in PolicyMiddleware: creating a key requires the
	// Microsoft.KeyVault/vaults/keys/create data action, granted by Key Vault
	// Crypto Officer or Key Vault Administrator in this vault. A second gate on
	// the caller's global role would contradict that per-vault decision.

	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Validate required fields.
	if req.Name == "" || req.Type == "" {
		c.SetInvalidParam("name and type are required")
		return
	}

	// Validate key type.
	req.Type = strings.ToUpper(req.Type)
	if req.Type != "RSA" && req.Type != "ECDSA" && req.Type != "OCT" {
		c.SetInvalidParam("type: must be RSA, ECDSA, or OCT")
		return
	}

	// Validate name format and tag limits.
	if err := vvalidation.ValidateKeyCreate(vvalidation.KeyCreateRequest{
		Name:  req.Name,
		Type:  req.Type,
		Bits:  req.Bits,
		Curve: req.Curve,
		Tags:  req.Tags,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	// Get user ID from claims.
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	// Resolve the target vault from the request context.
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	// Default Enabled to true when not specified.
	enabled := req.Enabled
	if enabled == nil {
		t := true
		enabled = &t
	}

	// Build create key request.
	createReq := keyservices.CreateKeyRequest{
		Name:      req.Name,
		Type:      req.Type,
		Tags:      req.Tags,
		UserID:    userID,
		VaultID:   vaultID,
		Enabled:   enabled,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}

	var result *keyservices.CreateKeyResult
	switch req.Type {
	case "RSA":
		// Validate RSA key size.
		if req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096 {
			if req.Bits == 0 {
				req.Bits = 2048 // Default RSA key size.
			} else {
				c.SetInvalidParam("bits: must be 2048, 3072, or 4096")
				return
			}
		}
		createReq.Bits = req.Bits
		result, err = keyService.CreateRSAKey(r.Context(), createReq)
	case "OCT":
		if req.Bits != 128 && req.Bits != 192 && req.Bits != 256 {
			c.SetInvalidParam("bits: must be 128, 192, or 256")
			return
		}
		createReq.Bits = req.Bits
		result, err = keyService.CreateOctKey(r.Context(), createReq)
	default:
		// Validate ECDSA curve.
		if req.Curve == "" {
			req.Curve = "P-256" // Default ECDSA curve.
		}
		if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" && req.Curve != "P-256K" {
			c.SetInvalidParam("curve: must be P-256, P-384, P-521, or P-256K")
			return
		}
		createReq.Curve = req.Curve
		result, err = keyService.CreateECDSAKey(r.Context(), createReq)
	}

	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Fetch the full key record so buildKeyResponse can inspect the stored value.
	key, err := keyService.GetKey(r.Context(), result.KeyID, model.NewOwnerScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(buildKeyResponse(key)) //nolint:errcheck,gosec
}

// listKeys lists cryptographic keys. Legacy flat routes use per-user visibility
// (the caller's own keys); explicit vault-scoped routes use vault-level
// "members see all" visibility, optionally filtered by type and tags.
func listKeys(c *Context, w http.ResponseWriter, r *http.Request) {
	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	keysList, err := keyService.ListKeys(r.Context(), scope, repositories.KeyFilter{
		Type: r.URL.Query().Get("type"),
		Tags: c.Params.Tags,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Convert to response format.
	response := KeyListResponse{Keys: make([]KeyResponse, len(keysList))}
	for i := range keysList {
		response.Keys[i] = buildKeyResponse(&keysList[i])
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response) //nolint:errcheck,gosec
}

// getKey retrieves a specific cryptographic key by ID.
func getKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	key, err := keyService.GetKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildKeyResponse(key)) //nolint:errcheck,gosec
}

// updateKey updates a cryptographic key.
func updateKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	var req UpdateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}

	if req.Name == nil && req.Revoked == nil && req.Tags == nil && req.Enabled == nil && req.ExpiresAt == nil && req.NotBefore == nil {
		c.SetInvalidParam("at least one update field (name, revoked, tags, enabled, expires_at, not_before) must be provided")
		return
	}

	if err := vvalidation.ValidateKeyUpdate(vvalidation.KeyUpdateRequest{
		Name: req.Name,
		Tags: req.Tags,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := keyService.UpdateKey(r.Context(), keyservices.UpdateKeyRequest{
		KeyID:     keyID,
		Scope:     scope,
		Name:      req.Name,
		Tags:      req.Tags,
		Revoked:   req.Revoked,
		Enabled:   req.Enabled,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}); err != nil {
		writeKeyError(c, err)
		return
	}

	// Get updated key for response, using the same scope as the update. The
	// read-back can legitimately be lifecycle-denied — the update may have
	// just disabled the key — so map it like any other lifecycle denial
	// rather than reporting an internal error for a write that succeeded.
	key, err := keyService.GetKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildKeyResponse(key)) //nolint:errcheck,gosec
}

// deleteKey deletes a cryptographic key.
func deleteKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	deleted, err := keyService.DeleteKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	// Return deletion metadata matching Azure Key Vault's DELETE /keys/{name} response.
	type deleteResponse struct {
		ID               string     `json:"id"`
		Name             string     `json:"name"`
		DeletedAt        *time.Time `json:"deleted_at"`
		ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
		RecoveryID       string     `json:"recovery_id,omitempty"`
	}

	resp := deleteResponse{
		ID:               deleted.ID.String(),
		Name:             deleted.Name,
		DeletedAt:        deleted.DeletedAt,
		ScheduledPurgeAt: deleted.ScheduledPurgeAt,
		RecoveryID:       "/deleted/keys/" + deleted.ID.String() + "/restore",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck,gosec
}

// rotateKey rotates a cryptographic key by generating a new key pair and revoking the old key.
func rotateKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Rotate the key. The scoped read inside the service is the access check.
	result, err := keyService.RotateKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	// Fetch the full key record so buildKeyResponse can inspect the stored
	// value, using the same scope that authorized the rotation.
	key, err := keyService.GetKey(r.Context(), result.KeyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildKeyResponse(key)) //nolint:errcheck,gosec
}

// listKeyVersions returns the version history for a key, excluding raw key material.
func listKeyVersions(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Authorize through the scope-aware read first, exactly like getKey on
	// this same route. KeyRepository.ListVersions filters on the key's owner
	// with no vault predicate, so calling it with the caller's own id would
	// hand a vault member an empty list for a key getKey happily returns.
	// Resolving the owner from the authorized row keeps both consistent.
	key, err := keyService.GetKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	repo := c.App.ServiceContainer.GetKeyRepository()
	if repo == nil {
		c.SetInternalError(nil)
		return
	}

	versions, err := repo.ListVersions(r.Context(), keyID, key.UserID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Return an empty array rather than null when no versions exist.
	if versions == nil {
		versions = []model.KeyVersion{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"versions": versions}) //nolint:errcheck,gosec
}

// wrapKey wraps plaintext key material using the vault key identified by {key_id}.
func wrapKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var req WrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.PlaintextKey == "" {
		c.SetInvalidParam("plaintext_key is required")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	plaintextBytes, err := base64.StdEncoding.DecodeString(req.PlaintextKey)
	if err != nil {
		c.SetInvalidParam("plaintext_key: must be valid base64")
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.WrapKey(r.Context(), keyservices.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       scope.ActorID(),
		VaultID:      scope.VaultID(),
		Scope:        scope,
		PlaintextKey: plaintextBytes,
		Algorithm:    req.Algorithm,
	})
	if err != nil {
		switch {
		case errors.Is(err, keyservices.ErrKeyForbidden) || errors.Is(err, keyservices.ErrKeyRevoked):
			c.SetPermissionError("key_access")
		case errors.Is(err, keyservices.ErrKeyNotFound):
			c.SetNotFound("key")
		case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
			c.SetPermissionError("key is disabled or outside its valid time window")
		case errors.Is(err, keyservices.ErrUnsupportedAlgorithm):
			c.SetInvalidParam("algorithm")
		default:
			c.SetInternalError(err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(WrapKeyResponse{ //nolint:errcheck,gosec
		WrappedKey: base64.StdEncoding.EncodeToString(result.WrappedKey),
		Algorithm:  result.Algorithm,
	})
}

// unwrapKey recovers plaintext key material from wrapped bytes using the vault key identified by {key_id}.
func unwrapKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var req UnwrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.WrappedKey == "" {
		c.SetInvalidParam("wrapped_key is required")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	wrappedBytes, err := base64.StdEncoding.DecodeString(req.WrappedKey)
	if err != nil {
		c.SetInvalidParam("wrapped_key: must be valid base64")
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.UnwrapKey(r.Context(), keyservices.UnwrapKeyRequest{
		KeyID:      keyID,
		UserID:     scope.ActorID(),
		VaultID:    scope.VaultID(),
		Scope:      scope,
		WrappedKey: wrappedBytes,
		Algorithm:  req.Algorithm,
	})
	if err != nil {
		switch {
		case errors.Is(err, keyservices.ErrKeyForbidden) || errors.Is(err, keyservices.ErrKeyRevoked):
			c.SetPermissionError("key_access")
		case errors.Is(err, keyservices.ErrKeyNotFound):
			c.SetNotFound("key")
		case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
			c.SetPermissionError("key is disabled or outside its valid time window")
		case errors.Is(err, keyservices.ErrUnsupportedAlgorithm):
			c.SetInvalidParam("algorithm")
		default:
			c.SetInternalError(err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UnwrapKeyResponse{ //nolint:errcheck,gosec
		PlaintextKey: base64.StdEncoding.EncodeToString(result.PlaintextKey),
		Algorithm:    result.Algorithm,
	})
}

// signKey signs data using the vault key identified by {key_id}.
func signKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var req SignKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Value == "" {
		c.SetInvalidParam("value is required")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RS256"
	}

	data, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		c.SetInvalidParam("value: must be valid base64")
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.Sign(r.Context(), keyservices.SignRequest{
		KeyID:     keyID,
		Data:      data,
		Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
		UserID:    scope.ActorID(),
		VaultID:   scope.VaultID(),
		Scope:     scope,
	})
	if err != nil {
		switch {
		case errors.Is(err, keyservices.ErrKeyForbidden) || errors.Is(err, keyservices.ErrKeyRevoked):
			c.SetPermissionError("key_access")
		case errors.Is(err, keyservices.ErrKeyNotFound):
			c.SetNotFound("key")
		case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
			c.SetPermissionError("key is disabled or outside its valid time window")
		case errors.Is(err, keyservices.ErrUnsupportedAlgorithm):
			c.SetInvalidParam("algorithm")
		default:
			c.SetInternalError(err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SignKeyResponse{ //nolint:errcheck,gosec
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Value:     base64.StdEncoding.EncodeToString(result.Signature),
	})
}

// verifyKey verifies a signature using the vault key identified by {key_id}.
func verifyKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var req VerifyKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Value == "" || req.Signature == "" {
		c.SetInvalidParam("value and signature are required")
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		c.SetInvalidParam("value: must be valid base64")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		c.SetInvalidParam("signature: must be valid base64")
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.Verify(r.Context(), keyservices.VerifyRequest{
		KeyID:     keyID,
		Data:      data,
		Signature: sig,
		Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
		UserID:    scope.ActorID(),
		VaultID:   scope.VaultID(),
		Scope:     scope,
	})
	if err != nil {
		switch {
		case errors.Is(err, keyservices.ErrKeyForbidden) || errors.Is(err, keyservices.ErrKeyRevoked):
			c.SetPermissionError("key_access")
		case errors.Is(err, keyservices.ErrKeyNotFound):
			c.SetNotFound("key")
		case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
			c.SetPermissionError("key is disabled or outside its valid time window")
		case errors.Is(err, keyservices.ErrUnsupportedAlgorithm):
			c.SetInvalidParam("algorithm")
		default:
			c.SetInternalError(err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifyKeyResponse{ //nolint:errcheck,gosec
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Valid:     result.Valid,
	})
}

// encryptKey encrypts data using the vault key identified by {key_id}.
func encryptKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var req EncryptKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Value == "" {
		c.SetInvalidParam("value is required")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		c.SetInvalidParam("value: must be valid base64")
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.Encrypt(r.Context(), keyservices.EncryptRequest{
		KeyID:     keyID,
		Data:      plaintext,
		Algorithm: crypto.EncryptionAlgorithm(req.Algorithm),
		UserID:    scope.ActorID(),
		VaultID:   scope.VaultID(),
		Scope:     scope,
	})
	if err != nil {
		switch {
		case errors.Is(err, keyservices.ErrKeyForbidden) || errors.Is(err, keyservices.ErrKeyRevoked):
			c.SetPermissionError("key_access")
		case errors.Is(err, keyservices.ErrKeyNotFound):
			c.SetNotFound("key")
		case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
			c.SetPermissionError("key is disabled or outside its valid time window")
		case errors.Is(err, keyservices.ErrUnsupportedAlgorithm):
			c.SetInvalidParam("algorithm")
		default:
			c.SetInternalError(err)
		}
		return
	}

	resp := EncryptKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Value:     base64.StdEncoding.EncodeToString(result.Ciphertext),
	}
	if len(result.Nonce) > 0 {
		resp.Nonce = base64.StdEncoding.EncodeToString(result.Nonce)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck,gosec
}

// decryptKey decrypts data using the vault key identified by {key_id}.
func decryptKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	var req DecryptKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Value == "" {
		c.SetInvalidParam("value is required")
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		c.SetInvalidParam("value: must be valid base64")
		return
	}

	var nonce []byte
	if req.Nonce != "" {
		nonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			c.SetInvalidParam("nonce: must be valid base64")
			return
		}
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.Decrypt(r.Context(), keyservices.DecryptRequest{
		KeyID:      keyID,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Algorithm:  crypto.EncryptionAlgorithm(req.Algorithm),
		UserID:     scope.ActorID(),
		VaultID:    scope.VaultID(),
		Scope:      scope,
	})
	if err != nil {
		switch {
		case errors.Is(err, keyservices.ErrKeyForbidden) || errors.Is(err, keyservices.ErrKeyRevoked):
			c.SetPermissionError("key_access")
		case errors.Is(err, keyservices.ErrKeyNotFound):
			c.SetNotFound("key")
		case errors.Is(err, keyservices.ErrKeyLifecycleDenied):
			c.SetPermissionError("key is disabled or outside its valid time window")
		case errors.Is(err, keyservices.ErrUnsupportedAlgorithm):
			c.SetInvalidParam("algorithm")
		default:
			c.SetInternalError(err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DecryptKeyResponse{ //nolint:errcheck,gosec
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Value:     base64.StdEncoding.EncodeToString(result.Plaintext),
	})
}
