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
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/common"
	"rocketvault/model"
	keyservices "rocketvault/internal/services/keys"
)

// CreateKeyRequest represents the request structure for creating a cryptographic key.
type CreateKeyRequest struct {
	Name  string   `json:"name"`  // Key name
	Type  string   `json:"type"`  // Key type (RSA, ECDSA)
	Bits  int      `json:"bits"`  // RSA key size in bits (2048 or 4096)
	Curve string   `json:"curve"` // ECDSA curve (P-256, P-384, P-521)
	Tags  []string `json:"tags"`  // Tags for the key
}

// UpdateKeyRequest represents the request structure for updating a cryptographic key.
type UpdateKeyRequest struct {
	Name    *string  `json:"name,omitempty"`    // New name for the key
	Revoked *bool    `json:"revoked,omitempty"` // Set key revocation status
	Tags    []string `json:"tags,omitempty"`    // Replace existing tags
}

// KeyResponse represents the response structure for a cryptographic key.
type KeyResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	UserID    uuid.UUID `json:"user_id"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	Tags      []string  `json:"tags"`
}

// KeyListResponse represents the response structure for listing keys.
type KeyListResponse struct {
	Keys []KeyResponse `json:"keys"`
}

// WrapKeyRequest is the HTTP request body for POST /keys/{id}/wrap.
type WrapKeyRequest struct {
	PlaintextKey string `json:"plaintext_key"` // base64-encoded key material
	Algorithm    string `json:"algorithm"`     // defaults to "RSA-OAEP"
}

// WrapKeyResponse is the HTTP response for a successful wrap.
type WrapKeyResponse struct {
	WrappedKey string `json:"wrapped_key"` // base64-encoded wrapped bytes
	Algorithm  string `json:"algorithm"`
}

// UnwrapKeyRequest is the HTTP request body for POST /keys/{id}/unwrap.
type UnwrapKeyRequest struct {
	WrappedKey string `json:"wrapped_key"` // base64-encoded wrapped bytes
	Algorithm  string `json:"algorithm"`   // defaults to "RSA-OAEP"
}

// UnwrapKeyResponse is the HTTP response for a successful unwrap.
type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"` // base64-encoded recovered key
	Algorithm    string `json:"algorithm"`
}

// InitKeys initializes the routes for cryptographic keys management API.
// It sets up the following endpoints:
// - POST /keys: Create a new cryptographic key.
// - GET /keys: List all keys for authenticated user (with filtering).
// - GET /keys/{id}: Get a specific key by ID.
// - PUT /keys/{id}: Update a key.
// - DELETE /keys/{id}: Delete a key.
// - POST /keys/{id}/rotate: Rotate a key (generate new key pair, revoke old).
//
// Parameters:
// - keys (*mux.Router): The router to which the routes will be added.
func (api *API) InitKeys() {
	k := api.BaseRoutes.Keys

	// Basic CRUD operations.
	k.Handle("", ApiSessionRequired(api.App, createKey)).Methods("POST")
	k.Handle("", ApiSessionRequired(api.App, listKeys)).Methods("GET")
	k.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getKey)).Methods("GET")
	k.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateKey)).Methods("PUT")
	k.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteKey)).Methods("DELETE")

	// Additional operations.
	k.Handle("/{id:[A-Fa-f0-9-]+}/rotate", ApiSessionRequired(api.App, rotateKey)).Methods("POST")
	k.Handle("/{id:[A-Fa-f0-9-]+}/wrap", ApiSessionRequired(api.App, wrapKey)).Methods("POST")
	k.Handle("/{id:[A-Fa-f0-9-]+}/unwrap", ApiSessionRequired(api.App, unwrapKey)).Methods("POST")

	api.Logger.Infoln("Keys API routes initialized")
}

// createKey creates a new cryptographic key.
func createKey(c *Context, w http.ResponseWriter, r *http.Request) {
	// Check authorization - requires admin or secrets manager role
	claims, ok := c.Claims["role"].(string)
	if !ok || !common.HasRequiredRole(claims, model.RoleAdmin, model.RoleSecretsManager) {
		c.Err = common.NewAppError("createKey", "Forbidden: requires admin or secrets_manager role", nil, "", http.StatusForbidden)
		return
	}

	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("createKey", "Invalid JSON request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Name == "" || req.Type == "" {
		c.Err = common.NewAppError("createKey", "Name and type are required", nil, "", http.StatusBadRequest)
		return
	}

	// Validate key type
	req.Type = strings.ToUpper(req.Type)
	if req.Type != "RSA" && req.Type != "ECDSA" {
		c.Err = common.NewAppError("createKey", "Invalid key type: must be RSA or ECDSA", nil, "", http.StatusBadRequest)
		return
	}

	// Get user ID from claims
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("createKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("createKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	// Build create key request
	createReq := keyservices.CreateKeyRequest{
		Name:   req.Name,
		Type:   req.Type,
		Tags:   req.Tags,
		UserID: userID,
	}

	var result *keyservices.CreateKeyResult
	if req.Type == "RSA" {
		// Validate RSA key size
		if req.Bits != 2048 && req.Bits != 4096 {
			if req.Bits == 0 {
				req.Bits = 2048 // Default RSA key size
			} else {
				c.Err = common.NewAppError("createKey", "Invalid RSA key size: must be 2048 or 4096", nil, "", http.StatusBadRequest)
				return
			}
		}
		createReq.Bits = req.Bits
		result, err = keyService.CreateRSAKey(r.Context(), createReq)
	} else {
		// Validate ECDSA curve
		if req.Curve == "" {
			req.Curve = "P-256" // Default ECDSA curve
		}
		if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" {
			c.Err = common.NewAppError("createKey", "Invalid ECDSA curve: must be P-256, P-384, or P-521", nil, "", http.StatusBadRequest)
			return
		}
		createReq.Curve = req.Curve
		result, err = keyService.CreateECDSAKey(r.Context(), createReq)
	}

	if err != nil {
		c.Err = common.NewAppError("createKey", "Failed to create key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	response := KeyResponse{
		ID:        result.KeyID,
		Name:      result.Name,
		Type:      result.Type,
		UserID:    userID,
		Revoked:   false, // New keys are never revoked
		CreatedAt: result.CreatedAt,
		Tags:      result.Tags,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// listKeys lists cryptographic keys with optional filtering.
func listKeys(c *Context, w http.ResponseWriter, r *http.Request) {
	// Get user ID from claims
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("listKeys", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("listKeys", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	// Parse query parameters
	keyType := r.URL.Query().Get("type")
	tagsParam := r.URL.Query().Get("tags")

	var tags []string
	if tagsParam != "" {
		tags = strings.Split(tagsParam, ",")
		for i, tag := range tags {
			tags[i] = strings.TrimSpace(tag)
		}
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	// Check if user is admin - admins can list all keys
	roleStr, ok := c.Claims["role"].(string)
	isAdmin := ok && roleStr == string(model.RoleAdmin)

	// Use service layer with proper admin/user distinction
	var keysList []model.Key
	if isAdmin {
		// Admins list all keys with filters (userID = nil)
		keysList, err = keyService.ListKeysWithFilters(r.Context(), nil, keyType, tags, true)
	} else {
		// Non-admins list only their keys
		keysList, err = keyService.ListKeysWithFilters(r.Context(), &userID, keyType, tags, false)
	}

	if err != nil {
		c.Err = common.NewAppError("listKeys", "Failed to list keys", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to response format
	response := KeyListResponse{Keys: make([]KeyResponse, len(keysList))}
	for i, key := range keysList {
		response.Keys[i] = KeyResponse{
			ID:        key.ID,
			Name:      key.Name,
			Type:      key.Type,
			UserID:    key.UserID,
			Revoked:   key.Revoked,
			CreatedAt: key.CreatedAt,
			Tags:      key.Tags,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getKey retrieves a specific cryptographic key by ID.
func getKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("getKey", "Invalid key ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user ID from claims
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("getKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("getKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	// Check authorization - users can only access their own keys, admins can access all
	roleStr, ok := c.Claims["role"].(string)
	isAdmin := ok && roleStr == string(model.RoleAdmin)

	// Use service layer with access control validation
	key, err := keyService.GetKey(r.Context(), keyID, userID)
	if err != nil {
		// If not admin and access denied, return forbidden
		if !isAdmin {
			c.Err = common.NewAppError("getKey", "Key not found or access denied", nil, err.Error(), http.StatusNotFound)
			return
		}
		// Admin can try to validate access with admin role
		if err := keyService.ValidateKeyAccess(r.Context(), keyID, userID, roleStr); err != nil {
			c.Err = common.NewAppError("getKey", "Key not found", nil, err.Error(), http.StatusNotFound)
			return
		}
		// Retry get for admin
		key, err = keyService.GetKey(r.Context(), keyID, userID)
		if err != nil {
			c.Err = common.NewAppError("getKey", "Key not found", nil, err.Error(), http.StatusNotFound)
			return
		}
	}

	// Return success response
	response := KeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Type:      key.Type,
		UserID:    key.UserID,
		Revoked:   key.Revoked,
		CreatedAt: key.CreatedAt,
		Tags:      key.Tags,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// updateKey updates a cryptographic key.
func updateKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("updateKey", "Invalid key ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user ID from claims
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("updateKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("updateKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req UpdateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("updateKey", "Invalid JSON request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate at least one field provided
	if req.Name == nil && req.Revoked == nil && req.Tags == nil {
		c.Err = common.NewAppError("updateKey", "At least one update field (name, revoked, tags) must be provided", nil, "", http.StatusBadRequest)
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	// Use service layer for update with access control
	updateReq := keyservices.UpdateKeyRequest{
		KeyID:  keyID,
		Name:   req.Name,
		Tags:   req.Tags,
		UserID: userID,
	}

	if err := keyService.UpdateKey(r.Context(), updateReq); err != nil {
		c.Err = common.NewAppError("updateKey", "Failed to update key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get updated key for response
	key, err := keyService.GetKey(r.Context(), keyID, userID)
	if err != nil {
		c.Err = common.NewAppError("updateKey", "Failed to get updated key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	response := KeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Type:      key.Type,
		UserID:    key.UserID,
		Revoked:   key.Revoked,
		CreatedAt: key.CreatedAt,
		Tags:      key.Tags,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// deleteKey deletes a cryptographic key.
func deleteKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("deleteKey", "Invalid key ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user ID from claims
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("deleteKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("deleteKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	// Use service layer for deletion with access control
	if err := keyService.DeleteKey(r.Context(), keyID, userID); err != nil {
		c.Err = common.NewAppError("deleteKey", "Failed to delete key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusNoContent)
}

// rotateKey rotates a cryptographic key by generating a new key pair and revoking the old key.
func rotateKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("rotateKey", "Invalid key ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user ID from claims
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("rotateKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("rotateKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	keyService := c.keySvc()
	if keyService == nil {
		return
	}

	// Rotate the key using service (handles authorization internally)
	result, err := keyService.RotateKey(r.Context(), keyID, userID)
	if err != nil {
		c.Err = common.NewAppError("rotateKey", "Failed to rotate key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response with the new key
	response := KeyResponse{
		ID:        result.KeyID,
		Name:      result.Name,
		Type:      result.Type,
		UserID:    userID,
		Revoked:   false, // New rotated keys are never revoked
		CreatedAt: result.CreatedAt,
		Tags:      result.Tags,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// wrapKey wraps plaintext key material using the vault key identified by {id}.
func wrapKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("wrapKey", "Invalid key ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("wrapKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("wrapKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req WrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("wrapKey", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}
	if req.PlaintextKey == "" {
		c.Err = common.NewAppError("wrapKey", "plaintext_key is required", nil, "", http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	plaintextBytes, err := base64.StdEncoding.DecodeString(req.PlaintextKey)
	if err != nil {
		c.Err = common.NewAppError("wrapKey", "plaintext_key must be valid base64", nil, err.Error(), http.StatusBadRequest)
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.WrapKey(r.Context(), keyservices.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: plaintextBytes,
		Algorithm:    req.Algorithm,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "forbidden") {
			status = http.StatusForbidden
		} else if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "unsupported algorithm") {
			status = http.StatusBadRequest
		}
		c.Err = common.NewAppError("wrapKey", "Wrap operation failed", nil, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(WrapKeyResponse{
		WrappedKey: base64.StdEncoding.EncodeToString(result.WrappedKey),
		Algorithm:  result.Algorithm,
	})
}

// unwrapKey recovers plaintext key material from wrapped bytes using the vault key identified by {id}.
func unwrapKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("unwrapKey", "Invalid key ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("unwrapKey", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("unwrapKey", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req UnwrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("unwrapKey", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}
	if req.WrappedKey == "" {
		c.Err = common.NewAppError("unwrapKey", "wrapped_key is required", nil, "", http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	wrappedBytes, err := base64.StdEncoding.DecodeString(req.WrappedKey)
	if err != nil {
		c.Err = common.NewAppError("unwrapKey", "wrapped_key must be valid base64", nil, err.Error(), http.StatusBadRequest)
		return
	}

	cryptoSvc := c.cryptoSvc()
	if cryptoSvc == nil {
		return
	}

	result, err := cryptoSvc.UnwrapKey(r.Context(), keyservices.UnwrapKeyRequest{
		KeyID:      keyID,
		UserID:     userID,
		WrappedKey: wrappedBytes,
		Algorithm:  req.Algorithm,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "forbidden") {
			status = http.StatusForbidden
		} else if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "unsupported algorithm") {
			status = http.StatusBadRequest
		}
		c.Err = common.NewAppError("unwrapKey", "Unwrap operation failed", nil, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UnwrapKeyResponse{
		PlaintextKey: base64.StdEncoding.EncodeToString(result.PlaintextKey),
		Algorithm:    result.Algorithm,
	})
}
