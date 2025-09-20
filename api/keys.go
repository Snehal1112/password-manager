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
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"password-manager/common"
	"password-manager/internal/domain"
	"password-manager/internal/db"
	"password-manager/internal/keys"
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
func (api *API) InitKeys(keys *mux.Router) {
	// Basic CRUD operations
	keys.Handle("", ApiSessionRequired(api.App, createKey)).Methods("POST")
	keys.Handle("", ApiSessionRequired(api.App, listKeys)).Methods("GET")
	keys.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getKey)).Methods("GET")
	keys.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateKey)).Methods("PUT")
	keys.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteKey)).Methods("DELETE")

	// Additional operations
	keys.Handle("/{id:[A-Fa-f0-9-]+}/rotate", ApiSessionRequired(api.App, rotateKey)).Methods("POST")

	api.Logger.Infoln("Keys API routes initialized")
}

// createKey creates a new cryptographic key.
func createKey(c *Context, w http.ResponseWriter, r *http.Request) {
	// Check authorization - requires admin or secrets manager role
	claims, ok := c.Claims["role"].(string)
	if !ok || (claims != string(domain.RoleAdmin) && claims != string(domain.RoleSecretsManager)) {
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

	// Initialize database and keys repository
	database := db.NewRepository(c.Logger)
	if err := database.InitializeDB(); err != nil {
		c.Err = common.NewAppError("createKey", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer database.GetDB().Close()

	keyRepo := keys.NewKeyRepository(database.GetDB(), c.Logger)

	var key *keys.Key
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
		key, err = keyRepo.GenerateRSA(r.Context(), userID, req.Name, req.Bits, req.Tags)
	} else {
		// Validate ECDSA curve
		if req.Curve == "" {
			req.Curve = "P-256" // Default ECDSA curve
		}
		if req.Curve != "P-256" && req.Curve != "P-384" && req.Curve != "P-521" {
			c.Err = common.NewAppError("createKey", "Invalid ECDSA curve: must be P-256, P-384, or P-521", nil, "", http.StatusBadRequest)
			return
		}
		key, err = keyRepo.GenerateECDSA(r.Context(), userID, req.Name, req.Curve, req.Tags)
	}

	if err != nil {
		c.Err = common.NewAppError("createKey", "Failed to create key", nil, err.Error(), http.StatusInternalServerError)
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

	// Create key repository
	// Initialize database and keys repository
	database := db.NewRepository(c.Logger)
	if err := database.InitializeDB(); err != nil {
		c.Err = common.NewAppError("listKeys", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer database.GetDB().Close()

	keyRepo := keys.NewKeyRepository(database.GetDB(), c.Logger)

	var keysList []keys.Key
	// Check if user is admin - admins can list all keys
	roleStr, ok := c.Claims["role"].(string)
	if ok && roleStr == string(domain.RoleAdmin) {
		// Admins list all keys with filters
		keysList, err = keyRepo.ListByUser(r.Context(), nil, keyType, tags)
	} else {
		// Non-admins list only their keys
		keysList, err = keyRepo.ListByUser(r.Context(), &userID, keyType, tags)
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

	// Create key repository
	// Initialize database and keys repository
	database := db.NewRepository(c.Logger)
	if err := database.InitializeDB(); err != nil {
		c.Err = common.NewAppError("listKeys", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer database.GetDB().Close()

	keyRepo := keys.NewKeyRepository(database.GetDB(), c.Logger)
	key, err := keyRepo.Read(r.Context(), keyID)
	if err != nil {
		c.Err = common.NewAppError("getKey", "Key not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	// Check authorization - users can only access their own keys, admins can access all
	roleStr, ok := c.Claims["role"].(string)
	if !ok || (key.UserID != userID && roleStr != string(domain.RoleAdmin)) {
		c.Err = common.NewAppError("getKey", "Forbidden: cannot access other users' keys", nil, "", http.StatusForbidden)
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

	// Create key repository
	// Initialize database and keys repository
	database := db.NewRepository(c.Logger)
	if err := database.InitializeDB(); err != nil {
		c.Err = common.NewAppError("listKeys", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer database.GetDB().Close()

	keyRepo := keys.NewKeyRepository(database.GetDB(), c.Logger)
	key, err := keyRepo.Read(r.Context(), keyID)
	if err != nil {
		c.Err = common.NewAppError("updateKey", "Key not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	// Check authorization - users can only update their own keys, admins can update all
	roleStr, ok := c.Claims["role"].(string)
	if !ok || (key.UserID != userID && roleStr != string(domain.RoleAdmin)) {
		c.Err = common.NewAppError("updateKey", "Forbidden: cannot update other users' keys", nil, "", http.StatusForbidden)
		return
	}

	// Apply updates
	updateRequired := false
	if req.Name != nil {
		key.Name = *req.Name
		updateRequired = true
	}
	if req.Revoked != nil {
		key.Revoked = *req.Revoked
		updateRequired = true
	}
	if req.Tags != nil {
		key.Tags = req.Tags
		updateRequired = true
	}

	if !updateRequired {
		c.Err = common.NewAppError("updateKey", "At least one update field (name, revoked, tags) must be provided", nil, "", http.StatusBadRequest)
		return
	}

	// Update the key
	err = keyRepo.Update(r.Context(), key)
	if err != nil {
		c.Err = common.NewAppError("updateKey", "Failed to update key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update tags if provided
	if req.Tags != nil {
		tagRepo := db.NewTagRepository[keys.Key](database.GetDB(), "key_tags", "key_id")
		if err := tagRepo.ReplaceTags(r.Context(), keyID, req.Tags); err != nil {
			c.Err = common.NewAppError("updateKey", "Failed to update tags", nil, err.Error(), http.StatusInternalServerError)
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

	// Create key repository
	// Initialize database and keys repository
	database := db.NewRepository(c.Logger)
	if err := database.InitializeDB(); err != nil {
		c.Err = common.NewAppError("listKeys", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer database.GetDB().Close()

	keyRepo := keys.NewKeyRepository(database.GetDB(), c.Logger)
	key, err := keyRepo.Read(r.Context(), keyID)
	if err != nil {
		c.Err = common.NewAppError("deleteKey", "Key not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	// Check authorization - users can only delete their own keys, admins can delete all
	roleStr, ok := c.Claims["role"].(string)
	if !ok || (key.UserID != userID && roleStr != string(domain.RoleAdmin)) {
		c.Err = common.NewAppError("deleteKey", "Forbidden: cannot delete other users' keys", nil, "", http.StatusForbidden)
		return
	}

	// Delete the key
	err = keyRepo.Delete(r.Context(), keyID)
	if err != nil {
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

	// Create key repository
	// Initialize database and keys repository
	database := db.NewRepository(c.Logger)
	if err := database.InitializeDB(); err != nil {
		c.Err = common.NewAppError("listKeys", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer database.GetDB().Close()

	keyRepo := keys.NewKeyRepository(database.GetDB(), c.Logger)
	key, err := keyRepo.Read(r.Context(), keyID)
	if err != nil {
		c.Err = common.NewAppError("rotateKey", "Key not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	// Check authorization - users can only rotate their own keys, admins can rotate all
	roleStr, ok := c.Claims["role"].(string)
	if !ok || (key.UserID != userID && roleStr != string(domain.RoleAdmin)) {
		c.Err = common.NewAppError("rotateKey", "Forbidden: cannot rotate other users' keys", nil, "", http.StatusForbidden)
		return
	}

	// Rotate the key
	newKey, err := keyRepo.Rotate(r.Context(), keyID)
	if err != nil {
		c.Err = common.NewAppError("rotateKey", "Failed to rotate key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response with the new key
	response := KeyResponse{
		ID:        newKey.ID,
		Name:      newKey.Name,
		Type:      newKey.Type,
		UserID:    newKey.UserID,
		Revoked:   newKey.Revoked,
		CreatedAt: newKey.CreatedAt,
		Tags:      newKey.Tags,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
