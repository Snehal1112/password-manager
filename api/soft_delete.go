package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/common"
)

// listDeletedSecrets returns all soft-deleted secrets for the authenticated user.
func listDeletedSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "listDeletedSecrets")
	if appErr != nil {
		c.Err = appErr
		return
	}

	repo := c.App.ServiceContainer.GetSecretRepository()
	secrets, err := repo.ListByUserIncludeDeleted(r.Context(), userID, nil)
	if err != nil {
		c.Err = common.NewAppError("listDeletedSecrets", "Failed to list deleted secrets", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Filter to only soft-deleted entries.
	var deleted []map[string]any
	for _, s := range secrets {
		if s.DeletedAt != nil {
			deleted = append(deleted, map[string]any{
				"id":         s.ID.String(),
				"name":       s.Name,
				"version":    s.Version,
				"deleted_at": s.DeletedAt,
				"created_at": s.CreatedAt,
			})
		}
	}
	if deleted == nil {
		deleted = []map[string]any{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted_secrets": deleted, "total": len(deleted)})
}

// recoverSecret restores a soft-deleted secret by ID.
func recoverSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "recoverSecret")
	if appErr != nil {
		c.Err = appErr
		return
	}

	secretID, appErr := resourceIDFromVars(c, r, "recoverSecret")
	if appErr != nil {
		c.Err = appErr
		return
	}

	// Verify ownership before recovering.
	repo := c.App.ServiceContainer.GetSecretRepository()
	secrets, err := repo.ListByUserIncludeDeleted(r.Context(), userID, nil)
	if err != nil {
		c.Err = common.NewAppError("recoverSecret", "Failed to verify secret ownership", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	found := false
	for _, s := range secrets {
		if s.ID == secretID && s.UserID == userID {
			found = true
			break
		}
	}
	if !found {
		c.Err = common.NewAppError("recoverSecret", "Secret not found or access denied", nil, "", http.StatusNotFound)
		return
	}

	if err := repo.RecoverSecret(r.Context(), secretID); err != nil {
		c.Err = common.NewAppError("recoverSecret", "Failed to recover secret", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Secret recovered successfully", "id": secretID.String()})
}

// purgeSecret permanently deletes a soft-deleted secret by ID.
func purgeSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "purgeSecret")
	if appErr != nil {
		c.Err = appErr
		return
	}

	secretID, appErr := resourceIDFromVars(c, r, "purgeSecret")
	if appErr != nil {
		c.Err = appErr
		return
	}

	// Verify ownership before purging.
	repo := c.App.ServiceContainer.GetSecretRepository()
	secrets, err := repo.ListByUserIncludeDeleted(r.Context(), userID, nil)
	if err != nil {
		c.Err = common.NewAppError("purgeSecret", "Failed to verify secret ownership", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	found := false
	for _, s := range secrets {
		if s.ID == secretID && s.UserID == userID {
			found = true
			break
		}
	}
	if !found {
		c.Err = common.NewAppError("purgeSecret", "Secret not found or access denied", nil, "", http.StatusNotFound)
		return
	}

	if err := repo.PurgeSecret(r.Context(), secretID); err != nil {
		c.Err = common.NewAppError("purgeSecret", "Failed to purge secret", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// listDeletedKeys returns all soft-deleted keys for the authenticated user.
func listDeletedKeys(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "listDeletedKeys")
	if appErr != nil {
		c.Err = appErr
		return
	}

	keys, err := c.App.ServiceContainer.GetKeyRepository().ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("listDeletedKeys", "Failed to list deleted keys", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	type keyItem struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Type            string `json:"type"`
		DeletedAt       any    `json:"deleted_at"`
		PurgeProtection bool   `json:"purge_protection"`
	}

	items := make([]keyItem, len(keys))
	for i, k := range keys {
		items[i] = keyItem{
			ID:              k.ID.String(),
			Name:            k.Name,
			Type:            k.Type,
			DeletedAt:       k.DeletedAt,
			PurgeProtection: k.PurgeProtection,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted_keys": items, "total": len(items)})
}

// recoverKey restores a soft-deleted key by ID.
func recoverKey(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "recoverKey")
	if appErr != nil {
		c.Err = appErr
		return
	}

	keyID, appErr := resourceIDFromVars(c, r, "recoverKey")
	if appErr != nil {
		c.Err = appErr
		return
	}

	// Verify ownership via ListSoftDeleted.
	repo := c.App.ServiceContainer.GetKeyRepository()
	keys, err := repo.ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("recoverKey", "Failed to verify key ownership", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	found := false
	for _, k := range keys {
		if k.ID == keyID {
			found = true
			break
		}
	}
	if !found {
		c.Err = common.NewAppError("recoverKey", "Key not found in deleted state or access denied", nil, "", http.StatusNotFound)
		return
	}

	if err := repo.RecoverKey(r.Context(), keyID); err != nil {
		c.Err = common.NewAppError("recoverKey", "Failed to recover key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Key recovered successfully", "id": keyID.String()})
}

// purgeKey permanently deletes a soft-deleted key by ID.
func purgeKey(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "purgeKey")
	if appErr != nil {
		c.Err = appErr
		return
	}

	keyID, appErr := resourceIDFromVars(c, r, "purgeKey")
	if appErr != nil {
		c.Err = appErr
		return
	}

	// Verify ownership via ListSoftDeleted.
	repo := c.App.ServiceContainer.GetKeyRepository()
	keys, err := repo.ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("purgeKey", "Failed to verify key ownership", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	found := false
	for _, k := range keys {
		if k.ID == keyID {
			found = true
			break
		}
	}
	if !found {
		c.Err = common.NewAppError("purgeKey", "Key not found in deleted state or access denied", nil, "", http.StatusNotFound)
		return
	}

	if err := repo.PurgeKey(r.Context(), keyID); err != nil {
		c.Err = common.NewAppError("purgeKey", "Failed to purge key", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// listDeletedCertificates returns all soft-deleted certificates for the authenticated user.
func listDeletedCertificates(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "listDeletedCertificates")
	if appErr != nil {
		c.Err = appErr
		return
	}

	certs, err := c.App.ServiceContainer.GetCertificateRepository().ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("listDeletedCertificates", "Failed to list deleted certificates", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	type certItem struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		DeletedAt       any    `json:"deleted_at"`
		PurgeProtection bool   `json:"purge_protection"`
	}

	items := make([]certItem, len(certs))
	for i, cert := range certs {
		items[i] = certItem{
			ID:              cert.ID.String(),
			Name:            cert.Name,
			DeletedAt:       cert.DeletedAt,
			PurgeProtection: cert.PurgeProtection,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted_certificates": items, "total": len(items)})
}

// recoverCertificate restores a soft-deleted certificate by ID.
func recoverCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "recoverCertificate")
	if appErr != nil {
		c.Err = appErr
		return
	}

	certID, appErr := resourceIDFromVars(c, r, "recoverCertificate")
	if appErr != nil {
		c.Err = appErr
		return
	}

	// Verify ownership via ListSoftDeleted.
	repo := c.App.ServiceContainer.GetCertificateRepository()
	certs, err := repo.ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("recoverCertificate", "Failed to verify certificate ownership", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	found := false
	for _, cert := range certs {
		if cert.ID == certID {
			found = true
			break
		}
	}
	if !found {
		c.Err = common.NewAppError("recoverCertificate", "Certificate not found in deleted state or access denied", nil, "", http.StatusNotFound)
		return
	}

	if err := repo.RecoverCertificate(r.Context(), certID); err != nil {
		c.Err = common.NewAppError("recoverCertificate", "Failed to recover certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Certificate recovered successfully", "id": certID.String()})
}

// purgeCertificate permanently deletes a soft-deleted certificate by ID.
func purgeCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, appErr := userIDFromClaims(c, "purgeCertificate")
	if appErr != nil {
		c.Err = appErr
		return
	}

	certID, appErr := resourceIDFromVars(c, r, "purgeCertificate")
	if appErr != nil {
		c.Err = appErr
		return
	}

	// Verify ownership via ListSoftDeleted.
	repo := c.App.ServiceContainer.GetCertificateRepository()
	certs, err := repo.ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("purgeCertificate", "Failed to verify certificate ownership", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	found := false
	for _, cert := range certs {
		if cert.ID == certID {
			found = true
			break
		}
	}
	if !found {
		c.Err = common.NewAppError("purgeCertificate", "Certificate not found in deleted state or access denied", nil, "", http.StatusNotFound)
		return
	}

	if err := repo.PurgeCertificate(r.Context(), certID); err != nil {
		c.Err = common.NewAppError("purgeCertificate", "Failed to purge certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// userIDFromClaims extracts and parses the user UUID from JWT claims.
// It returns an AppError if the claim is missing or cannot be parsed.
func userIDFromClaims(c *Context, op string) (uuid.UUID, *common.AppError) {
	str, ok := c.Claims["user_id"].(string)
	if !ok {
		return uuid.Nil, common.NewAppError(op, "Missing user ID in token", nil, "", http.StatusUnauthorized)
	}
	id, err := uuid.Parse(str)
	if err != nil {
		return uuid.Nil, common.NewAppError(op, "Invalid user ID format", nil, err.Error(), http.StatusBadRequest)
	}
	return id, nil
}

// resourceIDFromVars extracts and parses the resource UUID from URL path variables.
// It returns an AppError if the variable is missing or cannot be parsed.
func resourceIDFromVars(c *Context, r *http.Request, op string) (uuid.UUID, *common.AppError) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		return uuid.Nil, common.NewAppError(op, "Invalid resource ID", nil, err.Error(), http.StatusBadRequest)
	}
	return id, nil
}
