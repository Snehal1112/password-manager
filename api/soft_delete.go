package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// listDeletedSecrets returns all soft-deleted secrets for the authenticated user.
func listDeletedSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	repo := c.App.ServiceContainer.GetSecretRepository()
	secrets, err := repo.ListByUserIncludeDeleted(r.Context(), userID, nil)
	if err != nil {
		c.SetInternalError(err)
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
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	// Verify ownership before recovering.
	repo := c.App.ServiceContainer.GetSecretRepository()
	secrets, err := repo.ListByUserIncludeDeleted(r.Context(), userID, nil)
	if err != nil {
		c.SetInternalError(err)
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
		c.SetNotFound("secret")
		return
	}

	if err := repo.RecoverSecret(r.Context(), secretID); err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Secret recovered successfully", "id": secretID.String()})
}

// purgeSecret permanently deletes a soft-deleted secret by ID.
func purgeSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	// Verify ownership before purging.
	repo := c.App.ServiceContainer.GetSecretRepository()
	secrets, err := repo.ListByUserIncludeDeleted(r.Context(), userID, nil)
	if err != nil {
		c.SetInternalError(err)
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
		c.SetNotFound("secret")
		return
	}

	if err := repo.PurgeSecret(r.Context(), secretID); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

// listDeletedKeys returns all soft-deleted keys for the authenticated user.
func listDeletedKeys(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	keys, err := c.App.ServiceContainer.GetKeyRepository().ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
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
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	// Verify ownership via ListSoftDeleted.
	repo := c.App.ServiceContainer.GetKeyRepository()
	keys, err := repo.ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
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
		c.SetNotFound("key")
		return
	}

	if err := repo.RecoverKey(r.Context(), keyID); err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Key recovered successfully", "id": keyID.String()})
}

// purgeKey permanently deletes a soft-deleted key by ID.
func purgeKey(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	// Verify ownership via ListSoftDeleted.
	repo := c.App.ServiceContainer.GetKeyRepository()
	keys, err := repo.ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
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
		c.SetNotFound("key")
		return
	}

	if err := repo.PurgeKey(r.Context(), keyID); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

// listDeletedCertificates returns all soft-deleted certificates for the authenticated user.
func listDeletedCertificates(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	certs, err := c.App.ServiceContainer.GetCertificateRepository().ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
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
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	// Verify ownership via ListSoftDeleted.
	repo := c.App.ServiceContainer.GetCertificateRepository()
	certs, err := repo.ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
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
		c.SetNotFound("certificate")
		return
	}

	if err := repo.RecoverCertificate(r.Context(), certID); err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Certificate recovered successfully", "id": certID.String()})
}

// purgeCertificate permanently deletes a soft-deleted certificate by ID.
func purgeCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	// Verify ownership via ListSoftDeleted.
	repo := c.App.ServiceContainer.GetCertificateRepository()
	certs, err := repo.ListSoftDeleted(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
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
		c.SetNotFound("certificate")
		return
	}

	if err := repo.PurgeCertificate(r.Context(), certID); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

// userIDFromClaims extracts and parses the user UUID from JWT claims.
// Sets c.Err and returns false if the claim is missing or cannot be parsed.
func userIDFromClaims(c *Context) (uuid.UUID, bool) {
	str, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return uuid.Nil, false
	}
	id, err := uuid.Parse(str)
	if err != nil {
		c.SetInvalidParam("user_id")
		return uuid.Nil, false
	}
	return id, true
}

// InitDeleted registers soft-delete management routes.
func (api *API) InitDeleted() {
	r := api.BaseRoutes.Deleted
	r.Handle("/secrets", ApiSessionRequired(api.App, listDeletedSecrets)).Methods("GET")
	r.Handle("/secrets/{secret_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverSecret)).Methods("POST")
	r.Handle("/secrets/{secret_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeSecret)).Methods("DELETE")
	r.Handle("/keys", ApiSessionRequired(api.App, listDeletedKeys)).Methods("GET")
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverKey)).Methods("POST")
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeKey)).Methods("DELETE")
	r.Handle("/certificates", ApiSessionRequired(api.App, listDeletedCertificates)).Methods("GET")
	r.Handle("/certificates/{certificate_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverCertificate)).Methods("POST")
	r.Handle("/certificates/{certificate_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeCertificate)).Methods("DELETE")
}
