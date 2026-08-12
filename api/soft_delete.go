package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/model"
)

// listDeletedSecrets returns all soft-deleted secrets in the resolved vault.
// The vault is read from the request context (falling back to the default
// vault for legacy flat routes), so the listing honours the vault-scoped
// /vaults/{name}/deleted/secrets route. Per the visibility model, any caller
// authorized for a vault sees all of its soft-deleted secrets.
func listDeletedSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	// Resolve the target vault from the request context.
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	secretSvc := c.secretSvc()
	if secretSvc == nil {
		return
	}

	secrets, err := secretSvc.ListDeletedSecrets(r.Context(), model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// The service already filters to soft-deleted entries only.
	var deleted []map[string]any
	for _, s := range secrets {
		deleted = append(deleted, map[string]any{
			"id":         s.ID.String(),
			"name":       s.Name,
			"version":    s.Version,
			"deleted_at": s.DeletedAt,
			"created_at": s.CreatedAt,
		})
	}
	if deleted == nil {
		deleted = []map[string]any{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted_secrets": deleted, "total": len(deleted)}) //nolint:errcheck,gosec
}

// recoverSecret restores a soft-deleted secret by ID.
func recoverSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	secretSvc := c.secretSvc()
	if secretSvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := secretSvc.RecoverSecret(r.Context(), secretID, scope); err != nil {
		writeSecretError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Secret recovered successfully", "id": secretID.String()}) //nolint:errcheck,gosec
}

// purgeSecret permanently deletes a soft-deleted secret by ID.
func purgeSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	secretSvc := c.secretSvc()
	if secretSvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := secretSvc.PurgeSecret(r.Context(), secretID, scope); err != nil {
		writeSecretError(c, err)
		return
	}

	ReturnStatusOK(w)
}

// listDeletedKeys returns all soft-deleted keys in the resolved vault. The
// vault is read from the request context (falling back to the default vault
// for legacy flat routes), so the listing honours the vault-scoped
// /vaults/{name}/deleted/keys route. Per the visibility model, any caller
// authorized for a vault sees all of its soft-deleted keys (mirrors
// listDeletedSecrets).
func listDeletedKeys(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}

	keys, err := keySvc.ListDeletedKeys(r.Context(), model.NewVaultScope(vaultID, userID))
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
	json.NewEncoder(w).Encode(map[string]any{"deleted_keys": items, "total": len(items)}) //nolint:errcheck,gosec
}

// getDeletedKey returns a single soft-deleted key by its UUID, resolved
// within the same vault scope as listDeletedKeys. It has no vault-scoped
// route counterpart (secrets doesn't have a single-item deleted GET either),
// so it stays registered on the flat router only, where it resolves to the
// default vault.
func getDeletedKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}

	keys, err := keySvc.ListDeletedKeys(r.Context(), model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	for _, k := range keys {
		if k.ID == keyID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec
				"id":               k.ID.String(),
				"name":             k.Name,
				"type":             k.Type,
				"deleted_at":       k.DeletedAt,
				"purge_protection": k.PurgeProtection,
			})
			return
		}
	}
	c.SetNotFound("key")
}

// recoverKey restores a soft-deleted key by ID.
func recoverKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := keySvc.RecoverKey(r.Context(), keyID, scope); err != nil {
		writeKeyError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Key recovered successfully", "id": keyID.String()}) //nolint:errcheck,gosec
}

// purgeKey permanently deletes a soft-deleted key by ID.
func purgeKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(c.Params.KeyID)
	if err != nil {
		c.SetInvalidParam("key_id")
		return
	}

	keySvc := c.keySvc()
	if keySvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := keySvc.PurgeKey(r.Context(), keyID, scope); err != nil {
		writeKeyError(c, err)
		return
	}

	ReturnStatusOK(w)
}

// listDeletedCertificates returns all soft-deleted certificates in the
// resolved vault, mirroring listDeletedKeys/listDeletedSecrets.
func listDeletedCertificates(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	certs, err := certSvc.ListDeletedCertificates(r.Context(), model.NewVaultScope(vaultID, userID))
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
	json.NewEncoder(w).Encode(map[string]any{"deleted_certificates": items, "total": len(items)}) //nolint:errcheck,gosec
}

// recoverCertificate restores a soft-deleted certificate by ID.
func recoverCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := certSvc.RecoverCertificate(r.Context(), certID, scope); err != nil {
		writeCertificateError(c, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"message": "Certificate recovered successfully", "id": certID.String()}) //nolint:errcheck,gosec
}

// purgeCertificate permanently deletes a soft-deleted certificate by ID.
func purgeCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	certSvc := c.certSvc()
	if certSvc == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	if err := certSvc.PurgeCertificate(r.Context(), certID, scope); err != nil {
		writeCertificateError(c, err)
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
//
// All seven deleted-flow handlers (secrets, keys, certificates) are now
// vault-aware: they read the vault from the request context via
// scopeFromRequest/vaultIDFromRequest, so they are registered on both the
// legacy flat routes and the vault-scoped subrouter. getDeletedKey is the one
// exception — it has no vault-scoped route because it has no secrets
// equivalent to mirror (secrets exposes no single-item deleted GET either);
// it stays flat-only and resolves to the default vault.
func (api *API) InitDeleted() {
	api.registerDeletedRoutes(api.BaseRoutes.Deleted)
	if api.BaseRoutes.VaultScoped != nil {
		api.registerVaultScopedDeletedRoutes(api.BaseRoutes.VaultScoped.PathPrefix("/deleted").Subrouter())
	}
}

// registerDeletedRoutes registers all soft-delete handlers on the legacy flat
// routes. These resolve to the default vault / owner scope.
func (api *API) registerDeletedRoutes(r *mux.Router) {
	api.registerVaultScopedDeletedRoutes(r)

	// getDeletedKey has no vault-scoped counterpart; see the InitDeleted comment.
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getDeletedKey)).Methods("GET")
}

// registerVaultScopedDeletedRoutes registers the vault-aware soft-delete
// handlers for all three resource types. List handlers honour the resolved
// vault; restore/purge operate by globally-unique ID so they already act on
// the correct object once scoped.
func (api *API) registerVaultScopedDeletedRoutes(r *mux.Router) {
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
