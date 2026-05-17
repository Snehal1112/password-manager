package api

import (
	"encoding/json"
	"net/http"
	"time"

	"rocketvault/common"
)

// InitOAuth2 registers the public OAuth2 token endpoint and authenticated service-account routes.
// The token endpoint is placed outside the authenticated ApiRoot subrouter so it doesn't require
// a pre-existing JWT.
//
// Routes:
//   - POST /oauth2/token                          — Client-credentials grant (RFC 6749 §4.4)
//   - POST   /service-accounts                    — Create a new service account
//   - GET    /service-accounts                    — List all service accounts
//   - GET    /service-accounts/{id}               — Get a service account by ID
//   - DELETE /service-accounts/{id}               — Delete a service account
//   - POST   /service-accounts/{id}/rotate        — Rotate client secret
func (api *API) InitOAuth2() {
	api.BaseRoutes.OAuth2.HandleFunc("/oauth2/token", api.tokenHandler).Methods("POST")
	api.Logger.Infoln("OAuth2 token endpoint initialized")

	sa := api.BaseRoutes.ServiceAccounts
	sa.Handle("", ApiSessionRequired(api.App, createServiceAccount)).Methods("POST")
	sa.Handle("", ApiSessionRequired(api.App, listServiceAccounts)).Methods("GET")
	sa.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getServiceAccount)).Methods("GET")
	sa.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteServiceAccount)).Methods("DELETE")
	sa.Handle("/{id:[A-Fa-f0-9-]+}/rotate", ApiSessionRequired(api.App, rotateServiceAccountSecret)).Methods("POST")
	api.Logger.Infoln("Service accounts API routes initialized")
}

// ─── Token endpoint (public) ─────────────────────────────────────────────────

// tokenHandler handles POST /oauth2/token.
// It expects an application/x-www-form-urlencoded body with:
//   - client_id     — the service account name (unique identifier)
//   - client_secret — the plain-text client secret
//   - grant_type    — must be "client_credentials"
//
// On success it returns:
//
//	{ "access_token": "...", "token_type": "Bearer", "expires_in": <seconds> }
func (api *API) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" || clientSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "client_id and client_secret are required"})
		return
	}

	svc := api.App.ServiceContainer.GetOAuth2Service()
	if svc == nil {
		http.Error(w, "OAuth2 service unavailable", http.StatusInternalServerError)
		return
	}

	tokenResp, err := svc.IssueToken(r.Context(), clientID, clientSecret)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// ─── Service-account management handlers (authenticated) ─────────────────────

// createServiceAccount handles POST /service-accounts.
// Admin-only. Body: { "name": "...", "description": "...", "expires_at": "<RFC3339 optional>" }
// Returns the new client object plus the one-time plain-text secret.
func createServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		c.Err = common.NewAppError("createServiceAccount", "Invalid request body — name is required", nil, "", http.StatusBadRequest)
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	client, plainSecret, err := svc.CreateClient(r.Context(), req.Name, req.Description, req.ExpiresAt)
	if err != nil {
		c.Err = common.NewAppError("createServiceAccount", "Failed to create service account", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id":            client.ID.String(),
		"name":          client.Name,
		"description":   client.Description,
		"enabled":       client.Enabled,
		"created_at":    client.CreatedAt,
		"expires_at":    client.ExpiresAt,
		"client_secret": plainSecret, // returned once only
	})
}

// listServiceAccounts handles GET /service-accounts.
func listServiceAccounts(c *Context, w http.ResponseWriter, r *http.Request) {
	svc := c.App.ServiceContainer.GetOAuth2Service()
	clients, err := svc.ListClients(r.Context())
	if err != nil {
		c.Err = common.NewAppError("listServiceAccounts", "Failed to list service accounts", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"service_accounts": clients,
		"total":            len(clients),
	})
}

// getServiceAccount handles GET /service-accounts/{id}.
func getServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "getServiceAccount")
	if appErr != nil {
		c.Err = appErr
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	client, err := svc.GetClient(r.Context(), id)
	if err != nil {
		c.Err = common.NewAppError("getServiceAccount", "Service account not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

// deleteServiceAccount handles DELETE /service-accounts/{id}.
func deleteServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "deleteServiceAccount")
	if appErr != nil {
		c.Err = appErr
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	if err := svc.DeleteClient(r.Context(), id); err != nil {
		c.Err = common.NewAppError("deleteServiceAccount", "Failed to delete service account", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// rotateServiceAccountSecret handles POST /service-accounts/{id}/rotate.
// Returns the new plain-text client secret (one-time).
func rotateServiceAccountSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "rotateServiceAccountSecret")
	if appErr != nil {
		c.Err = appErr
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	newSecret, err := svc.RotateSecret(r.Context(), id)
	if err != nil {
		c.Err = common.NewAppError("rotateServiceAccountSecret", "Failed to rotate client secret", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"client_secret": newSecret, // returned once only
		"message":       "Secret rotated successfully. Store it securely — it will not be shown again.",
	})
}
