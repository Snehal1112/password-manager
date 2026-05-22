package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/model"
)

// InitOAuth2 registers the public OAuth2 token endpoint and authenticated service-account routes.
// The token endpoint is placed outside the authenticated ApiRoot subrouter so it doesn't require
// a pre-existing JWT.
//
// Routes:
//   - POST /oauth2/token                          — Client-credentials grant (RFC 6749 §4.4)
//   - POST   /service-accounts                    — Create a new service account
//   - GET    /service-accounts                    — List all service accounts
//   - GET    /service-accounts/{service_account_id}               — Get a service account by ID
//   - DELETE /service-accounts/{service_account_id}               — Delete a service account
//   - POST   /service-accounts/{service_account_id}/rotate        — Rotate client secret
func (api *API) InitOAuth2() {
	api.BaseRoutes.OAuth2.HandleFunc("/oauth2/token", api.tokenHandler).Methods("POST")
	api.Logger.Infoln("OAuth2 token endpoint initialized")

	sa := api.BaseRoutes.ServiceAccounts
	sa.Handle("", ApiSessionRequired(api.App, createServiceAccount)).Methods("POST")
	sa.Handle("", ApiSessionRequired(api.App, listServiceAccounts)).Methods("GET")
	sa.Handle("/{service_account_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getServiceAccount)).Methods("GET")
	sa.Handle("/{service_account_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteServiceAccount)).Methods("DELETE")
	sa.Handle("/{service_account_id:[A-Fa-f0-9-]+}/rotate", ApiSessionRequired(api.App, rotateServiceAccountSecret)).Methods("POST")
	api.Logger.Infoln("Service accounts API routes initialized")
}

// ─── Token endpoint (public) ─────────────────────────────────────────────────

// tokenHandler handles POST /oauth2/token.
//
// Accepts client credentials via two methods (RFC 6749 §2.3.1):
//   - HTTP Basic authentication: Authorization: Basic base64(client_id:client_secret)
//   - Request body: client_id and client_secret as form parameters
//
// Body must be application/x-www-form-urlencoded with grant_type=client_credentials.
//
// On success returns (RFC 6749 §5.1):
//
//	{ "access_token": "...", "token_type": "Bearer", "expires_in": <seconds> }
func (api *API) tokenHandler(w http.ResponseWriter, r *http.Request) {
	// RFC 6749 §5.1 MUST: prevent caching of token responses.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Enforce Content-Type — credentials MUST be in the body, not the query string (RFC 6749 §2.3.1).
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported")
		return
	}

	// Resolve client credentials: HTTP Basic takes priority over form body (RFC 6749 §2.3.1).
	clientID, clientSecret, ok := extractClientCredentials(r)
	if !ok || clientID == "" || clientSecret == "" {
		// RFC 6749 §5.2: respond with 401 + WWW-Authenticate when credentials are missing/malformed.
		w.Header().Set("WWW-Authenticate", `Basic realm="rocketvault"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	svc := api.App.ServiceContainer.GetOAuth2Service()
	if svc == nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "authorization server is temporarily unavailable")
		return
	}

	tokenResp, err := svc.IssueToken(r.Context(), clientID, clientSecret)
	if err != nil {
		// RFC 6749 §5.2: 401 + WWW-Authenticate for invalid_client.
		w.Header().Set("WWW-Authenticate", `Basic realm="rocketvault"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenResp) //nolint:errcheck
}

// extractClientCredentials resolves client_id and client_secret from the request.
// HTTP Basic (Authorization header) takes priority over form body per RFC 6749 §2.3.1.
func extractClientCredentials(r *http.Request) (clientID, clientSecret string, ok bool) {
	// Try HTTP Basic first.
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			return "", "", false
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		return parts[0], parts[1], true
	}

	// Fall back to form body.
	return r.FormValue("client_id"), r.FormValue("client_secret"), true
}

// writeTokenError writes an RFC 6749 §5.2 compliant JSON error response.
// Cache-control headers must already be set by the caller.
func writeTokenError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"error":             errCode,
		"error_description": description,
	})
}

// ─── Service-account management handlers (authenticated) ─────────────────────

// createServiceAccount handles POST /service-accounts.
// Admin-only. Body: { "name": "...", "description": "...", "expires_at": "<RFC3339 optional>" }
// Returns the new client object plus the one-time plain-text secret.
func createServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	roleStr, _ := c.Claims["role"].(string)
	if !common.HasRequiredRole(roleStr, model.RoleAdmin) {
		c.SetPermissionError("admin role required to create service accounts")
		return
	}

	var req struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		c.SetInvalidParam("name is required")
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	client, plainSecret, err := svc.CreateClient(r.Context(), req.Name, req.Description, req.ExpiresAt)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
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
	// Enforce admin-only access to prevent privilege escalation.
	roleStr, _ := c.Claims["role"].(string)
	if !common.HasRequiredRole(roleStr, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage service accounts")
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	clients, err := svc.ListClients(r.Context())
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"service_accounts": clients,
		"total":            len(clients),
	})
}

// getServiceAccount handles GET /service-accounts/{service_account_id}.
func getServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	roleStr, _ := c.Claims["role"].(string)
	if !common.HasRequiredRole(roleStr, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage service accounts")
		return
	}

	id, err := uuid.Parse(c.Params.ServiceAccountID)
	if err != nil {
		c.SetInvalidParam("service_account_id")
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	client, err := svc.GetClient(r.Context(), id)
	if err != nil {
		c.SetNotFound("service account")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client) //nolint:errcheck
}

// deleteServiceAccount handles DELETE /service-accounts/{service_account_id}.
func deleteServiceAccount(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	roleStr, _ := c.Claims["role"].(string)
	if !common.HasRequiredRole(roleStr, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage service accounts")
		return
	}

	id, err := uuid.Parse(c.Params.ServiceAccountID)
	if err != nil {
		c.SetInvalidParam("service_account_id")
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	if err := svc.DeleteClient(r.Context(), id); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

// rotateServiceAccountSecret handles POST /service-accounts/{service_account_id}/rotate.
// Returns the new plain-text client secret (one-time).
func rotateServiceAccountSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	// Enforce admin-only access to prevent privilege escalation.
	roleStr, _ := c.Claims["role"].(string)
	if !common.HasRequiredRole(roleStr, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage service accounts")
		return
	}

	id, err := uuid.Parse(c.Params.ServiceAccountID)
	if err != nil {
		c.SetInvalidParam("service_account_id")
		return
	}

	svc := c.App.ServiceContainer.GetOAuth2Service()
	newSecret, err := svc.RotateSecret(r.Context(), id)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"client_secret": newSecret, // returned once only — store securely
	})
}
