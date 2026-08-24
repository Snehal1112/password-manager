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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/common"
	"rocketvault/internal/services/secrets"
	vvalidation "rocketvault/internal/validation"
	"rocketvault/model"
)

// InitSecrets initializes the routes for secrets management API.
// It sets up the following endpoints:
// - POST /secrets: Create a new secret.
// - GET /secrets: List all secrets for authenticated user.
// - GET /secrets/{secret_id}: Get a specific secret by ID.
// - PUT /secrets/{secret_id}: Update a secret.
// - DELETE /secrets/{secret_id}: Delete a secret.
// - POST /secrets/generate: Generate a random password/secret.
// - POST /secrets/export: Export secrets in JSON or CSV format.
// - POST /secrets/import: Import secrets from JSON or CSV format.
func (api *API) InitSecrets() {
	api.registerSecretRoutes(api.BaseRoutes.Secrets, "legacy")
	if api.BaseRoutes.VaultScoped != nil {
		api.registerSecretRoutes(api.BaseRoutes.VaultScoped.PathPrefix("/secrets").Subrouter(), "vault-scoped")
	}
}

// registerSecretRoutes registers the secret handlers on the provided subrouter.
// It is called once for the legacy flat routes and once for the vault-scoped
// routes so both URL shapes resolve to the same handlers.
func (api *API) registerSecretRoutes(s *mux.Router, scope string) {
	// Basic CRUD operations on the collection.
	s.Handle("", ApiSessionRequired(api.App, createSecret)).Methods("POST")
	s.Handle("", ApiSessionRequired(api.App, listSecrets)).Methods("GET")
	s.Handle("/{secret_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getSecret)).Methods("GET")
	s.Handle("/{secret_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateSecret)).Methods("PUT")
	s.Handle("/{secret_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteSecret)).Methods("DELETE")

	// Additional operations.
	s.Handle("/generate", ApiSessionRequired(api.App, generateSecret)).Methods("POST")
	s.Handle("/export", ApiSessionRequired(api.App, exportSecrets)).Methods("POST")
	s.Handle("/import", ApiSessionRequired(api.App, importSecrets)).Methods("POST")

	// Secret versioning endpoints.
	s.Handle("/{secret_id:[A-Fa-f0-9-]+}/versions", ApiSessionRequired(api.App, listSecretVersionsHandler)).Methods("GET")
	s.Handle("/{secret_id:[A-Fa-f0-9-]+}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getSecretVersionHandler)).Methods("GET")
	s.Handle("/{secret_id:[A-Fa-f0-9-]+}/versions/latest", ApiSessionRequired(api.App, getLatestSecretVersionHandler)).Methods("GET")

	api.Logger.WithField("scope", scope).Infoln("Secrets API routes initialized")
}

// listSecretVersionsHandler lists all versions of a secret.
func listSecretVersionsHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Metadata only, and metadata only by construction: this route is
	// authorized by ActionSecretsReadMetadata, which Key Vault Reader holds.
	// It previously called GetSecretVersions, which decrypts every version,
	// so a Reader could read every historical plaintext value of the secret
	// (.claude/known-bugs.md § B30). A value is read through
	// GET /secrets/{id}/versions/{n}, which requires ActionSecretsGet.
	versions, err := secretService.GetSecretVersionsMetadata(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions) //nolint:errcheck,gosec
}

// getSecretVersionHandler retrieves a specific version of a secret.
func getSecretVersionHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}
	versionNum := c.Params.Version

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := secretService.GetSecretVersion(r.Context(), secretID, versionNum, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version) //nolint:errcheck,gosec
}

// getLatestSecretVersionHandler retrieves the latest version of a secret.
func getLatestSecretVersionHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := secretService.GetLatestSecretVersion(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version) //nolint:errcheck,gosec
}

// exportSecrets handles the export of secrets to encrypted files.
// Supports JSON and CSV formats with optional encryption.
func exportSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body using model type.
	exportReq, err := model.ExportSecretsRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Validate format.
	if exportReq.Format != "json" && exportReq.Format != "csv" {
		c.SetInvalidParam("format: must be 'json' or 'csv'")
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Use service layer for export.
	serviceReq := secrets.ExportSecretsRequest{
		Scope:       scope,
		Format:      exportReq.Format,
		FilterTags:  exportReq.Tags,
		IncludeTags: exportReq.IncludeTags,
		Encrypt:     exportReq.Encrypt,
		Passphrase:  exportReq.Passphrase,
	}

	data, err := secretService.ExportSecrets(r.Context(), serviceReq)
	if err != nil {
		writeSecretError(c, err)
		return
	}

	// Set response headers.
	contentType := "application/json"
	if exportReq.Format == "csv" {
		contentType = "text/csv"
	}

	filename := fmt.Sprintf("secrets-export-%s.%s", time.Now().Format("20060102-150405"), exportReq.Format)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	// Write raw file bytes.
	w.WriteHeader(http.StatusOK)
	w.Write(data) //nolint:errcheck,gosec

	c.Logger.Printf("User %s exported secrets in %s format", c.Claims.UserID, exportReq.Format)
}

// importSecrets handles the import of secrets from encrypted files.
// Accepts multipart form data with file, format, and options.
func importSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse multipart form.
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB max.
		c.SetInvalidParam("request body: failed to parse multipart form")
		return
	}

	// Get file from form.
	file, _, err := r.FormFile("file")
	if err != nil {
		c.SetInvalidParam("file: missing or invalid")
		return
	}
	defer file.Close() //nolint:errcheck

	// Read file data.
	data, err := io.ReadAll(file)
	if err != nil {
		c.SetInvalidParam("file: failed to read")
		return
	}

	// Get form parameters.
	format := r.FormValue("format")
	if format != "json" && format != "csv" {
		c.SetInvalidParam("format: must be 'json' or 'csv'")
		return
	}

	overwrite := r.FormValue("overwrite") == "true"

	// A sealed export must be opened here, in the handler, not in the
	// service: this is the only layer with a passphrase channel (the
	// "passphrase" form field). ImportSecrets refuses sealed data outright
	// by design (see secret_service.go's ImportSecrets) — plaintext must
	// reach it. This mirrors cmd/secrets/import.go's own detect-then-open
	// sequence exactly. The passphrase form value is used only for this
	// OpenExport call; it is never logged and never reaches the service.
	if common.IsSealedExport(data) {
		opened, openErr := common.OpenExport(data, r.FormValue("passphrase"))
		if openErr != nil {
			writeSecretError(c, openErr)
			return
		}
		data = opened
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Use service layer for import.
	serviceReq := secrets.ImportSecretsRequest{
		Scope:     scope,
		Data:      data,
		Format:    format,
		Overwrite: overwrite,
	}

	result, err := secretService.ImportSecrets(r.Context(), serviceReq)
	if err != nil {
		writeSecretError(c, err)
		return
	}

	// Prepare response using model type.
	response := model.ImportResponse{
		Success:       true,
		Message:       fmt.Sprintf("Successfully imported %d/%d secrets", result.ImportedCount, result.TotalCount),
		ImportedCount: result.ImportedCount,
		TotalCount:    result.TotalCount,
		Format:        format,
		ImportedAt:    time.Now().Format(time.RFC3339),
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s imported %d/%d secrets from %s format",
		c.Claims.UserID, result.ImportedCount, result.TotalCount, format)
}

// createSecret handles the creation of a new secret.
func createSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body using model type.
	req, err := model.CreateSecretRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Validate required fields.
	if req.Name == "" {
		c.SetInvalidParam("name is required")
		return
	}
	if req.Value == "" {
		c.SetInvalidParam("value is required")
		return
	}

	// Validate name format, value size, and tag limits.
	if err := vvalidation.ValidateSecretCreate(vvalidation.SecretCreateRequest{
		Name:  req.Name,
		Value: req.Value,
		Tags:  req.Tags,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	// Get user ID from JWT claims.
	userID, err := uuid.Parse(c.Claims.UserID)
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

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	// Create secret using service layer (which handles encryption).
	createReq := secrets.CreateSecretRequest{
		UserID:          userID,
		VaultID:         vaultID,
		Name:            req.Name,
		Value:           req.Value,
		Tags:            req.Tags,
		ContentType:     req.ContentType,
		Enabled:         req.Enabled,
		ExpiresAt:       req.ExpiresAt,
		NotBefore:       req.NotBefore,
		PurgeProtection: req.PurgeProtection,
	}

	secret, err := secretService.CreateSecret(r.Context(), createReq)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Prepare response (without value for security).
	response := model.SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Tags:        secret.Tags,
		Version:     secret.Version,
		ContentType: secret.ContentType,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
		Enabled:     secret.Enabled,
		ExpiresAt:   secret.ExpiresAt,
		NotBefore:   secret.NotBefore,
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s created secret %s", c.Claims.UserID, secret.Name)
}

// listSecrets handles the HTTP request to list secrets. Legacy flat routes
// list the default vault; explicit vault-scoped routes list the vault named
// in the path. Both use vault-level "members see all" visibility. Supports
// filtering by tags.
func listSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	secretsList, err := secretService.ListSecrets(r.Context(), scope, c.Params.Tags, c.Params.PerPage, c.Params.Page*c.Params.PerPage)
	if err != nil {
		writeSecretError(c, err)
		return
	}

	// Convert to response format (without values for security).
	secretResponses := make([]model.SecretResponse, len(secretsList))
	for i, secret := range secretsList {
		secretResponses[i] = model.SecretResponse{
			ID:        secret.ID.String(),
			Name:      secret.Name,
			Tags:      secret.Tags,
			Version:   secret.Version,
			CreatedAt: secret.CreatedAt.Format(time.RFC3339),
			Enabled:   secret.Enabled,
		}
	}

	response := model.ListSecretsResponse{
		Secrets: secretResponses,
		Total:   len(secretsList),
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec
}

// getSecret handles the HTTP request to retrieve a secret by its ID.
// Returns the secret with its decrypted value.
func getSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	secret, err := secretService.GetSecret(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}

	// Prepare response (include value for get operation).
	response := model.SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Value:       secret.Value,
		Tags:        secret.Tags,
		Version:     secret.Version,
		ContentType: secret.ContentType,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
		Enabled:     secret.Enabled,
		ExpiresAt:   secret.ExpiresAt,
		NotBefore:   secret.NotBefore,
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("Secret %s accessed", secret.Name)
}

// updateSecret handles the HTTP request to update a secret by its ID.
// Increments the version on change.
func updateSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	// Parse request body using model type.
	req, err := model.UpdateSecretRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Validate name format, value size, and tag limits.
	var updateName, updateValue *string
	if req.Name != "" {
		updateName = &req.Name
	}
	if req.Value != "" {
		updateValue = &req.Value
	}
	if err := vvalidation.ValidateSecretUpdate(vvalidation.SecretUpdateRequest{
		Name:      updateName,
		Value:     updateValue,
		Tags:      req.Tags,
		ExpiresAt: req.ExpiresAt,
		NotBefore: req.NotBefore,
	}); err != nil {
		c.SetInvalidParam(err.Error())
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	secret, err := secretService.GetSecret(r.Context(), secretID, scope)
	if err != nil {
		writeSecretError(c, err)
		return
	}

	// Update fields.
	updated := false
	if req.Name != "" && req.Name != secret.Name {
		secret.Name = req.Name
		updated = true
	}
	if req.Value != "" && req.Value != secret.Value {
		secret.Value = req.Value
		updated = true
	}
	if req.Tags != nil {
		secret.Tags = req.Tags
		updated = true
	}
	if req.ContentType != nil && *req.ContentType != secret.ContentType {
		secret.ContentType = *req.ContentType
		updated = true
	}
	if req.Enabled != nil {
		secret.Enabled = *req.Enabled
		updated = true
	}
	if req.ExpiresAt != nil {
		secret.ExpiresAt = req.ExpiresAt
		updated = true
	}
	if req.NotBefore != nil {
		secret.NotBefore = req.NotBefore
		updated = true
	}
	// Purge protection is persisted by the service, not by this handler, but it
	// still counts as a change so a protection-only request is not rejected.
	if req.PurgeProtection != nil {
		secret.PurgeProtection = *req.PurgeProtection
		updated = true
	}

	if !updated {
		c.SetInvalidParam("no changes provided")
		return
	}

	// Increment version.
	secret.Version++

	// Update secret.
	updateReq := secrets.UpdateSecretRequest{
		SecretID:        secret.ID,
		Scope:           scope,
		Name:            &secret.Name,
		Value:           &secret.Value,
		Tags:            &secret.Tags,
		ContentType:     req.ContentType,
		Enabled:         req.Enabled,
		ExpiresAt:       req.ExpiresAt,
		NotBefore:       req.NotBefore,
		PurgeProtection: req.PurgeProtection,
	}
	if err := secretService.UpdateSecret(r.Context(), updateReq); err != nil {
		writeSecretError(c, err)
		return
	}

	// Prepare response (without value for security).
	response := model.SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Tags:        secret.Tags,
		Version:     secret.Version,
		ContentType: secret.ContentType,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
		Enabled:     secret.Enabled,
		ExpiresAt:   secret.ExpiresAt,
		NotBefore:   secret.NotBefore,
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s updated secret %s", scope.ActorID(), secret.Name)
}

// deleteSecret handles the HTTP request to delete a secret by its ID.
func deleteSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	// deleteSecret builds its scope explicitly rather than calling
	// scopeFromRequest. Both now produce the same vault scope, so this is
	// belt-and-braces: it keeps the handler correct even if route-shape
	// branching is ever reintroduced into the shared helper.
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}
	scope := model.NewVaultScope(vaultID, userID)

	if err := secretService.DeleteSecret(r.Context(), secretID, scope); err != nil {
		writeSecretError(c, err)
		return
	}

	ReturnStatusOK(w)

	c.Logger.Printf("User %s deleted secret %s", userID, secretID.String())
}

// generateSecret handles the generation of random passwords or secrets.
func generateSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body using model type.
	req, err := model.GenerateSecretRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Validate request.
	if req.Name == "" {
		c.SetInvalidParam("name is required")
		return
	}

	// Set defaults for password generation.
	if req.Length == 0 {
		req.Length = 16
	}
	if req.Length < 8 || req.Length > 128 {
		c.SetInvalidParam("length: must be between 8 and 128")
		return
	}

	// Get user ID from JWT claims.
	userID, err := uuid.Parse(c.Claims.UserID)
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

	secretService := c.secretSvc()
	if secretService == nil {
		return
	}

	secret, err := secretService.GenerateSecret(r.Context(), secrets.GenerateSecretRequest{
		UserID:       userID,
		VaultID:      vaultID,
		Name:         req.Name,
		Length:       req.Length,
		UseSymbols:   req.UseSymbols,
		UseNumbers:   req.UseNumbers,
		UseUppercase: req.UseUppercase,
		UseLowercase: req.UseLowercase,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	// Prepare response (include value for generation operation).
	response := model.SecretResponse{
		ID:        secret.ID.String(),
		Name:      secret.Name,
		Value:     secret.Value,
		Tags:      secret.Tags,
		Version:   secret.Version,
		CreatedAt: secret.CreatedAt.Format(time.RFC3339),
	}

	// Send response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson())) //nolint:errcheck,gosec

	c.Logger.Printf("User %s generated secret %s", c.Claims.UserID, secret.Name)
}
