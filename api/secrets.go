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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"password-manager/common"
	"password-manager/internal/db"
	"password-manager/internal/secrets"
)

// ExportRequest represents the request structure for exporting secrets.
type ExportRequest struct {
	Format      string   `json:"format"`       // "json" or "csv"
	Encrypt     bool     `json:"encrypt"`      // Whether to encrypt the export
	Tags        []string `json:"tags"`         // Filter by tags
	IncludeTags bool     `json:"include_tags"` // Include tags in export
}

// ImportRequest represents the request structure for importing secrets.
type ImportRequest struct {
	Format    string `json:"format"`    // "json" or "csv"
	Encrypted bool   `json:"encrypted"` // Whether the data is encrypted
	Overwrite bool   `json:"overwrite"` // Overwrite existing secrets
}

// ExportResponse represents the response structure for export operations.
type ExportResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Count      int    `json:"count"`
	Format     string `json:"format"`
	Encrypted  bool   `json:"encrypted"`
	ExportedAt string `json:"exported_at"`
}

// ImportResponse represents the response structure for import operations.
type ImportResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	ImportedCount int    `json:"imported_count"`
	TotalCount    int    `json:"total_count"`
	Format        string `json:"format"`
	ImportedAt    string `json:"imported_at"`
}

// InitSecrets initializes the routes for secrets management API.
// It sets up the following endpoints:
// - POST /secrets/export: Export secrets in JSON or CSV format.
// - POST /secrets/import: Import secrets from JSON or CSV format.
//
// Parameters:
// - secrets (*mux.Router): The router to which the routes will be added.
func (api *API) InitSecrets(secrets *mux.Router) {
	secrets.Handle("/export", ApiSessionRequired(api.App, exportSecrets)).Methods("POST")
	secrets.Handle("/import", ApiSessionRequired(api.App, importSecrets)).Methods("POST")

	// Secret versioning endpoints
	secrets.Handle("/{id}/versions", ApiSessionRequired(api.App, listSecretVersionsHandler)).Methods("GET")
	secrets.Handle("/{id}/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getSecretVersionHandler)).Methods("GET")
	secrets.Handle("/{id}/versions/latest", ApiSessionRequired(api.App, getLatestSecretVersionHandler)).Methods("GET")
}

// Handler: List all versions of a secret
func listSecretVersionsHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	secretID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("listSecretVersions", "Invalid secret ID", nil, err.Error(), http.StatusBadRequest)
		return
	}
	dbRepo := db.NewRepository(c.Logger)
	if err := dbRepo.InitializeDB(); err != nil {
		c.Err = common.NewAppError("listSecretVersions", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dbRepo.GetDB().Close()
	secretsRepo := secrets.NewSecretRepository(dbRepo.GetDB(), c.Logger)
	ctx := r.Context()
	versions, err := secretsRepo.GetVersions(ctx, secretID)
	if err != nil {
		c.Err = common.NewAppError("listSecretVersions", "Failed to get versions", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions)
}

// Handler: Get a specific version of a secret
func getSecretVersionHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	secretID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("getSecretVersion", "Invalid secret ID", nil, err.Error(), http.StatusBadRequest)
		return
	}
	versionNum, err := strconv.Atoi(vars["version"])
	if err != nil {
		c.Err = common.NewAppError("getSecretVersion", "Invalid version number", nil, err.Error(), http.StatusBadRequest)
		return
	}
	dbRepo := db.NewRepository(c.Logger)
	if err := dbRepo.InitializeDB(); err != nil {
		c.Err = common.NewAppError("getSecretVersion", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dbRepo.GetDB().Close()
	secretsRepo := secrets.NewSecretRepository(dbRepo.GetDB(), c.Logger)
	ctx := r.Context()
	version, err := secretsRepo.GetVersion(ctx, secretID, versionNum)
	if err != nil {
		c.Err = common.NewAppError("getSecretVersion", "Failed to get version", nil, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version)
}

// Handler: Get the latest version of a secret
func getLatestSecretVersionHandler(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	secretID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("getLatestSecretVersion", "Invalid secret ID", nil, err.Error(), http.StatusBadRequest)
		return
	}
	dbRepo := db.NewRepository(c.Logger)
	if err := dbRepo.InitializeDB(); err != nil {
		c.Err = common.NewAppError("getLatestSecretVersion", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dbRepo.GetDB().Close()
	secretsRepo := secrets.NewSecretRepository(dbRepo.GetDB(), c.Logger)
	ctx := r.Context()
	version, err := secretsRepo.GetLatestVersion(ctx, secretID)
	if err != nil {
		c.Err = common.NewAppError("getLatestSecretVersion", "Failed to get latest version", nil, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version)
}

// exportSecrets handles the export of secrets to encrypted files.
// It supports both JSON and CSV formats with optional encryption.
//
// Request Body:
//
//	{
//	  "format": "json|csv",
//	  "encrypt": true|false,
//	  "tags": ["tag1", "tag2"],
//	  "include_tags": true|false
//	}
//
// Response:
//   - 200 OK with exported data in response body
//   - 400 Bad Request for invalid input
//   - 401 Unauthorized for missing/invalid authentication
//   - 500 Internal Server Error for processing errors
func exportSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var exportReq ExportRequest
	if err := json.NewDecoder(r.Body).Decode(&exportReq); err != nil {
		c.Err = common.NewAppError("exportSecrets", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate format
	if exportReq.Format != "json" && exportReq.Format != "csv" {
		c.Err = common.NewAppError("exportSecrets", "Invalid format. Must be 'json' or 'csv'", nil, "", http.StatusBadRequest)
		return
	}

	// Get user ID from JWT claims
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("exportSecrets", "Missing user ID in token", nil, "", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("exportSecrets", "Invalid user ID format", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Initialize database and secrets repository
	database := db.NewRepository(c.Logger)
	if err := database.InitializeDB(); err != nil {
		c.Err = common.NewAppError("exportSecrets", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer database.GetDB().Close()

	secretsRepo := secrets.NewSecretRepository(database.GetDB(), c.Logger)

	// Prepare export options
	var format secrets.ExportFormat
	if exportReq.Format == "json" {
		format = secrets.ExportFormatJSON
	} else {
		format = secrets.ExportFormatCSV
	}

	options := secrets.ExportOptions{
		Format:      format,
		IncludeTags: exportReq.IncludeTags,
		FilterTags:  exportReq.Tags,
		Encrypt:     exportReq.Encrypt,
		UserID:      userID,
		ExportedAt:  time.Now(),
		ExportedBy:  userIDStr,
	}

	// Create context with database
	ctx := r.Context()
	ctx = context.WithValue(ctx, common.DBKey, database.GetDB())
	ctx = context.WithValue(ctx, common.LogKey, c.Logger)

	// Export secrets
	data, err := secretsRepo.ExportSecrets(ctx, options)
	if err != nil {
		c.Err = common.NewAppError("exportSecrets", "Failed to export secrets", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Count exported secrets (for JSON format)
	var count int
	if !exportReq.Encrypt && exportReq.Format == "json" {
		var container secrets.ExportContainer
		if err := json.Unmarshal(data, &container); err == nil {
			count = len(container.Secrets)
		}
	}

	// Set response headers
	contentType := "application/json"
	if exportReq.Format == "csv" {
		contentType = "text/csv"
	}

	filename := fmt.Sprintf("secrets-export-%s.%s", time.Now().Format("20060102-150405"), exportReq.Format)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	// Write data
	w.WriteHeader(http.StatusOK)
	w.Write(data)

	// Log successful export
	c.Logger.Printf("User %s exported %d secrets in %s format (encrypted: %v)",
		userIDStr, count, exportReq.Format, exportReq.Encrypt)
}

// importSecrets handles the import of secrets from encrypted files.
// It supports both JSON and CSV formats with optional decryption.
//
// Request: Multipart form data with:
//   - file: The file to import
//   - format: "json" or "csv"
//   - encrypted: "true" or "false"
//   - overwrite: "true" or "false"
//
// Response:
//
//	{
//	  "success": true,
//	  "message": "Successfully imported secrets",
//	  "imported_count": 5,
//	  "total_count": 5,
//	  "format": "json",
//	  "imported_at": "2023-01-01T12:00:00Z"
//	}
func importSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
		c.Err = common.NewAppError("importSecrets", "Failed to parse multipart form", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Get file from form
	file, _, err := r.FormFile("file")
	if err != nil {
		c.Err = common.NewAppError("importSecrets", "Missing or invalid file", nil, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read file data
	data, err := io.ReadAll(file)
	if err != nil {
		c.Err = common.NewAppError("importSecrets", "Failed to read file data", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Get form parameters
	format := r.FormValue("format")
	if format != "json" && format != "csv" {
		c.Err = common.NewAppError("importSecrets", "Invalid format. Must be 'json' or 'csv'", nil, "", http.StatusBadRequest)
		return
	}

	encrypted := r.FormValue("encrypted") == "true"
	overwrite := r.FormValue("overwrite") == "true"

	// Get user ID from JWT claims
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("importSecrets", "Missing user ID in token", nil, "", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("importSecrets", "Invalid user ID format", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Initialize database and secrets repository
	database := db.NewRepository(c.Logger)
	if err := database.InitializeDB(); err != nil {
		c.Err = common.NewAppError("importSecrets", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer database.GetDB().Close()

	secretsRepo := secrets.NewSecretRepository(database.GetDB(), c.Logger)

	// Prepare import options
	var importFormat secrets.ExportFormat
	if format == "json" {
		importFormat = secrets.ExportFormatJSON
	} else {
		importFormat = secrets.ExportFormatCSV
	}

	options := secrets.ImportOptions{
		Format:            importFormat,
		OverwriteExisting: overwrite,
		Encrypted:         encrypted,
		UserID:            userID,
		ImportedBy:        userIDStr,
	}

	// Create context with database
	ctx := r.Context()
	ctx = context.WithValue(ctx, common.DBKey, database.GetDB())
	ctx = context.WithValue(ctx, common.LogKey, c.Logger)

	// Import secrets
	importedCount, err := secretsRepo.ImportSecrets(ctx, data, options)
	if err != nil {
		c.Err = common.NewAppError("importSecrets", "Failed to import secrets", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := ImportResponse{
		Success:       true,
		Message:       fmt.Sprintf("Successfully imported %d secrets", importedCount),
		ImportedCount: importedCount,
		TotalCount:    importedCount, // For now, assume all were processed
		Format:        format,
		ImportedAt:    time.Now().Format(time.RFC3339),
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	// Log successful import
	c.Logger.Printf("User %s imported %d secrets from %s format (encrypted: %v)",
		userIDStr, importedCount, format, encrypted)
}
