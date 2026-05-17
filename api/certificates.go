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
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/common"
	"rocketvault/model"
	certServices "rocketvault/internal/services/certificates"
)

// CreateCertificateAPIRequest is the HTTP request body for POST /certificates.
type CreateCertificateAPIRequest struct {
	Name         string   `json:"name"`           // Certificate common name
	KeyID        string   `json:"key_id"`         // UUID of the signing key
	ValidityDays int      `json:"validity_days"`  // Certificate validity in days
	Tags         []string `json:"tags,omitempty"` // Optional tags
	AutoRenew    bool     `json:"auto_renew"`     // Schedule automatic renewal
	RenewalDays  int      `json:"renewal_days"`   // Days before expiry to renew; defaults to 30
	CAKeyID      string   `json:"ca_key_id,omitempty"`  // Unused; kept for future use
	CACertID     string   `json:"ca_cert_id,omitempty"` // UUID of CA cert; triggers CA-signed path
}

// UpdateCertificateAPIRequest is the HTTP request body for PUT /certificates/{id}.
type UpdateCertificateAPIRequest struct {
	Name        *string  `json:"name,omitempty"`         // New name; nil means no change
	Tags        []string `json:"tags,omitempty"`         // Replace existing tags
	AutoRenew   *bool    `json:"auto_renew,omitempty"`   // Enable or disable auto-renewal
	RenewalDays *int     `json:"renewal_days,omitempty"` // Days before expiry to renew
}

// CertificateResponse is the JSON response for a single certificate.
type CertificateResponse struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	UserID      uuid.UUID  `json:"user_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Tags        []string   `json:"tags"`
	AutoRenew   bool       `json:"auto_renew"`
	RenewalDays int        `json:"renewal_days"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// CertificateListResponse is the JSON response for listing certificates.
type CertificateListResponse struct {
	Certificates []CertificateResponse `json:"certificates"`
}

// InitCertificates registers all certificate HTTP routes under the provided router.
// It sets up the following endpoints:
// - POST /certificates: Create a new certificate.
// - GET /certificates: List certificates for the authenticated user.
// - GET /certificates/{id}: Get a specific certificate by ID.
// - PUT /certificates/{id}: Update certificate metadata.
// - DELETE /certificates/{id}: Delete a certificate.
//
// Parameters:
// - certs (*mux.Router): The router to which the routes will be added.
func (api *API) InitCertificates() {
	c := api.BaseRoutes.Certificates

	c.Handle("", ApiSessionRequired(api.App, createCertificate)).Methods("POST")
	c.Handle("", ApiSessionRequired(api.App, listCertificates)).Methods("GET")
	c.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getCertificate)).Methods("GET")
	c.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateCertificate)).Methods("PUT")
	c.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteCertificate)).Methods("DELETE")

	api.Logger.Infoln("Certificates API routes initialized")
}

// certToDomainResponse converts a model.Certificate to a CertificateResponse.
func certToDomainResponse(cert *model.Certificate) CertificateResponse {
	return CertificateResponse{
		ID:          cert.ID,
		Name:        cert.Name,
		UserID:      cert.UserID,
		CreatedAt:   cert.CreatedAt,
		Tags:        cert.Tags,
		AutoRenew:   cert.AutoRenew,
		RenewalDays: cert.RenewalDays,
		ExpiresAt:   cert.ExpiresAt,
	}
}

// createCertificate creates a new X.509 certificate.
func createCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	// Requires admin or certificate_manager role.
	roleStr, ok := c.Claims["role"].(string)
	if !ok || !common.HasRequiredRole(roleStr, model.RoleAdmin, model.RoleCertificateManager) {
		c.Err = common.NewAppError("createCertificate", "Forbidden: requires admin or certificate_manager role", nil, "", http.StatusForbidden)
		return
	}

	var req CreateCertificateAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("createCertificate", "Invalid JSON request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.KeyID == "" || req.ValidityDays <= 0 {
		c.Err = common.NewAppError("createCertificate", "name, key_id, and validity_days are required", nil, "", http.StatusBadRequest)
		return
	}

	keyID, err := uuid.Parse(req.KeyID)
	if err != nil {
		c.Err = common.NewAppError("createCertificate", "Invalid key_id", nil, err.Error(), http.StatusBadRequest)
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("createCertificate", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("createCertificate", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	createReq := certServices.CreateCertificateRequest{
		Name:         req.Name,
		KeyID:        keyID,
		ValidityDays: req.ValidityDays,
		Tags:         req.Tags,
		UserID:       userID,
		AutoRenew:    req.AutoRenew,
		RenewalDays:  req.RenewalDays,
	}

	var result *certServices.CreateCertificateResult

	if req.CACertID != "" {
		// CA-signed certificate path.
		caCertID, parseErr := uuid.Parse(req.CACertID)
		if parseErr != nil {
			c.Err = common.NewAppError("createCertificate", "Invalid ca_cert_id", nil, parseErr.Error(), http.StatusBadRequest)
			return
		}
		createReq.CACertID = &caCertID
		result, err = certService.CreateCASignedCertificate(r.Context(), createReq)
	} else {
		result, err = certService.CreateSelfSignedCertificate(r.Context(), createReq)
	}

	if err != nil {
		c.Err = common.NewAppError("createCertificate", "Failed to create certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	response := CertificateResponse{
		ID:          result.CertID,
		Name:        result.Name,
		UserID:      userID,
		CreatedAt:   result.CreatedAt,
		Tags:        result.Tags,
		AutoRenew:   req.AutoRenew,
		RenewalDays: req.RenewalDays,
		ExpiresAt:   result.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// listCertificates lists all certificates for the authenticated user.
func listCertificates(c *Context, w http.ResponseWriter, r *http.Request) {
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("listCertificates", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("listCertificates", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	certs, err := certService.ListCertificates(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("listCertificates", "Failed to list certificates", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	response := CertificateListResponse{Certificates: make([]CertificateResponse, len(certs))}
	for i := range certs {
		response.Certificates[i] = certToDomainResponse(&certs[i])
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getCertificate retrieves a specific certificate by ID.
func getCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("getCertificate", "Invalid certificate ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("getCertificate", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("getCertificate", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	cert, err := certService.GetCertificate(r.Context(), certID, userID)
	if err != nil {
		c.Err = common.NewAppError("getCertificate", "Certificate not found or access denied", nil, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certToDomainResponse(cert))
}

// updateCertificate updates an existing certificate's metadata.
func updateCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("updateCertificate", "Invalid certificate ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("updateCertificate", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("updateCertificate", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req UpdateCertificateAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("updateCertificate", "Invalid JSON request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == nil && req.Tags == nil && req.AutoRenew == nil && req.RenewalDays == nil {
		c.Err = common.NewAppError("updateCertificate", "At least one update field must be provided", nil, "", http.StatusBadRequest)
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	updateReq := certServices.UpdateCertificateRequest{
		CertID:      certID,
		UserID:      userID,
		Name:        req.Name,
		Tags:        req.Tags,
		AutoRenew:   req.AutoRenew,
		RenewalDays: req.RenewalDays,
	}

	if err := certService.UpdateCertificate(r.Context(), updateReq); err != nil {
		c.Err = common.NewAppError("updateCertificate", "Failed to update certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch updated certificate for response.
	cert, err := certService.GetCertificate(r.Context(), certID, userID)
	if err != nil {
		c.Err = common.NewAppError("updateCertificate", "Failed to retrieve updated certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certToDomainResponse(cert))
}

// deleteCertificate removes a certificate from the system.
func deleteCertificate(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("deleteCertificate", "Invalid certificate ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("deleteCertificate", "Invalid user claims", nil, "", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.Err = common.NewAppError("deleteCertificate", "Invalid user ID", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	if err := certService.DeleteCertificate(r.Context(), certID, userID); err != nil {
		c.Err = common.NewAppError("deleteCertificate", "Failed to delete certificate", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
