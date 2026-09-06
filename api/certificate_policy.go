package api

import (
	"database/sql"
	"errors"
	"net/http"

	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// getCertificatePolicy returns the policy for a certificate.
func getCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	policy, err := certService.GetCertificatePolicy(r.Context(), certID, scope)
	if err != nil {
		if errors.Is(err, certServices.ErrCertNotFound) || errors.Is(err, certServices.ErrCertLifecycleDenied) {
			c.SetNotFound("certificate")
		} else {
			c.SetNotFound("policy")
		}
		return
	}

	writeJSON(w, policy)
}

// upsertCertificatePolicy creates or replaces the policy for a certificate.
func upsertCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}

	req, err := model.UpsertCertificatePolicyRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	policy, err := certService.UpsertCertificatePolicy(r.Context(), certID, scope, *req)
	if err != nil {
		if errors.Is(err, certServices.ErrCertNotFound) || errors.Is(err, certServices.ErrCertLifecycleDenied) {
			c.SetNotFound("certificate")
		} else {
			c.SetInternalError(err)
		}
		return
	}

	writeJSONStatus(w, http.StatusOK, policy)
}

// deleteCertificatePolicy removes the policy for a certificate.
func deleteCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, certOK := resourceID(c, c.Params.CertificateID, "certificate_id")
	if !certOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	certService := c.certSvc()
	if certService == nil {
		return
	}

	if err := certService.DeleteCertificatePolicy(r.Context(), certID, scope); err != nil {
		switch {
		case errors.Is(err, certServices.ErrCertNotFound), errors.Is(err, certServices.ErrCertLifecycleDenied):
			c.SetNotFound("certificate")
		case errors.Is(err, sql.ErrNoRows):
			c.SetNotFound("policy not found")
		default:
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}
