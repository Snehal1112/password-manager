package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// getCertificatePolicy returns the policy for a certificate.
func getCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	repo := c.certPolicyRepo()
	if repo == nil {
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
	if _, err := certService.GetCertificate(r.Context(), certID, scope); err != nil {
		c.SetNotFound("certificate")
		return
	}

	policy, err := repo.GetByCertificateIDAny(r.Context(), certID)
	if err != nil {
		c.SetNotFound("policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy) //nolint:errcheck
}

// upsertCertificatePolicy creates or replaces the policy for a certificate.
func upsertCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	req, err := model.UpsertCertificatePolicyRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	repo := c.certPolicyRepo()
	if repo == nil {
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
	if _, err := certService.GetCertificate(r.Context(), certID, scope); err != nil {
		c.SetNotFound("certificate")
		return
	}

	now := time.Now()
	policy := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           scope.ActorID(),
		ValidityMonths:   req.ValidityMonths,
		KeyType:          req.KeyType,
		KeySize:          req.KeySize,
		Curve:            req.Curve,
		Subject:          req.Subject,
		SANs:             req.SANs,
		AutoRenew:        req.AutoRenew,
		DaysBeforeExpiry: req.DaysBeforeExpiry,
		IssuerName:       req.IssuerName,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := repo.Upsert(r.Context(), policy); err != nil {
		c.SetInternalError(err)
		return
	}

	// Read-after-write so the response reflects the canonical stored ID. The
	// scope has already authorized the parent certificate, so the
	// owner-agnostic lookup is safe here too.
	stored, err := repo.GetByCertificateIDAny(r.Context(), certID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stored) //nolint:errcheck
}

// deleteCertificatePolicy removes the policy for a certificate.
func deleteCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	repo := c.certPolicyRepo()
	if repo == nil {
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
	if _, err := certService.GetCertificate(r.Context(), certID, scope); err != nil {
		c.SetNotFound("certificate")
		return
	}

	if err := repo.DeleteByCertificateIDAny(r.Context(), certID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.SetNotFound("policy not found")
		} else {
			c.SetInternalError(err)
		}
		return
	}

	ReturnStatusOK(w)
}
