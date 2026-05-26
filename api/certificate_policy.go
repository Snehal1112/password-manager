package api

import (
	"encoding/json"
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

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}

	policy, err := c.App.ServiceContainer.GetCertificatePolicyRepository().GetByCertificateID(r.Context(), certID, userID)
	if err != nil {
		c.SetNotFound("policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// upsertCertificatePolicy creates or replaces the policy for a certificate.
func upsertCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	req, err := model.UpsertCertificatePolicyRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}

	now := time.Now()
	policy := &model.CertificatePolicy{
		ID:               uuid.New(),
		CertificateID:    certID,
		UserID:           userID,
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

	if err := c.App.ServiceContainer.GetCertificatePolicyRepository().Upsert(r.Context(), policy); err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(policy)
}

// deleteCertificatePolicy removes the policy for a certificate.
func deleteCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	certID, err := uuid.Parse(c.Params.CertificateID)
	if err != nil {
		c.SetInvalidParam("certificate_id")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}

	if err := c.App.ServiceContainer.GetCertificatePolicyRepository().DeleteByCertificateID(r.Context(), certID, userID); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}
