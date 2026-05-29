// Package api — extra coverage tests for certificate handlers.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// ============================================================
// createCertificate — CA-signed path and additional branches
// ============================================================

// TestCreateCertificate_CASignedPath_Success_Returns201 exercises the CA-signed
// certificate creation path (req.CACertID is non-empty).
func TestCreateCertificate_CASignedPath_Success_Returns201(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(365 * 24 * time.Hour)

	svc.On("CreateCASignedCertificate", mock.Anything, mock.Anything).
		Return(&certServices.CreateCertificateResult{
			CertID:    certID,
			Name:      "signed-cert",
			CreatedAt: now,
			ExpiresAt: &expiresAt,
		}, nil)

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	enabled := true
	body, _ := json.Marshal(map[string]any{
		"name":          "signed-cert",
		"key_id":        uuid.New().String(),
		"validity_days": 365,
		"ca_cert_id":    uuid.New().String(),
		"enabled":       enabled,
		"auto_renew":    true,
		"renewal_days":  30,
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

// TestCreateCertificate_InvalidCACertID_Returns400 verifies that a malformed
// ca_cert_id UUID is rejected.
func TestCreateCertificate_InvalidCACertID_Returns400(t *testing.T) {
	svc2 := &mockCertService{}
	c := newCertCtx(svc2, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":          "cert",
		"key_id":        uuid.New().String(),
		"validity_days": 365,
		"ca_cert_id":    "not-a-uuid",
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateCertificate_CASignedPath_ServiceError_Returns500 verifies error handling
// for CA-signed certificate creation failures.
func TestCreateCertificate_CASignedPath_ServiceError_Returns500(t *testing.T) {
	svc := &mockCertService{}
	svc.On("CreateCASignedCertificate", mock.Anything, mock.Anything).
		Return(nil, errors.New("ca signing failed"))

	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":          "signed-cert",
		"key_id":        uuid.New().String(),
		"validity_days": 365,
		"ca_cert_id":    uuid.New().String(),
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// TestCreateCertificate_EnabledFieldExplicit_Returns201 exercises the req.Enabled != nil branch.
func TestCreateCertificate_EnabledFieldExplicit_Returns201(t *testing.T) {
	svc := &mockCertService{}
	certID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(365 * 24 * time.Hour)

	svc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).
		Return(&certServices.CreateCertificateResult{
			CertID:    certID,
			Name:      "cert",
			CreatedAt: now,
			ExpiresAt: &expiresAt,
		}, nil)

	disabled := false
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":          "cert",
		"key_id":        uuid.New().String(),
		"validity_days": 365,
		"enabled":       disabled,
	})
	r := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))

	createCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
}

// ============================================================
// updateCertificate — additional branches
// ============================================================

// TestUpdateCertificate_MultipleFieldsUpdated_Returns200 verifies updating
// multiple fields in a single call.
func TestUpdateCertificate_MultipleFieldsUpdated_Returns200(t *testing.T) {
	certID := uuid.New()
	userID := uuid.MustParse(certTestUserID)
	svc := &mockCertService{}
	svc.On("GetCertificate", mock.Anything, certID, userID).Return(
		&model.Certificate{
			ID:   certID,
			Name: "original-name",
		}, nil,
	)
	svc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(nil)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":       "updated-name",
		"auto_renew": true,
	})
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String(), bytes.NewReader(body))

	updateCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================
// deleteCertificate — additional branches
// ============================================================

// TestDeleteCertificate_Extra_ServiceError_Returns500 verifies service error on delete.
func TestDeleteCertificate_Extra_ServiceError_Returns500(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("DeleteCertificateInVault", mock.Anything, certID, mock.Anything).Return(errors.New("delete failed"))

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/"+certID.String(), nil)

	deleteCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// TestDeleteCertificate_Extra_Success_Returns200 verifies successful certificate deletion.
func TestDeleteCertificate_Extra_Success_Returns200(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	svc.On("DeleteCertificateInVault", mock.Anything, certID, mock.Anything).Return(nil)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/certificates/"+certID.String(), nil)

	deleteCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}
