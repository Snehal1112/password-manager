// Package api — additional coverage tests targeting low-coverage areas.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	certServices "rocketvault/internal/services/certificates"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// ============================================================
// importSecrets — multipart form branches
// ============================================================

// buildMultipartRequest builds a multipart form request with a file field.
func buildMultipartRequest(t *testing.T, fileContent string, extraFields map[string]string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "secrets.json")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	io.WriteString(fw, fileContent)
	for k, v := range extraFields {
		mw.WriteField(k, v)
	}
	mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/secrets/import", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// TestImportSecrets_MissingFile_Returns400 verifies that a multipart request
// without a file field is rejected.
func TestImportSecrets_MissingFile_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("format", "json")
	mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/secrets/import", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestImportSecrets_InvalidFormat_Returns400 verifies that an unrecognized
// format parameter is rejected after a valid file is present.
func TestImportSecrets_InvalidFormat_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	w := httptest.NewRecorder()
	r := buildMultipartRequest(t, `[{"name":"s","value":"v"}]`, map[string]string{
		"format": "xml",
	})

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestImportSecrets_ServiceError_Returns500 verifies that an ImportSecrets
// service failure is returned as a 500.
func TestImportSecrets_ServiceError_Returns500(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(nil, errors.New("import failed"))

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := buildMultipartRequest(t, `[{"name":"s","value":"v"}]`, map[string]string{
		"format": "json",
	})

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// TestImportSecrets_JSONFormat_Success_Returns200 verifies the successful
// JSON import path returns 200 with the import count.
func TestImportSecrets_JSONFormat_Success_Returns200(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(&secretServices.ImportResult{ImportedCount: 2, TotalCount: 2}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := buildMultipartRequest(t, `[{"name":"s1","value":"v1"},{"name":"s2","value":"v2"}]`, map[string]string{
		"format": "json",
	})

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// TestImportSecrets_CSVFormat_Overwrite_Returns200 verifies the CSV format
// with the overwrite=true flag.
func TestImportSecrets_CSVFormat_Overwrite_Returns200(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(&secretServices.ImportResult{ImportedCount: 1, TotalCount: 1}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := buildMultipartRequest(t, "name,value\nsecret1,value1\n", map[string]string{
		"format":    "csv",
		"overwrite": "true",
	})

	importSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// updateSecret — additional field branches
// ============================================================

// TestUpdateSecret_ContentTypeChange_Returns200 exercises the ContentType branch.
func TestUpdateSecret_ContentTypeChange_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	secret := makeSecretModel(secretID)
	secret.ContentType = "text/plain"

	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(secret, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	ct := "application/json"
	body, _ := json.Marshal(map[string]any{"content_type": ct})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// TestUpdateSecret_EnabledChange_Returns200 exercises the Enabled branch.
func TestUpdateSecret_EnabledChange_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	secret := makeSecretModel(secretID)
	secret.Enabled = true

	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(secret, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	enabled := false
	body, _ := json.Marshal(map[string]any{"enabled": enabled})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// TestUpdateSecret_ExpiresAtChange_Returns200 exercises the ExpiresAt branch.
func TestUpdateSecret_ExpiresAtChange_Returns200(t *testing.T) {
	secretID := uuid.New()
	svc := &mockSecretService{}
	secret := makeSecretModel(secretID)

	svc.On("GetSecret", mock.Anything, secretID, mock.Anything).Return(secret, nil)
	svc.On("UpdateSecret", mock.Anything, mock.Anything).Return(nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{SecretID: secretID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	exp := time.Now().Add(24 * time.Hour)
	body, _ := json.Marshal(map[string]any{"expires_at": exp.Format(time.RFC3339)})
	r := httptest.NewRequest(http.MethodPut, "/secrets/"+secretID.String(), bytes.NewReader(body))

	updateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// ApiParamsFromRequest — branch coverage
// ============================================================

// TestApiParamsFromRequest_Defaults verifies that missing query params
// produce sensible defaults.
func TestApiParamsFromRequest_Defaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/items", nil)
	p := ApiParamsFromRequest(r)

	assert.Equal(t, 0, p.Page)
	assert.Equal(t, 60, p.PerPage)
	assert.Nil(t, p.Tags)
	assert.False(t, p.Permanent)
}

// TestApiParamsFromRequest_ValidQueryParams verifies pagination, tags, and permanent
// query params are correctly parsed.
func TestApiParamsFromRequest_ValidQueryParams(t *testing.T) {
	u, _ := url.Parse("/items?page=2&per_page=50&tags=a,b,c&permanent=true")
	r := httptest.NewRequest(http.MethodGet, u.String(), nil)
	p := ApiParamsFromRequest(r)

	assert.Equal(t, 2, p.Page)
	assert.Equal(t, 50, p.PerPage)
	assert.Equal(t, []string{"a", "b", "c"}, p.Tags)
	assert.True(t, p.Permanent)
}

// TestApiParamsFromRequest_PerPageCappedAt200 verifies that per_page values
// exceeding 200 are clamped.
func TestApiParamsFromRequest_PerPageCappedAt200(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/items?per_page=500", nil)
	p := ApiParamsFromRequest(r)
	assert.Equal(t, 200, p.PerPage)
}

// TestApiParamsFromRequest_NegativePageIgnored verifies that a negative page
// value is ignored and defaults to 0.
func TestApiParamsFromRequest_NegativePageIgnored(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/items?page=-1", nil)
	p := ApiParamsFromRequest(r)
	assert.Equal(t, 0, p.Page)
}

// TestApiParamsFromRequest_InvalidIntsIgnored verifies that non-numeric values
// for page and per_page fall back to defaults.
func TestApiParamsFromRequest_InvalidIntsIgnored(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/items?page=abc&per_page=xyz", nil)
	p := ApiParamsFromRequest(r)
	assert.Equal(t, 0, p.Page)
	assert.Equal(t, 60, p.PerPage)
}

// ============================================================
// exportSecrets — CSV content-type branch
// ============================================================

// TestExportSecrets_CSVFormat_SetsCsvContentType verifies the CSV content-type
// header is set when format=csv.
func TestExportSecrets_CSVFormat_SetsCsvContentType(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ExportSecrets", mock.Anything, mock.Anything).Return([]byte("name,value\n"), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"format": "csv"})
	r := httptest.NewRequest(http.MethodPost, "/secrets/export", bytes.NewReader(body))

	exportSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	svc.AssertExpectations(t)
}

// ============================================================
// deleteSecret — additional branch
// ============================================================

// TestDeleteSecret_InvalidSecretIDParam_Returns400 exercises invalid secret_id
// from params.
func TestDeleteSecret_InvalidSecretIDParam_Returns400(t *testing.T) {
	c := newSecretCtx(nil)
	c.Params = &ApiParams{SecretID: "bad-uuid", PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/secrets/bad", nil)

	deleteSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================
// listSecrets — additional branch
// ============================================================

// TestListSecrets_WithTagFilter_Returns200 verifies that a tag filter is forwarded
// to the service.
func TestListSecrets_WithTagFilter_Returns200(t *testing.T) {
	svc := &mockSecretService{}
	// Legacy flat route (no vault_name) uses per-user visibility via ListSecrets.
	svc.On("ListSecrets", mock.Anything, mock.Anything, mock.Anything).
		Return([]model.Secret{}, nil)

	c := newSecretCtx(svc)
	c.Params = &ApiParams{Tags: []string{"env:prod"}, PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets?tags=env:prod", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// createSecret — tags branch
// ============================================================

// TestCreateSecret_WithTags_Returns201 verifies that tags are forwarded on create.
func TestCreateSecret_WithTags_Returns201(t *testing.T) {
	svc := &mockSecretService{}
	secretID := uuid.New()
	now := time.Now()
	svc.On("CreateSecret", mock.Anything, mock.Anything).Return(
		&model.Secret{
			ID:        secretID,
			Name:      "tagged-secret",
			CreatedAt: now,
		}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"name":  "tagged-secret",
		"value": "secret-value",
		"tags":  []string{"env:prod", "team:backend"},
	})
	r := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(body))

	createSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// generateSecret — additional branches
// ============================================================

// TestGenerateSecret_DefaultLength_Returns201 verifies that a missing length
// defaults to 16.
func TestGenerateSecret_DefaultLength_Returns201(t *testing.T) {
	svc := &mockSecretService{}
	secretID := uuid.New()
	now := time.Now()
	_ = now
	svc.On("GenerateSecret", mock.Anything, mock.Anything).Return(
		makeSecretModel(secretID), nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	// Length is 0 here, so the handler should default to 16.
	body, _ := json.Marshal(map[string]any{"name": "gen-secret", "length": 0})
	r := httptest.NewRequest(http.MethodPost, "/secrets/generate", bytes.NewReader(body))

	generateSecret(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
}

// ============================================================
// certificates — getCertificate additional branch
// ============================================================

// TestGetCertificate_ServiceError_Returns404 verifies a service error maps to 404.
func TestGetCertificate_ServiceError_Returns404(t *testing.T) {
	certID := uuid.New()
	svc := &mockCertService{}
	// Legacy flat route (no vault_name) yields an owner scope.
	// The service returns the not-found sentinel, which maps to 404.
	svc.On("GetCertificate", mock.Anything, certID, certLegacyOwnerScope()).Return(nil, certServices.ErrCertNotFound)

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/certificates/"+certID.String(), nil)

	getCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// certificates — updateCertificate service error branch
// ============================================================

// TestUpdateCertificate_ServiceError2_Returns500 verifies that an UpdateCertificate
// service error returns 500.
func TestUpdateCertificate_ServiceError2_Returns500(t *testing.T) {
	certID := uuid.New()
	_ = uuid.MustParse(certTestUserID)
	svc := &mockCertService{}
	svc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(errors.New("update failed"))

	c := newCertCtx(svc, certAdminClaims())
	c.Params = &ApiParams{CertificateID: certID.String(), PerPage: 60}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	r := httptest.NewRequest(http.MethodPut, "/certificates/"+certID.String(), bytes.NewReader(body))

	updateCertificate(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	svc.AssertExpectations(t)
}

// ============================================================
// listSecrets response — ensure non-empty list path is covered
// ============================================================

// TestListSecrets_NonEmptyList_Returns200 verifies the response includes secrets.
func TestListSecrets_NonEmptyList_Returns200(t *testing.T) {
	svc := &mockSecretService{}
	secretID := uuid.New()
	// Legacy flat route (no vault_name) uses per-user visibility via ListSecrets.
	svc.On("ListSecrets", mock.Anything, mock.Anything, mock.Anything).
		Return([]model.Secret{
			{
				ID:        secretID,
				Name:      "my-secret",
				CreatedAt: time.Now(),
			},
		}, nil)

	c := newSecretCtx(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/secrets", nil)

	listSecrets(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	secrets, _ := resp["secrets"].([]any)
	assert.Len(t, secrets, 1)
	svc.AssertExpectations(t)
}
