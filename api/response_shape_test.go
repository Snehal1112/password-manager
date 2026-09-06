// Package api — byte-level characterization tests for response envelopes.
//
// These pin the exact encoded body of the soft-delete and audit responses,
// including key order. A map[string]any encodes its keys sorted, whereas a
// struct encodes them in declaration order, so a conversion from one to the
// other is only safe if a test like this holds across it. They were written
// against the map bodies first and must keep passing unchanged afterwards.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/repositories"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// shapeTime is a fixed timestamp so the encoded bodies are deterministic.
var shapeTime = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// shapeID is a fixed UUID so the encoded bodies are deterministic.
var shapeID = uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

// topLevelKeys returns the top-level object keys of body in encoding order.
//
// json.Decoder yields tokens in the order they appear on the wire, which is
// what makes this an order-sensitive check rather than a set comparison.
func topLevelKeys(t *testing.T, body string) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(body))
	tok, err := dec.Token()
	require.NoError(t, err)
	require.Equal(t, json.Delim('{'), tok)

	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		require.NoError(t, err)
		key, ok := tok.(string)
		require.True(t, ok, "expected a string key")
		keys = append(keys, key)

		var discard json.RawMessage
		require.NoError(t, dec.Decode(&discard))
	}
	return keys
}

func TestResponseShape_ListDeletedSecrets(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ListDeletedSecrets", mock.Anything, mock.Anything).Return([]model.Secret{
		{ID: shapeID, Name: "db-password", Version: 3, CreatedAt: shapeTime, DeletedAt: &shapeTime},
	}, nil)
	c := newSecretCtx(svc)
	w := httptest.NewRecorder()

	listDeletedSecrets(c, w, httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"deleted_secrets":[{"created_at":"2026-05-01T12:00:00Z",`+
		`"deleted_at":"2026-05-01T12:00:00Z","id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",`+
		`"name":"db-password","version":3}],"total":1}`+"\n", w.Body.String())
}

// TestResponseShape_ListDeletedSecretsEmpty pins the empty listing, which must
// encode as [] rather than null and must still carry both keys.
func TestResponseShape_ListDeletedSecretsEmpty(t *testing.T) {
	svc := &mockSecretService{}
	svc.On("ListDeletedSecrets", mock.Anything, mock.Anything).Return([]model.Secret{}, nil)
	c := newSecretCtx(svc)
	w := httptest.NewRecorder()

	listDeletedSecrets(c, w, httptest.NewRequest(http.MethodGet, "/deleted/secrets", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"deleted_secrets":[],"total":0}`+"\n", w.Body.String())
}

func TestResponseShape_ListDeletedKeys(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return([]model.Key{
		{ID: shapeID, Name: "my-rsa-key", Type: model.KeyTypeRSA, DeletedAt: &shapeTime},
	}, nil)
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()

	listDeletedKeys(c, w, httptest.NewRequest(http.MethodGet, "/deleted/keys", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"deleted_keys":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",`+
		`"name":"my-rsa-key","type":"RSA","deleted_at":"2026-05-01T12:00:00Z",`+
		`"purge_protection":false}],"total":1}`+"\n", w.Body.String())
}

func TestResponseShape_ListDeletedKeysEmpty(t *testing.T) {
	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return([]model.Key{}, nil)
	c := newKeyCtx(svc)
	w := httptest.NewRecorder()

	listDeletedKeys(c, w, httptest.NewRequest(http.MethodGet, "/deleted/keys", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"deleted_keys":[],"total":0}`+"\n", w.Body.String())
}

func TestResponseShape_ListDeletedCertificates(t *testing.T) {
	svc := &mockCertService{}
	svc.On("ListDeletedCertificates", mock.Anything, mock.Anything).Return([]model.Certificate{
		{ID: shapeID, Name: "tls-cert", DeletedAt: &shapeTime},
	}, nil)
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()

	listDeletedCertificates(c, w, httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"deleted_certificates":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",`+
		`"name":"tls-cert","deleted_at":"2026-05-01T12:00:00Z","purge_protection":false}],`+
		`"total":1}`+"\n", w.Body.String())
}

func TestResponseShape_ListDeletedCertificatesEmpty(t *testing.T) {
	svc := &mockCertService{}
	svc.On("ListDeletedCertificates", mock.Anything, mock.Anything).Return([]model.Certificate{}, nil)
	c := newCertCtx(svc, certAdminClaims())
	w := httptest.NewRecorder()

	listDeletedCertificates(c, w, httptest.NewRequest(http.MethodGet, "/deleted/certificates", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"deleted_certificates":[],"total":0}`+"\n", w.Body.String())
}

// TestResponseShape_RecoverEnvelopes pins the restore envelope for all three
// resources. The shape is identical across them and only the message differs.
func TestResponseShape_RecoverEnvelopes(t *testing.T) {
	t.Run("secret", func(t *testing.T) {
		svc := &mockSecretService{}
		svc.On("RecoverSecret", mock.Anything, shapeID, mock.Anything).Return(nil)
		c := newSecretCtx(svc)
		c.Params = &ApiParams{SecretID: shapeID.String(), PerPage: 60}
		w := httptest.NewRecorder()

		recoverSecret(c, w, httptest.NewRequest(http.MethodPost, "/restore", nil))

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, `{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",`+
			`"message":"Secret recovered successfully"}`+"\n", w.Body.String())
	})

	t.Run("key", func(t *testing.T) {
		svc := &mockKeyService{}
		svc.On("RecoverKey", mock.Anything, shapeID, mock.Anything).Return(nil)
		c := newKeyCtx(svc)
		c.Params = &ApiParams{KeyID: shapeID.String(), PerPage: 60}
		w := httptest.NewRecorder()

		recoverKey(c, w, httptest.NewRequest(http.MethodPost, "/restore", nil))

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, `{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",`+
			`"message":"Key recovered successfully"}`+"\n", w.Body.String())
	})

	t.Run("certificate", func(t *testing.T) {
		svc := &mockCertService{}
		svc.On("RecoverCertificate", mock.Anything, shapeID, mock.Anything).Return(nil)
		c := newCertCtx(svc, certAdminClaims())
		c.Params = &ApiParams{CertificateID: shapeID.String(), PerPage: 60}
		w := httptest.NewRecorder()

		recoverCertificate(c, w, httptest.NewRequest(http.MethodPost, "/restore", nil))

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, `{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",`+
			`"message":"Certificate recovered successfully"}`+"\n", w.Body.String())
	})
}

// TestResponseShape_AuditLogs pins the audit envelope's key order and values.
//
// The individual log entries are left unpinned because their shape belongs to
// repositories.AuditLog, not to this envelope.
func TestResponseShape_AuditLogs(t *testing.T) {
	mockCRS := &testutils.MockComplianceReportService{}
	mockContainer := &testutils.MockServiceContainer{}
	mockContainer.On("GetComplianceReportService").Return(mockCRS)
	mockCRS.On("QueryLogs", mock.Anything, mock.Anything).Return(
		[]repositories.AuditLog{{ID: "id1", Action: "login", Outcome: "success"}},
		int64(1), true, nil,
	)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	c := &Context{App: &app.App{ServiceContainer: mockContainer}, Claims: adminClaims()}

	getAuditLogs(c, w, r)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Equal(t, []string{"integrity_ok", "logs", "next_cursor", "total"}, topLevelKeys(t, body))
	assert.True(t, strings.HasPrefix(body, `{"integrity_ok":true,"logs":[`), body)
	assert.True(t, strings.HasSuffix(body, `],"next_cursor":"","total":1}`+"\n"), body)
}
