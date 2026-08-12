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

// Package api — unit tests for soft-delete handlers.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// --- helpers ---

const sdTestUserIDStr = "c3d4e5f6-a7b8-9012-cdef-123456789012"

// newGetDeletedKeyContext builds a Context backed by the given KeyService mock.
func newGetDeletedKeyContext(svc keyServices.KeyService) *Context {
	a := &app.App{ServiceContainer: &keySvcTestContainer{keySvc: svc}}
	return &Context{
		App: a,
		Claims: jwt.MapClaims{
			"user_id": sdTestUserIDStr,
		},
	}
}

// --- tests ---

// TestGetDeletedKey_Found_Returns200 verifies that getDeletedKey returns 200
// with the expected JSON fields when the key exists in the soft-deleted list.
func TestGetDeletedKey_Found_Returns200(t *testing.T) {
	targetID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	deletedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return([]model.Key{
		{ID: targetID, Name: "my-rsa-key", Type: model.KeyTypeRSA, DeletedAt: &deletedAt},
	}, nil)

	c := newGetDeletedKeyContext(svc)
	c.Params = &ApiParams{KeyID: targetID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys/"+targetID.String(), nil)

	getDeletedKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, targetID.String(), body["id"])
	assert.Equal(t, "my-rsa-key", body["name"])
	assert.Equal(t, model.KeyTypeRSA, body["type"])
	assert.NotNil(t, body["deleted_at"], "deleted_at must be present in the response")
	svc.AssertExpectations(t)
}

// TestGetDeletedKey_NotFound_Returns404 verifies that getDeletedKey returns 404
// when no soft-deleted key with the requested ID exists.
func TestGetDeletedKey_NotFound_Returns404(t *testing.T) {
	existingID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	requestedID := uuid.MustParse("ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb")
	deletedAt := time.Now()

	svc := &mockKeyService{}
	svc.On("ListDeletedKeys", mock.Anything, mock.Anything).Return([]model.Key{
		{ID: existingID, Name: "other-key", Type: model.KeyTypeECDSA, DeletedAt: &deletedAt},
	}, nil)

	c := newGetDeletedKeyContext(svc)
	c.Params = &ApiParams{KeyID: requestedID.String()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/deleted/keys/"+requestedID.String(), nil)

	getDeletedKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
	svc.AssertExpectations(t)
}
