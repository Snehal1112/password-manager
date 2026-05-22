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

// Package api — internal tests for secret handlers.
package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

// TestCreateSecret_ValueTooLarge_Returns400 verifies that a secret value
// exceeding the 25KB limit is rejected before reaching the service layer.
func TestCreateSecret_ValueTooLarge_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	body := map[string]any{
		"name":  "valid-secret",
		"value": strings.Repeat("x", 25601), // over 25KB
	}
	bodyBytes, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/secrets", io.NopCloser(bytes.NewReader(bodyBytes)))

	c := &Context{
		// App is nil — the validation guard must fire before any App access.
		Claims: jwt.MapClaims{
			"role":    model.RoleAdmin,
			"user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
	}

	createSecret(c, w, r)

	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateSecret_InvalidName_Returns400 verifies that a secret name starting
// with a digit is rejected before reaching the service layer.
func TestCreateSecret_InvalidName_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	body := map[string]any{
		"name":  "123-starts-with-digit",
		"value": "some-value",
	}
	bodyBytes, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/secrets", io.NopCloser(bytes.NewReader(bodyBytes)))

	c := &Context{
		// App is nil — the validation guard must fire before any App access.
		Claims: jwt.MapClaims{
			"role":    model.RoleAdmin,
			"user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
	}

	createSecret(c, w, r)

	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateSecret_TooManyTags_Returns400 verifies that more than 15 tags
// are rejected before reaching the service layer.
func TestCreateSecret_TooManyTags_Returns400(t *testing.T) {
	tags := make([]string, 16)
	for i := range tags {
		tags[i] = "tag"
	}

	w := httptest.NewRecorder()
	body := map[string]any{
		"name":  "valid-secret",
		"value": "some-value",
		"tags":  tags,
	}
	bodyBytes, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/secrets", io.NopCloser(bytes.NewReader(bodyBytes)))

	c := &Context{
		// App is nil — the validation guard must fire before any App access.
		Claims: jwt.MapClaims{
			"role":    model.RoleAdmin,
			"user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
	}

	createSecret(c, w, r)

	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
