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

// Package api — unit tests for buildKeyResponse HSM type detection.
package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestBuildKeyResponse_RSA_HSM(t *testing.T) {
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "hsm-rsa-key",
		Type:      "RSA",
		Value:     "pkcs11:hsm-label",
		CreatedAt: time.Now(),
		Tags:      []string{},
	}
	resp := buildKeyResponse(key, nil)
	assert.Equal(t, "RSA-HSM", resp.Type)
	assert.Equal(t, key.ID, resp.ID)
	assert.Equal(t, key.Name, resp.Name)
}

func TestBuildKeyResponse_ECDSA_HSM(t *testing.T) {
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "hsm-ec-key",
		Type:      "ECDSA",
		Value:     "pkcs11:ec-label",
		CreatedAt: time.Now(),
		Tags:      []string{},
	}
	resp := buildKeyResponse(key, nil)
	// ECDSA maps to "EC-HSM" to match Azure Key Vault convention.
	assert.Equal(t, "EC-HSM", resp.Type)
}

func TestBuildKeyResponse_RSA_Software(t *testing.T) {
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "sw-rsa-key",
		Type:      "RSA",
		Value:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA==\n-----END RSA PRIVATE KEY-----",
		CreatedAt: time.Now(),
		Tags:      []string{},
	}
	resp := buildKeyResponse(key, nil)
	assert.Equal(t, "RSA", resp.Type)
}

func TestBuildKeyResponse_ECDSA_Software(t *testing.T) {
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "sw-ec-key",
		Type:      "ECDSA",
		Value:     "-----BEGIN EC PRIVATE KEY-----\nMHQ=\n-----END EC PRIVATE KEY-----",
		CreatedAt: time.Now(),
		Tags:      []string{},
	}
	resp := buildKeyResponse(key, nil)
	assert.Equal(t, "ECDSA", resp.Type)
}

func TestBuildKeyResponse_AllFieldsCopied(t *testing.T) {
	now := time.Now()
	exp := now.Add(24 * time.Hour)
	key := &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "full-key",
		Type:      "RSA",
		Value:     "pkcs11:full-label",
		Revoked:   true,
		CreatedAt: now,
		UpdatedAt: &now,
		Tags:      []string{"env:prod"},
		Enabled:   true,
		ExpiresAt: &exp,
		NotBefore: &now,
		Bits:      2048,
	}
	resp := buildKeyResponse(key, nil)
	assert.Equal(t, "RSA-HSM", resp.Type)
	assert.Equal(t, key.ID, resp.ID)
	assert.Equal(t, key.UserID, resp.UserID)
	assert.Equal(t, key.Revoked, resp.Revoked)
	assert.Equal(t, key.Enabled, resp.Enabled)
	assert.Equal(t, key.Tags, resp.Tags)
	assert.Equal(t, key.Bits, resp.Bits)
	assert.Equal(t, key.ExpiresAt, resp.ExpiresAt)
	assert.Equal(t, key.NotBefore, resp.NotBefore)
	assert.Equal(t, key.UpdatedAt, resp.UpdatedAt)
}
