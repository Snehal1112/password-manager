// Package api — tests for the CLI loopback relay added to the OIDC flow.
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestValidateCLIRedirectURI(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"empty is valid no-op", "", false},
		{"loopback IP with port", "http://127.0.0.1:54321/callback", false},
		{"localhost with port", "http://localhost:9999/callback", false},
		{"https rejected", "https://127.0.0.1:1234/callback", true},
		{"non-loopback host rejected", "http://evil.example.com:1234/callback", true},
		{"missing port rejected", "http://127.0.0.1/callback", true},
		{"malformed URL rejected", "://not a url", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCLIRedirectURI(tc.raw)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCLIExchangeStore_PutThenConsume_SingleUse(t *testing.T) {
	store := newCLIExchangeStore()
	response := model.LoginResponse{Token: "tok", RefreshToken: "rtok", UserID: "u1", Username: "jdoe", Roles: []string{"user"}}

	code, err := store.put(response)
	require.NoError(t, err)
	require.NotEmpty(t, code)

	got, ok := store.consume(code)
	require.True(t, ok)
	assert.Equal(t, response, got)

	_, ok = store.consume(code)
	assert.False(t, ok, "a code must not be redeemable twice")
}

func TestCLIExchangeStore_UnknownCode_NotOK(t *testing.T) {
	store := newCLIExchangeStore()
	_, ok := store.consume("does-not-exist")
	assert.False(t, ok)
}

func TestCLIExchangeStore_ExpiredCode_NotOK(t *testing.T) {
	store := newCLIExchangeStore()
	code, err := store.put(model.LoginResponse{Token: "tok"})
	require.NoError(t, err)

	// Force expiry directly — same package, unexported field access.
	entry := store.entries[code]
	entry.expiresAt = time.Now().Add(-1 * time.Second)
	store.entries[code] = entry

	_, ok := store.consume(code)
	assert.False(t, ok)
}

func TestCLIExchangeStore_Put_ReclaimsExpiredUnconsumedEntries(t *testing.T) {
	store := newCLIExchangeStore()

	// Mint a code that's never consumed (e.g. the browser was closed before
	// the CLI's loopback listener redeemed it), then force it into the past
	// the same way TestCLIExchangeStore_ExpiredCode_NotOK does.
	staleCode, err := store.put(model.LoginResponse{Token: "stale-tok"})
	require.NoError(t, err)
	entry := store.entries[staleCode]
	entry.expiresAt = time.Now().Add(-1 * time.Second)
	store.entries[staleCode] = entry
	require.Len(t, store.entries, 1)

	// A few more logins happen, spanning the expired entry.
	_, err = store.put(model.LoginResponse{Token: "tok2"})
	require.NoError(t, err)
	_, err = store.put(model.LoginResponse{Token: "tok3"})
	require.NoError(t, err)

	_, stillThere := store.entries[staleCode]
	assert.False(t, stillThere, "an expired, never-consumed entry must be reclaimed on a later put")
	assert.Len(t, store.entries, 2, "only the two still-live entries should remain")
}

func TestCLIExchangeHandler_ValidCode_ReturnsLoginResponse(t *testing.T) {
	api := newOIDCHAPI(nil, nil, nil)
	response := model.LoginResponse{Token: "tok", RefreshToken: "rtok", UserID: "u1", Username: "jdoe", Roles: []string{"user"}}
	code, err := api.cliExchange.put(response)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"code": code})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oidc/cli/exchange", bytes.NewReader(body))

	api.cliExchangeHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var got model.LoginResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, response, got)
}

func TestCLIExchangeHandler_MissingCode_Returns400(t *testing.T) {
	api := newOIDCHAPI(nil, nil, nil)
	body, _ := json.Marshal(map[string]string{"code": ""})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oidc/cli/exchange", bytes.NewReader(body))

	api.cliExchangeHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCLIExchangeHandler_UnknownCode_Returns410(t *testing.T) {
	api := newOIDCHAPI(nil, nil, nil)
	body, _ := json.Marshal(map[string]string{"code": "unknown"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oidc/cli/exchange", bytes.NewReader(body))

	api.cliExchangeHandler(w, r)

	assert.Equal(t, http.StatusGone, w.Code)
}
