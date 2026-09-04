package users

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartLoopbackListener_ReceivesCode(t *testing.T) {
	redirectURI, wait, err := startLoopbackListener()
	require.NoError(t, err)

	go func() {
		resp, getErr := http.Get(redirectURI + "?code=abc123") //nolint:noctx
		if getErr == nil {
			resp.Body.Close()
		}
	}()

	code, err := wait(2 * time.Second)
	require.NoError(t, err)
	assert.Equal(t, "abc123", code)
}

func TestStartLoopbackListener_MissingCode_ReturnsError(t *testing.T) {
	redirectURI, wait, err := startLoopbackListener()
	require.NoError(t, err)

	go func() {
		resp, getErr := http.Get(redirectURI) //nolint:noctx
		if getErr == nil {
			resp.Body.Close()
		}
	}()

	_, err = wait(2 * time.Second)
	assert.Error(t, err)
}

func TestStartLoopbackListener_WrongState_RejectedWithoutDeliveringCode(t *testing.T) {
	redirectURI, wait, err := startLoopbackListener()
	require.NoError(t, err)

	// Simulate an attacker (or a stale/foreign request) hitting the
	// listener's port with a different state segment in the path — the
	// legitimate exchange code must not be treated as a match.
	wrongURI := redirectURI + "-wrong-state?code=attacker-code"

	go func() {
		resp, getErr := http.Get(wrongURI) //nolint:noctx
		if getErr == nil {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			resp.Body.Close()
		}
	}()

	_, err = wait(200 * time.Millisecond)
	assert.Error(t, err, "a wrong-state request must not deliver a code via wait()")
}

func TestStartLoopbackListener_Timeout(t *testing.T) {
	_, wait, err := startLoopbackListener()
	require.NoError(t, err)

	_, err = wait(50 * time.Millisecond)
	assert.Error(t, err)
}

func TestExchangeOIDCCode_Success(t *testing.T) {
	// jwt.expiry is a required production config value (see CLAUDE.md); the
	// test binary loads no config file, so set it explicitly to avoid a
	// zero-duration ExpiresAt racing against time.Now() in the assertion below.
	previousExpiry := viper.Get("jwt.expiry")
	viper.Set("jwt.expiry", time.Hour)
	t.Cleanup(func() { viper.Set("jwt.expiry", previousExpiry) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/oidc/cli/exchange", r.URL.Path)
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "code123", body["code"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"token": "access-tok", "refresh_token": "refresh-tok",
			"user_id":  "11111111-1111-1111-1111-111111111111",
			"username": "user14@exchange4all.local", "roles": []string{"user"},
		})
	}))
	defer server.Close()

	session, err := exchangeOIDCCode(context.Background(), nil, server.URL, "code123")

	require.NoError(t, err)
	assert.Equal(t, "access-tok", session.Token)
	assert.Equal(t, "user14@exchange4all.local", session.Username)
	assert.Equal(t, []string{"user"}, session.Roles)
	assert.True(t, session.ExpiresAt.After(time.Now()))
}

// TestOIDCExchangeResponse_UnmarshalsRolesArray proves oidcExchangeResponse
// decodes a "roles" JSON array into its Roles []string field. This struct
// hand-duplicates the server's wire shape (see its doc comment) rather than
// importing model.LoginResponse, so it doesn't benefit from that type's own
// tests -- it needs this one directly.
func TestOIDCExchangeResponse_UnmarshalsRolesArray(t *testing.T) {
	var decoded oidcExchangeResponse
	err := json.Unmarshal([]byte(`{"roles":["admin","secrets_manager"]}`), &decoded)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "secrets_manager"}, decoded.Roles)
}

func TestExchangeOIDCCode_NonOKStatus_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer server.Close()

	_, err := exchangeOIDCCode(context.Background(), nil, server.URL, "expired-code")
	assert.Error(t, err)
}

func TestExchangeOIDCCode_InvalidUserID_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"user_id": "not-a-uuid"}) //nolint:errcheck
	}))
	defer server.Close()

	_, err := exchangeOIDCCode(context.Background(), nil, server.URL, "code123")
	assert.Error(t, err)
}
