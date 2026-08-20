package model

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultWebhookConfig_ToResponse_OmitsSecret is the load-bearing test for
// this file: the API-facing type must not carry the encrypted secret, so a
// handler cannot leak it by forwarding the wrong struct.
func TestVaultWebhookConfig_ToResponse_OmitsSecret(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	cfg := &VaultWebhookConfig{
		ID:                     uuid.New(),
		VaultID:                uuid.New(),
		URL:                    "https://hooks.example/rv",
		SigningSecretEncrypted: "SUPER-SECRET-CIPHERTEXT",
		Enabled:                true,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	resp := cfg.ToResponse()
	assert.Equal(t, "https://hooks.example/rv", resp.URL)
	assert.True(t, resp.Enabled)
	assert.Equal(t, "2026-08-19T12:00:00Z", resp.CreatedAt)
	assert.Equal(t, "2026-08-19T12:00:00Z", resp.UpdatedAt)

	encoded := resp.ToJson()
	assert.NotContains(t, encoded, "SUPER-SECRET-CIPHERTEXT")
	assert.NotContains(t, encoded, "signing_secret")
}

// TestVaultWebhookConfig_HasNoJsonTags proves the domain type cannot be
// marshaled into a response shape by accident -- no field carries a json tag,
// so any handler that forwarded this struct directly to json.Marshal would
// emit Go field names (URL, VaultID, etc.) not the API's snake_case contract,
// yielding visibly wrong output that tests would catch.
func TestVaultWebhookConfig_HasNoJsonTags(t *testing.T) {
	typ := reflect.TypeOf((*VaultWebhookConfig)(nil)).Elem()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		assert.Empty(t, tag, "field %s must not carry a json tag", field.Name)
	}
}

// TestVaultWebhookConfigCreatedResponse_CarriesSecret is the counterpart:
// exactly one shape may carry the plaintext, and this is it.
func TestVaultWebhookConfigCreatedResponse_CarriesSecret(t *testing.T) {
	resp := VaultWebhookConfigCreatedResponse{
		VaultWebhookConfigResponse: VaultWebhookConfigResponse{
			URL:     "https://hooks.example/rv",
			Enabled: true,
		},
		SigningSecret: "plaintext-secret",
	}
	encoded := resp.ToJson()
	assert.Contains(t, encoded, `"signing_secret":"plaintext-secret"`)
	assert.Contains(t, encoded, `"url":"https://hooks.example/rv"`)
}

func TestUpsertVaultWebhookRequestFromJson(t *testing.T) {
	t.Run("enabled omitted stays nil", func(t *testing.T) {
		req, err := UpsertVaultWebhookRequestFromJson(strings.NewReader(`{"url":"https://a.example"}`))
		require.NoError(t, err)
		assert.Equal(t, "https://a.example", req.URL)
		assert.False(t, req.RotateSecret)
		assert.Nil(t, req.Enabled, "an omitted enabled must be nil, not false")
	})

	t.Run("enabled false is distinguishable from omitted", func(t *testing.T) {
		req, err := UpsertVaultWebhookRequestFromJson(strings.NewReader(`{"url":"https://a.example","enabled":false}`))
		require.NoError(t, err)
		require.NotNil(t, req.Enabled)
		assert.False(t, *req.Enabled)
	})

	t.Run("rotate_secret parses", func(t *testing.T) {
		req, err := UpsertVaultWebhookRequestFromJson(strings.NewReader(`{"url":"https://a.example","rotate_secret":true}`))
		require.NoError(t, err)
		assert.True(t, req.RotateSecret)
	})

	t.Run("malformed json errors", func(t *testing.T) {
		_, err := UpsertVaultWebhookRequestFromJson(strings.NewReader(`{`))
		assert.Error(t, err)
	})
}
