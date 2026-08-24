package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateKey_PostsToTheVaultScopedRoute(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+rsaKeyID+`","name":"signing-key","type":"RSA","bits":2048,"enabled":true}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "signing-key", Type: "RSA", Bits: 2048,
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/keys", probe.path)
	require.Equal(t, "signing-key", got.Name)
	require.Equal(t, 2048, got.Bits)
	require.EqualValues(t, 2048, probe.body["bits"])
}

func TestCreateKey_AcceptsTheThreeServerTypes(t *testing.T) {
	for _, keyType := range []string{"RSA", "ECDSA", "OCT"} {
		t.Run(keyType, func(t *testing.T) {
			srv, probe := vaultWriteServer(t, http.StatusCreated,
				`{"id":"`+rsaKeyID+`","name":"k","type":"`+keyType+`"}`)

			c := newClientForTest(t, srv)
			_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
				Name: "k", Type: keyType, Bits: 2048,
			})
			require.NoError(t, err)
			require.Equal(t, keyType, probe.body["type"])
		})
	}
}

func TestCreateKey_RejectsAnUnknownTypeBeforeSending(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{}`)

	c := newClientForTest(t, srv)
	// "EC" is the natural guess and is wrong: the server wants "ECDSA".
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "k", Type: "EC", Bits: 256,
	})
	require.ErrorContains(t, err, "ECDSA")
	require.Zero(t, probe.calls, "a typo worth catching before a round trip")
}

func TestCreateKey_SendsCurveForECDSA(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+rsaKeyID+`","name":"ec-key","type":"ECDSA","curve":"P-256"}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "ec-key", Type: "ECDSA", Curve: "P-256",
	})
	require.NoError(t, err)
	require.Equal(t, "P-256", probe.body["curve"])
	require.Equal(t, "P-256", got.Curve)
}

func TestCreateKey_DoesNotPreemptTheHSMRuleForOCT(t *testing.T) {
	// Whether HSM is enabled is server state this client cannot see, so an
	// OCT request must be sent and the server's refusal surfaced.
	srv, probe := vaultWriteServer(t, http.StatusBadRequest,
		`{"message":"symmetric keys require an HSM"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "aes-key", Type: "OCT", Bits: 256,
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls, "the server decides whether OCT is available, not this client")
}

func TestCreateKey_SendsOptionalFields(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+rsaKeyID+`","name":"k","type":"RSA"}`)

	enabled := true
	c := newClientForTest(t, srv)
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "k", Type: "RSA", Bits: 2048, Tags: []string{"prod"}, Enabled: &enabled,
	})
	require.NoError(t, err)

	require.Equal(t, true, probe.body["enabled"])
	require.Len(t, probe.body["tags"], 1)
}

func TestCreateKey_RequiresVaultNameAndType(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.CreateKey(context.Background(), "", CreateKeyRequest{Name: "k", Type: "RSA"})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.CreateKey(context.Background(), "prod", CreateKeyRequest{Type: "RSA"})
	require.ErrorContains(t, err, "name is required")

	_, err = c.CreateKey(context.Background(), "prod", CreateKeyRequest{Name: "k"})
	require.ErrorContains(t, err, "type is required")

	require.Zero(t, probe.calls)
}

func TestCreateKey_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "k", Type: "RSA", Bits: 2048,
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestCreateKey_CarriesNoPrivateMaterial(t *testing.T) {
	srv, _ := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+rsaKeyID+`","name":"k","type":"RSA","value":"-----BEGIN PRIVATE KEY-----LEAKED"}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "k", Type: "RSA", Bits: 2048,
	})
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}

func TestRotateKey_PostsToTheRotateRoute(t *testing.T) {
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusOK,
		`{"id":"`+rsaKeyID+`","name":"signing-key","type":"RSA"}`)

	c := newClientForTest(t, srv)
	got, err := c.RotateKey(context.Background(), "prod", "signing-key")
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotate", probe.path)
	require.Equal(t, "signing-key", got.Name)
}

func TestRotateKey_SendsNoBody(t *testing.T) {
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusOK, `{"id":"`+rsaKeyID+`","name":"signing-key"}`)

	c := newClientForTest(t, srv)
	_, err := c.RotateKey(context.Background(), "prod", "signing-key")
	require.NoError(t, err)
	require.Empty(t, probe.body, "the rotate route takes no body")
}

func TestRotateKey_AcceptsAUUID(t *testing.T) {
	srv, probe := probeServer(t, `{"keys":[]}`, http.StatusOK, `{"id":"`+rsaKeyID+`","name":"k"}`)

	c := newClientForTest(t, srv)
	_, err := c.RotateKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotate", probe.path)
}

func TestRotateKey_UnknownNameIsNotFound(t *testing.T) {
	srv, probe := probeServer(t, `{"keys":[]}`, http.StatusOK, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.RotateKey(context.Background(), "prod", "nope")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Zero(t, probe.calls, "an unresolvable name must not produce a rotate call")
}

func TestRotateKey_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.RotateKey(context.Background(), "prod", "signing-key")
	require.Error(t, err)
	require.Equal(t, 1, probe.calls,
		"retrying a lost-response rotate would create a second key version")
}

func TestUpsertKeyRotationPolicy_PutsAllFourFields(t *testing.T) {
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusOK,
		`{"key_id":"`+rsaKeyID+`","rotate_after_days":90,"notify_before_expiry_days":14,
		  "expiry_days":365,"enabled":true,"next_rotation_at":"2026-11-01T00:00:00Z"}`)

	c := newClientForTest(t, srv)
	got, err := c.UpsertKeyRotationPolicy(context.Background(), "prod", "signing-key",
		SetKeyRotationPolicyRequest{
			RotateAfterDays: 90, NotifyBeforeExpiryDays: 14, ExpiryDays: 365, Enabled: true,
		})
	require.NoError(t, err)

	require.Equal(t, http.MethodPut, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotationpolicy", probe.path)
	require.EqualValues(t, 90, probe.body["rotate_after_days"])
	require.EqualValues(t, 14, probe.body["notify_before_expiry_days"])
	require.EqualValues(t, 365, probe.body["expiry_days"])
	require.Equal(t, true, probe.body["enabled"])
	require.Equal(t, 90, got.RotateAfterDays)
}

func TestUpsertKeyRotationPolicy_SendsZeroesRatherThanOmitting(t *testing.T) {
	// The server's request type has no pointers, so an upsert is always a
	// full replacement. Omitting a field would be a lie about what happens.
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusOK, `{"key_id":"`+rsaKeyID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertKeyRotationPolicy(context.Background(), "prod", "signing-key",
		SetKeyRotationPolicyRequest{RotateAfterDays: 30})
	require.NoError(t, err)

	for _, field := range []string{"rotate_after_days", "notify_before_expiry_days", "expiry_days", "enabled"} {
		_, present := probe.body[field]
		require.True(t, present, "field %q must be sent: this is a full replacement", field)
	}
	require.EqualValues(t, 0, probe.body["expiry_days"])
}

func TestUpsertKeyRotationPolicy_RequiresVaultAndName(t *testing.T) {
	srv, probe := probeServer(t, `{"keys":[]}`, http.StatusOK, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.UpsertKeyRotationPolicy(context.Background(), "", "k", SetKeyRotationPolicyRequest{})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.UpsertKeyRotationPolicy(context.Background(), "prod", "", SetKeyRotationPolicyRequest{})
	require.ErrorContains(t, err, "name is required")

	require.Zero(t, probe.calls)
}

func TestUpsertKeyRotationPolicy_ForbiddenSurfacesTheCryptoOfficerHint(t *testing.T) {
	srv, _ := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusForbidden, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertKeyRotationPolicy(context.Background(), "prod", "signing-key",
		SetKeyRotationPolicyRequest{RotateAfterDays: 90})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "Key Vault Crypto Officer")
}
