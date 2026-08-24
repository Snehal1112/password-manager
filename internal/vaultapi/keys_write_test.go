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
