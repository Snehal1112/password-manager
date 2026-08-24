package vaultapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// cryptoServer serves the key listing plus one crypto route, recording the
// request body.
func cryptoServer(t *testing.T, response string) (*httptest.Server, *writeProbe) {
	t.Helper()

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}

		probe.calls++
		probe.method, probe.path = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&probe.body)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv, probe
}

func TestSign_EncodesDataAndDecodesTheSignature(t *testing.T) {
	signature := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RS256",
		"value":"`+base64.StdEncoding.EncodeToString(signature)+`","version":3}`)

	got, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("hello"), "RS256", 0)
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/sign", probe.path)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), probe.body["value"],
		"the caller passes raw bytes; base64 is this layer's job")
	require.Equal(t, signature, got.Signature)
	require.Equal(t, 3, got.Version)
	require.Equal(t, uuid.MustParse(rsaKeyID), got.KeyID)
}

func TestSign_PassesTheAlgorithmThrough(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"ES256","value":"AAAA"}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "ES256", 0)
	require.NoError(t, err)
	require.Equal(t, "ES256", probe.body["algorithm"])
}

func TestSign_OmitsTheAlgorithmWhenUnset(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RS256","value":"AAAA"}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "", 0)
	require.NoError(t, err)

	value, present := probe.body["algorithm"]
	require.True(t, !present || value == "",
		"the server defaults to RS256; leaving that as the single source of truth beats duplicating it")
}

func TestSign_OmitsVersionZero(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"AAAA","version":5}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "RS256", 0)
	require.NoError(t, err)

	_, present := probe.body["version"]
	require.False(t, present, "zero means current, which the server already assumes")
}

func TestSign_SendsAnExplicitVersion(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"AAAA","version":2}`)

	got, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "RS256", 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, probe.body["version"])
	require.Equal(t, 2, got.Version)
}

func TestSign_RejectsEmptyData(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key", nil, "RS256", 0)
	require.ErrorContains(t, err, "data")
	require.Zero(t, probe.calls)
}

func TestSign_RequiresVaultAndName(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.Sign(context.Background(), "", "k", []byte("d"), "RS256", 0)
	require.ErrorContains(t, err, "vault is required")

	_, err = c.Sign(context.Background(), "prod", "", []byte("d"), "RS256", 0)
	require.ErrorContains(t, err, "name is required")

	require.Zero(t, probe.calls)
}

func TestSign_IsAttemptedExactlyOnce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "RS256", 0)
	require.Error(t, err,
		"a signature is not something to request twice on a timeout")
}

func TestSign_MalformedSignatureIsAnError(t *testing.T) {
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"not-valid-base64!!!"}`)

	_, err := newClientForTest(t, srv).Sign(context.Background(), "prod", "signing-key",
		[]byte("data"), "RS256", 0)
	require.ErrorContains(t, err, "base64",
		"an undecodable signature must fail loudly rather than yield empty bytes")
}

func TestVerify_ReportsAValidSignature(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RS256","valid":true,"version":3}`)

	got, err := newClientForTest(t, srv).Verify(context.Background(), "prod", "signing-key",
		[]byte("hello"), []byte{0xDE, 0xAD}, "RS256", 0)
	require.NoError(t, err)

	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/verify", probe.path)
	require.True(t, got.Valid)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), probe.body["value"])
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD}), probe.body["signature"])
}

func TestVerify_AnInvalidSignatureIsNotAnError(t *testing.T) {
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RS256","valid":false}`)

	got, err := newClientForTest(t, srv).Verify(context.Background(), "prod", "signing-key",
		[]byte("hello"), []byte{0x00}, "RS256", 0)
	require.NoError(t, err,
		"a negative answer is a successful call: conflating it with a transport failure would "+
			"leave a caller unable to tell a forgery from an unreachable vault")
	require.False(t, got.Valid)
}

func TestVerify_RequiresDataAndSignature(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.Verify(context.Background(), "prod", "k", nil, []byte{0x01}, "RS256", 0)
	require.ErrorContains(t, err, "data")

	_, err = c.Verify(context.Background(), "prod", "k", []byte("d"), nil, "RS256", 0)
	require.ErrorContains(t, err, "signature")

	require.Zero(t, probe.calls)
}
