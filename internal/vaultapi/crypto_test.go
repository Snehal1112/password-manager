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

func TestEncrypt_ReturnsCiphertextAndNonce(t *testing.T) {
	ciphertext := []byte{0xCA, 0xFE}
	nonce := []byte{0x01, 0x02, 0x03}
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"AES256-GCM",
		"value":"`+base64.StdEncoding.EncodeToString(ciphertext)+`",
		"nonce":"`+base64.StdEncoding.EncodeToString(nonce)+`","version":2}`)

	got, err := newClientForTest(t, srv).Encrypt(context.Background(), "prod", "signing-key",
		[]byte("hello"), "AES256-GCM", 0)
	require.NoError(t, err)

	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/encrypt", probe.path)
	require.Equal(t, ciphertext, got.Ciphertext)
	require.Equal(t, nonce, got.Nonce,
		"AES-GCM decryption needs this nonce; losing it makes the ciphertext undecryptable")
	require.Equal(t, 2, got.Version)
}

func TestEncrypt_OmitsAnAbsentNonce(t *testing.T) {
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RSA-OAEP","value":"AAAA"}`)

	got, err := newClientForTest(t, srv).Encrypt(context.Background(), "prod", "signing-key",
		[]byte("hello"), "RSA-OAEP", 0)
	require.NoError(t, err)
	require.Empty(t, got.Nonce, "RSA-OAEP has no nonce, which is not an error")
}

func TestEncrypt_EncodesThePlaintext(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"AAAA"}`)

	_, err := newClientForTest(t, srv).Encrypt(context.Background(), "prod", "signing-key",
		[]byte("hello"), "RSA-OAEP", 0)
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), probe.body["value"])
}

func TestEncrypt_RejectsEmptyPlaintext(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)

	_, err := newClientForTest(t, srv).Encrypt(context.Background(), "prod", "signing-key",
		nil, "RSA-OAEP", 0)
	require.ErrorContains(t, err, "plaintext")
	require.Zero(t, probe.calls)
}

func TestDecrypt_ReturnsPlaintextAsASecretValue(t *testing.T) {
	plaintext := []byte("the-decrypted-secret")
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","algorithm":"RSA-OAEP",
		"value":"`+base64.StdEncoding.EncodeToString(plaintext)+`","version":1}`)

	got, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA, 0xFE}, nil, "RSA-OAEP", 0)
	require.NoError(t, err)

	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/decrypt", probe.path)
	require.Equal(t, "the-decrypted-secret", got.Plaintext.Reveal())
	require.Equal(t, "[REDACTED]", got.Plaintext.String(),
		"decryption produces plaintext, which is what SecretValue exists for")
}

func TestDecrypt_MarshallingTheResultNeverLeaksThePlaintext(t *testing.T) {
	plaintext := []byte("the-decrypted-secret")
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`",
		"value":"`+base64.StdEncoding.EncodeToString(plaintext)+`"}`)

	got, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nil, "RSA-OAEP", 0)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "the-decrypted-secret")
}

func TestDecrypt_SendsTheNonce(t *testing.T) {
	nonce := []byte{0x01, 0x02, 0x03}
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"aGk="}`)

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nonce, "AES256-GCM", 0)
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString(nonce), probe.body["nonce"])
}

func TestDecrypt_OmitsAnAbsentNonce(t *testing.T) {
	srv, probe := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"aGk="}`)

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nil, "RSA-OAEP", 0)
	require.NoError(t, err)

	_, present := probe.body["nonce"]
	require.False(t, present)
}

func TestDecrypt_RejectsEmptyCiphertext(t *testing.T) {
	srv, probe := cryptoServer(t, `{}`)

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		nil, nil, "RSA-OAEP", 0)
	require.ErrorContains(t, err, "ciphertext")
	require.Zero(t, probe.calls)
}

func TestDecrypt_ErrorNeverContainsThePlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"denied while decrypting the-decrypted-secret"}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nil, "RSA-OAEP", 0)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "the-decrypted-secret")
}

func TestDecrypt_MalformedPlaintextIsAnError(t *testing.T) {
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"not-base64!!!"}`)

	_, err := newClientForTest(t, srv).Decrypt(context.Background(), "prod", "signing-key",
		[]byte{0xCA}, nil, "RSA-OAEP", 0)
	require.ErrorContains(t, err, "base64")
}

func TestCrypto_AllFourResolveTheKeyByName(t *testing.T) {
	// Each operation goes through the same resolver, so a name works
	// everywhere a UUID does.
	srv, _ := cryptoServer(t, `{"key_id":"`+rsaKeyID+`","value":"aGk=","valid":true}`)
	c := newClientForTest(t, srv)
	ctx := context.Background()

	_, err := c.Sign(ctx, "prod", "signing-key", []byte("d"), "RS256", 0)
	require.NoError(t, err)
	_, err = c.Verify(ctx, "prod", "signing-key", []byte("d"), []byte("s"), "RS256", 0)
	require.NoError(t, err)
	_, err = c.Encrypt(ctx, "prod", "signing-key", []byte("d"), "RSA-OAEP", 0)
	require.NoError(t, err)
	_, err = c.Decrypt(ctx, "prod", "signing-key", []byte("d"), nil, "RSA-OAEP", 0)
	require.NoError(t, err)
}
