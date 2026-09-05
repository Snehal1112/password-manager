package cachekit_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

type codecTestValue struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

func (v *codecTestValue) Clone() *codecTestValue {
	if v == nil {
		return nil
	}
	cp := *v
	return &cp
}

func TestPlainJSONCodec_RoundTrip(t *testing.T) {
	var codec cachekit.PlainJSONCodec[codecTestValue]
	in := codecTestValue{Name: "widget", N: 7}

	payload, err := codec.Encode(in)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "widget", "plain codec must not encrypt — the JSON is readable on the wire")

	out, err := codec.Decode(payload)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestPlainJSONCodec_DecodeMalformed(t *testing.T) {
	var codec cachekit.PlainJSONCodec[codecTestValue]
	_, err := codec.Decode([]byte("not json"))
	assert.Error(t, err)
}

// fakeEncrypt/fakeDecrypt stand in for common.EncryptSecret/DecryptSecret —
// same signature (func(string) (string, error)), base64 round-trip only,
// no real crypto (this test proves the codec wiring, not AES-GCM itself,
// which internal/crypto already tests independently).
func fakeEncrypt(plaintext string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(plaintext)), nil
}

func fakeDecrypt(ciphertext string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func TestEncryptedJSONCodec_RoundTrip(t *testing.T) {
	codec := cachekit.EncryptedJSONCodec[codecTestValue]{Encrypt: fakeEncrypt, Decrypt: fakeDecrypt}
	in := codecTestValue{Name: "top-secret", N: 42}

	payload, err := codec.Encode(in)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(payload), "top-secret"),
		"encrypted codec must never leak the plaintext substring onto the wire")

	out, err := codec.Decode(payload)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestEncryptedJSONCodec_EncryptErrorPropagates(t *testing.T) {
	codec := cachekit.EncryptedJSONCodec[codecTestValue]{
		Encrypt: func(string) (string, error) { return "", errors.New("boom") },
		Decrypt: fakeDecrypt,
	}
	_, err := codec.Encode(codecTestValue{Name: "x"})
	assert.Error(t, err)
}
