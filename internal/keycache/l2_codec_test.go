package keycache

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

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

var _ cachekit.Codec[*Entry] = entryCodec{}

func TestEntryCodec_RoundTrip_ReconstructsConcretePEMKeyType(t *testing.T) {
	codec := entryCodec{encrypt: fakeEncrypt, decrypt: fakeDecrypt}
	in := &Entry{
		PrivateKey: PEMKey{PEM: []byte("-----BEGIN PRIVATE KEY-----FAKE-----END PRIVATE KEY-----")},
		KeyType:    "RSA",
		Version:    2,
	}

	payload, err := codec.Encode(in)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(payload), "PRIVATE KEY"),
		"encrypted payload must never contain the plaintext PEM substring")

	out, err := codec.Decode(payload)
	require.NoError(t, err)
	require.NotNil(t, out.PrivateKey)
	// The critical regression check: a naive json.Unmarshal into an Entry
	// with an interface-typed PrivateKey field would decode into a
	// map[string]interface{}, not a PEMKey -- this type assertion is what
	// proves entryCodec avoids that trap.
	pemKey, ok := out.PrivateKey.(PEMKey)
	require.True(t, ok, "decoded PrivateKey must be a concrete PEMKey, not map[string]interface{} or nil")
	assert.Equal(t, "-----BEGIN PRIVATE KEY-----FAKE-----END PRIVATE KEY-----", string(pemKey.PEM))
	assert.Equal(t, "RSA", out.KeyType)
	assert.Equal(t, 2, out.Version)
	assert.Nil(t, out.PublicKey)
}

func TestEntryCodec_NilKeys_RoundTrip(t *testing.T) {
	codec := entryCodec{encrypt: fakeEncrypt, decrypt: fakeDecrypt}
	in := &Entry{KeyType: "oct", Version: 1} // both PrivateKey and PublicKey nil

	payload, err := codec.Encode(in)
	require.NoError(t, err)
	out, err := codec.Decode(payload)
	require.NoError(t, err)
	assert.Nil(t, out.PrivateKey)
	assert.Nil(t, out.PublicKey)
}

func TestEntryCodec_Encode_UnexpectedConcreteType_ReturnsError(t *testing.T) {
	codec := entryCodec{encrypt: fakeEncrypt, decrypt: fakeDecrypt}
	// Production code never stores anything but PEMKey (verified), but the
	// codec must fail safe -- not silently drop data -- if that invariant
	// is ever violated.
	in := &Entry{PrivateKey: "not-a-pemkey", KeyType: "RSA", Version: 1}
	_, err := codec.Encode(in)
	assert.Error(t, err)
}
