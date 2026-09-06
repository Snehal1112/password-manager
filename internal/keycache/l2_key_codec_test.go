// internal/keycache/l2_key_codec_test.go
package keycache

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyCacheKeyCodec_RoundTrip(t *testing.T) {
	codec := keyCacheKeyCodec()
	k := keyCacheKey{ID: uuid.New(), Version: 3}

	wire := codec.ToWire(k)
	got, ok := codec.FromWire(wire)
	require.True(t, ok)
	assert.Equal(t, k, got)
}

func TestKeyCacheKeyCodec_FromWire_Malformed_ReturnsFalseNotError(t *testing.T) {
	codec := keyCacheKeyCodec()

	for _, bad := range []string{"", "no-colon-here", "not-a-uuid:3", uuid.New().String() + ":not-a-number"} {
		_, ok := codec.FromWire(bad)
		assert.False(t, ok, "input %q must report ok=false, never panic or error", bad)
	}
}
