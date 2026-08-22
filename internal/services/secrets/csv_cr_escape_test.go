package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscapeCR_RoundTrips(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"no special bytes here",
		"has\ronecr",
		"has\r\ncrlf",
		"trailing\r",
		"\rleading",
		"multiple\r\r\rin a row",
		"already has a NUL \x00 byte and a \r too",
		"just a NUL \x00",
		"\x00\r\x00\r interleaved",
	}
	for _, s := range cases {
		got := unescapeCR(escapeCR(s))
		assert.Equal(t, s, got, "escapeCR/unescapeCR must round-trip %q exactly", s)
	}
}

func TestEscapeCR_NoOpFastPathForOrdinaryInput(t *testing.T) {
	t.Parallel()
	// A string with neither \r nor the escape byte must come back completely
	// unmodified — escapeCR takes a fast path (no allocation) precisely
	// because most secret values never touch \r or \x00 at all.
	s := "plain-value, with a comma and \"a quote\" and a \n newline — all of\nwhich encoding/csv already handles correctly on its own"
	assert.Equal(t, s, escapeCR(s))
	assert.Equal(t, s, unescapeCR(s))
}

func TestUnescapeCR_MalformedEscapePreservesBytesRatherThanDroppingData(t *testing.T) {
	t.Parallel()
	// A crEscape byte not followed by crEscape or 'r' cannot come from
	// escapeCR's own output, but unescapeCR must never silently drop bytes
	// on it — it should pass both bytes through unchanged.
	s := "abc\x00xdef"
	assert.Equal(t, s, unescapeCR(s))
}

func TestUnescapeCR_TrailingEscapeByteWithNoFollowingByte(t *testing.T) {
	t.Parallel()
	// A crEscape byte as the very last byte, with nothing after it to form a
	// pair, must be preserved rather than panicking or being dropped.
	s := "abc\x00"
	assert.Equal(t, s, unescapeCR(s))
}
