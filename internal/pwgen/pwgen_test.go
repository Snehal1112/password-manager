package pwgen

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateLength(t *testing.T) {
	got, err := Generate(Options{Length: 24, Upper: true, Lower: true, Numbers: true, Special: true})
	require.NoError(t, err)
	assert.Len(t, got, 24)
}

func TestGenerateRejectsZeroLength(t *testing.T) {
	_, err := Generate(Options{Length: 0, Lower: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 1")
}

func TestGenerateRejectsEmptyCharset(t *testing.T) {
	_, err := Generate(Options{Length: 8})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one character type")
}

func TestGenerateHonoursCharsetSelection(t *testing.T) {
	got, err := Generate(Options{Length: 32, Numbers: true})
	require.NoError(t, err)
	for _, r := range got {
		assert.True(t, r >= '0' && r <= '9', "unexpected rune %q", r)
	}
}

func TestGenerateHasNoRepeatingRunOfThree(t *testing.T) {
	for range 200 {
		got, err := Generate(Options{Length: 16, Lower: true, Numbers: true})
		require.NoError(t, err)
		runes := []rune(got)
		for i := 0; i+2 < len(runes); i++ {
			if runes[i] == runes[i+1] && runes[i+1] == runes[i+2] {
				t.Fatalf("three identical characters in a row: %q", got)
			}
		}
	}
}

func TestGenerateIncludesEachEnabledSet(t *testing.T) {
	got, err := Generate(Options{Length: 16, Upper: true, Lower: true, Numbers: true, Special: true})
	require.NoError(t, err)
	assert.True(t, strings.ContainsAny(got, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "no uppercase in %q", got)
	assert.True(t, strings.ContainsAny(got, "abcdefghijklmnopqrstuvwxyz"), "no lowercase in %q", got)
	assert.True(t, strings.ContainsAny(got, "0123456789"), "no digit in %q", got)
	assert.True(t, strings.ContainsAny(got, "!@#$%^&*()-_=+[]{}|;:,.<>?"), "no special in %q", got)
}

func TestGenerateIsNotDeterministic(t *testing.T) {
	seen := make(map[string]struct{}, 50)
	for range 50 {
		got, err := Generate(DefaultOptions())
		require.NoError(t, err)
		seen[got] = struct{}{}
	}
	assert.Greater(t, len(seen), 45, "generator appears to repeat itself")
}

// TestGenerateAtLength1WithAllSetsDoesNotIncludeEveryCharset pins the
// documented caveat: with Length smaller than the number of enabled sets,
// each set's guaranteed-character injection can overwrite an earlier one, so
// the result is not guaranteed to contain a character from every set. With
// all four sets enabled and Length 1, the special-character injection runs
// last and always wins, so every result comes from the special charset.
func TestGenerateAtLength1WithAllSetsDoesNotIncludeEveryCharset(t *testing.T) {
	for range 50 {
		got, err := Generate(Options{Length: 1, Upper: true, Lower: true, Numbers: true, Special: true})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.True(t, strings.ContainsAny(got, specialChars), "expected the last-injected (special) charset to win at Length 1, got %q", got)
	}
}

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	assert.Equal(t, 16, o.Length)
	assert.True(t, o.Upper && o.Lower && o.Numbers && o.Special)
}
