/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package secrets

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePasswordUsesCSPRNG(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pw, err := generatePassword(16, true, true, true, true)
		require.NoError(t, err)
		seen[pw] = true
	}
	assert.Greater(t, len(seen), 90, "expected near-unique passwords, got many duplicates — likely weak RNG")
}

func TestGeneratePasswordHasNoRepeatingRun(t *testing.T) {
	for i := 0; i < 1000; i++ {
		pw, err := generatePassword(16, true, true, true, true)
		require.NoError(t, err)
		runes := []rune(pw)
		for j := 0; j < len(runes)-2; j++ {
			assert.False(t, runes[j] == runes[j+1] && runes[j+1] == runes[j+2],
				"found 3 identical consecutive chars in password %q at pos %d — likely weak RNG", pw, j)
		}
	}
}

func TestGeneratePasswordLength(t *testing.T) {
	pw, err := generatePassword(20, true, true, true, false)
	require.NoError(t, err)
	assert.Len(t, []rune(pw), 20)
}

func TestGeneratePasswordCharsetEnforcement(t *testing.T) {
	pw, err := generatePassword(32, false, true, false, false)
	require.NoError(t, err)
	for _, c := range pw {
		assert.True(t, unicode.IsLower(c), "expected only lowercase, got %c in %q", c, pw)
	}
}

func TestGeneratePasswordAllCharsetTypes(t *testing.T) {
	pw, err := generatePassword(64, true, true, true, true)
	require.NoError(t, err)
	assert.True(t, strings.ContainsAny(pw, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "no uppercase in %q", pw)
	assert.True(t, strings.ContainsAny(pw, "abcdefghijklmnopqrstuvwxyz"), "no lowercase in %q", pw)
	assert.True(t, strings.ContainsAny(pw, "0123456789"), "no digits in %q", pw)
	assert.True(t, strings.ContainsAny(pw, "!@#$%^&*()-_=+[]{}|;:,.<>?"), "no special chars in %q", pw)
}

func TestGeneratePasswordRejectsEmptyCharset(t *testing.T) {
	_, err := generatePassword(16, false, false, false, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one character type")
}

func TestGeneratePasswordRejectsZeroLength(t *testing.T) {
	_, err := generatePassword(0, true, true, true, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "length must be at least 1")
}
