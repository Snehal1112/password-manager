package migrations

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersionNumber_NumericNotLexicographic(t *testing.T) {
	t.Parallel()
	nine, err := parseVersionNumber("9")
	require.NoError(t, err)
	ten, err := parseVersionNumber("10")
	require.NoError(t, err)

	assert.Equal(t, int64(9), nine)
	assert.Equal(t, int64(10), ten)
	assert.Greater(t, ten, nine, "10 must sort after 9 numerically")
	assert.Less(t, "10", "9", "sanity check: lexicographic string comparison gets this backwards, which is exactly why MigrateToVersion must not compare version strings directly")
}

func TestParseVersionNumber_LeadingZeros(t *testing.T) {
	t.Parallel()
	n, err := parseVersionNumber("001")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestParseVersionNumber_Timestamp(t *testing.T) {
	t.Parallel()
	n, err := parseVersionNumber("20260606000001")
	require.NoError(t, err)
	assert.Equal(t, int64(20260606000001), n)
}

func TestParseVersionNumber_NonNumeric(t *testing.T) {
	t.Parallel()
	_, err := parseVersionNumber("not-a-version")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-version")
}
