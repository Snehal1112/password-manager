package keys

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func baseKey() *model.Key {
	return &model.Key{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		VaultID:   uuid.New(),
		Name:      "original",
		Type:      model.KeyTypeRSA,
		Value:     "ENC(pem)",
		Tags:      []string{"a"},
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
		Bits:      2048,
	}
}

func TestApplyKeyUpdateLeavesTheInputUntouched(t *testing.T) {
	current := baseKey()
	name := "renamed"

	updated, err := applyKeyUpdate(current, UpdateKeyRequest{Name: &name})
	require.NoError(t, err)

	assert.Equal(t, "renamed", updated.Name)
	assert.Equal(t, "original", current.Name, "applyKeyUpdate must not mutate its input")
	assert.NotSame(t, current, updated)
}

func TestApplyKeyUpdateAppliesEveryOptionalField(t *testing.T) {
	current := baseKey()
	name := "renamed"
	revoked := true
	enabled := false
	expires := time.Now().Add(48 * time.Hour).UTC()
	notBefore := time.Now().Add(time.Hour).UTC()

	updated, err := applyKeyUpdate(current, UpdateKeyRequest{
		Name:      &name,
		Tags:      []string{"x", "y"},
		Revoked:   &revoked,
		Enabled:   &enabled,
		ExpiresAt: &expires,
		NotBefore: &notBefore,
	})
	require.NoError(t, err)

	assert.Equal(t, "renamed", updated.Name)
	assert.Equal(t, []string{"x", "y"}, updated.Tags)
	assert.True(t, updated.Revoked)
	assert.False(t, updated.Enabled)
	assert.Equal(t, expires, *updated.ExpiresAt)
	assert.Equal(t, notBefore, *updated.NotBefore)
}

func TestApplyKeyUpdateNilFieldsMeanNoChange(t *testing.T) {
	current := baseKey()

	updated, err := applyKeyUpdate(current, UpdateKeyRequest{})
	require.NoError(t, err)

	assert.Equal(t, current.Name, updated.Name)
	assert.Equal(t, current.Tags, updated.Tags)
	assert.Equal(t, current.Revoked, updated.Revoked)
	assert.Equal(t, current.Enabled, updated.Enabled)
}

func TestApplyKeyUpdateNonNilEmptyTagsClearsTags(t *testing.T) {
	current := baseKey()

	updated, err := applyKeyUpdate(current, UpdateKeyRequest{Tags: []string{}})
	require.NoError(t, err)
	assert.Empty(t, updated.Tags, "a non-nil empty slice clears all tags")
}

func TestApplyKeyUpdateRejectsNilKey(t *testing.T) {
	_, err := applyKeyUpdate(nil, UpdateKeyRequest{})
	assert.Error(t, err)
}
