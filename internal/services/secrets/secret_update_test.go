package secrets

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func baseSecret() *model.Secret {
	return &model.Secret{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		VaultID:     uuid.New(),
		Name:        "original",
		Value:       "ENC(original)",
		Version:     3,
		ContentType: "text/plain",
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
	}
}

func passthroughEncrypt(v string) (string, error) { return "ENC(" + v + ")", nil }

func TestApplySecretUpdateIncrementsVersionAndLeavesOriginalUntouched(t *testing.T) {
	current := baseSecret()
	snapshot := *current

	updated, err := applySecretUpdate(current, UpdateSecretRequest{}, passthroughEncrypt)
	require.NoError(t, err)

	assert.Equal(t, snapshot.Version+1, updated.Version)
	assert.Equal(t, snapshot, *current, "applySecretUpdate must not mutate its input")
	assert.NotSame(t, current, updated)
}

func TestApplySecretUpdateAppliesEveryOptionalField(t *testing.T) {
	current := baseSecret()
	name := "renamed"
	value := "fresh"
	contentType := "application/json"
	enabled := false
	expires := time.Now().Add(24 * time.Hour).UTC()
	notBefore := time.Now().Add(time.Hour).UTC()

	updated, err := applySecretUpdate(current, UpdateSecretRequest{
		Name:        &name,
		Value:       &value,
		ContentType: &contentType,
		Enabled:     &enabled,
		ExpiresAt:   &expires,
		NotBefore:   &notBefore,
	}, passthroughEncrypt)
	require.NoError(t, err)

	assert.Equal(t, "renamed", updated.Name)
	assert.Equal(t, "ENC(fresh)", updated.Value)
	assert.Equal(t, "application/json", updated.ContentType)
	assert.False(t, updated.Enabled)
	assert.Equal(t, expires, *updated.ExpiresAt)
	assert.Equal(t, notBefore, *updated.NotBefore)
}

func TestApplySecretUpdateNilFieldsMeanNoChange(t *testing.T) {
	current := baseSecret()

	updated, err := applySecretUpdate(current, UpdateSecretRequest{}, passthroughEncrypt)
	require.NoError(t, err)

	assert.Equal(t, current.Name, updated.Name)
	assert.Equal(t, current.Value, updated.Value)
	assert.Equal(t, current.ContentType, updated.ContentType)
	assert.Equal(t, current.Enabled, updated.Enabled)
	assert.Nil(t, updated.ExpiresAt)
	assert.Nil(t, updated.NotBefore)
}

func TestApplySecretUpdateRejectsUnsupportedContentType(t *testing.T) {
	current := baseSecret()
	bad := "application/x-not-allowed"

	_, err := applySecretUpdate(current, UpdateSecretRequest{ContentType: &bad}, passthroughEncrypt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported content type")
}

func TestApplySecretUpdatePropagatesEncryptionFailure(t *testing.T) {
	current := baseSecret()
	value := "fresh"
	boom := errors.New("cipher unavailable")

	_, err := applySecretUpdate(current, UpdateSecretRequest{Value: &value},
		func(string) (string, error) { return "", boom })
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

func TestApplySecretUpdateRejectsNilSecret(t *testing.T) {
	_, err := applySecretUpdate(nil, UpdateSecretRequest{}, passthroughEncrypt)
	assert.Error(t, err)
}
