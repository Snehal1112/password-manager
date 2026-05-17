package secrets_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
)

func TestCreateSecretRejectsUnknownContentType(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.CreateSecret(ctx, secrets.CreateSecretRequest{
		UserID:      uuid.New(),
		Name:        "my-secret",
		Value:       "data",
		ContentType: "application/unknown-type",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported content type")
}

func TestCreateSecretAcceptsValidContentType(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", "{}").Return("encrypted", nil)
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.CreateSecret(ctx, secrets.CreateSecretRequest{
		UserID:      userID,
		Name:        "json-secret",
		Value:       "{}",
		ContentType: "application/json",
	})

	require.NoError(t, err)
	assert.Equal(t, "application/json", got.ContentType)
	crypto.AssertExpectations(t)
	repo.AssertExpectations(t)
}
