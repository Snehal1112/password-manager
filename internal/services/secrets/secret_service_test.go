package secrets_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
)

// newService wires a secretService with the provided mocks.
func newService(
	repo *testutils.MockSecretRepository,
	crypto *testutils.MockCryptographyService,
	ver *testutils.MockVersioningService,
	tag *testutils.MockTagService,
	t *testing.T,
) secrets.SecretService {
	return secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: repo,
		CryptoService:    crypto,
		VersionService:   ver,
		TagService:       tag,
		Logger:           testutils.NewTestLogger(t),
	})
}

// --- CreateSecret ---

func TestCreateSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", "plaintext").Return("encrypted", nil)
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.CreateSecret(ctx, secrets.CreateSecretRequest{
		UserID: userID,
		Name:   "my-secret",
		Value:  "plaintext",
		Tags:   []string{"env:prod"},
	})

	require.NoError(t, err)
	assert.Equal(t, "plaintext", got.Value, "returned value should be decrypted")
	assert.Equal(t, "my-secret", got.Name)
	assert.Equal(t, userID, got.UserID)
	assert.True(t, got.Enabled, "new secrets must default to enabled=true")
	crypto.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestCreateSecret_EncryptionError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", mock.Anything).Return("", errors.New("crypto failure"))

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.CreateSecret(ctx, secrets.CreateSecretRequest{
		UserID: uuid.New(),
		Name:   "bad",
		Value:  "plaintext",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "crypto failure")
}

// --- GetSecret ---

func TestGetSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: userID, Name: "s", Value: "enc", Enabled: true}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// Ownership is now enforced at the SQL level via ReadByOwner.
	repo.On("ReadByOwner", ctx, secretID, userID).Return(stored, nil)
	crypto.On("DecryptSecret", "enc").Return("plain", nil)
	tag.On("GetTags", ctx, secretID).Return([]string{"k:v"}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.GetSecret(ctx, secretID, userID)

	require.NoError(t, err)
	assert.Equal(t, "plain", got.Value)
	assert.Equal(t, []string{"k:v"}, got.Tags)
}

func TestGetSecret_WrongOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	ownerID := uuid.New()
	otherID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// ReadByOwner returns an error when the user is not the owner.
	repo.On("ReadByOwner", ctx, secretID, otherID).Return(nil, errors.New("secret not found or access denied"))
	// ownerID is referenced only to show intent; the mock key is otherID.
	_ = ownerID

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GetSecret(ctx, secretID, otherID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found or access denied")
}

func TestGetSecret_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	callerID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("ReadByOwner", ctx, secretID, callerID).Return(nil, errors.New("secret not found or access denied"))

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GetSecret(ctx, secretID, callerID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- DeleteSecret ---

func TestDeleteSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: userID, Name: "to-delete"}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("Read", ctx, secretID).Return(stored, nil)
	tag.On("RemoveAllTags", ctx, secretID).Return(nil)
	repo.On("SoftDelete", ctx, secretID).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.DeleteSecret(ctx, secretID, userID)

	require.NoError(t, err)
	tag.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestDeleteSecret_WrongOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	ownerID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: ownerID}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("Read", ctx, secretID).Return(stored, nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.DeleteSecret(ctx, secretID, uuid.New())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- UpdateSecret ---

func TestUpdateSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: userID, Name: "old", Value: "enc-old", Version: 1}
	newValue := "new-plain"
	newName := "new-name"

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("Read", ctx, secretID).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-old").Return("old-plain", nil)
	ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).Return(
		&model.SecretVersion{Version: 1}, nil,
	)
	crypto.On("EncryptSecret", newValue).Return("enc-new", nil)
	repo.On("Update", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		UserID:   userID,
		Name:     &newName,
		Value:    &newValue,
	})

	require.NoError(t, err)
	ver.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestUpdateSecret_WrongOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	ownerID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: ownerID, Value: "enc"}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("Read", ctx, secretID).Return(stored, nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		UserID:   uuid.New(), // different user
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- ListSecrets ---

func TestListSecrets_DecryptsAndLoadsTags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	id1, id2 := uuid.New(), uuid.New()

	stored := []model.Secret{
		{ID: id1, UserID: userID, Name: "a", Value: "enc-a"},
		{ID: id2, UserID: userID, Name: "b", Value: "enc-b"},
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("ListByUser", ctx, userID, []string(nil)).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-a").Return("plain-a", nil)
	crypto.On("DecryptSecret", "enc-b").Return("plain-b", nil)
	tag.On("GetTags", ctx, id1).Return([]string{"x"}, nil)
	tag.On("GetTags", ctx, id2).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.ListSecrets(ctx, userID, nil)

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "plain-a", got[0].Value)
	assert.Equal(t, []string{"x"}, got[0].Tags)
	assert.Equal(t, "plain-b", got[1].Value)
}

// --- GenerateSecret ---

func TestGenerateSecret_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", mock.AnythingOfType("string")).Return("encrypted", nil)
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	got, err := svc.GenerateSecret(ctx, secrets.GenerateSecretRequest{
		UserID:       userID,
		Name:         "gen",
		Length:       16,
		UseUppercase: true,
		UseLowercase: true,
	})

	require.NoError(t, err)
	assert.Equal(t, "gen", got.Name)
	assert.Len(t, got.Value, 16)
}

func TestGenerateSecret_InvalidLength(t *testing.T) {
	t.Parallel()
	cases := []struct{ length int }{
		{length: 4},
		{length: 0},
		{length: 200},
	}
	for _, tc := range cases {
		t.Run("length", func(t *testing.T) {
			t.Parallel()
			repo := &testutils.MockSecretRepository{}
			crypto := &testutils.MockCryptographyService{}
			ver := &testutils.MockVersioningService{}
			tag := &testutils.MockTagService{}

			svc := newService(repo, crypto, ver, tag, t)
			_, err := svc.GenerateSecret(context.Background(), secrets.GenerateSecretRequest{
				UserID:       uuid.New(),
				Name:         "x",
				Length:       tc.length,
				UseUppercase: true,
			})
			require.Error(t, err)
		})
	}
}

func TestGenerateSecret_NoCharsetSelected(t *testing.T) {
	t.Parallel()
	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GenerateSecret(context.Background(), secrets.GenerateSecretRequest{
		UserID: uuid.New(),
		Name:   "x",
		Length: 16,
		// all charset flags false
	})
	require.Error(t, err)
}
