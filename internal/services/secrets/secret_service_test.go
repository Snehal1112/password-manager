package secrets_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
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

	// Ownership is now enforced at the SQL level via the scoped read.
	repo.On("ReadScoped", ctx, secretID, model.NewOwnerScope(uuid.Nil, userID)).Return(stored, nil)
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

	// The scoped read returns an error when the user is not the owner.
	repo.On("ReadScoped", ctx, secretID, model.NewOwnerScope(uuid.Nil, otherID)).Return(nil, errors.New("secret not found or access denied"))
	// ownerID is referenced only to show intent; the mock key is otherID.
	_ = ownerID

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GetSecret(ctx, secretID, otherID)

	require.Error(t, err)
	// A failed owner-scoped read now yields the ErrSecretNotFound sentinel so
	// the API layer can map it to a 404 rather than a 500.
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
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

	repo.On("ReadScoped", ctx, secretID, model.NewOwnerScope(uuid.Nil, callerID)).Return(nil, errors.New("secret not found or access denied"))

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

	repo.On("ReadScoped", ctx, secretID, model.NewOwnerScope(uuid.Nil, userID)).Return(stored, nil)
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
	callerID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	// A non-owner's scoped read finds no matching row, same as the SQL
	// predicate excluding it; the access check happens at the scoped read,
	// not via a separate Go-level ownership comparison.
	repo.On("ReadScoped", ctx, secretID, model.NewOwnerScope(uuid.Nil, callerID)).
		Return(nil, errors.New("secret not found or access denied"))

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.DeleteSecret(ctx, secretID, callerID)

	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
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

func TestUpdateSecretInVault_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	callerID := uuid.New() // a different vault member than the secret's original owner
	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	stored := &model.Secret{ID: secretID, UserID: ownerID, VaultID: vaultID, Name: "old", Value: "enc-old", Version: 1}
	newValue := "new-plain"
	newName := "new-name"

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("ReadInVault", ctx, secretID, vaultID).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-old").Return("old-plain", nil)
	ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).Return(
		&model.SecretVersion{Version: 1}, nil,
	)
	crypto.On("EncryptSecret", newValue).Return("enc-new", nil)
	repo.On("UpdateInVault", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecretInVault(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		UserID:   callerID,
		VaultID:  vaultID,
		Name:     &newName,
		Value:    &newValue,
	})

	require.NoError(t, err)
	ver.AssertExpectations(t)
	repo.AssertExpectations(t)
}

func TestUpdateSecretInVault_WrongVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("ReadInVault", ctx, secretID, vaultID).Return(nil, errors.New("secret not found or access denied"))

	svc := newService(repo, crypto, ver, tag, t)
	err := svc.UpdateSecretInVault(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		UserID:   uuid.New(),
		VaultID:  vaultID,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
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

	repo.On("ListScoped", ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
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

// TestGenerateSecret_PersistsInResolvedVault proves a generated secret lands in
// the vault carried by the request rather than the default vault. It captures
// the *model.Secret passed to the repository and asserts its VaultID.
func TestGenerateSecret_PersistsInResolvedVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userID := uuid.New()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", mock.AnythingOfType("string")).Return("encrypted", nil)

	var persisted *model.Secret
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) {
			persisted = args.Get(1).(*model.Secret)
		}).
		Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GenerateSecret(ctx, secrets.GenerateSecretRequest{
		UserID:       userID,
		VaultID:      vaultID,
		Name:         "gen",
		Length:       16,
		UseUppercase: true,
		UseLowercase: true,
	})

	require.NoError(t, err)
	require.NotNil(t, persisted, "repository Create must have been called")
	assert.Equal(t, vaultID, persisted.VaultID, "generated secret must land in the resolved vault")
	repo.AssertExpectations(t)
}

// TestGenerateSecret_DefaultsToDefaultVault proves a generated secret without an
// explicit vault still targets the default vault, preserving legacy behaviour.
func TestGenerateSecret_DefaultsToDefaultVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", mock.AnythingOfType("string")).Return("encrypted", nil)

	var persisted *model.Secret
	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).
		Run(func(args mock.Arguments) {
			persisted = args.Get(1).(*model.Secret)
		}).
		Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	_, err := svc.GenerateSecret(ctx, secrets.GenerateSecretRequest{
		UserID:       uuid.New(),
		Name:         "gen",
		Length:       16,
		UseUppercase: true,
	})

	require.NoError(t, err)
	require.NotNil(t, persisted, "repository Create must have been called")
	assert.Equal(t, uuid.MustParse(model.DefaultVaultID), persisted.VaultID,
		"generated secret without a vault must default to the default vault")
	repo.AssertExpectations(t)
}

// --- ExportSecrets / ImportSecrets ---

func TestExportSecrets_VaultScoped_UsesListSecretsInVault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	stored := []model.Secret{{ID: uuid.New(), VaultID: vaultID, Name: "s1", Value: "enc-v1"}}
	repo.On("ListScoped", ctx, model.NewVaultScope(vaultID, uuid.Nil), repositories.SecretFilter{Tags: nil}).Return(stored, nil)
	crypto.On("DecryptSecret", "enc-v1").Return("plain-v1", nil)
	tag.On("GetTags", ctx, stored[0].ID).Return([]string{}, nil)

	svc := newService(repo, crypto, ver, tag, t)
	data, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		UserID:  uuid.New(),
		VaultID: vaultID,
		Format:  "json",
	})

	require.NoError(t, err)
	require.Contains(t, string(data), "plain-v1")
	repo.AssertExpectations(t)
}

func TestImportSecrets_VaultScoped_ThreadsVaultIDIntoCreatedSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	crypto.On("EncryptSecret", "v1").Return("enc-v1", nil)
	repo.On("Create", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.VaultID == vaultID && s.Name == "n1"
	})).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	data := []byte(`[{"name":"n1","value":"v1"}]`)
	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		UserID:  uuid.New(),
		VaultID: vaultID,
		Data:    data,
		Format:  "json",
	})

	require.NoError(t, err)
	require.Equal(t, 1, result.ImportedCount)
	repo.AssertExpectations(t)
}

// TestUpdateSecretInVault_NonOwnerVaultMember_CreateVersionUsesSecretOwner
// proves that a vault member who is not the secret's owner can still update
// it: CreateVersion must be invoked with the secret's actual owner, not the
// caller, or its internal ownership check rejects a legitimate update.
func TestUpdateSecretInVault_NonOwnerVaultMember_CreateVersionUsesSecretOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New() // vault member who does not own the secret
	vaultID := uuid.New()
	secretID := uuid.New()

	current := &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID,
		Name: "shared-secret", Value: "encrypted-current", Version: 1, Enabled: true,
	}

	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}

	repo.On("ReadInVault", ctx, secretID, vaultID).Return(current, nil)
	crypto.On("DecryptSecret", "encrypted-current").Return("plaintext-current", nil)
	crypto.On("EncryptSecret", "new-plaintext").Return("encrypted-new", nil)

	var gotVersionReq secrets.CreateVersionRequest
	ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).
		Run(func(args mock.Arguments) {
			gotVersionReq = args.Get(1).(secrets.CreateVersionRequest)
		}).
		Return(&model.SecretVersion{}, nil)
	repo.On("UpdateInVault", ctx, mock.AnythingOfType("*model.Secret")).Return(nil)

	svc := newService(repo, crypto, ver, tag, t)
	newValue := "new-plaintext"
	err := svc.UpdateSecretInVault(ctx, secrets.UpdateSecretRequest{
		SecretID: secretID,
		VaultID:  vaultID,
		UserID:   callerID,
		Value:    &newValue,
	})

	require.NoError(t, err, "a vault member updating a secret they do not own must succeed")
	assert.Equal(t, ownerID, gotVersionReq.UserID,
		"CreateVersion must be called with the secret's owner, not the caller, so its internal ownership gate does not reject a legitimate vault-scoped update")
}
