package secrets_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

type mockSecretTagRepository struct {
	mock.Mock
}

func (m *mockSecretTagRepository) AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	return m.Called(ctx, secretID, tags).Error(0)
}

func (m *mockSecretTagRepository) RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	return m.Called(ctx, secretID, tags).Error(0)
}

func (m *mockSecretTagRepository) RemoveAllTags(ctx context.Context, secretID uuid.UUID) error {
	return m.Called(ctx, secretID).Error(0)
}

func (m *mockSecretTagRepository) GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockSecretTagRepository) FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error) {
	args := m.Called(ctx, userID, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uuid.UUID), args.Error(1)
}

type mockSecretVersionRepository struct {
	mock.Mock
}

func (m *mockSecretVersionRepository) CreateVersion(ctx context.Context, version *model.SecretVersion) error {
	return m.Called(ctx, version).Error(0)
}

func (m *mockSecretVersionRepository) GetVersions(ctx context.Context, secretID uuid.UUID) ([]model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretVersion), args.Error(1)
}

func (m *mockSecretVersionRepository) GetVersion(ctx context.Context, secretID uuid.UUID, version int) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *mockSecretVersionRepository) GetLatestVersion(ctx context.Context, secretID uuid.UUID) (*model.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
}

func (m *mockSecretVersionRepository) DeleteVersions(ctx context.Context, secretID uuid.UUID) error {
	return m.Called(ctx, secretID).Error(0)
}

func (m *mockSecretVersionRepository) DeleteSpecificVersion(ctx context.Context, secretID uuid.UUID, version int) error {
	return m.Called(ctx, secretID, version).Error(0)
}

type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) Create(ctx context.Context, user *model.User) error {
	return m.Called(ctx, user).Error(0)
}

func (m *mockUserRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *mockUserRepository) Update(ctx context.Context, user *model.User) error {
	return m.Called(ctx, user).Error(0)
}

func (m *mockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockUserRepository) ReadByUsername(ctx context.Context, username string) (model.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(model.User), args.Error(1)
}

func (m *mockUserRepository) List(ctx context.Context) ([]model.User, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.User), args.Error(1)
}

func (m *mockUserRepository) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *mockUserRepository) InvalidateBootstrapToken(ctx context.Context, token string) error {
	return m.Called(ctx, token).Error(0)
}

type mockRotationPolicyRepository struct {
	mock.Mock
}

func (m *mockRotationPolicyRepository) Create(ctx context.Context, policy *model.RotationPolicy) error {
	return m.Called(ctx, policy).Error(0)
}

func (m *mockRotationPolicyRepository) Read(ctx context.Context, id uuid.UUID) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *mockRotationPolicyRepository) Update(ctx context.Context, policy *model.RotationPolicy) error {
	return m.Called(ctx, policy).Error(0)
}

func (m *mockRotationPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockRotationPolicyRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *mockRotationPolicyRepository) AssignToSecret(ctx context.Context, secretID, policyID uuid.UUID, assignedAt time.Time, nextRotationAt time.Time) error {
	return m.Called(ctx, secretID, policyID, assignedAt, nextRotationAt).Error(0)
}

func (m *mockRotationPolicyRepository) RemoveFromSecret(ctx context.Context, secretID, policyID uuid.UUID) error {
	return m.Called(ctx, secretID, policyID).Error(0)
}

func (m *mockRotationPolicyRepository) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}

func (m *mockRotationPolicyRepository) GetPoliciesForSecret(ctx context.Context, secretID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *mockRotationPolicyRepository) UpdateSecretPolicyRotation(ctx context.Context, secretID, policyID uuid.UUID, lastRotatedAt, nextRotationAt time.Time) error {
	return m.Called(ctx, secretID, policyID, lastRotatedAt, nextRotationAt).Error(0)
}

func (m *mockRotationPolicyRepository) RecordRotation(ctx context.Context, history *model.RotationHistory) error {
	return m.Called(ctx, history).Error(0)
}

func (m *mockRotationPolicyRepository) GetRotationHistory(ctx context.Context, secretID uuid.UUID) ([]model.RotationHistory, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationHistory), args.Error(1)
}

func (m *mockRotationPolicyRepository) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}

func (m *mockRotationPolicyRepository) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]model.RotationReminder, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationReminder), args.Error(1)
}

func (m *mockRotationPolicyRepository) CreateReminder(ctx context.Context, reminder *model.RotationReminder) error {
	return m.Called(ctx, reminder).Error(0)
}

func (m *mockRotationPolicyRepository) UpdateReminder(ctx context.Context, reminder *model.RotationReminder) error {
	return m.Called(ctx, reminder).Error(0)
}

func (m *mockRotationPolicyRepository) GetReminderBySecret(ctx context.Context, secretID, policyID uuid.UUID, reminderType string) (*model.RotationReminder, error) {
	args := m.Called(ctx, secretID, policyID, reminderType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationReminder), args.Error(1)
}

type mockRotationService struct {
	mock.Mock
}

func (m *mockRotationService) CreatePolicy(ctx context.Context, req secrets.CreatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) GetPolicy(ctx context.Context, id uuid.UUID) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) UpdatePolicy(ctx context.Context, req secrets.UpdatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) DeletePolicy(ctx context.Context, id uuid.UUID, callerID uuid.UUID) error {
	return m.Called(ctx, id, callerID).Error(0)
}

func (m *mockRotationService) ListUserPolicies(ctx context.Context, userID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) AssignPolicyToSecret(ctx context.Context, req secrets.AssignPolicyRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, callerID uuid.UUID) error {
	return m.Called(ctx, secretID, policyID, callerID).Error(0)
}

func (m *mockRotationService) GetSecretPolicies(ctx context.Context, secretID, userID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) PerformManualRotation(ctx context.Context, req secrets.ManualRotationRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID, callerID uuid.UUID) ([]model.RotationHistory, error) {
	args := m.Called(ctx, secretID, callerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationHistory), args.Error(1)
}

func (m *mockRotationService) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}

func (m *mockRotationService) CreateRotationReminder(ctx context.Context, req secrets.CreateReminderRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]model.RotationReminder, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationReminder), args.Error(1)
}

func (m *mockRotationService) AcknowledgeReminder(ctx context.Context, reminderID, secretID, userID uuid.UUID) error {
	return m.Called(ctx, reminderID, secretID, userID).Error(0)
}

func TestTagServiceDelegatesAndHandlesEmptyInputs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secretID := uuid.New()
	userID := uuid.New()
	foundIDs := []uuid.UUID{uuid.New(), uuid.New()}
	repo := &mockSecretTagRepository{}
	svc := secrets.NewTagService(repo, testutils.NewTestLogger(t))

	require.NoError(t, svc.AddTags(ctx, secretID, nil))
	require.NoError(t, svc.RemoveTags(ctx, secretID, []string{}))
	emptyFound, err := svc.FindSecretsByTags(ctx, userID, nil)
	require.NoError(t, err)
	assert.Empty(t, emptyFound)

	repo.On("AddTags", ctx, secretID, []string{"prod", "db"}).Return(nil)
	repo.On("RemoveTags", ctx, secretID, []string{"db"}).Return(nil)
	repo.On("RemoveAllTags", ctx, secretID).Return(nil)
	repo.On("GetTags", ctx, secretID).Return([]string{"prod"}, nil)
	repo.On("FindSecretsByTags", ctx, userID, []string{"prod"}).Return(foundIDs, nil)

	require.NoError(t, svc.AddTags(ctx, secretID, []string{"prod", "db"}))
	require.NoError(t, svc.RemoveTags(ctx, secretID, []string{"db"}))
	require.NoError(t, svc.RemoveAllTags(ctx, secretID))
	tags, err := svc.GetTags(ctx, secretID)
	require.NoError(t, err)
	assert.Equal(t, []string{"prod"}, tags)
	ids, err := svc.FindSecretsByTags(ctx, userID, []string{"prod"})
	require.NoError(t, err)
	assert.Equal(t, foundIDs, ids)

	repo.AssertExpectations(t)
}

func TestTagServiceWrapsRepositoryErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secretID := uuid.New()
	userID := uuid.New()
	repo := &mockSecretTagRepository{}
	svc := secrets.NewTagService(repo, testutils.NewTestLogger(t))

	repo.On("AddTags", ctx, secretID, []string{"prod"}).Return(errors.New("insert failed"))
	repo.On("RemoveTags", ctx, secretID, []string{"prod"}).Return(errors.New("delete failed"))
	repo.On("RemoveAllTags", ctx, secretID).Return(errors.New("delete all failed"))
	repo.On("GetTags", ctx, secretID).Return(nil, errors.New("select failed"))
	repo.On("FindSecretsByTags", ctx, userID, []string{"prod"}).Return(nil, errors.New("find failed"))

	assert.ErrorContains(t, svc.AddTags(ctx, secretID, []string{"prod"}), "add tags")
	assert.ErrorContains(t, svc.RemoveTags(ctx, secretID, []string{"prod"}), "remove tags")
	assert.ErrorContains(t, svc.RemoveAllTags(ctx, secretID), "remove all tags")
	_, err := svc.GetTags(ctx, secretID)
	assert.ErrorContains(t, err, "get tags")
	_, err = svc.FindSecretsByTags(ctx, userID, []string{"prod"})
	assert.ErrorContains(t, err, "find secrets by tags")

	repo.AssertExpectations(t)
}

func TestExpirationServiceLifecycleAndPlaceholders(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	svc := secrets.NewExpirationService(secrets.ExpirationServiceConfig{
		SecretRepository: &testutils.MockSecretRepository{},
		Logger:           testutils.NewTestLogger(t),
	})

	expiring, err := svc.CheckExpiringSecrets(ctx)
	require.NoError(t, err)
	assert.Empty(t, expiring)

	expiring, err = svc.GetExpiringSecrets(ctx, 30)
	require.NoError(t, err)
	assert.Empty(t, expiring)

	disabledCount, err := svc.DisableExpiredSecrets(ctx)
	require.NoError(t, err)
	assert.Zero(t, disabledCount)

	now := time.Now()
	notBefore := now.Add(2 * time.Hour)
	expiresAt := now.Add(time.Hour)
	err = svc.ValidateSecretLifecycle(&model.Secret{ID: uuid.New(), NotBefore: &notBefore, ExpiresAt: &expiresAt})
	assert.ErrorContains(t, err, "must be before")

	pastExpiry := now.Add(-time.Hour)
	err = svc.ValidateSecretLifecycle(&model.Secret{ID: uuid.New(), ExpiresAt: &pastExpiry})
	assert.NoError(t, err)
}

func TestCryptographyServiceRoundTripAndConfigError(t *testing.T) {
	originalKey := viper.GetString("master_key")
	t.Cleanup(func() { viper.Set("master_key", originalKey) })

	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	viper.Set("master_key", key)

	svc := secrets.NewCryptographyService()
	encrypted, err := svc.EncryptSecret("plain-secret")
	require.NoError(t, err)
	assert.NotEqual(t, "plain-secret", encrypted)

	decrypted, err := svc.DecryptSecret(encrypted)
	require.NoError(t, err)
	assert.Equal(t, "plain-secret", decrypted)

	viper.Set("master_key", "")
	_, err = svc.EncryptSecret("plain-secret")
	assert.ErrorContains(t, err, "master key not configured")
	_, err = svc.DecryptSecret(encrypted)
	assert.ErrorContains(t, err, "master key not configured")
}

func TestSecretServiceVaultScopedOperations(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()
	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}
	svc := newService(repo, crypto, ver, tag, t)

	repo.On("ReadInVault", ctx, secretID, vaultID).Return(&model.Secret{
		ID:      secretID,
		UserID:  userID,
		VaultID: vaultID,
		Name:    "vault-secret",
		Value:   "encrypted",
		Enabled: true,
	}, nil).Once()
	crypto.On("DecryptSecret", "encrypted").Return("plain", nil).Once()
	tag.On("GetTags", ctx, secretID).Return([]string{"vault"}, nil).Once()

	got, err := svc.GetSecretInVault(ctx, secretID, vaultID)
	require.NoError(t, err)
	assert.Equal(t, "plain", got.Value)
	assert.Equal(t, []string{"vault"}, got.Tags)

	repo.On("ListInVault", ctx, vaultID, []string{"vault"}).Return([]model.Secret{{
		ID:      secretID,
		UserID:  userID,
		VaultID: vaultID,
		Name:    "vault-secret",
		Value:   "encrypted-list",
		Enabled: true,
	}}, nil).Once()
	crypto.On("DecryptSecret", "encrypted-list").Return("plain-list", nil).Once()
	tag.On("GetTags", ctx, secretID).Return([]string{"vault"}, nil).Once()

	list, err := svc.ListSecretsInVault(ctx, vaultID, []string{"vault"})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "plain-list", list[0].Value)

	repo.On("ReadInVault", ctx, secretID, vaultID).Return(&model.Secret{
		ID:      secretID,
		UserID:  userID,
		VaultID: vaultID,
		Name:    "vault-secret",
	}, nil).Once()
	tag.On("RemoveAllTags", ctx, secretID).Return(nil).Once()
	repo.On("SoftDelete", ctx, secretID).Return(nil).Once()

	require.NoError(t, svc.DeleteSecretInVault(ctx, secretID, vaultID))
	repo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	tag.AssertExpectations(t)
}

func TestSecretServiceVersionDelegates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	secretID := uuid.New()
	userID := uuid.New()
	versions := []model.SecretVersion{{ID: uuid.New(), SecretID: secretID, UserID: userID, Version: 1}}
	version := &model.SecretVersion{ID: uuid.New(), SecretID: secretID, UserID: userID, Version: 2}
	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}
	svc := newService(repo, crypto, ver, tag, t)

	ver.On("GetVersions", ctx, secretID, userID).Return(versions, nil)
	ver.On("GetVersion", ctx, secretID, 2, userID).Return(version, nil)
	ver.On("GetLatestVersion", ctx, secretID, userID).Return(version, nil)

	gotVersions, err := svc.GetSecretVersions(ctx, secretID, userID)
	require.NoError(t, err)
	assert.Equal(t, versions, gotVersions)

	gotVersion, err := svc.GetSecretVersion(ctx, secretID, 2, userID)
	require.NoError(t, err)
	assert.Equal(t, version, gotVersion)

	gotLatest, err := svc.GetLatestSecretVersion(ctx, secretID, userID)
	require.NoError(t, err)
	assert.Equal(t, version, gotLatest)

	ver.AssertExpectations(t)
}

func TestSecretServiceCoreErrorBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	t.Run("update failures", func(t *testing.T) {
		t.Parallel()

		current := &model.Secret{ID: secretID, UserID: userID, Name: "old", Value: "encrypted-old", Version: 1}

		repo := &testutils.MockSecretRepository{}
		crypto := &testutils.MockCryptographyService{}
		ver := &testutils.MockVersioningService{}
		tag := &testutils.MockTagService{}
		svc := newService(repo, crypto, ver, tag, t)

		repo.On("Read", ctx, secretID).Return(nil, errors.New("missing")).Once()
		err := svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, UserID: userID})
		assert.ErrorContains(t, err, "secret not found")

		repo.On("Read", ctx, secretID).Return(current, nil).Once()
		crypto.On("DecryptSecret", "encrypted-old").Return("", errors.New("decrypt failed")).Once()
		err = svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, UserID: userID})
		assert.ErrorContains(t, err, "failed to decrypt current secret")

		repo.On("Read", ctx, secretID).Return(current, nil).Once()
		crypto.On("DecryptSecret", "encrypted-old").Return("plain-old", nil).Once()
		ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).Return(nil, errors.New("version failed")).Once()
		err = svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, UserID: userID})
		assert.ErrorContains(t, err, "failed to create version")

		badContentType := "application/zip"
		repo.On("Read", ctx, secretID).Return(current, nil).Once()
		crypto.On("DecryptSecret", "encrypted-old").Return("plain-old", nil).Once()
		ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).Return(&model.SecretVersion{Version: 1}, nil).Once()
		err = svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, UserID: userID, ContentType: &badContentType})
		assert.ErrorContains(t, err, "unsupported content type")

		newValue := "new-value"
		repo.On("Read", ctx, secretID).Return(current, nil).Once()
		crypto.On("DecryptSecret", "encrypted-old").Return("plain-old", nil).Once()
		ver.On("CreateVersion", ctx, mock.AnythingOfType("secrets.CreateVersionRequest")).Return(&model.SecretVersion{Version: 1}, nil).Once()
		crypto.On("EncryptSecret", newValue).Return("", errors.New("encrypt failed")).Once()
		err = svc.UpdateSecret(ctx, secrets.UpdateSecretRequest{SecretID: secretID, UserID: userID, Value: &newValue})
		assert.ErrorContains(t, err, "failed to encrypt updated secret")

		repo.AssertExpectations(t)
		crypto.AssertExpectations(t)
		ver.AssertExpectations(t)
	})

	t.Run("read and delete failures", func(t *testing.T) {
		t.Parallel()

		repo := &testutils.MockSecretRepository{}
		crypto := &testutils.MockCryptographyService{}
		ver := &testutils.MockVersioningService{}
		tag := &testutils.MockTagService{}
		svc := newService(repo, crypto, ver, tag, t)

		repo.On("ReadByOwner", ctx, secretID, userID).Return(&model.Secret{
			ID:      secretID,
			UserID:  userID,
			Value:   "encrypted",
			Enabled: true,
		}, nil).Once()
		crypto.On("DecryptSecret", "encrypted").Return("", errors.New("decrypt failed")).Once()
		_, err := svc.GetSecret(ctx, secretID, userID)
		assert.ErrorContains(t, err, "failed to decrypt secret")

		repo.On("ReadByOwner", ctx, secretID, userID).Return(&model.Secret{
			ID:      secretID,
			UserID:  userID,
			Value:   "encrypted",
			Enabled: true,
		}, nil).Once()
		crypto.On("DecryptSecret", "encrypted").Return("plain", nil).Once()
		tag.On("GetTags", ctx, secretID).Return(nil, errors.New("tags failed")).Once()
		_, err = svc.GetSecret(ctx, secretID, userID)
		assert.ErrorContains(t, err, "failed to load tags")

		repo.On("ReadByOwner", ctx, secretID, userID).Return(&model.Secret{
			ID:      secretID,
			UserID:  userID,
			Value:   "encrypted",
			Enabled: false,
		}, nil).Once()
		crypto.On("DecryptSecret", "encrypted").Return("plain", nil).Once()
		tag.On("GetTags", ctx, secretID).Return([]string{}, nil).Once()
		_, err = svc.GetSecret(ctx, secretID, userID)
		assert.ErrorIs(t, err, secrets.ErrSecretLifecycleDenied)

		repo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: userID}, nil).Once()
		tag.On("RemoveAllTags", ctx, secretID).Return(errors.New("tags failed")).Once()
		err = svc.DeleteSecret(ctx, secretID, userID)
		assert.ErrorContains(t, err, "failed to remove tags")

		repo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: userID}, nil).Once()
		tag.On("RemoveAllTags", ctx, secretID).Return(nil).Once()
		repo.On("SoftDelete", ctx, secretID).Return(errors.New("soft delete failed")).Once()
		err = svc.DeleteSecret(ctx, secretID, userID)
		assert.ErrorContains(t, err, "failed to soft delete secret")

		repo.AssertExpectations(t)
		crypto.AssertExpectations(t)
		tag.AssertExpectations(t)
	})
}

func TestSecretServiceExportAndImport(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()
	repo := &testutils.MockSecretRepository{}
	crypto := &testutils.MockCryptographyService{}
	ver := &testutils.MockVersioningService{}
	tag := &testutils.MockTagService{}
	svc := newService(repo, crypto, ver, tag, t)

	repo.On("ListByUser", ctx, userID, []string{"prod"}).Return([]model.Secret{{
		ID:      secretID,
		UserID:  userID,
		Name:    "db",
		Value:   "encrypted",
		Enabled: true,
	}}, nil).Once()
	crypto.On("DecryptSecret", "encrypted").Return("plain", nil).Once()
	tag.On("GetTags", ctx, secretID).Return([]string{"prod"}, nil).Once()

	jsonData, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		UserID:      userID,
		Format:      "json",
		FilterTags:  []string{"prod"},
		IncludeTags: true,
	})
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), `"name": "db"`)
	assert.Contains(t, string(jsonData), `"tags"`)

	repo.On("ListByUser", ctx, userID, []string(nil)).Return([]model.Secret{{
		ID:      secretID,
		UserID:  userID,
		Name:    "csv-db",
		Value:   "encrypted-csv",
		Enabled: true,
	}}, nil).Once()
	crypto.On("DecryptSecret", "encrypted-csv").Return("csv-plain", nil).Once()
	tag.On("GetTags", ctx, secretID).Return([]string{"csv", "prod"}, nil).Once()

	csvData, err := svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{
		UserID:      userID,
		Format:      "csv",
		IncludeTags: true,
	})
	require.NoError(t, err)
	assert.Contains(t, string(csvData), "name,value,tags")
	assert.Contains(t, string(csvData), `"csv-db","csv-plain","csv,prod"`)

	_, err = svc.ExportSecrets(ctx, secrets.ExportSecretsRequest{UserID: userID, Format: "yaml"})
	assert.ErrorContains(t, err, "invalid format")

	crypto.On("EncryptSecret", "one").Return("encrypted-one", nil).Once()
	repo.On("Create", ctx, mock.MatchedBy(func(secret *model.Secret) bool {
		return secret.UserID == userID && secret.Name == "api" && secret.Value == "encrypted-one"
	})).Return(nil).Once()

	result, err := svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{
		UserID: userID,
		Format: "csv",
		Data:   []byte("name,value,tags\napi,one,\"prod,api\"\nmissing,\n"),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ImportedCount)
	assert.Equal(t, 1, result.SkippedCount)
	assert.Equal(t, 2, result.TotalCount)

	_, err = svc.ImportSecrets(ctx, secrets.ImportSecretsRequest{UserID: userID, Format: "xml"})
	assert.ErrorContains(t, err, "invalid format")

	repo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	tag.AssertExpectations(t)
}

func TestVersioningServiceHappyPathAndOwnershipErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	otherID := uuid.New()
	secretID := uuid.New()
	secret := &model.Secret{ID: secretID, UserID: userID, Name: "db", Value: "current", Version: 2}
	versionRepo := &mockSecretVersionRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	userRepo := &mockUserRepository{}
	crypto := &testutils.MockCryptographyService{}
	svc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t))

	userRepo.On("Read", ctx, userID).Return(&model.User{ID: userID, Username: "alice"}, nil).Once()
	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	crypto.On("EncryptSecret", "plain-v1").Return("encrypted-v1", nil).Once()
	versionRepo.On("CreateVersion", ctx, mock.MatchedBy(func(version *model.SecretVersion) bool {
		return version.SecretID == secretID && version.UserID == userID && version.Value == "encrypted-v1"
	})).Return(nil).Once()

	created, err := svc.CreateVersion(ctx, secrets.CreateVersionRequest{
		SecretID: secretID,
		UserID:   userID,
		Name:     "db",
		Value:    "plain-v1",
		Version:  1,
	})
	require.NoError(t, err)
	assert.Equal(t, "plain-v1", created.Value)

	encryptedVersions := []model.SecretVersion{{ID: uuid.New(), SecretID: secretID, UserID: userID, Value: "encrypted-v1", Version: 1}}
	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	versionRepo.On("GetVersions", ctx, secretID).Return(encryptedVersions, nil).Once()
	crypto.On("DecryptSecret", "encrypted-v1").Return("plain-v1", nil).Once()

	versions, err := svc.GetVersions(ctx, secretID, userID)
	require.NoError(t, err)
	require.Len(t, versions, 1)
	assert.Equal(t, "plain-v1", versions[0].Value)

	target := &model.SecretVersion{ID: uuid.New(), SecretID: secretID, UserID: userID, Value: "encrypted-target", Version: 1}
	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	versionRepo.On("GetVersion", ctx, secretID, 1).Return(target, nil).Once()
	crypto.On("DecryptSecret", "encrypted-target").Return("rolled-back", nil).Once()
	userRepo.On("Read", ctx, userID).Return(&model.User{ID: userID, Username: "alice"}, nil).Once()
	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	crypto.On("EncryptSecret", "current").Return("encrypted-current", nil).Once()
	versionRepo.On("CreateVersion", ctx, mock.MatchedBy(func(version *model.SecretVersion) bool {
		return version.SecretID == secretID && version.UserID == userID && version.Value == "encrypted-current"
	})).Return(nil).Once()
	secretRepo.On("Update", ctx, mock.MatchedBy(func(updated *model.Secret) bool {
		return updated.Value == "rolled-back" && updated.Version == 4
	})).Return(nil).Once()

	rolledBack, err := svc.RollbackToVersion(ctx, secrets.RollbackRequest{
		SecretID:      secretID,
		TargetVersion: 1,
		UserID:        userID,
	})
	require.NoError(t, err)
	assert.Equal(t, "rolled-back", rolledBack.Value)
	assert.Equal(t, 4, rolledBack.Version)

	secretRepo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: otherID}, nil).Once()
	err = svc.DeleteVersions(ctx, secretID, userID)
	assert.ErrorContains(t, err, "does not own")

	versionRepo.AssertExpectations(t)
	secretRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	crypto.AssertExpectations(t)
}

func TestVersioningServiceGetLatestAndDeleteMethods(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()
	secret := &model.Secret{ID: secretID, UserID: userID, Name: "db", Value: "current", Version: 3}
	versionRepo := &mockSecretVersionRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	userRepo := &mockUserRepository{}
	crypto := &testutils.MockCryptographyService{}
	svc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t))

	encryptedV2 := &model.SecretVersion{ID: uuid.New(), SecretID: secretID, UserID: userID, Value: "encrypted-v2", Version: 2}
	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	versionRepo.On("GetVersion", ctx, secretID, 2).Return(encryptedV2, nil).Once()
	crypto.On("DecryptSecret", "encrypted-v2").Return("plain-v2", nil).Once()

	gotVersion, err := svc.GetVersion(ctx, secretID, 2, userID)
	require.NoError(t, err)
	assert.Equal(t, "plain-v2", gotVersion.Value)

	encryptedLatest := &model.SecretVersion{ID: uuid.New(), SecretID: secretID, UserID: userID, Value: "encrypted-latest", Version: 3}
	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	versionRepo.On("GetLatestVersion", ctx, secretID).Return(encryptedLatest, nil).Once()
	crypto.On("DecryptSecret", "encrypted-latest").Return("plain-latest", nil).Once()

	gotLatest, err := svc.GetLatestVersion(ctx, secretID, userID)
	require.NoError(t, err)
	assert.Equal(t, "plain-latest", gotLatest.Value)

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	versionRepo.On("DeleteVersions", ctx, secretID).Return(nil).Once()
	require.NoError(t, svc.DeleteVersions(ctx, secretID, userID))

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	versionRepo.On("DeleteSpecificVersion", ctx, secretID, 2).Return(nil).Once()
	require.NoError(t, svc.DeleteSpecificVersion(ctx, secretID, 2, userID))

	secretRepo.On("Read", ctx, secretID).Return(nil, errors.New("missing")).Once()
	_, err = svc.GetVersion(ctx, secretID, 99, userID)
	assert.ErrorContains(t, err, "secret not found")

	secretRepo.AssertExpectations(t)
	versionRepo.AssertExpectations(t)
	crypto.AssertExpectations(t)
}

func TestRotationServicePolicyLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	policyID := uuid.New()
	createdAt := time.Now().Add(-time.Hour)
	repo := &mockRotationPolicyRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	userRepo := &mockUserRepository{}
	crypto := &testutils.MockCryptographyService{}
	svc := secrets.NewRotationService(repo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t))

	userRepo.On("Read", ctx, userID).Return(&model.User{ID: userID, Username: "alice"}, nil).Once()
	repo.On("Create", ctx, mock.MatchedBy(func(policy *model.RotationPolicy) bool {
		return policy.UserID == userID &&
			policy.Name == "monthly" &&
			policy.IntervalDays == 30 &&
			policy.ReminderDays == 7 &&
			policy.Enabled &&
			policy.AutoRotate
	})).Return(nil).Once()

	created, err := svc.CreatePolicy(ctx, secrets.CreatePolicyRequest{
		UserID:       userID,
		Name:         "monthly",
		Description:  "rotate monthly",
		IntervalDays: 30,
		ReminderDays: 7,
		Enabled:      true,
		AutoRotate:   true,
	})
	require.NoError(t, err)
	assert.Equal(t, "monthly", created.Name)

	userRepo.On("Read", ctx, userID).Return(&model.User{ID: userID, Username: "alice"}, nil).Once()
	_, err = svc.CreatePolicy(ctx, secrets.CreatePolicyRequest{
		UserID:       userID,
		Name:         "bad",
		IntervalDays: 7,
		ReminderDays: 7,
	})
	assert.ErrorContains(t, err, "must be less")

	existing := &model.RotationPolicy{ID: policyID, UserID: userID, Name: "old", IntervalDays: 30, ReminderDays: 7, CreatedAt: createdAt}
	repo.On("Read", ctx, policyID).Return(existing, nil).Once()
	repo.On("Update", ctx, mock.MatchedBy(func(policy *model.RotationPolicy) bool {
		return policy.ID == policyID && policy.UserID == userID && policy.Name == "weekly" && policy.CreatedAt.Equal(createdAt)
	})).Return(nil).Once()

	updated, err := svc.UpdatePolicy(ctx, secrets.UpdatePolicyRequest{
		ID:           policyID,
		UserID:       userID,
		Name:         "weekly",
		IntervalDays: 14,
		ReminderDays: 3,
		Enabled:      true,
	})
	require.NoError(t, err)
	assert.Equal(t, "weekly", updated.Name)

	repo.On("Read", ctx, policyID).Return(&model.RotationPolicy{ID: policyID, UserID: uuid.New()}, nil).Once()
	_, err = svc.UpdatePolicy(ctx, secrets.UpdatePolicyRequest{ID: policyID, UserID: userID, Name: "x", IntervalDays: 10})
	assert.ErrorContains(t, err, "does not own")

	policies := []model.RotationPolicy{*created}
	repo.On("Read", ctx, policyID).Return(existing, nil).Once()
	repo.On("ListByUser", ctx, userID).Return(policies, nil).Once()
	repo.On("Read", ctx, policyID).Return(existing, nil).Once()
	repo.On("Delete", ctx, policyID).Return(nil).Once()

	gotPolicy, err := svc.GetPolicy(ctx, policyID)
	require.NoError(t, err)
	assert.Equal(t, existing, gotPolicy)

	list, err := svc.ListUserPolicies(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, policies, list)

	require.NoError(t, svc.DeletePolicy(ctx, policyID, userID))
	repo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

func TestRotationServiceAssignmentRotationAndReminders(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()
	policyID := uuid.New()
	secret := &model.Secret{ID: secretID, UserID: userID, Name: "api", Value: "current", Version: 3}
	policy := &model.RotationPolicy{ID: policyID, UserID: userID, Name: "monthly", IntervalDays: 30, ReminderDays: 5, AutoRotate: true}
	repo := &mockRotationPolicyRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	userRepo := &mockUserRepository{}
	crypto := &testutils.MockCryptographyService{}
	svc := secrets.NewRotationService(repo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t))

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("Read", ctx, policyID).Return(policy, nil).Once()
	repo.On("AssignToSecret", ctx, secretID, policyID, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time")).Return(nil).Once()
	repo.On("CreateReminder", ctx, mock.MatchedBy(func(reminder *model.RotationReminder) bool {
		return reminder.SecretID == secretID && reminder.PolicyID == policyID && reminder.ReminderType == model.ReminderUpcoming
	})).Return(nil).Once()

	require.NoError(t, svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{
		SecretID: secretID,
		PolicyID: policyID,
		UserID:   userID,
	}))

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("RemoveFromSecret", ctx, secretID, policyID).Return(nil).Once()
	require.NoError(t, svc.RemovePolicyFromSecret(ctx, secretID, policyID, userID))

	policies := []model.RotationPolicy{*policy}
	repo.On("GetPoliciesForSecret", ctx, secretID).Return(policies, nil).Once()
	gotPolicies, err := svc.GetSecretPolicies(ctx, secretID, uuid.Nil)
	require.NoError(t, err)
	assert.Equal(t, policies, gotPolicies)

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("Read", ctx, policyID).Return(policy, nil).Once()
	secretRepo.On("Update", ctx, mock.MatchedBy(func(updated *model.Secret) bool {
		return updated.ID == secretID && updated.Version == 4 && updated.Value != "current"
	})).Return(nil).Once()
	repo.On("RecordRotation", ctx, mock.MatchedBy(func(history *model.RotationHistory) bool {
		return history.SecretID == secretID && *history.PolicyID == policyID && history.PreviousVersion == 3 && history.NewVersion == 4
	})).Return(nil).Once()
	repo.On("UpdateSecretPolicyRotation", ctx, secretID, policyID, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time")).Return(nil).Once()

	require.NoError(t, svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		UserID:   userID,
		Notes:    "rotate now",
	}))

	history := []model.RotationHistory{{ID: uuid.New(), SecretID: secretID}}
	due := []model.SecretPolicy{{SecretID: secretID, PolicyID: policyID}}
	reminders := []model.RotationReminder{{ID: uuid.New(), SecretID: secretID, PolicyID: policyID}}
	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("GetRotationHistory", ctx, secretID).Return(history, nil).Once()
	repo.On("GetDueRotations", ctx, userID).Return(due, nil).Once()
	repo.On("CreateReminder", ctx, mock.MatchedBy(func(reminder *model.RotationReminder) bool {
		return reminder.ReminderType == model.ReminderOverdue
	})).Return(nil).Once()
	repo.On("GetUpcomingReminders", ctx, userID).Return(reminders, nil).Once()
	repo.On("UpdateReminder", ctx, mock.MatchedBy(func(reminder *model.RotationReminder) bool {
		return reminder.ID == reminders[0].ID && reminder.Acknowledged
	})).Return(nil).Once()

	gotHistory, err := svc.GetRotationHistory(ctx, secretID, userID)
	require.NoError(t, err)
	assert.Equal(t, history, gotHistory)
	gotDue, err := svc.GetDueRotations(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, due, gotDue)
	require.NoError(t, svc.CreateRotationReminder(ctx, secrets.CreateReminderRequest{
		SecretID:     secretID,
		PolicyID:     policyID,
		ReminderType: model.ReminderOverdue,
	}))
	gotReminders, err := svc.GetUpcomingReminders(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, reminders, gotReminders)
	require.NoError(t, svc.AcknowledgeReminder(ctx, reminders[0].ID, secretID, uuid.Nil))

	err = svc.CreateRotationReminder(ctx, secrets.CreateReminderRequest{
		SecretID:     secretID,
		PolicyID:     policyID,
		ReminderType: "later",
	})
	assert.ErrorContains(t, err, "invalid reminder type")

	repo.AssertExpectations(t)
	secretRepo.AssertExpectations(t)
}

func TestRotationServiceErrorBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	otherID := uuid.New()
	secretID := uuid.New()
	policyID := uuid.New()
	secret := &model.Secret{ID: secretID, UserID: userID, Name: "api", Value: "current", Version: 1}
	policy := &model.RotationPolicy{ID: policyID, UserID: userID, Name: "monthly", IntervalDays: 30}
	repo := &mockRotationPolicyRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	userRepo := &mockUserRepository{}
	crypto := &testutils.MockCryptographyService{}
	svc := secrets.NewRotationService(repo, secretRepo, userRepo, crypto, testutils.NewTestLogger(t))

	userRepo.On("Read", ctx, userID).Return(nil, errors.New("missing user")).Once()
	_, err := svc.CreatePolicy(ctx, secrets.CreatePolicyRequest{UserID: userID, Name: "p", IntervalDays: 30})
	assert.ErrorContains(t, err, "user not found")

	userRepo.On("Read", ctx, userID).Return(&model.User{ID: userID}, nil).Once()
	repo.On("Create", ctx, mock.AnythingOfType("*model.RotationPolicy")).Return(errors.New("insert failed")).Once()
	_, err = svc.CreatePolicy(ctx, secrets.CreatePolicyRequest{UserID: userID, Name: "p", IntervalDays: 30})
	assert.ErrorContains(t, err, "failed to create rotation policy")

	repo.On("Read", ctx, policyID).Return(nil, errors.New("missing policy")).Once()
	_, err = svc.GetPolicy(ctx, policyID)
	assert.ErrorContains(t, err, "failed to get rotation policy")

	repo.On("Read", ctx, policyID).Return(nil, errors.New("missing policy")).Once()
	_, err = svc.UpdatePolicy(ctx, secrets.UpdatePolicyRequest{ID: policyID, UserID: userID, Name: "p", IntervalDays: 30})
	assert.ErrorContains(t, err, "policy not found")

	repo.On("Read", ctx, policyID).Return(policy, nil).Once()
	repo.On("Update", ctx, mock.AnythingOfType("*model.RotationPolicy")).Return(errors.New("update failed")).Once()
	_, err = svc.UpdatePolicy(ctx, secrets.UpdatePolicyRequest{ID: policyID, UserID: userID, Name: "p", IntervalDays: 30})
	assert.ErrorContains(t, err, "failed to update rotation policy")

	repo.On("Read", ctx, policyID).Return(&model.RotationPolicy{ID: policyID, UserID: otherID}, nil).Once()
	err = svc.DeletePolicy(ctx, policyID, userID)
	assert.ErrorContains(t, err, "forbidden")

	repo.On("Read", ctx, policyID).Return(policy, nil).Once()
	repo.On("Delete", ctx, policyID).Return(errors.New("delete failed")).Once()
	err = svc.DeletePolicy(ctx, policyID, userID)
	assert.ErrorContains(t, err, "failed to delete rotation policy")

	repo.On("ListByUser", ctx, userID).Return(nil, errors.New("list failed")).Once()
	_, err = svc.ListUserPolicies(ctx, userID)
	assert.ErrorContains(t, err, "failed to list user policies")

	secretRepo.On("Read", ctx, secretID).Return(nil, errors.New("missing secret")).Once()
	err = svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{SecretID: secretID, PolicyID: policyID, UserID: userID})
	assert.ErrorContains(t, err, "secret not found")

	secretRepo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: otherID}, nil).Once()
	err = svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{SecretID: secretID, PolicyID: policyID, UserID: userID})
	assert.ErrorContains(t, err, "does not own this secret")

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("Read", ctx, policyID).Return(nil, errors.New("missing policy")).Once()
	err = svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{SecretID: secretID, PolicyID: policyID, UserID: userID})
	assert.ErrorContains(t, err, "policy not found")

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("Read", ctx, policyID).Return(&model.RotationPolicy{ID: policyID, UserID: otherID}, nil).Once()
	err = svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{SecretID: secretID, PolicyID: policyID, UserID: userID})
	assert.ErrorContains(t, err, "does not own this policy")

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("Read", ctx, policyID).Return(policy, nil).Once()
	repo.On("AssignToSecret", ctx, secretID, policyID, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time")).Return(errors.New("assign failed")).Once()
	err = svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{SecretID: secretID, PolicyID: policyID, UserID: userID})
	assert.ErrorContains(t, err, "failed to assign policy")

	secretRepo.On("Read", ctx, secretID).Return(nil, errors.New("missing secret")).Once()
	err = svc.RemovePolicyFromSecret(ctx, secretID, policyID, userID)
	assert.ErrorContains(t, err, "secret not found")

	secretRepo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: otherID}, nil).Once()
	err = svc.RemovePolicyFromSecret(ctx, secretID, policyID, userID)
	assert.ErrorContains(t, err, "forbidden")

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("RemoveFromSecret", ctx, secretID, policyID).Return(errors.New("remove failed")).Once()
	err = svc.RemovePolicyFromSecret(ctx, secretID, policyID, userID)
	assert.ErrorContains(t, err, "failed to remove policy")

	repo.On("GetPoliciesForSecret", ctx, secretID).Return(nil, errors.New("policies failed")).Once()
	_, err = svc.GetSecretPolicies(ctx, secretID, uuid.Nil)
	assert.ErrorContains(t, err, "failed to get secret policies")

	secretRepo.On("Read", ctx, secretID).Return(nil, errors.New("missing secret")).Once()
	err = svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{SecretID: secretID, PolicyID: policyID, UserID: userID})
	assert.ErrorContains(t, err, "secret not found")

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("Read", ctx, policyID).Return(policy, nil).Once()
	secretRepo.On("Update", ctx, mock.AnythingOfType("*model.Secret")).Return(errors.New("update failed")).Once()
	err = svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{SecretID: secretID, PolicyID: policyID, UserID: userID})
	assert.ErrorContains(t, err, "failed to update secret during rotation")

	secretRepo.On("Read", ctx, secretID).Return(nil, errors.New("missing secret")).Once()
	_, err = svc.GetRotationHistory(ctx, secretID, userID)
	assert.ErrorContains(t, err, "secret not found")

	secretRepo.On("Read", ctx, secretID).Return(secret, nil).Once()
	repo.On("GetRotationHistory", ctx, secretID).Return(nil, errors.New("history failed")).Once()
	_, err = svc.GetRotationHistory(ctx, secretID, userID)
	assert.ErrorContains(t, err, "failed to get rotation history")

	repo.On("GetDueRotations", ctx, userID).Return(nil, errors.New("due failed")).Once()
	_, err = svc.GetDueRotations(ctx, userID)
	assert.ErrorContains(t, err, "failed to get due rotations")

	repo.On("CreateReminder", ctx, mock.AnythingOfType("*model.RotationReminder")).Return(errors.New("reminder failed")).Once()
	err = svc.CreateRotationReminder(ctx, secrets.CreateReminderRequest{
		SecretID:     secretID,
		PolicyID:     policyID,
		ReminderType: model.ReminderUpcoming,
	})
	assert.ErrorContains(t, err, "failed to create rotation reminder")

	repo.On("GetUpcomingReminders", ctx, userID).Return(nil, errors.New("reminders failed")).Once()
	_, err = svc.GetUpcomingReminders(ctx, userID)
	assert.ErrorContains(t, err, "failed to get upcoming reminders")

	repo.On("UpdateReminder", ctx, mock.AnythingOfType("*model.RotationReminder")).Return(errors.New("ack failed")).Once()
	err = svc.AcknowledgeReminder(ctx, uuid.New(), secretID, uuid.Nil)
	assert.ErrorContains(t, err, "failed to acknowledge reminder")

	repo.AssertExpectations(t)
	secretRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

func TestSchedulerServiceProcessesRotationsRemindersAndLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()
	policyID := uuid.New()
	reminderID := uuid.New()
	rotationSvc := &mockRotationService{}
	versionSvc := &testutils.MockVersioningService{}
	userRepo := &mockUserRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	rotationRepo := &mockRotationPolicyRepository{}
	svc := secrets.NewSchedulerService(rotationSvc, versionSvc, userRepo, secretRepo, rotationRepo, testutils.NewTestLogger(t))

	assert.False(t, svc.IsRunning())
	require.NoError(t, svc.Start(ctx, time.Hour))
	assert.True(t, svc.IsRunning())
	assert.ErrorContains(t, svc.Start(ctx, time.Hour), "already running")
	require.NoError(t, svc.Stop())
	assert.False(t, svc.IsRunning())
	require.NoError(t, svc.Stop())

	due := []model.SecretPolicy{{SecretID: secretID, PolicyID: policyID}}
	rotationSvc.On("GetDueRotations", ctx, userID).Return(due, nil).Once()
	rotationSvc.On("GetPolicy", ctx, policyID).Return(&model.RotationPolicy{ID: policyID, UserID: userID, AutoRotate: false}, nil).Once()
	require.NoError(t, svc.ProcessUserRotations(ctx, userID))

	rotationSvc.On("GetDueRotations", ctx, userID).Return(due, nil).Once()
	rotationSvc.On("GetPolicy", ctx, policyID).Return(&model.RotationPolicy{ID: policyID, UserID: userID, AutoRotate: true}, nil).Once()
	secretRepo.On("Read", ctx, secretID).Return(&model.Secret{ID: secretID, UserID: userID, Name: "api", Value: "current", Version: 1}, nil).Once()
	versionSvc.On("CreateVersion", ctx, mock.MatchedBy(func(req secrets.CreateVersionRequest) bool {
		return req.SecretID == secretID && req.UserID == userID && req.Version == 2
	})).Return(&model.SecretVersion{ID: uuid.New()}, nil).Once()
	rotationSvc.On("PerformManualRotation", ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		UserID:   userID,
		Notes:    "Automatic rotation by scheduler",
	}).Return(nil).Once()
	require.NoError(t, svc.ProcessUserRotations(ctx, userID))

	reminders := []model.RotationReminder{{ID: reminderID, SecretID: secretID, PolicyID: policyID, ReminderType: model.ReminderUpcoming}}
	rotationSvc.On("GetUpcomingReminders", ctx, userID).Return(reminders, nil).Once()
	rotationSvc.On("AcknowledgeReminder", ctx, reminderID, secretID, uuid.Nil).Return(nil).Once()
	require.NoError(t, svc.ProcessUserReminders(ctx, userID))

	manualReq := secrets.ManualSchedulerRotationRequest{SecretID: secretID, PolicyID: policyID, UserID: userID, Notes: "manual"}
	rotationSvc.On("PerformManualRotation", ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		UserID:   userID,
		Notes:    "manual",
	}).Return(nil).Once()
	require.NoError(t, svc.PerformManualRotation(ctx, manualReq))

	rotationSvc.AssertExpectations(t)
	versionSvc.AssertExpectations(t)
	secretRepo.AssertExpectations(t)
}

func TestSchedulerServiceBackgroundTickProcessesAllUsers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	userID := uuid.New()
	rotationSvc := &mockRotationService{}
	versionSvc := &testutils.MockVersioningService{}
	userRepo := &mockUserRepository{}
	secretRepo := &testutils.MockSecretRepository{}
	rotationRepo := &mockRotationPolicyRepository{}
	svc := secrets.NewSchedulerService(rotationSvc, versionSvc, userRepo, secretRepo, rotationRepo, testutils.NewTestLogger(t))

	listed := make(chan struct{})
	userRepo.On("List", mock.Anything).Return([]model.User{{ID: userID, Username: "alice"}}, nil).
		Run(func(mock.Arguments) {
			select {
			case <-listed:
			default:
				close(listed)
			}
		}).Maybe()
	rotationSvc.On("GetDueRotations", mock.Anything, userID).Return([]model.SecretPolicy{}, nil).Maybe()
	rotationSvc.On("GetUpcomingReminders", mock.Anything, userID).Return([]model.RotationReminder{}, nil).Maybe()

	require.NoError(t, svc.Start(ctx, time.Millisecond))
	select {
	case <-listed:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("List was not called within 100ms")
	}
	require.NoError(t, svc.Stop())

	userRepo.AssertExpectations(t)
	rotationSvc.AssertExpectations(t)
}
