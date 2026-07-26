package secrets

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// MockSecretRepository is a minimal test double for
// repositories.SecretRepositoryInterface. It embeds the interface (left nil)
// so it satisfies the full method set at compile time; this package's
// internal tests cannot import internal/testutils (that package imports
// rocketvault/internal/services/secrets, which would form an import cycle
// with a package-secrets test file), so only the methods these tests
// exercise get real behavior. Calling any other method panics on the nil
// embedded interface, which is the correct failure mode for an unstubbed call.
type MockSecretRepository struct {
	mock.Mock
	repositories.SecretRepositoryInterface
}

func (m *MockSecretRepository) ReadScoped(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepository) ListScoped(ctx context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// MockTagService is a minimal test double for TagService. See
// MockSecretRepository for why this is a local, package-scoped mock rather
// than a shared one from internal/testutils.
type MockTagService struct {
	mock.Mock
	TagService
}

func (m *MockTagService) GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockTagService) RemoveAllTags(ctx context.Context, secretID uuid.UUID) error {
	args := m.Called(ctx, secretID)
	return args.Error(0)
}

// MockVersioningService is a minimal test double for VersioningServiceInterface.
// None of the tests in this file exercise versioning, so no methods are
// overridden; it exists only to satisfy secretService.versionService's type.
type MockVersioningService struct {
	mock.Mock
	VersioningServiceInterface
}

// newTestLogger returns a logger suitable for use in tests. Mirrors
// testutils.NewTestLogger, duplicated locally because package-scoped tests
// here cannot import internal/testutils without an import cycle.
func newTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

// fakeCrypto is a reversible ENC(...) wrapper so tests can assert on the
// plaintext the service returns.
type fakeCrypto struct{}

func (fakeCrypto) EncryptSecret(v string) (string, error) { return "ENC(" + v + ")", nil }
func (fakeCrypto) DecryptSecret(v string) (string, error) {
	if len(v) > 5 && v[:4] == "ENC(" && v[len(v)-1] == ')' {
		return v[4 : len(v)-1], nil
	}
	return v, nil
}

// newScopeServiceFixture builds a secretService over mock collaborators.
// The crypto mock is a reversible ENC(...) wrapper so tests can assert on the
// plaintext the service returns.
func newScopeServiceFixture(t *testing.T) (*MockSecretRepository, *secretService) {
	t.Helper()
	repo := new(MockSecretRepository)
	tags := new(MockTagService)
	tags.On("GetTags", mock.Anything, mock.Anything).Return([]string{}, nil).Maybe()
	tags.On("RemoveAllTags", mock.Anything, mock.Anything).Return(nil).Maybe()

	svc := &secretService{
		secretRepo:     repo,
		cryptoService:  fakeCrypto{},
		versionService: new(MockVersioningService),
		tagService:     tags,
		logger:         newTestLogger(t),
	}
	return repo, svc
}

func TestGetSecretScopedPassesTheScopeStraightToTheRepository(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	vaultID := uuid.New()
	actorID := uuid.New()
	scope := model.NewVaultScope(vaultID, actorID)

	repo.On("ReadScoped", ctx, secretID, scope).Return(&model.Secret{
		ID: secretID, VaultID: vaultID, Name: "s", Value: "ENC(v)", Enabled: true,
	}, nil).Once()

	got, err := svc.GetSecretScoped(ctx, secretID, scope)
	require.NoError(t, err)
	assert.Equal(t, secretID, got.ID)
	assert.Equal(t, "v", got.Value, "the service decrypts before returning")
	repo.AssertExpectations(t)
}

func TestGetSecretScopedMapsNotFoundToErrSecretNotFound(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("ReadScoped", ctx, mock.Anything, scope).
		Return(nil, assert.AnError).Once()

	_, err := svc.GetSecretScoped(ctx, uuid.New(), scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestListDeletedSecretsScopedFiltersInSQLNotInGo(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("ListScoped", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: uuid.New()}}, nil).Once()

	got, err := svc.ListDeletedSecretsScoped(ctx, scope)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	repo.AssertExpectations(t)
}

func TestDeleteSecretScopedChecksScopeBeforeSoftDeleting(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("ReadScoped", ctx, secretID, scope).Return(nil, assert.AnError).Once()

	err := svc.DeleteSecretScoped(ctx, secretID, scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "SoftDelete", mock.Anything, mock.Anything)
}

func TestLegacyShimsBuildTheRightScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	userID := uuid.New()
	vaultID := uuid.New()

	repo.On("ReadScoped", ctx, secretID, model.NewOwnerScope(uuid.Nil, userID)).
		Return(&model.Secret{ID: secretID, Value: "ENC(v)", Enabled: true}, nil).Once()
	_, err := svc.GetSecret(ctx, secretID, userID)
	require.NoError(t, err)

	repo.On("ReadScoped", ctx, secretID, model.NewVaultScope(vaultID, uuid.Nil)).
		Return(&model.Secret{ID: secretID, Value: "ENC(v)", Enabled: true}, nil).Once()
	_, err = svc.GetSecretInVault(ctx, secretID, vaultID)
	require.NoError(t, err)

	repo.AssertExpectations(t)
}
