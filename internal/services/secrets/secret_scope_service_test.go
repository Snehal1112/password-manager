package secrets

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

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

func (m *MockSecretRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Secret), args.Error(1)
}

func (m *MockSecretRepository) List(ctx context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Secret), args.Error(1)
}

func (m *MockSecretRepository) Update(ctx context.Context, secret *model.Secret, scope model.Scope) error {
	args := m.Called(ctx, secret, scope)
	return args.Error(0)
}

func (m *MockSecretRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) RecoverSecret(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) PurgeSecret(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSecretRepository) Create(ctx context.Context, secret *model.Secret) error {
	args := m.Called(ctx, secret)
	return args.Error(0)
}

func (m *MockSecretRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	args := m.Called(ctx, id, enabled)
	return args.Error(0)
}

// MockVaultRepository is a minimal test double for
// repositories.VaultRepositoryInterface. Only ReadByID is exercised — the
// purge-protection cascade check is the sole reason the secret service holds a
// vault repository at all. See MockSecretRepository for why the interface is
// embedded rather than fully implemented.
type MockVaultRepository struct {
	mock.Mock
	repositories.VaultRepositoryInterface
}

func (m *MockVaultRepository) ReadByID(ctx context.Context, id uuid.UUID) (*model.Vault, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Vault), args.Error(1)
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
// CreateVersion is overridden because UpdateSecret calls it on every
// update; no other method is exercised by tests in this file, so those fall
// through to the nil embedded interface, which is the correct failure mode
// for an unstubbed call.
type MockVersioningService struct {
	mock.Mock
	VersioningServiceInterface
}

func (m *MockVersioningService) CreateVersion(ctx context.Context, req CreateVersionRequest) (*model.SecretVersion, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecretVersion), args.Error(1)
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

	versions := new(MockVersioningService)
	versions.On("CreateVersion", mock.Anything, mock.Anything).Return(&model.SecretVersion{}, nil).Maybe()

	svc := &secretService{
		secretRepo:     repo,
		cryptoService:  fakeCrypto{},
		versionService: versions,
		tagService:     tags,
		logger:         newTestLogger(t),
	}
	return repo, svc
}

func TestGetSecretPassesTheScopeStraightToTheRepository(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	vaultID := uuid.New()
	actorID := uuid.New()
	scope := model.NewVaultScope(vaultID, actorID)

	repo.On("Read", ctx, secretID, scope).Return(&model.Secret{
		ID: secretID, VaultID: vaultID, Name: "s", Value: "ENC(v)", Enabled: true,
	}, nil).Once()

	got, err := svc.GetSecret(ctx, secretID, scope)
	require.NoError(t, err)
	assert.Equal(t, secretID, got.ID)
	assert.Equal(t, "v", got.Value, "the service decrypts before returning")
	repo.AssertExpectations(t)
}

func TestGetSecretMapsNotFoundToErrSecretNotFound(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("Read", ctx, mock.Anything, scope).
		Return(nil, assert.AnError).Once()

	_, err := svc.GetSecret(ctx, uuid.New(), scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestListDeletedSecretsFiltersInSQLNotInGo(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: uuid.New()}}, nil).Once()

	got, err := svc.ListDeletedSecrets(ctx, scope)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	repo.AssertExpectations(t)
}

func TestDeleteSecretChecksScopeBeforeSoftDeleting(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("Read", ctx, secretID, scope).Return(nil, assert.AnError).Once()

	err := svc.DeleteSecret(ctx, secretID, scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "SoftDelete", mock.Anything, mock.Anything)
}

func TestUpdateSecretUsesTheSameScopeForReadAndWrite(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	vaultID := uuid.New()
	actorID := uuid.New()
	scope := model.NewVaultScope(vaultID, actorID)
	newName := "renamed"

	current := &model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultID,
		Name: "original", Value: "ENC(v1)", Version: 1, Enabled: true,
	}

	repo.On("Read", ctx, secretID, scope).Return(current, nil).Once()
	repo.On("Update", ctx, mock.MatchedBy(func(s *model.Secret) bool {
		return s.Name == "renamed" && s.Version == 2
	}), scope).Return(nil).Once()

	err := svc.UpdateSecret(ctx, UpdateSecretRequest{
		SecretID: secretID,
		Scope:    scope,
		Name:     &newName,
	})
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestUpdateSecretDeniesOutOfScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("Read", ctx, secretID, scope).Return(nil, assert.AnError).Once()

	err := svc.UpdateSecret(ctx, UpdateSecretRequest{SecretID: secretID, Scope: scope})
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

func TestUpdateSecretRejectsAnInvalidScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	// A half-migrated caller that forgot to set Scope must not reach the repo
	// with an admin-equivalent predicate.
	var zero model.Scope
	repo.On("Read", mock.Anything, mock.Anything, zero).
		Return(nil, repositories.ErrInvalidScope).Once()

	err := svc.UpdateSecret(ctx, UpdateSecretRequest{SecretID: uuid.New()})
	require.Error(t, err)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

func TestRecoverSecretRequiresTheSecretToBeInScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{}, nil).Once()

	err := svc.RecoverSecret(ctx, secretID, scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "RecoverSecret", mock.Anything, mock.Anything)
}

func TestRecoverSecretRecoversWhenInScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	deletedAt := time.Now().UTC()

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, DeletedAt: &deletedAt}}, nil).Once()
	repo.On("RecoverSecret", ctx, secretID).Return(nil).Once()

	require.NoError(t, svc.RecoverSecret(ctx, secretID, scope))
	repo.AssertExpectations(t)
}

func TestPurgeSecretRequiresTheSecretToBeInScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{}, nil).Once()

	err := svc.PurgeSecret(ctx, uuid.New(), scope)
	assert.ErrorIs(t, err, ErrSecretNotFound)
	repo.AssertNotCalled(t, "PurgeSecret", mock.Anything, mock.Anything)
}

func TestPurgeSecretPurgesWhenInScope(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	deletedAt := time.Now().UTC()

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, DeletedAt: &deletedAt}}, nil).Once()
	repo.On("PurgeSecret", ctx, secretID).Return(nil).Once()

	require.NoError(t, svc.PurgeSecret(ctx, secretID, scope))
	repo.AssertExpectations(t)
}

func TestCreateSecretSetsPurgeProtectionWhenRequested(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil).Once()
	repo.On("SetPurgeProtection", ctx, mock.AnythingOfType("uuid.UUID"), true).Return(nil).Once()

	protect := true
	secret, err := svc.CreateSecret(ctx, CreateSecretRequest{
		UserID: uuid.New(), Name: "s1", Value: "v1", PurgeProtection: &protect,
	})
	require.NoError(t, err)
	repo.AssertCalled(t, "SetPurgeProtection", ctx, secret.ID, true)
	repo.AssertExpectations(t)
}

func TestCreateSecretLeavesPurgeProtectionAloneByDefault(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil).Once()

	_, err := svc.CreateSecret(ctx, CreateSecretRequest{UserID: uuid.New(), Name: "s1", Value: "v1"})
	require.NoError(t, err)
	repo.AssertNotCalled(t, "SetPurgeProtection", mock.Anything, mock.Anything, mock.Anything)
}

func TestCreateSecretSetsPurgeProtectionFalseWhenExplicitlyRequested(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	repo.On("Create", ctx, mock.AnythingOfType("*model.Secret")).Return(nil).Once()
	repo.On("SetPurgeProtection", ctx, mock.AnythingOfType("uuid.UUID"), false).Return(nil).Once()

	protect := false
	secret, err := svc.CreateSecret(ctx, CreateSecretRequest{
		UserID: uuid.New(), Name: "s1", Value: "v1", PurgeProtection: &protect,
	})
	require.NoError(t, err)
	repo.AssertCalled(t, "SetPurgeProtection", ctx, secret.ID, false)
	repo.AssertExpectations(t)
}

func TestUpdateSecretSetsPurgeProtectionWhenRequested(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	secretID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())

	repo.On("Read", ctx, secretID, scope).Return(&model.Secret{
		ID: secretID, UserID: uuid.New(), VaultID: vaultID,
		Name: "original", Value: "ENC(v1)", Version: 1, Enabled: true,
	}, nil).Once()
	repo.On("Update", ctx, mock.Anything, scope).Return(nil).Once()
	repo.On("SetPurgeProtection", ctx, secretID, true).Return(nil).Once()

	protect := true
	require.NoError(t, svc.UpdateSecret(ctx, UpdateSecretRequest{
		SecretID: secretID, Scope: scope, PurgeProtection: &protect,
	}))
	repo.AssertExpectations(t)
}

func TestPurgeSecretBlockedWhenVaultIsPurgeProtected(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	vaultRepo := new(MockVaultRepository)
	svc.vaultRepo = vaultRepo

	secretID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	deletedAt := time.Now().UTC()

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, VaultID: vaultID, DeletedAt: &deletedAt}}, nil).Once()
	vaultRepo.On("ReadByID", ctx, vaultID).
		Return(&model.Vault{ID: vaultID, PurgeProtection: true}, nil).Once()

	err := svc.PurgeSecret(ctx, secretID, scope)
	assert.ErrorIs(t, err, repositories.ErrSecretPurgeProtected)
	repo.AssertNotCalled(t, "PurgeSecret", mock.Anything, mock.Anything)
	vaultRepo.AssertExpectations(t)
}

// TestPurgeSecretFailsClosedWhenVaultReadFails pins the fail-closed contract:
// for a secret carrying no purge-protection flag of its own, the vault lookup
// is the only protection layer, so a transient read failure must block the
// purge rather than silently skip the check.
func TestPurgeSecretFailsClosedWhenVaultReadFails(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	vaultRepo := new(MockVaultRepository)
	svc.vaultRepo = vaultRepo

	secretID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	deletedAt := time.Now().UTC()

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, VaultID: vaultID, DeletedAt: &deletedAt}}, nil).Once()
	vaultRepo.On("ReadByID", ctx, vaultID).Return(nil, assert.AnError).Once()

	err := svc.PurgeSecret(ctx, secretID, scope)
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
	repo.AssertNotCalled(t, "PurgeSecret", mock.Anything, mock.Anything)
	vaultRepo.AssertExpectations(t)
}

func TestPurgeSecretProceedsWhenVaultIsNotPurgeProtected(t *testing.T) {
	repo, svc := newScopeServiceFixture(t)
	ctx := context.Background()

	vaultRepo := new(MockVaultRepository)
	svc.vaultRepo = vaultRepo

	secretID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	deletedAt := time.Now().UTC()

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, VaultID: vaultID, DeletedAt: &deletedAt}}, nil).Once()
	vaultRepo.On("ReadByID", ctx, vaultID).
		Return(&model.Vault{ID: vaultID}, nil).Once()
	repo.On("PurgeSecret", ctx, secretID).Return(nil).Once()

	require.NoError(t, svc.PurgeSecret(ctx, secretID, scope))
	repo.AssertExpectations(t)
	vaultRepo.AssertExpectations(t)
}

// auditRecord is one persisted audit row. Mirrors the shape defined in
// direct_write_invalidation_test.go, duplicated here because that file lives
// in package secrets_test (a separate black-box package) and its unexported
// helpers aren't visible from this file's package secrets.
type auditRecord struct {
	userID  string
	action  string
	details string
}

// recordingAuditPersister captures the audit rows a service emitted.
type recordingAuditPersister struct {
	mu      sync.Mutex
	records []auditRecord
}

func (p *recordingAuditPersister) PersistAudit(userID, action, details string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, auditRecord{userID, action, details})
	return nil
}

func (p *recordingAuditPersister) find(action, status string) (auditRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rec := range p.records {
		if rec.action == action && strings.Contains(rec.details, "status="+status) {
			return rec, true
		}
	}
	return auditRecord{}, false
}

// newAuditingLogger returns a quiet logger whose audit calls are captured.
func newAuditingLogger(t *testing.T) (*logging.Logger, *recordingAuditPersister) {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	logger := logging.WrapLogrus(l)
	persister := &recordingAuditPersister{}
	logger.SetAuditPersister(persister)
	return logger, persister
}

func TestRecoverSecret_LogsSuccessAudit(t *testing.T) {
	repo := new(MockSecretRepository)
	tags := new(MockTagService)
	tags.On("GetTags", mock.Anything, mock.Anything).Return([]string{}, nil).Maybe()
	tags.On("RemoveAllTags", mock.Anything, mock.Anything).Return(nil).Maybe()
	versions := new(MockVersioningService)
	versions.On("CreateVersion", mock.Anything, mock.Anything).Return(&model.SecretVersion{}, nil).Maybe()

	logger, audit := newAuditingLogger(t)
	svc := &secretService{
		secretRepo:     repo,
		cryptoService:  fakeCrypto{},
		versionService: versions,
		tagService:     tags,
		logger:         logger,
	}

	ctx := context.Background()
	owner := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, owner)
	secretID := uuid.New()
	deletedAt := time.Now().UTC()

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, DeletedAt: &deletedAt}}, nil).Once()
	repo.On("RecoverSecret", ctx, secretID).Return(nil).Once()

	require.NoError(t, svc.RecoverSecret(ctx, secretID, scope))

	rec, ok := audit.find("recover_secret", "success")
	require.True(t, ok, "RecoverSecret must emit a success audit row")
	assert.Equal(t, owner.String(), rec.userID)
}

func TestPurgeSecret_LogsSuccessAudit(t *testing.T) {
	repo := new(MockSecretRepository)
	tags := new(MockTagService)
	tags.On("GetTags", mock.Anything, mock.Anything).Return([]string{}, nil).Maybe()
	tags.On("RemoveAllTags", mock.Anything, mock.Anything).Return(nil).Maybe()
	versions := new(MockVersioningService)
	versions.On("CreateVersion", mock.Anything, mock.Anything).Return(&model.SecretVersion{}, nil).Maybe()

	logger, audit := newAuditingLogger(t)
	svc := &secretService{
		secretRepo:     repo,
		cryptoService:  fakeCrypto{},
		versionService: versions,
		tagService:     tags,
		logger:         logger,
	}

	ctx := context.Background()
	owner := uuid.New()
	vaultID := uuid.New()
	scope := model.NewVaultScope(vaultID, owner)
	secretID := uuid.New()
	deletedAt := time.Now().UTC()

	repo.On("List", ctx, scope, repositories.SecretFilter{OnlyDeleted: true}).
		Return([]model.Secret{{ID: secretID, DeletedAt: &deletedAt}}, nil).Once()
	repo.On("PurgeSecret", ctx, secretID).Return(nil).Once()

	require.NoError(t, svc.PurgeSecret(ctx, secretID, scope))

	rec, ok := audit.find("purge_secret", "success")
	require.True(t, ok, "PurgeSecret must emit a success audit row")
	assert.Equal(t, owner.String(), rec.userID)
}
