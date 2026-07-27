package certificates

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

// newTestCertLoggerT builds a silent logger for scope-focused tests.
func newTestCertLoggerT(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &logging.Logger{Logger: l}
}

func newCertScopeFixture(t *testing.T) (*mockCertRepository, *certificateService) {
	t.Helper()
	repo := new(mockCertRepository)
	return repo, &certificateService{
		certRepo: repo,
		keyRepo:  new(mockKeyRepo),
		logger:   newTestCertLoggerT(t),
	}
}

func TestGetCertificateScopedPassesTheScopeToTheRepository(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	certID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	repo.On("ReadScoped", ctx, certID, scope).
		Return(&model.Certificate{ID: certID, VaultID: vaultID, Enabled: true}, nil).Once()

	got, err := svc.GetCertificateScoped(ctx, certID, scope)
	require.NoError(t, err)
	assert.Equal(t, certID, got.ID)
	repo.AssertExpectations(t)
}

func TestGetCertificateScopedEnforcesLifecycle(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	certID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, certID, scope).
		Return(&model.Certificate{ID: certID, Enabled: false}, nil).Once()

	_, err := svc.GetCertificateScoped(ctx, certID, scope)
	assert.ErrorIs(t, err, ErrCertLifecycleDenied)
}

func TestGetCertificateScopedDeniesOutOfScope(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, mock.Anything, scope).Return(nil, assert.AnError).Once()

	_, err := svc.GetCertificateScoped(ctx, uuid.New(), scope)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestListCertificatesScopedForwardsTheFilter(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	scope := model.NewOwnerScope(uuid.Nil, uuid.New())
	filter := repositories.CertificateFilter{Tags: []string{"tls"}}
	repo.On("ListScoped", ctx, scope, filter).Return([]model.Certificate{{ID: uuid.New()}}, nil).Once()

	got, err := svc.ListCertificatesScoped(ctx, scope, filter)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	repo.AssertExpectations(t)
}

func TestUpdateCertificateScopedUsesTheSameScopeForReadAndWrite(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	certID, vaultID := uuid.New(), uuid.New()
	scope := model.NewVaultScope(vaultID, uuid.New())
	name := "renamed"

	repo.On("ReadScoped", ctx, certID, scope).
		Return(&model.Certificate{ID: certID, VaultID: vaultID, Name: "original", Enabled: true, RenewalDays: 30}, nil).Once()
	repo.On("UpdateScoped", ctx, mock.MatchedBy(func(c *model.Certificate) bool {
		return c.Name == "renamed"
	}), scope).Return(nil).Once()

	require.NoError(t, svc.UpdateCertificateScoped(ctx, UpdateCertificateRequest{CertID: certID, Scope: scope, Name: &name}))
	repo.AssertExpectations(t)
}

func TestDeleteCertificateScopedChecksScopeFirst(t *testing.T) {
	repo, svc := newCertScopeFixture(t)
	ctx := context.Background()

	certID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	repo.On("ReadScoped", ctx, certID, scope).Return(nil, assert.AnError).Once()

	err := svc.DeleteCertificateScoped(ctx, certID, scope)
	assert.ErrorIs(t, err, ErrCertNotFound)
	repo.AssertNotCalled(t, "SoftDelete", mock.Anything, mock.Anything)
}
