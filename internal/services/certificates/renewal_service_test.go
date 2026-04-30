package certificates_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/certificates"
)

// mockCertRepoForRenewal satisfies CertificateRepositoryInterface for renewal tests.
type mockCertRepoForRenewal struct{ mock.Mock }

func (m *mockCertRepoForRenewal) Create(ctx context.Context, cert *domain.Certificate) error {
	return m.Called(ctx, cert).Error(0)
}

func (m *mockCertRepoForRenewal) Read(ctx context.Context, id uuid.UUID) (*domain.Certificate, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*domain.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepoForRenewal) Update(ctx context.Context, cert *domain.Certificate) error {
	return m.Called(ctx, cert).Error(0)
}

func (m *mockCertRepoForRenewal) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepoForRenewal) Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error {
	return m.Called(ctx, id, serialNumber, name).Error(0)
}

func (m *mockCertRepoForRenewal) ListByUser(ctx context.Context, userID uuid.UUID, certType string, tags []string) ([]domain.Certificate, error) {
	args := m.Called(ctx, userID, certType, tags)
	if v := args.Get(0); v != nil {
		return v.([]domain.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepoForRenewal) ListRevoked(ctx context.Context, userID uuid.UUID) ([]domain.RevokedCertificate, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]domain.RevokedCertificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepoForRenewal) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepoForRenewal) RecoverCertificate(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepoForRenewal) PurgeCertificate(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepoForRenewal) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return m.Called(ctx, id, enabled).Error(0)
}

func (m *mockCertRepoForRenewal) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*domain.Certificate, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]*domain.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepoForRenewal) ListAll(ctx context.Context) ([]domain.Certificate, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.([]domain.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

// mockCertSvcForRenewal satisfies CertificateService for renewal tests.
// Only RenewCertificate is exercised; all other methods panic if called unexpectedly.
type mockCertSvcForRenewal struct{ mock.Mock }

func (m *mockCertSvcForRenewal) CreateSelfSignedCertificate(ctx context.Context, req certificates.CreateCertificateRequest) (*certificates.CreateCertificateResult, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) CreateCASignedCertificate(ctx context.Context, req certificates.CreateCertificateRequest) (*certificates.CreateCertificateResult, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) GetCertificate(ctx context.Context, certID, userID uuid.UUID) (*domain.Certificate, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) ListCertificates(ctx context.Context, userID uuid.UUID) ([]domain.Certificate, error) {
	panic("not called")
}

func (m *mockCertSvcForRenewal) UpdateCertificate(ctx context.Context, req certificates.UpdateCertificateRequest) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) DeleteCertificate(ctx context.Context, certID, userID uuid.UUID) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*certificates.CreateCertificateResult, error) {
	args := m.Called(ctx, certID, userID, validityDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certificates.CreateCertificateResult), args.Error(1)
}

func (m *mockCertSvcForRenewal) ValidateCertificateAccess(ctx context.Context, certID, userID uuid.UUID, role string) error {
	panic("not called")
}

func (m *mockCertSvcForRenewal) ValidateKeyOwnership(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	panic("not called")
}

// newTestLogger creates a minimal logger for unit tests.
func newTestLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func TestCheckAndRenewCertificates_AutoRenew(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	certID := uuid.New()
	userID := uuid.New()
	cert := domain.Certificate{
		ID:          certID,
		UserID:      userID,
		Name:        "test-cert",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   true,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]domain.Certificate{cert}, nil)

	certSvc := &mockCertSvcForRenewal{}
	certSvc.On("RenewCertificate", mock.Anything, certID, userID, mock.AnythingOfType("int")).
		Return(&certificates.CreateCertificateResult{CertID: uuid.New()}, nil)

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertExpectations(t)
}

func TestCheckAndRenewCertificates_WarnOnly(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	cert := domain.Certificate{
		ID:          uuid.New(),
		UserID:      uuid.New(),
		Name:        "warn-cert",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		ExpiresAt:   &expires,
		AutoRenew:   false,
		RenewalDays: 30,
	}

	repo := &mockCertRepoForRenewal{}
	repo.On("ListAll", mock.Anything).Return([]domain.Certificate{cert}, nil)

	certSvc := &mockCertSvcForRenewal{}
	// RenewCertificate must NOT be called.

	svc := certificates.NewCertificateRenewalService(certificates.RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 1, warned)
	certSvc.AssertNotCalled(t, "RenewCertificate")
}
