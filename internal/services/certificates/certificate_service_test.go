package certificates

// Tests for the certificate-policy methods on CertificateService
// (GetCertificatePolicy, UpsertCertificatePolicy, DeleteCertificatePolicy).
// These reuse the hand-rolled mockCertRepository declared in
// cert_soft_delete_test.go (same package) and add a matching hand-rolled
// mockPolicyRepo for CertificatePolicyRepositoryInterface, since that
// repository interface has no mockery-generated mock.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// mockPolicyRepo is a minimal testify mock for CertificatePolicyRepositoryInterface.
type mockPolicyRepo struct {
	mock.Mock
}

func (m *mockPolicyRepo) Upsert(ctx context.Context, policy *model.CertificatePolicy) error {
	return m.Called(ctx, policy).Error(0)
}

func (m *mockPolicyRepo) GetByCertificateID(ctx context.Context, certID, userID uuid.UUID) (*model.CertificatePolicy, error) {
	args := m.Called(ctx, certID, userID)
	if v := args.Get(0); v != nil {
		return v.(*model.CertificatePolicy), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockPolicyRepo) DeleteByCertificateID(ctx context.Context, certID, userID uuid.UUID) error {
	return m.Called(ctx, certID, userID).Error(0)
}

func (m *mockPolicyRepo) GetByCertificateIDAny(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error) {
	args := m.Called(ctx, certID)
	if v := args.Get(0); v != nil {
		return v.(*model.CertificatePolicy), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockPolicyRepo) DeleteByCertificateIDAny(ctx context.Context, certID uuid.UUID) error {
	return m.Called(ctx, certID).Error(0)
}

func TestGetCertificatePolicy_VerifiesCertAccessFirst(t *testing.T) {
	certRepo := new(mockCertRepository)
	policyRepo := new(mockPolicyRepo)
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{ID: certID, Enabled: true}, nil)
	want := &model.CertificatePolicy{ID: uuid.New(), CertificateID: certID}
	policyRepo.On("GetByCertificateIDAny", mock.Anything, certID).Return(want, nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		PolicyRepository:      policyRepo,
		Logger:                newTestCertLogger(),
	})

	got, err := svc.GetCertificatePolicy(context.Background(), certID, scope)

	require.NoError(t, err)
	assert.Equal(t, want, got)
	certRepo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

func TestGetCertificatePolicy_DeniesWhenCertAccessDenied(t *testing.T) {
	certRepo := new(mockCertRepository)
	policyRepo := new(mockPolicyRepo)
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, sql.ErrNoRows)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		PolicyRepository:      policyRepo,
		Logger:                newTestCertLogger(),
	})

	_, err := svc.GetCertificatePolicy(context.Background(), certID, scope)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
	policyRepo.AssertNotCalled(t, "GetByCertificateIDAny", mock.Anything, mock.Anything)
}

func TestUpsertCertificatePolicy_VerifiesCertAccessFirstAndReadsBack(t *testing.T) {
	certRepo := new(mockCertRepository)
	policyRepo := new(mockPolicyRepo)
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{ID: certID, Enabled: true}, nil)

	req := model.UpsertCertificatePolicyRequest{
		ValidityMonths:   12,
		KeyType:          "RSA",
		KeySize:          2048,
		Subject:          "CN=example.com",
		AutoRenew:        true,
		DaysBeforeExpiry: 30,
	}
	policyRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(p *model.CertificatePolicy) bool {
		return p.CertificateID == certID &&
			p.UserID == scope.ActorID() &&
			p.ValidityMonths == req.ValidityMonths &&
			p.KeyType == req.KeyType &&
			p.KeySize == req.KeySize &&
			p.Subject == req.Subject &&
			p.AutoRenew == req.AutoRenew &&
			p.DaysBeforeExpiry == req.DaysBeforeExpiry
	})).Return(nil)

	stored := &model.CertificatePolicy{ID: uuid.New(), CertificateID: certID, Subject: req.Subject}
	policyRepo.On("GetByCertificateIDAny", mock.Anything, certID).Return(stored, nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		PolicyRepository:      policyRepo,
		Logger:                newTestCertLogger(),
	})

	got, err := svc.UpsertCertificatePolicy(context.Background(), certID, scope, req)

	require.NoError(t, err)
	assert.Equal(t, stored, got)
	certRepo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

func TestUpsertCertificatePolicy_DeniesWhenCertAccessDenied(t *testing.T) {
	certRepo := new(mockCertRepository)
	policyRepo := new(mockPolicyRepo)
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, sql.ErrNoRows)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		PolicyRepository:      policyRepo,
		Logger:                newTestCertLogger(),
	})

	_, err := svc.UpsertCertificatePolicy(context.Background(), certID, scope, model.UpsertCertificatePolicyRequest{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
	policyRepo.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
}

func TestDeleteCertificatePolicy_VerifiesCertAccessFirst(t *testing.T) {
	certRepo := new(mockCertRepository)
	policyRepo := new(mockPolicyRepo)
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{ID: certID, Enabled: true}, nil)
	policyRepo.On("DeleteByCertificateIDAny", mock.Anything, certID).Return(nil)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		PolicyRepository:      policyRepo,
		Logger:                newTestCertLogger(),
	})

	err := svc.DeleteCertificatePolicy(context.Background(), certID, scope)

	require.NoError(t, err)
	certRepo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

func TestDeleteCertificatePolicy_DeniesWhenCertAccessDenied(t *testing.T) {
	certRepo := new(mockCertRepository)
	policyRepo := new(mockPolicyRepo)
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, sql.ErrNoRows)

	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		PolicyRepository:      policyRepo,
		Logger:                newTestCertLogger(),
	})

	err := svc.DeleteCertificatePolicy(context.Background(), certID, scope)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
	policyRepo.AssertNotCalled(t, "DeleteByCertificateIDAny", mock.Anything, mock.Anything)
}
