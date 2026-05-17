package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/model"
	"rocketvault/internal/logging"
)

// mockCertRepository is a minimal testify mock for CertificateRepositoryInterface.
type mockCertRepository struct {
	mock.Mock
}

func (m *mockCertRepository) Create(ctx context.Context, cert *model.Certificate) error {
	return m.Called(ctx, cert).Error(0)
}

func (m *mockCertRepository) Read(ctx context.Context, id uuid.UUID) (*model.Certificate, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*model.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepository) Update(ctx context.Context, cert *model.Certificate) error {
	return m.Called(ctx, cert).Error(0)
}

func (m *mockCertRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepository) Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error {
	return m.Called(ctx, id, serialNumber, name).Error(0)
}

func (m *mockCertRepository) ListByUser(ctx context.Context, userID uuid.UUID, certType string, tags []string) ([]model.Certificate, error) {
	args := m.Called(ctx, userID, certType, tags)
	if v := args.Get(0); v != nil {
		return v.([]model.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepository) ListRevoked(ctx context.Context, userID uuid.UUID) ([]model.RevokedCertificate, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]model.RevokedCertificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepository) PurgeCertificate(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepository) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return m.Called(ctx, id, enabled).Error(0)
}

func (m *mockCertRepository) RecoverCertificate(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepository) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Certificate, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]*model.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepository) ListAll(ctx context.Context) ([]model.Certificate, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.([]model.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

// mockKeyRepo is a minimal stub for KeyRepositoryInterface used in CertificateServiceConfig.
// CertificateService only uses the key repo for ownership checks; we don't exercise it here.
type mockKeyRepo struct {
	mock.Mock
}

func (m *mockKeyRepo) Create(ctx context.Context, key *model.Key) error {
	return m.Called(ctx, key).Error(0)
}

func (m *mockKeyRepo) Read(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, id)
	if v := args.Get(0); v != nil {
		return v.(*model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepo) Update(ctx context.Context, key *model.Key) error {
	return m.Called(ctx, key).Error(0)
}

func (m *mockKeyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepo) PurgeKey(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepo) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return m.Called(ctx, id, enabled).Error(0)
}

func (m *mockKeyRepo) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]model.Key, error) {
	args := m.Called(ctx, userID, keyType, tags)
	if v := args.Get(0); v != nil {
		return v.([]model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyRepo) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return m.Called(ctx, id, revoked).Error(0)
}

func (m *mockKeyRepo) RecoverKey(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepo) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*model.Key, error) {
	args := m.Called(ctx, userID)
	if v := args.Get(0); v != nil {
		return v.([]*model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}

// TestDeleteCertificateSoftDeletes verifies that DeleteCertificate calls SoftDelete on the
// repository and does not call the hard Delete method.
func TestDeleteCertificateSoftDeletes(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()

	existingCert := &model.Certificate{
		ID:          certID,
		UserID:      userID,
		Name:        "test-cert",
		Certificate: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		PrivateKey:  "encrypted-key",
		CreatedAt:   time.Now(),
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// GetCertificate calls Read internally — return the cert so access check passes.
	certRepo.On("Read", mock.Anything, certID).Return(existingCert, nil)

	// SoftDelete must be called exactly once.
	certRepo.On("SoftDelete", mock.Anything, certID).Return(nil)

	// Delete must NOT be called — no expectation registered; AssertNotCalled confirms this.

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:         keyRepo,
		Logger:                logger,
	})

	err := svc.DeleteCertificate(context.Background(), certID, userID)
	assert.NoError(t, err)

	certRepo.AssertCalled(t, "SoftDelete", mock.Anything, certID)
	certRepo.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	certRepo.AssertExpectations(t)
}
