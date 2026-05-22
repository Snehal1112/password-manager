package certificates

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/model"
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

// TestRenewCertificate_Succeeds_WhenKeyIDSet verifies that RenewCertificate uses the KeyID
// stored on the original certificate to create the renewed certificate.
func TestRenewCertificate_Succeeds_WhenKeyIDSet(t *testing.T) {
	// Configure AES master key required by common.EncryptSecret / DecryptSecret.
	masterKeyBytes := make([]byte, 32)
	for i := range masterKeyBytes {
		masterKeyBytes[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(masterKeyBytes))

	userID := uuid.New()
	certID := uuid.New()
	keyID := uuid.New()

	// Generate a real RSA private key and encrypt it as the service would store it.
	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	existingCert := &model.Certificate{
		ID:          certID,
		UserID:      userID,
		KeyID:       keyID,
		Name:        "test-renew-cert",
		CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
		AutoRenew:   true,
		RenewalDays: 30,
	}

	mockKey := &model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// GetCertificate calls Read internally.
	certRepo.On("Read", mock.Anything, certID).Return(existingCert, nil)

	// keyRepo.Read is called twice: once in ValidateKeyOwnership, once to get the key PEM.
	keyRepo.On("Read", mock.Anything, keyID).Return(mockKey, nil)

	// Capture the cert passed to Create so we can assert KeyID is propagated.
	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) {
			createdCert = args.Get(1).(*model.Certificate)
		}).
		Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:         keyRepo,
		Logger:                logger,
	})

	result, err := svc.RenewCertificate(context.Background(), certID, userID, 365)
	require.NoError(t, err)
	assert.NotNil(t, result)

	require.NotNil(t, createdCert, "certRepo.Create must have been called")
	assert.Equal(t, keyID, createdCert.KeyID, "renewed certificate must carry the original KeyID")

	certRepo.AssertExpectations(t)
	keyRepo.AssertExpectations(t)
}
