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
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// mockCertRepository is a minimal testify mock for CertificateRepositoryInterface.
type mockCertRepository struct {
	mock.Mock
}

func (m *mockCertRepository) Create(ctx context.Context, cert *model.Certificate) error {
	return m.Called(ctx, cert).Error(0)
}

func (m *mockCertRepository) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Certificate), args.Error(1)
}

func (m *mockCertRepository) Update(ctx context.Context, cert *model.Certificate, scope model.Scope) error {
	args := m.Called(ctx, cert, scope)
	return args.Error(0)
}

func (m *mockCertRepository) List(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	args := m.Called(ctx, scope, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

func (m *mockCertRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockCertRepository) Revoke(ctx context.Context, id uuid.UUID, serialNumber, name string) error {
	return m.Called(ctx, id, serialNumber, name).Error(0)
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

func (m *mockCertRepository) ListAll(ctx context.Context) ([]model.Certificate, error) {
	args := m.Called(ctx)
	if v := args.Get(0); v != nil {
		return v.([]model.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockCertRepository) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

func (m *mockCertRepository) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	args := m.Called(ctx, vaultID, deletedAt)
	return args.Error(0)
}

// mockKeyRepo is a minimal stub for KeyRepositoryInterface used in CertificateServiceConfig.
// CertificateService only uses the key repo for ownership checks; we don't exercise it here.
type mockKeyRepo struct {
	mock.Mock
}

func (m *mockKeyRepo) Create(ctx context.Context, key *model.Key) error {
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

func (m *mockKeyRepo) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return m.Called(ctx, id, revoked).Error(0)
}

func (m *mockKeyRepo) RecoverKey(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockKeyRepo) ReadDeleted(ctx context.Context, id uuid.UUID) (*model.Key, error) {
	return nil, nil
}

func (m *mockKeyRepo) CreateVersion(ctx context.Context, keyID uuid.UUID, version int, value string) error {
	return nil
}

func (m *mockKeyRepo) ListVersions(ctx context.Context, keyID, userID uuid.UUID) ([]model.KeyVersion, error) {
	return nil, nil
}
func (m *mockKeyRepo) SoftDeleteVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}
func (m *mockKeyRepo) RecoverVaultContents(ctx context.Context, vaultID uuid.UUID, deletedAt time.Time) error {
	return nil
}
func (m *mockKeyRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	args := m.Called(ctx, id, scope)
	if v := args.Get(0); v != nil {
		return v.(*model.Key), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockKeyRepo) Update(ctx context.Context, key *model.Key, scope model.Scope) error {
	args := m.Called(ctx, key, scope)
	return args.Error(0)
}
func (m *mockKeyRepo) List(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	args := m.Called(ctx, scope, filter)
	if v := args.Get(0); v != nil {
		return v.([]model.Key), args.Error(1)
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
		Enabled:     true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// DeleteCertificate calls Read internally to check access before soft-deleting.
	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(existingCert, nil)

	// SoftDelete must be called exactly once.
	certRepo.On("SoftDelete", mock.Anything, certID).Return(nil)

	// Delete must NOT be called — no expectation registered; AssertNotCalled confirms this.

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:         keyRepo,
		Logger:                logger,
	})

	err := svc.DeleteCertificate(context.Background(), certID, model.NewOwnerScope(uuid.Nil, userID))
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
		Enabled:     true,
	}

	mockKey := &model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	// RenewCertificate calls GetCertificate, which calls Read internally.
	certRepo.On("Read", mock.Anything, certID, scope).Return(existingCert, nil)

	// keyRepo.Read is called twice with the same admin scope: once in
	// ValidateKeyOwnership, once to get the key PEM.
	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(mockKey, nil)

	// Renewal must update the existing row in place (same ID/name), not insert a
	// second row: certificates has a UNIQUE(vault_id, name) index, so inserting
	// a new row while the original (same name) still exists always fails.
	var updatedCert *model.Certificate
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).
		Run(func(args mock.Arguments) {
			updatedCert = args.Get(1).(*model.Certificate)
		}).
		Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:         keyRepo,
		Logger:                logger,
	})

	result, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
	require.NoError(t, err)
	assert.NotNil(t, result)

	require.NotNil(t, updatedCert, "certRepo.Update must have been called")
	assert.Equal(t, certID, updatedCert.ID, "renewal must keep the original certificate ID")
	assert.Equal(t, "test-renew-cert", updatedCert.Name, "renewal must keep the original certificate name")
	assert.Equal(t, keyID, updatedCert.KeyID, "renewed certificate must carry the original KeyID")

	certRepo.AssertExpectations(t)
	keyRepo.AssertExpectations(t)
}

// TestListDeletedCertificates_FiltersInSQLNotInGo verifies ListDeletedCertificates
// delegates straight to the scope-aware List with OnlyDeleted.
func TestListDeletedCertificates_FiltersInSQLNotInGo(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	now := time.Now()
	want := []model.Certificate{{ID: uuid.New(), Name: "cert", DeletedAt: &now}}

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).Return(want, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	got, err := svc.ListDeletedCertificates(context.Background(), scope)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
	repo.AssertExpectations(t)
}

// TestRecoverCertificate_RequiresTheCertToBeInScope verifies RecoverCertificate
// rejects a cert ID not in the scope's soft-deleted listing.
func TestRecoverCertificate_RequiresTheCertToBeInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).Return([]model.Certificate{}, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	err := svc.RecoverCertificate(context.Background(), certID, scope)
	assert.ErrorIs(t, err, ErrCertNotFound)
	repo.AssertNotCalled(t, "RecoverCertificate", mock.Anything, mock.Anything)
}

// TestRecoverCertificate_RecoversWhenInScope verifies RecoverCertificate calls
// the repository's RecoverCertificate once the cert is confirmed in scope.
func TestRecoverCertificate_RecoversWhenInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()
	now := time.Now()

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).
		Return([]model.Certificate{{ID: certID, Name: "cert", DeletedAt: &now}}, nil)
	repo.On("RecoverCertificate", mock.Anything, certID).Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	err := svc.RecoverCertificate(context.Background(), certID, scope)
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

// TestPurgeCertificate_RequiresTheCertToBeInScope mirrors
// TestRecoverCertificate_RequiresTheCertToBeInScope for purge.
func TestPurgeCertificate_RequiresTheCertToBeInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).Return([]model.Certificate{}, nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	err := svc.PurgeCertificate(context.Background(), certID, scope)
	assert.ErrorIs(t, err, ErrCertNotFound)
	repo.AssertNotCalled(t, "PurgeCertificate", mock.Anything, mock.Anything)
}

// TestPurgeCertificate_PurgesWhenInScope mirrors
// TestRecoverCertificate_RecoversWhenInScope for purge.
func TestPurgeCertificate_PurgesWhenInScope(t *testing.T) {
	scope := model.NewVaultScope(uuid.New(), uuid.New())
	certID := uuid.New()
	now := time.Now()

	repo := &mockCertRepository{}
	repo.On("List", mock.Anything, scope, repositories.CertificateFilter{OnlyDeleted: true}).
		Return([]model.Certificate{{ID: certID, Name: "cert", DeletedAt: &now}}, nil)
	repo.On("PurgeCertificate", mock.Anything, certID).Return(nil)

	logger := &logging.Logger{Logger: logrus.New()}
	svc := NewCertificateService(CertificateServiceConfig{CertificateRepository: repo, Logger: logger})

	err := svc.PurgeCertificate(context.Background(), certID, scope)
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}
