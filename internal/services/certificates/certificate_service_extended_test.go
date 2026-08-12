package certificates

// Extended tests for CertificateService and CertificateRenewalScheduler.
// These tests live in the same package (white-box) so they can reuse the mocks
// already declared in cert_soft_delete_test.go.

import (
	"context"
	"encoding/base64"
	"errors"
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

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

func newTestCertLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func newCertSvc(certRepo *mockCertRepository, keyRepo *mockKeyRepo) CertificateService {
	return NewCertificateService(CertificateServiceConfig{
		CertificateRepository: certRepo,
		KeyRepository:         keyRepo,
		Logger:                newTestCertLogger(),
	})
}

func accessibleCert(userID, certID uuid.UUID) *model.Certificate {
	return &model.Certificate{
		ID:      certID,
		UserID:  userID,
		Name:    "test-cert",
		Enabled: true,
	}
}

// ────────────────────────────────────────────────────────────────────────────
// resolveVaultID
// ────────────────────────────────────────────────────────────────────────────

func TestResolveVaultID_NilReturnsDefault(t *testing.T) {
	result := resolveVaultID(uuid.Nil)
	assert.Equal(t, uuid.MustParse(model.DefaultVaultID), result)
}

func TestResolveVaultID_NonNilPreserved(t *testing.T) {
	vaultID := uuid.New()
	result := resolveVaultID(vaultID)
	assert.Equal(t, vaultID, result)
}

// ────────────────────────────────────────────────────────────────────────────
// ListCertificates
// ────────────────────────────────────────────────────────────────────────────

func TestListCertificates_Success(t *testing.T) {
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	expected := []model.Certificate{{ID: uuid.New(), UserID: userID, Name: "c1", Enabled: true}}
	certRepo.On("List", mock.Anything, scope, repositories.CertificateFilter{}).Return(expected, nil)

	svc := newCertSvc(certRepo, keyRepo)
	got, err := svc.ListCertificates(context.Background(), scope, repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Equal(t, expected, got)
	certRepo.AssertExpectations(t)
}

func TestListCertificates_RepositoryError(t *testing.T) {
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("List", mock.Anything, scope, repositories.CertificateFilter{}).
		Return(nil, errors.New("db error"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.ListCertificates(context.Background(), scope, repositories.CertificateFilter{})
	assert.Error(t, err)
	certRepo.AssertExpectations(t)
}

// ────────────────────────────────────────────────────────────────────────────
// GetCertificate – additional branches
// ────────────────────────────────────────────────────────────────────────────

func TestGetCertificate_NotFound(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, model.NewOwnerScope(uuid.Nil, userID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

// TestGetCertificate_WrongOwner verifies that a certificate owned by a
// different user is treated as not-found. Authorization is now enforced by
// the repository's Read predicate rather than a post-fetch Go
// comparison, so the mock simulates the repository finding no row that
// matches the caller's scope.
func TestGetCertificate_WrongOwner(t *testing.T) {
	callerID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, callerID)).
		Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, model.NewOwnerScope(uuid.Nil, callerID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestGetCertificate_LifecycleDenied(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// disabled cert
	certRepo.On("Read", mock.Anything, certID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Certificate{
		ID:      certID,
		UserID:  userID,
		Name:    "cert",
		Enabled: false,
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, model.NewOwnerScope(uuid.Nil, userID))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertLifecycleDenied)
}

// ────────────────────────────────────────────────────────────────────────────
// UpdateCertificate
// ────────────────────────────────────────────────────────────────────────────

func TestUpdateCertificate_AllFields(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	existing := accessibleCert(userID, certID)
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(existing, nil)
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).Return(nil)

	newName := "updated-cert"
	autoRenew := true
	renewDays := 60
	enabled := false
	nb := time.Now().Add(time.Hour)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.UpdateCertificate(context.Background(), UpdateCertificateRequest{
		CertID:      certID,
		Scope:       scope,
		Name:        &newName,
		Tags:        []string{"tag1"},
		AutoRenew:   &autoRenew,
		RenewalDays: &renewDays,
		Enabled:     &enabled,
		NotBefore:   &nb,
	})
	require.NoError(t, err)
	certRepo.AssertExpectations(t)
}

func TestUpdateCertificate_NoOptionalFields(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	existing := accessibleCert(userID, certID)
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(existing, nil)
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.UpdateCertificate(context.Background(), UpdateCertificateRequest{
		CertID: certID,
		Scope:  scope,
		// all optional fields nil / empty
	})
	require.NoError(t, err)
	certRepo.AssertExpectations(t)
}

func TestUpdateCertificate_GetCertificateFails(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.UpdateCertificate(context.Background(), UpdateCertificateRequest{
		CertID: certID,
		Scope:  scope,
	})
	require.Error(t, err)
}

func TestUpdateCertificate_RepositoryUpdateFails(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	existing := accessibleCert(userID, certID)
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(existing, nil)
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).
		Return(errors.New("update failed"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.UpdateCertificate(context.Background(), UpdateCertificateRequest{
		CertID: certID,
		Scope:  scope,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update certificate")
}

// ────────────────────────────────────────────────────────────────────────────
// DeleteCertificate – SoftDelete failure
// ────────────────────────────────────────────────────────────────────────────

func TestDeleteCertificate_SoftDeleteFails(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo.On("Read", mock.Anything, certID, scope).Return(accessibleCert(userID, certID), nil)
	certRepo.On("SoftDelete", mock.Anything, certID).Return(errors.New("db error"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.DeleteCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete certificate")
}

// ────────────────────────────────────────────────────────────────────────────
// GetCertificate — vault-scoped access
// ────────────────────────────────────────────────────────────────────────────

func TestGetCertificateVaultScope_Success(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	cert := &model.Certificate{ID: certID, UserID: uuid.New(), Name: "vc", Enabled: true}
	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(cert, nil)

	svc := newCertSvc(certRepo, keyRepo)
	got, err := svc.GetCertificate(context.Background(), certID, scope)
	require.NoError(t, err)
	assert.Equal(t, certID, got.ID)
	certRepo.AssertExpectations(t)
}

func TestGetCertificateVaultScope_NotFound(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestGetCertificateVaultScope_LifecycleDenied(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	cert := &model.Certificate{ID: certID, UserID: uuid.New(), Name: "vc", Enabled: false}
	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(cert, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.GetCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertLifecycleDenied)
}

// ────────────────────────────────────────────────────────────────────────────
// ListCertificates — vault-scoped access
// ────────────────────────────────────────────────────────────────────────────

func TestListCertificatesVaultScope_Success(t *testing.T) {
	vaultID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certs := []model.Certificate{{ID: uuid.New(), Name: "c1", Enabled: true}}
	certRepo.On("List", mock.Anything, scope, repositories.CertificateFilter{}).Return(certs, nil)

	svc := newCertSvc(certRepo, keyRepo)
	got, err := svc.ListCertificates(context.Background(), scope, repositories.CertificateFilter{})
	require.NoError(t, err)
	assert.Len(t, got, 1)
	certRepo.AssertExpectations(t)
}

func TestListCertificatesVaultScope_RepositoryError(t *testing.T) {
	vaultID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("List", mock.Anything, scope, repositories.CertificateFilter{}).
		Return(nil, errors.New("db error"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.ListCertificates(context.Background(), scope, repositories.CertificateFilter{})
	assert.Error(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// DeleteCertificate — vault-scoped access
// ────────────────────────────────────────────────────────────────────────────

func TestDeleteCertificateVaultScope_Success(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	cert := &model.Certificate{ID: certID, UserID: uuid.New(), Name: "vc", Enabled: true}
	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(cert, nil)
	certRepo.On("SoftDelete", mock.Anything, certID).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.DeleteCertificate(context.Background(), certID, scope)
	require.NoError(t, err)
	certRepo.AssertCalled(t, "SoftDelete", mock.Anything, certID)
	certRepo.AssertExpectations(t)
}

func TestDeleteCertificateVaultScope_NotFound(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.DeleteCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestDeleteCertificateVaultScope_SoftDeleteFails(t *testing.T) {
	vaultID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	cert := &model.Certificate{ID: certID, UserID: uuid.New(), Enabled: true}
	scope := model.NewVaultScope(vaultID, uuid.Nil)
	certRepo.On("Read", mock.Anything, certID, scope).Return(cert, nil)
	certRepo.On("SoftDelete", mock.Anything, certID).Return(errors.New("db error"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.DeleteCertificate(context.Background(), certID, scope)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete certificate")
}

// ────────────────────────────────────────────────────────────────────────────
// ValidateCertificateAccess
// ────────────────────────────────────────────────────────────────────────────

func TestValidateCertificateAccess_AdminBypassesCheck(t *testing.T) {
	certID := uuid.New()
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.ValidateCertificateAccess(context.Background(), certID, userID, model.RoleAdmin)
	require.NoError(t, err)
	// repository must NOT be called for admins
	certRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything, mock.Anything)
}

func TestValidateCertificateAccess_OwnerGranted(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, model.NewAdminScope(userID)).Return(&model.Certificate{
		ID: certID, UserID: userID, Enabled: true,
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.ValidateCertificateAccess(context.Background(), certID, userID, "")
	require.NoError(t, err)
}

func TestValidateCertificateAccess_ForbiddenForOtherUser(t *testing.T) {
	ownerID := uuid.New()
	callerID := uuid.New()
	certID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, model.NewAdminScope(callerID)).Return(&model.Certificate{
		ID: certID, UserID: ownerID, Enabled: true,
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.ValidateCertificateAccess(context.Background(), certID, callerID, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestValidateCertificateAccess_CertNotFound(t *testing.T) {
	certID := uuid.New()
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, model.NewAdminScope(userID)).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.ValidateCertificateAccess(context.Background(), certID, userID, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate not found")
}

// ────────────────────────────────────────────────────────────────────────────
// ValidateKeyOwnership – additional branches
// ────────────────────────────────────────────────────────────────────────────

func TestValidateKeyOwnership_AdminBypasses(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.ValidateKeyOwnership(context.Background(), keyID, userID, model.RoleAdmin)
	require.NoError(t, err)
	keyRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything, mock.Anything)
}

func TestValidateKeyOwnership_OwnerGranted(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(&model.Key{
		ID: keyID, UserID: userID, Enabled: true,
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.ValidateKeyOwnership(context.Background(), keyID, userID, "")
	require.NoError(t, err)
}

func TestValidateKeyOwnership_ForbiddenForOtherUser(t *testing.T) {
	ownerID := uuid.New()
	callerID := uuid.New()
	keyID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(callerID)).Return(&model.Key{
		ID: keyID, UserID: ownerID,
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.ValidateKeyOwnership(context.Background(), keyID, callerID, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestValidateKeyOwnership_KeyNotFound(t *testing.T) {
	keyID := uuid.New()
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	err := svc.ValidateKeyOwnership(context.Background(), keyID, userID, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// ────────────────────────────────────────────────────────────────────────────
// RenewCertificate – error branches
// ────────────────────────────────────────────────────────────────────────────

func TestRenewCertificate_NoKeyID(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, scope).Return(&model.Certificate{
		ID:      certID,
		UserID:  userID,
		Enabled: true,
		KeyID:   uuid.Nil, // no key attached
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no associated key ID")
}

func TestRenewCertificate_GetCertificateFails(t *testing.T) {
	userID := uuid.New()
	certID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, scope).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.RenewCertificate(context.Background(), certID, scope, 365)
	require.Error(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// CreateSelfSignedCertificate – validation failures
// ────────────────────────────────────────────────────────────────────────────

func TestCreateSelfSignedCertificate_InvalidValidityDays(t *testing.T) {
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        uuid.New(),
		ValidityDays: 0, // invalid
		UserID:       userID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validity days must be positive")
}

func TestCreateSelfSignedCertificate_KeyOwnershipFails(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(nil, errors.New("key not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// ────────────────────────────────────────────────────────────────────────────
// CreateCASignedCertificate – validation failures
// ────────────────────────────────────────────────────────────────────────────

func TestCreateCASignedCertificate_NilCACertID_Panics(t *testing.T) {
	// Known production bug: CreateCASignedCertificate dereferences CACertID in the
	// logrus call (line 266 of certificate_service.go) before the nil guard on line 272.
	// This test documents the behaviour: passing nil CACertID causes a panic.
	userID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}
	svc := newCertSvc(certRepo, keyRepo)
	require.Panics(t, func() {
		_, _ = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
			Name:         "test",
			KeyID:        uuid.New(),
			ValidityDays: 365,
			UserID:       userID,
			CACertID:     nil,
		})
	})
}

func TestCreateCASignedCertificate_InvalidValidityDays(t *testing.T) {
	userID := uuid.New()
	caCertID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        uuid.New(),
		ValidityDays: -1,
		UserID:       userID,
		CACertID:     &caCertID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validity days must be positive")
}

func TestCreateCASignedCertificate_KeyOwnershipFails(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(nil, errors.New("key not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		CACertID:     &caCertID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

func TestCreateCASignedCertificate_CACertAccessFails(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()
	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// key ownership succeeds
	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
	}, nil)
	// CA cert not found
	certRepo.On("Read", mock.Anything, caCertID, model.NewAdminScope(userID)).Return(nil, errors.New("not found"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "test",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		CACertID:     &caCertID,
	})
	require.Error(t, err)
	// access to CA cert fails → "cannot access CA certificate"
	assert.Contains(t, err.Error(), "cannot access CA certificate")
}

// ────────────────────────────────────────────────────────────────────────────
// CertificateRenewalScheduler
// ────────────────────────────────────────────────────────────────────────────

// mockRenewalSvc satisfies CertificateRenewalService for scheduler tests.
type mockRenewalSvc struct {
	mock.Mock
}

func (m *mockRenewalSvc) CheckAndRenewCertificates(ctx context.Context) (int, int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Int(1), args.Error(2)
}

func TestScheduler_StartStop(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	// We use a very long interval so the ticker never fires during the test;
	// the check() called immediately on startup will execute once.
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(0, 0, nil).Maybe()

	logger := newTestCertLogger()
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	scheduler.Start(ctx)

	// Give the goroutine a moment to call check() on startup.
	time.Sleep(20 * time.Millisecond)

	scheduler.Stop()
	cancel()

	// No panic and scheduler stopped cleanly.
}

func TestScheduler_DefaultIntervalWhenZero(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(0, 0, nil).Maybe()

	logger := newTestCertLogger()
	// Passing 0 interval should default to 24 hours (tested via construction only).
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 0)
	assert.NotNil(t, scheduler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler.Start(ctx)
	time.Sleep(20 * time.Millisecond)
	scheduler.Stop()
}

func TestScheduler_ContextCancellation(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(0, 0, nil).Maybe()

	logger := newTestCertLogger()
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	scheduler.Start(ctx)
	time.Sleep(10 * time.Millisecond)
	cancel() // cancel context instead of Stop()
	time.Sleep(20 * time.Millisecond)
	// goroutine should have exited; no assertion needed beyond no deadlock.
}

func TestScheduler_CheckLogsRenewalResults(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	// Return non-zero counts so the log branch is exercised.
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(2, 1, nil).Once()
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).Return(0, 0, nil).Maybe()

	logger := newTestCertLogger()
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	scheduler.Stop()
	// The first check (startup) should have exercised the renewed>0 || warned>0 branch.
}

func TestScheduler_CheckLogsError(t *testing.T) {
	renewalSvc := &mockRenewalSvc{}
	renewalSvc.On("CheckAndRenewCertificates", mock.Anything).
		Return(0, 0, errors.New("renewal error")).Maybe()

	logger := newTestCertLogger()
	scheduler := NewCertificateRenewalScheduler(renewalSvc, logger, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	scheduler.Stop()
	// Scheduler must not panic when renewal service returns an error.
}

// ────────────────────────────────────────────────────────────────────────────
// CheckAndRenewCertificates – remaining branches
// ────────────────────────────────────────────────────────────────────────────

// mockRenewalCertSvc is a CertificateService mock for renewal service tests.
type mockRenewalCertSvc struct{ mock.Mock }

func (m *mockRenewalCertSvc) CreateSelfSignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) CreateCASignedCertificate(ctx context.Context, req CreateCertificateRequest) (*CreateCertificateResult, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) GetCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) (*model.Certificate, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) ListCertificates(ctx context.Context, scope model.Scope, filter repositories.CertificateFilter) ([]model.Certificate, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) UpdateCertificate(ctx context.Context, req UpdateCertificateRequest) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) DeleteCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error) {
	args := m.Called(ctx, certID, scope, validityDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*CreateCertificateResult), args.Error(1)
}
func (m *mockRenewalCertSvc) ValidateCertificateAccess(ctx context.Context, certID, userID uuid.UUID, role string) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) ValidateKeyOwnership(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) ListDeletedCertificates(ctx context.Context, scope model.Scope) ([]model.Certificate, error) {
	panic("not called")
}
func (m *mockRenewalCertSvc) RecoverCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}
func (m *mockRenewalCertSvc) PurgeCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope) error {
	panic("not called")
}

func TestCheckAndRenewCertificates_ListAllFails(t *testing.T) {
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return(nil, errors.New("db error"))

	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: &mockRenewalCertSvc{},
		Logger:             newTestCertLogger(),
	})

	_, _, err := svc.CheckAndRenewCertificates(context.Background())
	require.Error(t, err)
}

func TestCheckAndRenewCertificates_NilExpiresAtSkipped(t *testing.T) {
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{ID: uuid.New(), UserID: uuid.New(), Name: "no-expiry", ExpiresAt: nil},
	}, nil)

	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: &mockRenewalCertSvc{},
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
}

func TestCheckAndRenewCertificates_AlreadyExpiredSkipped(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{ID: uuid.New(), UserID: uuid.New(), Name: "expired", ExpiresAt: &past},
	}, nil)

	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: &mockRenewalCertSvc{},
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
}

func TestCheckAndRenewCertificates_OutsideWindowSkipped(t *testing.T) {
	// Expires in 90 days, renewal window is 30 days → no action needed.
	farFuture := time.Now().Add(90 * 24 * time.Hour)
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{
			ID: uuid.New(), UserID: uuid.New(), Name: "not-due",
			ExpiresAt:   &farFuture,
			AutoRenew:   true,
			RenewalDays: 30,
		},
	}, nil)

	certSvc := &mockRenewalCertSvc{}
	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 0, warned)
	certSvc.AssertNotCalled(t, "RenewCertificate")
}

func TestCheckAndRenewCertificates_AutoRenewFailureSkipped(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	certID := uuid.New()
	userID := uuid.New()

	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{
			ID:          certID,
			UserID:      userID,
			Name:        "failing",
			CreatedAt:   time.Now().Add(-365 * 24 * time.Hour),
			ExpiresAt:   &expires,
			AutoRenew:   true,
			RenewalDays: 30,
		},
	}, nil)

	certSvc := &mockRenewalCertSvc{}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewAdminScope(userID), mock.AnythingOfType("int")).
		Return(nil, errors.New("renewal failed"))

	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed) // failure is skipped, not counted
	assert.Equal(t, 0, warned)
	certSvc.AssertExpectations(t)
}

func TestCheckAndRenewCertificates_DefaultRenewalDays(t *testing.T) {
	// RenewalDays == 0 should default to 30; cert expiring in 10 days → warn.
	expires := time.Now().Add(10 * 24 * time.Hour)
	repo := &mockCertRepository{}
	repo.On("ListAll", mock.Anything).Return([]model.Certificate{
		{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			Name:        "default-renewal",
			ExpiresAt:   &expires,
			AutoRenew:   false,
			RenewalDays: 0, // zero → defaults to 30
		},
	}, nil)

	certSvc := &mockRenewalCertSvc{}
	svc := NewCertificateRenewalService(RenewalServiceConfig{
		CertRepository:     repo,
		CertificateService: certSvc,
		Logger:             newTestCertLogger(),
	})

	renewed, warned, err := svc.CheckAndRenewCertificates(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, renewed)
	assert.Equal(t, 1, warned)
}

// ────────────────────────────────────────────────────────────────────────────
// CreateSelfSignedCertificate – full success paths (real crypto)
// ────────────────────────────────────────────────────────────────────────────

func setupMasterKey() {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(k))
}

func TestCreateSelfSignedCertificate_SuccessDefaultRenewalDays(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "self-signed-test",
		KeyID:        keyID,
		ValidityDays: 90,
		UserID:       userID,
		RenewalDays:  0, // should default to 30
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "self-signed-test", result.Name)
	assert.NotNil(t, result.ExpiresAt)
	certRepo.AssertExpectations(t)
	keyRepo.AssertExpectations(t)
}

func TestCreateSelfSignedCertificate_SuccessWithExplicitEnabled(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)

	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) {
			createdCert = args.Get(1).(*model.Certificate)
		}).Return(nil)

	disabled := false
	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "disabled-cert",
		KeyID:        keyID,
		ValidityDays: 30,
		UserID:       userID,
		RenewalDays:  60,
		Enabled:      &disabled,
		AutoRenew:    true,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdCert)
	assert.False(t, createdCert.Enabled)
	assert.Equal(t, 60, createdCert.RenewalDays)
	assert.True(t, createdCert.AutoRenew)
}

func TestCreateSelfSignedCertificate_SuccessWithVaultID(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	vaultID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)

	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) {
			createdCert = args.Get(1).(*model.Certificate)
		}).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "vaulted-cert",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		VaultID:      vaultID,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdCert)
	assert.Equal(t, vaultID, createdCert.VaultID)
}

func TestCreateSelfSignedCertificate_RepoCreateFails(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Return(errors.New("db write error"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "fail-cert",
		KeyID:        keyID,
		ValidityDays: 30,
		UserID:       userID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store self-signed certificate")
}

func TestCreateSelfSignedCertificate_KeyReadFails(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	// ValidateKeyOwnership passes (user is owner), then keyRepo.Read called again for key material
	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  "not-valid-encrypted-data",
	}, nil)

	svc := newCertSvc(certRepo, keyRepo)
	_, err := svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "err-cert",
		KeyID:        keyID,
		ValidityDays: 30,
		UserID:       userID,
	})
	require.Error(t, err)
}

// ────────────────────────────────────────────────────────────────────────────
// CreateCASignedCertificate – deeper coverage
// ────────────────────────────────────────────────────────────────────────────

func TestCreateCASignedCertificate_FullSuccess(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	// Generate two RSA keys: one for the end-entity cert, one for the CA.
	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	// Create self-signed CA cert using the CA key.
	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName:   "Test CA",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	encryptedEntityKey, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encryptedCAKey, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	entityKey := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedEntityKey}
	caCert := &model.Certificate{
		ID:          caCertID,
		UserID:      userID,
		Name:        "test-ca",
		Certificate: caCertPEM,
		PrivateKey:  encryptedCAKey,
		Enabled:     true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(entityKey, nil)
	// ValidateCertificateAccess calls certRepo.Read for the CA cert
	certRepo.On("Read", mock.Anything, caCertID, model.NewAdminScope(userID)).Return(caCert, nil)
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).Return(nil)

	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "entity-cert",
		KeyID:        keyID,
		ValidityDays: 365,
		UserID:       userID,
		CACertID:     &caCertID,
		RenewalDays:  0, // default to 30
		AutoRenew:    true,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "entity-cert", result.Name)
	assert.NotNil(t, result.ExpiresAt)
}

func TestCreateCASignedCertificate_RepoCreateFails(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName:   "Test CA",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	encryptedEntityKey, err := common.EncryptSecret(entityKeyPEM)
	require.NoError(t, err)
	encryptedCAKey, err := common.EncryptSecret(caKeyPEM)
	require.NoError(t, err)

	entityKey := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encryptedEntityKey}
	caCert := &model.Certificate{
		ID: caCertID, UserID: userID, Name: "test-ca",
		Certificate: caCertPEM, PrivateKey: encryptedCAKey, Enabled: true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(entityKey, nil)
	certRepo.On("Read", mock.Anything, caCertID, model.NewAdminScope(userID)).Return(caCert, nil)
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Return(errors.New("db write error"))

	svc := newCertSvc(certRepo, keyRepo)
	_, err = svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "failing-entity", KeyID: keyID, ValidityDays: 365,
		UserID: userID, CACertID: &caCertID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store CA-signed certificate")
}

func TestCreateCASignedCertificate_WithExplicitEnabledFalse(t *testing.T) {
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()
	caCertID := uuid.New()

	entityKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	caKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caCertPEM, err := crypto.CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName: "CA", ValidityDays: 3650, IsCA: true,
	})
	require.NoError(t, err)

	encEntity, _ := common.EncryptSecret(entityKeyPEM)
	encCA, _ := common.EncryptSecret(caKeyPEM)

	entityKey := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: encEntity}
	caCert := &model.Certificate{
		ID: caCertID, UserID: userID, Name: "ca",
		Certificate: caCertPEM, PrivateKey: encCA, Enabled: true,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, model.NewAdminScope(userID)).Return(entityKey, nil)
	certRepo.On("Read", mock.Anything, caCertID, model.NewAdminScope(userID)).Return(caCert, nil)

	var createdCert *model.Certificate
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) { createdCert = args.Get(1).(*model.Certificate) }).
		Return(nil)

	disabled := false
	svc := newCertSvc(certRepo, keyRepo)
	result, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name: "entity", KeyID: keyID, ValidityDays: 365,
		UserID: userID, CACertID: &caCertID,
		RenewalDays: 90,
		Enabled:     &disabled,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	require.NotNil(t, createdCert)
	assert.False(t, createdCert.Enabled)
	assert.Equal(t, 90, createdCert.RenewalDays)
}

// ────────────────────────────────────────────────────────────────────────────
// extractExpiresAt – invalid PEM
// ────────────────────────────────────────────────────────────────────────────

func TestExtractExpiresAt_InvalidPEM(t *testing.T) {
	_, err := extractExpiresAt("not-a-pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestExtractExpiresAt_ValidCert(t *testing.T) {
	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	certPEM, err := crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, "RSA", crypto.CertificateTemplate{
		CommonName:   "test",
		ValidityDays: 30,
		IsCA:         false,
	})
	require.NoError(t, err)

	expiresAt, err := extractExpiresAt(certPEM)
	require.NoError(t, err)
	assert.NotNil(t, expiresAt)
	assert.True(t, expiresAt.After(time.Now()))
}
