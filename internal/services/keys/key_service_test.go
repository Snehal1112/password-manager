package keys

// These reuse the hand-rolled mockKeyRepository declared in
// key_soft_delete_test.go (same package) and add a matching hand-rolled
// mockKeyPolicyRepo for KeyRotationPolicyRepositoryInterface, since that
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

// mockKeyPolicyRepo is a minimal testify mock for
// KeyRotationPolicyRepositoryInterface.
type mockKeyPolicyRepo struct {
	mock.Mock
}

func (m *mockKeyPolicyRepo) Upsert(ctx context.Context, policy *model.KeyRotationPolicy) error {
	return m.Called(ctx, policy).Error(0)
}

func (m *mockKeyPolicyRepo) GetByKeyID(ctx context.Context, keyID, userID uuid.UUID) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID, userID)
	if v := args.Get(0); v != nil {
		return v.(*model.KeyRotationPolicy), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyPolicyRepo) DeleteByKeyID(ctx context.Context, keyID, userID uuid.UUID) error {
	return m.Called(ctx, keyID, userID).Error(0)
}

func (m *mockKeyPolicyRepo) GetByKeyIDAny(ctx context.Context, keyID uuid.UUID) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID)
	if v := args.Get(0); v != nil {
		return v.(*model.KeyRotationPolicy), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyPolicyRepo) DeleteByKeyIDAny(ctx context.Context, keyID uuid.UUID) error {
	return m.Called(ctx, keyID).Error(0)
}

func TestGetKeyRotationPolicy_VerifiesKeyAccessFirst(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, Enabled: true}, nil)
	want := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID}
	policyRepo.On("GetByKeyIDAny", mock.Anything, keyID).Return(want, nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	got, err := svc.GetKeyRotationPolicy(context.Background(), keyID, scope)

	require.NoError(t, err)
	assert.Equal(t, want, got)
	keyRepo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

func TestGetKeyRotationPolicy_DeniesWhenKeyAccessDenied(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(nil, sql.ErrNoRows)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	_, err := svc.GetKeyRotationPolicy(context.Background(), keyID, scope)

	require.Error(t, err)
	policyRepo.AssertNotCalled(t, "GetByKeyIDAny", mock.Anything, mock.Anything)
}

func TestUpsertKeyRotationPolicy_VerifiesKeyAccessFirstAndReadsBack(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, Enabled: true}, nil)

	req := model.UpsertKeyRotationPolicyRequest{
		RotateAfterDays:        90,
		NotifyBeforeExpiryDays: 30,
		ExpiryDays:             365,
		Enabled:                true,
	}
	policyRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(p *model.KeyRotationPolicy) bool {
		return p.KeyID == keyID &&
			p.UserID == scope.ActorID() &&
			p.RotateAfterDays == req.RotateAfterDays &&
			p.NotifyBeforeExpiryDays == req.NotifyBeforeExpiryDays &&
			p.ExpiryDays == req.ExpiryDays &&
			p.Enabled == req.Enabled
	})).Return(nil)

	stored := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID, RotateAfterDays: req.RotateAfterDays}
	policyRepo.On("GetByKeyIDAny", mock.Anything, keyID).Return(stored, nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	got, err := svc.UpsertKeyRotationPolicy(context.Background(), keyID, scope, req)

	require.NoError(t, err)
	assert.Equal(t, stored, got)
	keyRepo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

func TestUpsertKeyRotationPolicy_DeniesWhenKeyAccessDenied(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(nil, sql.ErrNoRows)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	_, err := svc.UpsertKeyRotationPolicy(context.Background(), keyID, scope, model.UpsertKeyRotationPolicyRequest{})

	require.Error(t, err)
	policyRepo.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
}

func TestDeleteKeyRotationPolicy_VerifiesKeyAccessFirst(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, Enabled: true}, nil)
	policyRepo.On("DeleteByKeyIDAny", mock.Anything, keyID).Return(nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	err := svc.DeleteKeyRotationPolicy(context.Background(), keyID, scope)

	require.NoError(t, err)
	keyRepo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

func TestDeleteKeyRotationPolicy_DeniesWhenKeyAccessDenied(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(nil, sql.ErrNoRows)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	err := svc.DeleteKeyRotationPolicy(context.Background(), keyID, scope)

	require.Error(t, err)
	policyRepo.AssertNotCalled(t, "DeleteByKeyIDAny", mock.Anything, mock.Anything)
}
