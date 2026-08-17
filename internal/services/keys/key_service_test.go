package keys

// These reuse the hand-rolled mockKeyRepository declared in
// key_soft_delete_test.go (same package) and add a matching hand-rolled
// mockKeyPolicyRepo for KeyRotationPolicyRepositoryInterface, since that
// repository interface has no mockery-generated mock.

import (
	"context"
	"database/sql"
	"testing"
	"time"

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

func (m *mockKeyPolicyRepo) GetByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	args := m.Called(ctx, keyID, scope)
	if v := args.Get(0); v != nil {
		return v.(*model.KeyRotationPolicy), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyPolicyRepo) DeleteByKeyID(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, keyID, scope).Error(0)
}

func (m *mockKeyPolicyRepo) GetDuePolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error) {
	args := m.Called(ctx, scope)
	if v := args.Get(0); v != nil {
		return v.([]model.KeyRotationPolicy), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockKeyPolicyRepo) MarkRotated(ctx context.Context, keyID uuid.UUID, scope model.Scope, at time.Time, rotateAfterDays int) error {
	return m.Called(ctx, keyID, scope, at, rotateAfterDays).Error(0)
}

func TestGetKeyRotationPolicy_VerifiesKeyAccessFirst(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, Enabled: true}, nil)
	want := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID}
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(want, nil)

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
	assert.ErrorIs(t, err, ErrKeyNotFound)
	policyRepo.AssertNotCalled(t, "GetByKeyID", mock.Anything, mock.Anything, mock.Anything)
}

func TestListKeyVersions_VerifiesKeyAccessFirst(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), ownerID)

	// The key row's owner (ownerID) is what ListVersions must be called
	// with, not the scope's own actor id -- they happen to match here for
	// an owner scope, but the point is the handoff goes through the
	// authorized key, not the scope directly.
	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, UserID: ownerID, Enabled: true}, nil)
	want := []model.KeyVersion{{KeyID: keyID, Version: 1}, {KeyID: keyID, Version: 2}}
	keyRepo.On("ListVersions", mock.Anything, keyID, ownerID).Return(want, nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: keyRepo,
		Logger:        newTestKeyLogger(t),
	})

	got, err := svc.ListKeyVersions(context.Background(), keyID, scope)

	require.NoError(t, err)
	assert.Equal(t, want, got)
	keyRepo.AssertExpectations(t)
}

func TestListKeyVersions_DeniesWhenKeyAccessDenied(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(nil, sql.ErrNoRows)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: keyRepo,
		Logger:        newTestKeyLogger(t),
	})

	_, err := svc.ListKeyVersions(context.Background(), keyID, scope)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	keyRepo.AssertNotCalled(t, "ListVersions", mock.Anything, mock.Anything, mock.Anything)
}

func TestUpsertKeyRotationPolicy_VerifiesKeyAccessFirstAndReadsBack(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil)

	req := model.UpsertKeyRotationPolicyRequest{
		RotateAfterDays:        90,
		NotifyBeforeExpiryDays: 30,
		ExpiryDays:             365,
		Enabled:                true,
	}
	policyRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(p *model.KeyRotationPolicy) bool {
		return p.KeyID == keyID &&
			p.UserID == scope.ActorID() &&
			p.VaultID == vaultID &&
			p.RotateAfterDays == req.RotateAfterDays &&
			p.NotifyBeforeExpiryDays == req.NotifyBeforeExpiryDays &&
			p.ExpiryDays == req.ExpiryDays &&
			p.Enabled == req.Enabled
	})).Return(nil)

	stored := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID, VaultID: vaultID, RotateAfterDays: req.RotateAfterDays}
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(stored, nil)

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

func TestUpsertKeyRotationPolicy_DerivesVaultFromParentKey(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	vaultID := uuid.New()
	// The scope's own vault id is deliberately different from the key's
	// vault id: if the implementation derived VaultID from the scope
	// instead of the parent key, this test would catch it.
	scope := model.NewVaultScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil)

	req := model.UpsertKeyRotationPolicyRequest{
		RotateAfterDays:        90,
		NotifyBeforeExpiryDays: 30,
		ExpiryDays:             365,
		Enabled:                true,
	}
	policyRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(p *model.KeyRotationPolicy) bool {
		return p.VaultID == vaultID
	})).Return(nil)

	stored := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID, VaultID: vaultID, RotateAfterDays: req.RotateAfterDays}
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(stored, nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	policy, err := svc.UpsertKeyRotationPolicy(context.Background(), keyID, scope, req)

	require.NoError(t, err)
	require.Equal(t, vaultID, policy.VaultID, "policy VaultID must be derived from the key's own vault, not independently settable")
	keyRepo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

func TestUpsertKeyRotationPolicy_FirstTimeCreate_ComputesNextRotationFromKeyCreatedAt(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())
	createdAt := time.Now().Add(-48 * time.Hour)

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true, CreatedAt: createdAt}, nil)

	// Pre-read finds no existing policy (first-time create): baseline for
	// NextRotationAt must fall back to the key's own CreatedAt, and
	// LastRotatedAt must stay nil.
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(nil, sql.ErrNoRows).Once()

	req := model.UpsertKeyRotationPolicyRequest{RotateAfterDays: 90, Enabled: true}
	policyRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(p *model.KeyRotationPolicy) bool {
		return p.LastRotatedAt == nil &&
			p.NextRotationAt.Equal(createdAt.AddDate(0, 0, req.RotateAfterDays))
	})).Return(nil)

	stored := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID, VaultID: vaultID}
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(stored, nil).Once()

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	_, err := svc.UpsertKeyRotationPolicy(context.Background(), keyID, scope, req)

	require.NoError(t, err)
	keyRepo.AssertExpectations(t)
	policyRepo.AssertExpectations(t)
}

func TestUpsertKeyRotationPolicy_PreservesLastRotatedAt_ComputesNextRotationFromIt(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())
	createdAt := time.Now().Add(-365 * 24 * time.Hour)
	lastRotatedAt := time.Now().Add(-10 * 24 * time.Hour)

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true, CreatedAt: createdAt}, nil)

	// Pre-read finds an existing policy whose LastRotatedAt an earlier
	// automatic rotation already advanced: this Upsert only changes an
	// unrelated field, so it must not reset the due-date clock back to the
	// key's CreatedAt.
	existing := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID, VaultID: vaultID, LastRotatedAt: &lastRotatedAt}
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(existing, nil).Once()

	req := model.UpsertKeyRotationPolicyRequest{RotateAfterDays: 30, NotifyBeforeExpiryDays: 7, Enabled: true}
	policyRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(p *model.KeyRotationPolicy) bool {
		return p.LastRotatedAt != nil && p.LastRotatedAt.Equal(lastRotatedAt) &&
			p.NextRotationAt.Equal(lastRotatedAt.AddDate(0, 0, req.RotateAfterDays))
	})).Return(nil)

	stored := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID, VaultID: vaultID}
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(stored, nil).Once()

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	_, err := svc.UpsertKeyRotationPolicy(context.Background(), keyID, scope, req)

	require.NoError(t, err)
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
	assert.ErrorIs(t, err, ErrKeyNotFound)
	policyRepo.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
}

func TestDeleteKeyRotationPolicy_VerifiesKeyAccessFirst(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, Enabled: true}, nil)
	policyRepo.On("DeleteByKeyID", mock.Anything, keyID, scope).Return(nil)

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
	assert.ErrorIs(t, err, ErrKeyNotFound)
	policyRepo.AssertNotCalled(t, "DeleteByKeyID", mock.Anything, mock.Anything, mock.Anything)
}
