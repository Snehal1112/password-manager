package keys

// These reuse the hand-rolled mockKeyRepository declared in
// key_soft_delete_test.go (same package) and add a matching hand-rolled
// mockKeyPolicyRepo for KeyRotationPolicyRepositoryInterface, since that
// repository interface has no mockery-generated mock.

import (
	"context"
	"database/sql"
	"errors"
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

// TestListKeyVersions_NeverRotatedKey_SynthesizesVersionOne pins that the
// list endpoint and the single-version endpoint agree about a never-rotated
// key. key_versions is genuinely empty until the first rotation, but
// GetKeyVersion and every crypto operation resolve version 1 from
// keys.value, so listing must report that same implicit version 1 rather
// than an empty history a client cannot reconcile.
func TestListKeyVersions_NeverRotatedKey_SynthesizesVersionOne(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), ownerID)
	createdAt := time.Now().Add(-2 * time.Hour).UTC()

	keyRepo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, Enabled: true, CreatedAt: createdAt}, nil)
	// Never rotated: the repository genuinely has zero key_versions rows.
	keyRepo.On("ListVersions", mock.Anything, keyID, ownerID).Return([]model.KeyVersion{}, nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: keyRepo,
		Logger:        newTestKeyLogger(t),
	})

	got, err := svc.ListKeyVersions(context.Background(), keyID, scope)

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 1, got[0].Version)
	assert.Equal(t, keyID, got[0].KeyID)
	// The synthesized entry is timestamped by the key's own creation time,
	// which is when its version-1 material came into existence.
	assert.Equal(t, createdAt, got[0].CreatedAt)
	keyRepo.AssertExpectations(t)
}

// TestListKeyVersions_RepositoryErrorPropagates pins that a repository
// failure is surfaced rather than being swallowed into the synthesized
// implicit-version-1 result.
func TestListKeyVersions_RepositoryErrorPropagates(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	keyID := uuid.New()
	ownerID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), ownerID)

	keyRepo.On("Read", mock.Anything, keyID, scope).
		Return(&model.Key{ID: keyID, UserID: ownerID, Enabled: true}, nil)
	keyRepo.On("ListVersions", mock.Anything, keyID, ownerID).Return(nil, errors.New("db down"))

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: keyRepo,
		Logger:        newTestKeyLogger(t),
	})

	_, err := svc.ListKeyVersions(context.Background(), keyID, scope)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "db down")
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

func TestGetKeyVersion_AuthorizesThenDelegatesToRepo(t *testing.T) {
	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Enabled: true}
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := new(mockKeyRepository)
	repo.On("Read", mock.Anything, keyID, scope).Return(vaultKey, nil)
	repo.On("GetVersion", mock.Anything, keyID, 1, userID).Return(&model.KeyVersion{KeyID: keyID, Version: 1}, nil)

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		Logger:        newTestKeyLogger(t),
	})

	v, err := svc.GetKeyVersion(context.Background(), keyID, 1, scope)

	require.NoError(t, err)
	assert.Equal(t, 1, v.Version)
	repo.AssertExpectations(t)
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

// TestUpsertKeyRotationPolicy_NeverRotated_MetadataOnlyEditPreservesNextRotationAt
// covers I1 from the final review: an Upsert that only changes an unrelated
// field (Enabled here) on a never-auto-rotated policy must not recompute
// NextRotationAt from key.CreatedAt -- doing so would silently undo the
// Task 2 migration's mass-rotation-hazard fix (which anchors a backfilled
// due-date on migration time, not key.CreatedAt) and could move the
// due-date into the past for a key older than its rotation window.
func TestUpsertKeyRotationPolicy_NeverRotated_MetadataOnlyEditPreservesNextRotationAt(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())
	// Key predates its own rotation window: if NextRotationAt were
	// recomputed from key.CreatedAt, it would land in the past.
	createdAt := time.Now().Add(-365 * 24 * time.Hour)
	// The existing due-date was anchored by a migration backfill (or an
	// earlier Upsert), not by key.CreatedAt -- it must survive untouched.
	existingNextRotation := time.Now().Add(20 * 24 * time.Hour)

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true, CreatedAt: createdAt}, nil)

	existing := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, VaultID: vaultID,
		RotateAfterDays: 90, Enabled: true, LastRotatedAt: nil,
		NextRotationAt: existingNextRotation,
	}
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(existing, nil).Once()

	// Only Enabled changes; RotateAfterDays (90) is unchanged.
	req := model.UpsertKeyRotationPolicyRequest{RotateAfterDays: 90, Enabled: false}
	policyRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(p *model.KeyRotationPolicy) bool {
		return p.LastRotatedAt == nil && p.NextRotationAt.Equal(existingNextRotation) && !p.Enabled
	})).Return(nil)

	stored := &model.KeyRotationPolicy{ID: uuid.New(), KeyID: keyID, VaultID: vaultID, NextRotationAt: existingNextRotation}
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

// TestUpsertKeyRotationPolicy_NeverRotated_ChangingRotateAfterDaysRecomputes
// documents the other side of the I1 judgment call: when the admin
// deliberately changes RotateAfterDays on a never-auto-rotated policy, that
// is treated as an intentional choice and DOES recompute from key.CreatedAt,
// unlike a metadata-only edit.
func TestUpsertKeyRotationPolicy_NeverRotated_ChangingRotateAfterDaysRecomputes(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())
	createdAt := time.Now().Add(-10 * 24 * time.Hour)

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true, CreatedAt: createdAt}, nil)

	existing := &model.KeyRotationPolicy{
		ID: uuid.New(), KeyID: keyID, VaultID: vaultID,
		RotateAfterDays: 90, Enabled: true, LastRotatedAt: nil,
		NextRotationAt: time.Now().Add(80 * 24 * time.Hour),
	}
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(existing, nil).Once()

	req := model.UpsertKeyRotationPolicyRequest{RotateAfterDays: 30, Enabled: true}
	policyRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(p *model.KeyRotationPolicy) bool {
		return p.LastRotatedAt == nil && p.NextRotationAt.Equal(createdAt.AddDate(0, 0, 30))
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

// TestUpsertKeyRotationPolicy_GetByKeyIDErrorPropagates covers the second
// half of I1: a GetByKeyID failure that is NOT "no existing policy" (e.g. a
// transient DB error) must propagate as an error from UpsertKeyRotationPolicy
// rather than being silently treated as "no existing policy", which would
// also incorrectly reset an update's due-date to key.CreatedAt.
func TestUpsertKeyRotationPolicy_GetByKeyIDErrorPropagates(t *testing.T) {
	keyRepo := new(mockKeyRepository)
	policyRepo := new(mockKeyPolicyRepo)
	keyID := uuid.New()
	vaultID := uuid.New()
	scope := model.NewOwnerScope(uuid.New(), uuid.New())

	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{ID: keyID, VaultID: vaultID, Enabled: true}, nil)
	policyRepo.On("GetByKeyID", mock.Anything, keyID, scope).Return(nil, errors.New("db unavailable"))

	svc := NewKeyService(KeyServiceConfig{
		KeyRepository:    keyRepo,
		PolicyRepository: policyRepo,
		Logger:           newTestKeyLogger(t),
	})

	_, err := svc.UpsertKeyRotationPolicy(context.Background(), keyID, scope,
		model.UpsertKeyRotationPolicyRequest{RotateAfterDays: 90, Enabled: true})

	require.Error(t, err)
	policyRepo.AssertNotCalled(t, "Upsert", mock.Anything, mock.Anything)
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
