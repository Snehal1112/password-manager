package keys

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// mockKeyRotatorForRotation is a minimal testify mock for the KeyRotator
// interface (the RotateKey-only subset of KeyService that RotationExecutor
// depends on).
//
// The generated mock (internal/services/keys/mocks.MockKeyService) can't be
// used here: it imports package keys to reference KeyService/CreateKeyResult,
// and this file is itself part of package keys (not keys_test, so it can
// reuse the unexported mockKeyPolicyRepo/newTestKeyLogger helpers) -- so
// importing the mocks package back would create an import cycle ("import
// cycle not allowed in test"). A small local mock of the narrow KeyRotator
// interface sidesteps that; a real KeyService still satisfies KeyRotator
// structurally, so this doesn't affect bootstrap wiring.
type mockKeyRotatorForRotation struct {
	mock.Mock
}

func (m *mockKeyRotatorForRotation) RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*CreateKeyResult, error) {
	args := m.Called(ctx, keyID, scope)
	var result *CreateKeyResult
	if v := args.Get(0); v != nil {
		result = v.(*CreateKeyResult)
	}
	return result, args.Error(1)
}

func TestRotationExecutor_Check_RotatesDuePolicies(t *testing.T) {
	keySvc := new(mockKeyRotatorForRotation)
	policyRepo := new(mockKeyPolicyRepo)

	keyID := uuid.New()
	due := []model.KeyRotationPolicy{{ID: uuid.New(), KeyID: keyID, Enabled: true, RotateAfterDays: 90}}

	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return(due, nil)
	keySvc.On("RotateKey", mock.Anything, keyID, mock.Anything).Return(&CreateKeyResult{KeyID: keyID}, nil)
	policyRepo.On("MarkRotated", mock.Anything, keyID, mock.Anything, mock.AnythingOfType("time.Time"), 90).Return(nil)

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	require.NoError(t, exec.Check(context.Background()))

	policyRepo.AssertExpectations(t)
	keySvc.AssertExpectations(t)
}

func TestRotationExecutor_Check_OneFailureDoesNotStopSweep(t *testing.T) {
	keySvc := new(mockKeyRotatorForRotation)
	policyRepo := new(mockKeyPolicyRepo)

	badKey, goodKey := uuid.New(), uuid.New()
	due := []model.KeyRotationPolicy{
		{ID: uuid.New(), KeyID: badKey, Enabled: true, RotateAfterDays: 90},
		{ID: uuid.New(), KeyID: goodKey, Enabled: true, RotateAfterDays: 30},
	}
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return(due, nil)
	keySvc.On("RotateKey", mock.Anything, badKey, mock.Anything).Return(nil, errors.New("rotation failed"))
	keySvc.On("RotateKey", mock.Anything, goodKey, mock.Anything).Return(&CreateKeyResult{KeyID: goodKey}, nil)
	policyRepo.On("MarkRotated", mock.Anything, goodKey, mock.Anything, mock.AnythingOfType("time.Time"), 30).Return(nil)

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	require.NoError(t, exec.Check(context.Background()))

	policyRepo.AssertExpectations(t)
	keySvc.AssertExpectations(t)
	policyRepo.AssertNotCalled(t, "MarkRotated", mock.Anything, badKey, mock.Anything, mock.Anything, mock.Anything)
}

func TestRotationExecutor_Check_MarkRotatedFailureIsLoggedNotFatal(t *testing.T) {
	keySvc := new(mockKeyRotatorForRotation)
	policyRepo := new(mockKeyPolicyRepo)

	keyID := uuid.New()
	due := []model.KeyRotationPolicy{{ID: uuid.New(), KeyID: keyID, Enabled: true, RotateAfterDays: 90}}
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return(due, nil)
	keySvc.On("RotateKey", mock.Anything, keyID, mock.Anything).Return(&CreateKeyResult{KeyID: keyID}, nil)
	policyRepo.On("MarkRotated", mock.Anything, keyID, mock.Anything, mock.AnythingOfType("time.Time"), 90).
		Return(errors.New("db write failed"))

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	// The rotation itself succeeded; a bookkeeping failure must not surface
	// as a sweep-level error (that would risk a double-rotation retry).
	require.NoError(t, exec.Check(context.Background()))
}

func TestRotationExecutor_Check_GetDuePoliciesErrorPropagates(t *testing.T) {
	keySvc := new(mockKeyRotatorForRotation)
	policyRepo := new(mockKeyPolicyRepo)
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return(nil, errors.New("db unavailable"))

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	require.Error(t, exec.Check(context.Background()))
}

func TestRotationExecutor_Check_NoDuePolicies_NoOp(t *testing.T) {
	keySvc := new(mockKeyRotatorForRotation)
	policyRepo := new(mockKeyPolicyRepo)
	policyRepo.On("GetDuePolicies", mock.Anything, mock.Anything).Return([]model.KeyRotationPolicy{}, nil)

	exec := NewRotationExecutor(keySvc, policyRepo, newTestKeyLogger(t))
	require.NoError(t, exec.Check(context.Background()))
	// keySvc has no RotateKey expectations set -- an unexpected call would
	// fail the mock automatically.
}
