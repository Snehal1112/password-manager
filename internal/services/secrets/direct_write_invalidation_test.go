package secrets_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// recordingInvalidator records the secret ids a service evicted from cache.
type recordingInvalidator struct {
	mu       sync.Mutex
	evicted  []uuid.UUID
	returnEr error
}

func (r *recordingInvalidator) DeleteByID(_ context.Context, secretID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evicted = append(r.evicted, secretID)
	return r.returnEr
}

func (r *recordingInvalidator) ids() []uuid.UUID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uuid.UUID(nil), r.evicted...)
}

// auditRecord is one persisted audit row.
type auditRecord struct {
	userID  string
	action  string
	details string
}

// recordingAuditPersister captures the audit rows a service emitted.
type recordingAuditPersister struct {
	mu      sync.Mutex
	records []auditRecord
}

func (p *recordingAuditPersister) PersistAudit(userID, action, details string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, auditRecord{userID, action, details})
	return nil
}

func (p *recordingAuditPersister) find(action, status string) (auditRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rec := range p.records {
		if rec.action == action && strings.Contains(rec.details, "status="+status) {
			return rec, true
		}
	}
	return auditRecord{}, false
}

// newAuditingLogger returns a quiet logger whose audit calls are captured.
func newAuditingLogger(t *testing.T) (*logging.Logger, *recordingAuditPersister) {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	logger := logging.WrapLogrus(l)
	persister := &recordingAuditPersister{}
	logger.SetAuditPersister(persister)
	return logger, persister
}

// TestPerformManualRotationInvalidatesCacheAndAudits pins both halves of the
// "mutator outside CachedSecretService" fix: rotation writes the secrets table
// directly, so without its own eviction a credential rotated because it was
// compromised keeps being served from cache for the full TTL, and without its
// own audit call the rotation leaves no trail at all.
func TestPerformManualRotationInvalidatesCacheAndAudits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	secretID := uuid.New()
	policyID := uuid.New()

	scope := model.NewAdminScope(ownerID)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).
		Return(&model.Secret{ID: secretID, UserID: ownerID, Name: "db", Value: "old-ciphertext", Version: 3}, nil).Once()
	secretRepo.On("Update", ctx, mock.Anything, mock.Anything).Return(nil).Once()

	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("Read", ctx, policyID, scope).
		Return(&model.RotationPolicy{ID: policyID, UserID: ownerID, IntervalDays: 30}, nil).Once()
	rotationRepo.On("RecordRotation", ctx, mock.Anything).Return(nil).Once()
	rotationRepo.On("UpdateSecretPolicyRotation", ctx, secretID, policyID, mock.Anything, mock.Anything).
		Return(nil).Once()

	crypto := &testutils.MockCryptographyService{}
	crypto.On("DecryptSecret", "old-ciphertext").Return("old-plaintext", nil).Once()
	crypto.On("EncryptSecret", "new-plaintext").Return("new-ciphertext", nil).Once()

	versioningSvc := &testutils.MockVersioningService{}
	versioningSvc.On("CreateVersion", ctx, mock.MatchedBy(func(req secrets.CreateVersionRequest) bool {
		return req.SecretID == secretID && req.UserID == ownerID &&
			req.Value == "old-plaintext" && req.Version == 3
	})).Return(&model.SecretVersion{ID: uuid.New()}, nil).Once()

	invalidator := &recordingInvalidator{}
	logger, audit := newAuditingLogger(t)
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, crypto, versioningSvc, logger, invalidator)

	require.NoError(t, svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		Scope:    scope,
		NewValue: "new-plaintext",
	}))

	assert.Equal(t, []uuid.UUID{secretID}, invalidator.ids(), "rotation must evict the rotated secret from cache")

	rec, ok := audit.find("rotate_secret", "success")
	require.True(t, ok, "rotation must emit a success audit row")
	assert.Equal(t, ownerID.String(), rec.userID, "the audit actor is the secret's owner, never uuid.Nil")

	secretRepo.AssertExpectations(t)
	rotationRepo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	versioningSvc.AssertExpectations(t)
}

// TestPerformManualRotationAuditsDenial pins the failure half of the audit
// trail: a rejected rotation must be recorded too. There is no longer a
// separate manual ownership-comparison step producing a "denied" status --
// a caller scope that doesn't cover the secret fails the scoped read itself,
// which is audited as "failed".
func TestPerformManualRotationAuditsDenial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	callerID := uuid.New()
	secretID := uuid.New()
	scope := model.NewOwnerScope(vaultID, callerID)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).
		Return(nil, errors.New("secret not found")).Once()

	invalidator := &recordingInvalidator{}
	logger, audit := newAuditingLogger(t)
	svc := secrets.NewRotationService(&mockRotationPolicyRepo{}, secretRepo, nil, nil, nil, logger, invalidator)

	err := svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: uuid.New(),
		Scope:    scope,
		NewValue: "new-plaintext",
	})
	require.Error(t, err)

	_, ok := audit.find("rotate_secret", "failed")
	assert.True(t, ok, "a rejected rotation must emit a failure audit row")
	assert.Empty(t, invalidator.ids(), "a rejected rotation must not touch the cache")

	secretRepo.AssertExpectations(t)
}

// TestPerformManualRotationDoesNotWriteWhenArchivingFails pins the ordering
// PerformManualRotation depends on: the pre-rotation value must be archived
// before the secret is overwritten, and a failed archive must abort the
// rotation entirely rather than fall through to the write.
func TestPerformManualRotationDoesNotWriteWhenArchivingFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	secretID := uuid.New()
	policyID := uuid.New()

	scope := model.NewAdminScope(ownerID)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).
		Return(&model.Secret{ID: secretID, UserID: ownerID, Name: "db", Value: "old-ciphertext", Version: 3}, nil).Once()

	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("Read", ctx, policyID, scope).
		Return(&model.RotationPolicy{ID: policyID, UserID: ownerID, IntervalDays: 30}, nil).Once()

	crypto := &testutils.MockCryptographyService{}
	crypto.On("DecryptSecret", "old-ciphertext").Return("old-plaintext", nil).Once()

	versioningSvc := &testutils.MockVersioningService{}
	versioningSvc.On("CreateVersion", ctx, mock.Anything).Return(nil, errors.New("disk full")).Once()

	logger, audit := newAuditingLogger(t)
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, crypto, versioningSvc, logger, &recordingInvalidator{})

	err := svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		Scope:    scope,
		NewValue: "new-plaintext",
	})
	require.Error(t, err, "a failed archive must abort the rotation")

	// secretRepo.Update has no expectation set up above, so a call to it would
	// already fail the mock -- this assertion just makes that guarantee explicit.
	secretRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)

	_, ok := audit.find("rotate_secret", "failed")
	assert.True(t, ok, "a failed archive must still emit a failure audit row")

	secretRepo.AssertExpectations(t)
	rotationRepo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	versioningSvc.AssertExpectations(t)
}

// TestRollbackToVersionInvalidatesCacheAndAudits is the versioning-service half
// of the same defect: rollback also writes the secrets table directly.
func TestRollbackToVersionInvalidatesCacheAndAudits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	secretID := uuid.New()
	secret := &model.Secret{ID: secretID, UserID: ownerID, Name: "db", Value: "current", Version: 2}
	adminScope := model.NewAdminScope(ownerID)

	versionRepo := &mockSecretVersionRepository{}
	versionRepo.On("GetVersion", ctx, secretID, 1).
		Return(&model.SecretVersion{ID: uuid.New(), SecretID: secretID, UserID: ownerID, Value: "encrypted-target", Version: 1}, nil).Once()
	versionRepo.On("CreateVersion", ctx, mock.Anything).Return(nil).Once()

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, adminScope).Return(secret, nil).Twice()
	secretRepo.On("Update", ctx, mock.Anything, model.NewOwnerScope(secret.VaultID, ownerID)).Return(nil).Once()

	userRepo := &mockUserRepository{}
	userRepo.On("Read", ctx, ownerID).Return(&model.User{ID: ownerID, Username: "alice"}, nil).Once()

	crypto := &testutils.MockCryptographyService{}
	crypto.On("DecryptSecret", "encrypted-target").Return("rolled-back", nil).Once()
	crypto.On("EncryptSecret", "current").Return("encrypted-current", nil).Once()

	invalidator := &recordingInvalidator{}
	logger, audit := newAuditingLogger(t)
	svc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, logger, invalidator)

	_, err := svc.RollbackToVersion(ctx, secrets.RollbackRequest{
		SecretID:      secretID,
		TargetVersion: 1,
		UserID:        ownerID,
	})
	require.NoError(t, err)

	assert.Equal(t, []uuid.UUID{secretID}, invalidator.ids(), "rollback must evict the rolled-back secret from cache")

	rec, ok := audit.find("rollback_secret", "success")
	require.True(t, ok, "rollback must emit a success audit row")
	assert.Equal(t, ownerID.String(), rec.userID)

	versionRepo.AssertExpectations(t)
	secretRepo.AssertExpectations(t)
}

// TestDirectWritersToleratesANoOpCacheInvalidator pins that the invalidator
// the container always supplies -- a real one when caching is enabled, a
// no-op-backed one otherwise -- is safe to call from a direct writer. The
// container never passes a nil interface (see NewServiceContainer), so
// NewRotationService no longer nil-checks cacheInv internally.
func TestDirectWritersToleratesANoOpCacheInvalidator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	secretID := uuid.New()
	policyID := uuid.New()

	scope := model.NewAdminScope(ownerID)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).
		Return(&model.Secret{ID: secretID, UserID: ownerID, Name: "db", Value: "old-ciphertext", Version: 1}, nil).Once()
	secretRepo.On("Update", ctx, mock.Anything, mock.Anything).Return(nil).Once()

	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("Read", ctx, policyID, scope).
		Return(&model.RotationPolicy{ID: policyID, UserID: ownerID, IntervalDays: 7}, nil).Once()
	rotationRepo.On("RecordRotation", ctx, mock.Anything).Return(nil).Once()
	rotationRepo.On("UpdateSecretPolicyRotation", ctx, secretID, policyID, mock.Anything, mock.Anything).
		Return(nil).Once()

	crypto := &testutils.MockCryptographyService{}
	crypto.On("DecryptSecret", "old-ciphertext").Return("old-plaintext", nil).Once()
	crypto.On("EncryptSecret", "new-plaintext").Return("new-ciphertext", nil).Once()

	versioningSvc := &testutils.MockVersioningService{}
	versioningSvc.On("CreateVersion", ctx, mock.Anything).Return(&model.SecretVersion{ID: uuid.New()}, nil).Once()

	logger, _ := newAuditingLogger(t)
	invalidator := &recordingInvalidator{}
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, crypto, versioningSvc, logger, invalidator)

	require.NoError(t, svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		Scope:    scope,
		NewValue: "new-plaintext",
	}))
}
