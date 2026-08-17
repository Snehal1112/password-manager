package keys

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// KeyRotator is the subset of KeyService that RotationExecutor depends on.
// Depending on this narrow interface (rather than the full KeyService)
// keeps the executor's dependency minimal; any KeyService implementation
// satisfies it structurally, so bootstrap wiring can pass a real KeyService
// straight through.
type KeyRotator interface {
	RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*CreateKeyResult, error)
}

// RotationExecutor sweeps for due KeyRotationPolicy rows and rotates their keys.
type RotationExecutor struct {
	keyService KeyRotator
	policyRepo repositories.KeyRotationPolicyRepositoryInterface
	log        *logging.Logger
}

// NewRotationExecutor constructs a RotationExecutor.
func NewRotationExecutor(keyService KeyRotator, policyRepo repositories.KeyRotationPolicyRepositoryInterface, log *logging.Logger) *RotationExecutor {
	return &RotationExecutor{keyService: keyService, policyRepo: policyRepo, log: log}
}

// Check is a schedulerkit.CheckFunc: sweep due policies and rotate their
// keys. The sweep is deliberately vault-agnostic (model.NewAdminScope) --
// this is a trusted background process, not a per-vault user request; see
// docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md
// section 10. A returned error here means the sweep itself could not run
// (e.g. the due-policy query failed); a single key's rotation failing is
// logged and does not abort the rest of the sweep.
func (e *RotationExecutor) Check(ctx context.Context) error {
	due, err := e.policyRepo.GetDuePolicies(ctx, model.NewAdminScope(uuid.Nil))
	if err != nil {
		return fmt.Errorf("get due key rotation policies: %w", err)
	}
	for _, policy := range due {
		if _, err := e.keyService.RotateKey(ctx, policy.KeyID, model.NewAdminScope(uuid.Nil)); err != nil {
			e.log.WithError(err).WithField("key_id", policy.KeyID).Error("automatic key rotation failed")
			continue
		}
		if err := e.policyRepo.MarkRotated(ctx, policy.KeyID, model.NewAdminScope(uuid.Nil), time.Now().UTC(), policy.RotateAfterDays); err != nil {
			// Rotation already succeeded -- do not retry the rotation itself
			// next tick just because this bookkeeping write failed, or the
			// key would be double-rotated.
			e.log.WithError(err).WithField("key_id", policy.KeyID).Error("failed to record key rotation timestamp")
		}
	}
	return nil
}
