// Package secrets provides business logic services for secret management operations.
// This package follows the established service layer patterns with dependency injection
// and proper separation of concerns.
package secrets

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// RotationServiceInterface defines the business logic contract for secret rotation operations.
// It orchestrates rotation policies, scheduling, and history tracking.
type RotationServiceInterface interface {
	// Policy management
	CreatePolicy(ctx context.Context, req CreatePolicyRequest) (*domain.RotationPolicy, error)
	GetPolicy(ctx context.Context, id uuid.UUID) (*domain.RotationPolicy, error)
	UpdatePolicy(ctx context.Context, req UpdatePolicyRequest) (*domain.RotationPolicy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID, callerID uuid.UUID) error
	ListUserPolicies(ctx context.Context, userID uuid.UUID) ([]domain.RotationPolicy, error)

	// Secret-policy assignment
	AssignPolicyToSecret(ctx context.Context, req AssignPolicyRequest) error
	RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, callerID uuid.UUID) error
	GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]domain.RotationPolicy, error)

	// Rotation operations
	PerformManualRotation(ctx context.Context, req ManualRotationRequest) error
	GetRotationHistory(ctx context.Context, secretID uuid.UUID, callerID uuid.UUID) ([]domain.RotationHistory, error)
	GetDueRotations(ctx context.Context, userID uuid.UUID) ([]domain.SecretPolicy, error)

	// Reminder management
	CreateRotationReminder(ctx context.Context, req CreateReminderRequest) error
	GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]domain.RotationReminder, error)
	AcknowledgeReminder(ctx context.Context, reminderID uuid.UUID) error
}

// CreatePolicyRequest represents the request to create a rotation policy.
type CreatePolicyRequest struct {
	UserID       uuid.UUID `json:"user_id" validate:"required"`
	Name         string    `json:"name" validate:"required,min=1,max=100"`
	Description  string    `json:"description" validate:"max=500"`
	IntervalDays int       `json:"interval_days" validate:"required,min=1,max=365"`
	Enabled      bool      `json:"enabled"`
	ReminderDays int       `json:"reminder_days" validate:"min=0,max=30"`
	AutoRotate   bool      `json:"auto_rotate"`
}

// UpdatePolicyRequest represents the request to update a rotation policy.
type UpdatePolicyRequest struct {
	ID           uuid.UUID `json:"id" validate:"required"`
	UserID       uuid.UUID `json:"user_id" validate:"required"`
	Name         string    `json:"name" validate:"required,min=1,max=100"`
	Description  string    `json:"description" validate:"max=500"`
	IntervalDays int       `json:"interval_days" validate:"required,min=1,max=365"`
	Enabled      bool      `json:"enabled"`
	ReminderDays int       `json:"reminder_days" validate:"min=0,max=30"`
	AutoRotate   bool      `json:"auto_rotate"`
}

// AssignPolicyRequest represents the request to assign a policy to a secret.
type AssignPolicyRequest struct {
	SecretID uuid.UUID `json:"secret_id" validate:"required"`
	PolicyID uuid.UUID `json:"policy_id" validate:"required"`
	UserID   uuid.UUID `json:"user_id" validate:"required"`
}

// ManualRotationRequest represents the request to perform manual rotation.
type ManualRotationRequest struct {
	SecretID uuid.UUID `json:"secret_id" validate:"required"`
	PolicyID uuid.UUID `json:"policy_id" validate:"required"`
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	Notes    string    `json:"notes" validate:"max=500"`
}

// CreateReminderRequest represents the request to create a rotation reminder.
type CreateReminderRequest struct {
	SecretID       uuid.UUID  `json:"secret_id" validate:"required"`
	PolicyID       uuid.UUID  `json:"policy_id" validate:"required"`
	ReminderType   string     `json:"reminder_type" validate:"required,oneof=upcoming overdue"`
	NextReminderAt *time.Time `json:"next_reminder_at"`
}

// rotationService implements RotationServiceInterface.
type rotationService struct {
	rotationRepo repositories.RotationPolicyRepositoryInterface
	secretRepo   repositories.SecretRepositoryInterface
	userRepo     repositories.UserRepositoryInterface
	cryptoSvc    CryptographyService
	log          *logging.Logger
}

// NewRotationService creates a new rotation service with the required dependencies.
func NewRotationService(
	rotationRepo repositories.RotationPolicyRepositoryInterface,
	secretRepo repositories.SecretRepositoryInterface,
	userRepo repositories.UserRepositoryInterface,
	cryptoSvc CryptographyService,
	log *logging.Logger,
) RotationServiceInterface {
	return &rotationService{
		rotationRepo: rotationRepo,
		secretRepo:   secretRepo,
		userRepo:     userRepo,
		cryptoSvc:    cryptoSvc,
		log:          log,
	}
}

// CreatePolicy creates a new rotation policy with business validation.
func (s *rotationService) CreatePolicy(ctx context.Context, req CreatePolicyRequest) (*domain.RotationPolicy, error) {
	// Validate user exists
	user, err := s.userRepo.Read(ctx, req.UserID)
	if err != nil {
		s.log.WithError(err).WithField("user_id", req.UserID).Error("User not found for policy creation")
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Business validation
	if req.ReminderDays >= req.IntervalDays {
		return nil, fmt.Errorf("reminder days (%d) must be less than interval days (%d)", req.ReminderDays, req.IntervalDays)
	}

	// Create policy domain object with generated ID and timestamps
	now := time.Now()
	policy := &domain.RotationPolicy{
		ID:           uuid.New(),
		UserID:       user.ID,
		Name:         req.Name,
		Description:  req.Description,
		IntervalDays: req.IntervalDays,
		Enabled:      req.Enabled,
		ReminderDays: req.ReminderDays,
		AutoRotate:   req.AutoRotate,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	err = s.rotationRepo.Create(ctx, policy)
	if err != nil {
		s.log.WithError(err).Error("Failed to create rotation policy")
		return nil, fmt.Errorf("failed to create rotation policy: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"policy_id": policy.ID,
		"user_id":   policy.UserID,
		"name":      policy.Name,
	}).Info("Rotation policy created successfully")

	return policy, nil
}

// GetPolicy retrieves a rotation policy by ID.
func (s *rotationService) GetPolicy(ctx context.Context, id uuid.UUID) (*domain.RotationPolicy, error) {
	policy, err := s.rotationRepo.Read(ctx, id)
	if err != nil {
		s.log.WithError(err).WithField("policy_id", id).Error("Failed to get rotation policy")
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}

	return policy, nil
}

// UpdatePolicy updates an existing rotation policy with business validation.
func (s *rotationService) UpdatePolicy(ctx context.Context, req UpdatePolicyRequest) (*domain.RotationPolicy, error) {
	// Validate ownership
	existingPolicy, err := s.rotationRepo.Read(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	if existingPolicy.UserID != req.UserID {
		return nil, fmt.Errorf("user does not own this policy")
	}

	// Business validation
	if req.ReminderDays >= req.IntervalDays {
		return nil, fmt.Errorf("reminder days (%d) must be less than interval days (%d)", req.ReminderDays, req.IntervalDays)
	}

	// Update policy with new values
	policy := &domain.RotationPolicy{
		ID:           req.ID,
		UserID:       req.UserID,
		Name:         req.Name,
		Description:  req.Description,
		IntervalDays: req.IntervalDays,
		Enabled:      req.Enabled,
		ReminderDays: req.ReminderDays,
		AutoRotate:   req.AutoRotate,
		CreatedAt:    existingPolicy.CreatedAt,
		UpdatedAt:    time.Now(),
	}

	err = s.rotationRepo.Update(ctx, policy)
	if err != nil {
		s.log.WithError(err).Error("Failed to update rotation policy")
		return nil, fmt.Errorf("failed to update rotation policy: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"policy_id": policy.ID,
		"user_id":   policy.UserID,
		"name":      policy.Name,
	}).Info("Rotation policy updated successfully")

	return policy, nil
}

// DeletePolicy deletes a rotation policy with ownership validation.
func (s *rotationService) DeletePolicy(ctx context.Context, id uuid.UUID, callerID uuid.UUID) error {
	policy, err := s.rotationRepo.Read(ctx, id)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}

	if policy.UserID != callerID {
		return fmt.Errorf("forbidden: user does not own this policy")
	}

	err = s.rotationRepo.Delete(ctx, id)
	if err != nil {
		s.log.WithError(err).WithField("policy_id", id).Error("Failed to delete rotation policy")
		return fmt.Errorf("failed to delete rotation policy: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"policy_id": id,
		"user_id":   callerID,
	}).Info("Rotation policy deleted successfully")

	return nil
}

// ListUserPolicies lists all rotation policies for a user.
func (s *rotationService) ListUserPolicies(ctx context.Context, userID uuid.UUID) ([]domain.RotationPolicy, error) {
	policies, err := s.rotationRepo.ListByUser(ctx, userID)
	if err != nil {
		s.log.WithError(err).WithField("user_id", userID).Error("Failed to list user policies")
		return nil, fmt.Errorf("failed to list user policies: %w", err)
	}

	return policies, nil
}

// AssignPolicyToSecret assigns a rotation policy to a secret with validation.
func (s *rotationService) AssignPolicyToSecret(ctx context.Context, req AssignPolicyRequest) error {
	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, req.SecretID)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != req.UserID {
		return fmt.Errorf("user does not own this secret")
	}

	// Validate policy exists and user owns it
	policy, err := s.rotationRepo.Read(ctx, req.PolicyID)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}

	if policy.UserID != req.UserID {
		return fmt.Errorf("user does not own this policy")
	}

	// Calculate rotation schedule
	now := time.Now()
	nextRotation := now.AddDate(0, 0, policy.IntervalDays)

	// Assign policy to secret
	err = s.rotationRepo.AssignToSecret(ctx, req.SecretID, req.PolicyID, now, nextRotation)
	if err != nil {
		s.log.WithError(err).Error("Failed to assign policy to secret")
		return fmt.Errorf("failed to assign policy to secret: %w", err)
	}

	// Create initial reminder if reminder days configured
	if policy.ReminderDays > 0 {
		reminderTime := nextRotation.AddDate(0, 0, -policy.ReminderDays)
		reminderReq := CreateReminderRequest{
			SecretID:       req.SecretID,
			PolicyID:       req.PolicyID,
			ReminderType:   domain.ReminderUpcoming,
			NextReminderAt: &reminderTime,
		}

		err = s.CreateRotationReminder(ctx, reminderReq)
		if err != nil {
			s.log.WithError(err).Warn("Failed to create initial reminder for policy assignment")
			// Don't fail the assignment if reminder creation fails
		}
	}

	s.log.WithFields(map[string]interface{}{
		"secret_id":     req.SecretID,
		"policy_id":     req.PolicyID,
		"user_id":       req.UserID,
		"next_rotation": nextRotation,
	}).Info("Policy assigned to secret successfully")

	return nil
}

// RemovePolicyFromSecret removes a rotation policy from a secret with ownership validation.
func (s *rotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, callerID uuid.UUID) error {
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	if secret.UserID != callerID {
		return fmt.Errorf("forbidden: user does not own this secret")
	}

	err = s.rotationRepo.RemoveFromSecret(ctx, secretID, policyID)
	if err != nil {
		s.log.WithError(err).Error("Failed to remove policy from secret")
		return fmt.Errorf("failed to remove policy from secret: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"secret_id": secretID,
		"policy_id": policyID,
		"user_id":   callerID,
	}).Info("Policy removed from secret successfully")

	return nil
}

// GetSecretPolicies gets all rotation policies assigned to a secret.
func (s *rotationService) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]domain.RotationPolicy, error) {
	policies, err := s.rotationRepo.GetPoliciesForSecret(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get secret policies")
		return nil, fmt.Errorf("failed to get secret policies: %w", err)
	}

	return policies, nil
}

// PerformManualRotation performs manual rotation with full business logic.
func (s *rotationService) PerformManualRotation(ctx context.Context, req ManualRotationRequest) error {
	// Validate secret exists and user owns it
	secret, err := s.secretRepo.Read(ctx, req.SecretID)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	if secret.UserID != req.UserID {
		return fmt.Errorf("user does not own this secret")
	}

	// Validate policy exists and user owns it
	policy, err := s.rotationRepo.Read(ctx, req.PolicyID)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}

	if policy.UserID != req.UserID {
		return fmt.Errorf("user does not own this policy")
	}

	// Generate new secret value (simplified implementation)
	newValue := s.generateNewSecretValue(secret.Value)

	// Update secret with new value and incremented version
	previousVersion := secret.Version
	secret.Value = newValue
	secret.Version++

	err = s.secretRepo.Update(ctx, secret)
	if err != nil {
		s.log.WithError(err).Error("Failed to update secret during rotation")
		return fmt.Errorf("failed to update secret during rotation: %w", err)
	}

	// Record rotation history
	now := time.Now()
	history := &domain.RotationHistory{
		ID:              uuid.New(),
		SecretID:        req.SecretID,
		PolicyID:        &req.PolicyID,
		RotatedAt:       now,
		PreviousVersion: previousVersion,
		NewVersion:      secret.Version,
		TriggeredBy:     domain.TriggerManual,
		Notes:           req.Notes,
	}

	err = s.rotationRepo.RecordRotation(ctx, history)
	if err != nil {
		s.log.WithError(err).Error("Failed to record rotation history")
		// Don't fail rotation if history recording fails
	}

	// Update next rotation time
	nextRotation := now.AddDate(0, 0, policy.IntervalDays)
	err = s.rotationRepo.UpdateSecretPolicyRotation(ctx, req.SecretID, req.PolicyID, now, nextRotation)
	if err != nil {
		s.log.WithError(err).Error("Failed to update next rotation time")
		// Don't fail rotation if scheduling update fails
	}

	s.log.WithFields(map[string]interface{}{
		"secret_id":   req.SecretID,
		"policy_id":   req.PolicyID,
		"user_id":     req.UserID,
		"new_version": secret.Version,
	}).Info("Manual rotation completed successfully")

	return nil
}

// GetRotationHistory retrieves rotation history for a secret with ownership validation.
func (s *rotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID, callerID uuid.UUID) ([]domain.RotationHistory, error) {
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	if secret.UserID != callerID {
		return nil, fmt.Errorf("forbidden: user does not own this secret")
	}

	history, err := s.rotationRepo.GetRotationHistory(ctx, secretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", secretID).Error("Failed to get rotation history")
		return nil, fmt.Errorf("failed to get rotation history: %w", err)
	}

	return history, nil
}

// GetDueRotations gets secrets that are due for rotation for a user.
func (s *rotationService) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]domain.SecretPolicy, error) {
	due, err := s.rotationRepo.GetDueRotations(ctx, userID)
	if err != nil {
		s.log.WithError(err).WithField("user_id", userID).Error("Failed to get due rotations")
		return nil, fmt.Errorf("failed to get due rotations: %w", err)
	}

	return due, nil
}

// CreateRotationReminder creates a rotation reminder.
func (s *rotationService) CreateRotationReminder(ctx context.Context, req CreateReminderRequest) error {
	// Validate reminder type
	if req.ReminderType != domain.ReminderUpcoming && req.ReminderType != domain.ReminderOverdue {
		return fmt.Errorf("invalid reminder type: %s", req.ReminderType)
	}

	now := time.Now()
	reminder := &domain.RotationReminder{
		ID:             uuid.New(),
		SecretID:       req.SecretID,
		PolicyID:       req.PolicyID,
		ReminderType:   req.ReminderType,
		SentAt:         now,
		NextReminderAt: req.NextReminderAt,
		Acknowledged:   false,
	}

	err := s.rotationRepo.CreateReminder(ctx, reminder)
	if err != nil {
		s.log.WithError(err).Error("Failed to create rotation reminder")
		return fmt.Errorf("failed to create rotation reminder: %w", err)
	}

	s.log.WithFields(map[string]interface{}{
		"reminder_id": reminder.ID,
		"secret_id":   req.SecretID,
		"type":        req.ReminderType,
	}).Info("Rotation reminder created successfully")

	return nil
}

// GetUpcomingReminders gets upcoming rotation reminders for a user.
func (s *rotationService) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]domain.RotationReminder, error) {
	reminders, err := s.rotationRepo.GetUpcomingReminders(ctx, userID)
	if err != nil {
		s.log.WithError(err).WithField("user_id", userID).Error("Failed to get upcoming reminders")
		return nil, fmt.Errorf("failed to get upcoming reminders: %w", err)
	}

	return reminders, nil
}

// AcknowledgeReminder marks a reminder as acknowledged.
func (s *rotationService) AcknowledgeReminder(ctx context.Context, reminderID uuid.UUID) error {
	// This would typically fetch the reminder first, then update it
	// For simplicity, we'll create a reminder object with just the ID and acknowledged status
	reminder := &domain.RotationReminder{
		ID:           reminderID,
		Acknowledged: true,
	}

	err := s.rotationRepo.UpdateReminder(ctx, reminder)
	if err != nil {
		s.log.WithError(err).WithField("reminder_id", reminderID).Error("Failed to acknowledge reminder")
		return fmt.Errorf("failed to acknowledge reminder: %w", err)
	}

	s.log.WithField("reminder_id", reminderID).Info("Reminder acknowledged successfully")
	return nil
}

// generateNewSecretValue generates a new value for a secret (simplified implementation).
// In production, this would be more sophisticated based on secret type.
func (s *rotationService) generateNewSecretValue(currentValue string) string {
	// This is a simplified implementation
	// In production, you'd want more sophisticated generation based on secret type
	return fmt.Sprintf("%s_rotated_%d", currentValue, time.Now().Unix())
}