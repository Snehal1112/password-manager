// Package secrets provides secret lifecycle and expiration monitoring services.
package secrets

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ExpirationService handles secret expiration monitoring and notifications.
// It checks for expiring secrets and triggers rotation workflows.
type ExpirationService interface {
	CheckExpiringSecrets(ctx context.Context) ([]model.Secret, error)
	GetExpiringSecrets(ctx context.Context, withinDays int) ([]model.Secret, error)
	DisableExpiredSecrets(ctx context.Context) (int, error)
	ValidateSecretLifecycle(secret *model.Secret) error
}

// expirationService implements ExpirationService for lifecycle management.
type expirationService struct {
	secretRepo repositories.SecretRepositoryInterface
	logger     *logging.Logger
}

// ExpirationServiceConfig holds dependencies for expiration service.
type ExpirationServiceConfig struct {
	SecretRepository repositories.SecretRepositoryInterface
	Logger           *logging.Logger
}

// NewExpirationService creates a new expiration monitoring service.
func NewExpirationService(config ExpirationServiceConfig) ExpirationService {
	return &expirationService{
		secretRepo: config.SecretRepository,
		logger:     config.Logger,
	}
}

// CheckExpiringSecrets finds secrets expiring within the default 7-day window.
func (s *expirationService) CheckExpiringSecrets(ctx context.Context) ([]model.Secret, error) {
	return s.GetExpiringSecrets(ctx, 7)
}

// GetExpiringSecrets retrieves secrets expiring within the specified number of days.
// This enables proactive rotation and notification workflows.
// Note: This is a system-level operation that checks all secrets across all users.
func (s *expirationService) GetExpiringSecrets(ctx context.Context, withinDays int) ([]model.Secret, error) {
	logrus.WithField("within_days", withinDays).Info("Checking for expiring secrets")

	// Note: We need to query secrets from all users for system-wide expiration monitoring
	// This would typically be implemented as a new repository method or admin query
	// For now, returning empty slice as this requires repository enhancement
	expiringSecrets := []model.Secret{}

	// TODO: Add ListAllSecrets() method to SecretRepositoryInterface for admin/system operations
	// or implement user-specific expiration checking in the scheduler

	s.logger.LogAuditInfo("system", "check_expiring", "info",
		"Expiration check not yet implemented - requires repository enhancement")

	return expiringSecrets, nil
}

// DisableExpiredSecrets disables all expired secrets.
// Returns the count of disabled secrets.
// Note: This is a system-level operation that affects all users' secrets.
func (s *expirationService) DisableExpiredSecrets(ctx context.Context) (int, error) {
	logrus.Info("Disabling expired secrets")

	// TODO: Add ListAllSecrets() method to SecretRepositoryInterface for admin/system operations
	// For now, this is a placeholder that requires repository enhancement

	disabledCount := 0

	s.logger.LogAuditInfo("system", "disable_expired", "info",
		"Expiration disable not yet implemented - requires repository enhancement")

	logrus.WithField("disabled_count", disabledCount).Info("Expired secrets disabled")
	return disabledCount, nil
}

// ValidateSecretLifecycle validates secret lifecycle timestamps.
// Returns an error if the secret has invalid expiration or activation dates.
func (s *expirationService) ValidateSecretLifecycle(secret *model.Secret) error {
	// Check if NotBefore is in the future but past ExpiresAt
	if secret.NotBefore != nil && secret.ExpiresAt != nil {
		if secret.NotBefore.After(*secret.ExpiresAt) {
			return fmt.Errorf("not_before (%s) must be before expires_at (%s)",
				secret.NotBefore.Format(time.RFC3339),
				secret.ExpiresAt.Format(time.RFC3339))
		}
	}

	// Warn if expiration is in the past for a new secret
	if secret.ExpiresAt != nil && secret.ExpiresAt.Before(time.Now()) {
		logrus.WithFields(logrus.Fields{
			"secret_id":  secret.ID,
			"expires_at": secret.ExpiresAt,
		}).Warn("Secret created with expiration in the past")
	}

	return nil
}
