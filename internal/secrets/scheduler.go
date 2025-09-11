/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package secrets

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/logging"
)

// RotationScheduler handles automated rotation and reminder scheduling
type RotationScheduler struct {
	db         *sql.DB
	log        *logging.Logger
	repo       RotationPolicyRepository
	secretRepo SecretRepository
	ticker     *time.Ticker
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.RWMutex
	running    bool
}

// NewRotationScheduler creates a new rotation scheduler
func NewRotationScheduler(db *sql.DB, log *logging.Logger, repo RotationPolicyRepository, secretRepo SecretRepository) *RotationScheduler {
	return &RotationScheduler{
		db:         db,
		log:        log,
		repo:       repo,
		secretRepo: secretRepo,
		stopChan:   make(chan struct{}),
	}
}

// Start begins the rotation scheduler
func (s *RotationScheduler) Start(interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		s.log.Warn("Rotation scheduler is already running")
		return
	}

	s.running = true
	s.ticker = time.NewTicker(interval)
	s.wg.Add(1)

	go s.run()

	s.log.WithField("interval", interval).Info("Rotation scheduler started")
}

// Stop stops the rotation scheduler
func (s *RotationScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	close(s.stopChan)
	s.ticker.Stop()

	s.wg.Wait()
	s.log.Info("Rotation scheduler stopped")
}

// IsRunning returns whether the scheduler is running
func (s *RotationScheduler) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// run is the main scheduler loop
func (s *RotationScheduler) run() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ticker.C:
			s.processRotations()
			s.processReminders()
		case <-s.stopChan:
			return
		}
	}
}

// processRotations handles automatic rotations
func (s *RotationScheduler) processRotations() {
	ctx := context.Background()

	// Get all users (simplified - in production, you'd want to batch this)
	users, err := s.getAllUsers(ctx)
	if err != nil {
		s.log.WithError(err).Error("Failed to get users for rotation processing")
		return
	}

	for _, userID := range users {
		s.processUserRotations(ctx, userID)
	}
}

// processUserRotations processes rotations for a specific user
func (s *RotationScheduler) processUserRotations(ctx context.Context, userID uuid.UUID) {
	dueRotations, err := s.repo.GetDueRotations(ctx, userID)
	if err != nil {
		s.log.WithError(err).WithField("user_id", userID).Error("Failed to get due rotations")
		return
	}

	for _, rotation := range dueRotations {
		s.performRotation(ctx, rotation)
	}
}

// performRotation performs an automatic rotation for a secret
func (s *RotationScheduler) performRotation(ctx context.Context, sp SecretPolicy) {
	// Get the secret
	secret, err := s.secretRepo.Read(ctx, sp.SecretID)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", sp.SecretID).Error("Failed to read secret for rotation")
		return
	}

	// Get the policy
	policy, err := s.repo.Read(ctx, sp.PolicyID)
	if err != nil {
		s.log.WithError(err).WithField("policy_id", sp.PolicyID).Error("Failed to read policy for rotation")
		return
	}

	// Only auto-rotate if enabled
	if !policy.AutoRotate {
		return
	}

	// Generate new value (simplified - in production, you'd want more sophisticated generation)
	newValue := s.generateNewSecretValue(secret.Value)

	// Update the secret
	previousVersion := secret.Version
	secret.Value = newValue
	secret.Version++

	err = s.secretRepo.Update(ctx, secret)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", sp.SecretID).Error("Failed to update secret during rotation")
		return
	}

	// Record the rotation
	history := &RotationHistory{
		SecretID:        sp.SecretID,
		PolicyID:        &sp.PolicyID,
		PreviousVersion: previousVersion,
		NewVersion:      secret.Version,
		TriggeredBy:     "auto",
		Notes:           "Automatic rotation by scheduler",
	}

	err = s.repo.RecordRotation(ctx, history)
	if err != nil {
		s.log.WithError(err).WithField("secret_id", sp.SecretID).Error("Failed to record rotation")
		return
	}

	// Update next rotation time
	s.updateNextRotationTime(ctx, sp, policy)

	s.log.WithFields(logrus.Fields{
		"secret_id":   sp.SecretID,
		"policy_id":   sp.PolicyID,
		"new_version": secret.Version,
	}).Info("Automatic rotation completed")
}

// processReminders handles reminder notifications
func (s *RotationScheduler) processReminders() {
	ctx := context.Background()

	// Get all users
	users, err := s.getAllUsers(ctx)
	if err != nil {
		s.log.WithError(err).Error("Failed to get users for reminder processing")
		return
	}

	for _, userID := range users {
		s.processUserReminders(ctx, userID)
	}
}

// processUserReminders processes reminders for a specific user
func (s *RotationScheduler) processUserReminders(ctx context.Context, userID uuid.UUID) {
	upcoming, err := s.repo.GetUpcomingReminders(ctx, userID)
	if err != nil {
		s.log.WithError(err).WithField("user_id", userID).Error("Failed to get upcoming reminders")
		return
	}

	for _, reminder := range upcoming {
		s.sendReminder(ctx, reminder)
	}
}

// sendReminder sends a reminder notification
func (s *RotationScheduler) sendReminder(ctx context.Context, reminder RotationReminder) {
	// In a real implementation, this would send email/SMS notifications
	// For now, we'll just log it
	s.log.WithFields(logrus.Fields{
		"secret_id":     reminder.SecretID,
		"reminder_type": reminder.ReminderType,
		"sent_at":       reminder.SentAt,
	}).Info("Rotation reminder sent")

	// Mark reminder as acknowledged (in production, this would be done when user acknowledges)
	reminder.Acknowledged = true
	err := s.repo.UpdateReminder(ctx, &reminder)
	if err != nil {
		s.log.WithError(err).WithField("reminder_id", reminder.ID).Error("Failed to update reminder")
	}
}

// updateNextRotationTime updates the next rotation time for a secret-policy pair
func (s *RotationScheduler) updateNextRotationTime(ctx context.Context, sp SecretPolicy, policy *RotationPolicy) {
	now := time.Now()
	nextRotation := now.AddDate(0, 0, policy.IntervalDays)

	query := `
		UPDATE secret_policies
		SET last_rotated_at = ?, next_rotation_at = ?
		WHERE secret_id = ? AND policy_id = ?
	`

	_, err := s.db.ExecContext(ctx, query,
		now,
		nextRotation,
		sp.SecretID.String(),
		sp.PolicyID.String(),
	)

	if err != nil {
		s.log.WithError(err).WithFields(logrus.Fields{
			"secret_id": sp.SecretID,
			"policy_id": sp.PolicyID,
		}).Error("Failed to update next rotation time")
	}
}

// generateNewSecretValue generates a new value for a secret (simplified implementation)
func (s *RotationScheduler) generateNewSecretValue(currentValue string) string {
	// This is a simplified implementation
	// In production, you'd want more sophisticated generation based on secret type
	return fmt.Sprintf("%s_rotated_%d", currentValue, time.Now().Unix())
}

// getAllUsers gets all user IDs (simplified - in production, you'd want proper user repository)
func (s *RotationScheduler) getAllUsers(ctx context.Context) ([]uuid.UUID, error) {
	query := `SELECT id FROM users`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var userIDStr string
		err := rows.Scan(&userIDStr)
		if err != nil {
			continue
		}
		userID, _ := uuid.Parse(userIDStr)
		userIDs = append(userIDs, userID)
	}

	return userIDs, nil
}

// ManualRotate performs a manual rotation
func (s *RotationScheduler) ManualRotate(ctx context.Context, secretID, policyID uuid.UUID, userID uuid.UUID) error {
	// Get the secret
	secret, err := s.secretRepo.Read(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}

	// Verify user owns the secret
	if secret.UserID != userID {
		return fmt.Errorf("user does not own the secret")
	}

	// Get the policy
	policy, err := s.repo.Read(ctx, policyID)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}

	// Verify user owns the policy
	if policy.UserID != userID {
		return fmt.Errorf("user does not own the policy")
	}

	// Generate new value
	newValue := s.generateNewSecretValue(secret.Value)

	// Update the secret
	previousVersion := secret.Version
	secret.Value = newValue
	secret.Version++

	err = s.secretRepo.Update(ctx, secret)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	// Record the rotation
	history := &RotationHistory{
		SecretID:        secretID,
		PolicyID:        &policyID,
		PreviousVersion: previousVersion,
		NewVersion:      secret.Version,
		TriggeredBy:     "manual",
		Notes:           "Manual rotation",
	}

	err = s.repo.RecordRotation(ctx, history)
	if err != nil {
		s.log.WithError(err).Error("Failed to record manual rotation")
	}

	// Update next rotation time
	sp := SecretPolicy{
		SecretID: secretID,
		PolicyID: policyID,
	}
	s.updateNextRotationTime(ctx, sp, policy)

	s.log.WithFields(logrus.Fields{
		"secret_id":   secretID,
		"policy_id":   policyID,
		"new_version": secret.Version,
	}).Info("Manual rotation completed")

	return nil
}

// CheckAndCreateReminders checks for secrets that need reminders and creates them
func (s *RotationScheduler) CheckAndCreateReminders(ctx context.Context, userID uuid.UUID) error {
	// Get all secret policies for the user
	query := `
		SELECT sp.secret_id, sp.policy_id, sp.next_rotation_at, rp.reminder_days
		FROM secret_policies sp
		JOIN rotation_policies rp ON sp.policy_id = rp.id
		WHERE rp.user_id = ? AND rp.enabled = TRUE
	`

	rows, err := s.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return fmt.Errorf("failed to get secret policies: %w", err)
	}
	defer rows.Close()

	now := time.Now()
	for rows.Next() {
		var secretID, policyID uuid.UUID
		var nextRotationAt time.Time
		var reminderDays int

		err := rows.Scan(&secretID, &policyID, &nextRotationAt, &reminderDays)
		if err != nil {
			continue
		}

		// Check if reminder is needed
		reminderTime := nextRotationAt.AddDate(0, 0, -reminderDays)
		if now.After(reminderTime) || now.Equal(reminderTime) {
			// Check if reminder already exists
			reminderID, exists, err := s.getReminderID(ctx, secretID, policyID, "upcoming")
			if err != nil {
				s.log.WithError(err).Error("Failed to check reminder existence")
				continue
			}

			if exists {
				// Update existing reminder's NextReminderAt to now
				err = s.updateReminderNextAt(ctx, reminderID, now)
				if err != nil {
					s.log.WithError(err).Error("Failed to update reminder")
				}
			} else {
				reminder := &RotationReminder{
					SecretID:       secretID,
					PolicyID:       policyID,
					ReminderType:   "upcoming",
					NextReminderAt: &now, // Set to now since the reminder is already due
				}
				err = s.repo.CreateReminder(ctx, reminder)
				if err != nil {
					s.log.WithError(err).Error("Failed to create reminder")
				}
			}
		}
	}

	return nil
}

// getReminderID gets the ID of an existing reminder
func (s *RotationScheduler) getReminderID(ctx context.Context, secretID, policyID uuid.UUID, reminderType string) (uuid.UUID, bool, error) {
	query := `
		SELECT id FROM rotation_reminders
		WHERE secret_id = ? AND policy_id = ? AND reminder_type = ? AND acknowledged = FALSE
	`

	var idStr string
	err := s.db.QueryRowContext(ctx, query, secretID.String(), policyID.String(), reminderType).Scan(&idStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, false, nil
		}
		return uuid.Nil, false, err
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		return uuid.Nil, false, err
	}

	return id, true, nil
}

// updateReminderNextAt updates a reminder's next_reminder_at
func (s *RotationScheduler) updateReminderNextAt(ctx context.Context, reminderID uuid.UUID, nextAt time.Time) error {
	query := `
		UPDATE rotation_reminders
		SET next_reminder_at = ?
		WHERE id = ?
	`

	result, err := s.db.ExecContext(ctx, query, nextAt.Format(time.RFC3339), reminderID.String())
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	s.log.WithFields(map[string]interface{}{
		"reminder_id":   reminderID,
		"next_at":       nextAt,
		"rows_affected": rowsAffected,
	}).Info("Reminder next_at updated")

	return nil
}
