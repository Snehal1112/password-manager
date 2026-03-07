// Package repositories provides data access interfaces and implementations following
// the repository pattern with clean separation of concerns.
package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"password-manager/internal/domain"
	"password-manager/internal/logging"
)

// RotationPolicyRepositoryInterface defines the data access contract for rotation policies.
// It follows the pure repository pattern expecting pre-processed data.
type RotationPolicyRepositoryInterface interface {
	// Basic CRUD operations
	Create(ctx context.Context, policy *domain.RotationPolicy) error
	Read(ctx context.Context, id uuid.UUID) (*domain.RotationPolicy, error)
	Update(ctx context.Context, policy *domain.RotationPolicy) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Query operations
	ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.RotationPolicy, error)

	// Policy assignment operations
	AssignToSecret(ctx context.Context, secretID, policyID uuid.UUID, assignedAt time.Time, nextRotationAt time.Time) error
	RemoveFromSecret(ctx context.Context, secretID, policyID uuid.UUID) error
	GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]domain.SecretPolicy, error)
	GetPoliciesForSecret(ctx context.Context, secretID uuid.UUID) ([]domain.RotationPolicy, error)
	UpdateSecretPolicyRotation(ctx context.Context, secretID, policyID uuid.UUID, lastRotatedAt, nextRotationAt time.Time) error

	// History operations
	RecordRotation(ctx context.Context, history *domain.RotationHistory) error
	GetRotationHistory(ctx context.Context, secretID uuid.UUID) ([]domain.RotationHistory, error)

	// Due rotations and reminders
	GetDueRotations(ctx context.Context, userID uuid.UUID) ([]domain.SecretPolicy, error)
	GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]domain.RotationReminder, error)

	// Reminder operations
	CreateReminder(ctx context.Context, reminder *domain.RotationReminder) error
	UpdateReminder(ctx context.Context, reminder *domain.RotationReminder) error
	GetReminderBySecret(ctx context.Context, secretID, policyID uuid.UUID, reminderType string) (*domain.RotationReminder, error)
}

// rotationPolicyRepository implements RotationPolicyRepositoryInterface.
type rotationPolicyRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewRotationPolicyRepository creates a new rotation policy repository.
func NewRotationPolicyRepository(db *sql.DB, log *logging.Logger) RotationPolicyRepositoryInterface {
	return &rotationPolicyRepository{
		db:  db,
		log: log,
	}
}

// Create creates a new rotation policy (expects pre-processed data with ID and timestamps).
func (r *rotationPolicyRepository) Create(ctx context.Context, policy *domain.RotationPolicy) error {
	query := `
		INSERT INTO rotation_policies (id, user_id, name, description, interval_days, enabled, reminder_days, auto_rotate, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		policy.ID.String(),
		policy.UserID.String(),
		policy.Name,
		policy.Description,
		policy.IntervalDays,
		policy.Enabled,
		policy.ReminderDays,
		policy.AutoRotate,
		policy.CreatedAt,
		policy.UpdatedAt,
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to create rotation policy")
		return fmt.Errorf("failed to create rotation policy: %w", err)
	}

	r.log.WithFields(map[string]interface{}{
		"policy_id": policy.ID,
		"name":      policy.Name,
	}).Info("Rotation policy created")

	return nil
}

// Read retrieves a rotation policy by ID.
func (r *rotationPolicyRepository) Read(ctx context.Context, id uuid.UUID) (*domain.RotationPolicy, error) {
	query := `
		SELECT id, user_id, name, description, interval_days, enabled, reminder_days, auto_rotate, created_at, updated_at
		FROM rotation_policies
		WHERE id = ?
	`

	var policy domain.RotationPolicy
	var userID, policyID string

	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
		&policyID,
		&userID,
		&policy.Name,
		&policy.Description,
		&policy.IntervalDays,
		&policy.Enabled,
		&policy.ReminderDays,
		&policy.AutoRotate,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("rotation policy not found")
		}
		r.log.WithError(err).Error("Failed to read rotation policy")
		return nil, fmt.Errorf("failed to read rotation policy: %w", err)
	}

	policy.ID, _ = uuid.Parse(policyID)
	policy.UserID, _ = uuid.Parse(userID)

	return &policy, nil
}

// Update updates a rotation policy (expects pre-processed data with updated timestamp).
func (r *rotationPolicyRepository) Update(ctx context.Context, policy *domain.RotationPolicy) error {
	query := `
		UPDATE rotation_policies
		SET name = ?, description = ?, interval_days = ?, enabled = ?, reminder_days = ?, auto_rotate = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := r.db.ExecContext(ctx, query,
		policy.Name,
		policy.Description,
		policy.IntervalDays,
		policy.Enabled,
		policy.ReminderDays,
		policy.AutoRotate,
		policy.UpdatedAt,
		policy.ID.String(),
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to update rotation policy")
		return fmt.Errorf("failed to update rotation policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("rotation policy not found")
	}

	r.log.WithFields(map[string]interface{}{
		"policy_id": policy.ID,
		"name":      policy.Name,
	}).Info("Rotation policy updated")

	return nil
}

// Delete deletes a rotation policy.
func (r *rotationPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM rotation_policies WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		r.log.WithError(err).Error("Failed to delete rotation policy")
		return fmt.Errorf("failed to delete rotation policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("rotation policy not found")
	}

	r.log.WithField("policy_id", id).Info("Rotation policy deleted")
	return nil
}

// ListByUser lists all rotation policies for a user.
func (r *rotationPolicyRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.RotationPolicy, error) {
	query := `
		SELECT id, user_id, name, description, interval_days, enabled, reminder_days, auto_rotate, created_at, updated_at
		FROM rotation_policies
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		r.log.WithError(err).Error("Failed to list rotation policies")
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}
	defer rows.Close()

	var policies []domain.RotationPolicy
	for rows.Next() {
		var policy domain.RotationPolicy
		var policyID, userIDStr string

		err := rows.Scan(
			&policyID,
			&userIDStr,
			&policy.Name,
			&policy.Description,
			&policy.IntervalDays,
			&policy.Enabled,
			&policy.ReminderDays,
			&policy.AutoRotate,
			&policy.CreatedAt,
			&policy.UpdatedAt,
		)
		if err != nil {
			r.log.WithError(err).Error("Failed to scan rotation policy")
			continue
		}

		policy.ID, _ = uuid.Parse(policyID)
		policy.UserID, _ = uuid.Parse(userIDStr)
		policies = append(policies, policy)
	}

	return policies, nil
}

// AssignToSecret assigns a policy to a secret (expects pre-calculated times).
func (r *rotationPolicyRepository) AssignToSecret(ctx context.Context, secretID, policyID uuid.UUID, assignedAt time.Time, nextRotationAt time.Time) error {
	query := `
		INSERT INTO secret_policies (secret_id, policy_id, assigned_at, next_rotation_at)
		VALUES (?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		secretID.String(),
		policyID.String(),
		assignedAt,
		nextRotationAt,
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to assign policy to secret")
		return fmt.Errorf("failed to assign policy to secret: %w", err)
	}

	r.log.WithFields(map[string]interface{}{
		"secret_id":     secretID,
		"policy_id":     policyID,
		"next_rotation": nextRotationAt,
	}).Info("Policy assigned to secret")

	return nil
}

// RemoveFromSecret removes a policy from a secret.
func (r *rotationPolicyRepository) RemoveFromSecret(ctx context.Context, secretID, policyID uuid.UUID) error {
	query := `DELETE FROM secret_policies WHERE secret_id = ? AND policy_id = ?`

	result, err := r.db.ExecContext(ctx, query, secretID.String(), policyID.String())
	if err != nil {
		r.log.WithError(err).Error("Failed to remove policy from secret")
		return fmt.Errorf("failed to remove policy from secret: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("policy assignment not found")
	}

	r.log.WithFields(map[string]interface{}{
		"secret_id": secretID,
		"policy_id": policyID,
	}).Info("Policy removed from secret")

	return nil
}

// GetSecretPolicies gets all policies assigned to a secret.
func (r *rotationPolicyRepository) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]domain.SecretPolicy, error) {
	query := `
		SELECT secret_id, policy_id, assigned_at, last_rotated_at, next_rotation_at
		FROM secret_policies
		WHERE secret_id = ?
	`

	rows, err := r.db.QueryContext(ctx, query, secretID.String())
	if err != nil {
		r.log.WithError(err).Error("Failed to get secret policies")
		return nil, fmt.Errorf("failed to get secret policies: %w", err)
	}
	defer rows.Close()

	var policies []domain.SecretPolicy
	for rows.Next() {
		var sp domain.SecretPolicy
		var secretIDStr, policyIDStr string
		var lastRotatedAt, nextRotationAt sql.NullTime

		err := rows.Scan(
			&secretIDStr,
			&policyIDStr,
			&sp.AssignedAt,
			&lastRotatedAt,
			&nextRotationAt,
		)
		if err != nil {
			r.log.WithError(err).Error("Failed to scan secret policy")
			continue
		}

		sp.SecretID, _ = uuid.Parse(secretIDStr)
		sp.PolicyID, _ = uuid.Parse(policyIDStr)
		if lastRotatedAt.Valid {
			sp.LastRotatedAt = &lastRotatedAt.Time
		}
		if nextRotationAt.Valid {
			sp.NextRotationAt = &nextRotationAt.Time
		}
		policies = append(policies, sp)
	}

	return policies, nil
}

// GetPoliciesForSecret gets all rotation policies for a secret.
func (r *rotationPolicyRepository) GetPoliciesForSecret(ctx context.Context, secretID uuid.UUID) ([]domain.RotationPolicy, error) {
	query := `
		SELECT rp.id, rp.user_id, rp.name, rp.description, rp.interval_days, rp.enabled,
		       rp.reminder_days, rp.auto_rotate, rp.created_at, rp.updated_at
		FROM rotation_policies rp
		JOIN secret_policies sp ON rp.id = sp.policy_id
		WHERE sp.secret_id = ?
	`

	rows, err := r.db.QueryContext(ctx, query, secretID.String())
	if err != nil {
		r.log.WithError(err).Error("Failed to get policies for secret")
		return nil, fmt.Errorf("failed to get policies for secret: %w", err)
	}
	defer rows.Close()

	var policies []domain.RotationPolicy
	for rows.Next() {
		var policy domain.RotationPolicy
		var policyID, userIDStr string

		err := rows.Scan(
			&policyID,
			&userIDStr,
			&policy.Name,
			&policy.Description,
			&policy.IntervalDays,
			&policy.Enabled,
			&policy.ReminderDays,
			&policy.AutoRotate,
			&policy.CreatedAt,
			&policy.UpdatedAt,
		)
		if err != nil {
			r.log.WithError(err).Error("Failed to scan policy")
			continue
		}

		policy.ID, _ = uuid.Parse(policyID)
		policy.UserID, _ = uuid.Parse(userIDStr)
		policies = append(policies, policy)
	}

	return policies, nil
}

// UpdateSecretPolicyRotation updates rotation times for a secret-policy pair.
func (r *rotationPolicyRepository) UpdateSecretPolicyRotation(ctx context.Context, secretID, policyID uuid.UUID, lastRotatedAt, nextRotationAt time.Time) error {
	query := `
		UPDATE secret_policies
		SET last_rotated_at = ?, next_rotation_at = ?
		WHERE secret_id = ? AND policy_id = ?
	`

	result, err := r.db.ExecContext(ctx, query,
		lastRotatedAt,
		nextRotationAt,
		secretID.String(),
		policyID.String(),
	)
	if err != nil {
		r.log.WithError(err).WithFields(map[string]interface{}{
			"secret_id": secretID,
			"policy_id": policyID,
		}).Error("Failed to update secret policy rotation")
		return fmt.Errorf("failed to update secret policy rotation: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("secret policy not found")
	}

	return nil
}

// RecordRotation records a rotation event (expects pre-processed data with ID and timestamp).
func (r *rotationPolicyRepository) RecordRotation(ctx context.Context, history *domain.RotationHistory) error {
	query := `
		INSERT INTO secret_rotation_history (id, secret_id, policy_id, rotated_at, previous_version, new_version, triggered_by, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	var policyID *string
	if history.PolicyID != nil {
		pid := history.PolicyID.String()
		policyID = &pid
	}

	_, err := r.db.ExecContext(ctx, query,
		history.ID.String(),
		history.SecretID.String(),
		policyID,
		history.RotatedAt,
		history.PreviousVersion,
		history.NewVersion,
		history.TriggeredBy,
		history.Notes,
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to record rotation")
		return fmt.Errorf("failed to record rotation: %w", err)
	}

	r.log.WithFields(map[string]interface{}{
		"secret_id":    history.SecretID,
		"triggered_by": history.TriggeredBy,
	}).Info("Rotation recorded")

	return nil
}

// GetRotationHistory gets rotation history for a secret.
func (r *rotationPolicyRepository) GetRotationHistory(ctx context.Context, secretID uuid.UUID) ([]domain.RotationHistory, error) {
	query := `
		SELECT id, secret_id, policy_id, rotated_at, previous_version, new_version, triggered_by, notes
		FROM secret_rotation_history
		WHERE secret_id = ?
		ORDER BY rotated_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, secretID.String())
	if err != nil {
		r.log.WithError(err).Error("Failed to get rotation history")
		return nil, fmt.Errorf("failed to get rotation history: %w", err)
	}
	defer rows.Close()

	var history []domain.RotationHistory
	for rows.Next() {
		var h domain.RotationHistory
		var historyID, secretIDStr string
		var policyID sql.NullString

		err := rows.Scan(
			&historyID,
			&secretIDStr,
			&policyID,
			&h.RotatedAt,
			&h.PreviousVersion,
			&h.NewVersion,
			&h.TriggeredBy,
			&h.Notes,
		)
		if err != nil {
			r.log.WithError(err).Error("Failed to scan rotation history")
			continue
		}

		h.ID, _ = uuid.Parse(historyID)
		h.SecretID, _ = uuid.Parse(secretIDStr)
		if policyID.Valid {
			pid, _ := uuid.Parse(policyID.String)
			h.PolicyID = &pid
		}
		history = append(history, h)
	}

	return history, nil
}

// GetDueRotations gets secrets that are due for rotation.
func (r *rotationPolicyRepository) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]domain.SecretPolicy, error) {
	query := `
		SELECT sp.secret_id, sp.policy_id, sp.assigned_at, sp.last_rotated_at, sp.next_rotation_at
		FROM secret_policies sp
		JOIN rotation_policies rp ON sp.policy_id = rp.id
		WHERE rp.user_id = ? AND rp.enabled = TRUE AND sp.next_rotation_at <= ?
	`

	now := time.Now()
	rows, err := r.db.QueryContext(ctx, query, userID.String(), now)
	if err != nil {
		r.log.WithError(err).Error("Failed to get due rotations")
		return nil, fmt.Errorf("failed to get due rotations: %w", err)
	}
	defer rows.Close()

	var due []domain.SecretPolicy
	for rows.Next() {
		var sp domain.SecretPolicy
		var secretIDStr, policyIDStr string
		var lastRotatedAt, nextRotationAt sql.NullTime

		err := rows.Scan(
			&secretIDStr,
			&policyIDStr,
			&sp.AssignedAt,
			&lastRotatedAt,
			&nextRotationAt,
		)
		if err != nil {
			r.log.WithError(err).Error("Failed to scan due rotation")
			continue
		}

		sp.SecretID, _ = uuid.Parse(secretIDStr)
		sp.PolicyID, _ = uuid.Parse(policyIDStr)
		if lastRotatedAt.Valid {
			sp.LastRotatedAt = &lastRotatedAt.Time
		}
		if nextRotationAt.Valid {
			sp.NextRotationAt = &nextRotationAt.Time
		}
		due = append(due, sp)
	}

	return due, nil
}

// GetUpcomingReminders gets upcoming rotation reminders.
func (r *rotationPolicyRepository) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]domain.RotationReminder, error) {
	query := `
		SELECT rr.id, rr.secret_id, rr.policy_id, rr.reminder_type, rr.sent_at, rr.next_reminder_at, rr.acknowledged
		FROM rotation_reminders rr
		JOIN rotation_policies rp ON rr.policy_id = rp.id
		WHERE rp.user_id = ? AND rr.acknowledged = FALSE AND rr.next_reminder_at <= ?
	`

	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	rows, err := r.db.QueryContext(ctx, query, userID.String(), nowStr)
	if err != nil {
		r.log.WithError(err).Error("Failed to get upcoming reminders")
		return nil, fmt.Errorf("failed to get upcoming reminders: %w", err)
	}
	defer rows.Close()

	var reminders []domain.RotationReminder
	for rows.Next() {
		var reminder domain.RotationReminder
		var reminderID, secretIDStr, policyIDStr string
		var nextReminderAt sql.NullTime

		err := rows.Scan(
			&reminderID,
			&secretIDStr,
			&policyIDStr,
			&reminder.ReminderType,
			&reminder.SentAt,
			&nextReminderAt,
			&reminder.Acknowledged,
		)
		if err != nil {
			r.log.WithError(err).Error("Failed to scan reminder")
			continue
		}

		reminder.ID, _ = uuid.Parse(reminderID)
		reminder.SecretID, _ = uuid.Parse(secretIDStr)
		reminder.PolicyID, _ = uuid.Parse(policyIDStr)
		if nextReminderAt.Valid {
			reminder.NextReminderAt = &nextReminderAt.Time
		}

		reminders = append(reminders, reminder)
	}

	return reminders, nil
}

// CreateReminder creates a rotation reminder (expects pre-processed data with ID and timestamp).
func (r *rotationPolicyRepository) CreateReminder(ctx context.Context, reminder *domain.RotationReminder) error {
	query := `
		INSERT INTO rotation_reminders (id, secret_id, policy_id, reminder_type, sent_at, next_reminder_at, acknowledged)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	var nextReminderAt *string
	if reminder.NextReminderAt != nil {
		nra := reminder.NextReminderAt.Format(time.RFC3339)
		nextReminderAt = &nra
	}

	_, err := r.db.ExecContext(ctx, query,
		reminder.ID.String(),
		reminder.SecretID.String(),
		reminder.PolicyID.String(),
		reminder.ReminderType,
		reminder.SentAt,
		nextReminderAt,
		reminder.Acknowledged,
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to create reminder")
		return fmt.Errorf("failed to create reminder: %w", err)
	}

	r.log.WithFields(map[string]interface{}{
		"reminder_id": reminder.ID,
		"type":        reminder.ReminderType,
	}).Info("Reminder created")

	return nil
}

// UpdateReminder updates a rotation reminder.
func (r *rotationPolicyRepository) UpdateReminder(ctx context.Context, reminder *domain.RotationReminder) error {
	query := `
		UPDATE rotation_reminders
		SET acknowledged = ?, next_reminder_at = ?
		WHERE id = ?
	`

	var nextReminderAt *string
	if reminder.NextReminderAt != nil {
		nra := reminder.NextReminderAt.Format(time.RFC3339)
		nextReminderAt = &nra
	}

	result, err := r.db.ExecContext(ctx, query,
		reminder.Acknowledged,
		nextReminderAt,
		reminder.ID.String(),
	)
	if err != nil {
		r.log.WithError(err).Error("Failed to update reminder")
		return fmt.Errorf("failed to update reminder: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("reminder not found")
	}

	r.log.WithField("reminder_id", reminder.ID).Info("Reminder updated")
	return nil
}

// GetReminderBySecret gets a specific reminder by secret, policy, and type.
func (r *rotationPolicyRepository) GetReminderBySecret(ctx context.Context, secretID, policyID uuid.UUID, reminderType string) (*domain.RotationReminder, error) {
	query := `
		SELECT id, secret_id, policy_id, reminder_type, sent_at, next_reminder_at, acknowledged
		FROM rotation_reminders
		WHERE secret_id = ? AND policy_id = ? AND reminder_type = ? AND acknowledged = FALSE
	`

	var reminder domain.RotationReminder
	var idStr, secretIDStr, policyIDStr string
	var nextReminderAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, secretID.String(), policyID.String(), reminderType).Scan(
		&idStr,
		&secretIDStr,
		&policyIDStr,
		&reminder.ReminderType,
		&reminder.SentAt,
		&nextReminderAt,
		&reminder.Acknowledged,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No reminder found
		}
		return nil, fmt.Errorf("failed to get reminder: %w", err)
	}

	reminder.ID, _ = uuid.Parse(idStr)
	reminder.SecretID, _ = uuid.Parse(secretIDStr)
	reminder.PolicyID, _ = uuid.Parse(policyIDStr)
	if nextReminderAt.Valid {
		reminder.NextReminderAt = &nextReminderAt.Time
	}

	return &reminder, nil
}
