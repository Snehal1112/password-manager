// Package domain contains the core domain types and constants for secret rotation management.
// It defines the fundamental entities, value objects, and business rules that are central
// to the secret rotation domain, following Domain-Driven Design principles.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// RotationPolicy represents a rotation policy for secrets.
type RotationPolicy struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	IntervalDays int       `json:"interval_days"`
	Enabled      bool      `json:"enabled"`
	ReminderDays int       `json:"reminder_days"`
	AutoRotate   bool      `json:"auto_rotate"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RotationHistory represents a rotation event.
type RotationHistory struct {
	ID              uuid.UUID  `json:"id"`
	SecretID        uuid.UUID  `json:"secret_id"`
	PolicyID        *uuid.UUID `json:"policy_id,omitempty"`
	RotatedAt       time.Time  `json:"rotated_at"`
	PreviousVersion int        `json:"previous_version"`
	NewVersion      int        `json:"new_version"`
	TriggeredBy     string     `json:"triggered_by"` // 'manual', 'scheduled', 'auto'
	Notes           string     `json:"notes"`
}

// RotationReminder represents a reminder notification.
type RotationReminder struct {
	ID             uuid.UUID  `json:"id"`
	SecretID       uuid.UUID  `json:"secret_id"`
	PolicyID       uuid.UUID  `json:"policy_id"`
	ReminderType   string     `json:"reminder_type"` // 'upcoming', 'overdue'
	SentAt         time.Time  `json:"sent_at"`
	NextReminderAt *time.Time `json:"next_reminder_at,omitempty"`
	Acknowledged   bool       `json:"acknowledged"`
}

// SecretPolicy represents the association between a secret and a policy.
type SecretPolicy struct {
	SecretID       uuid.UUID  `json:"secret_id"`
	PolicyID       uuid.UUID  `json:"policy_id"`
	AssignedAt     time.Time  `json:"assigned_at"`
	LastRotatedAt  *time.Time `json:"last_rotated_at,omitempty"`
	NextRotationAt *time.Time `json:"next_rotation_at,omitempty"`
}

// Rotation trigger types.
const (
	TriggerManual    = "manual"
	TriggerScheduled = "scheduled"
	TriggerAuto      = "auto"
)

// Reminder types.
const (
	ReminderUpcoming = "upcoming"
	ReminderOverdue  = "overdue"
)