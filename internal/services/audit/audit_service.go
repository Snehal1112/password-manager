// Package audit provides the write and read paths for the compliance audit trail.
package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
)

// AuditEvent is the input to RecordEvent.
type AuditEvent struct {
	UserID       string
	Action       string
	Details      string
	ResourceType string
	ResourceID   string
	IPAddress    string
	Outcome      string // "success" | "failure" | "warning"
	Source       string // "api" | "cli" | "system"
}

// AuditServiceInterface is the write-path contract for audit events.
// It replaces logging.AuditPersister across the codebase.
type AuditServiceInterface interface {
	// RecordEvent persists one audit event. Errors are swallowed — audit
	// failures must never block vault operations.
	RecordEvent(ctx context.Context, event AuditEvent) error

	// PersistAudit satisfies logging.AuditPersister for legacy callers.
	PersistAudit(userID, action, details string) error
}

// AuditService implements AuditServiceInterface with hash-chained writes.
type AuditService struct {
	repo repositories.AuditRepositoryExtended
	mu   sync.Mutex // serialises writes so prev_hash is consistent
}

// NewAuditService creates an AuditService backed by repo.
func NewAuditService(repo repositories.AuditRepositoryExtended) AuditServiceInterface {
	return &AuditService{repo: repo}
}

// RecordEvent computes the hash chain and inserts the enriched audit row.
// Insert errors are swallowed — audit failures must never block vault operations.
func (s *AuditService) RecordEvent(ctx context.Context, event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevHash, err := s.repo.GetLastHash(ctx)
	if err != nil {
		// Non-fatal: proceed without hash chain continuity.
		prevHash = ""
	}

	now := time.Now().UTC()
	hash := computeHash(prevHash, now, event)

	entry := repositories.AuditLog{
		ID:           uuid.New().String(),
		UserID:       event.UserID,
		Action:       event.Action,
		Details:      event.Details,
		Timestamp:    now,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		IPAddress:    event.IPAddress,
		Outcome:      event.Outcome,
		Source:       event.Source,
		PrevHash:     hash,
	}

	if err := s.repo.InsertAuditLog(ctx, entry); err != nil {
		// Audit failures must never block vault operations.
		fmt.Printf("audit insert failed: %v\n", err)
	}
	return nil
}

// PersistAudit satisfies logging.AuditPersister for legacy callers.
func (s *AuditService) PersistAudit(userID, action, details string) error {
	return s.RecordEvent(context.Background(), AuditEvent{
		UserID:  userID,
		Action:  action,
		Details: details,
		Source:  "system",
	})
}

// computeHash returns SHA-256(prevHash|timestamp|userID|action|details|resourceType+resourceID|outcome).
func computeHash(prevHash string, ts time.Time, e AuditEvent) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		prevHash, ts.Format(time.RFC3339Nano),
		e.UserID, e.Action, e.Details,
		e.ResourceType+e.ResourceID, e.Outcome)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}
