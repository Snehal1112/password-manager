package repositories

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// AuditRepositoryInterface is the contract for persisting audit log records.
// It satisfies logging.AuditPersister so the logger can write to the DB.
type AuditRepositoryInterface interface {
	PersistAudit(userID, action, details string) error
}

// AuditRepository writes audit records to the audit_logs table.
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates an AuditRepository backed by db.
func NewAuditRepository(db *sql.DB) AuditRepositoryInterface {
	return &AuditRepository{db: db}
}

// PersistAudit inserts one row into audit_logs.
// An empty userID is stored as an empty string (not NULL) for unauthenticated events.
func (r *AuditRepository) PersistAudit(userID, action, details string) error {
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := r.db.Exec(
		`INSERT INTO audit_logs (id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)`,
		id, userID, action, details, now,
	)
	return err
}
