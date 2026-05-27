package repositories

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AuditLog is a single enriched audit event read from the database.
type AuditLog struct {
	ID           string
	UserID       string
	Action       string
	Details      string
	Timestamp    time.Time
	ResourceType string
	ResourceID   string
	IPAddress    string
	Outcome      string
	Source       string
	PrevHash     string
}

// AuditFilter specifies query constraints for QueryAuditLogs.
// Nil pointer fields are ignored (not filtered).
type AuditFilter struct {
	From         *time.Time
	To           *time.Time
	UserID       *string
	Action       *string
	Outcome      *string
	ResourceType *string
	ResourceID   *string
	Source       *string
	Limit        int    // 0 defaults to 100; max 1000
	Cursor       string // opaque: last seen timestamp|id
}

// AuditRepositoryInterface is the contract for persisting audit log records.
// It satisfies logging.AuditPersister so the logger can write to the DB.
type AuditRepositoryInterface interface {
	PersistAudit(userID, action, details string) error
}

// AuditRepositoryExtended adds the read-side and enriched-write methods needed
// by the audit service layer.
type AuditRepositoryExtended interface {
	AuditRepositoryInterface
	InsertAuditLog(log AuditLog) error
	GetLastHash() (string, error)
	QueryAuditLogs(filter AuditFilter) ([]AuditLog, int64, error)
	DeleteBefore(cutoff time.Time) (int64, error)
	GetAuditConfig(key string) (string, error)
	SetAuditConfig(key, value string) error
}

// AuditRepository writes and reads audit records from the audit_logs table.
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates an AuditRepository backed by db.
// The returned value implements both AuditRepositoryInterface and
// AuditRepositoryExtended.
func NewAuditRepository(db *sql.DB) AuditRepositoryExtended {
	return &AuditRepository{db: db}
}

// PersistAudit inserts one row with the legacy (thin) signature.
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

// InsertAuditLog inserts a fully-populated AuditLog row.
func (r *AuditRepository) InsertAuditLog(log AuditLog) error {
	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now().UTC()
	}
	_, err := r.db.Exec(
		`INSERT INTO audit_logs
			(id, user_id, action, details, timestamp,
			 resource_type, resource_id, ip_address, outcome, source, prev_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.ID, log.UserID, log.Action, log.Details, log.Timestamp,
		nullableString(log.ResourceType), nullableString(log.ResourceID),
		nullableString(log.IPAddress), nullableString(log.Outcome),
		nullableString(log.Source), nullableString(log.PrevHash),
	)
	return err
}

// GetLastHash returns the prev_hash of the most recently inserted row,
// or "" if the table is empty.
func (r *AuditRepository) GetLastHash() (string, error) {
	var hash sql.NullString
	err := r.db.QueryRow(
		`SELECT prev_hash FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 1`,
	).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return hash.String, nil
}

// QueryAuditLogs returns audit log rows matching filter, along with the total
// count of matching rows (before limit). Cursor-based pagination uses
// "timestamp|id" encoded as a plain string.
func (r *AuditRepository) QueryAuditLogs(filter AuditFilter) ([]AuditLog, int64, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	where, args := buildAuditWhere(filter)

	// Count total matching rows.
	var total int64
	countSQL := "SELECT COUNT(*) FROM audit_logs" + where
	if err := r.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("audit count query: %w", err)
	}

	// Fetch page.
	querySQL := `SELECT id, user_id, action, details, timestamp,
					resource_type, resource_id, ip_address, outcome, source, prev_hash
				 FROM audit_logs` + where +
		` ORDER BY timestamp DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := r.db.Query(querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("audit log query: %w", err)
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		var userID, resourceType, resourceID, ipAddress, outcome, source, prevHash sql.NullString
		if err := rows.Scan(
			&l.ID, &userID, &l.Action, &l.Details, &l.Timestamp,
			&resourceType, &resourceID, &ipAddress, &outcome, &source, &prevHash,
		); err != nil {
			return nil, 0, fmt.Errorf("audit log scan: %w", err)
		}
		l.UserID = userID.String
		l.ResourceType = resourceType.String
		l.ResourceID = resourceID.String
		l.IPAddress = ipAddress.String
		l.Outcome = outcome.String
		l.Source = source.String
		l.PrevHash = prevHash.String
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

// DeleteBefore deletes all audit_logs rows with timestamp < cutoff.
// Returns the number of deleted rows.
func (r *AuditRepository) DeleteBefore(cutoff time.Time) (int64, error) {
	result, err := r.db.Exec(
		`DELETE FROM audit_logs WHERE timestamp < ?`, cutoff,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetAuditConfig reads a value from audit_config by key.
// Returns "" and no error if the key does not exist.
func (r *AuditRepository) GetAuditConfig(key string) (string, error) {
	var value sql.NullString
	err := r.db.QueryRow(`SELECT value FROM audit_config WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value.String, err
}

// SetAuditConfig upserts a key/value pair in audit_config.
func (r *AuditRepository) SetAuditConfig(key, value string) error {
	_, err := r.db.Exec(
		`INSERT INTO audit_config (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// nullableString converts an empty string to a sql.NullString with Valid=false.
func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// buildAuditWhere constructs a WHERE clause and args slice from an AuditFilter.
func buildAuditWhere(f AuditFilter) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	if f.From != nil {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, *f.From)
	}
	if f.To != nil {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, *f.To)
	}
	if f.UserID != nil {
		clauses = append(clauses, "user_id = ?")
		args = append(args, *f.UserID)
	}
	if f.Action != nil {
		clauses = append(clauses, "action = ?")
		args = append(args, *f.Action)
	}
	if f.Outcome != nil {
		clauses = append(clauses, "outcome = ?")
		args = append(args, *f.Outcome)
	}
	if f.ResourceType != nil {
		clauses = append(clauses, "resource_type = ?")
		args = append(args, *f.ResourceType)
	}
	if f.ResourceID != nil {
		clauses = append(clauses, "resource_id = ?")
		args = append(args, *f.ResourceID)
	}
	if f.Source != nil {
		clauses = append(clauses, "source = ?")
		args = append(args, *f.Source)
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
