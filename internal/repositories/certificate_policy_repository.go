package repositories

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// CertificatePolicyRepositoryInterface defines CRUD operations for certificate policies.
type CertificatePolicyRepositoryInterface interface {
	// Upsert inserts or replaces the policy for a certificate.
	Upsert(ctx context.Context, policy *model.CertificatePolicy) error
	// GetByCertificateID retrieves the policy for a given certificate and owner.
	GetByCertificateID(ctx context.Context, certID, userID uuid.UUID) (*model.CertificatePolicy, error)
	// DeleteByCertificateID removes the policy for a given certificate and owner.
	DeleteByCertificateID(ctx context.Context, certID, userID uuid.UUID) error
}

// CertificatePolicyRepository is the default database-backed implementation.
type CertificatePolicyRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewCertificatePolicyRepository creates a new CertificatePolicyRepository.
func NewCertificatePolicyRepository(db *sql.DB, log *logging.Logger) CertificatePolicyRepositoryInterface {
	return &CertificatePolicyRepository{db: db, log: log}
}

// Upsert inserts a new policy or updates the existing one for the same certificate_id.
func (r *CertificatePolicyRepository) Upsert(ctx context.Context, p *model.CertificatePolicy) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificate_policies
			(id, certificate_id, user_id, validity_months, key_type, key_size, curve,
			 subject, sans, auto_renew, days_before_expiry, issuer_name, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(certificate_id) DO UPDATE SET
			validity_months    = excluded.validity_months,
			key_type           = excluded.key_type,
			key_size           = excluded.key_size,
			curve              = excluded.curve,
			subject            = excluded.subject,
			sans               = excluded.sans,
			auto_renew         = excluded.auto_renew,
			days_before_expiry = excluded.days_before_expiry,
			issuer_name        = excluded.issuer_name,
			updated_at         = excluded.updated_at`,
		p.ID.String(), p.CertificateID.String(), p.UserID.String(),
		p.ValidityMonths, p.KeyType, p.KeySize, p.Curve, p.Subject, p.SANs,
		p.AutoRenew, p.DaysBeforeExpiry, p.IssuerName, p.CreatedAt, p.UpdatedAt,
	)
	return err
}

// GetByCertificateID retrieves the policy scoped to a certificate and its owner.
func (r *CertificatePolicyRepository) GetByCertificateID(ctx context.Context, certID, userID uuid.UUID) (*model.CertificatePolicy, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, certificate_id, user_id, validity_months, key_type, key_size, curve,
		       subject, sans, auto_renew, days_before_expiry, issuer_name, created_at, updated_at
		FROM certificate_policies
		WHERE certificate_id = ? AND user_id = ?`,
		certID.String(), userID.String(),
	)
	var p model.CertificatePolicy
	var idStr, cidStr, uidStr string
	if err := row.Scan(&idStr, &cidStr, &uidStr,
		&p.ValidityMonths, &p.KeyType, &p.KeySize, &p.Curve,
		&p.Subject, &p.SANs, &p.AutoRenew, &p.DaysBeforeExpiry,
		&p.IssuerName, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.ID, _ = uuid.Parse(idStr)
	p.CertificateID, _ = uuid.Parse(cidStr)
	p.UserID, _ = uuid.Parse(uidStr)
	return &p, nil
}

// DeleteByCertificateID removes the policy owned by userID for the given certificate.
func (r *CertificatePolicyRepository) DeleteByCertificateID(ctx context.Context, certID, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM certificate_policies WHERE certificate_id = ? AND user_id = ?",
		certID.String(), userID.String(),
	)
	return err
}
