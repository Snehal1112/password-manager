package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/db"
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
	// GetByCertificateIDAny retrieves the policy for a certificate regardless
	// of owner. Callers must independently verify the caller's access to the
	// certificate (e.g. vault membership) before calling this.
	GetByCertificateIDAny(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error)
	// DeleteByCertificateIDAny removes the policy for a certificate regardless
	// of owner. Callers must independently verify the caller's access to the
	// certificate before calling this.
	DeleteByCertificateIDAny(ctx context.Context, certID uuid.UUID) error
	// ListByVault returns every certificate policy for certificates in
	// scope's vault, each paired with its parent certificate's name, for the
	// "certificates rotation-policy list" report. Certificates with no
	// policy set are simply absent -- this lists policies, not all
	// certificates. Must only be called with a vault scope -- see the
	// implementation's own comment for why.
	ListByVault(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error)
}

// CertificatePolicyRepository is the default database-backed implementation.
type CertificatePolicyRepository struct {
	db  db.DB
	log *logging.Logger
}

// NewCertificatePolicyRepository creates a new CertificatePolicyRepository.
func NewCertificatePolicyRepository(db db.DB, log *logging.Logger) CertificatePolicyRepositoryInterface {
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
// Returns sql.ErrNoRows when no matching policy exists.
func (r *CertificatePolicyRepository) DeleteByCertificateID(ctx context.Context, certID, userID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM certificate_policies WHERE certificate_id = ? AND user_id = ?",
		certID.String(), userID.String(),
	)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListByVault returns every certificate policy for certificates in scope's
// vault, each paired with its parent certificate's name, for the
// "certificates rotation-policy list" report. Certificates with no policy
// set are simply absent -- this lists policies, not all certificates.
//
// certificate_policies itself carries no vault_id column (unlike
// key_rotation_policies, which denormalizes one onto every row), so this
// method JOINs certificates -- the only table in this query with a vault_id
// column -- to keep the unqualified "vault_id = ?" predicate ScopedList
// appends unambiguous. Both sides of the join do carry a user_id column,
// though, so this method must only ever be called with a vault scope: an
// owner-scoped call would append an ambiguous "user_id = ?" predicate.
func (r *CertificatePolicyRepository) ListByVault(ctx context.Context, scope model.Scope) ([]model.CertificatePolicyWithCertName, error) {
	query := `
		SELECT cp.id, cp.certificate_id, cp.user_id, cp.validity_months, cp.key_type, cp.key_size, cp.curve,
		       cp.subject, cp.sans, cp.auto_renew, cp.days_before_expiry, cp.issuer_name, cp.created_at, cp.updated_at,
		       c.name AS cert_name
		FROM certificate_policies cp
		JOIN certificates c ON c.id = cp.certificate_id
		WHERE c.deleted_at IS NULL
	`
	list, err := ScopedList(ctx, r.db, query, nil, scope, "", nil, scanCertificatePolicyWithCertNameRow)
	if err != nil {
		r.log.WithError(err).Error("Failed to list certificate policies")
		return nil, fmt.Errorf("failed to list certificate policies: %w", err)
	}
	return list, nil
}

// scanCertificatePolicyWithCertNameRow scans one certificate_policies row
// plus its trailing cert_name column from ListByVault's JOIN.
func scanCertificatePolicyWithCertNameRow(rows *sql.Rows) (model.CertificatePolicyWithCertName, error) {
	var out model.CertificatePolicyWithCertName
	var idStr, cidStr, uidStr string
	if err := rows.Scan(&idStr, &cidStr, &uidStr,
		&out.ValidityMonths, &out.KeyType, &out.KeySize, &out.Curve,
		&out.Subject, &out.SANs, &out.AutoRenew, &out.DaysBeforeExpiry,
		&out.IssuerName, &out.CreatedAt, &out.UpdatedAt, &out.CertificateName); err != nil {
		return out, err
	}
	var err error
	if out.ID, err = uuid.Parse(idStr); err != nil {
		return out, err
	}
	if out.CertificateID, err = uuid.Parse(cidStr); err != nil {
		return out, err
	}
	if out.UserID, err = uuid.Parse(uidStr); err != nil {
		return out, err
	}
	return out, nil
}

// GetByCertificateIDAny retrieves the policy for a certificate, ignoring
// owner. Callers are responsible for verifying access to the certificate
// (e.g. vault membership) before calling this.
func (r *CertificatePolicyRepository) GetByCertificateIDAny(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, certificate_id, user_id, validity_months, key_type, key_size, curve,
		       subject, sans, auto_renew, days_before_expiry, issuer_name, created_at, updated_at
		FROM certificate_policies
		WHERE certificate_id = ?`,
		certID.String(),
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

// DeleteByCertificateIDAny removes the policy for a certificate, ignoring
// owner. Callers are responsible for verifying access to the certificate
// before calling this. Returns sql.ErrNoRows when no matching policy exists.
func (r *CertificatePolicyRepository) DeleteByCertificateIDAny(ctx context.Context, certID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM certificate_policies WHERE certificate_id = ?",
		certID.String(),
	)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
