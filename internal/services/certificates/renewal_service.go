// Package certificates provides certificate management services for the password manager.
// This file implements the certificate renewal service which scans all certificates
// and either auto-renews or emits warnings based on the auto_renew flag.
package certificates

import (
	"context"
	"time"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// CertificateRenewalService checks all certificates and renews or warns based on auto_renew flag.
type CertificateRenewalService interface {
	CheckAndRenewCertificates(ctx context.Context) (renewed int, warned int, err error)
}

// RenewalServiceConfig holds dependencies for the renewal service.
type RenewalServiceConfig struct {
	CertRepository     repositories.CertificateRepositoryInterface
	CertificateService CertificateService
	Logger             *logging.Logger
}

type certRenewalService struct {
	certRepo repositories.CertificateRepositoryInterface
	certSvc  CertificateService
	logger   *logging.Logger
}

// NewCertificateRenewalService constructs the renewal service with the given configuration.
func NewCertificateRenewalService(cfg RenewalServiceConfig) CertificateRenewalService {
	return &certRenewalService{
		certRepo: cfg.CertRepository,
		certSvc:  cfg.CertificateService,
		logger:   cfg.Logger,
	}
}

// CheckAndRenewCertificates scans all certificates and either auto-renews or warns for each
// certificate that is within its renewal window but has not yet expired.
func (s *certRenewalService) CheckAndRenewCertificates(ctx context.Context) (int, int, error) {
	certs, err := s.certRepo.ListAll(ctx)
	if err != nil {
		return 0, 0, err
	}

	var renewed, warned int
	now := time.Now()

	for _, cert := range certs {
		if cert.ExpiresAt == nil {
			continue
		}

		// Skip certificates that are already expired.
		if cert.ExpiresAt.Before(now) {
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_expiry_warning", "warning",
				"Certificate already expired: "+cert.Name)
			continue
		}

		daysUntilExpiry := int(cert.ExpiresAt.Sub(now).Hours() / 24)
		renewalDays := cert.RenewalDays
		if renewalDays <= 0 {
			renewalDays = 30
		}

		// Certificate is not yet within the renewal window.
		if daysUntilExpiry > renewalDays {
			continue
		}

		if cert.AutoRenew {
			// Preserve original validity period when renewing.
			validityDays := 365
			if !cert.CreatedAt.IsZero() && cert.ExpiresAt != nil {
				validityDays = int(cert.ExpiresAt.Sub(cert.CreatedAt).Hours() / 24)
			}
			if validityDays <= 0 {
				validityDays = 365
			}

			_, err := s.certSvc.RenewCertificate(ctx, cert.ID, cert.UserID, validityDays)
			if err != nil {
				s.logger.LogAuditError(cert.UserID.String(), "cert_auto_renew", "failed",
					"Auto-renewal failed for: "+cert.Name, err)
				continue
			}
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_auto_renew", "success",
				"Auto-renewed certificate: "+cert.Name)
			renewed++
		} else {
			s.logger.LogAuditInfo(cert.UserID.String(), "cert_expiry_warning", "warning",
				"Certificate expiring soon (auto_renew disabled): "+cert.Name)
			warned++
		}
	}

	return renewed, warned, nil
}
