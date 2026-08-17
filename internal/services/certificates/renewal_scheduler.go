package certificates

import (
	"context"
	"time"

	"rocketvault/internal/logging"
	"rocketvault/internal/schedulerkit"
)

// CertificateRenewalScheduler runs CertificateRenewalService on a configurable interval.
type CertificateRenewalScheduler struct {
	runner   *schedulerkit.Runner
	interval time.Duration
}

// NewCertificateRenewalScheduler creates a scheduler with the given interval.
// If interval is <= 0 it defaults to 24 hours.
func NewCertificateRenewalScheduler(svc CertificateRenewalService, log *logging.Logger, interval time.Duration) *CertificateRenewalScheduler {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	check := func(ctx context.Context) error {
		renewed, warned, err := svc.CheckAndRenewCertificates(ctx)
		if err != nil {
			log.WithError(err).Error("certificate renewal check failed")
			return nil // handled here; nothing further for the Runner to log
		}
		if renewed > 0 || warned > 0 {
			log.Infof("certificate renewal check: %d renewed, %d warned", renewed, warned)
		}
		return nil
	}
	return &CertificateRenewalScheduler{
		runner:   schedulerkit.NewRunner("certificate renewal", check, log),
		interval: interval,
	}
}

// Start launches the scheduler in a background goroutine.
func (s *CertificateRenewalScheduler) Start(ctx context.Context) {
	_ = s.runner.Start(ctx, s.interval)
}

// Stop signals the scheduler to stop.
func (s *CertificateRenewalScheduler) Stop() {
	_ = s.runner.Stop()
}
