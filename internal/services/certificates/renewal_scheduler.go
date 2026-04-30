package certificates

import (
	"context"
	"time"

	"rocketvault/internal/logging"
)

// CertificateRenewalScheduler runs CertificateRenewalService on a configurable interval.
type CertificateRenewalScheduler struct {
	svc      CertificateRenewalService
	log      *logging.Logger
	done     chan struct{}
	interval time.Duration
}

// NewCertificateRenewalScheduler creates a scheduler with the given interval.
// If interval is <= 0 it defaults to 24 hours.
func NewCertificateRenewalScheduler(svc CertificateRenewalService, log *logging.Logger, interval time.Duration) *CertificateRenewalScheduler {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &CertificateRenewalScheduler{svc: svc, log: log, done: make(chan struct{}), interval: interval}
}

// Start launches the scheduler in a background goroutine.
func (s *CertificateRenewalScheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop signals the scheduler to stop.
func (s *CertificateRenewalScheduler) Stop() {
	close(s.done)
}

func (s *CertificateRenewalScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run once immediately on startup.
	s.check(ctx)

	for {
		select {
		case <-ticker.C:
			s.check(ctx)
		case <-s.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *CertificateRenewalScheduler) check(ctx context.Context) {
	renewed, warned, err := s.svc.CheckAndRenewCertificates(ctx)
	if err != nil {
		s.log.WithError(err).Error("certificate renewal check failed")
		return
	}
	if renewed > 0 || warned > 0 {
		s.log.Infof("certificate renewal check: %d renewed, %d warned", renewed, warned)
	}
}
