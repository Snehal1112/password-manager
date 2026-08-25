// Package repositories_test covers CertificateRepository.ListDueForRenewal,
// the query backing "certificates rotation-policy status"'s due-for-renewal
// section. It must mirror exactly the condition
// CertificateRenewalService.CheckAndRenewCertificates itself applies (reading
// AutoRenew/RenewalDays/ExpiresAt straight off the certificates table), so
// these tests exercise that condition case by case rather than trusting a
// single happy-path check.
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// TestCertificateRepository_ListDueForRenewal_MatchesSchedulerCondition
// covers every branch CheckAndRenewCertificates itself evaluates: a
// certificate is only "due" when AutoRenew is set, it has an ExpiresAt in the
// future, and it has entered its RenewalDays window (defaulting to 30 when
// unset or non-positive).
func TestCertificateRepository_ListDueForRenewal_MatchesSchedulerCondition(t *testing.T) {
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	dueSoon := newCert(userID, vaultID, "due-soon")
	dueSoon.AutoRenew = true
	dueSoon.RenewalDays = 30
	expiry := now.Add(10 * 24 * time.Hour)
	dueSoon.ExpiresAt = &expiry

	notYetInWindow := newCert(userID, vaultID, "not-yet-in-window")
	notYetInWindow.AutoRenew = true
	notYetInWindow.RenewalDays = 30
	farExpiry := now.Add(200 * 24 * time.Hour)
	notYetInWindow.ExpiresAt = &farExpiry

	autoRenewOff := newCert(userID, vaultID, "auto-renew-off")
	autoRenewOff.AutoRenew = false
	autoRenewOff.RenewalDays = 30
	autoRenewOff.ExpiresAt = &expiry

	alreadyExpired := newCert(userID, vaultID, "already-expired")
	alreadyExpired.AutoRenew = true
	alreadyExpired.RenewalDays = 30
	pastExpiry := now.Add(-24 * time.Hour)
	alreadyExpired.ExpiresAt = &pastExpiry

	noExpiry := newCert(userID, vaultID, "no-expiry")
	noExpiry.AutoRenew = true
	noExpiry.RenewalDays = 30
	noExpiry.ExpiresAt = nil

	defaultedRenewalDays := newCert(userID, vaultID, "defaulted-renewal-days")
	defaultedRenewalDays.AutoRenew = true
	defaultedRenewalDays.RenewalDays = 0 // Must default to 30, same as the scheduler.
	within30 := now.Add(20 * 24 * time.Hour)
	defaultedRenewalDays.ExpiresAt = &within30

	for _, c := range []*model.Certificate{dueSoon, notYetInWindow, autoRenewOff, alreadyExpired, noExpiry, defaultedRenewalDays} {
		require.NoError(t, repo.Create(ctx, c))
	}

	got, err := repo.ListDueForRenewal(ctx, model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)

	names := make(map[string]bool, len(got))
	for _, c := range got {
		names[c.Name] = true
	}
	require.True(t, names["due-soon"], "an auto-renew cert within its window must be due")
	require.True(t, names["defaulted-renewal-days"], "a zero RenewalDays must default to 30, same as the scheduler")
	require.False(t, names["not-yet-in-window"], "a cert far from expiry must not be due")
	require.False(t, names["auto-renew-off"], "a cert with auto-renew off must not be due")
	require.False(t, names["already-expired"], "an already-expired cert must not be due -- the scheduler skips these too")
	require.False(t, names["no-expiry"], "a cert with no ExpiresAt must not be due")
	require.Len(t, got, 2)
}

// TestCertificateRepository_ListDueForRenewal_ScopedToVault verifies that
// ListDueForRenewal only reports certificates in the requested vault.
func TestCertificateRepository_ListDueForRenewal_ScopedToVault(t *testing.T) {
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)
	ctx := context.Background()

	vaultA, vaultB := uuid.New(), uuid.New()
	now := time.Now()
	expiry := now.Add(5 * 24 * time.Hour)

	certA := newCert(uuid.New(), vaultA, "cert-a")
	certA.AutoRenew = true
	certA.RenewalDays = 30
	certA.ExpiresAt = &expiry
	require.NoError(t, repo.Create(ctx, certA))

	certB := newCert(uuid.New(), vaultB, "cert-b")
	certB.AutoRenew = true
	certB.RenewalDays = 30
	certB.ExpiresAt = &expiry
	require.NoError(t, repo.Create(ctx, certB))

	got, err := repo.ListDueForRenewal(ctx, model.NewVaultScope(vaultA, uuid.New()))
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "cert-a", got[0].Name)
}

// TestCertificateRepository_ListDueForRenewal_EmptyWhenNoneDue verifies an
// empty, non-nil slice and no error when nothing is due.
func TestCertificateRepository_ListDueForRenewal_EmptyWhenNoneDue(t *testing.T) {
	db := setupFullCertDB(t)
	log := logging.InitLogger()
	repo := repositories.NewCertificateRepository(rvdb.NewConn(db, rvdb.SQLite), log)

	got, err := repo.ListDueForRenewal(context.Background(), model.NewVaultScope(uuid.New(), uuid.New()))
	require.NoError(t, err)
	require.Empty(t, got)
}
