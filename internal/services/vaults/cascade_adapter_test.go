package vaults

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/db"
)

type recordingRepo struct{ softCalls, recoverCalls, purgeCalls int }

func (r *recordingRepo) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	r.softCalls++
	return nil
}
func (r *recordingRepo) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error {
	r.recoverCalls++
	return nil
}
func (r *recordingRepo) SoftDeleteVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	r.softCalls++
	return nil
}
func (r *recordingRepo) RecoverVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	r.recoverCalls++
	return nil
}
func (r *recordingRepo) PurgeVaultContents(context.Context, uuid.UUID) error {
	r.purgeCalls++
	return nil
}

func TestCascadeAdapter_FansOutToAllRepos(t *testing.T) {
	s, k, c := &recordingRepo{}, &recordingRepo{}, &recordingRepo{}
	ad := NewCascadeAdapter(s, k, c)
	if err := ad.SoftDeleteVaultContents(context.Background(), uuid.New(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.softCalls != 1 || k.softCalls != 1 || c.softCalls != 1 {
		t.Fatalf("soft-delete must fan out to all three repos: s=%d k=%d c=%d", s.softCalls, k.softCalls, c.softCalls)
	}
	if err := ad.RecoverVaultContents(context.Background(), uuid.New(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.recoverCalls != 1 || k.recoverCalls != 1 || c.recoverCalls != 1 {
		t.Fatalf("recover must fan out to all three repos")
	}
}

// failingRepo fails its soft-delete to exercise the adapter's error path.
type failingRepo struct{ err error }

func (f *failingRepo) SoftDeleteVaultContents(context.Context, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingRepo) RecoverVaultContents(context.Context, uuid.UUID, time.Time) error { return f.err }
func (f *failingRepo) SoftDeleteVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingRepo) RecoverVaultContentsTx(context.Context, db.DBTX, uuid.UUID, time.Time) error {
	return f.err
}
func (f *failingRepo) PurgeVaultContents(context.Context, uuid.UUID) error {
	return f.err
}

func TestCascadeAdapter_ReturnsFirstError(t *testing.T) {
	boom := errors.New("boom")
	failing := &failingRepo{err: boom}
	later := &recordingRepo{}
	ad := NewCascadeAdapter(failing, later)

	err := ad.SoftDeleteVaultContents(context.Background(), uuid.New(), time.Now())
	if !errors.Is(err, boom) {
		t.Fatalf("expected the first repo's error, got %v", err)
	}
	if later.softCalls != 0 {
		t.Fatalf("expected later repo not to be called after an error, got %d", later.softCalls)
	}
}

// TestCascadeAdapter_TxFansOutToAllRepos proves the Tx-scoped fan-out behaves
// exactly like the non-Tx fan-out, threading the same executor to every repo.
func TestCascadeAdapter_TxFansOutToAllRepos(t *testing.T) {
	s, k, c := &recordingRepo{}, &recordingRepo{}, &recordingRepo{}
	ad := NewCascadeAdapter(s, k, c)
	if err := ad.SoftDeleteVaultContentsTx(context.Background(), nil, uuid.New(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.softCalls != 1 || k.softCalls != 1 || c.softCalls != 1 {
		t.Fatalf("Tx soft-delete must fan out to all three repos: s=%d k=%d c=%d", s.softCalls, k.softCalls, c.softCalls)
	}
}

func TestCascadeAdapter_TxReturnsFirstError(t *testing.T) {
	boom := errors.New("boom")
	failing := &failingRepo{err: boom}
	later := &recordingRepo{}
	ad := NewCascadeAdapter(failing, later)

	err := ad.SoftDeleteVaultContentsTx(context.Background(), nil, uuid.New(), time.Now())
	if !errors.Is(err, boom) {
		t.Fatalf("expected the first repo's error, got %v", err)
	}
	if later.softCalls != 0 {
		t.Fatalf("expected later repo not to be called after an error, got %d", later.softCalls)
	}
}

// TestCascadeAdapter_PurgeFansOutToAllRepos proves PurgeVaultContents fans
// out to every repo, the same as soft-delete and recover.
func TestCascadeAdapter_PurgeFansOutToAllRepos(t *testing.T) {
	s, k, c := &recordingRepo{}, &recordingRepo{}, &recordingRepo{}
	ad := NewCascadeAdapter(s, k, c)
	if err := ad.PurgeVaultContents(context.Background(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if s.purgeCalls != 1 || k.purgeCalls != 1 || c.purgeCalls != 1 {
		t.Fatalf("purge must fan out to all three repos: s=%d k=%d c=%d", s.purgeCalls, k.purgeCalls, c.purgeCalls)
	}
}

func TestCascadeAdapter_PurgeReturnsFirstError(t *testing.T) {
	boom := errors.New("boom")
	failing := &failingRepo{err: boom}
	later := &recordingRepo{}
	ad := NewCascadeAdapter(failing, later)

	err := ad.PurgeVaultContents(context.Background(), uuid.New())
	if !errors.Is(err, boom) {
		t.Fatalf("expected the first repo's error, got %v", err)
	}
	if later.purgeCalls != 0 {
		t.Fatalf("expected later repo not to be called after an error, got %d", later.purgeCalls)
	}
}
