package vaults

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type recordingRepo struct{ softCalls, recoverCalls int }

func (r *recordingRepo) SoftDeleteVaultContents(context.Context, uuid.UUID) error {
	r.softCalls++
	return nil
}
func (r *recordingRepo) RecoverVaultContents(context.Context, uuid.UUID) error {
	r.recoverCalls++
	return nil
}

func TestCascadeAdapter_FansOutToAllRepos(t *testing.T) {
	s, k, c := &recordingRepo{}, &recordingRepo{}, &recordingRepo{}
	ad := NewCascadeAdapter(s, k, c)
	if err := ad.SoftDeleteVaultContents(context.Background(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if s.softCalls != 1 || k.softCalls != 1 || c.softCalls != 1 {
		t.Fatalf("soft-delete must fan out to all three repos: s=%d k=%d c=%d", s.softCalls, k.softCalls, c.softCalls)
	}
	if err := ad.RecoverVaultContents(context.Background(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if s.recoverCalls != 1 || k.recoverCalls != 1 || c.recoverCalls != 1 {
		t.Fatalf("recover must fan out to all three repos")
	}
}
