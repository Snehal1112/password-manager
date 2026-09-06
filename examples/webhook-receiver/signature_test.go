package main

import (
	"strconv"
	"testing"
	"time"
)

// Golden vector: fixed secret, timestamp and body, asserted against an exact
// hex digest, so a refactor of Sign/Verify can't silently drift from the
// documented scheme without failing here.
const (
	goldenSecret = "whsec_5f3a8c2e9b114d6f8a0c3e7b9d2f4a6c8e0b2d4f6a8c0e"
	goldenTS     = int64(1755689576)
	goldenBody   = `{"version":"1","id":"8f14e45f-ea3f-4b21-9c1d-0a1b2c3d4e5f","type":"webhook.test","time":"2025-08-20T14:32:56Z","vault":"demo","data":{}}`
	goldenSig    = "66d1472d5045b1d934eaf3e2ad3f8aef5d6d5aa32737247f7eceeac5e9e7a171"
)

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func TestSign_GoldenVector(t *testing.T) {
	got := Sign(goldenSecret, goldenTS, []byte(goldenBody))
	if got != goldenSig {
		t.Fatalf("Sign() = %q, want %q", got, goldenSig)
	}
}

func TestVerify_GoldenVector(t *testing.T) {
	header := "t=" + itoa(goldenTS) + ",v1=" + goldenSig
	now := time.Unix(goldenTS, 0).Add(2 * time.Second)
	if err := Verify(goldenSecret, header, []byte(goldenBody), 5*time.Minute, now); err != nil {
		t.Fatalf("Verify() = %v, want nil", err)
	}
}

func TestVerify_RejectsBadSecret(t *testing.T) {
	header := "t=" + itoa(goldenTS) + ",v1=" + goldenSig
	now := time.Unix(goldenTS, 0)
	err := Verify("wrong-secret", header, []byte(goldenBody), 5*time.Minute, now)
	if err != ErrSignatureMismatch {
		t.Fatalf("Verify() = %v, want ErrSignatureMismatch", err)
	}
}

func TestVerify_RejectsTamperedBody(t *testing.T) {
	header := "t=" + itoa(goldenTS) + ",v1=" + goldenSig
	now := time.Unix(goldenTS, 0)
	tampered := append([]byte(goldenBody), ' ')
	err := Verify(goldenSecret, header, tampered, 5*time.Minute, now)
	if err != ErrSignatureMismatch {
		t.Fatalf("Verify() = %v, want ErrSignatureMismatch", err)
	}
}

func TestVerify_RejectsStaleTimestamp(t *testing.T) {
	header := "t=" + itoa(goldenTS) + ",v1=" + goldenSig
	now := time.Unix(goldenTS, 0).Add(10 * time.Minute)
	err := Verify(goldenSecret, header, []byte(goldenBody), 5*time.Minute, now)
	if err != ErrTimestampSkew {
		t.Fatalf("Verify() = %v, want ErrTimestampSkew", err)
	}
}

func TestVerify_RejectsMalformedHeader(t *testing.T) {
	now := time.Unix(goldenTS, 0)
	for _, header := range []string{"", "v1=abc", "t=abc,v1=def", "t=1,v1="} {
		if err := Verify(goldenSecret, header, []byte(goldenBody), 5*time.Minute, now); err == nil {
			t.Fatalf("Verify(header=%q) = nil, want an error", header)
		}
	}
}
