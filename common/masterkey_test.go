package common

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidateMasterKey_AcceptsRandomKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	if err := ValidateMasterKey(base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Errorf("expected a CSPRNG key to be accepted, got: %v", err)
	}
}

func TestValidateMasterKey_RejectsCommittedDefault(t *testing.T) {
	// The exact value committed to .rocketvault.yaml.
	const committed = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

	err := ValidateMasterKey(committed)
	if err == nil {
		t.Fatal("expected the known-compromised default key to be rejected")
	}
	if !strings.Contains(err.Error(), "known-compromised") {
		t.Errorf("error should identify the key as the compromised default, got: %v", err)
	}
	if !strings.Contains(err.Error(), "master-key rotate") {
		t.Errorf("error should point at the rotation command, got: %v", err)
	}
}

func TestValidateMasterKey_RejectsPrintableASCIIKey(t *testing.T) {
	typed := "correct horse battery staple 32b"
	if len(typed) != 32 {
		t.Fatalf("test fixture must be 32 bytes, got %d", len(typed))
	}

	err := ValidateMasterKey(base64.StdEncoding.EncodeToString([]byte(typed)))
	if err == nil {
		t.Fatal("expected an all-printable-ASCII key to be rejected")
	}
	if !strings.Contains(err.Error(), "openssl rand -base64 32") {
		t.Errorf("error should tell the operator how to generate a key, got: %v", err)
	}
}

func TestValidateMasterKey_RejectsLowDistinctByteKey(t *testing.T) {
	// 32 bytes drawn from only 4 distinct non-printable values.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i % 4)
	}

	if err := ValidateMasterKey(base64.StdEncoding.EncodeToString(key)); err == nil {
		t.Error("expected a low-entropy key to be rejected")
	}
}

func TestValidateMasterKey_RejectsShortKey(t *testing.T) {
	if err := ValidateMasterKey(base64.StdEncoding.EncodeToString([]byte("sixteen bytes!!!"))); err == nil {
		t.Error("expected a 16-byte key to be rejected")
	}
}

func TestValidateMasterKey_RejectsEmptyKey(t *testing.T) {
	if err := ValidateMasterKey(""); err == nil {
		t.Error("expected an empty key to be rejected")
	}
}

func TestValidateMasterKey_RejectsNonBase64Key(t *testing.T) {
	if err := ValidateMasterKey("not-base64!!"); err == nil {
		t.Error("expected a non-base64 key to be rejected")
	}
}
