package model

import "testing"

func TestValidateVaultTags(t *testing.T) {
	if err := ValidateVaultTags(nil); err != nil {
		t.Fatalf("nil tags should be valid, got %v", err)
	}
	if err := ValidateVaultTags(map[string]string{"env": "prod"}); err != nil {
		t.Fatalf("valid tags rejected: %v", err)
	}
	if err := ValidateVaultTags(map[string]string{"": "x"}); err == nil {
		t.Fatal("empty key should be rejected")
	}
	if err := ValidateVaultTags(map[string]string{"k": ""}); err == nil {
		t.Fatal("empty value should be rejected")
	}
	big := make(map[string]string)
	for i := 0; i < 16; i++ {
		big[string(rune('a'+i))] = "v"
	}
	if err := ValidateVaultTags(big); err == nil {
		t.Fatal("more than 15 tags should be rejected")
	}
	long := make([]byte, 257)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidateVaultTags(map[string]string{string(long): "v"}); err == nil {
		t.Fatal("over-256-char key should be rejected")
	}
}
