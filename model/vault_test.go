package model

import "testing"

func TestValidateVaultName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid simple", "prod", true},
		{"valid hyphen", "team-a", true},
		{"too short", "ab", false},
		{"uppercase", "Prod", false},
		{"underscore", "team_a", false},
		{"leading hyphen", "-prod", false},
		{"trailing hyphen", "prod-", false},
		{"too long", "a-very-long-vault-name-that-exceeds-the-sixty-three-character-limit-xx", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ValidateVaultName(c.in) == nil; got != c.ok {
				t.Fatalf("ValidateVaultName(%q) ok=%v, want %v", c.in, got, c.ok)
			}
		})
	}
}

func TestDefaultVaultConstants(t *testing.T) {
	if DefaultVaultName != "default" {
		t.Fatalf("DefaultVaultName = %q", DefaultVaultName)
	}
	if DefaultVaultID != "00000000-0000-0000-0000-00000000efa1" {
		t.Fatalf("DefaultVaultID = %q", DefaultVaultID)
	}
}
