package model

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

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

func TestVault_Clone_IndependentCopy(t *testing.T) {
	updatedBy := uuid.New()
	v := &Vault{
		ID:        uuid.New(),
		Name:      "original",
		Tags:      map[string]string{"env": "prod"},
		UpdatedBy: &updatedBy,
	}
	clone := v.Clone()

	clone.Name = "changed"
	clone.Tags["env"] = "mutated"
	*clone.UpdatedBy = uuid.New()

	assert.Equal(t, "original", v.Name)
	assert.Equal(t, "prod", v.Tags["env"], "mutating the clone's Tags must not affect the original's backing map")
	assert.NotEqual(t, *v.UpdatedBy, *clone.UpdatedBy)
}

func TestVault_Clone_NilFieldsStayNil(t *testing.T) {
	v := &Vault{ID: uuid.New(), Name: "x"}
	clone := v.Clone()
	assert.Nil(t, clone.Tags)
	assert.Nil(t, clone.DeletedAt)
	assert.Nil(t, clone.ScheduledPurgeAt)
	assert.Nil(t, clone.UpdatedAt)
	assert.Nil(t, clone.UpdatedBy)
}
