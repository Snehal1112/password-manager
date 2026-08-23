package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsValidRole accepts every member of ValidRoles and rejects everything
// else, including a role that is valid everywhere but here (RoleServiceAccount,
// deliberately excluded -- see ValidRoles' doc comment), whitespace, and case
// variations. IsValidRole itself performs no trimming or case-folding -- the
// match is exact.
func TestIsValidRole(t *testing.T) {
	for _, role := range ValidRoles {
		assert.True(t, IsValidRole(role), "expected %q to be a valid role", role)
	}

	cases := []string{
		"",
		RoleServiceAccount,
		" admin",
		"ADMIN",
		"not_a_role",
	}
	for _, role := range cases {
		assert.False(t, IsValidRole(role), "expected %q not to be a valid role", role)
	}
}
