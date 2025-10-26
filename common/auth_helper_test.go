/*
Copyright © 2025 Snehal Dangroshiya
*/

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasRequiredRole(t *testing.T) {
	tests := []struct {
		name          string
		userRole      string
		requiredRoles []string
		expected      bool
	}{
		{
			name:          "single role exact match",
			userRole:      "admin",
			requiredRoles: []string{"admin"},
			expected:      true,
		},
		{
			name:          "single role no match",
			userRole:      "user",
			requiredRoles: []string{"admin"},
			expected:      false,
		},
		{
			name:          "single role matches one of multiple required",
			userRole:      "secrets_manager",
			requiredRoles: []string{"admin", "secrets_manager"},
			expected:      true,
		},
		{
			name:          "multiple roles comma-separated - first role matches",
			userRole:      "secrets_manager, crypto_manager",
			requiredRoles: []string{"secrets_manager"},
			expected:      true,
		},
		{
			name:          "multiple roles comma-separated - second role matches",
			userRole:      "secrets_manager, crypto_manager",
			requiredRoles: []string{"crypto_manager"},
			expected:      true,
		},
		{
			name:          "multiple roles comma-separated - matches one of required",
			userRole:      "secrets_manager, crypto_manager",
			requiredRoles: []string{"admin", "secrets_manager", "certificate_manager"},
			expected:      true,
		},
		{
			name:          "multiple roles comma-separated - no match",
			userRole:      "secrets_manager, crypto_manager",
			requiredRoles: []string{"admin", "user"},
			expected:      false,
		},
		{
			name:          "multiple roles with whitespace",
			userRole:      "secrets_manager , crypto_manager",
			requiredRoles: []string{"crypto_manager"},
			expected:      true,
		},
		{
			name:          "multiple roles with extra whitespace",
			userRole:      "secrets_manager  ,  crypto_manager",
			requiredRoles: []string{"secrets_manager"},
			expected:      true,
		},
		{
			name:          "empty user role",
			userRole:      "",
			requiredRoles: []string{"admin"},
			expected:      false,
		},
		{
			name:          "empty required roles",
			userRole:      "admin",
			requiredRoles: []string{},
			expected:      false,
		},
		{
			name:          "both empty",
			userRole:      "",
			requiredRoles: []string{},
			expected:      false,
		},
		{
			name:          "three roles comma-separated - matches middle one",
			userRole:      "user, secrets_manager, crypto_manager",
			requiredRoles: []string{"secrets_manager"},
			expected:      true,
		},
		{
			name:          "real scenario - sd000097 user with secrets_manager and crypto_manager",
			userRole:      "secrets_manager, crypto_manager",
			requiredRoles: []string{"admin", "secrets_manager"},
			expected:      true,
		},
		{
			name:          "certificate manager role check",
			userRole:      "certificate_manager, crypto_manager",
			requiredRoles: []string{"admin", "certificate_manager"},
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasRequiredRole(tt.userRole, tt.requiredRoles...)
			assert.Equal(t, tt.expected, result, "HasRequiredRole(%q, %v) should return %v", tt.userRole, tt.requiredRoles, tt.expected)
		})
	}
}

// TestHasRequiredRole_BackwardCompatibility ensures single role assignments still work.
func TestHasRequiredRole_BackwardCompatibility(t *testing.T) {
	// Test all single role scenarios to ensure backward compatibility
	singleRoleTests := []struct {
		role     string
		required []string
		expected bool
	}{
		{"admin", []string{"admin"}, true},
		{"user", []string{"admin"}, false},
		{"secrets_manager", []string{"admin", "secrets_manager"}, true},
		{"crypto_manager", []string{"crypto_manager", "certificate_manager"}, true},
		{"certificate_manager", []string{"admin", "secrets_manager"}, false},
	}

	for _, tt := range singleRoleTests {
		t.Run(tt.role, func(t *testing.T) {
			result := HasRequiredRole(tt.role, tt.required...)
			assert.Equal(t, tt.expected, result)
		})
	}
}
