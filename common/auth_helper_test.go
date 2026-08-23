package common

import "testing"

func TestHasAnyRole(t *testing.T) {
	tests := []struct {
		name          string
		userRoles     []string
		requiredRoles []string
		want          bool
	}{
		{"single role exact match", []string{"admin"}, []string{"admin"}, true},
		{"single role no match", []string{"user"}, []string{"admin"}, false},
		{"single role matches one of multiple required", []string{"secrets_manager"}, []string{"admin", "secrets_manager"}, true},
		{"multiple roles - first matches", []string{"secrets_manager", "crypto_manager"}, []string{"secrets_manager"}, true},
		{"multiple roles - second matches", []string{"secrets_manager", "crypto_manager"}, []string{"crypto_manager"}, true},
		{"multiple roles - matches one of required", []string{"secrets_manager", "crypto_manager"}, []string{"admin", "secrets_manager", "certificate_manager"}, true},
		{"multiple roles - no match", []string{"secrets_manager", "crypto_manager"}, []string{"admin", "user"}, false},
		{"empty user roles", []string{}, []string{"admin"}, false},
		{"nil user roles", nil, []string{"admin"}, false},
		{"empty required roles", []string{"admin"}, []string{}, false},
		{"both empty", []string{}, []string{}, false},
		{"three roles - matches middle one", []string{"user", "secrets_manager", "crypto_manager"}, []string{"secrets_manager"}, true},
		{"real scenario - user with secrets_manager and crypto_manager", []string{"secrets_manager", "crypto_manager"}, []string{"admin", "secrets_manager"}, true},
		{"certificate manager role check", []string{"certificate_manager", "crypto_manager"}, []string{"admin", "certificate_manager"}, true},
		{"duplicate roles in user roles", []string{"admin", "admin"}, []string{"admin"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasAnyRole(tt.userRoles, tt.requiredRoles...)
			if got != tt.want {
				t.Errorf("HasAnyRole(%v, %v...) = %v, want %v", tt.userRoles, tt.requiredRoles, got, tt.want)
			}
		})
	}
}
