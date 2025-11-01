package authorization

import (
	"testing"

	"password-manager/internal/domain"
	"password-manager/internal/logging"
)

// TestRBACPermissionValidation validates that each role has the correct permissions.
func TestRBACPermissionValidation(t *testing.T) {
	logger := logging.InitLogger()
	rbacService := NewRBACService(logger)

	tests := []struct {
		name       string
		role       string
		permission Permission
		expected   bool
	}{
		// Admin role tests - should have all permissions
		{"admin has secret create", domain.RoleAdmin, PermissionCreateSecret, true},
		{"admin has secret delete", domain.RoleAdmin, PermissionDeleteSecret, true},
		{"admin has user create", domain.RoleAdmin, PermissionCreateUser, true},
		{"admin has key delete", domain.RoleAdmin, PermissionDeleteKey, true},
		{"admin has cert delete", domain.RoleAdmin, PermissionDeleteCertificate, true},
		{"admin has system manage", domain.RoleAdmin, PermissionManageSystem, true},

		// Basic user role tests - should only have read permissions
		{"user has secret read", domain.RoleUser, PermissionReadSecret, true},
		{"user has secret list", domain.RoleUser, PermissionListSecrets, true},
		{"user has key read", domain.RoleUser, PermissionReadKey, true},
		{"user CANNOT create secret", domain.RoleUser, PermissionCreateSecret, false},
		{"user CANNOT delete secret", domain.RoleUser, PermissionDeleteSecret, false},
		{"user CANNOT create user", domain.RoleUser, PermissionCreateUser, false},
		{"user CANNOT delete key", domain.RoleUser, PermissionDeleteKey, false},
		{"user CANNOT manage system", domain.RoleUser, PermissionManageSystem, false},

		// Secrets manager role tests
		{"secrets-manager can create secret", domain.RoleSecretsManager, PermissionCreateSecret, true},
		{"secrets-manager can update secret", domain.RoleSecretsManager, PermissionUpdateSecret, true},
		{"secrets-manager can delete secret", domain.RoleSecretsManager, PermissionDeleteSecret, true},
		{"secrets-manager can read secret", domain.RoleSecretsManager, PermissionReadSecret, true},
		{"secrets-manager can list secrets", domain.RoleSecretsManager, PermissionListSecrets, true},
		{"secrets-manager CANNOT create user", domain.RoleSecretsManager, PermissionCreateUser, false},
		{"secrets-manager CANNOT delete key", domain.RoleSecretsManager, PermissionDeleteKey, false},
		{"secrets-manager CANNOT manage certs", domain.RoleSecretsManager, PermissionDeleteCertificate, false},

		// Crypto manager role tests
		{"crypto-manager can create key", domain.RoleCryptoManager, PermissionCreateKey, true},
		{"crypto-manager can update key", domain.RoleCryptoManager, PermissionUpdateKey, true},
		{"crypto-manager can delete key", domain.RoleCryptoManager, PermissionDeleteKey, true},
		{"crypto-manager can read key", domain.RoleCryptoManager, PermissionReadKey, true},
		{"crypto-manager can list keys", domain.RoleCryptoManager, PermissionListKeys, true},
		{"crypto-manager CANNOT delete secret", domain.RoleCryptoManager, PermissionDeleteSecret, false},
		{"crypto-manager CANNOT create user", domain.RoleCryptoManager, PermissionCreateUser, false},
		{"crypto-manager CANNOT manage certs", domain.RoleCryptoManager, PermissionDeleteCertificate, false},

		// Certificate manager role tests
		{"cert-manager can create cert", domain.RoleCertificateManager, PermissionCreateCertificate, true},
		{"cert-manager can update cert", domain.RoleCertificateManager, PermissionUpdateCertificate, true},
		{"cert-manager can delete cert", domain.RoleCertificateManager, PermissionDeleteCertificate, true},
		{"cert-manager can read cert", domain.RoleCertificateManager, PermissionReadCertificate, true},
		{"cert-manager can list certs", domain.RoleCertificateManager, PermissionListCertificates, true},
		{"cert-manager CANNOT delete secret", domain.RoleCertificateManager, PermissionDeleteSecret, false},
		{"cert-manager CANNOT delete key", domain.RoleCertificateManager, PermissionDeleteKey, false},
		{"cert-manager CANNOT create user", domain.RoleCertificateManager, PermissionCreateUser, false},

		// Unknown role tests
		{"unknown role has no permissions", "unknown", PermissionReadSecret, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rbacService.HasPermission(tt.role, tt.permission)
			if result != tt.expected {
				t.Errorf("HasPermission(%s, %s) = %v, want %v",
					tt.role, tt.permission, result, tt.expected)
			}
		})
	}
}

// TestEndpointAccessValidation validates endpoint-to-permission mapping.
func TestEndpointAccessValidation(t *testing.T) {
	logger := logging.InitLogger()
	rbacService := NewRBACService(logger)

	tests := []struct {
		name        string
		role        string
		method      string
		path        string
		shouldAllow bool
	}{
		// Admin access tests
		{"admin can POST /secrets", domain.RoleAdmin, "POST", "/api/v1/secrets", true},
		{"admin can DELETE /secrets/123", domain.RoleAdmin, "DELETE", "/api/v1/secrets/123", true},
		{"admin can POST /users", domain.RoleAdmin, "POST", "/api/v1/users", true},
		{"admin can DELETE /users/123", domain.RoleAdmin, "DELETE", "/api/v1/users/123", true},
		{"admin can DELETE /keys/123", domain.RoleAdmin, "DELETE", "/api/v1/keys/123", true},

		// Basic user access tests
		{"user can GET /secrets", domain.RoleUser, "GET", "/api/v1/secrets", true},
		{"user can GET /secrets/123", domain.RoleUser, "GET", "/api/v1/secrets/123", true},
		{"user CANNOT POST /secrets", domain.RoleUser, "POST", "/api/v1/secrets", false},
		{"user CANNOT DELETE /secrets/123", domain.RoleUser, "DELETE", "/api/v1/secrets/123", false},
		{"user CANNOT POST /users", domain.RoleUser, "POST", "/api/v1/users", false},
		{"user CANNOT DELETE /keys/123", domain.RoleUser, "DELETE", "/api/v1/keys/123", false},

		// Secrets manager access tests
		{"secrets-manager can POST /secrets", domain.RoleSecretsManager, "POST", "/api/v1/secrets", true},
		{"secrets-manager can PUT /secrets/123", domain.RoleSecretsManager, "PUT", "/api/v1/secrets/123", true},
		{"secrets-manager can DELETE /secrets/123", domain.RoleSecretsManager, "DELETE", "/api/v1/secrets/123", true},
		{"secrets-manager can GET /secrets", domain.RoleSecretsManager, "GET", "/api/v1/secrets", true},
		{"secrets-manager CANNOT POST /users", domain.RoleSecretsManager, "POST", "/api/v1/users", false},
		{"secrets-manager CANNOT DELETE /keys/123", domain.RoleSecretsManager, "DELETE", "/api/v1/keys/123", false},

		// Crypto manager access tests
		{"crypto-manager can POST /keys", domain.RoleCryptoManager, "POST", "/api/v1/keys", true},
		{"crypto-manager can PUT /keys/123", domain.RoleCryptoManager, "PUT", "/api/v1/keys/123", true},
		{"crypto-manager can DELETE /keys/123", domain.RoleCryptoManager, "DELETE", "/api/v1/keys/123", true},
		{"crypto-manager can GET /keys", domain.RoleCryptoManager, "GET", "/api/v1/keys", true},
		{"crypto-manager CANNOT DELETE /secrets/123", domain.RoleCryptoManager, "DELETE", "/api/v1/secrets/123", false},
		{"crypto-manager CANNOT POST /users", domain.RoleCryptoManager, "POST", "/api/v1/users", false},

		// Certificate manager access tests
		{"cert-manager can POST /certificates", domain.RoleCertificateManager, "POST", "/api/v1/certificates", true},
		{"cert-manager can DELETE /certificates/123", domain.RoleCertificateManager, "DELETE", "/api/v1/certificates/123", true},
		{"cert-manager CANNOT DELETE /secrets/123", domain.RoleCertificateManager, "DELETE", "/api/v1/secrets/123", false},
		{"cert-manager CANNOT POST /users", domain.RoleCertificateManager, "POST", "/api/v1/users", false},

		// Public endpoint tests (no permission required - should pass for all roles)
		{"admin can access health", domain.RoleAdmin, "GET", "/api/v1/health", true},
		{"user can access health", domain.RoleUser, "GET", "/api/v1/health", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rbacService.ValidateEndpointAccess(tt.role, tt.method, tt.path)

			if tt.shouldAllow {
				if err != nil {
					t.Errorf("ValidateEndpointAccess(%s, %s, %s) should allow but got error: %v",
						tt.role, tt.method, tt.path, err)
				}
			} else {
				if err == nil {
					t.Errorf("ValidateEndpointAccess(%s, %s, %s) should deny but allowed access",
						tt.role, tt.method, tt.path)
				}
			}
		})
	}
}

// TestGetRolePermissions validates that role permissions are correctly returned.
func TestGetRolePermissions(t *testing.T) {
	logger := logging.InitLogger()
	rbacService := NewRBACService(logger)

	tests := []struct {
		name          string
		role          string
		minPermCount  int
		shouldInclude []Permission
		shouldExclude []Permission
	}{
		{
			name:         "admin has all permissions",
			role:         domain.RoleAdmin,
			minPermCount: 15, // Should have all permissions
			shouldInclude: []Permission{
				PermissionCreateSecret,
				PermissionDeleteSecret,
				PermissionCreateUser,
				PermissionManageSystem,
			},
			shouldExclude: []Permission{}, // Admin should have everything
		},
		{
			name:         "user has only read permissions",
			role:         domain.RoleUser,
			minPermCount: 6, // Limited permissions
			shouldInclude: []Permission{
				PermissionReadSecret,
				PermissionListSecrets,
				PermissionReadKey,
			},
			shouldExclude: []Permission{
				PermissionCreateSecret,
				PermissionDeleteSecret,
				PermissionCreateUser,
				PermissionManageSystem,
			},
		},
		{
			name:         "secrets-manager has secret permissions",
			role:         domain.RoleSecretsManager,
			minPermCount: 5, // All secret operations
			shouldInclude: []Permission{
				PermissionCreateSecret,
				PermissionReadSecret,
				PermissionUpdateSecret,
				PermissionDeleteSecret,
				PermissionListSecrets,
			},
			shouldExclude: []Permission{
				PermissionCreateUser,
				PermissionDeleteKey,
				PermissionManageSystem,
			},
		},
		{
			name:         "unknown role has no permissions",
			role:         "unknown",
			minPermCount: 0,
			shouldInclude: []Permission{},
			shouldExclude: []Permission{
				PermissionReadSecret,
				PermissionCreateUser,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := rbacService.GetRolePermissions(tt.role)

			// Check minimum permission count
			if len(perms) < tt.minPermCount {
				t.Errorf("Role %s should have at least %d permissions, got %d",
					tt.role, tt.minPermCount, len(perms))
			}

			// Check included permissions
			for _, perm := range tt.shouldInclude {
				found := false
				for _, p := range perms {
					if p == perm {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Role %s should include permission %s", tt.role, perm)
				}
			}

			// Check excluded permissions
			for _, perm := range tt.shouldExclude {
				for _, p := range perms {
					if p == perm {
						t.Errorf("Role %s should NOT include permission %s", tt.role, perm)
					}
				}
			}
		})
	}
}

// TestRoleHierarchy validates that admin role has superset of all other roles.
func TestRoleHierarchy(t *testing.T) {
	logger := logging.InitLogger()
	rbacService := NewRBACService(logger)

	adminPerms := rbacService.GetRolePermissions(domain.RoleAdmin)

	// Create map for quick lookup
	adminPermMap := make(map[Permission]bool)
	for _, perm := range adminPerms {
		adminPermMap[perm] = true
	}

	roles := []string{
		domain.RoleUser,
		domain.RoleSecretsManager,
		domain.RoleCryptoManager,
		domain.RoleCertificateManager,
	}

	for _, role := range roles {
		t.Run("admin includes "+role, func(t *testing.T) {
			rolePerms := rbacService.GetRolePermissions(role)

			for _, perm := range rolePerms {
				if !adminPermMap[perm] {
					t.Errorf("Admin role should include all permissions from %s role, missing: %s",
						role, perm)
				}
			}
		})
	}
}
