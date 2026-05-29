package authorization

import (
	"testing"

	"rocketvault/model"
	"rocketvault/internal/logging"
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
		{"admin has secret create", model.RoleAdmin, PermissionCreateSecret, true},
		{"admin has secret delete", model.RoleAdmin, PermissionDeleteSecret, true},
		{"admin has user create", model.RoleAdmin, PermissionCreateUser, true},
		{"admin has key delete", model.RoleAdmin, PermissionDeleteKey, true},
		{"admin has cert delete", model.RoleAdmin, PermissionDeleteCertificate, true},
		{"admin has system manage", model.RoleAdmin, PermissionManageSystem, true},

		// Basic user role tests - should only have read permissions
		{"user has secret read", model.RoleUser, PermissionReadSecret, true},
		{"user has secret list", model.RoleUser, PermissionListSecrets, true},
		{"user has key read", model.RoleUser, PermissionReadKey, true},
		{"user CANNOT create secret", model.RoleUser, PermissionCreateSecret, false},
		{"user CANNOT delete secret", model.RoleUser, PermissionDeleteSecret, false},
		{"user CANNOT create user", model.RoleUser, PermissionCreateUser, false},
		{"user CANNOT delete key", model.RoleUser, PermissionDeleteKey, false},
		{"user CANNOT manage system", model.RoleUser, PermissionManageSystem, false},

		// Secrets manager role tests
		{"secrets-manager can create secret", model.RoleSecretsManager, PermissionCreateSecret, true},
		{"secrets-manager can update secret", model.RoleSecretsManager, PermissionUpdateSecret, true},
		{"secrets-manager can delete secret", model.RoleSecretsManager, PermissionDeleteSecret, true},
		{"secrets-manager can read secret", model.RoleSecretsManager, PermissionReadSecret, true},
		{"secrets-manager can list secrets", model.RoleSecretsManager, PermissionListSecrets, true},
		{"secrets-manager CANNOT create user", model.RoleSecretsManager, PermissionCreateUser, false},
		{"secrets-manager CANNOT delete key", model.RoleSecretsManager, PermissionDeleteKey, false},
		{"secrets-manager CANNOT manage certs", model.RoleSecretsManager, PermissionDeleteCertificate, false},

		// Crypto manager role tests
		{"crypto-manager can create key", model.RoleCryptoManager, PermissionCreateKey, true},
		{"crypto-manager can update key", model.RoleCryptoManager, PermissionUpdateKey, true},
		{"crypto-manager can delete key", model.RoleCryptoManager, PermissionDeleteKey, true},
		{"crypto-manager can read key", model.RoleCryptoManager, PermissionReadKey, true},
		{"crypto-manager can list keys", model.RoleCryptoManager, PermissionListKeys, true},
		{"crypto-manager CANNOT delete secret", model.RoleCryptoManager, PermissionDeleteSecret, false},
		{"crypto-manager CANNOT create user", model.RoleCryptoManager, PermissionCreateUser, false},
		{"crypto-manager CANNOT manage certs", model.RoleCryptoManager, PermissionDeleteCertificate, false},

		// Certificate manager role tests
		{"cert-manager can create cert", model.RoleCertificateManager, PermissionCreateCertificate, true},
		{"cert-manager can update cert", model.RoleCertificateManager, PermissionUpdateCertificate, true},
		{"cert-manager can delete cert", model.RoleCertificateManager, PermissionDeleteCertificate, true},
		{"cert-manager can read cert", model.RoleCertificateManager, PermissionReadCertificate, true},
		{"cert-manager can list certs", model.RoleCertificateManager, PermissionListCertificates, true},
		{"cert-manager CANNOT delete secret", model.RoleCertificateManager, PermissionDeleteSecret, false},
		{"cert-manager CANNOT delete key", model.RoleCertificateManager, PermissionDeleteKey, false},
		{"cert-manager CANNOT create user", model.RoleCertificateManager, PermissionCreateUser, false},

		// Service account role tests - read-only consumers (Azure Key Vault model)
		{"service-account can read secret", model.RoleServiceAccount, PermissionReadSecret, true},
		{"service-account can list secrets", model.RoleServiceAccount, PermissionListSecrets, true},
		{"service-account can read key", model.RoleServiceAccount, PermissionReadKey, true},
		{"service-account can list keys", model.RoleServiceAccount, PermissionListKeys, true},
		{"service-account can read cert", model.RoleServiceAccount, PermissionReadCertificate, true},
		{"service-account can list certs", model.RoleServiceAccount, PermissionListCertificates, true},
		{"service-account CANNOT create secret", model.RoleServiceAccount, PermissionCreateSecret, false},
		{"service-account CANNOT update secret", model.RoleServiceAccount, PermissionUpdateSecret, false},
		{"service-account CANNOT delete secret", model.RoleServiceAccount, PermissionDeleteSecret, false},
		{"service-account CANNOT create key", model.RoleServiceAccount, PermissionCreateKey, false},
		{"service-account CANNOT create cert", model.RoleServiceAccount, PermissionCreateCertificate, false},
		{"service-account CANNOT create user", model.RoleServiceAccount, PermissionCreateUser, false},
		{"service-account CANNOT manage system", model.RoleServiceAccount, PermissionManageSystem, false},

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
		{"admin can POST /secrets", model.RoleAdmin, "POST", "/api/v1/secrets", true},
		{"admin can DELETE /secrets/123", model.RoleAdmin, "DELETE", "/api/v1/secrets/123", true},
		{"admin can POST /users", model.RoleAdmin, "POST", "/api/v1/users", true},
		{"admin can DELETE /users/123", model.RoleAdmin, "DELETE", "/api/v1/users/123", true},
		{"admin can DELETE /keys/123", model.RoleAdmin, "DELETE", "/api/v1/keys/123", true},

		// Basic user access tests
		{"user can GET /secrets", model.RoleUser, "GET", "/api/v1/secrets", true},
		{"user can GET /secrets/123", model.RoleUser, "GET", "/api/v1/secrets/123", true},
		{"user CANNOT POST /secrets", model.RoleUser, "POST", "/api/v1/secrets", false},
		{"user CANNOT DELETE /secrets/123", model.RoleUser, "DELETE", "/api/v1/secrets/123", false},
		{"user CANNOT POST /users", model.RoleUser, "POST", "/api/v1/users", false},
		{"user CANNOT DELETE /keys/123", model.RoleUser, "DELETE", "/api/v1/keys/123", false},

		// Secrets manager access tests
		{"secrets-manager can POST /secrets", model.RoleSecretsManager, "POST", "/api/v1/secrets", true},
		{"secrets-manager can PUT /secrets/123", model.RoleSecretsManager, "PUT", "/api/v1/secrets/123", true},
		{"secrets-manager can DELETE /secrets/123", model.RoleSecretsManager, "DELETE", "/api/v1/secrets/123", true},
		{"secrets-manager can GET /secrets", model.RoleSecretsManager, "GET", "/api/v1/secrets", true},
		{"secrets-manager CANNOT POST /users", model.RoleSecretsManager, "POST", "/api/v1/users", false},
		{"secrets-manager CANNOT DELETE /keys/123", model.RoleSecretsManager, "DELETE", "/api/v1/keys/123", false},

		// Crypto manager access tests
		{"crypto-manager can POST /keys", model.RoleCryptoManager, "POST", "/api/v1/keys", true},
		{"crypto-manager can PUT /keys/123", model.RoleCryptoManager, "PUT", "/api/v1/keys/123", true},
		{"crypto-manager can DELETE /keys/123", model.RoleCryptoManager, "DELETE", "/api/v1/keys/123", true},
		{"crypto-manager can GET /keys", model.RoleCryptoManager, "GET", "/api/v1/keys", true},
		{"crypto-manager CANNOT DELETE /secrets/123", model.RoleCryptoManager, "DELETE", "/api/v1/secrets/123", false},
		{"crypto-manager CANNOT POST /users", model.RoleCryptoManager, "POST", "/api/v1/users", false},

		// Certificate manager access tests
		{"cert-manager can POST /certificates", model.RoleCertificateManager, "POST", "/api/v1/certificates", true},
		{"cert-manager can DELETE /certificates/123", model.RoleCertificateManager, "DELETE", "/api/v1/certificates/123", true},
		{"cert-manager CANNOT DELETE /secrets/123", model.RoleCertificateManager, "DELETE", "/api/v1/secrets/123", false},
		{"cert-manager CANNOT POST /users", model.RoleCertificateManager, "POST", "/api/v1/users", false},

		// Public endpoint tests (no permission required - should pass for all roles)
		{"admin can access health", model.RoleAdmin, "GET", "/api/v1/health", true},
		{"user can access health", model.RoleUser, "GET", "/api/v1/health", true},
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
			role:         model.RoleAdmin,
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
			role:         model.RoleUser,
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
			role:         model.RoleSecretsManager,
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

	adminPerms := rbacService.GetRolePermissions(model.RoleAdmin)

	// Create map for quick lookup
	adminPermMap := make(map[Permission]bool)
	for _, perm := range adminPerms {
		adminPermMap[perm] = true
	}

	roles := []string{
		model.RoleUser,
		model.RoleSecretsManager,
		model.RoleCryptoManager,
		model.RoleCertificateManager,
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
