package authorization

import (
	"testing"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// TestValidateEndpointAccess_VaultScopedResourceRoutes verifies that vault-scoped
// resource routes (/api/v1/vaults/{name}/secrets|keys|certificates) enforce the
// SAME permissions as the legacy flat routes. Before the fix these paths fell
// through mapEndpointToPermission (prefix "vaults" matched nothing), returning ""
// which ValidateEndpointAccess treated as allow — letting read-only roles write.
func TestValidateEndpointAccess_VaultScopedResourceRoutes(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	cases := []struct {
		name      string
		role      string
		method    string
		path      string
		wantAllow bool
	}{
		// Read-only roles must be DENIED writes on vault-scoped routes.
		{"user cannot create secret in vault", model.RoleUser, "POST", "/api/v1/vaults/prod/secrets", false},
		{"user cannot delete secret in vault", model.RoleUser, "DELETE", "/api/v1/vaults/prod/secrets/abc", false},
		{"user cannot update key in vault", model.RoleUser, "PUT", "/api/v1/vaults/prod/keys/abc", false},
		{"service-account cannot create key in vault", model.RoleServiceAccount, "POST", "/api/v1/vaults/prod/keys", false},
		{"service-account cannot delete cert in vault", model.RoleServiceAccount, "DELETE", "/api/v1/vaults/prod/certificates/abc", false},

		// Read-only roles are still ALLOWED reads on vault-scoped routes.
		{"user can list secrets in vault", model.RoleUser, "GET", "/api/v1/vaults/prod/secrets", true},
		{"user can read secret in vault", model.RoleUser, "GET", "/api/v1/vaults/prod/secrets/abc", true},
		{"service-account can list keys in vault", model.RoleServiceAccount, "GET", "/api/v1/vaults/prod/keys", true},

		// Privileged roles are ALLOWED writes on vault-scoped routes.
		{"secrets-manager can create secret in vault", model.RoleSecretsManager, "POST", "/api/v1/vaults/prod/secrets", true},
		{"admin can delete cert in vault", model.RoleAdmin, "DELETE", "/api/v1/vaults/prod/certificates/abc", true},

		// Legacy flat routes keep working identically (no regression).
		{"user cannot create secret on flat route", model.RoleUser, "POST", "/api/v1/secrets", false},
		{"user can read secret on flat route", model.RoleUser, "GET", "/api/v1/secrets/abc", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := svc.ValidateEndpointAccess(c.role, c.method, c.path)
			gotAllow := err == nil
			if gotAllow != c.wantAllow {
				t.Fatalf("ValidateEndpointAccess(%s, %s, %s) allow=%v, want %v (err=%v)",
					c.role, c.method, c.path, gotAllow, c.wantAllow, err)
			}
		})
	}
}

// TestValidateEndpointAccess_VaultManagementRoutes verifies that vault management
// routes (/api/v1/vaults[/{name}]) require the vaults:manage permission, which only
// admins hold. Before the fix these routes had no RBAC mapping at all, so any
// authenticated user could create or delete (cascade-delete) a vault.
func TestValidateEndpointAccess_VaultManagementRoutes(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	cases := []struct {
		name      string
		role      string
		method    string
		path      string
		wantAllow bool
	}{
		// Non-admins must be DENIED vault management.
		{"user cannot create vault", model.RoleUser, "POST", "/api/v1/vaults", false},
		{"user cannot delete vault", model.RoleUser, "DELETE", "/api/v1/vaults/prod", false},
		{"user cannot update vault", model.RoleUser, "PATCH", "/api/v1/vaults/prod", false},
		{"service-account cannot delete vault", model.RoleServiceAccount, "DELETE", "/api/v1/vaults/prod", false},
		{"secrets-manager cannot delete vault", model.RoleSecretsManager, "DELETE", "/api/v1/vaults/prod", false},

		// Admin is ALLOWED vault management.
		{"admin can create vault", model.RoleAdmin, "POST", "/api/v1/vaults", true},
		{"admin can delete vault", model.RoleAdmin, "DELETE", "/api/v1/vaults/prod", true},
		{"admin can get vault", model.RoleAdmin, "GET", "/api/v1/vaults/prod", true},
		{"admin can list vaults", model.RoleAdmin, "GET", "/api/v1/vaults", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := svc.ValidateEndpointAccess(c.role, c.method, c.path)
			gotAllow := err == nil
			if gotAllow != c.wantAllow {
				t.Fatalf("ValidateEndpointAccess(%s, %s, %s) allow=%v, want %v (err=%v)",
					c.role, c.method, c.path, gotAllow, c.wantAllow, err)
			}
		})
	}
}

// TestVaultManagePermission_OnlyAdmin verifies the vaults:manage permission is
// granted exclusively to the admin role.
func TestVaultManagePermission_OnlyAdmin(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	if !svc.HasPermission(model.RoleAdmin, PermissionManageVaults) {
		t.Fatal("admin must have vaults:manage permission")
	}
	for _, role := range []string{
		model.RoleUser, model.RoleServiceAccount, model.RoleSecretsManager,
		model.RoleCryptoManager, model.RoleCertificateManager,
	} {
		if svc.HasPermission(role, PermissionManageVaults) {
			t.Fatalf("role %s must NOT have vaults:manage permission", role)
		}
	}
}
