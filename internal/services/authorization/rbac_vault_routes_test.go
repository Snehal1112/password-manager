package authorization

import (
	"testing"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// TestValidateEndpointAccess_DataPlaneRoutesDelegate asserts that vault
// data-plane routes no longer consult the caller's global role. They are
// authorized by PolicyMiddleware against the caller's role assignments in the
// resolved vault, so the global RBAC layer must not second-guess that decision:
// a Key Vault Crypto Officer whose global role is "user" must be able to create
// a key in the vault they hold the role in.
func TestValidateEndpointAccess_DataPlaneRoutesDelegate(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	paths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/vaults/prod/secrets"},
		{"DELETE", "/api/v1/vaults/prod/secrets/abc"},
		{"PUT", "/api/v1/vaults/prod/keys/abc"},
		{"POST", "/api/v1/vaults/prod/keys"},
		{"DELETE", "/api/v1/vaults/prod/certificates/abc"},
		{"POST", "/api/v1/vaults/prod/keys/abc/sign"},
		{"DELETE", "/api/v1/vaults/prod/deleted/secrets/abc/purge"},
		{"POST", "/api/v1/secrets"},
		{"GET", "/api/v1/secrets/abc"},
		{"POST", "/api/v1/keys"},
		{"DELETE", "/api/v1/certificates/abc"},
	}
	roles := []string{
		model.RoleUser, model.RoleServiceAccount, model.RoleSecretsManager,
		model.RoleCryptoManager, model.RoleCertificateManager, model.RoleAdmin,
	}

	for _, p := range paths {
		for _, role := range roles {
			t.Run(role+" "+p.method+" "+p.path, func(t *testing.T) {
				if err := svc.ValidateEndpointAccess(role, p.method, p.path); err != nil {
					t.Fatalf("data-plane routes must not be gated by the global role, got %v", err)
				}
			})
		}
	}
}

// TestMapEndpointToPermission_DataPlaneReturnsEmpty pins the mapping directly,
// so a future edit cannot reintroduce a global permission on a data-plane route
// without failing here.
func TestMapEndpointToPermission_DataPlaneReturnsEmpty(t *testing.T) {
	svc := NewRBACService(logging.InitLogger()).(*rbacService)
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/vaults/prod/secrets"},
		{"GET", "/api/v1/vaults/prod/keys"},
		{"PUT", "/api/v1/certificates/abc"},
		{"GET", "/api/v1/deleted/secrets"},
	} {
		if got := svc.mapEndpointToPermission(c.method, c.path); got != "" {
			t.Fatalf("mapEndpointToPermission(%s, %s) = %q, want empty", c.method, c.path, got)
		}
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

	// User management keeps its global permissions; it is not a vault data plane.
	if err := svc.ValidateEndpointAccess(model.RoleUser, "POST", "/api/v1/users"); err == nil {
		t.Fatal("user creation must still require the global users:create permission")
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
