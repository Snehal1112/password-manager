// Package authorization provides authorization services for the password manager.
// It handles role-based access control (RBAC) and permission checking,
// separating authorization logic from middleware and other components.
package authorization

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"rocketvault/model"
	"rocketvault/internal/logging"
)

// Permission represents a specific permission that can be granted to roles.
type Permission string

const (
	// Secret permissions
	PermissionCreateSecret Permission = "secrets:create"
	PermissionReadSecret   Permission = "secrets:read"
	PermissionUpdateSecret Permission = "secrets:update"
	PermissionDeleteSecret Permission = "secrets:delete"
	PermissionListSecrets  Permission = "secrets:list"

	// Key permissions
	PermissionCreateKey Permission = "keys:create"
	PermissionReadKey   Permission = "keys:read"
	PermissionUpdateKey Permission = "keys:update"
	PermissionDeleteKey Permission = "keys:delete"
	PermissionListKeys  Permission = "keys:list"

	// Certificate permissions
	PermissionCreateCertificate Permission = "certificates:create"
	PermissionReadCertificate   Permission = "certificates:read"
	PermissionUpdateCertificate Permission = "certificates:update"
	PermissionDeleteCertificate Permission = "certificates:delete"
	PermissionListCertificates  Permission = "certificates:list"

	// User management permissions
	PermissionCreateUser Permission = "users:create"
	PermissionReadUser   Permission = "users:read"
	PermissionUpdateUser Permission = "users:update"
	PermissionDeleteUser Permission = "users:delete"
	PermissionListUsers  Permission = "users:list"

	// Admin permissions
	PermissionManageSystem Permission = "system:manage"
)

// RBACService handles role-based access control operations.
// It provides permission checking and role management functionality,
// separating authorization concerns from HTTP middleware.
type RBACService interface {
	HasPermission(role string, permission Permission) bool
	GetRolePermissions(role string) []Permission
	ValidateEndpointAccess(role, method, path string) error
}

// rbacService implements RBACService with configurable role-permission mappings.
type rbacService struct {
	rolePermissions map[string][]Permission
	logger          *logging.Logger
}

// NewRBACService creates a new RBACService with default role-permission mappings.
// It initializes the service with standard permissions for each role.
//
// Parameters:
//
//	logger: The logger for audit and error logging.
//
// Returns:
//
//	An RBACService implementation for authorization operations.
func NewRBACService(logger *logging.Logger) RBACService {
	return &rbacService{
		rolePermissions: getDefaultRolePermissions(),
		logger:          logger,
	}
}

// getDefaultRolePermissions returns the default role-permission mappings.
func getDefaultRolePermissions() map[string][]Permission {
	return map[string][]Permission{
		model.RoleAdmin: {
			// Admin has all permissions
			PermissionCreateSecret, PermissionReadSecret, PermissionUpdateSecret, PermissionDeleteSecret, PermissionListSecrets,
			PermissionCreateKey, PermissionReadKey, PermissionUpdateKey, PermissionDeleteKey, PermissionListKeys,
			PermissionCreateCertificate, PermissionReadCertificate, PermissionUpdateCertificate, PermissionDeleteCertificate, PermissionListCertificates,
			PermissionCreateUser, PermissionReadUser, PermissionUpdateUser, PermissionDeleteUser, PermissionListUsers,
			PermissionManageSystem,
		},
		model.RoleUser: {
			// Basic user has limited permissions
			PermissionReadSecret, PermissionListSecrets,
			PermissionReadKey, PermissionListKeys,
			PermissionReadCertificate, PermissionListCertificates,
		},
		model.RoleSecretsManager: {
			// Secrets manager has full secret permissions
			PermissionCreateSecret, PermissionReadSecret, PermissionUpdateSecret, PermissionDeleteSecret, PermissionListSecrets,
		},
		model.RoleCryptoManager: {
			// Crypto manager has full key permissions
			PermissionCreateKey, PermissionReadKey, PermissionUpdateKey, PermissionDeleteKey, PermissionListKeys,
		},
		model.RoleCertificateManager: {
			// Certificate manager has full certificate permissions
			PermissionCreateCertificate, PermissionReadCertificate, PermissionUpdateCertificate, PermissionDeleteCertificate, PermissionListCertificates,
		},
		model.RoleServiceAccount: {
			// Service accounts get read-only access to secrets, keys, and certificates by default;
			// fine-grained control is delegated to the access-policy layer (Milestone 2)
			PermissionReadSecret, PermissionListSecrets,
			PermissionReadKey, PermissionListKeys,
			PermissionReadCertificate, PermissionListCertificates,
		},
	}
}

// HasPermission checks if a role has a specific permission.
//
// Parameters:
//
//	role: The user's role.
//	permission: The permission to check.
//
// Returns:
//
//	True if the role has the permission, false otherwise.
func (s *rbacService) HasPermission(role string, permission Permission) bool {
	permissions, exists := s.rolePermissions[role]
	if !exists {
		logrus.WithFields(logrus.Fields{
			"role":       role,
			"permission": string(permission),
		}).Warn("Unknown role in permission check")
		return false
	}

	for _, perm := range permissions {
		if perm == permission {
			return true
		}
	}

	return false
}

// GetRolePermissions returns all permissions for a given role.
//
// Parameters:
//
//	role: The role to get permissions for.
//
// Returns:
//
//	A slice of permissions granted to the role.
func (s *rbacService) GetRolePermissions(role string) []Permission {
	permissions, exists := s.rolePermissions[role]
	if !exists {
		return []Permission{}
	}

	// Return a copy to prevent modification
	result := make([]Permission, len(permissions))
	copy(result, permissions)
	return result
}

// ValidateEndpointAccess validates if a role can access a specific endpoint.
// It maps HTTP endpoints to required permissions and checks authorization.
//
// Parameters:
//
//	role: The user's role.
//	method: The HTTP method (GET, POST, PUT, DELETE).
//	path: The request path.
//
// Returns:
//
//	An error if access is denied, nil if access is granted.
func (s *rbacService) ValidateEndpointAccess(role, method, path string) error {
	permission := s.mapEndpointToPermission(method, path)
	if permission == "" {
		// No specific permission required, allow access
		return nil
	}

	if !s.HasPermission(role, permission) {
		s.logger.LogAuditError("", "authorization", "failed",
			fmt.Sprintf("Access denied for role %s to %s %s", role, method, path), nil)

		logrus.WithFields(logrus.Fields{
			"role":                role,
			"method":              method,
			"path":                path,
			"required_permission": string(permission),
		}).Warn("Access denied: insufficient permissions")

		return fmt.Errorf("insufficient permissions: %s required", permission)
	}

	logrus.WithFields(logrus.Fields{
		"role":       role,
		"method":     method,
		"path":       path,
		"permission": string(permission),
	}).Debug("Access granted")

	return nil
}

// mapEndpointToPermission maps HTTP endpoints to required permissions.
func (s *rbacService) mapEndpointToPermission(method, path string) Permission {
	// Normalize path for comparison
	path = strings.TrimPrefix(path, "/api/v1")
	path = strings.TrimPrefix(path, "/")

	// Secrets endpoints
	if strings.HasPrefix(path, "secrets") {
		switch method {
		case "POST":
			return PermissionCreateSecret
		case "GET":
			if strings.Contains(path, "/") {
				return PermissionReadSecret
			}
			return PermissionListSecrets
		case "PUT":
			return PermissionUpdateSecret
		case "DELETE":
			return PermissionDeleteSecret
		}
	}

	// Keys endpoints
	if strings.HasPrefix(path, "keys") {
		switch method {
		case "POST":
			return PermissionCreateKey
		case "GET":
			if strings.Contains(path, "/") {
				return PermissionReadKey
			}
			return PermissionListKeys
		case "PUT":
			return PermissionUpdateKey
		case "DELETE":
			return PermissionDeleteKey
		}
	}

	// Certificates endpoints
	if strings.HasPrefix(path, "certificates") {
		switch method {
		case "POST":
			return PermissionCreateCertificate
		case "GET":
			if strings.Contains(path, "/") {
				return PermissionReadCertificate
			}
			return PermissionListCertificates
		case "PUT":
			return PermissionUpdateCertificate
		case "DELETE":
			return PermissionDeleteCertificate
		}
	}

	// Users endpoints
	if strings.HasPrefix(path, "users") {
		switch method {
		case "POST":
			return PermissionCreateUser
		case "GET":
			if strings.Contains(path, "/") {
				return PermissionReadUser
			}
			return PermissionListUsers
		case "PUT":
			return PermissionUpdateUser
		case "DELETE":
			return PermissionDeleteUser
		}
	}

	// Health and other endpoints don't require specific permissions
	return ""
}
