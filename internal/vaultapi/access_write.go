package vaultapi

import (
	"context"
	"fmt"
	"net/http"
)

// GrantRoleRequest describes a role grant to create.
//
// Principal is sent verbatim -- a username or a UUID -- because the server
// resolves it (api/role_assignments.go), and duplicating that resolution
// client-side would just be a second place for it to drift or disagree.
type GrantRoleRequest struct {
	Principal     string `json:"principal"`
	PrincipalType string `json:"principal_type,omitempty"`
	Role          string `json:"role"`
}

// CreateRoleAssignment grants a role to a principal within vault.
//
// The role name is not validated client-side. The server owns the list of
// built-in and future roles, and a client-side copy would drift the moment
// one is added.
func (c *Client) CreateRoleAssignment(ctx context.Context, vault string, req GrantRoleRequest) (*RoleAssignment, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to grant a role")
	}
	if req.Principal == "" {
		return nil, fmt.Errorf("vaultapi: principal is required to grant a role")
	}
	if req.Role == "" {
		return nil, fmt.Errorf("vaultapi: role is required to grant a role")
	}

	var wire roleAssignmentWire
	path := fmt.Sprintf("/api/v1/vaults/%s/role-assignments", vault)
	if err := c.Do(ctx, http.MethodPost, path, req, &wire); err != nil {
		return nil, err
	}

	assignment := wire.toAssignment()
	return &assignment, nil
}
