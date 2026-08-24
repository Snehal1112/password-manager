package vaultapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// RoleAssignment is one principal's Azure-parity role grant within a vault.
//
// Timestamps and identifiers stay as the response renders them
// (model/role_assignment.go:36), which is as strings.
type RoleAssignment struct {
	ID                uuid.UUID `json:"id"`
	PrincipalID       uuid.UUID `json:"principal_id"`
	PrincipalUsername string    `json:"principal_username,omitempty"`
	PrincipalType     string    `json:"principal_type"`
	Role              string    `json:"role"`
	VaultName         string    `json:"vault_name,omitempty"`
	CreatedAt         string    `json:"created_at,omitempty"`
}

type roleAssignmentWire struct {
	ID                string `json:"id"`
	PrincipalID       string `json:"principal_id"`
	PrincipalUsername string `json:"principal_username"`
	PrincipalType     string `json:"principal_type"`
	Role              string `json:"role"`
	VaultName         string `json:"vault_name"`
	CreatedAt         string `json:"created_at"`
}

type roleAssignmentsListResponse struct {
	RoleAssignments []roleAssignmentWire `json:"role_assignments"`
	Total           int                  `json:"total"`
}

func (w roleAssignmentWire) toAssignment() RoleAssignment {
	assignment := RoleAssignment{
		PrincipalUsername: w.PrincipalUsername,
		PrincipalType:     w.PrincipalType,
		Role:              w.Role,
		VaultName:         w.VaultName,
		CreatedAt:         w.CreatedAt,
	}
	// An unparseable identifier leaves the zero UUID rather than failing the
	// whole listing: the role and principal name are the useful parts.
	if id, err := uuid.Parse(w.ID); err == nil {
		assignment.ID = id
	}
	if principalID, err := uuid.Parse(w.PrincipalID); err == nil {
		assignment.PrincipalID = principalID
	}
	return assignment
}

// ListRoleAssignments returns the role grants in vault, capped at limit. The
// bool reports truncation.
//
// This route requires admin, vaults/manage, or Key Vault Data Access
// Administrator (api/role_assignments.go:139). The last is grantable per
// vault, so a least-privileged service account can hold it.
func (c *Client) ListRoleAssignments(ctx context.Context, vault string, limit int) ([]RoleAssignment, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to list role assignments")
	}

	var response roleAssignmentsListResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/role-assignments", vault)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	truncated := limit > 0 && len(response.RoleAssignments) > limit
	wires := response.RoleAssignments
	if truncated {
		wires = wires[:limit]
	}

	assignments := make([]RoleAssignment, 0, len(wires))
	for _, wire := range wires {
		assignments = append(assignments, wire.toAssignment())
	}
	return assignments, truncated, nil
}
