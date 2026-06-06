package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// RoleAssignment records that a principal holds a built-in role within a vault.
type RoleAssignment struct {
	ID            uuid.UUID     `json:"id"`
	PrincipalID   uuid.UUID     `json:"principal_id"`
	PrincipalType PrincipalType `json:"principal_type"`
	Role          string        `json:"role"`
	VaultID       uuid.UUID     `json:"vault_id"`
	CreatedBy     uuid.UUID     `json:"created_by"`
	CreatedAt     time.Time     `json:"created_at"`
}

// AssignRoleRequest is the body for granting a role in a vault.
// Principal accepts either a username or a UUID; the server resolves it.
type AssignRoleRequest struct {
	Principal     string `json:"principal"`
	PrincipalType string `json:"principal_type,omitempty"`
	Role          string `json:"role"`
}

func AssignRoleRequestFromJson(data io.Reader) (*AssignRoleRequest, error) {
	var r AssignRoleRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

// RoleAssignmentResponse is the API representation of an assignment.
type RoleAssignmentResponse struct {
	ID                  string `json:"id"`
	PrincipalID         string `json:"principal_id"`
	PrincipalUsername   string `json:"principal_username,omitempty"`
	PrincipalType       string `json:"principal_type"`
	Role                string `json:"role"`
	VaultID             string `json:"vault_id"`
	VaultName           string `json:"vault_name,omitempty"`
	CreatedAt           string `json:"created_at"`
	ExpandedPolicyCount int    `json:"expanded_policy_count,omitempty"`
}

func (r *RoleAssignmentResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListRoleAssignmentsResponse struct {
	RoleAssignments []RoleAssignmentResponse `json:"role_assignments"`
	Total           int                      `json:"total"`
}

func (r *ListRoleAssignmentsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
