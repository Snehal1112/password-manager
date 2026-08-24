package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listRoleAssignmentsArgs struct {
	Vault string `json:"vault,omitempty" jsonschema:"the vault whose grants to list; defaults to the server's configured vault"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of assignments to return; capped by the server"`
}

// roleAssignmentResult is one principal's grant in a vault.
//
// PrincipalUsername is wrapped because it is chosen at account creation and
// is therefore user-controlled. Role is not: role names come from the fixed
// set in model/azure_roles.go.
type roleAssignmentResult struct {
	ID                string    `json:"id"`
	PrincipalID       string    `json:"principal_id"`
	PrincipalUsername Untrusted `json:"principal_username,omitempty"`
	PrincipalType     string    `json:"principal_type"`
	Role              string    `json:"role"`
	CreatedAt         string    `json:"created_at,omitempty"`
}

type listRoleAssignmentsResult struct {
	Vault       string                 `json:"vault"`
	Assignments []roleAssignmentResult `json:"assignments"`
	Truncated   bool                   `json:"truncated"`
	Note        string                 `json:"note,omitempty"`
}

// registerAccessReadTools adds the read-tier access tools.
func registerAccessReadTools(s *Server) {
	registerIf(s, TierRead, "list_role_assignments",
		"List who holds which Azure-parity role in a vault. Requires admin, vaults/manage, or the Key Vault Data Access Administrator role in that vault.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleListRoleAssignments)
}

func (s *Server) handleListRoleAssignments(ctx context.Context, _ *mcp.CallToolRequest, args listRoleAssignmentsArgs) (*mcp.CallToolResult, listRoleAssignmentsResult, error) {
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), listRoleAssignmentsResult{}, nil
	}

	limit := s.effectiveLimit(args.Limit)
	assignments, truncated, err := s.client.ListRoleAssignments(ctx, vault, limit)
	if err != nil {
		return errorResult("could not list role assignments in vault %q: %s", vault, err), listRoleAssignmentsResult{}, nil
	}

	results := make([]roleAssignmentResult, 0, len(assignments))
	for _, assignment := range assignments {
		results = append(results, roleAssignmentResult{
			ID:                assignment.ID.String(),
			PrincipalID:       assignment.PrincipalID.String(),
			PrincipalUsername: Wrap(assignment.PrincipalUsername),
			PrincipalType:     assignment.PrincipalType,
			Role:              assignment.Role,
			CreatedAt:         assignment.CreatedAt,
		})
	}

	return nil, listRoleAssignmentsResult{
		Vault:       vault,
		Assignments: results,
		Truncated:   truncated,
		Note:        truncationNote(truncated, limit),
	}, nil
}
