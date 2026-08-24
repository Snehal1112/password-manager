package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type grantVaultRoleArgs struct {
	Principal     string `json:"principal" jsonschema:"the username or id of the user or service account to grant to"`
	Role          string `json:"role" jsonschema:"a built-in role name, such as Key Vault Secrets User; list_role_assignments shows roles already in use"`
	PrincipalType string `json:"principal_type,omitempty" jsonschema:"user or service_account; defaults to user"`
	Vault         string `json:"vault,omitempty" jsonschema:"the vault to grant in; defaults to the server's configured vault"`
}

// grantVaultRoleResult restates the grant.
//
// It repeats the role and principal deliberately: a grant changes who can
// reach the vault, and an operator reading the transcript should be able to
// see exactly what was given to whom without re-reading the request.
type grantVaultRoleResult struct {
	Vault             string    `json:"vault"`
	AssignmentID      string    `json:"assignment_id"`
	Role              string    `json:"role"`
	PrincipalID       string    `json:"principal_id,omitempty"`
	PrincipalUsername Untrusted `json:"principal_username,omitempty"`
	PrincipalType     string    `json:"principal_type,omitempty"`
}

// registerAccessWriteTools adds the write-tier access tools.
//
// Granting is a write rather than a destructive operation: it adds access and
// removes nothing. Revoking is its destructive counterpart and lives in the
// destructive tier.
func registerAccessWriteTools(s *Server) {
	registerIf(s, TierWrite, "grant_vault_role",
		"Grant a built-in role to a user or service account in a vault. "+
			"Requires admin, vaults/manage, or the Key Vault Data Access Administrator role in that vault.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleGrantVaultRole)
}

func (s *Server) handleGrantVaultRole(ctx context.Context, _ *mcp.CallToolRequest, args grantVaultRoleArgs) (*mcp.CallToolResult, grantVaultRoleResult, error) {
	if args.Principal == "" {
		return errorResult("grant_vault_role requires a principal"), grantVaultRoleResult{}, nil
	}
	if args.Role == "" {
		return errorResult("grant_vault_role requires a role"), grantVaultRoleResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), grantVaultRoleResult{}, nil
	}

	assignment, err := s.client.CreateRoleAssignment(ctx, vault, vaultapi.GrantRoleRequest{
		Principal:     args.Principal,
		PrincipalType: args.PrincipalType,
		Role:          args.Role,
	})
	if err != nil {
		return errorResult("could not grant %q to %q in vault %q: %s",
			args.Role, args.Principal, vault, err), grantVaultRoleResult{}, nil
	}

	return nil, grantVaultRoleResult{
		Vault:             vault,
		AssignmentID:      assignment.ID.String(),
		Role:              assignment.Role,
		PrincipalID:       assignment.PrincipalID.String(),
		PrincipalUsername: Wrap(assignment.PrincipalUsername),
		PrincipalType:     assignment.PrincipalType,
	}, nil
}
