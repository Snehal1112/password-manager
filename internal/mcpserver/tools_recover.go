package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type recoverDeletedArgs struct {
	Type  string `json:"type" jsonschema:"which kind of item to recover: secrets, keys or certificates"`
	Name  string `json:"name" jsonschema:"the deleted item's name, or its id; list_deleted shows what is recoverable"`
	Vault string `json:"vault,omitempty" jsonschema:"the vault holding the item; defaults to the server's configured vault"`
}

type recoverDeletedResult struct {
	Vault string `json:"vault"`
	Type  string `json:"type"`
	Name  string `json:"name"`
}

// registerRecoverTools adds recovery, which is a write rather than a
// destructive operation.
//
// Recovery restores something that was deleted. Gating it behind
// allow_destructive would produce an obviously wrong configuration, where an
// operator who enabled writing could not undo a deletion someone else made.
// Recovery is additive, so it belongs with the additive tier.
func registerRecoverTools(s *Server) {
	registerIf(s, TierWrite, "recover_deleted",
		"Restore a soft-deleted secret, key or certificate. Use list_deleted to see what can be recovered.",
		// Not destructive: it restores rather than removes. Idempotent:
		// recovering an already-recovered item leaves the same state.
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleRecoverDeleted)
}

func (s *Server) handleRecoverDeleted(ctx context.Context, _ *mcp.CallToolRequest, args recoverDeletedArgs) (*mcp.CallToolResult, recoverDeletedResult, error) {
	kind, err := parseDeletedKind(args.Type)
	if err != nil {
		return errorResult("%s", err), recoverDeletedResult{}, nil
	}
	if args.Name == "" {
		return errorResult("recover_deleted requires a name"), recoverDeletedResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), recoverDeletedResult{}, nil
	}

	// No confirmation: recovery undoes damage, and friction here is
	// unhelpful.
	if err := s.client.RecoverDeleted(ctx, vault, kind, args.Name); err != nil {
		return errorResult("could not recover %s %q in vault %q: %s",
			args.Type, args.Name, vault, err), recoverDeletedResult{}, nil
	}

	return nil, recoverDeletedResult{Vault: vault, Type: args.Type, Name: args.Name}, nil
}
