package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// listSecretsArgs are the arguments to list_secrets.
type listSecretsArgs struct {
	Vault string `json:"vault,omitempty" jsonschema:"the vault to list; defaults to the server's configured vault"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of secrets to return; capped by the server"`
}

// secretSummaryResult is one secret's metadata. It has no value field: the
// list route returns none, and this type could not carry one if it did.
type secretSummaryResult struct {
	Name      string      `json:"name"`
	ID        string      `json:"id"`
	Version   int         `json:"version"`
	Tags      []Untrusted `json:"tags,omitempty"`
	CreatedAt string      `json:"created_at,omitempty"`
}

// listSecretsResult is what list_secrets returns.
type listSecretsResult struct {
	Vault     string                `json:"vault"`
	Secrets   []secretSummaryResult `json:"secrets"`
	Truncated bool                  `json:"truncated"`
	Note      string                `json:"note,omitempty"`
}

// effectiveLimit reconciles a requested limit with the configured cap.
//
// A model that asks for more than the cap gets the cap. Silently returning
// fewer results than requested without saying so is what makes a partial view
// look complete.
func (s *Server) effectiveLimit(requested int) int {
	if requested <= 0 || requested > s.cfg.MaxResults {
		return s.cfg.MaxResults
	}
	return requested
}

// truncationNote explains a cut-short list, or returns "" when complete.
func truncationNote(truncated bool, limit int) string {
	if !truncated {
		return ""
	}
	return fmt.Sprintf("Results were truncated to %d entries. Narrow the query or raise mcp.max_results to see more.", limit)
}

// registerSecretsReadTools adds the read-tier secret tools.
func registerSecretsReadTools(s *Server) {
	registerIf(s, TierRead, "list_secrets",
		"List the secrets in a vault. Returns names, versions and tags only, never secret values.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleListSecrets)
}

// handleListSecrets implements list_secrets.
func (s *Server) handleListSecrets(ctx context.Context, _ *mcp.CallToolRequest, args listSecretsArgs) (*mcp.CallToolResult, listSecretsResult, error) {
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), listSecretsResult{}, nil
	}

	limit := s.effectiveLimit(args.Limit)
	summaries, truncated, err := s.client.ListSecrets(ctx, vault, limit)
	if err != nil {
		return errorResult("could not list secrets in vault %q: %s", vault, err), listSecretsResult{}, nil
	}

	secrets := make([]secretSummaryResult, 0, len(summaries))
	for _, summary := range summaries {
		secrets = append(secrets, secretSummaryResult{
			Name:      summary.Name,
			ID:        summary.ID.String(),
			Version:   summary.Version,
			Tags:      WrapAll(summary.Tags),
			CreatedAt: summary.CreatedAt,
		})
	}

	return nil, listSecretsResult{
		Vault:     vault,
		Secrets:   secrets,
		Truncated: truncated,
		Note:      truncationNote(truncated, limit),
	}, nil
}
