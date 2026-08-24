package mcpserver

import (
	"context"
	"fmt"
	"time"

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

	// The two variants advertise different schemas. With disclosure off,
	// include_value is not a property the model can name.
	if s.MayDiscloseValues() {
		registerIf(s, TierRead, "get_secret",
			"Get a secret's metadata, tags, expiry and version history. Pass include_value to also return its plaintext value.",
			Annotations{ReadOnly: true, Idempotent: true}, s.handleGetSecretWithValue)
	} else {
		registerIf(s, TierRead, "get_secret",
			"Get a secret's metadata, tags, expiry and version history. Does not return the secret value.",
			Annotations{ReadOnly: true, Idempotent: true}, s.handleGetSecret)
	}
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

// getSecretArgs are the arguments to get_secret when values are withheld.
type getSecretArgs struct {
	Name  string `json:"name" jsonschema:"the secret's name, or its id"`
	Vault string `json:"vault,omitempty" jsonschema:"the vault to read from; defaults to the server's configured vault"`
}

// secretVersionResult is one entry of a secret's version history.
type secretVersionResult struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at,omitempty"`
	Enabled   bool   `json:"enabled"`
}

// getSecretResult is what get_secret returns, under either registration.
type getSecretResult struct {
	Vault       string                `json:"vault"`
	Name        string                `json:"name"`
	ID          string                `json:"id"`
	Version     int                   `json:"version"`
	Tags        []Untrusted           `json:"tags,omitempty"`
	ContentType string                `json:"content_type,omitempty"`
	Enabled     bool                  `json:"enabled"`
	ExpiresAt   string                `json:"expires_at,omitempty"`
	NotBefore   string                `json:"not_before,omitempty"`
	Versions    []secretVersionResult `json:"versions,omitempty"`

	// Value is present only when the server discloses values.
	Value string `json:"value,omitempty"`
	// ValueDisclosed says whether Value holds the real plaintext, so a
	// placeholder is never mistaken for the value itself.
	ValueDisclosed bool `json:"value_disclosed"`
}

// fetchSecret gathers a secret's metadata and version history.
//
// Version history is supplementary: if that call fails, the metadata is still
// worth returning rather than failing the whole tool.
func (s *Server) fetchSecret(ctx context.Context, vault, name string) (getSecretResult, *mcp.CallToolResult) {
	secret, err := s.client.GetSecret(ctx, vault, name)
	if err != nil {
		return getSecretResult{}, errorResult("could not get secret %q in vault %q: %s", name, vault, err)
	}

	result := getSecretResult{
		Vault:       vault,
		Name:        secret.Name,
		ID:          secret.ID.String(),
		Version:     secret.Version,
		Tags:        WrapAll(secret.Tags),
		ContentType: secret.ContentType,
		Enabled:     secret.Enabled,
	}
	if secret.ExpiresAt != nil {
		result.ExpiresAt = secret.ExpiresAt.Format(time.RFC3339)
	}
	if secret.NotBefore != nil {
		result.NotBefore = secret.NotBefore.Format(time.RFC3339)
	}

	if versions, err := s.client.GetSecretVersions(ctx, vault, name); err == nil {
		for _, version := range versions {
			result.Versions = append(result.Versions, secretVersionResult{
				Version:   version.Version,
				CreatedAt: version.CreatedAt,
				Enabled:   version.Enabled,
			})
		}
	}
	return result, nil
}

// handleGetSecret implements get_secret when values are withheld.
func (s *Server) handleGetSecret(ctx context.Context, _ *mcp.CallToolRequest, args getSecretArgs) (*mcp.CallToolResult, getSecretResult, error) {
	if args.Name == "" {
		return errorResult("get_secret requires a name"), getSecretResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), getSecretResult{}, nil
	}

	result, failure := s.fetchSecret(ctx, vault, args.Name)
	if failure != nil {
		return failure, getSecretResult{}, nil
	}
	// The value is deliberately never populated here.
	return nil, result, nil
}

// getSecretArgsWithValue are get_secret's arguments when the server is
// configured to disclose values.
//
// This is a separate type rather than a flag on getSecretArgs because
// mcp.AddTool infers the input schema from the argument type. Registering
// this type means include_value is a property the model can see and name;
// registering the other means no such property exists at all. That is
// stronger than accepting the argument and refusing it — there is nothing to
// refuse, and nothing for injected text to ask for.
type getSecretArgsWithValue struct {
	Name         string `json:"name" jsonschema:"the secret's name, or its id"`
	Vault        string `json:"vault,omitempty" jsonschema:"the vault to read from; defaults to the server's configured vault"`
	IncludeValue bool   `json:"include_value,omitempty" jsonschema:"set true to return the secret's plaintext value"`
}

// handleGetSecretWithValue implements get_secret when disclosure is enabled.
func (s *Server) handleGetSecretWithValue(ctx context.Context, _ *mcp.CallToolRequest, args getSecretArgsWithValue) (*mcp.CallToolResult, getSecretResult, error) {
	if args.Name == "" {
		return errorResult("get_secret requires a name"), getSecretResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), getSecretResult{}, nil
	}

	result, failure := s.fetchSecret(ctx, vault, args.Name)
	if failure != nil {
		return failure, getSecretResult{}, nil
	}

	// Permitting disclosure is not the same as disclosing by default: the
	// caller still has to ask.
	if args.IncludeValue {
		secret, err := s.client.GetSecret(ctx, vault, args.Name)
		if err != nil {
			return errorResult("could not read the value of %q in vault %q: %s", args.Name, vault, err), getSecretResult{}, nil
		}
		value, disclosed := s.discloseValue(secret.Value)
		result.Value, result.ValueDisclosed = value, disclosed
	}
	return nil, result, nil
}
