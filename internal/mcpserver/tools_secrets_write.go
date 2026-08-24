package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

// setSecretArgs are the arguments to set_secret.
//
// Value is present regardless of allow_secret_values. That flag governs
// whether the server will show an existing secret to the model; it has
// nothing to do with whether the model may supply one. Conflating them would
// leave an operator who enabled writing but not disclosure unable to write.
type setSecretArgs struct {
	Name        string   `json:"name" jsonschema:"the secret's name"`
	Value       string   `json:"value" jsonschema:"the secret value to store"`
	Vault       string   `json:"vault,omitempty" jsonschema:"the vault to write to; defaults to the server's configured vault"`
	Tags        []string `json:"tags,omitempty" jsonschema:"tags to attach to the secret"`
	ContentType string   `json:"content_type,omitempty" jsonschema:"a MIME type describing the value, such as text/plain"`
	ExpiresAt   string   `json:"expires_at,omitempty" jsonschema:"expiry as an RFC3339 timestamp, such as 2027-01-01T00:00:00Z"`
	Enabled     *bool    `json:"enabled,omitempty" jsonschema:"whether the secret is usable"`
}

// setSecretResult reports what happened.
//
// It deliberately does not echo the value: the caller supplied it, so
// returning it would put a plaintext secret in the transcript for no reason.
type setSecretResult struct {
	Vault   string `json:"vault"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Version int    `json:"version"`
	// Created distinguishes a new secret from a new version of an existing
	// one, which the caller usually cannot tell in advance.
	Created bool `json:"created"`
}

// registerSecretsWriteTools adds the write-tier secret tools.
func registerSecretsWriteTools(s *Server) {
	registerIf(s, TierWrite, "set_secret",
		"Create a secret, or store a new version of an existing one. "+
			"Returns metadata only; the value is never echoed back.",
		// Not idempotent: calling this twice stores two versions, so a host
		// must not treat a retry as free.
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleSetSecret)
}

// parseOptionalTime parses an RFC3339 timestamp, treating "" as unset.
func parseOptionalTime(field, value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be an RFC3339 timestamp such as 2027-01-01T00:00:00Z, got %q", field, value)
	}
	return &parsed, nil
}

func (s *Server) handleSetSecret(ctx context.Context, _ *mcp.CallToolRequest, args setSecretArgs) (*mcp.CallToolResult, setSecretResult, error) {
	if args.Name == "" {
		return errorResult("set_secret requires a name"), setSecretResult{}, nil
	}
	if args.Value == "" {
		return errorResult("set_secret requires a value"), setSecretResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), setSecretResult{}, nil
	}

	expiresAt, err := parseOptionalTime("expires_at", args.ExpiresAt)
	if err != nil {
		return errorResult("%s", err), setSecretResult{}, nil
	}

	secret, created, err := s.client.SetSecret(ctx, vault, vaultapi.SetSecretRequest{
		Name:        args.Name,
		Value:       vaultapi.SecretValue(args.Value),
		Tags:        args.Tags,
		ContentType: args.ContentType,
		Enabled:     args.Enabled,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		return errorResult("could not set secret %q in vault %q: %s", args.Name, vault, err), setSecretResult{}, nil
	}

	return nil, setSecretResult{
		Vault:   vault,
		Name:    secret.Name,
		ID:      secret.ID.String(),
		Version: secret.Version,
		Created: created,
	}, nil
}
