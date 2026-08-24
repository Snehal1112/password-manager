package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listKeysArgs struct {
	Vault string `json:"vault,omitempty" jsonschema:"the vault to list; defaults to the server's configured vault"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of keys to return; capped by the server"`
}

// keySummaryResult is one key's metadata. No type in this file has a field
// for private material, and none may be added.
type keySummaryResult struct {
	Name      string      `json:"name"`
	ID        string      `json:"id"`
	Type      string      `json:"type"`
	Enabled   bool        `json:"enabled"`
	Revoked   bool        `json:"revoked"`
	Tags      []Untrusted `json:"tags,omitempty"`
	CreatedAt string      `json:"created_at,omitempty"`
	ExpiresAt string      `json:"expires_at,omitempty"`
}

type listKeysResult struct {
	Vault     string             `json:"vault"`
	Keys      []keySummaryResult `json:"keys"`
	Truncated bool               `json:"truncated"`
	Note      string             `json:"note,omitempty"`
}

type getKeyArgs struct {
	Name  string `json:"name" jsonschema:"the key's name, or its id"`
	Vault string `json:"vault,omitempty" jsonschema:"the vault to read from; defaults to the server's configured vault"`
}

type publicJWKResult struct {
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
}

type keyVersionResult struct {
	Version   int             `json:"version"`
	CreatedAt string          `json:"created_at,omitempty"`
	PublicJWK publicJWKResult `json:"public_jwk,omitempty"`
}

type rotationPolicyResult struct {
	RotateAfterDays        int    `json:"rotate_after_days"`
	NotifyBeforeExpiryDays int    `json:"notify_before_expiry_days"`
	ExpiryDays             int    `json:"expiry_days"`
	Enabled                bool   `json:"enabled"`
	NextRotationAt         string `json:"next_rotation_at,omitempty"`
	LastRotatedAt          string `json:"last_rotated_at,omitempty"`
}

type getKeyResult struct {
	Vault   string      `json:"vault"`
	Name    string      `json:"name"`
	ID      string      `json:"id"`
	Type    string      `json:"type"`
	Bits    int         `json:"bits,omitempty"`
	Curve   string      `json:"curve,omitempty"`
	Enabled bool        `json:"enabled"`
	Revoked bool        `json:"revoked"`
	Tags    []Untrusted `json:"tags,omitempty"`

	PublicJWK publicJWKResult `json:"public_jwk,omitempty"`
	// HasPublicComponents is false for an HSM-backed key, whose material
	// never left the token. That is a normal state, not a problem, so it is
	// reported as a fact rather than framed as a warning.
	HasPublicComponents bool `json:"has_public_components"`

	Versions       []keyVersionResult    `json:"versions,omitempty"`
	RotationPolicy *rotationPolicyResult `json:"rotation_policy,omitempty"`

	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// registerKeysReadTools adds the read-tier key tools.
func registerKeysReadTools(s *Server) {
	registerIf(s, TierRead, "list_keys",
		"List the cryptographic keys in a vault. Returns names, types and status; never private key material.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleListKeys)

	registerIf(s, TierRead, "get_key",
		"Get a key's metadata, public JWK components, version history and rotation policy. Never returns private key material.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleGetKey)
}

func (s *Server) handleListKeys(ctx context.Context, _ *mcp.CallToolRequest, args listKeysArgs) (*mcp.CallToolResult, listKeysResult, error) {
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), listKeysResult{}, nil
	}

	limit := s.effectiveLimit(args.Limit)
	summaries, truncated, err := s.client.ListKeys(ctx, vault, limit)
	if err != nil {
		return errorResult("could not list keys in vault %q: %s", vault, err), listKeysResult{}, nil
	}

	keys := make([]keySummaryResult, 0, len(summaries))
	for _, summary := range summaries {
		entry := keySummaryResult{
			Name:      summary.Name,
			ID:        summary.ID.String(),
			Type:      summary.Type,
			Enabled:   summary.Enabled,
			Revoked:   summary.Revoked,
			Tags:      WrapAll(summary.Tags),
			CreatedAt: summary.CreatedAt.Format(time.RFC3339),
		}
		if summary.ExpiresAt != nil {
			entry.ExpiresAt = summary.ExpiresAt.Format(time.RFC3339)
		}
		keys = append(keys, entry)
	}

	return nil, listKeysResult{
		Vault:     vault,
		Keys:      keys,
		Truncated: truncated,
		Note:      truncationNote(truncated, limit),
	}, nil
}

func (s *Server) handleGetKey(ctx context.Context, _ *mcp.CallToolRequest, args getKeyArgs) (*mcp.CallToolResult, getKeyResult, error) {
	if args.Name == "" {
		return errorResult("get_key requires a name"), getKeyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), getKeyResult{}, nil
	}

	key, err := s.client.GetKey(ctx, vault, args.Name)
	if err != nil {
		return errorResult("could not get key %q in vault %q: %s", args.Name, vault, err), getKeyResult{}, nil
	}

	result := getKeyResult{
		Vault:               vault,
		Name:                key.Name,
		ID:                  key.ID.String(),
		Type:                key.Type,
		Bits:                key.Bits,
		Curve:               key.Curve,
		Enabled:             key.Enabled,
		Revoked:             key.Revoked,
		Tags:                WrapAll(key.Tags),
		PublicJWK:           publicJWKResult(key.PublicJWK),
		HasPublicComponents: !key.PublicJWK.IsEmpty(),
		CreatedAt:           key.CreatedAt.Format(time.RFC3339),
	}
	if key.ExpiresAt != nil {
		result.ExpiresAt = key.ExpiresAt.Format(time.RFC3339)
	}

	// Versions and the rotation policy are supplementary: failing to fetch
	// either must not lose the key's metadata.
	if versions, err := s.client.GetKeyVersions(ctx, vault, args.Name); err == nil {
		for _, version := range versions {
			result.Versions = append(result.Versions, keyVersionResult{
				Version:   version.Version,
				CreatedAt: version.CreatedAt.Format(time.RFC3339),
				PublicJWK: publicJWKResult(version.PublicJWK),
			})
		}
	}
	if policy, err := s.client.GetKeyRotationPolicy(ctx, vault, args.Name); err == nil && policy != nil {
		converted := rotationPolicyResult{
			RotateAfterDays:        policy.RotateAfterDays,
			NotifyBeforeExpiryDays: policy.NotifyBeforeExpiryDays,
			ExpiryDays:             policy.ExpiryDays,
			Enabled:                policy.Enabled,
			NextRotationAt:         policy.NextRotationAt.Format(time.RFC3339),
		}
		if policy.LastRotatedAt != nil {
			converted.LastRotatedAt = policy.LastRotatedAt.Format(time.RFC3339)
		}
		result.RotationPolicy = &converted
	}

	return nil, result, nil
}
