package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"rocketvault/internal/vaultapi"
)

type createVaultArgs struct {
	Name            string            `json:"name" jsonschema:"the new vault's name; lowercase letters, digits and hyphens"`
	Enabled         *bool             `json:"enabled,omitempty" jsonschema:"whether the vault is usable immediately"`
	PurgeProtection *bool             `json:"purge_protection,omitempty" jsonschema:"prevent permanent deletion of items before their retention period ends"`
	RetentionDays   *int              `json:"retention_days,omitempty" jsonschema:"how long soft-deleted items remain recoverable"`
	Tags            map[string]string `json:"tags,omitempty" jsonschema:"tags to attach to the vault"`
}

type createVaultResult struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	Enabled         bool   `json:"enabled"`
	PurgeProtection bool   `json:"purge_protection"`
	RetentionDays   int    `json:"retention_days"`
}

// registerVaultsWriteTools adds the write-tier vault tools.
func registerVaultsWriteTools(s *Server) {
	registerIf(s, TierWrite, "create_vault",
		"Create a new vault. Each vault is an isolated boundary with its own secrets, keys, certificates and role assignments.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleCreateVault)
}

func (s *Server) handleCreateVault(ctx context.Context, _ *mcp.CallToolRequest, args createVaultArgs) (*mcp.CallToolResult, createVaultResult, error) {
	if args.Name == "" {
		return errorResult("create_vault requires a name"), createVaultResult{}, nil
	}

	// This tool creates a vault, so there is nothing to resolve -- but the
	// allowlist still applies. Creating a vault this server would then be
	// forbidden to touch is a strange thing to permit, and refusing now is
	// cheaper than explaining afterwards.
	if !s.vaultPermitted(args.Name) {
		return errorResult(
			"this server is not permitted to operate on a vault named %q, so creating it would leave it unusable here",
			args.Name), createVaultResult{}, nil
	}

	vault, err := s.client.CreateVault(ctx, vaultapi.CreateVaultRequest{
		Name:            args.Name,
		Enabled:         args.Enabled,
		PurgeProtection: args.PurgeProtection,
		RetentionDays:   args.RetentionDays,
		Tags:            args.Tags,
	})
	if err != nil {
		return errorResult("could not create vault %q: %s", args.Name, err), createVaultResult{}, nil
	}

	return nil, createVaultResult{
		Name:            vault.Name,
		ID:              vault.ID.String(),
		Enabled:         vault.Enabled,
		PurgeProtection: vault.PurgeProtection,
		RetentionDays:   vault.RetentionDays,
	}, nil
}
