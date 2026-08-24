package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// listVaultsArgs are the arguments to list_vaults.
//
// There is deliberately no vault field: this tool lists vaults, so scoping it
// to one would be nonsense. It is the only read tool for which that is true.
type listVaultsArgs struct {
	IncludeDeleted bool `json:"include_deleted,omitempty" jsonschema:"include soft-deleted vaults, which can be recovered or purged"`
	Limit          int  `json:"limit,omitempty" jsonschema:"maximum number of vaults to return; capped by the server"`
}

type vaultResult struct {
	Name             string               `json:"name"`
	ID               string               `json:"id"`
	Enabled          bool                 `json:"enabled"`
	PurgeProtection  bool                 `json:"purge_protection"`
	RetentionDays    int                  `json:"retention_days"`
	Tags             map[string]Untrusted `json:"tags,omitempty"`
	CreatedAt        string               `json:"created_at,omitempty"`
	DeletedAt        string               `json:"deleted_at,omitempty"`
	ScheduledPurgeAt string               `json:"scheduled_purge_at,omitempty"`
}

type listVaultsResult struct {
	Vaults    []vaultResult `json:"vaults"`
	Truncated bool          `json:"truncated"`
	// FilteredOut counts vaults removed by mcp.allowed_vaults, so the caller
	// can tell "no others exist" from "this server will not show them".
	FilteredOut int    `json:"filtered_out,omitempty"`
	Note        string `json:"note,omitempty"`
}

// registerVaultsReadTools adds the read-tier vault tools.
func registerVaultsReadTools(s *Server) {
	registerIf(s, TierRead, "list_vaults",
		"List the vaults on this server, with their retention and purge-protection settings.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleListVaults)
}

// vaultPermitted reports whether name survives the allowlist.
func (s *Server) vaultPermitted(name string) bool {
	if len(s.cfg.AllowedVaults) == 0 {
		return true
	}
	for _, allowed := range s.cfg.AllowedVaults {
		if allowed == name {
			return true
		}
	}
	return false
}

func (s *Server) handleListVaults(ctx context.Context, _ *mcp.CallToolRequest, args listVaultsArgs) (*mcp.CallToolResult, listVaultsResult, error) {
	limit := s.effectiveLimit(args.Limit)

	// The limit is applied after filtering, so the allowlist does not eat
	// into the caller's budget. Fetch unbounded and cap below.
	vaults, _, err := s.client.ListVaults(ctx, args.IncludeDeleted, 0)
	if err != nil {
		return errorResult("could not list vaults: %s", err), listVaultsResult{}, nil
	}

	// Vaults outside the allowlist are removed rather than shown. Presenting
	// a vault the server will refuse to touch invites the model to try it,
	// which costs a turn and produces a confusing error.
	permitted := make([]vaultResult, 0, len(vaults))
	filteredOut := 0
	for _, vault := range vaults {
		if !s.vaultPermitted(vault.Name) {
			filteredOut++
			continue
		}
		entry := vaultResult{
			Name:             vault.Name,
			ID:               vault.ID.String(),
			Enabled:          vault.Enabled,
			PurgeProtection:  vault.PurgeProtection,
			RetentionDays:    vault.RetentionDays,
			CreatedAt:        vault.CreatedAt,
			DeletedAt:        vault.DeletedAt,
			ScheduledPurgeAt: vault.ScheduledPurgeAt,
		}
		if len(vault.Tags) > 0 {
			entry.Tags = make(map[string]Untrusted, len(vault.Tags))
			for key, value := range vault.Tags {
				entry.Tags[key] = Wrap(value)
			}
		}
		permitted = append(permitted, entry)
	}

	truncated := len(permitted) > limit
	if truncated {
		permitted = permitted[:limit]
	}

	return nil, listVaultsResult{
		Vaults:      permitted,
		Truncated:   truncated,
		FilteredOut: filteredOut,
		Note:        truncationNote(truncated, limit),
	}, nil
}
