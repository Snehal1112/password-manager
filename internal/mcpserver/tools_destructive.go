package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type deleteItemArgs struct {
	Type    string `json:"type" jsonschema:"which kind of item to delete: secrets, keys or certificates"`
	Name    string `json:"name" jsonschema:"the item's name, or its id"`
	Confirm string `json:"confirm,omitempty" jsonschema:"repeat the item's name exactly to confirm the deletion"`
	Vault   string `json:"vault,omitempty" jsonschema:"the vault holding the item; defaults to the server's configured vault"`
}

type deleteItemResult struct {
	Vault string `json:"vault"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	// Recoverable states that the item can still be restored, which is the
	// difference between this tool and purge_item.
	Recoverable bool `json:"recoverable"`
}

type purgeItemArgs struct {
	Type    string `json:"type" jsonschema:"which kind of item to purge: secrets, keys or certificates"`
	Name    string `json:"name" jsonschema:"the deleted item's name, or its id; list_deleted shows what can be purged"`
	Confirm string `json:"confirm,omitempty" jsonschema:"repeat the item's name exactly to confirm this permanent deletion"`
	Vault   string `json:"vault,omitempty" jsonschema:"the vault holding the item; defaults to the server's configured vault"`
}

type purgeItemResult struct {
	Vault string `json:"vault"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	// Purged is always true on success, and exists so the result reads as a
	// statement of what happened rather than an empty object.
	Purged bool `json:"purged"`
}

// purgeVaultArgs are the arguments to purge_vault.
//
// Vault is required and has no default. Every other tool falls back to
// mcp.vault when none is given; this one does not, because defaulting the
// target of an irreversible whole-vault deletion to whatever the
// configuration happens to say is exactly the convenience that produces a
// catastrophe.
type purgeVaultArgs struct {
	Vault   string `json:"vault" jsonschema:"the name of the vault to purge; there is no default for this tool"`
	Confirm string `json:"confirm,omitempty" jsonschema:"repeat the vault's name exactly to confirm this permanent deletion"`
}

type purgeVaultResult struct {
	Vault  string `json:"vault"`
	Purged bool   `json:"purged"`
}

// revokeVaultRoleArgs are the arguments to revoke_vault_role.
//
// The target is an assignment id, not a principal. One principal can hold
// several roles in a vault, so a name would not identify which grant to
// remove -- and confirming a name would appear to authorise removing "alice's
// access" while actually removing whichever single grant the id pointed at.
type revokeVaultRoleArgs struct {
	AssignmentID string `json:"assignment_id" jsonschema:"the role assignment's id, from list_role_assignments"`
	Confirm      string `json:"confirm,omitempty" jsonschema:"repeat the assignment id exactly to confirm the revocation"`
	Vault        string `json:"vault,omitempty" jsonschema:"the vault holding the assignment; defaults to the server's configured vault"`
}

type revokeVaultRoleResult struct {
	Vault        string `json:"vault"`
	AssignmentID string `json:"assignment_id"`
	Revoked      bool   `json:"revoked"`
}

// registerDestructiveTools adds the tools that remove things.
//
// delete_item is gated here rather than under writes despite being
// reversible: it removes access to a live secret immediately, which can break
// a running system whatever the retention policy says, and folding deletion
// into allow_write would make that flag a much larger grant than its name
// suggests.
func registerDestructiveTools(s *Server) {
	registerIf(s, TierDestructive, "delete_item",
		"Soft-delete a secret, key or certificate. The item stops working immediately but can be restored with "+
			"recover_deleted until its retention period ends. Requires confirm to repeat the item's name.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: true},
		s.handleDeleteItem)

	registerIf(s, TierDestructive, "purge_item",
		"Permanently destroy a soft-deleted secret, key or certificate. This cannot be undone and the item is not "+
			"recoverable afterwards. Requires confirm to repeat the item's name.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: true},
		s.handlePurgeItem)

	registerIf(s, TierDestructive, "purge_vault",
		"Permanently destroy a soft-deleted vault and everything it contains. This cannot be undone. "+
			"The vault must be named explicitly and confirm must repeat it.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: true},
		s.handlePurgeVault)

	registerIf(s, TierDestructive, "revoke_vault_role",
		"Revoke a role assignment in a vault, removing that principal's access under that role. "+
			"Takes the assignment's id, which list_role_assignments provides -- not a username, since one principal "+
			"can hold several roles. Requires confirm to repeat the assignment id.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: true},
		s.handleRevokeVaultRole)
}

func (s *Server) handleDeleteItem(ctx context.Context, _ *mcp.CallToolRequest, args deleteItemArgs) (*mcp.CallToolResult, deleteItemResult, error) {
	kind, err := parseDeletedKind(args.Type)
	if err != nil {
		return errorResult("%s", err), deleteItemResult{}, nil
	}
	if args.Name == "" {
		return errorResult("delete_item requires a name"), deleteItemResult{}, nil
	}
	if refusal := s.requireConfirmation("delete_item", args.Name, args.Confirm); refusal != nil {
		return refusal, deleteItemResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), deleteItemResult{}, nil
	}

	if err := s.client.DeleteItem(ctx, vault, kind, args.Name); err != nil {
		return errorResult("could not delete %s %q in vault %q: %s",
			args.Type, args.Name, vault, err), deleteItemResult{}, nil
	}

	return nil, deleteItemResult{
		Vault:       vault,
		Type:        args.Type,
		Name:        args.Name,
		Recoverable: true,
	}, nil
}

func (s *Server) handlePurgeItem(ctx context.Context, _ *mcp.CallToolRequest, args purgeItemArgs) (*mcp.CallToolResult, purgeItemResult, error) {
	kind, err := parseDeletedKind(args.Type)
	if err != nil {
		return errorResult("%s", err), purgeItemResult{}, nil
	}
	if args.Name == "" {
		return errorResult("purge_item requires a name"), purgeItemResult{}, nil
	}
	if refusal := s.requireConfirmation("purge_item", args.Name, args.Confirm); refusal != nil {
		return refusal, purgeItemResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), purgeItemResult{}, nil
	}

	if err := s.client.PurgeItem(ctx, vault, kind, args.Name); err != nil {
		return errorResult("could not purge %s %q in vault %q: %s",
			args.Type, args.Name, vault, err), purgeItemResult{}, nil
	}

	return nil, purgeItemResult{Vault: vault, Type: args.Type, Name: args.Name, Purged: true}, nil
}

func (s *Server) handlePurgeVault(ctx context.Context, _ *mcp.CallToolRequest, args purgeVaultArgs) (*mcp.CallToolResult, purgeVaultResult, error) {
	if args.Vault == "" {
		return errorResult(
			"purge_vault requires an explicit vault: this permanently destroys a vault and everything in it, " +
				"so it does not fall back to the configured default"), purgeVaultResult{}, nil
	}
	if refusal := s.requireConfirmation("purge_vault", args.Vault, args.Confirm); refusal != nil {
		return refusal, purgeVaultResult{}, nil
	}

	// The allowlist still applies, so a pinned server cannot reach outside
	// its scope even with a confirmed call.
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), purgeVaultResult{}, nil
	}

	if err := s.client.PurgeVault(ctx, vault); err != nil {
		return errorResult("could not purge vault %q: %s", vault, err), purgeVaultResult{}, nil
	}
	return nil, purgeVaultResult{Vault: vault, Purged: true}, nil
}

func (s *Server) handleRevokeVaultRole(ctx context.Context, _ *mcp.CallToolRequest, args revokeVaultRoleArgs) (*mcp.CallToolResult, revokeVaultRoleResult, error) {
	if args.AssignmentID == "" {
		return errorResult(
			"revoke_vault_role requires an assignment id: use list_role_assignments to find it"), revokeVaultRoleResult{}, nil
	}
	if refusal := s.requireConfirmation("revoke_vault_role", args.AssignmentID, args.Confirm); refusal != nil {
		return refusal, revokeVaultRoleResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), revokeVaultRoleResult{}, nil
	}

	if err := s.client.DeleteRoleAssignment(ctx, vault, args.AssignmentID); err != nil {
		return errorResult("could not revoke assignment %q in vault %q: %s",
			args.AssignmentID, vault, err), revokeVaultRoleResult{}, nil
	}

	return nil, revokeVaultRoleResult{Vault: vault, AssignmentID: args.AssignmentID, Revoked: true}, nil
}
