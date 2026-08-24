package mcpserver

import (
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// requireConfirmation checks that a destructive call echoed its target's
// name. It returns nil when the call may proceed, and a refusal otherwise.
//
// This is not a security boundary and should not be described as one. Text
// injected into a vault could name a specific resource and supply a matching
// confirmation, and nothing here would stop it.
//
// What it does stop is the likelier case: a drive-by destructive call made
// from a partially-formed intention. Requiring a second argument that
// restates the target means the call cannot be made by accident, the host's
// confirmation prompt shows the operator the name twice, and an injected
// instruction has to be specific enough to name the exact resource -- a
// meaningfully higher bar than "purge the vault".
//
// It returns a result rather than an error because every caller would
// otherwise convert one into the other, and that is a conversion each tool
// could get wrong.
func (s *Server) requireConfirmation(toolName, resource, confirm string) *mcp.CallToolResult {
	if !s.cfg.ConfirmDestructive {
		return nil
	}

	// Trimming is safe: leading whitespace is a transport artifact, not a
	// different name. Case is not, since names are case-sensitive
	// identifiers and accepting a different case would confirm a name that
	// does not exist.
	if strings.TrimSpace(confirm) == resource {
		return nil
	}

	if strings.TrimSpace(confirm) == "" {
		return errorResult(
			"%s is destructive and requires confirmation: pass confirm=%q to proceed",
			toolName, resource)
	}
	return errorResult(
		"%s was not confirmed: the target is %q but confirm was %q. "+
			"Pass confirm=%q to proceed, or check the target is right.",
		toolName, resource, strings.TrimSpace(confirm), resource)
}
