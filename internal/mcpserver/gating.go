package mcpserver

import (
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tier is a capability group that config enables as a unit.
type Tier int

const (
	// TierRead is always enabled. It is still named explicitly at every
	// registration site, so a tool can never land in a default tier by
	// omission.
	TierRead Tier = iota
	TierWrite
	TierDestructive
	TierCrypto
)

// String names the tier, for diagnostics and --check output.
func (t Tier) String() string {
	switch t {
	case TierWrite:
		return "write"
	case TierDestructive:
		return "destructive"
	case TierCrypto:
		return "crypto"
	default:
		return "read"
	}
}

// TierEnabled reports whether the configuration enables tier.
func (s *Server) TierEnabled(t Tier) bool {
	switch t {
	case TierWrite:
		return s.cfg.AllowWrite
	case TierDestructive:
		return s.cfg.AllowDestructive
	case TierCrypto:
		return s.cfg.AllowCrypto
	default:
		return true
	}
}

// registerIf adds a tool only when its tier is enabled.
//
// Gating happens here, at registration, rather than inside the handler. A
// disabled tool is therefore absent from tools/list entirely: it costs the
// host no context and cannot be invoked at all, which is a stronger property
// than a tool that exists and refuses.
func registerIf[In, Out any](s *Server, tier Tier, name, description string, ann Annotations, h mcp.ToolHandlerFor[In, Out]) {
	if !s.TierEnabled(tier) {
		return
	}
	register(s, tier, name, description, ann, h)
}

// ResolveVault decides which vault a call targets.
//
// Precedence is the explicit request, then the configured default. When
// allowed_vaults is set, anything outside it is refused here, before any
// request leaves the process — the guard bounds blast radius regardless of
// what the principal's role assignments would otherwise permit.
func (s *Server) ResolveVault(requested string) (string, error) {
	vault := strings.TrimSpace(requested)
	if vault == "" {
		vault = s.cfg.Vault
	}
	if vault == "" {
		return "", fmt.Errorf("no vault was given and no default is configured")
	}

	if len(s.cfg.AllowedVaults) == 0 {
		// Deferring to RBAC is deliberate: it already bounds what the
		// principal can reach.
		return vault, nil
	}
	for _, allowed := range s.cfg.AllowedVaults {
		if allowed == vault {
			return vault, nil
		}
	}
	// Naming the permitted set lets the model correct itself rather than
	// guess at another name.
	return "", fmt.Errorf("vault %q is not permitted by this server; permitted vaults are: %s",
		vault, strings.Join(s.cfg.AllowedVaults, ", "))
}
