package mcpserver

import "rocketvault/internal/vaultapi"

// RedactedPlaceholder is what a withheld secret value renders as. It matches
// vaultapi.SecretValue's own placeholder, so output does not vary by which
// layer did the redacting.
const RedactedPlaceholder = "[REDACTED]"

// MayDiscloseValues reports whether this server is configured to return
// plaintext secret values.
func (s *Server) MayDiscloseValues() bool { return s.cfg.AllowSecretValues }

// discloseValue is the only place a secret value becomes a plain string.
//
// It is a method rather than a package function on purpose: it must consult
// the configuration on every call, and a package function would need the flag
// passed in — a parameter a caller could get wrong. A method cannot be called
// without a server whose config has already decided.
//
// The second return reports whether the value was actually disclosed, so a
// caller can label its output honestly rather than presenting a placeholder
// as though it were the value.
func (s *Server) discloseValue(v vaultapi.SecretValue) (string, bool) {
	if !s.MayDiscloseValues() {
		// An empty value redacts identically to a populated one, so its
		// emptiness is not itself disclosed.
		return RedactedPlaceholder, false
	}
	return v.Reveal(), true
}
