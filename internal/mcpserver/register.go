package mcpserver

// RegisterAllTools adds every tool the configuration enables.
//
// This is the single registration entry point. Callers -- the mcp command,
// the --check preflight, and the gating table test -- all go through it, so
// the set of registered tools is defined in exactly one place rather than
// duplicated across a command file and a test.
//
// Each register*Tools function decides for itself, via registerIf, which of
// its tools the enabled tiers permit.
func RegisterAllTools(s *Server) {
	registerSecretsReadTools(s)
	registerKeysReadTools(s)
	registerCertificatesReadTools(s)
	registerVaultsReadTools(s)
	registerAccessReadTools(s)
	registerAuditReadTools(s)
	registerSecretsWriteTools(s)
	registerVaultsWriteTools(s)
}
